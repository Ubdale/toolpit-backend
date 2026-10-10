-- Email verification for new accounts.
--
-- Before this, sign-up inserted a user, the insert trigger granted the 50-token
-- bonus, and the person was signed in - so any plausible-looking invented
-- address became a fully working account with tokens. Now:
--
--   sign-up      -> a pending registration (not a user, no wallet, no tokens)
--   email link   -> a confirmation page; the person enters the password they
--                   chose, and only then is the user created, verified, and
--                   given the bonus, in one transaction
--
-- Existing accounts are untouched: same balances, purchases and sessions. They
-- are marked 'legacy' so they can be told apart from verified ones later; no
-- one is locked out or asked to verify by this migration.

-- ------------------------------------------------------------ user state

alter table users add column email_status text;
alter table users add column email_verified_at timestamptz;

-- Every account that exists now was created before verification existed.
update users set email_status = 'legacy';

-- No default on purpose: an insert must say which kind of account it is. A
-- server still running the old code during a deploy fails to sign people up
-- rather than creating unverified accounts.
alter table users alter column email_status set not null;
alter table users add constraint users_email_status check (email_status in ('legacy', 'verified'));
alter table users add constraint users_verified_when check ((email_status = 'verified') = (email_verified_at is not null));

-- --------------------------------------------------- one bonus per inbox

/*
 * The key a sign-up bonus is remembered under: the inbox, as best we can tell.
 *
 * Provider-specific, not global. Gmail delivers ann.example+x@gmail.com to
 * annexample@gmail.com, so those are one inbox; on most other domains a plus
 * or a dot is part of a different address, and stripping it everywhere would
 * deny a bonus to a different person. Plus tags are dropped only for providers
 * that document plus addressing; dots only for Gmail.
 *
 * This decides bonus eligibility only. Accounts are told apart by the whole
 * address, case-insensitively, everywhere (sign-up, sign-in, reset).
 */
create or replace function normalised_email(p_email text) returns text language plpgsql immutable as $$
declare
  v_local text;
  v_domain text;
begin
  if p_email is null or position('@' in p_email) = 0 then
    return null;
  end if;
  v_local := lower(split_part(trim(p_email), '@', 1));
  v_domain := lower(split_part(trim(p_email), '@', 2));
  if v_domain = 'googlemail.com' then
    v_domain := 'gmail.com';
  end if;
  if v_domain in (
    'gmail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
    'icloud.com', 'me.com', 'mac.com', 'fastmail.com', 'fastmail.fm',
    'proton.me', 'protonmail.com', 'pm.me'
  ) then
    v_local := split_part(v_local, '+', 1);
  end if;
  if v_domain = 'gmail.com' then
    v_local := replace(v_local, '.', '');
  end if;
  return v_local || '@' || v_domain;
end;
$$;

/** A new user gets a wallet. The bonus is no longer granted here. */
create or replace function handle_new_user() returns trigger language plpgsql as $$
begin
  insert into wallets (user_id) values (new.id);
  return new;
end;
$$;

/*
 * The sign-up bonus, for a verified user, once per inbox.
 *
 * bonus_claims is the "once per inbox" (it outlives deleted accounts) and the
 * unique index on token_entries is "once per wallet", so a retried or parallel
 * call cannot grant twice: the second finds the claim taken.
 */
create function grant_signup_bonus(p_user_id uuid) returns boolean language plpgsql as $$
declare
  v_wallet uuid;
  v_email text;
  v_claimed int;
begin
  select w.id, u.email into v_wallet, v_email
  from users u join wallets w on w.user_id = u.id
  where u.id = p_user_id and u.email_status = 'verified'
  for update of w;
  if not found then
    return false;
  end if;

  insert into bonus_claims (email_hash)
  values (encode(sha256(convert_to(normalised_email(v_email), 'utf8')), 'hex'))
  on conflict (email_hash) do nothing;
  get diagnostics v_claimed = row_count;
  if v_claimed = 0 then
    return false;
  end if;

  perform credit_tokens(v_wallet, signup_bonus_tokens(), 'signup_bonus');
  return true;
end;
$$;

-- ------------------------------------------------ pending registrations

/*
 * A sign-up waiting for its email to be confirmed. Not an account: it cannot
 * sign in, hold tokens or buy anything. One per address; a new sign-up for the
 * same address replaces it, so an abandoned or hostile one cannot hold an
 * address hostage, and it expires on its own.
 */
create table pending_registrations (
  id uuid primary key default gen_random_uuid(),
  email text not null check (length(email) between 3 and 254),
  -- lower(email): the same comparison users get.
  email_key text not null unique,
  name text not null default '' check (length(name) <= 80),
  password_hash text not null,
  -- Lets the browser or app that started this resend or change the address.
  -- Only its SHA-256 is kept, like sessions.
  handle_hash text not null unique,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  last_sent_at timestamptz,
  sends int not null default 0
);

/*
 * Confirmation links. Only the SHA-256 of the secret is stored. A link belongs
 * to one registration and the address it was sent to; sending another (resend,
 * change of address) supersedes it. Rows outlive their registration briefly so
 * a reused link can say "already confirmed" instead of "not valid".
 */
create table email_verifications (
  token_hash text primary key,
  registration_id uuid references pending_registrations (id) on delete set null,
  email_key text not null,
  state text not null check (state in ('active', 'superseded', 'used', 'cancelled')),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at timestamptz,
  user_id uuid references users (id) on delete set null
);

create index email_verifications_registration_idx on email_verifications (registration_id) where state = 'active';
create index email_verifications_created_idx on email_verifications (created_at);

/** Sign-up and resend attempts, per address and per source, kept briefly for rate limits. */
create table auth_rate_events (
  scope text not null,
  key_hash text not null,
  at timestamptz not null default now()
);

create index auth_rate_events_idx on auth_rate_events (scope, key_hash, at desc);

/*
 * Start (or restart) a registration. Replaces any pending one for the address,
 * superseding its links. Serialised per address, so two sign-ups at once end
 * with one registration, not an error.
 */
create function start_registration(
  p_email text, p_key text, p_name text, p_password_hash text,
  p_handle_hash text, p_token_hash text, p_link_minutes int, p_hold_hours int
) returns jsonb language plpgsql as $$
declare
  v_id uuid;
begin
  perform pg_advisory_xact_lock(hashtext('registration:' || p_key));

  -- Housekeeping, cheap enough to do here.
  delete from pending_registrations where expires_at < now();
  delete from email_verifications where created_at < now() - interval '30 days';
  delete from auth_rate_events where at < now() - interval '1 day';

  if exists (select 1 from users where lower(email) = p_key) then
    return jsonb_build_object('status', 'exists');
  end if;

  update email_verifications set state = 'superseded'
  where state = 'active' and registration_id in (select id from pending_registrations where email_key = p_key);
  delete from pending_registrations where email_key = p_key;

  insert into pending_registrations (email, email_key, name, password_hash, handle_hash, expires_at, last_sent_at, sends)
  values (p_email, p_key, p_name, p_password_hash, p_handle_hash, now() + make_interval(hours => p_hold_hours), now(), 1)
  returning id into v_id;

  insert into email_verifications (token_hash, registration_id, email_key, state, expires_at)
  values (p_token_hash, v_id, p_key, 'active', now() + make_interval(mins => p_link_minutes));

  return jsonb_build_object('status', 'started', 'registration_id', v_id);
end;
$$;

/** A new link for a registration (resend), optionally to a new address (change of email). */
create function reissue_verification(
  p_registration uuid, p_new_email text, p_new_key text, p_token_hash text, p_link_minutes int
) returns jsonb language plpgsql as $$
declare
  v_reg pending_registrations%rowtype;
  v_key text;
begin
  select * into v_reg from pending_registrations where id = p_registration and expires_at > now() for update;
  if not found then
    return jsonb_build_object('status', 'gone');
  end if;
  v_key := coalesce(p_new_key, v_reg.email_key);

  if p_new_key is not null and p_new_key <> v_reg.email_key then
    perform pg_advisory_xact_lock(hashtext('registration:' || p_new_key));
    if exists (select 1 from users where lower(email) = p_new_key) then
      return jsonb_build_object('status', 'exists');
    end if;
    -- Someone else's pending sign-up for the new address is replaced, as a new
    -- sign-up would replace it.
    update email_verifications set state = 'superseded'
    where state = 'active' and registration_id in (
      select id from pending_registrations where email_key = p_new_key and id <> v_reg.id
    );
    delete from pending_registrations where email_key = p_new_key and id <> v_reg.id;
    update pending_registrations set email = p_new_email, email_key = p_new_key where id = v_reg.id;
  end if;

  update email_verifications set state = 'superseded' where registration_id = v_reg.id and state = 'active';
  insert into email_verifications (token_hash, registration_id, email_key, state, expires_at)
  values (p_token_hash, v_reg.id, v_key, 'active', now() + make_interval(mins => p_link_minutes));
  update pending_registrations set last_sent_at = now(), sends = sends + 1 where id = v_reg.id;
  return jsonb_build_object('status', 'issued');
end;
$$;

/** What a link is, without using it. */
create function inspect_verification(p_token_hash text) returns jsonb language plpgsql stable as $$
declare
  v_token email_verifications%rowtype;
  v_reg pending_registrations%rowtype;
begin
  select * into v_token from email_verifications where token_hash = p_token_hash;
  if not found then
    return jsonb_build_object('status', 'invalid');
  end if;
  if v_token.state <> 'active' then
    return jsonb_build_object('status', v_token.state);
  end if;
  select * into v_reg from pending_registrations where id = v_token.registration_id;
  if not found or v_token.expires_at <= now() or v_reg.expires_at <= now() then
    return jsonb_build_object('status', 'expired');
  end if;
  if v_reg.email_key <> v_token.email_key then
    return jsonb_build_object('status', 'invalid');
  end if;
  return jsonb_build_object('status', 'active', 'email', v_reg.email, 'registration_id', v_reg.id,
                            'password_hash', v_reg.password_hash);
end;
$$;

/*
 * Confirm a link: create the verified user, grant the bonus, consume the link,
 * end the registration - all or nothing. The caller has already checked the
 * password against the registration.
 *
 * Locks the registration before the link, the same order reissue uses, so the
 * two cannot deadlock. Two confirmations at once: the second waits, finds the
 * registration gone, and reports the link as used.
 */
create function activate_registration(p_token_hash text) returns jsonb language plpgsql as $$
declare
  v_registration uuid;
  v_token email_verifications%rowtype;
  v_reg pending_registrations%rowtype;
  v_user uuid;
  v_bonus boolean;
begin
  select registration_id into v_registration from email_verifications where token_hash = p_token_hash;
  if not found then
    return jsonb_build_object('status', 'invalid');
  end if;

  select * into v_reg from pending_registrations where id = v_registration for update;
  select * into v_token from email_verifications where token_hash = p_token_hash for update;

  if v_token.state <> 'active' then
    return jsonb_build_object('status', v_token.state);
  end if;
  if v_reg.id is null or v_token.expires_at <= now() or v_reg.expires_at <= now() then
    return jsonb_build_object('status', 'expired');
  end if;
  if v_reg.email_key <> v_token.email_key then
    return jsonb_build_object('status', 'invalid');
  end if;

  if exists (select 1 from users where lower(email) = v_reg.email_key) then
    update email_verifications set state = 'superseded' where registration_id = v_reg.id and state = 'active';
    delete from pending_registrations where id = v_reg.id;
    return jsonb_build_object('status', 'exists');
  end if;

  insert into users (email, name, password_hash, email_status, email_verified_at)
  values (v_reg.email, v_reg.name, v_reg.password_hash, 'verified', now())
  returning id into v_user;
  v_bonus := grant_signup_bonus(v_user);

  update email_verifications set state = 'used', used_at = now(), user_id = v_user where token_hash = p_token_hash;
  update email_verifications set state = 'superseded' where registration_id = v_reg.id and state = 'active';
  delete from pending_registrations where id = v_reg.id;

  return jsonb_build_object('status', 'activated', 'user_id', v_user, 'bonus', v_bonus);
end;
$$;

/** "This was not me": the inbox owner ends a registration they did not start. */
create function cancel_registration(p_token_hash text) returns jsonb language plpgsql as $$
declare
  v_registration uuid;
begin
  select registration_id into v_registration from email_verifications
  where token_hash = p_token_hash and state = 'active' and expires_at > now();
  if v_registration is null then
    return jsonb_build_object('status', 'gone');
  end if;
  perform 1 from pending_registrations where id = v_registration for update;
  update email_verifications set state = 'cancelled' where registration_id = v_registration and state = 'active';
  delete from pending_registrations where id = v_registration;
  return jsonb_build_object('status', 'cancelled');
end;
$$;
