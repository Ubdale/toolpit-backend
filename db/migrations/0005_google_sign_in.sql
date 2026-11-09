-- "Continue with Google" for the website (src/google.ts).
--
-- A Google sign-in proves two things: who the Google account is (its stable
-- subject id) and, when Google says email_verified, that the person controls
-- that inbox - the same thing our own email code proves. So:
--
--   seen this Google account before           -> its Toolpit account
--   same address as a VERIFIED account         -> link Google to it
--   same address as a LEGACY account           -> refuse: nobody ever proved
--                                                 that inbox, so whoever made
--                                                 the account may not own it;
--                                                 sign in with its password
--   new address                                -> a verified account, and the
--                                                 sign-up bonus once per inbox
--
-- Nothing here changes existing accounts, balances or sessions.

/** Which outside sign-in belongs to which account. */
create table user_identities (
  provider text not null check (provider in ('google')),
  -- Google's "sub": stable for the life of the Google account, unlike its email.
  subject text not null check (length(subject) between 1 and 255),
  user_id uuid not null references users (id) on delete cascade,
  email text not null,
  created_at timestamptz not null default now(),
  primary key (provider, subject)
);

create index user_identities_user_idx on user_identities (user_id);

/**
 * One sign-in attempt between leaving for Google and coming back: the state
 * (hashed), the PKCE verifier and the nonce. Single use, ten minutes.
 */
create table oauth_attempts (
  state_hash text primary key,
  code_verifier text not null,
  nonce text not null,
  return_to text not null default '/account',
  expires_at timestamptz not null
);

/** Takes an attempt exactly once. */
create function take_oauth_attempt(p_state_hash text) returns jsonb language plpgsql as $$
declare
  v_row oauth_attempts%rowtype;
begin
  delete from oauth_attempts where expires_at < now() - interval '1 hour';
  delete from oauth_attempts where state_hash = p_state_hash and expires_at > now() returning * into v_row;
  if not found then
    return null;
  end if;
  return jsonb_build_object('code_verifier', v_row.code_verifier, 'nonce', v_row.nonce, 'return_to', v_row.return_to);
end;
$$;

/*
 * The account for a verified Google identity, made or found in one
 * transaction. Serialised per address, like sign-up, so two first sign-ins at
 * once make one account.
 *
 * A Google-only account gets a password hash that matches nothing ('!google'),
 * so password sign-in is simply refused until the person sets one through
 * "Forgot password", which proves the inbox again.
 */
create function google_sign_in(p_subject text, p_email text, p_key text, p_name text) returns jsonb language plpgsql as $$
declare
  v_user users%rowtype;
  v_id uuid;
  v_bonus boolean;
begin
  perform pg_advisory_xact_lock(hashtext('registration:' || p_key));

  select u.* into v_user from user_identities i join users u on u.id = i.user_id
  where i.provider = 'google' and i.subject = p_subject;
  if found then
    return jsonb_build_object('status', 'existing', 'user_id', v_user.id);
  end if;

  select * into v_user from users where lower(email) = p_key;
  if found then
    if v_user.email_status <> 'verified' then
      return jsonb_build_object('status', 'legacy_conflict');
    end if;
    insert into user_identities (provider, subject, user_id, email) values ('google', p_subject, v_user.id, p_email);
    return jsonb_build_object('status', 'linked', 'user_id', v_user.id);
  end if;

  -- A pending email sign-up for this address is replaced: Google has just
  -- proved the inbox, which is what that sign-up was waiting for.
  update email_verifications set state = 'superseded'
  where state = 'active' and registration_id in (select id from pending_registrations where email_key = p_key);
  delete from pending_registrations where email_key = p_key;

  insert into users (email, name, password_hash, email_status, email_verified_at)
  values (p_email, left(coalesce(p_name, ''), 80), '!google', 'verified', now())
  returning id into v_id;
  v_bonus := grant_signup_bonus(v_id);
  insert into user_identities (provider, subject, user_id, email) values ('google', p_subject, v_id, p_email);
  return jsonb_build_object('status', 'created', 'user_id', v_id, 'bonus', v_bonus);
end;
$$;
