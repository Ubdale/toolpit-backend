-- Toolpit's database: accounts, sessions and the token ledger.
--
-- Plain Postgres (Neon). Only the website's server talks to it - the browser
-- and the phone app never connect directly - so every function takes the user
-- id the server has already authenticated, and nothing here trusts a client.
--
-- No document, filename or extracted text is ever stored. The tests in
-- scripts/tokens-qc.mjs assert that no column could hold one.

-- ---------------------------------------------------------------- accounts

create table users (
  id uuid primary key default gen_random_uuid(),
  -- Stored as typed, matched case-insensitively.
  email text not null check (length(email) between 3 and 254),
  name text not null default '' check (length(name) <= 80),
  -- scrypt, as "scrypt$N$r$p$salt$hash" (lib/server/password.ts).
  password_hash text not null,
  created_at timestamptz not null default now()
);

create unique index users_email_idx on users (lower(email));

/*
 * Sessions are opaque random tokens. Only their SHA-256 is stored, so a leaked
 * copy of this table cannot be used to sign in as anyone.
 */
create table sessions (
  token_hash text primary key,
  user_id uuid not null references users (id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  user_agent text check (length(user_agent) <= 300)
);

create index sessions_user_idx on sessions (user_id);

/** One-time password-reset tokens, hashed like sessions, valid for an hour. */
create table password_resets (
  token_hash text primary key,
  user_id uuid not null references users (id) on delete cascade,
  expires_at timestamptz not null,
  used boolean not null default false
);

-- ------------------------------------------------------------------ ledger

create table wallets (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references users (id) on delete cascade,
  balance bigint not null default 0 check (balance >= 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create type token_reason as enum (
  'purchase', 'promo', 'signup_bonus', 'spend', 'refund', 'chargeback', 'expiry', 'admin_adjustment'
);

/*
 * Append-only. A balance is the sum of its entries; wallets.balance is a cache
 * written in the same transaction by the same function.
 */
create table token_entries (
  id uuid primary key default gen_random_uuid(),
  wallet_id uuid not null references wallets (id) on delete cascade,
  delta bigint not null check (delta <> 0),
  reason token_reason not null,
  balance_after bigint not null check (balance_after >= 0),
  -- The payment an entry came from. The unique index below is what makes a
  -- retried webhook harmless: the second insert fails, and is turned into
  -- "already done" rather than a second credit.
  provider text,
  provider_txn_id text,
  created_at timestamptz not null default now(),
  constraint purchase_has_provider check (
    (reason in ('purchase', 'refund', 'chargeback')) = (provider_txn_id is not null)
  )
);

create unique index token_entries_provider_txn_idx
  on token_entries (provider, provider_txn_id) where provider_txn_id is not null;
create unique index token_entries_one_signup_bonus
  on token_entries (wallet_id) where reason = 'signup_bonus';
create index token_entries_wallet_idx on token_entries (wallet_id, created_at desc);

/*
 * One sign-up bonus per inbox, remembered after the account is deleted, as a
 * one-way hash of the normalised address - never the address itself.
 */
create table bonus_claims (
  email_hash text primary key,
  claimed_at timestamptz not null default now()
);

create table token_packs (
  id text primary key,
  tokens int not null check (tokens > 0),
  price_cents int not null check (price_cents > 0),
  currency text not null default 'usd',
  label text not null,
  badge text,
  store_product_id text unique,
  active boolean not null default true,
  sort_order int not null default 0
);

insert into token_packs (id, tokens, price_cents, label, badge, store_product_id, sort_order) values
  ('tokens_30',   30,   99,   'Mini',     null,         'toolpit.tokens.30',   0),
  ('tokens_100',  100,  299,  'Starter',  null,         'toolpit.tokens.100',  1),
  ('tokens_500',  500,  999,  'Standard', 'Popular',    'toolpit.tokens.500',  2),
  ('tokens_1500', 1500, 2499, 'Pro',      'Best value', 'toolpit.tokens.1500', 3);

-- ----------------------------------------------------------------- numbers

create function tokens_per_file() returns int language sql immutable as $$ select 10; $$;
create function signup_bonus_tokens() returns int language sql immutable as $$ select 50; $$;

-- --------------------------------------------------------------- functions

/*
 * Credit tokens. Called only by the server after a verified payment, or for the
 * sign-up bonus. Idempotent on (provider, provider_txn_id).
 */
create function credit_tokens(
  p_wallet_id uuid, p_amount bigint, p_reason token_reason,
  p_provider text default null, p_provider_txn_id text default null
) returns bigint language plpgsql as $$
declare
  v_balance bigint;
begin
  if p_amount is null or p_amount <= 0 then
    raise exception 'amount must be positive' using errcode = '22023';
  end if;
  if p_reason not in ('purchase', 'promo', 'signup_bonus', 'admin_adjustment') then
    raise exception 'credit_tokens only credits' using errcode = '22023';
  end if;

  select balance into v_balance from wallets where id = p_wallet_id for update;
  if not found then
    raise exception 'no such wallet' using errcode = 'P0002';
  end if;

  v_balance := v_balance + p_amount;
  begin
    insert into token_entries (wallet_id, delta, reason, balance_after, provider, provider_txn_id)
    values (p_wallet_id, p_amount, p_reason, v_balance, p_provider, p_provider_txn_id);
  exception when unique_violation then
    select balance into v_balance from wallets where id = p_wallet_id;
    return v_balance;
  end;

  update wallets set balance = v_balance, updated_at = now() where id = p_wallet_id;
  return v_balance;
end;
$$;

/*
 * Take tokens back after a refund or chargeback, clamped at zero: someone who
 * bought 500, spent 400 and charged back loses the 100 that are left.
 */
create function revoke_tokens(
  p_wallet_id uuid, p_amount bigint, p_reason token_reason,
  p_provider text, p_provider_txn_id text
) returns bigint language plpgsql as $$
declare
  v_balance bigint;
  v_taken bigint;
begin
  if p_reason not in ('refund', 'chargeback') then
    raise exception 'revoke_tokens is for refunds' using errcode = '22023';
  end if;

  select balance into v_balance from wallets where id = p_wallet_id for update;
  if not found then
    raise exception 'no such wallet' using errcode = 'P0002';
  end if;

  v_taken := least(v_balance, p_amount);
  if v_taken = 0 then
    return v_balance;
  end if;

  v_balance := v_balance - v_taken;
  begin
    insert into token_entries (wallet_id, delta, reason, balance_after, provider, provider_txn_id)
    values (p_wallet_id, -v_taken, p_reason, v_balance, p_provider, p_provider_txn_id);
  exception when unique_violation then
    select balance into v_balance from wallets where id = p_wallet_id;
    return v_balance;
  end;

  update wallets set balance = v_balance, updated_at = now() where id = p_wallet_id;
  return v_balance;
end;
$$;

/*
 * Charge one download to a user, or fail. The row lock is the point: two
 * downloads started at the same instant on two devices cannot both spend the
 * last ten tokens.
 */
create function consume_download(p_user_id uuid) returns jsonb language plpgsql as $$
declare
  v_wallet uuid;
  v_balance bigint;
  v_cost int := tokens_per_file();
begin
  select id, balance into v_wallet, v_balance from wallets where user_id = p_user_id for update;
  if not found then
    raise exception 'no such wallet' using errcode = 'P0002';
  end if;
  if v_balance < v_cost then
    raise exception 'insufficient tokens' using errcode = 'P0001';
  end if;

  v_balance := v_balance - v_cost;
  update wallets set balance = v_balance, updated_at = now() where id = v_wallet;
  insert into token_entries (wallet_id, delta, reason, balance_after)
  values (v_wallet, -v_cost, 'spend', v_balance);

  return jsonb_build_object('charged', v_cost, 'balance', v_balance);
end;
$$;

/** Gmail ignores dots and +suffixes; other providers only +suffixes. */
create function normalised_email(p_email text) returns text language plpgsql immutable as $$
declare
  v_local text;
  v_domain text;
begin
  if p_email is null or position('@' in p_email) = 0 then
    return null;
  end if;
  v_local := split_part(lower(split_part(trim(p_email), '@', 1)), '+', 1);
  v_domain := lower(split_part(trim(p_email), '@', 2));
  if v_domain in ('gmail.com', 'googlemail.com') then
    v_local := replace(v_local, '.', '');
    v_domain := 'gmail.com';
  end if;
  return v_local || '@' || v_domain;
end;
$$;

/** Every new user gets a wallet, and the first account per inbox 50 tokens. */
create function handle_new_user() returns trigger language plpgsql as $$
declare
  v_wallet uuid;
  v_claimed int;
begin
  insert into wallets (user_id) values (new.id) returning id into v_wallet;

  insert into bonus_claims (email_hash)
  values (encode(sha256(convert_to(coalesce(normalised_email(new.email), new.id::text), 'utf8')), 'hex'))
  on conflict (email_hash) do nothing;
  get diagnostics v_claimed = row_count;

  if v_claimed = 1 then
    perform credit_tokens(v_wallet, signup_bonus_tokens(), 'signup_bonus');
  end if;
  return new;
end;
$$;

create trigger on_user_created after insert on users
  for each row execute function handle_new_user();

-- ------------------------------------------------------------- brute force

/** Failed sign-ins, kept briefly, to slow down password guessing per address. */
create table auth_failures (
  email_lower text not null,
  at timestamptz not null default now()
);

create index auth_failures_idx on auth_failures (email_lower, at desc);
