-- Keep legacy links usable while new website clients use inbox codes.
alter table email_verifications add column code_hash text;
alter table email_verifications add column code_attempts int not null default 0;

create function start_code_registration(
  p_email text, p_key text, p_name text, p_password text,
  p_handle text, p_token text, p_minutes int, p_hours int, p_code text
) returns jsonb language plpgsql as $$
declare r jsonb;
begin
  r := start_registration(p_email, p_key, p_name, p_password, p_handle, p_token, p_minutes, p_hours);
  if r->>'status' = 'started' then
    update email_verifications set code_hash = p_code where token_hash = p_token;
  end if;
  return r;
end;
$$;

create function reissue_code_verification(
  p_registration uuid, p_email text, p_key text, p_token text, p_minutes int, p_code text
) returns jsonb language plpgsql as $$
declare r jsonb;
begin
  r := reissue_verification(p_registration, p_email, p_key, p_token, p_minutes);
  if r->>'status' = 'issued' then
    update email_verifications set code_hash = p_code where token_hash = p_token;
  end if;
  return r;
end;
$$;

-- Reserve an attempt atomically, including concurrent requests. Only an
-- unexpired challenge belonging to this browser's registration is returned.
create function claim_code_attempt(p_handle text) returns jsonb language plpgsql as $$
declare reg pending_registrations%rowtype; challenge email_verifications%rowtype;
begin
  select * into reg from pending_registrations
    where handle_hash = p_handle and expires_at > now() for update;
  if not found then return jsonb_build_object('status', 'gone'); end if;
  select * into challenge from email_verifications
    where registration_id = reg.id and state = 'active' and code_hash is not null for update;
  if not found or challenge.expires_at <= now() then
    return jsonb_build_object('status', 'expired');
  end if;
  if challenge.code_attempts >= 5 then return jsonb_build_object('status', 'locked'); end if;
  update email_verifications set code_attempts = code_attempts + 1 where token_hash = challenge.token_hash;
  return jsonb_build_object('status', 'active', 'token_hash', challenge.token_hash, 'code_hash', challenge.code_hash);
end;
$$;
