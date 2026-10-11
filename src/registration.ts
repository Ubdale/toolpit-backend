import { createHash, randomBytes, randomInt } from 'node:crypto';

import { AccountError, json, readBody, signedIn } from './account';
import { webOrigin } from './config';
import { db, one } from './db';
import { checkEmail } from './email';
import { requireReceivableEmail } from './mailbox';
import { MailError, mailConfigured, sendMail } from './mail';
import { hashPassword, verifyPassword } from './password';
import { hashToken } from './session';

/**
 * New accounts, with the email confirmed before anything is granted.
 *
 *   POST /api/auth/signup               -> pending registration + email; no account
 *   POST /api/auth/signup/resend        -> a new link; the old one stops working
 *   POST /api/auth/signup/change-email  -> the same registration, a new address
 *   POST /api/auth/verify/inspect       -> what a link is (never uses it)
 *   POST /api/auth/verify               -> link + the password chosen at sign-up
 *                                          -> verified account, bonus, session
 *   POST /api/auth/verify/cancel        -> "this was not me"
 *
 * Why the password is asked for again on the confirmation page: anyone can
 * type anyone's address into a sign-up form. If opening the link were enough,
 * whoever started the registration - knowing the password they chose - would
 * get an account on someone else's verified address the moment its owner
 * clicked. Requiring the password means only someone who both reads the inbox
 * and chose the password can finish; the inbox owner who did not start it is
 * shown "This was not me" instead, which cancels it.
 *
 * The link opens a page (GET does nothing); confirmation is a POST from an
 * explicit button, so a mail scanner that follows links cannot use one up.
 * The secret rides after the `#`, which browsers never send to a server, so
 * it is not in request logs, analytics page URLs or Referer headers.
 */

export const LINK_MINUTES = 30;
const CODE_MINUTES = 10;
export const HOLD_HOURS = 24;
const RESEND_COOLDOWN_SECONDS = 60;
/** Emails per address per hour (sign-up, resend and change of address together). */
const PER_ADDRESS_PER_HOUR = 5;
/** Sign-up attempts per source per hour. */
const PER_SOURCE_PER_HOUR = 20;
const MAX_CONFIRM_FAILURES = 10;

const CONTACT_EMAIL = process.env.CONTACT_EMAIL ?? 'contact@toolpit.app';

export type PendingView = {
  email: string;
  /** Lets this browser or app resend or change the address. Not a session. */
  handle: string;
  /** Whether the email was handed to the mail service just now. */
  delivery: 'sent' | 'failed' | 'earlier';
  resendAfter: number;
  linkMinutes: number;
  method: 'link' | 'code';
  expiresAt: string;
};

const secret = () => randomBytes(32).toString('base64url');
const sha = (value: string) => createHash('sha256').update(value).digest('hex');

/**
 * The client's address, for rate limits only (hashed before it is stored).
 * Behind Render's proxy the last X-Forwarded-For entry is the one the proxy
 * added; anything to its left is whatever the client sent.
 */
function source(request: Request): string {
  const forwarded = request.headers.get('x-forwarded-for');
  const last = forwarded?.split(',').map((part) => part.trim()).filter(Boolean).pop();
  return last ?? 'unknown';
}

async function limit(scope: string, key: string, max: number, message: string): Promise<void> {
  const keyHash = sha(`${scope}:${key}`);
  const row = await one<{ n: number; oldest: string | null }>(
    `select count(*)::int as n, min(at) as oldest from auth_rate_events
     where scope = $1 and key_hash = $2 and at > now() - interval '1 hour'`,
    [scope, keyHash],
  );
  if ((row?.n ?? 0) >= max) {
    const oldest = row?.oldest ? new Date(row.oldest).getTime() : Date.now();
    const retryAfter = Math.max(60, Math.ceil((oldest + 3600_000 - Date.now()) / 1000));
    throw new AccountError(message, 429, { code: 'rate_limited', retryAfter });
  }
  await db().query('insert into auth_rate_events (scope, key_hash) values ($1, $2)', [scope, keyHash]);
}

function link(token: string): string {
  // The configured website origin, never the request's Host header.
  return `${webOrigin()}/account/confirm#t=${token}`;
}

async function deliver(email: string, token: string, code?: string): Promise<'sent' | 'failed'> {
  try {
    const mailId = await sendMail({
      to: email,
      subject: 'Confirm your email for Toolpit',
      text: code ? [
        'Your Toolpit verification code is:', code, '',
        `Enter this six-digit code on the sign-up screen within ${CODE_MINUTES} minutes.`,
        'Do not share this code. If you did not request it, ignore this email.',
        'Your account and 50-token bonus are activated only after verification.',
      ].join('\n') : [
        'Someone - hopefully you - started creating a Toolpit account with this email address.',
        '',
        `To finish, open this link within ${LINK_MINUTES} minutes and enter the password you chose:`,
        link(token),
        '',
        'Your 50-token sign-up bonus is added when the email is confirmed. It is given once per email address.',
        '',
        'If this was not you, open the link and choose "This was not me" to cancel it, or ignore this email. No account is created unless the link is confirmed.',
      ].join('\n'),
    });
    await db().query('update email_verifications set mail_id = $1 where token_hash = $2', [mailId, hashToken(token)]);
    return 'sent';
  } catch (error) {
    if (error instanceof MailError) return 'failed';
    throw error;
  }
}

function requireMail(): void {
  if (!mailConfigured()) {
    throw new AccountError(
      `Creating an account needs email confirmation, which is not set up on this server yet. The tools still work without an account; write to ${CONTACT_EMAIL} if you need one now.`,
      503,
      { code: 'email_unavailable' },
    );
  }
}

function checkPassword(value: unknown): string {
  if (typeof value !== 'string' || value.length < 8) throw new AccountError('Use a password of at least 8 characters.', 400);
  if (value.length > 200) throw new AccountError('That password is too long.', 400);
  return value;
}

function view(email: string, handle: string, delivery: PendingView['delivery'], lastSent: Date, expires: Date, method: 'link' | 'code' = 'link'): PendingView {
  return {
    email,
    handle,
    delivery,
    resendAfter: Math.max(0, Math.ceil((lastSent.getTime() + RESEND_COOLDOWN_SECONDS * 1000 - Date.now()) / 1000)),
    linkMinutes: method === 'code' ? CODE_MINUTES : LINK_MINUTES,
    method,
    expiresAt: expires.toISOString(),
  };
}

type Registration = {
  id: string;
  email: string;
  password_hash: string;
  last_sent_at: string | null;
  expires_at: string;
  code_mode: boolean;
};

async function byHandle(handle: unknown): Promise<Registration> {
  if (typeof handle !== 'string' || handle.length > 100) throw new AccountError('This sign-up has ended. Start again.', 410, { code: 'registration_gone' });
  const reg = await one<Registration>(
    `select id, email, password_hash, last_sent_at, expires_at, exists (select 1 from email_verifications v where v.registration_id = pending_registrations.id and v.state = 'active' and v.code_hash is not null) as code_mode from pending_registrations where handle_hash = $1 and expires_at > now()`,
    [hashToken(handle)],
  );
  if (!reg) throw new AccountError('This sign-up has expired. Start again; it only takes a moment.', 410, { code: 'registration_gone' });
  return reg;
}

// ---------------------------------------------------------------- sign-up

export async function startSignUp(request: Request): Promise<Response> {
  const body = await readBody(request);
  const email = checkEmail(body.email);
  if (!email.ok) throw new AccountError(email.error, 400, { code: 'invalid_email' });
  const password = checkPassword(body.password);
  // The name is optional: it only greets the person on their account page.
  const name = typeof body.name === 'string' ? body.name.trim().slice(0, 80) : '';
  requireMail();

  await limit('signup-source', source(request), PER_SOURCE_PER_HOUR, 'Too many sign-ups from this connection. Try again later.');
  await limit('signup-address', email.key, PER_ADDRESS_PER_HOUR, 'Too many confirmation emails for this address. Try again later.');

  await requireReceivableEmail(email.email);
  const handle = secret();
  const token = secret();
  const code = body.verification === 'code' ? String(randomInt(0, 1000000)).padStart(6, '0') : undefined;
  const started = await one<{ r: { status: string } }>(
    code ? 'select start_code_registration($1,$2,$3,$4,$5,$6,$7,$8,$9) as r' : 'select start_registration($1, $2, $3, $4, $5, $6, $7, $8) as r',
    [email.email, email.key, name, await hashPassword(password), hashToken(handle), hashToken(token), code ? CODE_MINUTES : LINK_MINUTES, HOLD_HOURS, ...(code ? [await hashPassword(code)] : [])],
  );
  if (started!.r.status === 'exists') {
    throw new AccountError('There is already an account with that email. Sign in instead.', 409, { code: 'account_exists' });
  }

  const delivery = await deliver(email.email, token, code);
  const now = new Date();
  const pending = view(email.email, handle, delivery, now, new Date(now.getTime() + HOLD_HOURS * 3600_000), code ? 'code' : 'link');

  // Clients from before verification expect a signed-in account back. They get
  // an error they will display, which says exactly what to do, rather than a
  // response they would misread as success. The registration is real: the
  // link works, and they can sign in once it is confirmed.
  if (body.verification !== 'link' && body.verification !== 'code') {
    throw new AccountError(
      delivery === 'sent'
        ? `Almost done: we sent a link to ${email.email}. Open it to confirm your email, then sign in here. (Updating the app shows these steps in the app.)`
        : `We could not send the confirmation email to ${email.email}. Try again in a few minutes, or update the app.`,
      403,
      { code: 'verification_required', pending: { email: pending.email, delivery, linkMinutes: LINK_MINUTES } },
    );
  }
  return json({ pending }, 202);
}

export async function resend(request: Request): Promise<Response> {
  const body = await readBody(request);
  requireMail();
  const reg = await byHandle(body.handle);
  const last = reg.last_sent_at ? new Date(reg.last_sent_at).getTime() : 0;
  const wait = Math.ceil((last + RESEND_COOLDOWN_SECONDS * 1000 - Date.now()) / 1000);
  if (wait > 0) {
    throw new AccountError(`Wait ${wait} seconds before sending another email.`, 429, { code: 'cooldown', retryAfter: wait });
  }
  await limit('signup-source', source(request), PER_SOURCE_PER_HOUR, 'Too many emails requested from this connection. Try again later.');
  await limit('signup-address', reg.email.toLowerCase(), PER_ADDRESS_PER_HOUR, 'Too many confirmation emails for this address. Try again later.');

  await requireReceivableEmail(reg.email);
  const token = secret();
  const code = reg.code_mode ? String(randomInt(0, 1000000)).padStart(6, '0') : undefined;
  const issued = await one<{ r: { status: string } }>(code ? 'select reissue_code_verification($1,null,null,$2,$3,$4) as r' : 'select reissue_verification($1, null, null, $2, $3) as r', [
    reg.id,
    hashToken(token),
    code ? CODE_MINUTES : LINK_MINUTES,
    ...(code ? [await hashPassword(code)] : []),
  ]);
  if (issued!.r.status !== 'issued') throw new AccountError('This sign-up has expired. Start again.', 410, { code: 'registration_gone' });
  const delivery = await deliver(reg.email, token, code);
  return json({ pending: view(reg.email, body.handle as string, delivery, new Date(), new Date(reg.expires_at), reg.code_mode ? 'code' : 'link') });
}

export async function changeEmail(request: Request): Promise<Response> {
  const body = await readBody(request);
  requireMail();
  const email = checkEmail(body.email);
  if (!email.ok) throw new AccountError(email.error, 400, { code: 'invalid_email' });
  const reg = await byHandle(body.handle);
  await limit('signup-source', source(request), PER_SOURCE_PER_HOUR, 'Too many emails requested from this connection. Try again later.');
  await limit('signup-address', email.key, PER_ADDRESS_PER_HOUR, 'Too many confirmation emails for this address. Try again later.');
  await requireReceivableEmail(email.email);

  const token = secret();
  const code = reg.code_mode ? String(randomInt(0, 1000000)).padStart(6, '0') : undefined;
  const issued = await one<{ r: { status: string } }>(code ? 'select reissue_code_verification($1,$2,$3,$4,$5,$6) as r' : 'select reissue_verification($1, $2, $3, $4, $5) as r', [
    reg.id,
    email.email,
    email.key,
    hashToken(token),
    code ? CODE_MINUTES : LINK_MINUTES,
    ...(code ? [await hashPassword(code)] : []),
  ]);
  if (issued!.r.status === 'exists') {
    throw new AccountError('There is already an account with that email. Sign in instead.', 409, { code: 'account_exists' });
  }
  if (issued!.r.status !== 'issued') throw new AccountError('This sign-up has expired. Start again.', 410, { code: 'registration_gone' });
  const delivery = await deliver(email.email, token, code);
  return json({ pending: view(email.email, body.handle as string, delivery, new Date(), new Date(reg.expires_at), reg.code_mode ? 'code' : 'link') });
}

// ------------------------------------------------------------------ links

const LINK_MESSAGES: Record<string, [string, number]> = {
  expired: [`This link has expired. Links work for ${LINK_MINUTES} minutes; ask for a new one from the sign-up screen, or sign up again.`, 410],
  superseded: ['A newer confirmation email was sent. Use the link in the most recent email.', 410],
  used: ['This email is already confirmed. Sign in with your password.', 409],
  cancelled: ['This sign-up was cancelled.', 410],
  invalid: ['This link is not valid. Check that you opened the whole link from the email.', 400],
  exists: ['There is already an account with this email. Sign in instead.', 409],
  gone: ['This link has expired or was already used.', 410],
};

function linkError(status: string): AccountError {
  const [message, code] = LINK_MESSAGES[status] ?? LINK_MESSAGES.invalid!;
  return new AccountError(message, code, { code: `link_${status}` });
}

function readToken(value: unknown): string {
  if (typeof value !== 'string' || value.length < 20 || value.length > 100) throw linkError('invalid');
  return value;
}

type Inspected = { status: string; email?: string; password_hash?: string };

async function inspect(token: string): Promise<Inspected> {
  const row = await one<{ r: Inspected }>('select inspect_verification($1) as r', [hashToken(token)]);
  return row!.r;
}

/** What a link is: its address if it can still be confirmed. Never uses it. */
export async function inspectLink(request: Request): Promise<Response> {
  const body = await readBody(request);
  const found = await inspect(readToken(body.token));
  if (found.status !== 'active') {
    const [message] = LINK_MESSAGES[found.status] ?? LINK_MESSAGES.invalid!;
    return json({ status: found.status, message });
  }
  return json({ status: 'active', email: found.email, linkMinutes: LINK_MINUTES });
}

export async function confirmLink(request: Request): Promise<Response> {
  const body = await readBody(request);
  const token = readToken(body.token);
  const found = await inspect(token);
  if (found.status !== 'active') throw linkError(found.status);

  const key = `verify:${found.email!.toLowerCase()}`;
  const failures = await one<{ n: number }>(
    `select count(*)::int as n from auth_failures where email_lower = $1 and at > now() - interval '15 minutes'`,
    [key],
  );
  if ((failures?.n ?? 0) >= MAX_CONFIRM_FAILURES) {
    throw new AccountError('Too many attempts. Wait 15 minutes and try again.', 429, { code: 'rate_limited', retryAfter: 900 });
  }
  const password = typeof body.password === 'string' && body.password.length <= 200 ? body.password : '';
  if (!(await verifyPassword(password, found.password_hash!))) {
    await db().query('insert into auth_failures (email_lower) values ($1)', [key]);
    throw new AccountError(
      'That is not the password chosen when this sign-up was started. If you did not start it, choose "This was not me".',
      401,
      { code: 'wrong_password' },
    );
  }

  let result: { status: string; user_id?: string; bonus?: boolean };
  try {
    result = (await one<{ r: typeof result }>('select activate_registration($1) as r', [hashToken(token)]))!.r;
  } catch (error) {
    // A user with this address appeared between the checks (unique index).
    if ((error as { code?: string }).code === '23505') throw linkError('exists');
    throw error;
  }
  if (result.status !== 'activated') throw linkError(result.status);
  await db().query('delete from auth_failures where email_lower = $1', [key]);
  return signedIn(result.user_id!, request, 200, { bonusGranted: Boolean(result.bonus) });
}

export async function cancelLink(request: Request): Promise<Response> {
  const body = await readBody(request);
  const token = readToken(body.token);
  const row = await one<{ r: { status: string } }>('select cancel_registration($1) as r', [hashToken(token)]);
  if (row!.r.status !== 'cancelled') throw linkError('gone');
  return json({ ok: true });
}

// ----------------------------------------------------- sign-in, pending

/**
 * Sign-in for an address that has no account yet but a sign-up waiting for
 * its email. With the right password, an error that says so and a fresh
 * handle (so this device can resend or change the address); otherwise null,
 * and the caller answers like any wrong password.
 */
export async function pendingSignIn(key: string, password: string): Promise<AccountError | null> {
  const reg = await one<Registration>(
    `select id, email, password_hash, last_sent_at, expires_at, exists (select 1 from email_verifications v where v.registration_id = pending_registrations.id and v.state = 'active' and v.code_hash is not null) as code_mode from pending_registrations where email_key = $1 and expires_at > now()`,
    [key],
  );
  if (!reg || !(await verifyPassword(password, reg.password_hash))) return null;
  const handle = secret();
  await db().query('update pending_registrations set handle_hash = $1 where id = $2', [hashToken(handle), reg.id]);
  return new AccountError(
    `Confirm your email to finish creating your account. We sent a ${reg.code_mode ? 'code' : 'link'} to ${reg.email}.`,
    403,
    {
      code: 'email_unverified',
      pending: view(reg.email, handle, 'earlier', reg.last_sent_at ? new Date(reg.last_sent_at) : new Date(0), new Date(reg.expires_at), reg.code_mode ? 'code' : 'link'),
    },
  );
}

/** The handle binds the inbox code to the browser that chose the password. */
export async function confirmCode(request: Request): Promise<Response> {
  const body = await readBody(request);
  if (typeof body.handle !== 'string' || body.handle.length > 100 || typeof body.code !== 'string' || !/^\d{6}$/.test(body.code)) {
    throw new AccountError('Enter the six-digit code from your email.', 400, { code: 'invalid_code' });
  }
  const found = (await one<{ r: { status: string; token_hash?: string; code_hash?: string } }>(
    'select claim_code_attempt($1) as r', [hashToken(body.handle)],
  ))!.r;
  if (found.status === 'gone') throw new AccountError('This sign-up has ended. Start again or sign in.', 410, { code: 'registration_gone' });
  if (found.status === 'locked') throw new AccountError('Too many incorrect attempts. Request a new code.', 429, { code: 'code_locked' });
  if (found.status !== 'active') throw new AccountError('Your code has expired. Request a new code.', 410, { code: 'code_expired' });
  if (!(await verifyPassword(body.code, found.code_hash!))) throw new AccountError('That code is incorrect. Use the latest code from your email.', 400, { code: 'invalid_code' });
  const result = (await one<{ r: { status: string; user_id?: string; bonus?: boolean } }>(
    'select activate_registration($1) as r', [found.token_hash],
  ))!.r;
  if (result.status !== 'activated') throw new AccountError('This code was replaced, expired, or already used. Request a new code or sign in.', 410, { code: 'code_expired' });
  return signedIn(result.user_id!, request, 200, { bonusGranted: Boolean(result.bonus) });
}
