import { AccountError, json, readBody, requireUser, summary } from './account';
import { db, one } from './db';
import { hashPassword, verifyPassword } from './password';
import { hashToken, tokenFrom } from './session';

/**
 * Changing your own account details while signed in.
 *
 *   POST /api/account/profile   {name}               -> {account}
 *   POST /api/account/password  {current, password}  -> {account}
 *
 * The email address is not changed here: a new address has to be proved like
 * the first one was, which is its own flow.
 *
 * A password change needs the current password (a stolen session alone must
 * not be able to lock the owner out), is limited like sign-in, and signs out
 * every other device. An account made with Google has no password to give;
 * it sets one through "Forgot password", which proves the inbox.
 */

const MAX_NAME = 80;
const MAX_FAILURES = 10;

export async function updateProfile(request: Request): Promise<Response> {
  const user = await requireUser(request);
  const body = await readBody(request);
  if (typeof body.name !== 'string') throw new AccountError('Enter a name, or leave it empty.', 400, { code: 'invalid_name' });
  // eslint-disable-next-line no-control-regex
  const name = body.name.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, '').replace(/\s+/g, ' ').trim();
  if (name.length > MAX_NAME) throw new AccountError(`Use at most ${MAX_NAME} characters.`, 400, { code: 'invalid_name' });
  await db().query('update users set name = $2 where id = $1', [user.id, name]);
  return json({ account: await summary(user.id) });
}

export async function changePassword(request: Request): Promise<Response> {
  const user = await requireUser(request);
  const body = await readBody(request);
  const current = typeof body.current === 'string' && body.current.length <= 200 ? body.current : '';
  const next = typeof body.password === 'string' ? body.password : '';
  if (next.length < 8) throw new AccountError('Use a new password of at least 8 characters.', 400, { code: 'weak_password' });
  if (next.length > 200) throw new AccountError('That password is too long.', 400, { code: 'weak_password' });

  const row = await one<{ password_hash: string }>('select password_hash from users where id = $1', [user.id]);
  if (!row) throw new AccountError('This account no longer exists.', 401);
  if (!row.password_hash.startsWith('scrypt$')) {
    throw new AccountError('This account signs in with Google and has no password yet. Use "Set a password" to get an email link.', 409, { code: 'no_password' });
  }

  const key = user.email.toLowerCase();
  const failures = await one<{ n: number }>(
    `select count(*)::int as n from auth_failures where email_lower = $1 and at > now() - interval '15 minutes'`,
    [key],
  );
  if ((failures?.n ?? 0) >= MAX_FAILURES) {
    throw new AccountError('Too many attempts. Wait 15 minutes and try again.', 429, { code: 'rate_limited', retryAfter: 900 });
  }
  if (!(await verifyPassword(current, row.password_hash))) {
    await db().query('insert into auth_failures (email_lower) values ($1)', [key]);
    // 400, not 401: the session is fine, only the typed password is wrong.
    throw new AccountError('Your current password is not right.', 400, { code: 'wrong_password' });
  }
  await db().query('delete from auth_failures where email_lower = $1', [key]);

  await db().query('update users set password_hash = $2 where id = $1', [user.id, await hashPassword(next)]);
  // Every other device has to sign in again with the new password.
  const token = tokenFrom(request);
  await db().query('delete from sessions where user_id = $1 and token_hash <> $2', [user.id, token ? hashToken(token) : '']);
  return json({ account: await summary(user.id), signedOutElsewhere: true });
}

