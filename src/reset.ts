import { randomBytes } from 'node:crypto';

import { AccountError } from './account';
import { db, one } from './db';
import { emailKey } from './email';
import { MailError, mailConfigured, sendMail } from './mail';
import { hashPassword } from './password';
import { hashToken } from './session';

/**
 * Forgotten passwords: a one-hour, one-use link.
 *
 * Without email delivery the site cannot send one, and says so instead of
 * pretending a link is on its way.
 *
 * The secret travels after the `#` of the link, which browsers never send to
 * a server or put in a Referer header, so it stays out of request logs.
 */

const CONTACT_EMAIL = process.env.CONTACT_EMAIL ?? 'contact@toolpit.app';

export function emailConfigured(): boolean {
  return mailConfigured();
}

export async function sendReset(emailInput: unknown, origin: string): Promise<void> {
  if (!emailConfigured()) {
    throw new AccountError(`Password reset by email is not set up yet. Write to ${CONTACT_EMAIL} and we will help.`, 503);
  }
  if (typeof emailInput !== 'string' || emailInput.length > 320) throw new AccountError('Enter a valid email address.', 400);
  const user = await one<{ id: string; email: string }>('select id, email from users where lower(email) = $1', [
    emailKey(emailInput),
  ]);
  // The same answer either way, so this cannot be used to test which emails have accounts.
  if (!user) return;

  const token = randomBytes(32).toString('base64url');
  await db().query(
    `insert into password_resets (token_hash, user_id, expires_at) values ($1, $2, now() + interval '1 hour')`,
    [hashToken(token), user.id],
  );

  const link = `${origin}/account#reset=${token}`;
  try {
    await sendMail({
      to: user.email,
      subject: 'Reset your Toolpit password',
      text: `Someone asked to reset the password for your Toolpit account.\n\nTo choose a new password, open this link within an hour:\n${link}\n\nIf it was not you, ignore this email; your password stays the same.`,
    });
  } catch (error) {
    if (error instanceof MailError) {
      throw new AccountError('The reset email could not be sent. Try again in a few minutes.', 502);
    }
    throw error;
  }
}

export async function completeReset(token: string, password: string): Promise<string> {
  if (password.length < 8) throw new AccountError('Use a password of at least 8 characters.', 400);
  if (password.length > 200) throw new AccountError('That password is too long.', 400);
  const row = await one<{ user_id: string }>(
    `update password_resets set used = true
     where token_hash = $1 and not used and expires_at > now()
     returning user_id`,
    [hashToken(token)],
  );
  if (!row) throw new AccountError('That reset link has expired or was already used. Ask for a new one.', 400);
  await db().query('update users set password_hash = $1 where id = $2', [await hashPassword(password), row.user_id]);
  // Everywhere that was signed in with the old password is signed out.
  await db().query('delete from sessions where user_id = $1', [row.user_id]);
  return row.user_id;
}
