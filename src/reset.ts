import { randomBytes } from 'node:crypto';

import { AccountError } from './account';
import { db, one } from './db';
import { hashPassword } from './password';
import { hashToken } from './session';

/**
 * Forgotten passwords: a one-hour, one-use link, sent with Resend.
 *
 * Without RESEND_API_KEY the site cannot send email, and says so instead of
 * pretending a link is on its way.
 */

const CONTACT_EMAIL = process.env.CONTACT_EMAIL ?? 'contact@toolpit.app';

export function emailConfigured(): boolean {
  return Boolean(process.env.RESEND_API_KEY);
}

export async function sendReset(emailInput: string, origin: string): Promise<void> {
  if (!emailConfigured()) {
    throw new AccountError(`Password reset by email is not set up yet. Write to ${CONTACT_EMAIL} and we will help.`, 503);
  }
  const user = await one<{ id: string; email: string }>('select id, email from users where lower(email) = $1', [
    emailInput.trim().toLowerCase(),
  ]);
  // The same answer either way, so this cannot be used to test which emails have accounts.
  if (!user) return;

  const token = randomBytes(32).toString('base64url');
  await db().query(
    `insert into password_resets (token_hash, user_id, expires_at) values ($1, $2, now() + interval '1 hour')`,
    [hashToken(token), user.id],
  );

  const link = `${origin}/account?reset=${encodeURIComponent(token)}`;
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      from: process.env.EMAIL_FROM ?? `Toolpit <no-reply@toolpit.app>`,
      to: user.email,
      subject: 'Reset your Toolpit password',
      text: `Someone asked to reset the password for your Toolpit account.\n\nTo choose a new password, open this link within an hour:\n${link}\n\nIf it was not you, ignore this email; your password stays the same.`,
    }),
  });
  if (!response.ok) throw new Error(`Resend refused the email: ${response.status}`);
}

export async function completeReset(token: string, password: string): Promise<string> {
  if (password.length < 8) throw new AccountError('Use a password of at least 8 characters.', 400);
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
