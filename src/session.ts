import { createHash, randomBytes } from 'node:crypto';

import { db, one } from './db';

/**
 * Sessions: an opaque random token handed to the client, its SHA-256 kept here.
 *
 * The website keeps the token in an httpOnly cookie, out of reach of any
 * script on the page. The phone app keeps it in the device's secure storage
 * and sends it as a bearer token. Both arrive at `userFromRequest`.
 */

export const SESSION_COOKIE = 'tp_session';
const SESSION_DAYS = 90;

export type SessionUser = { id: string; email: string; name: string; email_status: string };

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export async function createSession(userId: string, userAgent: string | null): Promise<string> {
  const token = randomBytes(32).toString('base64url');
  await db().query(
    `insert into sessions (token_hash, user_id, expires_at, user_agent)
     values ($1, $2, now() + make_interval(days => $3), $4)`,
    [hashToken(token), userId, SESSION_DAYS, userAgent?.slice(0, 300) ?? null],
  );
  return token;
}

function tokenFrom(request: Request): string | null {
  const bearer = request.headers.get('authorization')?.match(/^Bearer\s+(\S+)$/i)?.[1];
  if (bearer) return bearer;
  const cookie = request.headers.get('cookie') ?? '';
  const match = cookie.split(/;\s*/).find((part) => part.startsWith(`${SESSION_COOKIE}=`));
  return match ? decodeURIComponent(match.slice(SESSION_COOKIE.length + 1)) : null;
}

export async function userFromRequest(request: Request): Promise<SessionUser | null> {
  const token = tokenFrom(request);
  if (!token || token.length > 200) return null;
  return one<SessionUser>(
    `select u.id, u.email, u.name, u.email_status from sessions s join users u on u.id = s.user_id
     where s.token_hash = $1 and s.expires_at > now()`,
    [hashToken(token)],
  );
}

export async function endSession(request: Request): Promise<void> {
  const token = tokenFrom(request);
  if (token) await db().query('delete from sessions where token_hash = $1', [hashToken(token)]);
}

/** Set-Cookie for the website. Secure everywhere but plain-http localhost. */
export function sessionCookie(token: string | null, request: Request): string {
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  if (!token) return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${secure}`;
}
