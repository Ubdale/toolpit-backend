import { db, databaseConfigured, one } from './db';
import { emailKey } from './email';
import { DECOY_HASH, verifyPassword } from './password';
import { pendingSignIn, startSignUp } from './registration';
import { createSession, sessionCookie, userFromRequest, type SessionUser } from './session';

/**
 * Accounts: what the /api/auth and /api/account routes do, kept out of the
 * route files so each route is a few lines of HTTP around one call here.
 */

export type AccountSummary = {
  id: string;
  email: string;
  name: string;
  balance: number;
  cost: number;
  emailVerified: boolean;
  emailStatus: 'legacy' | 'verified';
};

export class AccountError extends Error {
  readonly status: number;
  /** More of the response body: a machine-readable code, a pending sign-up, a retry delay. */
  readonly extra: Record<string, unknown>;
  constructor(message: string, status: number, extra: Record<string, unknown> = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

const MAX_FAILURES = 10;

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return Response.json(body, { status, headers: { 'cache-control': 'no-store', ...headers } });
}

/** Wraps a route: 503 when unconfigured, AccountError as its status, anything else as 500. */
export async function handle(run: () => Promise<Response>): Promise<Response> {
  if (!databaseConfigured()) return json({ error: 'Accounts are not configured.' }, 503);
  try {
    return await run();
  } catch (error) {
    if (error instanceof AccountError) {
      const retry = typeof error.extra.retryAfter === 'number' ? { 'retry-after': String(error.extra.retryAfter) } : undefined;
      return json({ error: error.message, ...error.extra }, error.status, retry);
    }
    console.error('[account]', error);
    return json({ error: 'Something went wrong on our side. Try again in a moment.' }, 500);
  }
}

export async function readBody(request: Request): Promise<Record<string, unknown>> {
  try {
    const body = (await request.json()) as unknown;
    return body && typeof body === 'object' ? (body as Record<string, unknown>) : {};
  } catch {
    throw new AccountError('Bad request.', 400);
  }
}

export async function requireUser(request: Request): Promise<SessionUser> {
  const user = await userFromRequest(request);
  if (!user) throw new AccountError('Sign in first.', 401);
  // Only real accounts have sessions: one that existed before verification
  // ('legacy') or one whose email was confirmed. Checked here as well as by
  // the schema, so a future account state cannot reach tokens by accident.
  if (user.email_status !== 'legacy' && user.email_status !== 'verified') {
    throw new AccountError('Confirm your email to use this account.', 403, { code: 'email_unverified' });
  }
  return user;
}

export async function summary(userId: string): Promise<AccountSummary> {
  const row = await one<{ email: string; name: string; balance: string; email_status: 'legacy' | 'verified' }>(
    'select u.email, u.name, u.email_status, w.balance from users u join wallets w on w.user_id = u.id where u.id = $1',
    [userId],
  );
  if (!row) throw new AccountError('This account no longer exists.', 401);
  const cost = await one<{ c: number }>('select tokens_per_file() as c');
  return {
    id: userId,
    email: row.email,
    name: row.name,
    balance: Number(row.balance),
    cost: Number(cost!.c),
    // Explicit, so no client has to infer it: every account the API returns
    // is a usable one, and these two say which kind.
    emailVerified: row.email_status === 'verified',
    emailStatus: row.email_status,
  };
}

/** The response every successful sign-in returns: token for the app, cookie for the site. */
export async function signedIn(userId: string, request: Request, status = 200, extra: Record<string, unknown> = {}): Promise<Response> {
  const token = await createSession(userId, request.headers.get('user-agent'));
  const account = await summary(userId);
  return json({ token, account, ...extra }, status, { 'set-cookie': sessionCookie(token, request) });
}

/** Sign-up starts a registration that waits for its email link (registration.ts). */
export function signUp(request: Request): Promise<Response> {
  return startSignUp(request);
}

export async function signIn(request: Request): Promise<Response> {
  const body = await readBody(request);
  if (typeof body.email !== 'string' || typeof body.password !== 'string' || body.email.length > 320 || body.password.length > 200) {
    throw new AccountError('That email and password do not match an account.', 401);
  }
  const password = body.password;
  const key = emailKey(body.email);

  const failures = await one<{ n: number }>(
    `select count(*)::int as n from auth_failures where email_lower = $1 and at > now() - interval '15 minutes'`,
    [key],
  );
  if ((failures?.n ?? 0) >= MAX_FAILURES) {
    throw new AccountError('Too many attempts for this email. Wait 15 minutes and try again.', 429, { retryAfter: 900 });
  }

  const user = await one<{ id: string; password_hash: string }>(
    'select id, password_hash from users where lower(email) = $1',
    [key],
  );
  if (!user) {
    // Not an account yet - perhaps a sign-up still waiting for its email. With
    // the right password, say so and let them resend; otherwise the same
    // answer as any wrong password.
    const pending = await pendingSignIn(key, password);
    if (pending) throw pending;
  }
  // Always verify something, so an unknown email takes as long as a wrong password.
  const ok = await verifyPassword(password, user?.password_hash ?? DECOY_HASH);
  if (!user || !ok) {
    await db().query('insert into auth_failures (email_lower) values ($1)', [key]);
    await db().query(`delete from auth_failures where at < now() - interval '1 day'`);
    throw new AccountError('That email and password do not match an account.', 401);
  }
  await db().query('delete from auth_failures where email_lower = $1', [key]);
  return signedIn(user.id, request);
}

export async function chargeDownload(userId: string): Promise<{ charged: number; balance: number }> {
  try {
    const row = await one<{ r: { charged: number; balance: number } }>('select consume_download($1) as r', [userId]);
    return { charged: Number(row!.r.charged), balance: Number(row!.r.balance) };
  } catch (error) {
    if (/insufficient tokens/.test(String((error as Error).message))) {
      throw new AccountError('Not enough tokens.', 402);
    }
    throw error;
  }
}

export async function deleteAccount(userId: string): Promise<void> {
  // Sessions, wallet and ledger go with the user through their foreign keys;
  // the bonus claim (a hash) deliberately stays.
  await db().query('delete from users where id = $1', [userId]);
}

export async function listPacks() {
  const result = await db().query(
    'select id, tokens, price_cents, currency, label, badge, store_product_id from token_packs where active order by sort_order',
  );
  return result.rows.map((row) => ({
    id: String(row.id),
    tokens: Number(row.tokens),
    priceCents: Number(row.price_cents),
    currency: String(row.currency),
    label: String(row.label),
    badge: row.badge ? String(row.badge) : null,
    productId: row.store_product_id ? String(row.store_product_id) : null,
  }));
}
