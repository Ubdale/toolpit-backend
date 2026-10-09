import { db, databaseConfigured, one } from './db';
import { DECOY_HASH, hashPassword, verifyPassword } from './password';
import { createSession, sessionCookie, userFromRequest, type SessionUser } from './session';

/**
 * Accounts: what the /api/auth and /api/account routes do, kept out of the
 * route files so each route is a few lines of HTTP around one call here.
 */

export type AccountSummary = { id: string; email: string; name: string; balance: number; cost: number };

export class AccountError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
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
    if (error instanceof AccountError) return json({ error: error.message }, error.status);
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
  return user;
}

export async function summary(userId: string): Promise<AccountSummary> {
  const row = await one<{ email: string; name: string; balance: string }>(
    'select u.email, u.name, w.balance from users u join wallets w on w.user_id = u.id where u.id = $1',
    [userId],
  );
  if (!row) throw new AccountError('This account no longer exists.', 401);
  const cost = await one<{ c: number }>('select tokens_per_file() as c');
  return { id: userId, email: row.email, name: row.name, balance: Number(row.balance), cost: Number(cost!.c) };
}

/** The response every successful sign-in or sign-up returns: token for the app, cookie for the site. */
async function signedIn(userId: string, request: Request, status = 200): Promise<Response> {
  const token = await createSession(userId, request.headers.get('user-agent'));
  const account = await summary(userId);
  return json({ token, account }, status, { 'set-cookie': sessionCookie(token, request) });
}

export async function signUp(request: Request): Promise<Response> {
  const body = await readBody(request);
  const name = String(body.name ?? '').trim().slice(0, 80);
  const email = String(body.email ?? '').trim();
  const password = String(body.password ?? '');

  if (name.length < 2) throw new AccountError('Enter your name.', 400);
  if (!EMAIL.test(email) || email.length > 254) throw new AccountError('Enter a valid email address.', 400);
  if (password.length < 8) throw new AccountError('Use a password of at least 8 characters.', 400);
  if (password.length > 200) throw new AccountError('That password is too long.', 400);

  const hash = await hashPassword(password);
  try {
    // The insert trigger creates the wallet and grants the sign-up bonus.
    const user = await one<{ id: string }>(
      'insert into users (email, name, password_hash) values ($1, $2, $3) returning id',
      [email, name, hash],
    );
    return signedIn(user!.id, request, 201);
  } catch (error) {
    if ((error as { code?: string }).code === '23505') {
      throw new AccountError('There is already an account with that email. Sign in instead.', 409);
    }
    throw error;
  }
}

export async function signIn(request: Request): Promise<Response> {
  const body = await readBody(request);
  const email = String(body.email ?? '').trim();
  const password = String(body.password ?? '');
  const key = email.toLowerCase();

  const failures = await one<{ n: number }>(
    `select count(*)::int as n from auth_failures where email_lower = $1 and at > now() - interval '15 minutes'`,
    [key],
  );
  if ((failures?.n ?? 0) >= MAX_FAILURES) {
    throw new AccountError('Too many attempts for this email. Wait 15 minutes and try again.', 429);
  }

  const user = await one<{ id: string; password_hash: string }>(
    'select id, password_hash from users where lower(email) = $1',
    [key],
  );
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
