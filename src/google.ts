import { createHash, createPublicKey, randomBytes, verify, type JsonWebKey } from 'node:crypto';

import { json } from './account';
import { apiOrigin, webOrigin } from './config';
import { db, one } from './db';
import { checkEmail } from './email';
import { hashToken, createSession, sessionCookie } from './session';

/**
 * "Continue with Google" for the website.
 *
 *   GET /api/auth/google/start     -> 302 to Google, with state, nonce, PKCE
 *   GET /api/auth/google/callback  -> code exchanged, ID token verified,
 *                                     account found / linked / made, session
 *                                     cookie set, 302 back to the website
 *   GET /api/auth/providers        -> { google: boolean }, so the button only
 *                                     shows when it can work
 *
 * The authorization-code flow with PKCE, a single-use state stored hashed for
 * ten minutes, and a nonce bound into the ID token. The ID token is verified
 * here, not trusted: RS256 signature against Google's published keys, issuer,
 * audience (our client id), expiry, nonce, and email_verified. No secret or
 * code ever appears in a URL we build; the final redirect carries only a
 * result code. Which account a Google identity gets is decided in SQL
 * (google_sign_in, migration 0005).
 *
 * Configuration (Render env): GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and
 * API_ORIGIN when the API is not at https://api.toolpit.app. The redirect URI
 * registered with Google must be exactly API_ORIGIN + /api/auth/google/callback.
 */

const AUTHORIZE = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN = 'https://oauth2.googleapis.com/token';
const CERTS = 'https://www.googleapis.com/oauth2/v3/certs';
const ISSUERS = new Set(['accounts.google.com', 'https://accounts.google.com']);
const ATTEMPT_MINUTES = 10;

const env = (name: string) => process.env[name]?.trim() ?? '';
const b64url = (bytes: Buffer) => bytes.toString('base64url');

export function googleConfigured(): boolean {
  return Boolean(env('GOOGLE_CLIENT_ID') && env('GOOGLE_CLIENT_SECRET'));
}

export function redirectUri(): string {
  return `${apiOrigin()}/api/auth/google/callback`;
}

/** Only a path on our own site; anything else falls back to the account page. */
function safeReturn(value: string | null): string {
  if (!value || !value.startsWith('/') || value.startsWith('//') || value.includes('\\') || value.length > 300) return '/account';
  return value;
}

function back(path: string, params: Record<string, string>): Response {
  const url = new URL(path, `${webOrigin()}/`);
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  return new Response(null, { status: 302, headers: { location: url.toString(), 'cache-control': 'no-store' } });
}

export function providers(): Response {
  return json({ google: googleConfigured() });
}

export async function start(request: Request): Promise<Response> {
  if (!googleConfigured()) return back('/account', { google_error: 'unavailable' });
  const returnTo = safeReturn(new URL(request.url).searchParams.get('return'));

  const state = b64url(randomBytes(32));
  const verifier = b64url(randomBytes(32));
  const nonce = b64url(randomBytes(24));
  await db().query(
    `insert into oauth_attempts (state_hash, code_verifier, nonce, return_to, expires_at)
     values ($1, $2, $3, $4, now() + make_interval(mins => $5))`,
    [hashToken(state), verifier, nonce, returnTo, ATTEMPT_MINUTES],
  );

  const url = new URL(AUTHORIZE);
  url.search = new URLSearchParams({
    client_id: env('GOOGLE_CLIENT_ID'),
    redirect_uri: redirectUri(),
    response_type: 'code',
    scope: 'openid email profile',
    state,
    nonce,
    code_challenge: b64url(createHash('sha256').update(verifier).digest()),
    code_challenge_method: 'S256',
    prompt: 'select_account',
  }).toString();
  return new Response(null, { status: 302, headers: { location: url.toString(), 'cache-control': 'no-store' } });
}

// ------------------------------------------------------------- ID tokens

type Jwk = JsonWebKey & { kid?: string };
let certs: { keys: Jwk[]; until: number } | null = null;

async function googleKeys(force = false): Promise<Jwk[]> {
  if (!force && certs && certs.until > Date.now()) return certs.keys;
  const response = await fetch(CERTS, { signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error(`Google keys: ${response.status}`);
  const body = (await response.json()) as { keys: Jwk[] };
  certs = { keys: body.keys, until: Date.now() + 60 * 60 * 1000 };
  return certs.keys;
}

export type GoogleClaims = { sub: string; email: string; name: string };

/** Verifies an ID token completely, or throws with a short reason. */
export async function verifyIdToken(idToken: string, nonce: string): Promise<GoogleClaims> {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('malformed token');
  const [head, body, signature] = parts as [string, string, string];
  const header = JSON.parse(Buffer.from(head, 'base64url').toString('utf8')) as { alg?: string; kid?: string };
  if (header.alg !== 'RS256' || !header.kid) throw new Error('unexpected algorithm');

  let key = (await googleKeys()).find((k) => k.kid === header.kid);
  // Google rotates its keys; an unknown kid is worth one fresh fetch.
  if (!key) key = (await googleKeys(true)).find((k) => k.kid === header.kid);
  if (!key) throw new Error('unknown signing key');
  const ok = verify(
    'RSA-SHA256',
    Buffer.from(`${head}.${body}`),
    createPublicKey({ key, format: 'jwk' }),
    Buffer.from(signature, 'base64url'),
  );
  if (!ok) throw new Error('bad signature');

  const claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as Record<string, unknown>;
  const now = Math.floor(Date.now() / 1000);
  if (!ISSUERS.has(String(claims.iss))) throw new Error('wrong issuer');
  if (claims.aud !== env('GOOGLE_CLIENT_ID')) throw new Error('wrong audience');
  if (typeof claims.exp !== 'number' || claims.exp < now - 60) throw new Error('expired');
  if (typeof claims.iat === 'number' && claims.iat > now + 300) throw new Error('issued in the future');
  if (claims.nonce !== nonce) throw new Error('nonce mismatch');
  if (claims.email_verified !== true) throw new Error('email not verified by Google');
  if (typeof claims.sub !== 'string' || typeof claims.email !== 'string') throw new Error('missing claims');
  return { sub: claims.sub, email: claims.email, name: typeof claims.name === 'string' ? claims.name : '' };
}

// -------------------------------------------------------------- callback

export async function callback(request: Request): Promise<Response> {
  const params = new URL(request.url).searchParams;
  if (!googleConfigured()) return back('/account', { google_error: 'unavailable' });

  const state = params.get('state') ?? '';
  const attempt = state && state.length <= 100
    ? (await one<{ a: { code_verifier: string; nonce: string; return_to: string } | null }>('select take_oauth_attempt($1) as a', [hashToken(state)]))?.a
    : null;
  if (!attempt) return back('/account', { google_error: 'expired' });
  const returnTo = safeReturn(attempt.return_to);

  // The person pressed Cancel on Google's screen.
  if (params.get('error')) return back(returnTo, { google_error: 'cancelled' });
  const code = params.get('code');
  if (!code || code.length > 2000) return back(returnTo, { google_error: 'failed' });

  let claims: GoogleClaims;
  try {
    const response = await fetch(TOKEN, {
      method: 'POST',
      signal: AbortSignal.timeout(10_000),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: env('GOOGLE_CLIENT_ID'),
        client_secret: env('GOOGLE_CLIENT_SECRET'),
        redirect_uri: redirectUri(),
        grant_type: 'authorization_code',
        code_verifier: attempt.code_verifier,
      }).toString(),
    });
    const tokens = (await response.json().catch(() => ({}))) as { id_token?: string };
    if (!response.ok || !tokens.id_token) throw new Error(`token exchange: ${response.status}`);
    claims = await verifyIdToken(tokens.id_token, attempt.nonce);
  } catch (error) {
    // Reason only; never the code or a token.
    console.error(`[google] sign-in refused: ${(error as Error).message}`);
    return back(returnTo, { google_error: 'failed' });
  }

  const email = checkEmail(claims.email);
  if (!email.ok) return back(returnTo, { google_error: 'email' });
  const result = (
    await one<{ r: { status: string; user_id?: string; bonus?: boolean } }>('select google_sign_in($1, $2, $3, $4) as r', [
      claims.sub,
      email.email,
      email.key,
      claims.name,
    ])
  )!.r;
  if (result.status === 'legacy_conflict') return back(returnTo, { google_error: 'password_account' });

  const token = await createSession(result.user_id!, request.headers.get('user-agent'));
  const response = back(returnTo, { google: result.status === 'created' ? 'welcome' : 'signed-in' });
  response.headers.set('set-cookie', sessionCookie(token, request));
  return response;
}

