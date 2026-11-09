/**
 * "Continue with Google", end to end through the real app on PGlite, with
 * Google replaced by a local RSA key and a captured fetch. Nothing leaves the
 * machine.
 *
 *   npm run test:google
 *
 * Start: state, nonce and PKCE go to Google; the return path stays on our site.
 * Callback: a good ID token signs in (new verified account, bonus once),
 * a repeat finds the same account, a verified account is linked, a legacy one
 * is refused, a pending sign-up is replaced. Every bad token is refused:
 * signature, audience, issuer, expiry, nonce, unverified email, reused or
 * unknown state. Unconfigured: providers says so and start sends people back.
 */
import { createSign, generateKeyPairSync } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';

process.env.NODE_ENV = 'production';
process.env.WEB_ORIGIN = 'https://toolpit.app';
process.env.API_ORIGIN = 'https://api.toolpit.app';
process.env.GOOGLE_CLIENT_ID = 'client-123.apps.googleusercontent.com';
process.env.GOOGLE_CLIENT_SECRET = 'qc-secret';

const { app } = await import('../src/app.ts');
const { useDatabase } = await import('../src/db.ts');
const { verifyPassword } = await import('../src/password.ts');

let problems = 0;
const check = (name, ok, detail) => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${ok || detail === undefined ? '' : ` — ${detail}`}`);
  if (!ok) problems += 1;
};

const pg = await PGlite.create();
for (const name of readdirSync('db/migrations').filter((f) => f.endsWith('.sql')).sort()) {
  await pg.exec(readFileSync(`db/migrations/${name}`, 'utf8'));
}
useDatabase({ query: async (sql, params) => ({ rows: (await pg.query(sql, params)).rows }) });
const one = async (sql, params) => (await pg.query(sql, params)).rows[0];

// ---------------------------------------------------------- fake Google

const google = generateKeyPairSync('rsa', { modulusLength: 2048 });
const stranger = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...google.publicKey.export({ format: 'jwk' }), kid: 'kid-1', alg: 'RS256', use: 'sig' };
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

function idToken(claims, { key = google.privateKey, kid = 'kid-1' } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64({ alg: 'RS256', kid, typ: 'JWT' });
  const body = b64({
    iss: 'https://accounts.google.com',
    aud: process.env.GOOGLE_CLIENT_ID,
    iat: now,
    exp: now + 3600,
    email_verified: true,
    name: 'Google Person',
    ...claims,
  });
  const signature = createSign('RSA-SHA256').update(`${head}.${body}`).sign(key).toString('base64url');
  return `${head}.${body}.${signature}`;
}

/** What the token endpoint will answer next, and what it was sent. */
let nextToken = null;
const tokenRequests = [];
globalThis.fetch = async (url, init) => {
  const href = String(url);
  if (href === 'https://www.googleapis.com/oauth2/v3/certs') return Response.json({ keys: [jwk] });
  if (href === 'https://oauth2.googleapis.com/token') {
    tokenRequests.push(new URLSearchParams(init.body));
    return nextToken ? Response.json({ id_token: nextToken }) : Response.json({ error: 'invalid_grant' }, { status: 400 });
  }
  throw new Error(`unexpected fetch ${href}`);
};

const get = (path, headers = {}) => app.fetch(new Request(`https://api.toolpit.app${path}`, { headers }));

/** Leaves for Google; returns the authorize URL's parameters. */
async function begin(returnTo = '/tools/merge-pdf') {
  const response = await get(`/api/auth/google/start?return=${encodeURIComponent(returnTo)}`);
  return { response, params: new URL(response.headers.get('location')).searchParams };
}

/** A whole sign-in, with Google answering with the claims given. */
async function signIn(claims, options = {}) {
  const { params } = await begin(options.returnTo);
  nextToken = idToken({ nonce: options.nonce ?? params.get('nonce'), ...claims }, options);
  const response = await get(`/api/auth/google/callback?state=${params.get('state')}&code=code-abc`);
  nextToken = null;
  const location = new URL(response.headers.get('location'));
  return { response, location, cookie: response.headers.get('set-cookie') ?? '', state: params.get('state') };
}

const user = async (email) => one('select u.*, w.balance from users u join wallets w on w.user_id = u.id where lower(u.email) = lower($1)', [email]);

console.log('\nproviders and start');
{
  const providers = await (await get('/api/auth/providers')).json();
  check('providers says Google is on', providers.google === true, JSON.stringify(providers));
  const { response, params } = await begin('/tools/merge-pdf');
  const location = new URL(response.headers.get('location'));
  check('start redirects to Google', response.status === 302 && location.origin + location.pathname === 'https://accounts.google.com/o/oauth2/v2/auth');
  check('with our client id and exact redirect URI', params.get('client_id') === process.env.GOOGLE_CLIENT_ID && params.get('redirect_uri') === 'https://api.toolpit.app/api/auth/google/callback');
  check('asking for openid email profile, a code, PKCE S256', params.get('scope') === 'openid email profile' && params.get('response_type') === 'code' && params.get('code_challenge_method') === 'S256' && (params.get('code_challenge') ?? '').length === 43);
  check('with a long random state and nonce', (params.get('state') ?? '').length >= 40 && (params.get('nonce') ?? '').length >= 30);
  const stored = await one('select count(*)::int as n from oauth_attempts where state_hash = $1', [params.get('state')]);
  check('the state is stored hashed, not as itself', stored.n === 0);
  const evil = await begin('//evil.example/steal');
  const attempt = await one('select return_to from oauth_attempts order by expires_at desc limit 1');
  check('a return path to another site becomes /account', evil.response.status === 302 && attempt.return_to === '/account', attempt.return_to);
}

console.log('\na new person');
{
  const r = await signIn({ sub: 'g-1', email: 'New.Person@gmail.com' });
  check('comes back to the page they left, welcomed', r.location.origin === 'https://toolpit.app' && r.location.pathname === '/tools/merge-pdf' && r.location.searchParams.get('google') === 'welcome', r.location.href);
  check('with a secure session cookie', /^tp_session=[^;]+;.*HttpOnly.*SameSite=Lax.*Secure/.test(r.cookie), r.cookie);
  const made = await user('new.person@gmail.com');
  check('gets a verified account with the 50-token bonus', made?.email_status === 'verified' && Number(made.balance) === 50 && made.name === 'Google Person', JSON.stringify(made));
  check('whose password matches nothing', !(await verifyPassword('', made.password_hash)) && !(await verifyPassword('!google', made.password_hash)));
  const sent = tokenRequests.at(-1);
  check('the code was exchanged with the secret and the PKCE verifier', sent.get('client_secret') === 'qc-secret' && (sent.get('code_verifier') ?? '').length === 43 && sent.get('redirect_uri') === 'https://api.toolpit.app/api/auth/google/callback');

  const token = decodeURIComponent(r.cookie.split(';')[0].split('=')[1]);
  const me = await (await get('/api/account', { authorization: `Bearer ${token}` })).json().catch(() => null);
  check('the session works', me?.email?.toLowerCase() === 'new.person@gmail.com' || me?.account?.email?.toLowerCase() === 'new.person@gmail.com', JSON.stringify(me));

  const again = await signIn({ sub: 'g-1', email: 'new.person@gmail.com' });
  const after = await user('new.person@gmail.com');
  check('signing in again finds the same account, no second bonus', again.location.searchParams.get('google') === 'signed-in' && Number(after.balance) === 50 && after.id === made.id);
  const users = await one('select count(*)::int as n from users');
  check('and makes no second user', users.n === 1, String(users.n));
}

console.log('\nexisting accounts');
{
  await pg.query(`insert into users (email, name, password_hash, email_status, email_verified_at) values ('verified@toolpit-test.dev', 'V', 'x', 'verified', now())`);
  const linked = await signIn({ sub: 'g-2', email: 'Verified@toolpit-test.dev' });
  const v = await user('verified@toolpit-test.dev');
  check('a verified account with that email is linked and signed in', linked.location.searchParams.get('google') === 'signed-in' && linked.cookie.startsWith('tp_session=') && v.password_hash === 'x');
  const identity = await one(`select user_id from user_identities where subject = 'g-2'`);
  check('the link is recorded', identity?.user_id === v.id);

  
  const status = 'legacy';
  await pg.query(`insert into users (email, name, password_hash, email_status) values ('legacy@toolpit-test.dev', 'L', 'x', $1)`, [status]);
  const legacy = await signIn({ sub: 'g-3', email: 'legacy@toolpit-test.dev' });
  check('an unverified (legacy) account is refused, not taken over', legacy.location.searchParams.get('google_error') === 'password_account' && legacy.cookie === '', legacy.location.href);
  check('and nothing is linked to it', (await one(`select count(*)::int as n from user_identities where subject = 'g-3'`)).n === 0);

  await pg.query(`insert into pending_registrations (email, email_key, password_hash, handle_hash, expires_at) values ('pending@toolpit-test.dev', 'pending@toolpit-test.dev', 'x', 'h1', now() + interval '1 day')`);
  const pending = await signIn({ sub: 'g-4', email: 'pending@toolpit-test.dev' });
  check('a pending email sign-up is replaced by the Google account', pending.location.searchParams.get('google') === 'welcome' && (await one(`select count(*)::int as n from pending_registrations`)).n === 0);
}

console.log('\nrefused tokens');
{
  const before = (await one('select count(*)::int as n from users')).n;
  const refused = async (name, claims, options) => {
    const r = await signIn(claims, options);
    check(name, r.location.searchParams.get('google_error') === 'failed' && r.cookie === '', r.location.href);
  };
  await refused('signed by someone else', { sub: 'g-x', email: 'x@gmail.com' }, { key: stranger.privateKey });
  await refused('for another app (audience)', { sub: 'g-x', email: 'x@gmail.com', aud: 'other.apps.googleusercontent.com' });
  await refused('from another issuer', { sub: 'g-x', email: 'x@gmail.com', iss: 'https://evil.example' });
  await refused('expired', { sub: 'g-x', email: 'x@gmail.com', exp: Math.floor(Date.now() / 1000) - 3600 });
  await refused('with the wrong nonce', { sub: 'g-x', email: 'x@gmail.com' }, { nonce: 'not-the-nonce' });
  await refused('with an email Google has not verified', { sub: 'g-x', email: 'x@gmail.com', email_verified: false });
  await refused('with an unknown key id', { sub: 'g-x', email: 'x@gmail.com' }, { kid: 'kid-unknown' });
  check('none of them made an account', (await one('select count(*)::int as n from users')).n === before);

  const first = await signIn({ sub: 'g-1', email: 'new.person@gmail.com' });
  nextToken = idToken({ sub: 'g-1', email: 'new.person@gmail.com' });
  const replay = await get(`/api/auth/google/callback?state=${first.state}&code=code-abc`);
  nextToken = null;
  check('a used state cannot be used again', new URL(replay.headers.get('location')).searchParams.get('google_error') === 'expired' && !replay.headers.get('set-cookie'));
  const unknown = await get('/api/auth/google/callback?state=made-up&code=code-abc');
  check('an unknown state is refused', new URL(unknown.headers.get('location')).searchParams.get('google_error') === 'expired');
  const { params } = await begin('/account');
  const cancelled = await get(`/api/auth/google/callback?state=${params.get('state')}&error=access_denied`);
  check('Cancel on Google brings them back quietly', new URL(cancelled.headers.get('location')).searchParams.get('google_error') === 'cancelled');
  const badCode = await begin('/account');
  const failedExchange = await get(`/api/auth/google/callback?state=${badCode.params.get('state')}&code=wrong`);
  check('a code Google rejects is refused', new URL(failedExchange.headers.get('location')).searchParams.get('google_error') === 'failed');
}

console.log('\nnot configured');
{
  delete process.env.GOOGLE_CLIENT_SECRET;
  check('providers says Google is off', (await (await get('/api/auth/providers')).json()).google === false);
  const r = await get('/api/auth/google/start');
  check('start sends people back with a message', r.status === 302 && new URL(r.headers.get('location')).searchParams.get('google_error') === 'unavailable');
}

console.log(problems === 0 ? '\ngoogle-qc: all checks passed\n' : `\ngoogle-qc: ${problems} check(s) failed\n`);
process.exit(problems === 0 ? 0 : 1);
