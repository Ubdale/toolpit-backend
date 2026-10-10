/**
 * The account API, end to end, against a real database.
 *
 * Sends real HTTP requests through the Hono app (app.fetch, exactly what the
 * server runs) with DATABASE_URL pointing at a real Postgres. Creates one
 * throwaway account, walks it through sign-up, five downloads, the refused
 * sixth, sign-out, sign-in and deletion, and leaves nothing behind.
 *
 *   npm run test:api
 */
// It writes to whatever DATABASE_URL names. Say so explicitly, so it is never
// run by accident against the database the live API uses.
if (process.env.API_E2E_ALLOW !== '1') {
  console.error('api-e2e writes to DATABASE_URL. Set API_E2E_ALLOW=1 to run it against a database you intend to use for testing.');
  process.exit(2);
}
// Confirmation emails are captured in memory, never sent.
process.env.MAIL_TRANSPORT = 'capture';
process.env.WEB_ORIGIN = 'http://localhost:3000';

const { app } = await import('../src/app.ts');
const { db } = await import('../src/db.ts');
const { captured } = await import('../src/mail.ts');

/** Sign up, then confirm the captured link, as a person would. */
async function signUpAndConfirm(name, email, password) {
  const started = await call(null, req('/api/auth/signup', { body: { name, email, password, verification: 'link' } }));
  if (started.status !== 202) return started;
  const mail = [...captured].reverse().find((m) => m.to.toLowerCase() === email.toLowerCase());
  const token = /#t=([w-]+)/.exec(mail?.text ?? '')?.[1];
  return call(null, req('/api/auth/verify', { body: { token, password } }));
}

let problems = 0;
const check = (name, ok, detail) => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${ok || detail === undefined ? '' : ` — ${detail}`}`);
  if (!ok) problems += 1;
};

const BASE = 'https://toolpit.app';
const req = (path, { method = 'POST', body, token, cookie } = {}) =>
  new Request(BASE + path, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(cookie ? { cookie } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
const call = async (_route, request) => {
  const response = await app.fetch(request);
  return { status: response.status, body: await response.json(), cookie: response.headers.get('set-cookie') };
};

const email = `e2e-${Date.now()}@toolpit-test.invalid`;
const password = 'a-long-test-password';

try {
  console.log('\nsign up');
  const weak = await call(null, req('/api/auth/signup', { body: { name: 'E2E', email, password: 'short' } }));
  check('a short password is refused', weak.status === 400, JSON.stringify(weak.body));
  const noName = await signUpAndConfirm('', `noname-${email}`, password);
  check('a name is optional', noName.status === 200 && noName.body.account?.name === '', JSON.stringify(noName.body));

  const pending = await call(null, req('/api/auth/signup', { body: { name: 'E2E Tester', email, password, verification: 'link' } }));
  check('sign-up waits for the email: no token yet', pending.status === 202 && !pending.body.token, JSON.stringify(pending.body));
  const up = await signUpAndConfirm('E2E Tester', email, password);
  check('confirming the link signs in', up.status === 200 && typeof up.body.token === 'string', JSON.stringify(up.body));
  check('with 50 tokens', up.body.account?.balance === 50, JSON.stringify(up.body.account));
  check('and sets an httpOnly session cookie for the website', /tp_session=.+HttpOnly/i.test(up.cookie ?? ''), up.cookie);
  const token = up.body.token;

  const again = await call(null, req('/api/auth/signup', { body: { name: 'Second Try', email: email.toUpperCase(), password } }));
  check('the same email cannot sign up twice', again.status === 409, JSON.stringify(again.body));

  console.log('\nthe account');
  const me = await call(null, req('/api/account', { method: 'GET', token }));
  check('the app reads it with its bearer token', me.status === 200 && me.body.account.name === 'E2E Tester', JSON.stringify(me.body));
  const cookieValue = up.cookie.split(';')[0];
  const viaCookie = await call(null, req('/api/account', { method: 'GET', cookie: cookieValue }));
  check('the website reads it with its cookie', viaCookie.status === 200, JSON.stringify(viaCookie.body));
  const anon = await call(null, req('/api/account', { method: 'GET' }));
  check('nobody signed in gets 401', anon.status === 401);
  const forged = await call(null, req('/api/account', { method: 'GET', token: 'not-a-real-token' }));
  check('a made-up token gets 401', forged.status === 401);

  console.log('\nfive downloads, then pay');
  const balances = [];
  for (let i = 0; i < 5; i += 1) balances.push((await call(null, req('/api/account/download', { body: {}, token }))).body.balance);
  check('five downloads leave 40, 30, 20, 10, 0', balances.join(',') === '40,30,20,10,0', balances.join(','));
  const sixth = await call(null, req('/api/account/download', { body: {}, token }));
  check('the sixth is refused with 402', sixth.status === 402, JSON.stringify(sixth.body));
  const anonDownload = await call(null, req('/api/account/download', { body: {} }));
  check('a download without a session is refused', anonDownload.status === 401);

  console.log('\nsign out, sign in');
  await call(null, req('/api/auth/logout', { body: {}, token }));
  const afterOut = await call(null, req('/api/account', { method: 'GET', token }));
  check('after sign-out the old token no longer works', afterOut.status === 401);
  const wrong = await call(null, req('/api/auth/login', { body: { email, password: 'wrong-password' } }));
  check('a wrong password is refused, without saying which part was wrong', wrong.status === 401 && /do not match/.test(wrong.body.error), JSON.stringify(wrong.body));
  const nobody = await call(null, req('/api/auth/login', { body: { email: 'nobody@toolpit-test.invalid', password } }));
  check('an unknown email gets the same answer', nobody.status === 401 && nobody.body.error === wrong.body.error);
  const back = await call(null, req('/api/auth/login', { body: { email: email.toUpperCase(), password } }));
  check('signing in works, whatever the email case', back.status === 200 && back.body.account.balance === 0, JSON.stringify(back.body));

  console.log('\npacks');
  const packs = await call(null, new Request(BASE + '/api/packs'));
  check('four packs from the database', packs.body.packs?.length === 4, JSON.stringify(packs.body));

  console.log('\nwho may call from a browser');
  const preflight = (origin) =>
    app.fetch(
      new Request(BASE + '/api/account', {
        method: 'OPTIONS',
        headers: { origin, 'access-control-request-method': 'GET' },
      }),
    );
  const ours = await preflight('https://toolpit.app');
  check(
    'the website may call with credentials',
    ours.headers.get('access-control-allow-origin') === 'https://toolpit.app' &&
      ours.headers.get('access-control-allow-credentials') === 'true',
  );
  const theirs = await preflight('https://evil.example');
  check('any other site may not', !theirs.headers.get('access-control-allow-origin'), theirs.headers.get('access-control-allow-origin'));

  console.log('\ndelete');
  const del = await call(null, req('/api/account', { method: 'DELETE', token: back.body.token }));
  check('the account deletes itself', del.status === 200);
  const gone = await call(null, req('/api/auth/login', { body: { email, password } }));
  check('and can no longer sign in', gone.status === 401);
} finally {
  // Leave nothing behind, whatever happened above.
  await db().query('delete from users where email in ($1, $2)', [email, `noname-${email}`]);
  await db().query('delete from pending_registrations where email_key in (lower($1), lower($2))', [email, `noname-${email}`]);
  await db().query('delete from email_verifications where email_key in (lower($1), lower($2))', [email, `noname-${email}`]);
  await db().query('delete from auth_failures where email_lower like $1', ['%@toolpit-test.invalid']);
  await db().query(
    `delete from bonus_claims where email_hash in (
       encode(sha256(convert_to(normalised_email($1), 'utf8')), 'hex'),
       encode(sha256(convert_to(normalised_email($2), 'utf8')), 'hex'))`,
    [email, `noname-${email}`],
  );
  await db().end();
}

console.log(problems === 0 ? '\nall assertions passed\n' : `\n${problems} assertion(s) failed\n`);
process.exit(problems === 0 ? 0 : 1);
