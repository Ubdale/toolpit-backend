/**
 * Editing your own account: name, password, and what the summary reports.
 * Through the real app on PGlite.
 *
 *   npm run test:profile
 */
import { readdirSync, readFileSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';

process.env.NODE_ENV = 'production';

const { app } = await import('../src/app.ts');
const { useDatabase } = await import('../src/db.ts');
const { hashToken } = await import('../src/session.ts');
const { hashPassword } = await import('../src/password.ts');

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

async function makeUser(email, passwordHash) {
  const id = (await one(`insert into users (email, name, password_hash, email_status, email_verified_at) values ($1, 'Old Name', $2, 'verified', now()) returning id`, [email, passwordHash])).id;
  const tokens = [];
  for (let i = 0; i < 2; i += 1) {
    const token = `profile-qc-${email}-${i}-0000000000000000`;
    await pg.query(`insert into sessions (token_hash, user_id, expires_at) values ($1, $2, now() + interval '1 day')`, [hashToken(token), id]);
    tokens.push(token);
  }
  return { id, tokens };
}

const call = async (path, token, body) => {
  const response = await app.fetch(
    new Request(`https://api.toolpit.test${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  );
  return { status: response.status, body: await response.json().catch(() => ({})) };
};

const person = await makeUser('person@toolpit-test.dev', await hashPassword('old-password-1'));
const googleOnly = await makeUser('g@gmail.com', '!google');
await pg.query(`insert into user_identities (provider, subject, user_id, email) values ('google', 'g-1', $1, 'g@gmail.com')`, [googleOnly.id]);

console.log('\nthe summary');
{
  const a = (await call('/api/account', person.tokens[0])).body.account;
  check('reports when the account was made', typeof a.createdAt === 'string' && !Number.isNaN(Date.parse(a.createdAt)), JSON.stringify(a));
  check('a password account: hasPassword true, google false', a.hasPassword === true && a.google === false);
  const g = (await call('/api/account', googleOnly.tokens[0])).body.account;
  check('a Google-only account: hasPassword false, google true', g.hasPassword === false && g.google === true, JSON.stringify(g));
}

console.log('\nthe name');
{
  const r = await call('/api/account/profile', person.tokens[0], { name: '  New\u0000  Name\n ' });
  check('is saved, tidied (control characters and extra spaces gone)', r.status === 200 && r.body.account.name === 'New Name', JSON.stringify(r.body));
  check('can be cleared', (await call('/api/account/profile', person.tokens[0], { name: '' })).body.account?.name === '');
  check('over 80 characters is refused', (await call('/api/account/profile', person.tokens[0], { name: 'x'.repeat(81) })).status === 400);
  check('a non-string is refused', (await call('/api/account/profile', person.tokens[0], { name: 42 })).status === 400);
  check('nobody signed in cannot change it (401)', (await call('/api/account/profile', null, { name: 'Hacker' })).status === 401);
}

console.log('\nthe password');
{
  const wrong = await call('/api/account/password', person.tokens[0], { current: 'not-it', password: 'new-password-2' });
  check('a wrong current password is refused (400, not 401)', wrong.status === 400 && wrong.body.code === 'wrong_password', JSON.stringify(wrong));
  const short = await call('/api/account/password', person.tokens[0], { current: 'old-password-1', password: 'short' });
  check('a new password under 8 characters is refused', short.status === 400 && short.body.code === 'weak_password');
  const ok = await call('/api/account/password', person.tokens[0], { current: 'old-password-1', password: 'new-password-2' });
  check('the right current password changes it', ok.status === 200 && ok.body.account?.hasPassword === true, JSON.stringify(ok.body));
  check('this device stays signed in', (await call('/api/account', person.tokens[0])).status === 200);
  check('the other device is signed out', (await call('/api/account', person.tokens[1])).status === 401);
  const login = await app.fetch(new Request('https://api.toolpit.test/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'person@toolpit-test.dev', password: 'new-password-2' }) }));
  check('the new password signs in', login.status === 200);
  const oldLogin = await app.fetch(new Request('https://api.toolpit.test/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'person@toolpit-test.dev', password: 'old-password-1' }) }));
  check('the old one does not', oldLogin.status === 401);

  const g = await call('/api/account/password', googleOnly.tokens[0], { current: '', password: 'new-password-2' });
  check('a Google-only account is told to set one by email (409 no_password)', g.status === 409 && g.body.code === 'no_password', JSON.stringify(g));

  for (let i = 0; i < 10; i += 1) await call('/api/account/password', person.tokens[0], { current: 'guess', password: 'new-password-3' });
  const limited = await call('/api/account/password', person.tokens[0], { current: 'new-password-2', password: 'new-password-3' });
  check('ten wrong guesses lock it for 15 minutes, even with the right one', limited.status === 429, String(limited.status));
}

console.log(problems === 0 ? '\nprofile-qc: all checks passed\n' : `\nprofile-qc: ${problems} check(s) failed\n`);
process.exit(problems === 0 ? 0 : 1);
