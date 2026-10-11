/**
 * Email verification, end to end: the real Hono app on a real Postgres
 * (PGlite), with mail captured in memory. No network, no real inbox.
 *
 *   npm run test:verification
 *
 * Covers the acceptance list: malformed input, invented addresses staying
 * pending, plus/custom/international addresses, link replay/expiry/tamper/
 * resend/change-email, parallel confirmation, delete-and-recreate, the
 * attacker-started registration, rate limits, delivery failure, missing mail
 * configuration, old clients, and the migration of existing accounts.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';

process.env.WEB_ORIGIN = 'http://localhost:3000';
process.env.MAIL_TRANSPORT = 'capture';
process.env.MAIL_CAPTURE_DIR = process.env.MAIL_CAPTURE_DIR ?? '.mail/qc';
delete process.env.RESEND_API_KEY;

const { app } = await import('../src/app.ts');
const { useDatabase } = await import('../src/db.ts');
const { captured } = await import('../src/mail.ts');
const { checkEmail } = await import('../src/email.ts');

let problems = 0;
const check = (name, ok, detail) => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${ok || detail === undefined ? '' : ` — ${detail}`}`);
  if (!ok) problems += 1;
};
const section = (title) => console.log(`\n${title}`);

// ----------------------------------------------------------- database

const migrations = readdirSync('db/migrations').filter((f) => f.endsWith('.sql')).sort();
const pg = await PGlite.create();
// The pre-verification schema first, with accounts on it, then the migration:
// the same order production goes through.
await pg.exec(readFileSync(`db/migrations/${migrations[0]}`, 'utf8'));
const legacy = (await pg.query(`insert into users (email, name, password_hash) values ('Legacy.Person@Example.com', 'Old', 'x') returning id`)).rows[0].id;
const legacyWallet = (await pg.query('select id from wallets where user_id = $1', [legacy])).rows[0].id;
await pg.query(`select credit_tokens($1, 500, 'purchase', 'revenuecat', 'GPA-LEGACY')`, [legacyWallet]);
const { hashToken } = await import('../src/session.ts');
const legacyToken = 'legacy-session-token-for-the-migration-test-0001';
await pg.query(`insert into sessions (token_hash, user_id, expires_at) values ($1, $2, now() + interval '30 days')`, [hashToken(legacyToken), legacy]);
for (const name of migrations.slice(1)) await pg.exec(readFileSync(`db/migrations/${name}`, 'utf8'));

useDatabase({ query: async (sql, params) => ({ rows: (await pg.query(sql, params)).rows }) });
const one = async (sql, params) => (await pg.query(sql, params)).rows[0];
const count = async (sql, params) => Number((await one(sql, params)).n);

// --------------------------------------------------------------- http

let ip = 0;
const call = async (path, { body, token, method = 'POST', from } = {}) => {
  const response = await app.fetch(
    new Request(`https://api.toolpit.test${path}`, {
      method,
      headers: {
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        'x-forwarded-for': from ?? `198.51.100.${(ip += 1) % 250}`,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }),
  );
  return { status: response.status, body: await response.json().catch(() => ({})), cookie: response.headers.get('set-cookie'), headers: response.headers };
};
const signUp = (email, password = 'correct horse battery', extra = {}) =>
  call('/api/auth/signup', { body: { email, password, name: 'QC', verification: 'link', ...extra } });
/** The link secret from the newest captured mail to an address. */
const linkFor = (email) => {
  const mail = [...captured].reverse().find((m) => m.to.toLowerCase() === email.toLowerCase());
  const match = mail && /\/account\/confirm#t=([\w-]+)/.exec(mail.text);
  return match ? match[1] : null;
};
const users = (email) => count('select count(*)::int as n from users where lower(email) = lower($1)', [email]);
const bonusOf = async (email) =>
  Number(
    (await one(
      `select coalesce(sum(e.delta), 0) as n from users u join wallets w on w.user_id = u.id
       join token_entries e on e.wallet_id = w.id where lower(u.email) = lower($1) and e.reason = 'signup_bonus'`,
      [email],
    )).n,
  );

// ============================================================== tests

section('existing accounts survive the migration');
{
  const row = await one('select email_status, email_verified_at from users where id = $1', [legacy]);
  check('marked legacy, not verified, not deleted', row?.email_status === 'legacy' && row.email_verified_at === null, JSON.stringify(row));
  const me = await call('/api/account', { method: 'GET', token: legacyToken });
  check('their session still works', me.status === 200, JSON.stringify(me.body));
  check('balance kept: 50 bonus + 500 bought', me.body.account?.balance === 550, String(me.body.account?.balance));
  check('the API says which kind of account it is', me.body.account?.emailStatus === 'legacy' && me.body.account?.emailVerified === false);
  const spend = await call('/api/account/download', { token: legacyToken, body: {} });
  check('and they can still save', spend.status === 200 && spend.body.balance === 540, JSON.stringify(spend.body));
  const login = await call('/api/auth/login', { body: { email: 'legacy.person@example.com', password: 'wrong' } });
  check('sign-in is still case-insensitive on the whole address', login.status === 401);
}

section('malformed addresses are refused by the API, and nothing is created');
{
  const before = await count('select count(*)::int as n from pending_registrations');
  const bad = [
    ['not a string (number)', 42],
    ['not a string (array)', ['a@example.com']],
    ['not a string (object)', { email: 'a@example.com' }],
    ['null', null],
    ['empty', ''],
    ['only spaces', '   '],
    ['no @', 'person.example.com'],
    ['two @', 'a@b@example.com'],
    ['space inside', 'pe rson@example.com'],
    ['tab inside', 'person@exa\tmple.com'],
    ['control character', 'person\u0007@example.com'],
    ['newline injection', 'person@example.com\nBcc: x@example.com'],
    ['two addresses, comma', 'a@example.com,b@example.com'],
    ['two addresses, semicolon', 'a@example.com;b@example.com'],
    ['quoted local part', '"a b"@example.com'],
    ['IP domain', 'person@[192.0.2.1]'],
    ['no top-level domain', 'person@localhost'],
    ['trailing dot', 'person@example.com.'],
    ['double dot', 'per..son@example.com'],
    ['leading dot', '.person@example.com'],
    ['non-Latin before @', 'ñandú@example.com'],
    ['display name', 'Ann <ann@example.com>'],
    ['too long', `${'a'.repeat(250)}@example.com`],
    ['local part over 64', `${'a'.repeat(65)}@example.com`],
  ];
  for (const [label, email] of bad) {
    const r = await signUp(email);
    check(`${label} → 400`, r.status === 400 && r.body.code === 'invalid_email', `${r.status} ${JSON.stringify(r.body)}`);
  }
  check('no registration was created', (await count('select count(*)::int as n from pending_registrations')) === before);
  check('no user was created', (await count(`select count(*)::int as n from users where email_status = 'verified'`)) === 0);
  check('no mail was sent', captured.length === 0, String(captured.length));
}

section('valid addresses the same rules accept');
{
  const good = [
    ['plus addressing', 'ann+toolpit@gmail.com', 'ann+toolpit@gmail.com'],
    ['custom domain', 'qc@toolpit-test.dev', 'qc@toolpit-test.dev'],
    ['subdomain', 'qc@mail.toolpit-test.dev', 'qc@mail.toolpit-test.dev'],
    ['surrounding spaces trimmed', '  qc@toolpit-test.dev  ', 'qc@toolpit-test.dev'],
    ['uppercase domain lowered', 'QC.Person@Toolpit-Test.DEV', 'QC.Person@toolpit-test.dev'],
    ['international domain, ASCII form', 'qc@bücher.example', 'qc@xn--bcher-kva.example'],
    ['apostrophe', "o'neil@toolpit-test.dev", "o'neil@toolpit-test.dev"],
  ];
  for (const [label, input, stored] of good) {
    const c = checkEmail(input);
    check(`${label}: ${JSON.stringify(input)} → ${stored}`, c.ok && c.email === stored, JSON.stringify(c));
  }
}

section('sign-in validates addresses and refuses unknown inboxes');
{
  for (const email of ['not-an-email', 'a@example.com,b@example.com', 'a b@example.com']) {
    const r = await call('/api/auth/login', { body: { email, password: 'correct horse battery' } });
    check(`invalid login address refused: ${email}`, r.status === 400 && r.body.code === 'invalid_email' && !r.body.token && !r.cookie);
  }
  const r = await call('/api/auth/login', { body: { email: 'never-registered@toolpit-test.dev', password: 'correct horse battery' } });
  check('unknown address cannot sign in', r.status === 401 && !r.body.token && !r.cookie);
}

section('an invented address stays pending: no account, no tokens, no session');
{
  const email = 'invented-person-8133@toolpit-test.dev';
  const r = await signUp(email);
  check('sign-up answers 202 with a pending registration', r.status === 202 && r.body.pending?.email === email, `${r.status} ${JSON.stringify(r.body)}`);
  check('no session token and no cookie', !r.body.token && !r.cookie);
  check('delivery reported as sent (captured)', r.body.pending?.delivery === 'sent');
  check('no user row', (await users(email)) === 0);
  check('no wallet anywhere for it', (await count(`select count(*)::int as n from wallets w join users u on u.id = w.user_id where u.email = $1`, [email])) === 0);
  const login = await call('/api/auth/login', { body: { email, password: 'correct horse battery' } });
  check('sign-in says "confirm your email", with no token', login.status === 403 && login.body.code === 'email_unverified' && !login.body.token, JSON.stringify(login.body));
  check('and gives this device a handle to resend', typeof login.body.pending?.handle === 'string');
  const wrong = await call('/api/auth/login', { body: { email, password: 'not the password' } });
  check('a wrong password gets the ordinary answer (no hint a sign-up exists)', wrong.status === 401 && !wrong.body.pending, JSON.stringify(wrong.body));
  const save = await call('/api/account/download', { body: {} });
  check('saving without an account is refused', save.status === 401);
}

section('the email and the link');
const confirmEmail = 'qc+confirm@toolpit-test.dev';
let firstHandle;
{
  const r = await signUp(confirmEmail);
  firstHandle = r.body.pending.handle;
  const mail = captured.at(-1);
  check('sent to the address typed', mail.to === confirmEmail);
  check('the link is on the configured website, not the request host', mail.text.includes('http://localhost:3000/account/confirm#t='), mail.text);
  check('the secret is after #, so it never reaches a server or a Referer', !/[?&]t=/.test(mail.text));
  check('it explains the bonus comes after confirming', /50-token sign-up bonus is added when the email is confirmed/.test(mail.text));
  const token = linkFor(confirmEmail);
  const stored = await count('select count(*)::int as n from email_verifications where token_hash = $1', [token]);
  check('only a hash of the secret is stored', stored === 0 && (await count('select count(*)::int as n from email_verifications where token_hash = $1', [hashToken(token)])) === 1);
  const raw = JSON.stringify((await pg.query('select * from pending_registrations')).rows);
  check('the handle is stored hashed too', !raw.includes(firstHandle));
}

section('confirming');
{
  const token = linkFor(confirmEmail);
  const seen = await call('/api/auth/verify/inspect', { body: { token } });
  check('opening the link shows the address and uses nothing', seen.body.status === 'active' && seen.body.email === confirmEmail, JSON.stringify(seen.body));
  check('still pending after inspecting', (await users(confirmEmail)) === 0);
  const wrong = await call('/api/auth/verify', { body: { token, password: 'someone elses password' } });
  check('the wrong password does not confirm', wrong.status === 401 && wrong.body.code === 'wrong_password', JSON.stringify(wrong.body));
  check('and leaves the link usable', (await call('/api/auth/verify/inspect', { body: { token } })).body.status === 'active');
  const ok = await call('/api/auth/verify', { body: { token, password: 'correct horse battery' } });
  check('the right password confirms and signs in', ok.status === 200 && typeof ok.body.token === 'string' && /tp_session=/.test(ok.cookie ?? ''), JSON.stringify(ok.body));
  check('the account is verified', ok.body.account?.emailVerified === true && ok.body.account?.emailStatus === 'verified');
  check('with the 50-token bonus', ok.body.account?.balance === 50 && ok.body.bonusGranted === true, JSON.stringify(ok.body.account));
  const replay = await call('/api/auth/verify', { body: { token, password: 'correct horse battery' } });
  check('replaying the link fails safely ("already confirmed")', replay.status === 409 && replay.body.code === 'link_used', JSON.stringify(replay.body));
  check('one account, one bonus', (await users(confirmEmail)) === 1 && (await bonusOf(confirmEmail)) === 50);
  const save = await call('/api/account/download', { token: ok.body.token, body: {} });
  check('the verified account can save', save.status === 200 && save.body.balance === 40, JSON.stringify(save.body));
  const again = await signUp(confirmEmail);
  check('signing up again with that address: already an account', again.status === 409 && again.body.code === 'account_exists');
}

section('tampered and expired links');
{
  const tampered = await call('/api/auth/verify', { body: { token: 'A'.repeat(43), password: 'x' } });
  check('a made-up link is not valid', tampered.status === 400 && tampered.body.code === 'link_invalid', JSON.stringify(tampered.body));
  const short = await call('/api/auth/verify', { body: { token: 'abc', password: 'x' } });
  check('a truncated link is not valid', short.status === 400);
  const notString = await call('/api/auth/verify', { body: { token: { $ne: null }, password: 'x' } });
  check('a non-string token is not valid', notString.status === 400);

  const email = 'expiry@toolpit-test.dev';
  await signUp(email);
  const token = linkFor(email);
  await pg.query(`update email_verifications set expires_at = now() - interval '1 minute' where token_hash = $1`, [hashToken(token)]);
  const late = await call('/api/auth/verify', { body: { token, password: 'correct horse battery' } });
  check('a link older than 30 minutes has expired', late.status === 410 && late.body.code === 'link_expired', JSON.stringify(late.body));
  check('and created nothing', (await users(email)) === 0);
}

section('resend: cooldown, and the old link stops working');
{
  const email = 'resend@toolpit-test.dev';
  const r = await signUp(email);
  const handle = r.body.pending.handle;
  const first = linkFor(email);
  const soon = await call('/api/auth/signup/resend', { body: { handle } });
  check('resending at once is refused with a wait', soon.status === 429 && soon.body.code === 'cooldown' && soon.body.retryAfter > 0 && soon.headers.get('retry-after'), JSON.stringify(soon.body));
  await pg.query(`update pending_registrations set last_sent_at = now() - interval '2 minutes' where email_key = $1`, [email]);
  const again = await call('/api/auth/signup/resend', { body: { handle } });
  check('after the cooldown it sends', again.status === 200 && again.body.pending?.delivery === 'sent', JSON.stringify(again.body));
  const second = linkFor(email);
  check('a different link', second && second !== first);
  const old = await call('/api/auth/verify', { body: { token: first, password: 'correct horse battery' } });
  check('the old link is superseded', old.status === 410 && old.body.code === 'link_superseded', JSON.stringify(old.body));
  const ok = await call('/api/auth/verify', { body: { token: second, password: 'correct horse battery' } });
  check('the new link confirms', ok.status === 200 && ok.body.account?.balance === 50);
  const bogus = await call('/api/auth/signup/resend', { body: { handle: 'not-a-handle' } });
  check('a made-up handle cannot resend', bogus.status === 410);
}

section('change of address');
{
  const typo = 'chnage@toolpit-test.dev';
  const fixed = 'change@toolpit-test.dev';
  const r = await signUp(typo);
  const oldLink = linkFor(typo);
  const moved = await call('/api/auth/signup/change-email', { body: { handle: r.body.pending.handle, email: fixed } });
  check('the address changes and a new email goes to it', moved.status === 200 && moved.body.pending?.email === fixed && !!linkFor(fixed), JSON.stringify(moved.body));
  const old = await call('/api/auth/verify', { body: { token: oldLink, password: 'correct horse battery' } });
  check('the link sent to the old address no longer works', old.status === 410, JSON.stringify(old.body));
  const badChange = await call('/api/auth/signup/change-email', { body: { handle: r.body.pending.handle, email: 'not an email' } });
  check('changing to a malformed address is refused', badChange.status === 400);
  const ok = await call('/api/auth/verify', { body: { token: linkFor(fixed), password: 'correct horse battery' } });
  check('the new inbox confirms, under the new address', ok.status === 200 && ok.body.account?.email === fixed);
  check('nothing was created under the typo', (await users(typo)) === 0);
}

section('two confirmations at once');
{
  const email = 'race@toolpit-test.dev';
  await signUp(email);
  const token = linkFor(email);
  const results = await Promise.all(
    Array.from({ length: 5 }, () => call('/api/auth/verify', { body: { token, password: 'correct horse battery' } })),
  );
  const ok = results.filter((r) => r.status === 200).length;
  check('exactly one succeeds', ok === 1, results.map((r) => r.status).join(','));
  check('the rest are told it was already used', results.filter((r) => r.body.code === 'link_used').length === 4, results.map((r) => r.body.code).join(','));
  check('one account', (await users(email)) === 1);
  check('one bonus', (await bonusOf(email)) === 50, String(await bonusOf(email)));
  const user = (await one('select id from users where email = $1', [email])).id;
  const extra = await one('select grant_signup_bonus($1) as g', [user]);
  check('granting again directly does nothing', extra.g === false && (await bonusOf(email)) === 50);
}

section('one bonus per inbox: delete and recreate, case, plus tags');
{
  const email = 'Recreate@Toolpit-Test.dev';
  await signUp(email);
  const first = await call('/api/auth/verify', { body: { token: linkFor('Recreate@toolpit-test.dev'), password: 'correct horse battery' } });
  check('first account gets 50', first.body.account?.balance === 50);
  await call('/api/account', { method: 'DELETE', token: first.body.token });
  await signUp('recreate@toolpit-test.dev');
  const second = await call('/api/auth/verify', { body: { token: linkFor('recreate@toolpit-test.dev'), password: 'correct horse battery' } });
  check('recreated (different case) account is verified but gets no second bonus', second.status === 200 && second.body.account?.balance === 0 && second.body.bonusGranted === false, JSON.stringify(second.body.account));

  await signUp('bonus.person@gmail.com');
  await call('/api/auth/verify', { body: { token: linkFor('bonus.person@gmail.com'), password: 'correct horse battery' } });
  await signUp('bonusperson+again@gmail.com');
  const gmailAgain = await call('/api/auth/verify', { body: { token: linkFor('bonusperson+again@gmail.com'), password: 'correct horse battery' } });
  check('Gmail: a dotted or +tagged form of the same inbox gets no second bonus', gmailAgain.status === 200 && gmailAgain.body.account?.balance === 0, JSON.stringify(gmailAgain.body.account));
  check('but it is its own account (addresses are not merged)', (await users('bonusperson+again@gmail.com')) === 1);

  await signUp('team@toolpit-test.dev');
  await call('/api/auth/verify', { body: { token: linkFor('team@toolpit-test.dev'), password: 'correct horse battery' } });
  await signUp('team+sales@toolpit-test.dev');
  const custom = await call('/api/auth/verify', { body: { token: linkFor('team+sales@toolpit-test.dev'), password: 'correct horse battery' } });
  check('a custom domain: + is part of a different address, so it is eligible', custom.body.account?.balance === 50, JSON.stringify(custom.body.account));
}

section('someone registers another person\'s address');
{
  const victim = 'owner@toolpit-test.dev';
  const attacker = await signUp(victim, 'attacker chosen password');
  const link = linkFor(victim);
  const ownerTries = await call('/api/auth/verify', { body: { token: link, password: 'the owner does not know it' } });
  check('the inbox owner cannot be made to activate it without the attacker\'s password', ownerTries.status === 401 && (await users(victim)) === 0);
  const cancel = await call('/api/auth/verify/cancel', { body: { token: link } });
  check('"This was not me" cancels it', cancel.status === 200 && (await count('select count(*)::int as n from pending_registrations where email_key = $1', [victim])) === 0);
  const attackerResend = await call('/api/auth/signup/resend', { body: { handle: attacker.body.pending.handle } });
  check('the attacker\'s handle is dead', attackerResend.status === 410);
  const attackerLogin = await call('/api/auth/login', { body: { email: victim, password: 'attacker chosen password' } });
  check('and the attacker cannot sign in', attackerLogin.status === 401, JSON.stringify(attackerLogin.body));
  const cancelled = await call('/api/auth/verify', { body: { token: link, password: 'attacker chosen password' } });
  check('a cancelled link cannot be confirmed later', cancelled.status === 410 && cancelled.body.code === 'link_cancelled', JSON.stringify(cancelled.body));
  const own = await signUp(victim, 'the real owners password');
  const mine = await call('/api/auth/verify', { body: { token: linkFor(victim), password: 'the real owners password' } });
  check('the owner then signs up with their own password', own.status === 202 && mine.status === 200);
  const attackerAfter = await call('/api/auth/login', { body: { email: victim, password: 'attacker chosen password' } });
  check('and the attacker\'s password does not open it', attackerAfter.status === 401);
}

section('a pending sign-up cannot hold an address');
{
  const email = 'squat@toolpit-test.dev';
  await signUp(email, 'squatter password');
  const squatLink = linkFor(email);
  const owner = await signUp(email, 'owner password');
  check('a new sign-up for the address replaces the pending one', owner.status === 202);
  const squat = await call('/api/auth/verify', { body: { token: squatLink, password: 'squatter password' } });
  check('the earlier link is superseded', squat.status === 410, JSON.stringify(squat.body));
  await pg.query(`update pending_registrations set expires_at = now() - interval '1 minute' where email_key = $1`, [email]);
  const later = await call('/api/auth/login', { body: { email, password: 'owner password' } });
  check('an expired registration is not treated as pending', later.status === 401, JSON.stringify(later.body));
}

section('rate limits');
{
  const email = 'limits@toolpit-test.dev';
  const statuses = [];
  for (let i = 0; i < 6; i += 1) statuses.push((await signUp(email)).status);
  check('five emails per address per hour, the sixth refused', statuses.slice(0, 5).every((s) => s === 202) && statuses[5] === 429, statuses.join(','));
  const single = [];
  for (let i = 0; i < 21; i += 1) {
    single.push((await call('/api/auth/signup', { from: '203.0.113.9', body: { email: `one-source-${i}@toolpit-test.dev`, password: 'correct horse battery', verification: 'link' } })).status);
  }
  check('twenty sign-ups per source per hour, then refused', single.slice(0, 20).every((s) => s === 202) && single[20] === 429, single.join(','));
  const spoof = await call('/api/auth/signup', { from: '1.2.3.4, 203.0.113.9', body: { email: 'spoof@toolpit-test.dev', password: 'correct horse battery', verification: 'link' } });
  check('a forged left-hand X-Forwarded-For does not escape it', spoof.status === 429);
}

section('delivery failure is reported, and recoverable');
{
  const email = 'bounce@toolpit-test.dev';
  process.env.MAIL_CAPTURE_FAIL = '1';
  const r = await signUp(email);
  delete process.env.MAIL_CAPTURE_FAIL;
  check('sign-up still answers, saying the email was not sent', r.status === 202 && r.body.pending?.delivery === 'failed', JSON.stringify(r.body));
  check('nothing was activated', (await users(email)) === 0);
  await pg.query(`update pending_registrations set last_sent_at = now() - interval '2 minutes' where email_key = $1`, [email]);
  const retry = await call('/api/auth/signup/resend', { body: { handle: r.body.pending.handle } });
  check('resend works once delivery does', retry.status === 200 && retry.body.pending?.delivery === 'sent');
}

section('no mail service configured');
{
  process.env.MAIL_TRANSPORT = '';
  const before = await count('select count(*)::int as n from pending_registrations');
  const r = await signUp('nomail@toolpit-test.dev');
  process.env.MAIL_TRANSPORT = 'capture';
  check('sign-up says it is unavailable (503), not that an email was sent', r.status === 503 && r.body.code === 'email_unavailable', JSON.stringify(r.body));
  check('and creates nothing', (await count('select count(*)::int as n from pending_registrations')) === before);
  process.env.MAIL_TRANSPORT = 'capture';
  process.env.WEB_ORIGIN = 'https://toolpit.app';
  const prod = await signUp('prodcapture@toolpit-test.dev');
  process.env.WEB_ORIGIN = 'http://localhost:3000';
  check('capture is refused for the real website origin', prod.status === 503, JSON.stringify(prod.body));
}

section('older apps cannot get an account without the email');
{
  const email = 'oldapp@toolpit-test.dev';
  const r = await call('/api/auth/signup', { body: { email, password: 'correct horse battery', name: 'Old' } });
  check('they get an error they will show, telling them to open the link', r.status === 403 && r.body.code === 'verification_required' && /Open it to confirm/.test(r.body.error), JSON.stringify(r.body));
  check('no token, no account', !r.body.token && (await users(email)) === 0);
  const ok = await call('/api/auth/verify', { body: { token: linkFor(email), password: 'correct horse battery' } });
  check('the link works on the website, and then the old app can sign in', ok.status === 200);
  const login = await call('/api/auth/login', { body: { email, password: 'correct horse battery' } });
  check('sign-in after confirming', login.status === 200 && login.body.account?.emailVerified === true);
}

section('password reset uses the same address rules and keeps the secret out of the URL');
{
  const before = captured.length;
  await call('/api/auth/forgot', { body: { email: '  RACE@toolpit-test.dev ' } });
  const mail = captured.at(-1);
  check('a reset email went to the account', captured.length === before + 1 && mail.to === 'race@toolpit-test.dev');
  check('its secret is after #', /\/account#reset=[\w-]+/.test(mail.text) && !/\?reset=/.test(mail.text), mail.text);
  const weird = await call('/api/auth/forgot', { body: { email: ['x'] } });
  check('a non-string address is refused', weird.status === 400);
}

section('the schema itself');
{
  const nulls = await count(`select count(*)::int as n from users where email_status is null`);
  check('every user has a state', nulls === 0);
  const direct = await pg.query(`insert into users (email, name, password_hash) values ('direct@x.dev', '', 'x')`).then(() => 'inserted', (e) => e.message);
  check('an insert that does not say which kind of account fails', direct !== 'inserted', direct);
  const bad = await pg.query(`insert into users (email, name, password_hash, email_status) values ('d@x.dev', '', 'x', 'verified')`).then(() => 'inserted', (e) => e.message);
  check('"verified" needs a verification time', bad !== 'inserted', bad);
  const plain = await count(`select count(*)::int as n from users u join wallets w on w.user_id = u.id
    join token_entries e on e.wallet_id = w.id where e.reason = 'signup_bonus' and u.email_status = 'verified' and u.email_verified_at is null`);
  check('no bonus on an unverified account', plain === 0);
}


section('six-digit inbox codes');
const codeFor = (email) => [...captured].reverse().find(m => m.to === email)?.text.match(/^\d{6}$/m)?.[0];
const codeSignup = (email) => signUp(email, 'correct horse battery', { verification: 'code' });
const verifyCode = (handle, code) => call('/api/auth/verify/code', { body: { handle, code } });
{
  const email = 'code@toolpit-test.dev';
  const started = await codeSignup(email);
  const handle = started.body.pending.handle;
  const code = codeFor(email);
  check('code signup is pending with ten-minute expiry', started.status === 202 && started.body.pending.method === 'code' && started.body.pending.linkMinutes === 10);
  check('mail contains six digits and no confirmation URL', /^\d{6}$/.test(code) && !captured.at(-1).text.includes('/account/confirm'));
  check('code is not stored in plaintext', !(await pg.query('select code_hash from email_verifications where code_hash is not null')).rows.some(r => r.code_hash === code));
  check('pending code account cannot sign in', (await users(email)) === 0);
  check('malformed code rejected', (await verifyCode(handle, '123')).status === 400);
  const wrong = code === '000000' ? '111111' : '000000';
  check('wrong code rejected without creating account', (await verifyCode(handle, wrong)).status === 400 && (await users(email)) === 0);
  check('code cannot be used with another browser handle', (await verifyCode('made-up-handle', code)).status === 410);
  const confirmed = await verifyCode(handle, code);
  check('correct code activates verified account with bonus and session', confirmed.status === 200 && confirmed.body.account.emailVerified && confirmed.body.account.balance === 50 && confirmed.cookie.includes('tp_session='));
  check('used code cannot be replayed', (await verifyCode(handle, code)).status === 410 && (await bonusOf(email)) === 50);
}
{
  const email = 'code-expiry@toolpit-test.dev';
  const r = await codeSignup(email);
  await pg.query("update email_verifications set expires_at = now() - interval '1 second' where email_key = $1", [email]);
  check('expired code rejected', (await verifyCode(r.body.pending.handle, codeFor(email))).body.code === 'code_expired' && (await users(email)) === 0);
}
{
  const email = 'code-resend@toolpit-test.dev';
  const r = await codeSignup(email); const handle = r.body.pending.handle; const first = codeFor(email);
  check('code resend obeys cooldown', (await call('/api/auth/signup/resend', { body: { handle } })).status === 429);
  await pg.query("update pending_registrations set last_sent_at = now() - interval '2 minutes' where email_key = $1", [email]);
  const resent = await call('/api/auth/signup/resend', { body: { handle } });
  check('resend preserves code flow', resent.status === 200 && resent.body.pending.method === 'code');
  const newest = codeFor(email);
  if (newest !== first) check('old code is invalidated by resend', (await verifyCode(handle, first)).status === 400);
  const moved = await call('/api/auth/signup/change-email', { body: { handle, email: 'code-moved@toolpit-test.dev' } });
  check('changing address sends a code to the new address', moved.status === 200 && moved.body.pending.method === 'code' && !!codeFor('code-moved@toolpit-test.dev'));
  check('new inbox code activates only the new address', (await verifyCode(handle, codeFor('code-moved@toolpit-test.dev'))).body.account?.email === 'code-moved@toolpit-test.dev' && (await users(email)) === 0);
}
{
  const email = 'code-attempts@toolpit-test.dev'; const r = await codeSignup(email); const code = codeFor(email);
  const wrong = code === '000000' ? '111111' : '000000';
  const results = await Promise.all(Array.from({ length: 8 }, () => verifyCode(r.body.pending.handle, wrong)));
  check('parallel guesses enforce five-attempt cap', results.filter(r => r.status === 400).length === 5 && results.filter(r => r.body.code === 'code_locked').length === 3);
  check('correct code is blocked once attempts exhausted', (await verifyCode(r.body.pending.handle, code)).body.code === 'code_locked' && (await users(email)) === 0);
}
{
  const email = 'code-race@toolpit-test.dev'; const r = await codeSignup(email); const code = codeFor(email);
  const results = await Promise.all(Array.from({ length: 5 }, () => verifyCode(r.body.pending.handle, code)));
  check('parallel correct codes create one account and one bonus', results.filter(r => r.status === 200).length === 1 && (await users(email)) === 1 && (await bonusOf(email)) === 50);
}


section('signed delivery reports and private registration status');
{
  const { Webhook } = await import('svix');
  const { randomBytes } = await import('node:crypto');
  process.env.RESEND_WEBHOOK_SECRET = 'whsec_' + randomBytes(32).toString('base64');
  const signer = new Webhook(process.env.RESEND_WEBHOOK_SECRET);
  const event = async (mailId, type, eventTime, { bad = false, stale = false } = {}) => {
    const id = 'msg_' + randomBytes(10).toString('hex');
    const date = new Date(Date.now() - (stale ? 600000 : 0));
    const payload = JSON.stringify({ type, created_at: new Date(eventTime).toISOString(), data: { email_id: mailId } });
    const response = await app.fetch(new Request('https://api.toolpit.test/api/webhooks/resend', {
      method: 'POST', headers: { 'content-type': 'application/json', 'svix-id': id, 'svix-timestamp': String(Math.floor(date.getTime()/1000)), 'svix-signature': bad ? 'v1,bogus' : signer.sign(id, date, payload) }, body: payload,
    }));
    return { status: response.status, body: await response.json() };
  };
  const email = 'delivery@toolpit-test.dev';
  const r = await codeSignup(email); const handle = r.body.pending.handle;
  const mail = captured.at(-1); const originalId = mail.id;
  const status = () => call('/api/auth/signup/delivery', { body: { handle } });
  check('provider acceptance starts with delivery pending', (await status()).body.delivery === 'pending');
  check('invented handle cannot expose delivery', (await call('/api/auth/signup/delivery', { body: { handle: 'fake' } })).status === 410);
  check('forged report rejected', (await event(mail.id, 'email.bounced', Date.now(), { bad: true })).status === 401 && (await status()).body.delivery === 'pending');
  check('stale signed request rejected', (await event(mail.id, 'email.bounced', Date.now(), { stale: true })).status === 401);
  const time = Date.now();
  check('valid signed bounce accepted', (await event(mail.id, 'email.bounced', time)).status === 200);
  check('recipient rejection becomes visible without creating account', (await status()).body.delivery === 'bounced' && (await users(email)) === 0);
  await event(mail.id, 'email.delivered', time - 1000);
  await event(mail.id, 'email.delivery_delayed', time + 1000);
  check('out-of-order events cannot undo a bounce', (await status()).body.delivery === 'bounced');
  await pg.query("update pending_registrations set last_sent_at = now() - interval '2 minutes' where email_key = $1", [email]);
  await call('/api/auth/signup/resend', { body: { handle } });
  check('resend watches only the new message', (await status()).body.delivery === 'pending');
  await event(originalId, 'email.bounced', time + 2000);
  check('old message rejection cannot affect a new code', (await status()).body.delivery === 'pending');
  await event(captured.at(-1).id, 'email.delivered', time + 2000);
  check('successful delivery becomes visible', (await status()).body.delivery === 'delivered');
  check('correct inbox code still activates account', (await verifyCode(handle, codeFor(email))).status === 200);
  check('finished registration exposes no status', (await status()).status === 410);
  // Webhooks can race the POST /emails response. Save the event before attaching the receipt.
  await event('mail-before-receipt', 'email.bounced', time);
  const early = await codeSignup('early-delivery@toolpit-test.dev');
  await pg.query("update email_verifications set mail_id = 'mail-before-receipt' where email_key = 'early-delivery@toolpit-test.dev' and state = 'active'");
  check('delivery reports arriving before receipt storage are retained', (await call('/api/auth/signup/delivery', { body: { handle: early.body.pending.handle } })).body.delivery === 'bounced');
  delete process.env.RESEND_WEBHOOK_SECRET;
}

console.log(problems === 0 ? '\nverification-qc: all checks passed\n' : `\nverification-qc: ${problems} check(s) failed\n`);
process.exit(problems === 0 ? 0 : 1);
