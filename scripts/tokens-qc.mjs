/**
 * The accounts and token ledger, run against a real Postgres.
 *
 * PGlite is Postgres compiled to WebAssembly, in process: the same plpgsql,
 * constraints, triggers and row locks as Neon. Schema that has never executed
 * is a guess, and these guarantees - a balance cannot go negative, a retried
 * webhook cannot pay twice, the sign-up bonus comes once per inbox - are the
 * kind that look obviously true in SQL and are not.
 *
 *   node scripts/tokens-qc.mjs
 */
import { readdirSync, readFileSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';

let problems = 0;
const check = (name, ok, detail) => {
  if (ok) console.log(`  PASS  ${name}`);
  else {
    problems += 1;
    console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
  }
};

async function rejects(fn, fragment) {
  try {
    await fn();
    return { threw: false, message: '' };
  } catch (error) {
    const message = String(error?.message ?? error);
    return { threw: true, message, matched: message.toLowerCase().includes(fragment.toLowerCase()) };
  }
}

const db = await PGlite.create();
const dir = 'db/migrations';
for (const name of readdirSync(dir).filter((f) => f.endsWith('.sql')).sort()) {
  try {
    await db.exec(readFileSync(`${dir}/${name}`, 'utf8'));
  } catch (error) {
    console.log(`\n${name} does not apply: ${error.message}\n`);
    process.exit(1);
  }
}
console.log('\nthe migrations apply to a real Postgres');
check('schema, functions and trigger all execute', true);

const one = async (sql, params) => (await db.query(sql, params)).rows[0];
const signUp = async (email) =>
  (await one(`insert into users (email, name, password_hash) values ($1, 'Test', 'x') returning id`, [email])).id;
const balanceOf = async (user) => Number((await one('select balance from wallets where user_id = $1', [user])).balance);
const walletOf = async (user) => (await one('select id from wallets where user_id = $1', [user])).id;

console.log('\na new account gets a wallet and 50 tokens');
const alice = await signUp('alice@example.com');
const wallet = await walletOf(alice);
check('the sign-up trigger created a wallet with 50', (await balanceOf(alice)) === 50, String(await balanceOf(alice)));
const bonus = await one(`select delta, reason from token_entries where wallet_id = $1`, [wallet]);
check('recorded in the ledger as a sign-up bonus', Number(bonus.delta) === 50 && bonus.reason === 'signup_bonus');

const dupEmail = await rejects(() => signUp('ALICE@example.com'), 'unique');
check('an email can only have one account, whatever its case', dupEmail.threw && dupEmail.matched, dupEmail.message);

console.log('\nfifty tokens is five downloads, then pay');
{
  const balances = [];
  for (let i = 0; i < 5; i += 1) balances.push(Number((await one('select consume_download($1) as r', [alice])).r.balance));
  check('five downloads charge ten each', balances.join(',') === '40,30,20,10,0', balances.join(','));
  const sixth = await rejects(() => db.query('select consume_download($1)', [alice]), 'insufficient');
  check('the sixth is refused', sixth.threw && sixth.matched, sixth.message);
  check('and the refusal costs nothing', (await balanceOf(alice)) === 0);
  const ghost = await rejects(() => db.query('select consume_download($1)', ['00000000-0000-0000-0000-000000000000']), 'no such wallet');
  check('a user with no wallet cannot download', ghost.threw && ghost.matched, ghost.message);
}

console.log('\ncrediting is the consequence of a payment, and retries are free');
{
  await db.query('select credit_tokens($1, $2, $3, $4, $5)', [wallet, 500, 'purchase', 'revenuecat', 'GPA-1']);
  await db.query('select credit_tokens($1, $2, $3, $4, $5)', [wallet, 500, 'purchase', 'revenuecat', 'GPA-1']);
  await db.query('select credit_tokens($1, $2, $3, $4, $5)', [wallet, 500, 'purchase', 'revenuecat', 'GPA-1']);
  check('three deliveries of one purchase grant 500, not 1500', (await balanceOf(alice)) === 500, String(await balanceOf(alice)));
  const n = await one(`select count(*)::int as n from token_entries where provider_txn_id = 'GPA-1'`);
  check('and leave exactly one ledger entry', n.n === 1, String(n.n));
  const neg = await rejects(() => db.query('select credit_tokens($1, $2, $3)', [wallet, -5, 'promo']), 'positive');
  check('a negative credit is refused', neg.threw && neg.matched, neg.message);
  const spendAsCredit = await rejects(() => db.query('select credit_tokens($1, $2, $3)', [wallet, 5, 'spend']), 'only credits');
  check('credit_tokens cannot record a spend', spendAsCredit.threw && spendAsCredit.matched, spendAsCredit.message);
}

console.log('\nrefunds take back what is left, never more');
{
  const bob = await signUp('bob@example.com');
  const bw = await walletOf(bob);
  await db.query('select credit_tokens($1, $2, $3, $4, $5)', [bw, 100, 'purchase', 'play', 'B-1']);
  for (let i = 0; i < 14; i += 1) await db.query('select consume_download($1)', [bob]);
  const left = await one('select revoke_tokens($1, $2, $3, $4, $5) as b', [bw, 100, 'chargeback', 'play', 'B-1:refund']);
  check('the wallet is emptied rather than driven negative', Number(left.b) === 0, String(left.b));
  const e = await one(`select delta from token_entries where provider_txn_id = 'B-1:refund'`);
  check('the entry records what was actually taken', Number(e.delta) === -10, String(e?.delta));
}

console.log('\none bonus per inbox, even across deleted accounts');
{
  const first = await signUp('Sam.Smith+promo@Gmail.com');
  check('the first account gets the bonus', (await balanceOf(first)) === 50);
  const alias = await signUp('samsmith@googlemail.com');
  check('the same Gmail inbox under another spelling gets none', (await balanceOf(alias)) === 0, String(await balanceOf(alias)));

  await db.query('delete from users where id = $1', [first]);
  const gone = await one('select count(*)::int as n from wallets where user_id = $1', [first]);
  check('deleting the account removes its wallet', gone.n === 0);
  const again = await signUp('sam.smith@gmail.com');
  check('signing up again with that inbox gets no second bonus', (await balanceOf(again)) === 0, String(await balanceOf(again)));
  const other = await signUp('sam+x@example.org');
  check('a different inbox still does', (await balanceOf(other)) === 50);

  const ow = await walletOf(other);
  const dup = await rejects(
    () => db.query(`insert into token_entries (wallet_id, delta, reason, balance_after) values ($1, 50, 'signup_bonus', 100)`, [ow]),
    'unique',
  );
  check('a second bonus entry on one wallet is refused by an index', dup.threw && dup.matched, dup.message);
  const hashes = await one(`select count(*)::int as n from bonus_claims where email_hash !~ '^[0-9a-f]{64}$'`);
  check('claims are stored as hashes, never as addresses', hashes.n === 0, String(hashes.n));
}

console.log('\ndeleting a user takes their sessions with them');
{
  const carol = await signUp('carol@example.com');
  await db.query(`insert into sessions (token_hash, user_id, expires_at) values ('h1', $1, now() + interval '1 day')`, [carol]);
  await db.query('delete from users where id = $1', [carol]);
  const n = await one(`select count(*)::int as n from sessions where token_hash = 'h1'`);
  check('no session outlives its account', n.n === 0, String(n.n));
}

console.log('\nthe cached balance always equals the ledger');
{
  const rows = await db.query(
    `select w.id, w.balance, coalesce(sum(e.delta), 0) as summed
     from wallets w left join token_entries e on e.wallet_id = w.id group by w.id, w.balance`,
  );
  const drift = rows.rows.filter((r) => Number(r.balance) !== Number(r.summed));
  check('no wallet has drifted from its entries', drift.length === 0, JSON.stringify(drift));
}

console.log('\nnothing here can hold a document');
{
  const cols = await db.query(`select table_name, column_name from information_schema.columns where table_schema = 'public'`);
  const suspicious = cols.rows.filter((c) => /file|document|content|text_extract|path|upload|image/i.test(c.column_name));
  check('no column names anything file-shaped', suspicious.length === 0, JSON.stringify(suspicious));
  const plain = cols.rows.filter((c) => c.column_name === 'password');
  check('there is no plain password column', plain.length === 0);
}

console.log('\nprices live in the database');
{
  const packs = await db.query('select tokens, price_cents, store_product_id from token_packs order by sort_order');
  check(
    'four packs at the launch prices',
    packs.rows.map((p) => `${p.tokens}/${p.price_cents}`).join(' ') === '30/99 100/299 500/999 1500/2499',
    packs.rows.map((p) => `${p.tokens}/${p.price_cents}`).join(' '),
  );
  check('each sold under a store product id', packs.rows.every((p) => p.store_product_id === `toolpit.tokens.${p.tokens}`));
}

console.log(problems === 0 ? '\nall assertions passed\n' : `\n${problems} assertion(s) failed\n`);
await db.close();
process.exit(problems === 0 ? 0 : 1);
