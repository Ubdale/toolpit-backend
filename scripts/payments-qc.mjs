/**
 * The payment path, from webhook bytes to a balance in Postgres.
 *
 * Two things are being tested, and the second is the one that matters.
 *
 * First, that a legitimate purchase credits the right wallet once. Easy, and
 * easy to get right by accident.
 *
 * Second, that everything else does not. A forged signature, a replayed
 * delivery, a tampered amount, an unknown event type, a refund for a purchase
 * that was already spent - these are the cases a payment integration is judged
 * by, and they are all cases where "it worked when I tried it" means nothing.
 *
 * Runs the real migrations against PGlite (Postgres 18 in WebAssembly) and the
 * real mock provider, whose signature verification is genuine HMAC-SHA256 in
 * constant time rather than a stub that returns true. A signature check tested
 * against something that always agrees is not tested.
 *
 *   node scripts/payments-qc.mjs
 */
import { readdirSync, readFileSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';

import { fulfil } from '../src/payments/fulfil.ts';
import { mockProvider, signMockWebhook } from '../src/payments/mock.ts';
import { parseRevenueCatWebhook } from '../src/payments/revenuecat.ts';
import { WebhookVerificationError } from '../src/payments/provider.ts';

let problems = 0;
const check = (name, ok, detail) => {
  if (ok) console.log(`  PASS  ${name}`);
  else {
    problems += 1;
    console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
  }
};

const db = await PGlite.create();
for (const name of readdirSync('db/migrations').filter((f) => f.endsWith('.sql')).sort()) {
  await db.exec(readFileSync(`db/migrations/${name}`, 'utf8'));
}

const one = async (sql, params) => (await db.query(sql, params)).rows[0];
const user = (await one(`insert into users (email, name, password_hash) values ('p@example.com', 'P', 'x') returning id`)).id;
const wallet = (await one('select id from wallets where user_id = $1', [user])).id;

/**
 * The ledger `fulfil` writes to, over PGlite.
 *
 * The production one (lib/server/ledger.ts) makes the same calls through the
 * server's own Postgres connection. Both reach the same plpgsql, which is where the
 * guarantees under test actually live.
 */
const ledger = {
  async packById(id) {
    return (await one('select id, tokens from token_packs where id = $1 and active', [id])) ?? null;
  },
  async packByStoreProduct(productId) {
    return (await one('select id, tokens from token_packs where store_product_id = $1', [productId])) ?? null;
  },
  async walletForUser(userId) {
    return (await one('select id from wallets where user_id = $1', [userId]))?.id ?? null;
  },
  async walletExists(walletId) {
    return Boolean(await one('select id from wallets where id = $1', [walletId]));
  },
  async grantedBy(provider, txn) {
    const row = await one('select delta from token_entries where provider = $1 and provider_txn_id = $2', [provider, txn]);
    return row ? Number(row.delta) : null;
  },
  async credit(walletId, tokens, provider, txn) {
    return Number((await one('select credit_tokens($1, $2, $3, $4, $5) as b', [walletId, tokens, 'purchase', provider, txn])).b);
  },
  async revoke(walletId, tokens, reason, provider, txn) {
    return Number((await one('select revoke_tokens($1, $2, $3, $4, $5) as b', [walletId, tokens, reason, provider, txn])).b);
  },
};

/** The web webhook route, minus HTTP: verify, then fulfil. */
async function handleWebhook(body, signature) {
  const event = await mockProvider.parseWebhook({
    body,
    headers: { 'x-mock-signature': signature },
  });
  return fulfil(event, 'mock', ledger);
}

const purchase = (txn, packId = 'tokens_500') =>
  JSON.stringify({
    type: 'purchase.completed',
    transaction_id: txn,
    wallet_id: wallet,
    pack_id: packId,
    amount_cents: 999,
    currency: 'usd',
  });

console.log('\na signed purchase credits the wallet');
{
  const body = purchase('txn_001');
  const result = await handleWebhook(body, signMockWebhook(body));
  check('the webhook is handled', result.handled === true, JSON.stringify(result));
  check('500 tokens are granted', result.granted === 500 && result.balance === 550, JSON.stringify(result));
}

console.log('\nan unsigned or forged webhook grants nothing');
{
  const body = purchase('txn_forged');

  let threw = null;
  try {
    await handleWebhook(body, 'deadbeef');
  } catch (error) {
    threw = error;
  }
  check('a wrong signature throws', threw instanceof WebhookVerificationError, String(threw));

  let threwEmpty = null;
  try {
    await handleWebhook(body, '');
  } catch (error) {
    threwEmpty = error;
  }
  check('a missing signature throws', threwEmpty instanceof WebhookVerificationError, String(threwEmpty));

  const w = await one('select balance from wallets where id = $1', [wallet]);
  check('and the balance is untouched', Number(w.balance) === 550, String(w.balance));
}

console.log('\na tampered body is rejected, not re-signed');
{
  // Signed honestly, then edited: the classic replay-with-edits attack.
  const body = purchase('txn_tamper', 'tokens_100');
  const signature = signMockWebhook(body);
  const tampered = body.replace('tokens_100', 'tokens_1500');

  let threw = null;
  try {
    await handleWebhook(tampered, signature);
  } catch (error) {
    threw = error;
  }
  check('editing the pack after signing invalidates it', threw instanceof WebhookVerificationError, String(threw));

  const w = await one('select balance from wallets where id = $1', [wallet]);
  check('no tokens granted', Number(w.balance) === 550, String(w.balance));
}

console.log('\nthe amount comes from our catalogue, not the payload');
{
  // A correctly signed webhook that claims a different price. Even signed, the
  // figure it carries must not decide the grant.
  const body = JSON.stringify({
    type: 'purchase.completed',
    transaction_id: 'txn_cheap',
    wallet_id: wallet,
    pack_id: 'tokens_100',
    amount_cents: 1, // claims to have paid one cent
    currency: 'usd',
  });
  const result = await handleWebhook(body, signMockWebhook(body));
  check('the pack grants its catalogue tokens', result.granted === 100, JSON.stringify(result));
  check('not something derived from the claimed amount', result.balance === 650, String(result.balance));
}

console.log('\nretries are free');
{
  const body = purchase('txn_retry');
  const first = await handleWebhook(body, signMockWebhook(body));
  const second = await handleWebhook(body, signMockWebhook(body));
  const third = await handleWebhook(body, signMockWebhook(body));

  check('three identical deliveries all succeed', [first, second, third].every((r) => r.handled), '');
  check('and the balance moves once', third.balance === 1150, `${first.balance} ${second.balance} ${third.balance}`);

  const n = await one(`select count(*)::int as n from token_entries where provider_txn_id = 'txn_retry'`);
  check('leaving one ledger entry', n.n === 1, String(n.n));
}

console.log('\nunknown events are acknowledged, not retried forever');
{
  const body = JSON.stringify({ type: 'customer.updated', id: 'evt_1' });
  const result = await handleWebhook(body, signMockWebhook(body));
  check('an unhandled type does not throw', result.handled === false, JSON.stringify(result));
  check('and says why', typeof result.reason === 'string' && result.reason.includes('customer.updated'), result.reason);
}

console.log('\na refund takes back what is there');
{
  const spendable = await one('select balance from wallets where id = $1', [wallet]);
  check('balance before the refund', Number(spendable.balance) === 1150, String(spendable.balance));

  const body = JSON.stringify({
    type: 'purchase.refunded',
    transaction_id: 'txn_001_refund',
    original_transaction_id: 'txn_001',
    wallet_id: wallet,
  });
  const result = await handleWebhook(body, signMockWebhook(body));
  check('the refund is handled', result.handled === true, JSON.stringify(result));
  check('500 tokens come back out', result.balance === 650, String(result.balance));

  // And a retried refund must not take them twice.
  const again = await handleWebhook(body, signMockWebhook(body));
  check('a repeated refund changes nothing', again.balance === 650, String(again.balance));
}

console.log('\na refund after the tokens are spent empties rather than fails');
{
  // Spend down to less than the refund is worth.
  for (let i = 0; i < 63; i += 1) await db.query('select consume_download($1)', [user]);
  const before = await one('select balance from wallets where id = $1', [wallet]);
  check('20 tokens left', Number(before.balance) === 20, String(before.balance));

  const body = JSON.stringify({
    type: 'purchase.chargeback',
    transaction_id: 'txn_retry_cb',
    original_transaction_id: 'txn_retry',
    wallet_id: wallet,
  });
  const result = await handleWebhook(body, signMockWebhook(body));
  check('the wallet empties instead of going negative', result.balance === 0, String(result.balance));

  const w = await one('select balance from wallets where id = $1', [wallet]);
  check('and the stored balance agrees', Number(w.balance) === 0, String(w.balance));
}

console.log('\napp store purchases, via RevenueCat');
{
  const SECRET = 'rc-test-secret-0123456789abcdef';
  const buyer = (await one(`insert into users (email, name, password_hash) values ('store@example.com', 'S', 'x') returning id`)).id;
  const rcEvent = (event) => JSON.stringify({ api_version: '1.0', event });
  const deliver = async (body, authorization = SECRET, options = {}) => {
    const event = parseRevenueCatWebhook({ body, headers: { Authorization: authorization } }, SECRET);
    return fulfil(event, 'revenuecat', ledger, options);
  };
  const buy = (txn, product = 'toolpit.tokens.100', environment = 'PRODUCTION') =>
    rcEvent({
      type: 'NON_RENEWING_PURCHASE',
      app_user_id: buyer,
      product_id: product,
      transaction_id: txn,
      environment,
      price_in_purchased_currency: 0.01,
      currency: 'USD',
    });
  const balanceOf = async () =>
    Number((await one('select balance from wallets where user_id = $1', [buyer])).balance);

  check('a new store customer starts with the 50 bonus', (await balanceOf()) === 50, String(await balanceOf()));

  const bought = await deliver(buy('GPA.1111'));
  check('a Play purchase of toolpit.tokens.100 grants 100', bought.handled && bought.granted === 100, JSON.stringify(bought));
  check('into the account RevenueCat names', (await balanceOf()) === 150, String(await balanceOf()));

  await deliver(buy('GPA.1111'));
  await deliver(buy('GPA.1111'));
  check('RevenueCat retrying the same purchase changes nothing', (await balanceOf()) === 150, String(await balanceOf()));

  let wrong = null;
  try {
    await deliver(buy('GPA.2222'), 'not-the-secret');
  } catch (error) {
    wrong = error;
  }
  check('a webhook without our secret is refused', wrong instanceof WebhookVerificationError, String(wrong));

  let none = null;
  try {
    parseRevenueCatWebhook({ body: buy('GPA.3333'), headers: {} }, SECRET);
  } catch (error) {
    none = error;
  }
  check('so is one with no Authorization at all', none instanceof WebhookVerificationError, String(none));

  let unconfigured = null;
  try {
    parseRevenueCatWebhook({ body: buy('GPA.3334'), headers: { Authorization: '' } }, '');
  } catch (error) {
    unconfigured = error;
  }
  check('and a server with no secret configured trusts nothing', unconfigured instanceof WebhookVerificationError, String(unconfigured));
  check('none of those moved the balance', (await balanceOf()) === 150, String(await balanceOf()));

  const bearer = await deliver(buy('GPA.4444', 'toolpit.tokens.30'), `Bearer ${SECRET}`);
  check('the secret sent as a bearer token is accepted too', bearer.handled && bearer.granted === 30, JSON.stringify(bearer));

  const sandbox = await deliver(buy('GPA.5555', 'toolpit.tokens.1500', 'SANDBOX'));
  check('a sandbox purchase grants nothing by default', sandbox.handled === false, JSON.stringify(sandbox));
  const sandboxOn = await deliver(buy('GPA.5556', 'toolpit.tokens.30', 'SANDBOX'), SECRET, { acceptSandbox: true });
  check('unless the server is told to accept them, for testing', sandboxOn.handled && sandboxOn.granted === 30, JSON.stringify(sandboxOn));

  const unknown = await deliver(buy('GPA.6666', 'toolpit.tokens.999999'));
  check('a product we do not sell grants nothing', unknown.handled === false, JSON.stringify(unknown));

  const anonymous = await deliver(
    rcEvent({ type: 'NON_RENEWING_PURCHASE', app_user_id: '$RCAnonymousID:abc', product_id: 'toolpit.tokens.100', transaction_id: 'GPA.7777' }),
  );
  check('a purchase with no Toolpit account id is acknowledged, not applied', anonymous.handled === false, JSON.stringify(anonymous));

  const aliased = await deliver(
    rcEvent({
      type: 'NON_RENEWING_PURCHASE',
      app_user_id: '$RCAnonymousID:def',
      aliases: ['$RCAnonymousID:def', buyer],
      product_id: 'toolpit.tokens.30',
      transaction_id: 'GPA.8888',
    }),
  );
  check('but one whose aliases include the account is credited to it', aliased.handled && aliased.granted === 30, JSON.stringify(aliased));
  check('balance after the store purchases', (await balanceOf()) === 240, String(await balanceOf()));

  const test = await deliver(rcEvent({ type: 'TEST', app_user_id: buyer }));
  check('RevenueCat test events are acknowledged and ignored', test.handled === false, JSON.stringify(test));

  const refund = rcEvent({
    type: 'CANCELLATION',
    cancel_reason: 'CUSTOMER_SUPPORT',
    app_user_id: buyer,
    product_id: 'toolpit.tokens.100',
    transaction_id: 'GPA.1111',
  });
  const refunded = await deliver(refund);
  check('a store refund takes back what that purchase granted', refunded.handled && refunded.revoked === 100, JSON.stringify(refunded));
  await deliver(refund);
  check('once, however often it is delivered', (await balanceOf()) === 140, String(await balanceOf()));

  const notRefund = await deliver(
    rcEvent({ type: 'CANCELLATION', cancel_reason: 'UNSUBSCRIBE', app_user_id: buyer, transaction_id: 'GPA.4444' }),
  );
  check('a cancellation that is not a refund takes nothing', notRefund.handled === false && (await balanceOf()) === 140, JSON.stringify(notRefund));
}

console.log('\nthe ledger still reconciles after all of that');
{
  const rows = await db.query(
    `select w.id, w.balance, coalesce(sum(e.delta), 0) as summed
     from wallets w left join token_entries e on e.wallet_id = w.id
     group by w.id, w.balance`,
  );
  const drift = rows.rows.filter((r) => Number(r.balance) !== Number(r.summed));
  check('every balance equals the sum of its entries', drift.length === 0, JSON.stringify(drift));

  const history = await db.query(
    `select reason, delta from token_entries where wallet_id = $1 order by created_at`,
    [wallet],
  );
  check('and the history is complete enough to explain it', history.rows.length >= 6, String(history.rows.length));
}

console.log('\nthe mock cannot run in production');
{
  const original = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = 'production';
    check('it reports itself unconfigured', mockProvider.isConfigured() === false);
    let threw = null;
    try {
      await mockProvider.parseWebhook({ body: '{}', headers: {} });
    } catch (error) {
      threw = error;
    }
    check('and refuses to verify anything', threw instanceof WebhookVerificationError, String(threw));
  } finally {
    process.env.NODE_ENV = original;
  }
}

console.log(problems === 0 ? '\nall assertions passed\n' : `\n${problems} assertion(s) failed\n`);
await db.close();
process.exit(problems === 0 ? 0 : 1);
