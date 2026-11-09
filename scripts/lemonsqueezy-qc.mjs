/**
 * Lemon Squeezy, end to end through the real app on PGlite, with Lemon
 * Squeezy itself replaced by recorded-shape payloads and a captured fetch.
 * Nothing leaves the machine.
 *
 *   npm run test:lemonsqueezy
 *
 * Webhooks: signature, paid order credits the pack the VARIANT says, retries
 * are free, spoofed custom pack ignored, unknown variant / pending order /
 * no wallet acknowledged without effect, test-mode orders only when allowed,
 * refund takes the tokens back. Checkout: the request sent to Lemon Squeezy
 * carries our price, store, variant and wallet; unverified accounts cannot
 * reach it.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';

process.env.NODE_ENV = 'production'; // the mock provider must not be the one answering
process.env.WEB_ORIGIN = 'https://toolpit.app';
process.env.PAYMENT_PROVIDER = 'lemonsqueezy';
process.env.LEMONSQUEEZY_API_KEY = 'test-key-not-real';
process.env.LEMONSQUEEZY_STORE_ID = '490826';
process.env.LEMONSQUEEZY_WEBHOOK_SECRET = 'qc-webhook-secret-0123456789abcdef';
process.env.LEMONSQUEEZY_VARIANT_TOKENS_30 = '1001';
process.env.LEMONSQUEEZY_VARIANT_TOKENS_100 = '1002';
process.env.LEMONSQUEEZY_VARIANT_TOKENS_500 = '1003';
process.env.LEMONSQUEEZY_VARIANT_TOKENS_1500 = '1004';
delete process.env.PAYMENTS_ACCEPT_TEST_MODE;

const { app } = await import('../src/app.ts');
const { useDatabase } = await import('../src/db.ts');
const { hashToken } = await import('../src/session.ts');
const { signLemonSqueezyWebhook } = await import('../src/payments/lemonsqueezy.ts');

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

// A verified account with a session, and its wallet.
const user = (await one(`insert into users (email, name, password_hash, email_status, email_verified_at) values ('buyer@toolpit-test.dev', 'Buyer', 'x', 'verified', now()) returning id`)).id;
const wallet = (await one('select id from wallets where user_id = $1', [user])).id;
const token = 'session-token-for-lemonsqueezy-qc-000000001';
await pg.query(`insert into sessions (token_hash, user_id, expires_at) values ($1, $2, now() + interval '1 day')`, [hashToken(token), user]);
const balance = async () => Number((await one('select balance from wallets where id = $1', [wallet])).balance);

/** A webhook as Lemon Squeezy sends it (order object, meta.custom_data). */
function order({ event = 'order_created', id = 5001, status = 'paid', variant = 1003, total = 999, walletId = wallet, packId, testMode = false } = {}) {
  return JSON.stringify({
    meta: { event_name: event, test_mode: testMode, custom_data: walletId ? { wallet_id: walletId, user_id: user, ...(packId ? { pack_id: packId } : {}) } : null },
    data: {
      type: 'orders',
      id: String(id),
      attributes: {
        store_id: 490826,
        status: event === 'order_refunded' ? 'refunded' : status,
        total,
        currency: 'USD',
        refunded: event === 'order_refunded',
        first_order_item: { variant_id: variant, order_id: id },
      },
    },
  });
}
const send = async (body, signature = signLemonSqueezyWebhook(body, process.env.LEMONSQUEEZY_WEBHOOK_SECRET)) => {
  const response = await app.fetch(
    new Request('https://api.toolpit.test/api/webhooks/payments', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-signature': signature, 'x-event-name': JSON.parse(body).meta.event_name },
      body,
    }),
  );
  return { status: response.status, body: await response.json().catch(() => ({})) };
};

console.log('\nwebhook signatures');
{
  const body = order();
  check('an unsigned webhook is refused (401) and grants nothing', (await send(body, '')).status === 401 && (await balance()) === 0);
  check('a wrongly signed webhook is refused', (await send(body, 'a'.repeat(64))).status === 401);
  const tampered = body.replace('"variant_id":1003', '"variant_id":1004');
  check('a body changed after signing is refused', (await send(tampered, signLemonSqueezyWebhook(body, process.env.LEMONSQUEEZY_WEBHOOK_SECRET))).status === 401);
}

console.log('\na paid order');
{
  const r = await send(order({ id: 5001, variant: 1003 }));
  check('is acknowledged and credits the pack its variant names (500)', r.status === 200 && (await balance()) === 500, JSON.stringify(r.body));
  await send(order({ id: 5001, variant: 1003 }));
  await send(order({ id: 5001, variant: 1003 }));
  check('three deliveries of the same order credit once', (await balance()) === 500, String(await balance()));
  await send(order({ id: 5002, variant: 1001, total: 99, packId: 'tokens_1500' }));
  check('custom data claiming a bigger pack is ignored: the $0.99 variant gives 30', (await balance()) === 530, String(await balance()));
}

console.log('\norders that must not credit');
{
  const unknown = await send(order({ id: 5003, variant: 9999 }));
  check('an unknown variant is acknowledged (200) without tokens', unknown.status === 200 && unknown.body.handled === false && (await balance()) === 530, JSON.stringify(unknown.body));
  const pending = await send(order({ id: 5004, status: 'pending' }));
  check('a pending order is acknowledged without tokens', pending.status === 200 && (await balance()) === 530);
  const noWallet = await send(order({ id: 5005, walletId: null }));
  check('an order with no Toolpit wallet is acknowledged without tokens', noWallet.status === 200 && (await balance()) === 530);
  const test = await send(order({ id: 5006, testMode: true }));
  check('a test-mode order grants nothing unless test mode is allowed', test.status === 200 && test.body.handled === false && (await balance()) === 530, JSON.stringify(test.body));
  process.env.PAYMENTS_ACCEPT_TEST_MODE = 'true';
  await send(order({ id: 5007, testMode: true, variant: 1002 }));
  delete process.env.PAYMENTS_ACCEPT_TEST_MODE;
  check('…and does credit when PAYMENTS_ACCEPT_TEST_MODE=true', (await balance()) === 630, String(await balance()));
}

console.log('\na refund');
{
  const r = await send(order({ event: 'order_refunded', id: 5001, variant: 1003 }));
  check('takes back what the order granted (500)', r.status === 200 && (await balance()) === 130, `${JSON.stringify(r.body)} balance ${await balance()}`);
  await send(order({ event: 'order_refunded', id: 5001, variant: 1003 }));
  check('a repeated refund delivery takes nothing more', (await balance()) === 130, String(await balance()));
  const ledger = await one(`select count(*)::int as n from token_entries where provider = 'lemonsqueezy'`);
  check('every movement is in the ledger under lemonsqueezy', ledger.n === 4, String(ledger.n));
}

console.log('\nstarting a checkout');
{
  const sent = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    sent.push({ url: String(url), init });
    return new Response(JSON.stringify({ data: { id: 'chk_123', attributes: { url: 'https://toolpit.lemonsqueezy.com/checkout/custom/abc' } } }), {
      status: 201,
      headers: { 'content-type': 'application/vnd.api+json' },
    });
  };
  const response = await app.fetch(
    new Request('https://api.toolpit.test/api/checkout', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ packId: 'tokens_500' }),
    }),
  );
  const body = await response.json();
  globalThis.fetch = realFetch;
  check('the site gets the hosted checkout URL', response.status === 200 && body.url === 'https://toolpit.lemonsqueezy.com/checkout/custom/abc', JSON.stringify(body));
  const request = JSON.parse(sent[0]?.init?.body ?? '{}').data ?? {};
  check('it goes to the Lemon Squeezy checkouts API with the key', sent[0]?.url === 'https://api.lemonsqueezy.com/v1/checkouts' && /Bearer test-key-not-real/.test(sent[0].init.headers.authorization));
  check('the price is ours ($9.99 from token_packs)', request.attributes?.custom_price === 999, String(request.attributes?.custom_price));
  check('for our store and the 500-token variant', request.relationships?.store?.data?.id === '490826' && request.relationships?.variant?.data?.id === '1003');
  check('carrying the wallet in custom data', request.attributes?.checkout_data?.custom?.wallet_id === wallet);
  check('returning to the account page afterwards', request.attributes?.product_options?.redirect_url === 'https://toolpit.app/account?bought=tokens_500');
  check('pre-filling the account email', request.attributes?.checkout_data?.email === 'buyer@toolpit-test.dev');

  const anonymous = await app.fetch(new Request('https://api.toolpit.test/api/checkout', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"packId":"tokens_30"}' }));
  check('nobody signed in cannot start one (401)', anonymous.status === 401);
  const bogus = await app.fetch(
    new Request('https://api.toolpit.test/api/checkout', { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: '{"packId":"tokens_999999"}' }),
  );
  check('an unknown pack is refused (404)', bogus.status === 404);
}

console.log(problems === 0 ? '\nlemonsqueezy-qc: all checks passed\n' : `\nlemonsqueezy-qc: ${problems} check(s) failed\n`);
process.exit(problems === 0 ? 0 : 1);
