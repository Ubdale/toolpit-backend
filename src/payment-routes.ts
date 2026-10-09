import { AccountError, json, readBody, requireUser } from './account';
import { databaseConfigured, one } from './db';
import { postgresLedger } from './ledger';
import { webOrigin } from './config';
import { fulfil } from './payments/fulfil';
import { webProvider, WebhookVerificationError } from './payments/index';
import { mockPaymentsAllowed, mockProvider, signMockWebhook } from './payments/mock';
import { parseRevenueCatWebhook } from './payments/revenuecat';

/**
 * Money: starting a website checkout, and the webhooks that turn a verified
 * payment into tokens.
 *
 * Webhook status codes are what the sender acts on: 401 for anything not
 * verifiably from it (nothing is read or written), 200 for anything verified
 * even if ignored (an error would make it retry for days), 500 only when the
 * database was unreachable and a retry could help - the ledger's idempotency
 * makes that retry safe.
 */

/** Start a website purchase. The request names a pack and nothing else. */
export async function checkout(request: Request): Promise<Response> {
  const provider = webProvider();
  if (!provider || !provider.isConfigured()) {
    throw new AccountError('Buying tokens on the website is not open yet. You can buy them in the Toolpit app.', 503);
  }
  const user = await requireUser(request);
  const packId = String((await readBody(request)).packId ?? '');

  const pack = await one<{ id: string; tokens: number; price_cents: number; currency: string; label: string }>(
    'select id, tokens, price_cents, currency, label from token_packs where id = $1 and active',
    [packId],
  );
  if (!pack) throw new AccountError('No such pack.', 404);
  const walletId = await postgresLedger.walletForUser(user.id);
  if (!walletId) throw new AccountError('No wallet for this account.', 404);

  const site = webOrigin();
  const session = await provider.createCheckout({
    pack: {
      id: pack.id,
      tokens: Number(pack.tokens),
      priceCents: Number(pack.price_cents),
      currency: String(pack.currency),
      label: String(pack.label),
    },
    walletId,
    userId: user.id,
    successUrl: `${site}/account?bought=${encodeURIComponent(pack.id)}`,
    cancelUrl: `${site}/account`,
  });
  // A provider may hand back a path on our own site (the sandbox does).
  const url = session.url.startsWith('/') ? `${site}${session.url}` : session.url;
  return json({ url, reference: session.reference });
}

export async function revenueCatWebhook(request: Request): Promise<Response> {
  if (!databaseConfigured()) return json({ error: 'not configured' }, 503);
  const body = await request.text();
  let event;
  try {
    event = parseRevenueCatWebhook(
      { body, headers: Object.fromEntries(request.headers.entries()) },
      process.env.REVENUECAT_WEBHOOK_SECRET,
    );
  } catch (error) {
    if (error instanceof WebhookVerificationError) return json({ error: 'unauthorised' }, 401);
    throw error;
  }
  try {
    const outcome = await fulfil(event, 'revenuecat', postgresLedger, {
      acceptSandbox: process.env.REVENUECAT_ACCEPT_SANDBOX === 'true',
    });
    if (!outcome.handled) console.info(`[revenuecat] acknowledged without effect: ${outcome.reason}`);
    return json({ ok: true, ...outcome });
  } catch (error) {
    console.error('[revenuecat] could not apply event', error);
    return json({ error: 'temporarily unavailable' }, 500);
  }
}

export async function webPaymentWebhook(request: Request): Promise<Response> {
  const provider = webProvider();
  if (!databaseConfigured() || !provider || !provider.isConfigured()) return json({ error: 'not configured' }, 503);
  const body = await request.text();
  let event;
  try {
    event = await provider.parseWebhook({ body, headers: Object.fromEntries(request.headers.entries()) });
  } catch (error) {
    if (error instanceof WebhookVerificationError) return json({ error: 'unauthorised' }, 401);
    throw error;
  }
  try {
    return json({ ok: true, ...(await fulfil(event, provider.name, postgresLedger)) });
  } catch (error) {
    console.error(`[${provider.name}] could not apply event`, error);
    return json({ error: 'temporarily unavailable' }, 500);
  }
}

/**
 * The sandbox checkout's "Pay" button. Development only: it plays the
 * provider, signing a webhook with the mock's secret and running it through
 * the real verification and ledger code.
 */
export async function sandboxComplete(request: Request): Promise<Response> {
  if (!mockPaymentsAllowed()) return json({ error: 'Not found' }, 404);
  const user = await requireUser(request);
  const input = await readBody(request);
  const walletId = await postgresLedger.walletForUser(user.id);
  if (!walletId) throw new AccountError('No wallet.', 404);
  const body = JSON.stringify({
    type: 'purchase.completed',
    transaction_id: String(input.reference ?? ''),
    wallet_id: walletId,
    pack_id: String(input.packId ?? ''),
    amount_cents: 0,
    currency: 'usd',
  });
  const event = await mockProvider.parseWebhook({ body, headers: { 'x-mock-signature': signMockWebhook(body) } });
  return json(await fulfil(event, mockProvider.name, postgresLedger));
}
