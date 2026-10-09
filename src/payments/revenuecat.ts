import { timingSafeEqual } from 'node:crypto';

import { WebhookVerificationError, type PaymentEvent, type WebhookInput } from './provider';

/**
 * Google Play and App Store purchases, as RevenueCat reports them.
 *
 * The app sells tokens through the stores, because both stores require their
 * own billing for anything digital that is used inside an app. RevenueCat sits
 * between: it validates each receipt with Google or Apple and then tells us
 * what happened, here. The app logs in to RevenueCat with our user id, so
 * `app_user_id` on every event is the Toolpit user whose wallet to credit.
 *
 * HOW A WEBHOOK IS TRUSTED
 *
 * RevenueCat does not sign webhooks. It sends back, in the Authorization
 * header, a value we chose when configuring the webhook in its dashboard. So
 * that value is a shared secret, compared in constant time, and a webhook
 * without it is refused before its body is even parsed.
 *
 * WHICH EVENTS MOVE TOKENS
 *
 * Tokens are consumable products. A consumable arrives as
 * NON_RENEWING_PURCHASE. A refund of one - Google's or Apple's - arrives as
 * CANCELLATION with cancel_reason CUSTOMER_SUPPORT. Everything else, including
 * RevenueCat's own TEST event, is acknowledged and ignored.
 */

type RevenueCatEvent = {
  type?: string;
  id?: string;
  app_user_id?: string;
  original_app_user_id?: string;
  aliases?: string[];
  product_id?: string;
  transaction_id?: string;
  original_transaction_id?: string;
  environment?: string;
  cancel_reason?: string;
  price_in_purchased_currency?: number;
  currency?: string;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Our user id, from the ids RevenueCat knows this customer by.
 *
 * The app never buys anonymously - it asks for sign-in first - so app_user_id
 * should already be a UUID. The aliases are checked too, because RevenueCat
 * reports a purchase made just before a login under the anonymous id and
 * lists the real one as an alias.
 */
function userIdOf(event: RevenueCatEvent): string | null {
  const candidates = [event.app_user_id, event.original_app_user_id, ...(event.aliases ?? [])];
  return candidates.find((id): id is string => typeof id === 'string' && UUID.test(id)) ?? null;
}

function header(headers: Record<string, string>, name: string): string {
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) if (key.toLowerCase() === wanted) return value;
  return '';
}

function sameSecret(given: string, expected: string): boolean {
  // The dashboard can send the value bare or as a bearer token; accept both.
  const bare = given.replace(/^Bearer\s+/i, '');
  const a = Buffer.from(bare, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  // Length first: timingSafeEqual throws on a mismatch, which would leak it.
  return a.length === b.length && timingSafeEqual(a, b);
}

export function parseRevenueCatWebhook(input: WebhookInput, secret: string | undefined): PaymentEvent {
  if (!secret || secret.length < 16) {
    // A missing or trivially short secret is a configuration error, and the
    // safe reading of it is "trust nothing".
    throw new WebhookVerificationError('RevenueCat webhook secret is not configured.');
  }
  if (!sameSecret(header(input.headers, 'authorization'), secret)) {
    throw new WebhookVerificationError('Authorization did not match.');
  }

  let event: RevenueCatEvent;
  try {
    event = (JSON.parse(input.body) as { event?: RevenueCatEvent }).event ?? {};
  } catch {
    throw new WebhookVerificationError('Body was not JSON.');
  }

  const type = event.type ?? '';
  const sandbox = event.environment === 'SANDBOX';
  const userId = userIdOf(event);
  const transaction = event.transaction_id;

  if (type === 'NON_RENEWING_PURCHASE') {
    if (!userId) return { kind: 'ignored', reason: 'purchase by a customer with no Toolpit account id' };
    if (!transaction || !event.product_id) return { kind: 'ignored', reason: 'purchase without a transaction or product' };
    return {
      kind: 'purchase',
      transactionId: transaction,
      payer: { userId },
      pack: { storeProductId: event.product_id },
      amountCents:
        typeof event.price_in_purchased_currency === 'number'
          ? Math.round(event.price_in_purchased_currency * 100)
          : undefined,
      currency: event.currency?.toLowerCase(),
      sandbox,
    };
  }

  if (type === 'CANCELLATION' && event.cancel_reason === 'CUSTOMER_SUPPORT') {
    if (!userId || !transaction) return { kind: 'ignored', reason: 'refund without a customer or transaction' };
    return {
      kind: 'refund',
      // Its own key in the ledger, so a repeated refund is a no-op, and so it
      // never collides with the purchase it reverses.
      transactionId: `${transaction}:refund`,
      originalTransactionId: transaction,
      payer: { userId },
      sandbox,
    };
  }

  return { kind: 'ignored', reason: `unhandled type: ${type || '(none)'}` };
}
