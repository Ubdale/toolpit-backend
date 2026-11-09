import { createHmac, timingSafeEqual } from 'node:crypto';

import {
  WebhookVerificationError,
  type CheckoutRequest,
  type CheckoutSession,
  type PaymentEvent,
  type PaymentProvider,
  type WebhookInput,
} from './provider';

/**
 * Lemon Squeezy: the website's checkout and its webhooks.
 *
 * Lemon Squeezy is the merchant of record - it takes the card, handles tax,
 * and pays out - so all this file does is open a hosted checkout and turn its
 * signed webhooks into PaymentEvents. Balances, retries and refunds stay in
 * fulfil() and Postgres, the same as for every other provider.
 *
 * WHAT DECIDES WHAT WAS BOUGHT
 *
 * The pack comes from the variant Lemon Squeezy actually charged for, mapped
 * through our own configuration - never from checkout custom data. Custom
 * data can be set by anyone on a public "buy" link
 * (?checkout[custom][pack_id]=…), so trusting it would let someone pay for
 * the smallest pack and claim the largest. The wallet does come from custom
 * data, because paying for someone else's wallet harms nobody.
 *
 * WHAT DECIDES THE PRICE
 *
 * Our token_packs table. Each checkout is created with `custom_price` set
 * from it, so a price changed in the database is the price charged, and a
 * variant edited in the Lemon Squeezy dashboard cannot quietly drift from it.
 *
 * Configuration (Render env; never in the repo):
 *   PAYMENT_PROVIDER=lemonsqueezy
 *   LEMONSQUEEZY_API_KEY, LEMONSQUEEZY_STORE_ID, LEMONSQUEEZY_WEBHOOK_SECRET
 *   LEMONSQUEEZY_VARIANT_TOKENS_30 / _100 / _500 / _1500  (one per pack id)
 *   PAYMENTS_ACCEPT_TEST_MODE=true  only while testing with a test-mode key
 */

const API = 'https://api.lemonsqueezy.com/v1';
const PACK_IDS = ['tokens_30', 'tokens_100', 'tokens_500', 'tokens_1500'] as const;

const env = (name: string) => process.env[name]?.trim() ?? '';
const variantEnv = (packId: string) => `LEMONSQUEEZY_VARIANT_${packId.toUpperCase()}`;

/** Our pack id for a Lemon Squeezy variant id, from configuration. */
export function packForVariant(variantId: string | number): string | null {
  const id = String(variantId);
  return PACK_IDS.find((pack) => env(variantEnv(pack)) === id) ?? null;
}

/** The signature Lemon Squeezy puts in X-Signature: HMAC-SHA256 of the raw body, hex. */
export function signLemonSqueezyWebhook(body: string, secret: string): string {
  return createHmac('sha256', secret).update(body, 'utf8').digest('hex');
}

type LemonOrder = {
  meta?: {
    event_name?: string;
    test_mode?: boolean;
    custom_data?: Record<string, unknown> | null;
  };
  data?: {
    id?: string | number;
    type?: string;
    attributes?: {
      status?: string;
      total?: number;
      currency?: string;
      refunded?: boolean;
      refunded_at?: string | null;
      first_order_item?: { variant_id?: number | string } | null;
    };
  };
};

export const lemonSqueezyProvider: PaymentProvider = {
  name: 'lemonsqueezy',

  isConfigured() {
    return Boolean(
      env('LEMONSQUEEZY_API_KEY') &&
        env('LEMONSQUEEZY_STORE_ID') &&
        env('LEMONSQUEEZY_WEBHOOK_SECRET') &&
        PACK_IDS.every((pack) => env(variantEnv(pack))),
    );
  },

  async createCheckout(request: CheckoutRequest): Promise<CheckoutSession> {
    const variant = env(variantEnv(request.pack.id));
    if (!variant) throw new Error(`No Lemon Squeezy variant is configured for ${request.pack.id}.`);

    const response = await fetch(`${API}/checkouts`, {
      method: 'POST',
      signal: AbortSignal.timeout(15_000),
      headers: {
        accept: 'application/vnd.api+json',
        'content-type': 'application/vnd.api+json',
        authorization: `Bearer ${env('LEMONSQUEEZY_API_KEY')}`,
      },
      body: JSON.stringify({
        data: {
          type: 'checkouts',
          attributes: {
            // Our catalogue is the price; see the note at the top.
            custom_price: request.pack.priceCents,
            product_options: {
              enabled_variants: [Number(variant)],
              redirect_url: request.successUrl,
              receipt_button_text: 'Back to Toolpit',
              receipt_link_url: request.successUrl,
            },
            checkout_data: {
              ...(request.email ? { email: request.email } : {}),
              // Read back by the webhook: whose wallet. Never which pack.
              custom: { wallet_id: request.walletId, user_id: request.userId, pack_id: request.pack.id },
            },
            // A link nobody can reuse days later at an old price.
            expires_at: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
          },
          relationships: {
            store: { data: { type: 'stores', id: env('LEMONSQUEEZY_STORE_ID') } },
            variant: { data: { type: 'variants', id: variant } },
          },
        },
      }),
    });
    const body = (await response.json().catch(() => ({}))) as { data?: { id?: string; attributes?: { url?: string } }; errors?: unknown };
    if (!response.ok || !body.data?.attributes?.url) {
      // Status only: the body can echo the request.
      console.error(`[lemonsqueezy] checkout was not created: ${response.status}`);
      throw new Error('The checkout could not be opened. Try again in a moment.');
    }
    return { url: body.data.attributes.url, reference: String(body.data.id ?? '') };
  },

  async parseWebhook(input: WebhookInput): Promise<PaymentEvent> {
    const secret = env('LEMONSQUEEZY_WEBHOOK_SECRET');
    if (!secret) throw new WebhookVerificationError('Lemon Squeezy is not configured.');

    // Constant time, length-checked first (timingSafeEqual throws on a
    // length mismatch, which would itself leak the length).
    const given = Buffer.from(input.headers['x-signature'] ?? '', 'utf8');
    const expected = Buffer.from(signLemonSqueezyWebhook(input.body, secret), 'utf8');
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
      throw new WebhookVerificationError('Signature did not match.');
    }

    let payload: LemonOrder;
    try {
      payload = JSON.parse(input.body) as LemonOrder;
    } catch {
      throw new WebhookVerificationError('Body was not JSON.');
    }

    const eventName = payload.meta?.event_name ?? '';
    const order = payload.data;
    const attributes = order?.attributes ?? {};
    const custom = payload.meta?.custom_data ?? {};
    const walletId = typeof custom.wallet_id === 'string' ? custom.wallet_id : '';
    const sandbox = payload.meta?.test_mode === true;

    if (order?.type !== 'orders' || order.id === undefined) {
      return { kind: 'ignored', reason: `not an order event: ${eventName || '(none)'}` };
    }
    const orderId = String(order.id);
    if (!walletId) return { kind: 'ignored', reason: 'order has no Toolpit wallet (bought outside the website?)' };

    if (eventName === 'order_created') {
      // Only a paid order grants tokens. Pending and failed ones are not money.
      if (attributes.status !== 'paid') return { kind: 'ignored', reason: `order ${orderId} is ${attributes.status ?? 'unknown'}` };
      const variantId = attributes.first_order_item?.variant_id;
      const packId = variantId === undefined ? null : packForVariant(variantId);
      if (!packId) return { kind: 'ignored', reason: `variant ${String(variantId)} is not a Toolpit pack` };
      return {
        kind: 'purchase',
        transactionId: orderId,
        payer: { walletId },
        pack: { packId },
        amountCents: typeof attributes.total === 'number' ? attributes.total : undefined,
        currency: attributes.currency?.toLowerCase(),
        sandbox,
      };
    }

    if (eventName === 'order_refunded') {
      return {
        kind: 'refund',
        // One refund per order: a repeated delivery is the same refund.
        transactionId: `${orderId}:refund`,
        originalTransactionId: orderId,
        payer: { walletId },
        sandbox,
      };
    }

    return { kind: 'ignored', reason: `unhandled event: ${eventName || '(none)'}` };
  },
};
