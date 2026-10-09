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
 * A payment provider with no payment provider behind it.
 *
 * It exists because the real one is not decided - Stripe will not take a
 * Pakistani merchant, and whether a merchant of record will accept a product
 * that looks like store credit is an open question. Waiting for that answer
 * before writing any of this would mean writing all of it afterwards, under
 * time pressure, against a live key.
 *
 * It is not a stub that returns true. It signs its webhooks with HMAC-SHA256
 * and verifies them in constant time, exactly as a real provider does, because
 * the signature check is the single most security-sensitive line in the whole
 * payment path and testing it against something that always says yes proves
 * nothing. A forged webhook is an instruction from a stranger to grant tokens.
 *
 * It cannot run in production: the guard is the build mode, so no environment
 * variable and no mistaken conditional can switch it on for a real customer.
 */

const SECRET = 'mock-webhook-secret-not-for-production';

export function mockPaymentsAllowed(): boolean {
  return process.env.NODE_ENV !== 'production';
}

/** Sign a payload the way a provider would, for tests and the sandbox UI. */
export function signMockWebhook(body: string, secret = SECRET): string {
  return createHmac('sha256', secret).update(body, 'utf8').digest('hex');
}

export const mockProvider: PaymentProvider = {
  name: 'mock',

  isConfigured() {
    return mockPaymentsAllowed();
  },

  async createCheckout(request: CheckoutRequest): Promise<CheckoutSession> {
    if (!mockPaymentsAllowed()) throw new Error('Payments are not configured.');

    const reference = `mock_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;

    // A page inside the app that stands in for the provider's hosted checkout,
    // with the details it would need to complete or abandon the purchase.
    const url =
      `/sandbox/checkout?ref=${encodeURIComponent(reference)}` +
      `&pack=${encodeURIComponent(request.pack.id)}` +
      `&wallet=${encodeURIComponent(request.walletId)}` +
      `&amount=${request.pack.priceCents}` +
      `&success=${encodeURIComponent(request.successUrl)}` +
      `&cancel=${encodeURIComponent(request.cancelUrl)}`;

    return { url, reference };
  },

  async parseWebhook(input: WebhookInput): Promise<PaymentEvent> {
    if (!mockPaymentsAllowed()) throw new WebhookVerificationError('Payments are not configured.');

    const given = input.headers['x-mock-signature'] ?? '';
    const expected = signMockWebhook(input.body);

    // Constant time, and length-checked first because timingSafeEqual throws
    // on a length mismatch - which would itself leak the length.
    const a = Buffer.from(given, 'utf8');
    const b = Buffer.from(expected, 'utf8');
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw new WebhookVerificationError('Signature did not match.');
    }

    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(input.body) as Record<string, unknown>;
    } catch {
      throw new WebhookVerificationError('Body was not JSON.');
    }

    const type = String(payload.type ?? '');

    if (type === 'purchase.completed') {
      return {
        kind: 'purchase',
        transactionId: String(payload.transaction_id),
        payer: { walletId: String(payload.wallet_id) },
        pack: { packId: String(payload.pack_id) },
        amountCents: Number(payload.amount_cents),
        currency: String(payload.currency ?? 'usd'),
      };
    }

    if (type === 'purchase.refunded' || type === 'purchase.chargeback') {
      return {
        kind: type === 'purchase.refunded' ? 'refund' : 'chargeback',
        transactionId: String(payload.transaction_id),
        originalTransactionId: String(payload.original_transaction_id),
        payer: { walletId: String(payload.wallet_id) },
      };
    }

    // Unknown events are not failures. A provider sends many kinds and will
    // retry anything it is told went wrong, so the honest answer to one we do
    // not handle is a cheerful acknowledgement.
    return { kind: 'ignored', reason: `unhandled type: ${type || '(none)'}` };
  },
};
