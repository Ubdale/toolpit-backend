/**
 * The payment provider, behind an interface, because which one we can use is
 * not settled and may change under us.
 *
 * WHY THIS IS NOT CALLED stripe.ts
 *
 * Stripe does not accept merchants in Pakistan. That is not a preference or a
 * difficulty, it is a closed door: https://stripe.com/global lists the
 * supported countries and Pakistan is not among them. So the provider is
 * whichever one will take the business, and that question is still open.
 *
 * THE HARDER CONSTRAINT, WHICH IS NOT THE COUNTRY
 *
 * Paddle's acceptable use policy prohibits, in its own words, "virtual currency
 * or stored value, including but not limited to store credit, gift cards,
 * vouchers". A balance someone buys and draws down looks a great deal like
 * store credit, and that is the category most merchant-of-record providers
 * refuse. Notably their policy says nothing about prepaid usage of the seller's
 * own software, which is what this actually is - the tokens buy file exports
 * from Toolpit, are not transferable, are not redeemable for cash, and are
 * worth nothing outside it.
 *
 * Which of those two things it is read as is a decision for a compliance
 * reviewer and not for this file, so it must be asked and answered in writing
 * before a live key exists. Everything here is built so the answer can be
 * "use a different provider" without touching the ledger, the API or the app.
 *
 * WHAT A PROVIDER HAS TO DO
 *
 * Very little, deliberately. Take a pack id and return somewhere to send the
 * customer; turn an incoming webhook into a verified fact. Everything about
 * balances, idempotency and refunds already lives in Postgres, where it is the
 * same regardless of who processes the card.
 */

/** A pack as the database defines it. Prices never come from the client. */
export type TokenPack = {
  id: string;
  tokens: number;
  priceCents: number;
  currency: string;
  label: string;
};

export type CheckoutRequest = {
  pack: TokenPack;
  /** Our user, so the webhook can find the wallet again. */
  walletId: string;
  userId: string;
  /** Where to send the customer afterwards. */
  successUrl: string;
  cancelUrl: string;
};

export type CheckoutSession = {
  /** Send the browser here. */
  url: string;
  /** The provider's id for this attempt, recorded so support can trace it. */
  reference: string;
};

/**
 * Whose wallet a payment is for.
 *
 * A web checkout carries our wallet id through the provider and back. An app
 * store does not know our wallets; it knows the app user id the app logged in
 * with, which is our user id, and the wallet is looked up from that.
 */
export type Payer = { walletId: string } | { userId: string };

/**
 * Which pack was bought: our id, or the product id a store sold it under.
 * Either way the token count is read from our own table, never from the event.
 */
export type PackRef = { packId: string } | { storeProductId: string };

/**
 * What a webhook turned out to mean.
 *
 * Deliberately small. A provider sends dozens of event types and almost all of
 * them are noise; these four are the ones that move tokens. Anything else is
 * acknowledged and ignored, because an unrecognised event is not an error and
 * must not make the provider retry forever.
 */
export type PaymentEvent =
  | {
      kind: 'purchase';
      /** The provider's transaction id. The ledger's idempotency key. */
      transactionId: string;
      payer: Payer;
      pack: PackRef;
      /** Minor units, as the provider reports charging. Recorded, never trusted. */
      amountCents?: number;
      currency?: string;
      /** A store sandbox or test purchase: no money moved. */
      sandbox?: boolean;
    }
  | {
      kind: 'refund' | 'chargeback';
      transactionId: string;
      /** The purchase being reversed. */
      originalTransactionId: string;
      payer: Payer;
      sandbox?: boolean;
    }
  | { kind: 'ignored'; reason: string };

export type WebhookInput = {
  /** Raw body. Must be the exact bytes received: signatures cover bytes, not objects. */
  body: string;
  headers: Record<string, string>;
};

export interface PaymentProvider {
  readonly name: string;

  /** False when no credentials are configured; the UI then hides checkout rather than offering a broken one. */
  isConfigured(): boolean;

  createCheckout(request: CheckoutRequest): Promise<CheckoutSession>;

  /**
   * Verify and interpret a webhook.
   *
   * Throws if the signature does not check out. That is not an ordinary
   * failure to be logged and swallowed: an unverified webhook is an
   * instruction from a stranger to grant tokens, and the only safe response is
   * to refuse it loudly.
   */
  parseWebhook(input: WebhookInput): Promise<PaymentEvent>;
}

/** Thrown when a webhook cannot be trusted. Never caught into a success path. */
export class WebhookVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WebhookVerificationError';
  }
}
