import type { PackRef, Payer, PaymentEvent } from './provider';

/**
 * What a verified payment event does to the ledger.
 *
 * One function for every provider. Web checkout and the two app stores all
 * arrive here as the same small `PaymentEvent`, so the rules below - the
 * amount comes from our catalogue, a retry is free, a refund takes back what
 * the purchase granted and never more than is there - are written once and
 * tested once, against real Postgres, in scripts/payments-qc.mjs.
 *
 * The ledger is passed in. In production it is Postgres through the service
 * role (lib/server/ledger.ts); in the tests it is PGlite. Both run the same
 * plpgsql, which is where idempotency and the balance floor actually live.
 */

export type LedgerPack = { id: string; tokens: number };

export interface Ledger {
  packById(id: string): Promise<LedgerPack | null>;
  packByStoreProduct(productId: string): Promise<LedgerPack | null>;
  /** The personal wallet of a user, or null if there is no such user. */
  walletForUser(userId: string): Promise<string | null>;
  walletExists(walletId: string): Promise<boolean>;
  /** The delta a provider transaction granted, or null if it never did. */
  grantedBy(provider: string, transactionId: string): Promise<number | null>;
  credit(walletId: string, tokens: number, provider: string, transactionId: string): Promise<number>;
  revoke(
    walletId: string,
    tokens: number,
    reason: 'refund' | 'chargeback',
    provider: string,
    transactionId: string,
  ): Promise<number>;
}

export type Outcome =
  | { handled: true; balance: number; granted?: number; revoked?: number }
  | { handled: false; reason: string };

export type FulfilOptions = {
  /** Whether store sandbox purchases may grant tokens. Off unless set. */
  acceptSandbox?: boolean;
};

async function resolveWallet(ledger: Ledger, payer: Payer): Promise<string | null> {
  if ('walletId' in payer) return (await ledger.walletExists(payer.walletId)) ? payer.walletId : null;
  return ledger.walletForUser(payer.userId);
}

function resolvePack(ledger: Ledger, ref: PackRef): Promise<LedgerPack | null> {
  return 'packId' in ref ? ledger.packById(ref.packId) : ledger.packByStoreProduct(ref.storeProductId);
}

/**
 * Apply one event.
 *
 * Returns `handled: false` for events that are understood but cannot be
 * applied - an unknown pack, a wallet that has been deleted. The caller still
 * acknowledges those to the provider: retrying them will never make them
 * succeed, and a provider that is told "error" retries for days.
 */
export async function fulfil(
  event: PaymentEvent,
  provider: string,
  ledger: Ledger,
  options: FulfilOptions = {},
): Promise<Outcome> {
  if (event.kind === 'ignored') return { handled: false, reason: event.reason };

  if (event.sandbox && !options.acceptSandbox) {
    return { handled: false, reason: 'sandbox purchase, and sandbox purchases are not accepted here' };
  }

  const wallet = await resolveWallet(ledger, event.payer);
  if (!wallet) return { handled: false, reason: 'no wallet for this payer' };

  if (event.kind === 'purchase') {
    // The amount is read from our own catalogue, never from the event. A
    // provider that is compromised, or a payload replayed with an edited
    // figure, must not be able to decide how many tokens we grant.
    const pack = await resolvePack(ledger, event.pack);
    if (!pack) return { handled: false, reason: 'unknown pack' };

    const balance = await ledger.credit(wallet, pack.tokens, provider, event.transactionId);
    return { handled: true, balance, granted: pack.tokens };
  }

  // A refund takes back what the original purchase granted, which the ledger
  // remembers; the event does not get to say how much.
  const granted = await ledger.grantedBy(provider, event.originalTransactionId);
  if (granted === null || granted <= 0) return { handled: false, reason: 'refund for unknown purchase' };

  const balance = await ledger.revoke(wallet, granted, event.kind, provider, event.transactionId);
  return { handled: true, balance, revoked: granted };
}
