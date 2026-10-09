import type { Ledger, LedgerPack } from './payments/fulfil';

import { one } from './db';

/**
 * The production ledger: Postgres on Neon.
 *
 * Every write goes through the plpgsql functions in db/migrations, never a
 * table insert, so the idempotency index and the balance floor apply here
 * exactly as they do in scripts/payments-qc.mjs, which drives the same
 * `fulfil` against PGlite.
 */
export const postgresLedger: Ledger = {
  async packById(id) {
    return one<LedgerPack>('select id, tokens from token_packs where id = $1 and active', [id]);
  },

  async packByStoreProduct(productId) {
    return one<LedgerPack>('select id, tokens from token_packs where store_product_id = $1', [productId]);
  },

  async walletForUser(userId) {
    if (!/^[0-9a-f-]{36}$/i.test(userId)) return null;
    return (await one<{ id: string }>('select id from wallets where user_id = $1', [userId]))?.id ?? null;
  },

  async walletExists(walletId) {
    if (!/^[0-9a-f-]{36}$/i.test(walletId)) return false;
    return Boolean(await one('select 1 from wallets where id = $1', [walletId]));
  },

  async grantedBy(provider, transactionId) {
    const row = await one<{ delta: string }>(
      'select delta from token_entries where provider = $1 and provider_txn_id = $2',
      [provider, transactionId],
    );
    return row ? Number(row.delta) : null;
  },

  async credit(walletId, tokens, provider, transactionId) {
    const row = await one<{ b: string }>('select credit_tokens($1, $2, $3, $4, $5) as b', [
      walletId, tokens, 'purchase', provider, transactionId,
    ]);
    return Number(row!.b);
  },

  async revoke(walletId, tokens, reason, provider, transactionId) {
    const row = await one<{ b: string }>('select revoke_tokens($1, $2, $3, $4, $5) as b', [
      walletId, tokens, reason, provider, transactionId,
    ]);
    return Number(row!.b);
  },
};
