import { mockPaymentsAllowed, mockProvider } from './mock';
import type { PaymentProvider } from './provider';

export * from './provider';

/**
 * The provider that sells tokens on the website, if there is one.
 *
 * In development, the mock, so the whole web purchase path can be walked end
 * to end. In production, nothing yet: Stripe will not take a Pakistani
 * merchant, and which provider will is the owner's decision (see
 * docs/billing-setup.md). Until one is added here, the website shows the packs
 * and points people at the app to buy, rather than offering a checkout that
 * cannot complete.
 *
 * Adding a provider is one file implementing PaymentProvider and one line here.
 * The ledger, the webhook route and both apps do not change.
 */
export function webProvider(): PaymentProvider | null {
  if (mockPaymentsAllowed()) return mockProvider;
  return null;
}
