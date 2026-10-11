import { Resolver } from 'node:dns/promises';

import { AccountError } from './account';
import { mailTransport } from './mail';

export type MailboxStatus = 'deliverable' | 'undeliverable' | 'unknown';

const resolver = new Resolver({ timeout: 2000, tries: 1 });

/** Only authoritative DNS failures reject an address; outages stay unknown.
 * No MX alone is not enough: SMTP also permits an A/AAAA fallback.
 */
export async function domainCanReceive(
  domain: string,
  dns: Pick<Resolver, 'resolveMx' | 'resolve4' | 'resolve6'> = resolver,
): Promise<MailboxStatus> {
  try {
    const mx = await dns.resolveMx(domain);
    if (mx.some((record) => record.exchange && record.exchange !== '.')) return 'deliverable';
    // A Null MX explicitly says this domain does not accept email.
    if (mx.length) return 'undeliverable';
  } catch (error) {
    const code = (error as { code?: string }).code;
    if (code === 'ENOTFOUND') return 'undeliverable';
    if (code !== 'ENODATA') return 'unknown';
  }
  const hosts = await Promise.allSettled([dns.resolve4(domain), dns.resolve6(domain)]);
  if (hosts.some((result) => result.status === 'fulfilled' && result.value.length > 0)) return 'deliverable';
  return hosts.every((result) => result.status === 'fulfilled' || ['ENOTFOUND', 'ENODATA'].includes((result.reason as { code?: string }).code ?? ''))
    ? 'undeliverable' : 'unknown';
}

export async function requireReceivableEmail(email: string): Promise<void> {
  // Tests use made-up domains and captured mail, never external services.
  if (mailTransport() === 'capture') return;
  if (await domainCanReceive(email.split('@')[1]!) === 'undeliverable') {
    throw new AccountError('This email domain cannot receive mail. Check your email address.', 400, { code: 'invalid_email' });
  }
}
