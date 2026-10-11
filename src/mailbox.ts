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

/** Optional mailbox probe. Never log the URL: it includes the private key.
 * Risky, catch-all, timeout and unknown results still require inbox OTP.
 */
export async function probeMailbox(email: string, key = process.env.EMAILABLE_API_KEY, request = fetch): Promise<MailboxStatus> {
  if (!key) return 'unknown';
  try {
    const url = new URL('https://api.emailable.com/v1/verify');
    url.searchParams.set('email', email);
    url.searchParams.set('api_key', key);
    url.searchParams.set('timeout', '5');
    const response = await request(url, { signal: AbortSignal.timeout(6500) });
    if (!response.ok) return 'unknown';
    const result = await response.json() as { email?: string; state?: string };
    if (result.email?.toLowerCase() !== email.toLowerCase()) return 'unknown';
    return result.state === 'undeliverable' ? 'undeliverable' : result.state === 'deliverable' ? 'deliverable' : 'unknown';
  } catch { return 'unknown'; }
}

export async function requireReceivableEmail(email: string): Promise<void> {
  // Tests use made-up domains and captured mail, never external services.
  if (mailTransport() === 'capture') return;
  if (await domainCanReceive(email.split('@')[1]!) === 'undeliverable') {
    throw new AccountError('This email domain cannot receive mail. Check your email address.', 400, { code: 'invalid_email' });
  }
  if (await probeMailbox(email) === 'undeliverable') {
    throw new AccountError('This email address cannot receive mail. Check for a typo or use another address.', 400, { code: 'invalid_email' });
  }
}
