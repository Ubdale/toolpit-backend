import isEmail from 'validator/lib/isEmail.js';

/**
 * Which email addresses Toolpit accepts, and the one form it keeps them in.
 *
 * The same rules as the website and app (toolpit: lib/account/email.ts); the
 * test vectors in scripts/verification-qc.mjs and the website's
 * scripts/email-rules-qc.ts are the same list, so the two cannot drift
 * without a test failing.
 *
 * The syntax check is validator.js's isEmail, a maintained validator, with
 * options matching what the mail provider (Resend) can deliver to. It says
 * nothing about whether a mailbox exists. mailbox.ts checks deliverability,
 * while the inbox code proves ownership. Temporary DNS or verifier failures
 * stay unknown so a real address is not turned away.
 *
 * Not supported, and said so plainly:
 *   - quoted local parts ("a b"@example.com)
 *   - non-Latin characters before the @ (SMTPUTF8 mailboxes)
 *   - IP-address domains (user@[192.0.2.1])
 * Internationalised domains are accepted and kept in their ASCII (punycode)
 * form, which is what mail servers use.
 */

export const MAX_EMAIL = 254;

/** Unicode line and paragraph separators, which are not caught by s in every engine. */
const LINE_BREAKS = [String.fromCharCode(0x2028), String.fromCharCode(0x2029)];

export type EmailCheck = { ok: true; email: string; key: string } | { ok: false; error: string };

/** The ASCII form of a domain, where the runtime can make it. */
function asciiDomain(domain: string): string {
  if (/^[\x00-\x7f]*$/.test(domain)) return domain.toLowerCase();
  try {
    const host = new URL(`http://${domain}`).hostname;
    return host || domain.toLowerCase();
  } catch {
    return domain.toLowerCase();
  }
}

export function checkEmail(input: unknown): EmailCheck {
  if (typeof input !== 'string') return { ok: false, error: 'Enter your email address.' };
  const trimmed = input.trim();
  if (!trimmed) return { ok: false, error: 'Enter your email address.' };
  if (trimmed.length > MAX_EMAIL) return { ok: false, error: 'That email address is too long.' };
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(trimmed) || LINE_BREAKS.some((c) => trimmed.includes(c))) {
    return { ok: false, error: 'That email address contains characters that are not allowed.' };
  }
  if (/\s/.test(trimmed)) return { ok: false, error: 'An email address cannot contain spaces.' };
  if (/[,;]/.test(trimmed) || trimmed.split('@').length > 2) return { ok: false, error: 'Enter one email address.' };
  if (!trimmed.includes('@')) return { ok: false, error: 'An email address needs an @.' };

  const at = trimmed.lastIndexOf('@');
  const local = trimmed.slice(0, at);
  const domain = trimmed.slice(at + 1);
  if (local.startsWith('"')) return { ok: false, error: 'Quoted email addresses are not supported.' };
  if (/[^\x00-\x7f]/.test(local)) {
    return { ok: false, error: 'Use an address with only Latin letters, digits and . _ + - before the @.' };
  }
  if (domain.startsWith('[')) return { ok: false, error: 'Use an address with a domain name, not an IP address.' };

  const email = `${local}@${asciiDomain(domain)}`;
  const valid =
    email.length <= MAX_EMAIL &&
    isEmail(email, {
      allow_display_name: false,
      allow_utf8_local_part: false,
      require_tld: true,
      allow_ip_domain: false,
      domain_specific_validation: false,
      ignore_max_length: false,
    });
  if (!valid) return { ok: false, error: 'That email address does not look right.' };
  return { ok: true, email, key: email.toLowerCase() };
}

/** The comparison key for an address already stored: case-insensitive, whole address. */
export function emailKey(email: string): string {
  return email.trim().toLowerCase();
}
