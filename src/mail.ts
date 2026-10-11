import { randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { webOrigin } from './config';

/**
 * Sending email: Resend in production, captured to disk in development.
 *
 *   RESEND_API_KEY set           -> sent through Resend
 *   MAIL_TRANSPORT=capture       -> written to MAIL_CAPTURE_DIR (default .mail/)
 *                                   and kept in memory for tests; nothing leaves
 *                                   the machine
 *   neither                      -> not configured: features that need email
 *                                   say so instead of pretending
 *
 * Capture is refused when the server is configured for the real website, so a
 * stray environment variable cannot silently swallow real sign-up emails.
 *
 * Nothing here logs a message body: it carries one-time links.
 */

export type Mail = { to: string; subject: string; text: string };

export class MailError extends Error {}

/** Every captured message, newest last. Tests read this. */
export const captured: (Mail & { at: string; id: string })[] = [];

export function mailTransport(): 'resend' | 'capture' | null {
  if (process.env.MAIL_TRANSPORT === 'capture') {
    return /^https:\/\/(www\.)?toolpit\.app$/.test(webOrigin()) ? null : 'capture';
  }
  return process.env.RESEND_API_KEY ? 'resend' : null;
}

export function mailConfigured(): boolean {
  return mailTransport() !== null;
}

/** Hands a message to the provider. Throws MailError when it was not accepted. */
export async function sendMail(mail: Mail): Promise<string> {
  const transport = mailTransport();
  if (transport === 'capture') {
    const entry = { ...mail, id: randomUUID(), at: new Date().toISOString() };
    captured.push(entry);
    const dir = process.env.MAIL_CAPTURE_DIR ?? '.mail';
    try {
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, `${entry.at.replace(/[:.]/g, '-')}.json`), JSON.stringify(entry, null, 2));
    } catch {
      // The in-memory copy is enough for tests; the file is a convenience.
    }
    if (process.env.MAIL_CAPTURE_FAIL === '1') throw new MailError('Capture told to fail (testing).');
    return entry.id;
  }
  if (transport !== 'resend') throw new MailError('Email is not configured.');

  let response: Response;
  try {
    response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      signal: AbortSignal.timeout(10000),
      headers: { authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        from: process.env.EMAIL_FROM ?? 'Toolpit <no-reply@toolpit.app>',
        to: mail.to,
        subject: mail.subject,
        text: mail.text,
      }),
    });
  } catch {
    throw new MailError('The email service could not be reached.');
  }
  if (!response.ok) {
    // Status only; the body can echo the message, which holds a link.
    console.error(`[mail] Resend refused a message: ${response.status}`);
    throw new MailError(`The email service refused the message (${response.status}).`);
  }
  const result = await response.json() as { id?: string };
  if (typeof result.id !== 'string' || result.id.length > 100) throw new MailError('The email service gave an unexpected response.');
  return result.id;
}
