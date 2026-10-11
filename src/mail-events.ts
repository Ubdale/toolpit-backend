import { Webhook } from 'svix';

import { AccountError, json } from './account';
import { db, one } from './db';
import { hashToken } from './session';
import { readBody } from './account';

const statuses: Record<string, string> = {
  'email.delivered': 'delivered', 'email.delivery_delayed': 'delayed',
  'email.bounced': 'bounced', 'email.failed': 'failed', 'email.suppressed': 'suppressed',
};

export async function receiveMailEvent(request: Request): Promise<Response> {
  const secret = process.env.RESEND_WEBHOOK_SECRET;
  if (!secret) throw new AccountError('Delivery reporting is not configured.', 503);
  if (Number(request.headers.get('content-length') ?? 0) > 65536) throw new AccountError('Payload too large.', 413);
  const body = await request.text();
  if (Buffer.byteLength(body) > 65536) throw new AccountError('Payload too large.', 413);
  let event: { type?: string; created_at?: string; data?: { email_id?: string } };
  try {
    new Webhook(secret).verify(body, {
      'svix-id': request.headers.get('svix-id') ?? '',
      'svix-timestamp': request.headers.get('svix-timestamp') ?? '',
      'svix-signature': request.headers.get('svix-signature') ?? '',
    });
    event = JSON.parse(body) as typeof event;
  } catch { throw new AccountError('Invalid webhook signature.', 401); }
  const status = statuses[event?.type ?? ''];
  if (!status) return json({ ok: true });
  const mailId = event.data?.email_id;
  const eventAt = event.created_at;
  if (typeof mailId !== 'string' || mailId.length > 100 || !eventAt || !Number.isFinite(Date.parse(eventAt))) {
    throw new AccountError('Invalid delivery event.', 400);
  }
  // Duplicate events are harmless; old events cannot undo a newer result.
  // A delivered message cannot become merely delayed, and terminal failures
  // cannot be overwritten by a delayed/out-of-order success.
  await db().query(`insert into mail_delivery (mail_id, status, event_at) values ($1,$2,$3)
    on conflict (mail_id) do update set status = excluded.status, event_at = excluded.event_at
    where excluded.event_at > mail_delivery.event_at
      and mail_delivery.status not in ('bounced','failed','suppressed')
      and not (mail_delivery.status = 'delivered' and excluded.status = 'delayed')`, [mailId, status, eventAt]);
  return json({ ok: true });
}

/** Only the random registration handle exposes its current delivery result. */
export async function registrationDelivery(request: Request): Promise<Response> {
  const body = await readBody(request);
  if (typeof body.handle !== 'string' || body.handle.length > 100) throw new AccountError('This sign-up has ended.', 410, { code: 'registration_gone' });
  const row = await one<{ status: string | null }>(`select d.status from pending_registrations p
    left join email_verifications v on v.registration_id = p.id and v.state = 'active'
    left join mail_delivery d on d.mail_id = v.mail_id
    where p.handle_hash = $1 and p.expires_at > now()`, [hashToken(body.handle)]);
  if (!row) throw new AccountError('This sign-up has ended.', 410, { code: 'registration_gone' });
  return json({ delivery: row.status ?? 'pending' });
}
