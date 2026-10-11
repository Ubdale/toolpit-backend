alter table email_verifications add column mail_id text;
create index email_verifications_mail_idx on email_verifications (mail_id) where mail_id is not null;

-- Store only the delivery result, never an email body, OTP, or recipient.
-- Events may arrive before the send request returns; keep them independently.
create table mail_delivery (
  mail_id text primary key,
  status text not null check (status in ('delivered', 'delayed', 'bounced', 'failed', 'suppressed')),
  event_at timestamptz not null
);
