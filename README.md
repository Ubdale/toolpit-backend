# Toolpit API

The backend for toolpit.app and the Toolpit app: accounts, sessions, the token
ledger and payment webhooks. A small [Hono](https://hono.dev) server on Postgres
(Neon). It is its own project - own `package.json`, own environment, own deploy.

**It never receives a file.** Every tool runs on the user's device; the only
thing a download sends here is "charge one download to my account".

## Run it

```bash
cd backend
npm install
cp .env.example .env        # then fill DATABASE_URL
npm run db:migrate          # creates the tables (safe to run again)
npm run dev                 # http://localhost:8787
npm run dev:local           # the same, with nothing external: PGlite + mail captured to .mail/
```

The website talks to it when its `.env.local` has
`NEXT_PUBLIC_API_URL=http://localhost:8787`; the phone app via
`EXPO_PUBLIC_API_URL` in `apps/mobile/.env`.

## Layout

```
src/
  app.ts             every route, CORS
  index.ts           entry for Vercel (exports the app)
  server.ts          entry for Node: local dev, Railway, Render, a VPS
  account.ts         sign-in, balance, download charge, delete
  registration.ts    sign-up with email confirmation (see "Email verification")
  email.ts           which addresses are accepted (validator.js) and their stored form
  mail.ts            Resend, or captured mail for development
  password.ts        scrypt hashing
  session.ts         session tokens (cookie for the website, bearer for the app)
  reset.ts           password-reset emails via Resend
  db.ts              Postgres pool
  ledger.ts          the ledger the payment code writes to
  config.ts          website origin and CORS allow-list
  payment-routes.ts  checkout + webhooks
  payments/          provider interface, RevenueCat, mock, fulfil()
db/migrations/       the schema and the token rules, in SQL
scripts/             migrate + tests
```

## Routes

| Method | Path | |
|---|---|---|
| POST | `/api/auth/signup` | `{name, email, password, verification: "code"}` → 202 `{pending}`; a confirmation email, **no account yet** |
| POST | `/api/auth/signup/resend` | `{handle}` → a new code (60 s cooldown); the old code stops working |
| POST | `/api/auth/signup/change-email` | `{handle, email}` → same sign-up, new address, new code |
| POST | `/api/auth/verify/code` | `{handle, code}` → verified account, bonus and session |
| POST | `/api/auth/verify/inspect` | `{token}` → what a link is; never uses it |
| POST | `/api/auth/verify` | `{token, password}` → verified account, 50 tokens (once per inbox), signed in |
| POST | `/api/auth/verify/cancel` | `{token}` → "this was not me": ends the sign-up |
| POST | `/api/auth/login` | `{email, password}` → `{token, account}` + cookie |
| POST | `/api/auth/logout` | ends the session |
| POST | `/api/auth/forgot` | `{email}` → reset link by email (needs `RESEND_API_KEY`) |
| POST | `/api/auth/reset` | `{token, password}` → new password, signed in |
| GET | `/api/account` | `{id, email, name, balance, cost, emailVerified, emailStatus}` |
| DELETE | `/api/account` | deletes the account and its balance |
| POST | `/api/account/download` | charges 10 tokens; 402 if not enough |
| GET | `/api/packs` | the four token packs |
| POST | `/api/webhooks/revenuecat` | Play / App Store purchases and refunds |
| POST | `/api/checkout`, `/api/webhooks/payments` | website purchases (off until a provider is chosen) |
| GET | `/health` | `{ok: true}` |

The website authenticates with an httpOnly `tp_session` cookie (the API and the
site share the `toolpit.app` domain, so it is first-party); the app sends
`Authorization: Bearer <token>`. Browsers may call only from `ALLOWED_ORIGINS`.

## Deliverability checks

Sign-up, resend and email changes check whether the destination domain accepts
mail (MX or SMTP A/AAAA fallback). Missing domains and Null MX are rejected;
DNS outages remain unknown. Optional `EMAILABLE_API_KEY` enables mailbox-level
checks before sending: only an explicit undeliverable result blocks signup.
Unknown/risky results still require the inbox code.

Configure a Resend webhook at `https://api.toolpit.app/api/webhooks/resend`
for `email.delivered`, `email.delivery_delayed`, `email.bounced`,
`email.failed`, and `email.suppressed`. Store its signing secret as
`RESEND_WEBHOOK_SECRET` on the backend. Svix verifies the raw payload and
request timestamp before any event is stored. Migration `0004_email_delivery.sql`
adds receipt tracking. The website polls `POST /api/auth/signup/delivery`
using its private registration handle and shows delivery failures. Resending
tracks the new receipt only; a delayed event for an old code cannot change it.
Only delivery states are stored, not webhook bodies, OTPs or recipient details.

Provider acceptance is not proof a mailbox exists, and a bounce may also mean
a policy rejection rather than a missing mailbox. The UI asks users to check
the address without asserting that an inbox definitely does not exist.

## Email verification

The website requests `verification: "code"`. Resend emails a cryptographically
random six-digit code, valid for 10 minutes. The user enters it on the pending
sign-up screen; `POST /api/auth/verify/code` requires both that code and the
random registration handle belonging to the browser that chose the password.
Codes are stored using salted scrypt hashes. The database atomically limits
each code to five attempts, including concurrent guesses. Resending or changing
the address invalidates the previous code. A successful confirmation creates
one verified account, grants the bonus once, consumes the challenge, and signs
in. No account, wallet or session is created before confirmation.

Deploy the backend first: its startup migration runner applies
`0003_email_codes.sql`. Then deploy the website. Existing pending registrations
and older mobile builds continue using the link flow described below.


Sign-up does not create an account. It creates a **pending registration**
(no wallet, no tokens, no session) and emails a link to
`WEB_ORIGIN/account/confirm#t=<secret>`. The page asks for the password chosen
at sign-up; only then is the user created as `verified` and given the bonus,
in one database transaction (`activate_registration`).

- **Secrets:** 32 random bytes; only SHA-256 stored. Links last 30 minutes, are
  single-use, and a resend or change of address supersedes the previous one.
  The secret is after `#`, so it is never sent to a server, logged, or put in
  a Referer header; the page removes it from the address bar at once.
- **Scanners:** opening the link changes nothing; confirming is a POST from a
  button.
- **Someone else's address:** whoever starts a registration chooses its
  password; the inbox owner who did not cannot confirm it without that
  password, and "This was not me" cancels it. A new sign-up for an address
  replaces a pending one; pending sign-ups expire after 24 hours.
- **Limits:** 5 emails per address per hour, 20 sign-ups per source per hour,
  60 s between resends, 10 wrong passwords per 15 minutes on a link.
- **Bonus:** granted once per inbox (`bonus_claims`, provider-aware: plus tags
  stripped only for providers that document them, dots only for Gmail).
  Accounts are compared by the whole address, case-insensitively.
- **Existing accounts** were marked `legacy` by migration 0002 and are
  otherwise untouched: balances, purchases and sessions carry on.
- **Old app builds** that sign up without `verification: "link"` get a 403
  telling them to open the emailed link, then sign in - never an account.

Addresses: validator.js `isEmail`, trimmed, one address, no spaces or control
characters, at most 254 characters. Not supported: quoted local parts,
non-Latin characters before the @, IP-address domains. International domains
are stored in ASCII (punycode). No DNS or SMTP checks.

Mail: `RESEND_API_KEY` sends through Resend (the `EMAIL_FROM` domain must be
verified there). For development set `MAIL_TRANSPORT=capture`: messages are
written to `.mail/` and never sent; capture is refused when `WEB_ORIGIN` is
the real website. With neither, sign-up answers 503 and says why.

**Deploy order:** run `npm run db:migrate`, then deploy this code. Between the
two, the old code's sign-up fails (the new column has no default) rather than
creating unverified accounts; sign-in and saving keep working.

## Tests

```bash
npm test            # ledger + payments + password hashing + email verification, all on PGlite
API_E2E_ALLOW=1 npm run test:api   # against DATABASE_URL: use a test database, never the live one
npm run typecheck
```

## Deploy

**Render:** New → Blueprint → pick this repository. `render.yaml` sets up the
web service (build `npm install`, start `npm start`, health check `/health`) and
asks once for `DATABASE_URL` and `RESEND_API_KEY`. After the first deploy, add
the custom domain `api.toolpit.app` (Settings → Custom Domains) and its CNAME in
Cloudflare. Render's free plan sleeps after 15 minutes idle, so the first
request after a quiet spell takes ~30-50 s; the Starter plan stays awake.

`npm start` applies pending database migrations before starting the API. If a
migration fails, the API does not start against an incompatible schema.
Already applied migrations are skipped. `DATABASE_URL` must be available in
the service environment.

If an existing deployment logs `column u.email_status does not exist`, set
its Render Start Command to `node scripts/db-migrate.mjs && npm start` and
save to redeploy. This also works on the free plan, where Shell is unavailable.
On a paid plan, you can instead run `node scripts/db-migrate.mjs` in the service
Shell and restart the service. Migration `0002_email_verification.sql` adds the email verification
columns and preserves existing accounts, sessions and balances. Do not add
just the missing column manually: verification also needs the migration's
tables and functions.

**Vercel:** New Project → import this repository (Root Directory: the
repository root here, or `backend` when deploying from the toolpit monorepo).
Vercel detects Hono and serves `src/index.ts`.

**Any other Node host (Railway, Fly, a VPS):** build `npm install`, start
`npm start`, and set `PORT` if the host requires it.

### Environment

| Variable | |
|---|---|
| `DATABASE_URL` | Neon pooled connection string, `sslmode=verify-full`. **Secret.** |
| `WEB_ORIGIN` | `https://toolpit.app` - links in emails and checkout returns |
| `ALLOWED_ORIGINS` | `https://toolpit.app,https://www.toolpit.app` |
| `RESEND_API_KEY`, `EMAIL_FROM` | confirmation and password-reset emails. **Required for sign-up.** |
| `MAIL_TRANSPORT`, `MAIL_CAPTURE_DIR` | development only: `capture` writes emails to disk instead of sending |
| `REVENUECAT_WEBHOOK_SECRET` | shared secret RevenueCat sends. **Secret.** |
| `REVENUECAT_ACCEPT_SANDBOX` | `true` while testing store purchases, `false` at launch |
