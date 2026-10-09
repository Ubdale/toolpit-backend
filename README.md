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
  account.ts         sign-up, sign-in, balance, download charge, delete
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
| POST | `/api/auth/signup` | `{name, email, password}` → signed in, 50 tokens |
| POST | `/api/auth/login` | `{email, password}` → `{token, account}` + cookie |
| POST | `/api/auth/logout` | ends the session |
| POST | `/api/auth/forgot` | `{email}` → reset link by email (needs `RESEND_API_KEY`) |
| POST | `/api/auth/reset` | `{token, password}` → new password, signed in |
| GET | `/api/account` | `{id, email, name, balance, cost}` |
| DELETE | `/api/account` | deletes the account and its balance |
| POST | `/api/account/download` | charges 10 tokens; 402 if not enough |
| GET | `/api/packs` | the four token packs |
| POST | `/api/webhooks/revenuecat` | Play / App Store purchases and refunds |
| POST | `/api/checkout`, `/api/webhooks/payments` | website purchases (off until a provider is chosen) |
| GET | `/health` | `{ok: true}` |

The website authenticates with an httpOnly `tp_session` cookie (the API and the
site share the `toolpit.app` domain, so it is first-party); the app sends
`Authorization: Bearer <token>`. Browsers may call only from `ALLOWED_ORIGINS`.

## Tests

```bash
npm test            # ledger + payments (real Postgres via PGlite) + password hashing
npm run test:api    # end to end through the app against DATABASE_URL; cleans up after itself
npm run typecheck
```

## Deploy

**Render:** New → Blueprint → pick this repository. `render.yaml` sets up the
web service (build `npm install`, start `npm start`, health check `/health`) and
asks once for `DATABASE_URL` and `RESEND_API_KEY`. After the first deploy, add
the custom domain `api.toolpit.app` (Settings → Custom Domains) and its CNAME in
Cloudflare. Render's free plan sleeps after 15 minutes idle, so the first
request after a quiet spell takes ~30-50 s; the Starter plan stays awake.

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
| `RESEND_API_KEY`, `EMAIL_FROM` | password-reset emails (optional) |
| `REVENUECAT_WEBHOOK_SECRET` | shared secret RevenueCat sends. **Secret.** |
| `REVENUECAT_ACCEPT_SANDBOX` | `true` while testing store purchases, `false` at launch |
