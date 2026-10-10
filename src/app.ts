import { Hono } from 'hono';
import { cors } from 'hono/cors';

import {
  chargeDownload,
  deleteAccount,
  handle,
  json,
  listPacks,
  readBody,
  requireUser,
  signIn,
  signUp,
  summary,
} from './account';
import { allowedOrigins, webOrigin } from './config';
import { checkout, revenueCatWebhook, sandboxComplete, webPaymentWebhook } from './payment-routes';
import { cancelLink, changeEmail, confirmLink, inspectLink, resend } from './registration';
import { completeReset, sendReset } from './reset';
import { createSession, endSession, sessionCookie } from './session';

/**
 * Toolpit's API, as one Hono app.
 *
 * Runs the same everywhere: `src/server.ts` serves it with Node for local
 * development or any Node host, and `src/index.ts` exports it for Vercel.
 *
 * Nothing here receives a file. The heaviest request any route takes is a
 * payment webhook; the website's and the app's files never leave the device.
 */
export const app = new Hono();

// Browsers may call with credentials only from the website's own origins.
app.use(
  '/api/*',
  cors({
    origin: (origin) => (allowedOrigins().includes(origin) ? origin : null),
    credentials: true,
    allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowHeaders: ['content-type', 'authorization'],
    maxAge: 600,
  }),
);

app.get('/', (c) => c.json({ name: 'toolpit-api', ok: true }));
app.get('/health', (c) => c.json({ ok: true }));

// ------------------------------------------------------------------- auth

// Sign-up creates a registration that waits for its email (registration.ts).
app.post('/api/auth/signup', (c) => handle(() => signUp(c.req.raw)));
app.post('/api/auth/signup/resend', (c) => handle(() => resend(c.req.raw)));
app.post('/api/auth/signup/change-email', (c) => handle(() => changeEmail(c.req.raw)));
app.post('/api/auth/verify/inspect', (c) => handle(() => inspectLink(c.req.raw)));
app.post('/api/auth/verify', (c) => handle(() => confirmLink(c.req.raw)));
app.post('/api/auth/verify/cancel', (c) => handle(() => cancelLink(c.req.raw)));
app.post('/api/auth/login', (c) => handle(() => signIn(c.req.raw)));

app.post('/api/auth/logout', (c) =>
  handle(async () => {
    await endSession(c.req.raw);
    return json({ ok: true }, 200, { 'set-cookie': sessionCookie(null, c.req.raw) });
  }),
);

app.post('/api/auth/forgot', (c) =>
  handle(async () => {
    const body = await readBody(c.req.raw);
    await sendReset(body.email, webOrigin());
    return json({ ok: true });
  }),
);

app.post('/api/auth/reset', (c) =>
  handle(async () => {
    const body = await readBody(c.req.raw);
    const userId = await completeReset(String(body.token ?? ''), String(body.password ?? ''));
    const token = await createSession(userId, c.req.header('user-agent') ?? null);
    return json({ token, account: await summary(userId) }, 200, { 'set-cookie': sessionCookie(token, c.req.raw) });
  }),
);

// ---------------------------------------------------------------- account

app.get('/api/account', (c) =>
  handle(async () => {
    const user = await requireUser(c.req.raw);
    return json({ account: await summary(user.id) });
  }),
);

app.delete('/api/account', (c) =>
  handle(async () => {
    const user = await requireUser(c.req.raw);
    await deleteAccount(user.id);
    return json({ ok: true }, 200, { 'set-cookie': sessionCookie(null, c.req.raw) });
  }),
);

/** Charge one download. The request carries the session and nothing else. */
app.post('/api/account/download', (c) =>
  handle(async () => {
    const user = await requireUser(c.req.raw);
    return json(await chargeDownload(user.id));
  }),
);

app.get('/api/packs', () => handle(async () => json({ packs: await listPacks() })));

// ------------------------------------------------------------------ money

app.post('/api/checkout', (c) => handle(() => checkout(c.req.raw)));
app.post('/api/sandbox/complete', (c) => handle(() => sandboxComplete(c.req.raw)));
app.post('/api/webhooks/revenuecat', (c) => revenueCatWebhook(c.req.raw));
app.post('/api/webhooks/payments', (c) => webPaymentWebhook(c.req.raw));

app.notFound(() => json({ error: 'Not found.' }, 404));
app.onError((error) => {
  console.error('[api]', error);
  return json({ error: 'Something went wrong on our side.' }, 500);
});
