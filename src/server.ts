import { serve } from '@hono/node-server';

import { app } from './app';

/**
 * Entry point for local development and any plain Node host (Railway, Render,
 * a VPS): `npm run dev` or `npm start`. Listens on PORT, 8787 by default.
 */
const port = Number(process.env.PORT ?? 8787);
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`toolpit-api listening on http://localhost:${info.port}`);
});
