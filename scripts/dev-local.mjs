/**
 * The API on your machine with nothing external: Postgres is PGlite (in
 * memory, fresh each start), and email is captured to .mail/ instead of sent.
 *
 *   npm run dev:local          # http://localhost:8787
 *
 * For trying sign-up and email confirmation end to end without a database
 * account, a mail provider or a real inbox. Open the newest file in .mail/
 * for the confirmation link. Never use it for anything that should persist.
 */
import { readdirSync, readFileSync } from 'node:fs';

import { serve } from '@hono/node-server';
import { PGlite } from '@electric-sql/pglite';

process.env.MAIL_TRANSPORT = 'capture';
process.env.WEB_ORIGIN = process.env.WEB_ORIGIN ?? 'http://localhost:3000';
delete process.env.RESEND_API_KEY;
delete process.env.DATABASE_URL;

const { app } = await import('../src/app.ts');
const { useDatabase } = await import('../src/db.ts');

const pg = await PGlite.create();
for (const name of readdirSync('db/migrations').filter((f) => f.endsWith('.sql')).sort()) {
  await pg.exec(readFileSync(`db/migrations/${name}`, 'utf8'));
}
useDatabase({ query: async (sql, params) => ({ rows: (await pg.query(sql, params)).rows }) });

const port = Number(process.env.PORT ?? 8787);
serve({ fetch: app.fetch, port }, () => {
  console.log(`toolpit-api (local: PGlite, captured mail in ${process.env.MAIL_CAPTURE_DIR ?? '.mail'}/) on http://localhost:${port}`);
});
