/**
 * Applies db/migrations/*.sql to a database, in order, once each.
 *
 *   DATABASE_URL='<Neon connection string>' \
 *     node scripts/db-migrate.mjs
 *
 * Applied files are recorded in toolpit_meta.migrations - its own schema, so
 * it never mixes with the app's own tables - and each file runs inside one
 * transaction: a migration either lands whole or not at all, and running this
 * twice is harmless.
 *
 * The connection string carries the database password. Pass it in the
 * environment for this one command; never write it into a file in the repo.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import pg from 'pg';

const url = process.env.DATABASE_URL;
if (!url) {
  console.error('Set DATABASE_URL to the Postgres connection string (Neon -> Connect).');
  process.exit(1);
}

const dir = 'db/migrations';
const files = readdirSync(dir).filter((name) => name.endsWith('.sql')).sort();

const client = new pg.Client({ connectionString: url, ssl: { rejectUnauthorized: false } });
await client.connect();

await client.query(`
  create schema if not exists toolpit_meta;
  create table if not exists toolpit_meta.migrations (
    name text primary key,
    applied_at timestamptz not null default now()
  );
`);

const done = new Set((await client.query('select name from toolpit_meta.migrations')).rows.map((r) => r.name));

for (const name of files) {
  if (done.has(name)) {
    console.log(`  skip  ${name} (already applied)`);
    continue;
  }
  try {
    await client.query('begin');
    await client.query(readFileSync(join(dir, name), 'utf8'));
    await client.query('insert into toolpit_meta.migrations (name) values ($1)', [name]);
    await client.query('commit');
    console.log(`  done  ${name}`);
  } catch (error) {
    await client.query('rollback');
    console.error(`  FAIL  ${name}: ${error.message}`);
    await client.end();
    process.exit(1);
  }
}

const packs = await client.query('select id, tokens, price_cents from token_packs order by sort_order');
console.log(`\n${packs.rows.length} token packs: ${packs.rows.map((p) => `${p.tokens}/$${(p.price_cents / 100).toFixed(2)}`).join(', ')}`);
const bonus = await client.query('select signup_bonus_tokens() as n, tokens_per_file() as cost');
console.log(`sign-up bonus ${bonus.rows[0].n} tokens, ${bonus.rows[0].cost} per download`);
await client.end();
