import pg from 'pg';

/**
 * The database, from the server only.
 *
 * DATABASE_URL is Neon's pooled connection string. It carries the password, so
 * it lives in Vercel's environment and .env.local, never in a NEXT_PUBLIC_
 * variable and never in the repository.
 *
 * One small pool per server instance: Vercel runs many short-lived instances,
 * and Neon's pooler (the "-pooler" host) multiplexes them onto a few real
 * connections, so each instance holding more than a handful would only queue.
 */

let pool: pg.Pool | null = null;

export function databaseConfigured(): boolean {
  return Boolean(process.env.DATABASE_URL);
}

export function db(): pg.Pool {
  if (pool) return pool;
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) throw new Error('DATABASE_URL is not set.');
  pool = new pg.Pool({ connectionString, max: 3, idleTimeoutMillis: 10_000 });
  return pool;
}

/** One row, or null. */
export async function one<T>(sql: string, params: unknown[] = []): Promise<T | null> {
  const result = await db().query(sql, params);
  return (result.rows[0] as T | undefined) ?? null;
}
