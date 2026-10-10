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
 *
 * Every multi-step write is one plpgsql function call, so nothing here needs
 * a checked-out client or an explicit transaction - which is also what lets
 * the tests swap in PGlite (`useDatabase`) and run the real app end to end.
 */

export type Queryable = {
  query: (sql: string, params?: unknown[]) => Promise<{ rows: any[] }>;
};

let pool: Queryable | null = null;

/** Tests only: run the app against another Postgres (PGlite). */
export function useDatabase(database: Queryable): void {
  pool = database;
}

export function databaseConfigured(): boolean {
  return pool !== null || Boolean(process.env.DATABASE_URL);
}

export function db(): Queryable {
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
