import pg from 'pg';
import { readFile } from 'node:fs/promises';
export const connect = (connectionString: string) => new pg.Pool({ connectionString, max: 5, connectionTimeoutMillis: 5000 });
export async function migrate(pool: pg.Pool) {
  await pool.query(await readFile(new URL('../../infrastructure/postgres/001_initial.sql', import.meta.url), 'utf8'));
}
export async function transaction<T>(pool: pg.Pool, fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try { await client.query('BEGIN'); const value = await fn(client); await client.query('COMMIT'); return value; }
  catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}
