import pg from 'pg';
import { readFile } from 'node:fs/promises';

export const connect = (connectionString: string) => new pg.Pool({ connectionString, max: 5, connectionTimeoutMillis: 5000 });

const migrationFiles = ['001_initial.sql', '002_hardening.sql', '003_execution_depth.sql', '004_application_research.sql', '005_ops.sql', '006_cleanup.sql'];

export async function migrate(pool: pg.Pool) {
  const client = await pool.connect();
  let locked = false;
  try {
    await client.query('CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
    await client.query('SELECT pg_advisory_lock(784290)');
    locked = true;
    for (const version of migrationFiles) {
      const applied = await client.query('SELECT 1 FROM schema_migrations WHERE version=$1', [version]);
      if (applied.rowCount) continue;
      const sql = await readFile(new URL(`../../infrastructure/postgres/${version}`, import.meta.url), 'utf8');
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations(version) VALUES($1)', [version]);
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    }
  } finally {
    if (locked) await client.query('SELECT pg_advisory_unlock(784290)');
    client.release();
  }
}

export async function transaction<T>(pool: pg.Pool, fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try { await client.query('BEGIN'); const value = await fn(client); await client.query('COMMIT'); return value; }
  catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}
