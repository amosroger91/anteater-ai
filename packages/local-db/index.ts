import EmbeddedPostgres from 'embedded-postgres';
import { existsSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

// Zero-setup local database: a bundled, embedded PostgreSQL server (no Docker, no install). It lives in
// a persistent folder on LOCAL disk — not the project's network share, which Postgres handles poorly —
// on the port the default DATABASE_URL already points at, so nothing needs configuring.
export interface LocalDatabase { url: string; stop: () => Promise<void> }

export async function startLocalPostgres(opts: { dataDir?: string; port?: number } = {}): Promise<LocalDatabase> {
  const base = opts.dataDir ?? join(homedir(), '.anteater', 'pgdata');
  const port = opts.port ?? 55432;
  const user = 'anteater';
  const password = 'local-fixture-only';
  const database = 'anteater';
  await mkdir(base, { recursive: true });
  const postgres = new EmbeddedPostgres({
    databaseDir: join(base, 'data'), user, password, port, persistent: true,
    postgresFlags: ['-h', '127.0.0.1'], onLog: () => {}, onError: () => {},
  });
  // Initialise only the first time; a persistent data dir already has PG_VERSION.
  if (!existsSync(join(base, 'data', 'PG_VERSION'))) await postgres.initialise();
  await postgres.start();
  try { await postgres.createDatabase(database); } catch { /* already created on a prior run */ }
  return {
    url: `postgresql://${user}:${password}@127.0.0.1:${port}/${database}`,
    stop: () => postgres.stop(),
  };
}
