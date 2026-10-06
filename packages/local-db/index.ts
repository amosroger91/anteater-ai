import EmbeddedPostgres from 'embedded-postgres';
import { existsSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { connect as netConnect } from 'node:net';
import { homedir } from 'node:os';
import { join } from 'node:path';

const DEFAULT_PORT = 55432;
function localUrl(port: number): string { return `postgresql://anteater:local-fixture-only@127.0.0.1:${port}/anteater`; }

// Is something already listening on the local DB port? (e.g. the setup server started it, and now the
// worker/auto wants the same database.) A plain TCP probe — no auth, no query.
function portOpen(port: number, host = '127.0.0.1', timeoutMs = 600): Promise<boolean> {
  return new Promise(resolve => {
    const socket = netConnect({ port, host });
    const finish = (open: boolean) => { socket.destroy(); resolve(open); };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

// Zero-setup local database: a bundled, embedded PostgreSQL server (no Docker, no install). It lives in
// a persistent folder on LOCAL disk — not the project's network share, which Postgres handles poorly —
// on the port the default DATABASE_URL already points at, so nothing needs configuring.
export interface LocalDatabase { url: string; stop: () => Promise<void> }

// Share one local database across processes: if the port is already serving (the setup server, say,
// started it), reuse it with a no-op stop so we don't try to bind it twice; otherwise start our own.
// Either way the data lives in the same persistent folder, so programs imported in setup are visible
// to `auto`/the worker started later.
export async function ensureLocalPostgres(opts: { dataDir?: string; port?: number } = {}): Promise<LocalDatabase> {
  const port = opts.port ?? DEFAULT_PORT;
  if (await portOpen(port)) return { url: localUrl(port), stop: async () => { /* owned by another process */ } };
  return startLocalPostgres(opts);
}

export async function startLocalPostgres(opts: { dataDir?: string; port?: number } = {}): Promise<LocalDatabase> {
  const base = opts.dataDir ?? join(homedir(), '.anteater', 'pgdata');
  const port = opts.port ?? DEFAULT_PORT;
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
