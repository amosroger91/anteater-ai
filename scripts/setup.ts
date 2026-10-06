import { spawn } from 'node:child_process';
import { createSetupServer } from '../apps/setup/server.js';
import { windowsKeyProtector } from '../packages/setup/dpapi.js';
import { FileSetupStore, setupDirectory } from '../packages/setup/store.js';
import { ensureLocalPostgres, type LocalDatabase } from '../packages/local-db/index.js';
import { connect, migrate } from '../packages/research-state/db.js';

function openBrowser(url: string): void {
  if (process.env.ANTEATER_SETUP_NO_BROWSER === '1') return;
  const child = process.platform === 'win32'
    ? spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'Start-Process', url], { detached: true, stdio: 'ignore', windowsHide: true })
    : spawn(process.platform === 'darwin' ? 'open' : 'xdg-open', [url], { detached: true, stdio: 'ignore' });
  child.on('error', () => console.log('Open that address in a browser on this computer.'));
  child.unref();
}

// The database the setup UI writes to must be the same one the engine reads later. Use an external
// DATABASE_URL if one is set; otherwise start (or reuse) the bundled local database on its shared,
// persistent folder — so companies you import here are saved and waiting for `npm run auto` to test.
let localDb: LocalDatabase | undefined;
const external = process.env.DATABASE_URL && !process.env.DATABASE_URL.includes(':55432/');
if (external) {
  console.log('Setup: using external DATABASE_URL.');
} else {
  try {
    localDb = await ensureLocalPostgres();
    process.env.DATABASE_URL = localDb.url;
    const pool = connect(localDb.url);
    try { await migrate(pool); } finally { await pool.end(); }
    console.log('Setup: local database ready — companies you import are saved here for the engine to test.');
  } catch (error) {
    console.error(`Setup: could not start the local database: ${error instanceof Error ? error.message : 'unknown'}`);
    process.exit(1);
  }
}

const store = new FileSetupStore(setupDirectory(), windowsKeyProtector);
const server = createSetupServer(store);
async function stop(code = 0): Promise<never> {
  try { server.close(); } catch { /* already closing */ }
  if (localDb) { try { await localDb.stop(); } catch { /* already stopped */ } }
  process.exit(code);
}
process.on('SIGINT', () => { void stop(0); });
process.on('SIGTERM', () => { void stop(0); });
const started = await new Promise<number>((resolve, reject) => {
  server.once('error', reject);
  server.listen(4317, '127.0.0.1', () => {
    const address = server.address();
    resolve(typeof address === 'object' && address ? address.port : 4317);
  });
});
const url = `http://127.0.0.1:${started}/`;
console.log(`Setup is local only: ${url}`);
console.log('Fetch companies contacts HackerOne; Scan contacts a saved hostname. Saving setup starts neither.');
openBrowser(url);
