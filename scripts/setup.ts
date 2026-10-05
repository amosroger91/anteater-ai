import { spawn } from 'node:child_process';
import { createSetupServer } from '../apps/setup/server.js';
import { windowsKeyProtector } from '../packages/setup/dpapi.js';
import { FileSetupStore, setupDirectory } from '../packages/setup/store.js';

function openBrowser(url: string): void {
  if (process.env.ANTEATER_SETUP_NO_BROWSER === '1') return;
  const child = process.platform === 'win32'
    ? spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'Start-Process', url], { detached: true, stdio: 'ignore', windowsHide: true })
    : spawn(process.platform === 'darwin' ? 'open' : 'xdg-open', [url], { detached: true, stdio: 'ignore' });
  child.on('error', () => console.log('Open that address in a browser on this computer.'));
  child.unref();
}

const store = new FileSetupStore(setupDirectory(), windowsKeyProtector);
const server = createSetupServer(store);
const started = await new Promise<number>((resolve, reject) => {
  server.once('error', reject);
  server.listen(4317, '127.0.0.1', () => {
    const address = server.address();
    resolve(typeof address === 'object' && address ? address.port : 4317);
  });
});
const url = `http://127.0.0.1:${started}/`;
console.log(`Setup is local only: ${url}`);
console.log('Nothing is sent to a research target. The kill switch stays on.');
openBrowser(url);
