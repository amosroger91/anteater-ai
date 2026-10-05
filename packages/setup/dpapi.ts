import { spawnSync } from 'node:child_process';
import type { KeyProtector } from './store.js';

// Current-user DPAPI. The setup key never sits in git, and another Windows account cannot open it.
function run(action: 'Protect' | 'Unprotect', input: Buffer): Buffer {
  const command = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$in = [Convert]::FromBase64String($env:ANTEATER_DPAPI_IN)
$out = [System.Security.Cryptography.ProtectedData]::${action}($in, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Out.Write([Convert]::ToBase64String($out))
`;
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], {
    env: { ...process.env, ANTEATER_DPAPI_IN: input.toString('base64') },
    encoding: 'utf8',
    windowsHide: true,
  });
  const text = result.stdout.trim();
  if (result.status !== 0 || !text) throw new Error('setup_key_protection_failed');
  return Buffer.from(text, 'base64');
}

export const windowsKeyProtector: KeyProtector = {
  sealKey: raw => run('Protect', raw),
  openKey: blob => run('Unprotect', blob),
};
