import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { decrypt, encrypt } from '../evidence/index.js';
import { blankProfile, SetupProfileSchema, type SetupProfile } from './profile.js';

export interface KeyProtector {
  sealKey(raw: Buffer): Buffer;
  openKey(blob: Buffer): Buffer;
}

export const rawKeyProtector: KeyProtector = {
  sealKey: raw => Buffer.from(raw),
  openKey: blob => Buffer.from(blob),
};

export class FileSetupStore {
  constructor(private directory: string, private keys: KeyProtector) {}

  read(): SetupProfile | null {
    const sealedPath = join(this.directory, 'setup.json');
    if (!existsSync(sealedPath)) return null;
    const parsed = JSON.parse(readFileSync(sealedPath, 'utf8')) as { version?: number; sealed?: string };
    if (parsed.version !== 1 || typeof parsed.sealed !== 'string') throw new Error('setup_unreadable');
    const key = this.keyHex();
    let json: string;
    try { json = decrypt(parsed.sealed, key); }
    catch { throw new Error('setup_unreadable'); }
    return SetupProfileSchema.parse(JSON.parse(json));
  }

  write(profile: SetupProfile): void {
    const stored = SetupProfileSchema.parse(profile);
    mkdirSync(this.directory, { recursive: true });
    const sealed = encrypt(JSON.stringify(stored), this.keyHex());
    writeFileSync(join(this.directory, 'setup.json'), JSON.stringify({ version: 1, sealed }), { mode: 0o600 });
  }

  private keyHex(): string {
    const path = join(this.directory, 'setup.key');
    mkdirSync(this.directory, { recursive: true });
    if (!existsSync(path)) {
      const created = randomBytes(32);
      writeFileSync(path, this.keys.sealKey(created), { mode: 0o600 });
    }
    const opened = this.keys.openKey(readFileSync(path));
    if (opened.length !== 32) throw new Error('setup_unreadable');
    return opened.toString('hex');
  }
}

export function setupDirectory(env: NodeJS.ProcessEnv = process.env): string {
  return env.ANTEATER_SETUP_DIR || 'secrets';
}

export { blankProfile };
