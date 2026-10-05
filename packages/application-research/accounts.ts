import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
const AccountSchema = z.object({
  id: z.string(), username: z.string(), password: z.string(), createdAt: z.string(),
  registration: z.enum(['prepared', 'submitted', 'verified']),
  role: z.enum(['user', 'admin']).default('user'),
  tenant: z.string().regex(/^[a-z0-9-]+$/).default('default'),
}).strict();
export type Account = z.infer<typeof AccountSchema>;
// Labels are safe to log. The password and username stay in the encrypted store.
export function publicAccountLabel(account: { id: string; role?: 'user' | 'admin'; tenant?: string }) {
  return { id: account.id, role: account.role ?? 'user', tenant: account.tenant ?? 'default' };
}
export class AccountStore {
  constructor(private directory: string, private key: string) {
    if (!/^[a-f0-9]{64}$/i.test(key)) throw new Error('account_key_required');
  }
  private file(domain: string, id: string) { return join(this.directory, createHash('sha256').update(domain + ':' + id).digest('hex') + '.json'); }
  async get(domain: string, id: string): Promise<Account | undefined> {
    try {
      const envelope = JSON.parse(await readFile(this.file(domain, id), 'utf8'));
      const decipher = createDecipheriv('aes-256-gcm', Buffer.from(this.key, 'hex'), Buffer.from(envelope.iv, 'hex'));
      decipher.setAAD(Buffer.from(`${domain}:${id}`)); decipher.setAuthTag(Buffer.from(envelope.tag, 'hex'));
      return AccountSchema.parse(JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.data, 'base64')), decipher.final()]).toString('utf8')));
    } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw new Error('account_store_unreadable'); }
  }
  async put(domain: string, account: Account, create = false) {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', Buffer.from(this.key, 'hex'), iv);
    cipher.setAAD(Buffer.from(`${domain}:${account.id}`));
    const data = Buffer.concat([cipher.update(JSON.stringify(account)), cipher.final()]);
    const contents = JSON.stringify({ iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), data: data.toString('base64') });
    const file = this.file(domain, account.id);
    if (create) { await writeFile(file, contents, { flag: 'wx', mode: 0o600 }); return; }
    const temporary = `${file}.${randomBytes(8).toString('hex')}.tmp`;
    await writeFile(temporary, contents, { flag: 'wx', mode: 0o600 }); await rename(temporary, file);
  }
  async prepare(domain: string, id: string, emailDomain: string): Promise<Account> {
    const existing = await this.get(domain, id); if (existing) return existing;
    const account = AccountSchema.parse({ id, username: `anteater-${randomBytes(10).toString('hex')}@${emailDomain}`, password: `Aa1!${randomBytes(24).toString('base64url')}`, createdAt: new Date().toISOString(), registration: 'prepared' });
    try { await this.put(domain, account, true); return account; }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'EEXIST') return (await this.get(domain, id))!; throw error; }
  }
}
