import { ImapFlow } from 'imapflow';
import PostalMime from 'postal-mime';
import { setTimeout as sleep } from 'node:timers/promises';
import type { Account } from './accounts.js';
import type { Auth, Mailbox } from './profile.js';

export function verificationLink(text: string, origin: string, auth: Auth): string | undefined {
  for (const match of text.matchAll(/https:\/\/[^\s<>"']+/g)) {
    try {
      const url = new URL(match[0].replaceAll('&amp;', '&'));
      if (url.origin === origin && !url.username && !url.password && auth.verificationPaths.includes(url.pathname)) return url.href;
    } catch { /* Ignore malformed email links. */ }
  }
  return undefined;
}
export type VerifyMailbox = (account: Account, origin: string, auth: Auth, signal: AbortSignal) => Promise<string | undefined>;

export function imapVerifier(config: Mailbox, env: NodeJS.ProcessEnv = process.env): VerifyMailbox {
  return async (account, origin, auth, signal) => {
    const user = env[config.usernameEnv]; const pass = env[config.passwordEnv];
    if (!user || !pass) throw new Error('mailbox_credentials_missing');
    const client = new ImapFlow({ host: config.host, port: config.port, secure: true, auth: { user, pass }, logger: false,
      connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 10000, tls: { rejectUnauthorized: true } });
    const stop = () => client.close(); signal.addEventListener('abort', stop, { once: true });
    const deadline = Date.now() + config.timeoutSeconds * 1000;
    try {
      signal.throwIfAborted(); await client.connect();
      const lock = await client.getMailboxLock(config.folder);
      try {
        while (Date.now() < deadline && !signal.aborted) {
          const ids = await client.search({ to: account.username, since: new Date(account.createdAt) }, { uid: true });
          if (ids && ids.length) {
            const messages = await client.fetchAll(ids.slice(-10), { uid: true, envelope: true, internalDate: true, size: true }, { uid: true });
            for (const message of messages.reverse()) {
              if (!message.size || message.size > 262144 || !message.envelope?.to?.some(to => to.address?.toLowerCase() === account.username.toLowerCase())) continue;
              if (message.internalDate && new Date(message.internalDate).getTime() < Date.parse(account.createdAt) - 60000) continue;
              const full = await client.fetchOne(message.uid, { source: true }, { uid: true });
              if (!full || !full.source || full.source.length > 262144) continue;
              const mail = await PostalMime.parse(full.source);
              const link = verificationLink(`${mail.text ?? ''}\n${mail.html ?? ''}`, origin, auth);
              if (link) return link;
            }
          }
          await sleep(2000, undefined, { signal });
        }
      } finally { lock.release(); }
    } finally { signal.removeEventListener('abort', stop); client.close(); }
    return undefined;
  };
}
