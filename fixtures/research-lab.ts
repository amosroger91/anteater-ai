import http from 'node:http';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import type { Exchange } from '../packages/application-research/transport.js';
import type { CleanupIntent, CleanupJournal } from '../packages/application-research/cleanup.js';

// Synthetic transport tests only. Production always injects the PostgreSQL journal.
export class FixtureCleanupJournal implements CleanupJournal {
  readonly records = new Map<string, CleanupIntent>();
  async pending() { return [...this.records.values()].map(value => structuredClone(value)); }
  async prepare(intent: CleanupIntent) { this.records.set(intent.id, structuredClone(intent)); }
  async complete(id: string) { this.records.delete(id); }
}

export async function startResearchLab(options: { vulnerable?: boolean; challenge?: boolean; signup?: boolean; tokenAuth?: boolean; missingIdOnCreate?: boolean } = {}) {
  const users = new Map<string, { password: string; verified: boolean }>([['alice@example.test', { password: 'alice-password', verified: true }], ['bob@example.test', { password: 'bob-password', verified: true }]]);
  const sessions = new Map<string, string>();
  const records = new Map<string, { owner: string; title: string }>();
  const verification = new Map<string, string>();
  const requests: Array<{ method: string; path: string }> = [];
  let registrations = 0;
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url!, 'http://localhost'); const path = url.pathname;
    requests.push({ method: req.method!, path });
    const cookie = /(?:^|;\s*)session=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];
    const token = req.headers.authorization?.replace(/^Bearer /, '');
    const user = sessions.get(options.tokenAuth ? token ?? '' : cookie ?? '');
    const json = (status: number, value: unknown) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)); };
    const html = (body: string) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(`<!doctype html><html><head><title>Research lab</title></head><body>${body}</body></html>`); };
    let data = ''; for await (const part of req) data += part.toString();
    const fields = req.headers['content-type']?.includes('json') ? (() => { try { return JSON.parse(data); } catch { return {}; } })() : Object.fromEntries(new URLSearchParams(data));
    if (path === '/login' || path === '/register') {
      if (path === '/register' && !options.signup) { json(404, {}); return; }
      const signup = path === '/register';
      html(`<form method="post" action="${signup ? '/api/register' : '/api/login'}"><input type="email" name="email" required><input type="password" name="password" required>${options.challenge ? '<input autocomplete="one-time-code" name="otp">' : ''}<button type="submit">${signup ? 'Register' : 'Log in'}</button></form>`); return;
    }
    if (path === '/api/register' && req.method === 'POST') {
      registrations++;
      if (!options.signup || users.has(fields.email)) { json(409, {}); return; }
      users.set(fields.email, { password: fields.password, verified: false });
      verification.set(fields.email, randomBytes(12).toString('hex')); html('<p>Check your email</p>'); return;
    }
    if (path === '/verify-email') {
      for (const [email, secret] of verification) if (secret === url.searchParams.get('token')) users.get(email)!.verified = true;
      html('<a href="/login">Log in</a>'); return;
    }
    if (path === '/api/login' && req.method === 'POST') {
      const account = users.get(fields.email);
      if (!account?.verified || account.password !== fields.password) { json(401, {}); return; }
      const id = randomBytes(12).toString('hex'); sessions.set(id, fields.email);
      res.writeHead(303, { 'set-cookie': `session=${id}; Path=/; Secure; HttpOnly; SameSite=Lax`, location: '/dashboard' }); res.end(); return;
    }
    if (path === '/api/me') { json(user ? 200 : 401, user ? { email: user, id: user } : {}); return; }
    if (path === '/api/documents' && req.method === 'POST') {
      if (!user) { json(401, {}); return; }
      const id = randomBytes(8).toString('hex'); records.set(id, { owner: user, title: fields.title }); json(201, options.missingIdOnCreate ? {} : { id }); return;
    }
    if (path.startsWith('/api/documents/by-marker/') && req.method === 'DELETE') {
      if (!user) { json(401, {}); return; }
      const marker = decodeURIComponent(path.slice('/api/documents/by-marker/'.length));
      const match = [...records].find(([, record]) => record.owner === user && record.title === marker);
      if (!match) { json(404, {}); return; }
      records.delete(match[0]); res.writeHead(204); res.end(); return;
    }
    if (path.startsWith('/api/documents/')) {
      const id = path.split('/').pop()!; const doc = records.get(id);
      if (!doc) { json(404, {}); return; }
      if (!user || (!options.vulnerable && doc.owner !== user) || (req.method === 'DELETE' && doc.owner !== user)) { json(403, {}); return; }
      if (req.method === 'DELETE') { records.delete(id); res.writeHead(204); res.end(); return; }
      json(200, { id, title: doc.title }); return;
    }
    if (path === '/dashboard' && !user) { res.writeHead(302, { location: '/login' }); res.end(); return; }
    if (path === '/api/catalog') { json(200, { products: [] }); return; }
    if (path === '/') { html(`<a href="/login">Log in</a>${options.signup ? '<a href="/register">Create account</a>' : ''}<a href="/dashboard">Dashboard</a><a href="https://outside.test/leak">Outside</a><script>fetch('/api/catalog');fetch('https://outside.test/leak').catch(()=>{});</script>`); return; }
    if (path === '/dashboard') { html('<h1>Private dashboard</h1><a href="/logout">Log out</a><script>fetch("/api/me")</script>'); return; }
    json(404, {});
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const address = server.address() as { port: number };
  const exchange: Exchange = async input => {
    await input.beforeConnect();
    return new Promise((resolve, reject) => {
      const request = http.request({ host: '127.0.0.1', port: address.port, method: input.method, path: input.url.pathname + input.url.search, headers: { ...input.headers, host: 'lab.example.test' }, signal: input.signal }, response => {
        const chunks: Buffer[] = [];
        response.on('data', part => chunks.push(part)); response.on('end', () => resolve({ status: response.statusCode!, headers: response.headers, body: Buffer.concat(chunks), truncated: false })); response.on('error', reject);
      });
      request.on('error', reject); request.end(input.body);
    });
  };
  return { exchange, requests, records, registrations: () => registrations,
    verification: (email: string) => verification.has(email) ? `https://lab.example.test/verify-email?token=${verification.get(email)}` : undefined,
    close: () => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())) };
}
