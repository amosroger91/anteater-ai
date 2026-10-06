import https from 'node:https';
import { lookup } from 'node:dns/promises';
import { createHash } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';
import { addressBlockReason } from '../../scripts/posture-check.js';
import { mutatingGet, underPath, type Application } from './profile.js';

export type Purpose = 'discover' | 'login' | 'signup' | 'verify' | 'cleanup';
export interface ExchangeRequest { url: URL; method: string; headers: Record<string, string>; body?: Buffer; signal: AbortSignal; maxBytes: number; beforeConnect: () => Promise<void> }
export interface ExchangeResponse { status: number; headers: IncomingHttpHeaders; body: Buffer; truncated: boolean }
export type Exchange = (request: ExchangeRequest) => Promise<ExchangeResponse>;
export async function abortable<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  let listener = () => {};
  try {
    return await Promise.race([operation, new Promise<never>((_, reject) => {
      listener = () => reject(signal.reason);
      signal.addEventListener('abort', listener, { once: true });
      if (signal.aborted) listener();
    })]);
  } finally { signal.removeEventListener('abort', listener); }
}
export interface Endpoint { url: string; method: string; session: string; status: number; contentType: string; hash: string; truncated: boolean }
export function publicUrl(value: string): string {
  const url = new URL(value);
  return url.origin + url.pathname + (url.search ? '?' + [...new Set(url.searchParams.keys())].sort().map(key => `${encodeURIComponent(key)}=[redacted]`).join('&') : '');
}
export function allowedRequest(origin: string, app: Application, value: string, method: string, purpose: Purpose, ownedDeletes: Set<string> = new Set()): boolean {
  let url: URL;
  try { url = new URL(value); } catch { return false; }
  if (value.includes('\\') || url.origin !== origin || url.username || url.password || url.hash || value.length > 4096) return false;
  let path: string;
  try { path = decodeURIComponent(url.pathname); } catch { return false; }
  if (/[\\%\u0000-\u001f]/.test(path) || path.includes('//') || path.split('/').some(part => part === '.' || part === '..')) return false;
  if (app.excludedPaths.some(prefix => underPath(path, prefix))) return false;
  if (method === 'GET' || method === 'HEAD') {
    if (mutatingGet(path)) return false;
    return app.readPathPrefixes.some(prefix => underPath(path, prefix));
  }
  if (method === 'POST' && purpose === 'login') return app.auth.loginWritePaths.includes(path);
  if (method === 'POST' && purpose === 'signup' && app.auth.signupEnabled) return app.auth.signupWritePaths.includes(path);
  if (method === 'POST' && purpose === 'verify') return app.privateResources.some(rule => rule.createPath === path);
  if (method === 'DELETE' && purpose === 'cleanup') return ownedDeletes.has(url.href);
  return false;
}

export const pinnedExchange: Exchange = async input => {
  const records = await abortable(lookup(input.url.hostname, { all: true, verbatim: true }), input.signal);
  input.signal.throwIfAborted();
  const selected = records.find(record => !addressBlockReason(record.address));
  if (!selected) throw new Error('blocked_address');
  await input.beforeConnect(); input.signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const headers = { ...input.headers, host: input.url.host, 'accept-encoding': 'identity', 'user-agent': 'anteater-ai authorized application research' };
    for (const key of Object.keys(headers)) if (/^(connection|content-length|transfer-encoding|proxy-.*)$/i.test(key)) delete headers[key as keyof typeof headers];
    const request = https.request({ host: selected.address, family: selected.family, port: 443, servername: input.url.hostname,
      rejectUnauthorized: true, method: input.method, path: input.url.pathname + input.url.search, headers,
      signal: input.signal, agent: false, maxHeaderSize: 16384 }, response => {
      const chunks: Buffer[] = []; let bytes = 0; let settled = false;
      const finish = (truncated: boolean) => {
        if (settled) return; settled = true;
        resolve({ status: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks, bytes), truncated });
      };
      response.on('data', (data: Buffer) => {
        if (settled) return;
        const remaining = input.maxBytes - bytes; const chunk = data.subarray(0, remaining);
        chunks.push(chunk); bytes += chunk.length;
        if (data.length > remaining) { finish(true); response.destroy(); request.destroy(); }
      });
      response.on('end', () => finish(false));
      response.on('error', reject);
      response.on('aborted', () => { if (!settled) reject(new Error('response_aborted')); });
    });
    request.on('error', reject);
    request.end(input.body);
  });
};

export class RequestGate {
  readonly endpoints: Endpoint[] = [];
  readonly blocked: Record<string, number> = {};
  readonly ownedDeletes = new Set<string>();
  count = 0;
  constructor(readonly origin: string, readonly app: Application, readonly signal: AbortSignal,
    private beforeRequest: (signal: AbortSignal) => Promise<void>, private exchange: Exchange = pinnedExchange,
    private activeEnabled = false, private parentSignal?: AbortSignal) {}
  deny(reason: string) { this.blocked[reason] = (this.blocked[reason] ?? 0) + 1; }
  // A cleanup request remains inside maxRequests, but discovery and replay cannot spend its slot.
  get remainingRequests() { return Math.max(0, this.app.maxRequests - this.count - this.ownedDeletes.size); }
  reserveCleanup(value: string): boolean {
    if (this.ownedDeletes.has(value)) return true;
    if (!this.activeEnabled || this.remainingRequests < 1 || !allowedRequest(this.origin, this.app, value, 'DELETE', 'cleanup', new Set([value]))) return false;
    this.ownedDeletes.add(value);
    return true;
  }
  releaseCleanup(value: string) { this.ownedDeletes.delete(value); }
  async send(session: string, purpose: Purpose, value: string, method = 'GET', headers: Record<string, string> = {}, body?: Buffer): Promise<ExchangeResponse> {
    const cleanup = purpose === 'cleanup' && method === 'DELETE' && this.ownedDeletes.has(value);
    // Ordinary assessment expiry must not abandon owned data. Parent cancellation (kill switch,
    // revoked scope, shutdown, or lost job lease) still applies, as does beforeRequest below.
    const baseSignal = cleanup ? this.parentSignal : this.signal;
    baseSignal?.throwIfAborted();
    if (!allowedRequest(this.origin, this.app, value, method, purpose, this.ownedDeletes)) { this.deny('out_of_scope_or_method'); throw new Error('request_denied'); }
    if (!['GET', 'HEAD'].includes(method) && !this.activeEnabled) { this.deny('active_testing_disabled'); throw new Error('active_testing_disabled'); }
    if ((body?.length ?? 0) > 65536) throw new Error('request_body_too_large');
    if (this.count >= this.app.maxRequests || (!cleanup && this.remainingRequests < 1)) { this.deny('request_budget'); throw new Error('request_budget'); }
    if (cleanup) this.ownedDeletes.delete(value);
    this.count++;
    const timeout = AbortSignal.timeout(15000);
    const signal = baseSignal ? AbortSignal.any([baseSignal, timeout]) : timeout;
    signal.throwIfAborted();
    const response = await abortable(this.exchange({ url: new URL(value), method, headers, body, signal, maxBytes: this.app.maxResponseBytes,
      beforeConnect: () => abortable(this.beforeRequest(signal), signal) }), signal);
    this.endpoints.push({ url: publicUrl(value), method, session, status: response.status, contentType: String(response.headers['content-type'] ?? '').slice(0, 100), hash: createHash('sha256').update(response.body).digest('hex'), truncated: response.truncated });
    return response;
  }
}
