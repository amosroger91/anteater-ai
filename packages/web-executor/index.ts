import https from 'node:https';
import { lookup, resolveCname } from 'node:dns/promises';
import { createHash } from 'node:crypto';
import type { ClientRequest, IncomingMessage, IncomingHttpHeaders, RequestOptions } from 'node:http';
import { addressBlockReason, findingsFromResponse } from '../../scripts/posture-check.js';
import { authorize } from '../scope-engine/index.js';
import { paidReadFindings } from '../web-checks/index.js';
import { guardModelContext } from '../inert/index.js';

export interface PassiveDeps {
  lookup(hostname: string): Promise<Array<{ address: string; family: number }>>;
  request(options: RequestOptions, callback: (response: IncomingMessage) => void): ClientRequest;
  // Optional, read-only: the host's CNAME target, used only as subdomain-takeover detector metadata.
  // It never changes which address the socket connects to (that stays pinned to the A/AAAA lookup).
  resolveCname?(hostname: string): Promise<string | undefined>;
}
export interface PassiveOptions {
  maxBytes: number;
  signal?: AbortSignal;
  beforeRequest?: () => Promise<void>;
  timeoutMs?: number;
  deps?: PassiveDeps;
  labTargets?: LabTargetAllow;
}
// Private-address relaxation for an explicit owned-lab hostname list. Loopback and link-local
// stay blocked inside addressBlockReason. A host that is not in the set never receives allowPrivate.
export interface LabTargetAllow { enabled: boolean; hosts: ReadonlySet<string> }
export function parseLabTargetAllow(enabled: boolean, hostList: string): LabTargetAllow {
  const hosts = new Set<string>();
  for (const part of hostList.split(',')) {
    const host = part.trim().toLowerCase().replace(/\.$/, '');
    if (host) hosts.add(host);
  }
  return { enabled, hosts };
}
export function labPrivateAllowed(hostname: string, allow: LabTargetAllow | undefined): boolean {
  if (!allow?.enabled) return false;
  return allow.hosts.has(hostname.toLowerCase().replace(/\.$/, ''));
}
const realDeps: PassiveDeps = {
  lookup: hostname => lookup(hostname, { all: true, verbatim: true }),
  request: (options, callback) => https.request(options, callback),
  resolveCname: async hostname => { try { const names = await resolveCname(hostname); return names[0]; } catch { return undefined; } },
};
const HEADER_NAMES = new Set(['content-type', 'content-length', 'cache-control', 'last-modified', 'server', 'x-powered-by', 'strict-transport-security', 'content-security-policy', 'x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy']);
const RETRYABLE_TRANSPORT = new Set(['enotfound', 'eai_again', 'econnreset', 'econnrefused', 'etimedout', 'econnaborted', 'request_failed', 'response_aborted', 'enetunreach', 'ehostunreach', 'esockettimedout']);

/** DNS, TLS, and socket failures are incomplete observations. The worker retries them instead of storing them as finished. */
export function retryableTransportError(observation: unknown): string | undefined {
  if (!observation || typeof observation !== 'object' || !('error' in observation)) return undefined;
  const code = (observation as { error?: unknown }).error;
  return typeof code === 'string' && RETRYABLE_TRANSPORT.has(code) ? code : undefined;
}

function rawHeaderRecord(headers: IncomingHttpHeaders): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    result[name.toLowerCase()] = (Array.isArray(value) ? value.join(', ') : String(value ?? '')).slice(0, 2048);
  }
  return result;
}

function cleanHeaders(headers: IncomingHttpHeaders): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (HEADER_NAMES.has(name.toLowerCase())) result[name.toLowerCase()] = (Array.isArray(value) ? value.join(', ') : String(value ?? '')).slice(0, 512);
  }
  // Locations can contain access tokens: retain only their origin/path.
  if (headers.location) {
    try { const location = new URL(headers.location, 'https://relative.invalid'); result.location = `${location.origin === 'https://relative.invalid' ? '' : location.origin}${location.pathname}`.slice(0, 512); }
    catch { result.location = '[invalid location]'; }
  }
  return result;
}

/** One DNS-pinned HTTPS GET with a total deadline, byte cap, strict TLS and no redirects. */
export async function executePassiveHttp(target: string, options: PassiveOptions): Promise<Record<string, unknown>> {
  const url = new URL(target);
  if (url.protocol !== 'https:' || (url.port && url.port !== '443') || url.username || url.password || url.search || url.hash) throw new Error('unsupported_target_form');
  if (!Number.isInteger(options.maxBytes) || options.maxBytes < 1024 || options.maxBytes > 1048576) throw new Error('invalid_response_limit');
  const timeoutMs = options.timeoutMs ?? 10000;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60000) throw new Error('invalid_timeout');
  const deps = options.deps ?? realDeps;
  const controller = new AbortController();
  const cancel = () => controller.abort(new Error('cancelled'));
  options.signal?.addEventListener('abort', cancel, { once: true });
  if (options.signal?.aborted) cancel();
  const timer = setTimeout(() => controller.abort(new Error('request_timeout')), timeoutMs);
  const base = { kind: 'OBSERVATION', executor: 'http-passive', target };
  let gateError: unknown;
  const abortable = async <T>(operation: Promise<T>): Promise<T> => {
    controller.signal.throwIfAborted();
    let listener: () => void = () => {};
    try {
      return await Promise.race([operation, new Promise<never>((_, reject) => {
        listener = () => reject(controller.signal.reason);
        controller.signal.addEventListener('abort', listener, { once: true });
      })]);
    } finally { controller.signal.removeEventListener('abort', listener); }
  };
  try {
    controller.signal.throwIfAborted();
    // One lookup, then connect to that address. A later resolution cannot move the socket.
    const answers = await abortable(deps.lookup(url.hostname));
    const allowPrivate = labPrivateAllowed(url.hostname, options.labTargets);
    const selected = answers.find(answer => (answer.family === 4 || answer.family === 6) && !addressBlockReason(answer.address, allowPrivate));
    if (!selected) return { ...base, error: 'blocked_address' };
    // Resolve first, then revalidate the current lease/policy and reserve a request slot.
    if (options.beforeRequest) {
      try { await abortable(options.beforeRequest()); }
      catch (error) { gateError = error; throw error; }
    }
    controller.signal.throwIfAborted();
    // Best-effort CNAME (read-only DNS metadata for the takeover detector). Never fatal, never pins the socket.
    let cname: string | undefined;
    if (deps.resolveCname) { try { cname = await abortable(deps.resolveCname(url.hostname)); } catch { cname = undefined; } }
    controller.signal.throwIfAborted();
    return await new Promise<Record<string, unknown>>((resolve, reject) => {
      let settled = false;
      const request = deps.request({
        host: selected.address, family: selected.family, port: 443, servername: url.hostname,
        path: url.pathname || '/', method: 'GET', signal: controller.signal,
        headers: { host: url.host, 'user-agent': 'anteater-ai passive research (read-only)', 'accept-encoding': 'identity', accept: 'text/html,application/json,application/xml,text/plain;q=0.8,*/*;q=0.1' },
        rejectUnauthorized: true, maxHeaderSize: 16384, agent: false,
      } as https.RequestOptions, response => {
        const chunks: Buffer[] = [];
        let bytes = 0;
        const finish = (truncated: boolean) => {
          if (settled) return;
          settled = true;
          const captured = Buffer.concat(chunks, bytes);
          const headers = cleanHeaders(response.headers);
          const contentType = headers['content-type'] ?? '';
          const readable = (!response.headers['content-encoding'] || response.headers['content-encoding'] === 'identity') && (/^text\//i.test(contentType) || /json|xml/i.test(contentType));
          const signals = findingsFromResponse(url, response.headers)
            .filter(finding => /html/i.test(contentType) || !/csp|missing_headers/.test(finding.code))
            .slice(0, 20).map(finding => ({ ...finding, detail: finding.detail.slice(0, 512) }));
          const seen = new Set(signals.map(finding => finding.code));
          for (const finding of paidReadFindings({
            status: response.statusCode ?? 0,
            headers: rawHeaderRecord(response.headers),
            body: captured.toString('utf8'),
            path: url.pathname || '/',
            requestHost: url.hostname,
            cname,
          })) {
            if (seen.has(finding.code)) continue;
            seen.add(finding.code);
            signals.push({ code: finding.code, severity: finding.severity, detail: finding.detail.slice(0, 512) });
          }
          resolve({ ...base, ip: selected.address, status: response.statusCode ?? 0, headers, contentType,
            bodyBytes: bytes, bodySha256: createHash('sha256').update(captured).digest('hex'), hashScope: 'captured_bytes',
            bodySnippet: readable ? guardModelContext(captured.toString('utf8').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').slice(0, 2048)).redacted : null,
            truncated, signals });
        };
        response.on('data', (chunk: Buffer) => {
          if (settled) return;
          const remaining = options.maxBytes - bytes;
          const part = chunk.subarray(0, remaining);
          chunks.push(part); bytes += part.length;
          if (chunk.length > remaining) { finish(true); response.destroy(); request.destroy(); }
        });
        response.on('end', () => finish(false));
        response.on('error', error => { if (!settled) { settled = true; reject(error); } });
        response.on('aborted', () => { if (!settled) { settled = true; reject(Object.assign(new Error('response_aborted'), { code: 'RESPONSE_ABORTED' })); } });
      });
      request.on('error', error => { if (!settled) { settled = true; reject(error); } });
      request.end();
    });
  } catch (error) {
    // Authorization, cancellation and rate-limit errors must remain retry/stop decisions for the worker.
    if (controller.signal.aborted || gateError === error) throw error;
    const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
    return { ...base, error: /^[A-Z0-9_]+$/.test(code) ? code.toLowerCase() : 'request_failed' };
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', cancel);
  }
}

const PAID_OBSERVATION_CODES = new Set(['exposed_vcs', 'exposed_admin', 'secrets_in_js', 'open_redirect_to_takeover']);

export interface PaidProbe {
  probed: string[];
  signals: Array<{ code: string; severity: string; detail: string }>;
}

// One read-only GET per path, and only when the reviewed policy allows that exact path.
// A denied path is not requested. The returned signals are detector codes and fixed details.
export async function probeAuthorizedGets(input: {
  host: string;
  policy: unknown;
  killSwitch: boolean;
  enabled: boolean;
  paths: readonly string[];
  maxBytes: number;
  deps?: PassiveDeps;
  reserve?: () => Promise<boolean>;
  beforeRequest?: (target: string) => Promise<void>;
  signal?: AbortSignal;
  labTargets?: LabTargetAllow;
}): Promise<PaidProbe> {
  const empty: PaidProbe = { probed: [], signals: [] };
  const host = input.host.toLowerCase().replace(/\.$/, '');
  if (!input.enabled || input.killSwitch || !/^[a-z0-9.-]+$/.test(host)) return empty;
  const probed: string[] = [];
  const signals: PaidProbe['signals'] = [];
  for (const path of input.paths) {
    input.signal?.throwIfAborted();
    if (!path.startsWith('/') || path.includes('//') || path.includes('?') || path.includes('#')) continue;
    const decision = authorize(input.policy, `https://${host}${path}`, 'inspect_http_target', { GLOBAL_KILL_SWITCH: input.killSwitch });
    if (!decision.allowed) continue;
    if (input.reserve && !await input.reserve()) break;
    const target = `https://${host}${path}`;
    const observation = await executePassiveHttp(target, {
      maxBytes: input.maxBytes, deps: input.deps, signal: input.signal, labTargets: input.labTargets,
      beforeRequest: input.beforeRequest ? () => input.beforeRequest!(target) : undefined,
    });
    if (typeof observation.status !== 'number' || observation.error !== undefined) continue;
    probed.push(path);
    if (!Array.isArray(observation.signals)) continue;
    for (const signal of observation.signals) {
      if (!signal || typeof signal !== 'object') continue;
      const row = signal as Record<string, unknown>;
      if (typeof row.code !== 'string' || !PAID_OBSERVATION_CODES.has(row.code)) continue;
      if (typeof row.severity !== 'string' || typeof row.detail !== 'string') continue;
      signals.push({ code: row.code, severity: row.severity, detail: row.detail.slice(0, 512) });
    }
  }
  return { probed, signals };
}
