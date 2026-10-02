import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { BlockList, isIP } from 'node:net';
import { lookup } from 'node:dns/promises';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';

// Read-only exposure check for one operator-listed URL.
//
// One row is one URL. A bare domain becomes https://that-host/ and nothing else:
// no subdomain enumeration, no extra ports, no path discovery.
// For each accepted target this performs one TLS handshake (HTTPS only) and one GET,
// following at most three same-host redirects. It does not follow a redirect onto
// another host or from HTTPS to HTTP. The GET is pinned to the DNS address that
// passed the address check, so a later answer cannot move the connection.
// Loopback, link-local, and unspecified addresses are always refused.
// RFC1918 and CGNAT addresses are refused unless the caller passes allowPrivate.

const TIMEOUT = 10000;
const DELAY_MS = 1500;
const MAX_REDIRECTS = 3;
const USER_AGENT = 'anteater-posture-check (read-only)';

const SECURITY_HEADERS = [
  'strict-transport-security', 'content-security-policy', 'x-content-type-options',
  'x-frame-options', 'referrer-policy', 'permissions-policy',
];

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export interface Finding { code: string; severity: Severity; detail: string }
export interface TargetResult {
  target: string; origin: string; ip: string | null; reachable: boolean;
  findings: Finding[]; checkedAt: string;
}
export interface ExchangeResult { status: number; headers: http.IncomingHttpHeaders }
export interface TlsInfo {
  protocol: string | null; issuer: string; subject: string;
  daysToExpiry: number | null; selfSigned: boolean; authorized: boolean;
  authorizationError: string | null; error?: string;
}
export interface CheckDeps {
  lookup(hostname: string): Promise<Array<{ address: string; family: number }>>;
  tls(ip: string, port: number, servername: string): Promise<TlsInfo>;
  exchange(url: URL, ip: string, family: number): Promise<ExchangeResult>;
}
export interface CheckOptions { allowPrivate?: boolean; deps?: CheckDeps }

const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export const worstSeverity = (findings: Finding[]): Severity =>
  findings.reduce<Severity>((acc, f) => (RANK[f.severity] > RANK[acc] ? f.severity : acc), 'info');

const block = (subnets: Array<[string, number, 'ipv4' | 'ipv6']>, addresses: Array<[string, 'ipv4' | 'ipv6']> = []) => {
  const list = new BlockList();
  for (const [network, prefix, type] of subnets) list.addSubnet(network, prefix, type);
  for (const [address, type] of addresses) list.addAddress(address, type);
  return list;
};
const BLOCKS: Array<{ reason: string; privateOnly?: boolean; list: BlockList }> = [
  { reason: 'unspecified', list: block([['0.0.0.0', 8, 'ipv4']], [['::', 'ipv6']]) },
  { reason: 'loopback', list: block([['127.0.0.0', 8, 'ipv4']], [['::1', 'ipv6']]) },
  { reason: 'link-local', list: block([['169.254.0.0', 16, 'ipv4'], ['fe80::', 10, 'ipv6']]) },
  { reason: 'multicast', list: block([['224.0.0.0', 4, 'ipv4'], ['ff00::', 8, 'ipv6']]) },
  { reason: 'reserved', list: block([['240.0.0.0', 4, 'ipv4']]) },
  { reason: 'private', privateOnly: true, list: block([['10.0.0.0', 8, 'ipv4'], ['172.16.0.0', 12, 'ipv4'], ['192.168.0.0', 16, 'ipv4'], ['100.64.0.0', 10, 'ipv4'], ['fc00::', 7, 'ipv6']]) },
];

function canonicalIp(ip: string): { address: string; family: 'ipv4' | 'ipv6' } | null {
  if (isIP(ip) === 4) return { address: ip, family: 'ipv4' };
  if (isIP(ip) !== 6) return null;
  const lower = ip.toLowerCase().split('%')[0] ?? ip;
  const dotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
  if (dotted?.[1] && isIP(dotted[1]) === 4) return { address: dotted[1], family: 'ipv4' };
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(lower);
  if (hex?.[1] && hex[2]) {
    const hi = parseInt(hex[1], 16);
    const lo = parseInt(hex[2], 16);
    return { address: `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`, family: 'ipv4' };
  }
  return { address: lower, family: 'ipv6' };
}

export function addressBlockReason(ip: string, allowPrivate = false): string | null {
  const canon = canonicalIp(ip);
  if (!canon) return 'invalid_address';
  for (const rule of BLOCKS) {
    if (rule.privateOnly && allowPrivate) continue;
    if (rule.list.check(canon.address, canon.family)) return rule.reason;
  }
  return null;
}

export function canonicalTarget(raw: string): { href: string; origin: string } | { error: string } {
  const trimmed = raw.trim();
  let url: URL;
  try { url = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`); }
  catch { return { error: 'invalid_target' }; }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return { error: 'unsupported_scheme' };
  if (url.username || url.password) return { error: 'credentials_in_url' };
  if (!url.hostname) return { error: 'invalid_target' };
  url.hash = '';
  url.hostname = url.hostname.replace(/\.$/, '');
  return { href: url.href, origin: url.origin };
}

export function hstsFindings(value: string | null): Finding[] {
  if (!value) return [{ code: 'missing_hsts', severity: 'medium', detail: 'no Strict-Transport-Security' }];
  const findings: Finding[] = [];
  const match = /(?:^|;)\s*max-age\s*=\s*(\d+)/i.exec(value);
  const maxAge = match?.[1] === undefined ? null : Number(match[1]);
  if (maxAge === null || maxAge === 0) findings.push({ code: 'hsts_disabled', severity: 'medium', detail: value.slice(0, 160) });
  else if (maxAge < 2_592_000) findings.push({ code: 'hsts_short_max_age', severity: 'low', detail: `max-age=${maxAge}` });
  if (!/includeSubDomains/i.test(value)) findings.push({ code: 'hsts_host_only', severity: 'info', detail: 'no includeSubDomains' });
  return findings;
}

export function cspFindings(value: string | null): Finding[] {
  if (!value?.trim()) return [{ code: 'missing_csp', severity: 'medium', detail: 'no Content-Security-Policy' }];
  const directives = new Map<string, string>();
  for (const part of value.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    const name = tokens.shift()?.toLowerCase();
    if (name) directives.set(name, tokens.join(' '));
  }
  const script = directives.get('script-src') ?? directives.get('default-src');
  if (script === undefined) return [{ code: 'csp_weak', severity: 'low', detail: 'no default-src or script-src' }];
  const sources = script.toLowerCase().split(/\s+/).filter(Boolean);
  const hashed = sources.some(token => token.startsWith("'nonce-") || token.startsWith("'sha"));
  const weak = sources.includes('*') || sources.includes("'unsafe-eval'") || (sources.includes("'unsafe-inline'") && !hashed);
  return weak ? [{ code: 'csp_weak', severity: 'low', detail: script.slice(0, 160) }] : [];
}

export function cookieWeakness(cookie: string): string | null {
  const parts = cookie.split(';').map(part => part.trim()).filter(Boolean);
  const name = parts[0]?.split('=')[0]?.trim() || 'cookie';
  const flags = parts.slice(1).map(part => part.toLowerCase());
  const present = (flag: string) => flags.some(item => item === flag || item.startsWith(`${flag}=`));
  const missing = ['secure', 'httponly', 'samesite'].filter(flag => !present(flag));
  return missing.length ? `${name} missing ${missing.join(', ')}` : null;
}

export function findingsFromTls(info: TlsInfo): Finding[] {
  if (info.error) return [{ code: 'tls_uninspectable', severity: 'info', detail: info.error }];
  const findings: Finding[] = [];
  const auth = info.authorizationError ?? '';
  const expired = (info.daysToExpiry !== null && info.daysToExpiry < 0) || /CERT_HAS_EXPIRED/i.test(auth);
  const selfSigned = info.selfSigned || /SELF_SIGNED/i.test(auth);
  const nameMismatch = /altname|does not match|ERR_TLS_CERT_ALTNAME/i.test(auth);
  if (info.protocol && /TLSv1(\.1)?$/.test(info.protocol)) findings.push({ code: 'tls_outdated_protocol', severity: 'high', detail: info.protocol });
  if (selfSigned) findings.push({ code: 'tls_self_signed', severity: 'medium', detail: `issuer=subject (${info.subject})` });
  else if (nameMismatch) findings.push({ code: 'tls_name_mismatch', severity: 'high', detail: auth.slice(0, 200) });
  else if (!info.authorized && !expired) findings.push({ code: 'tls_untrusted', severity: 'medium', detail: (auth || 'certificate is not trusted').slice(0, 200) });
  if (expired) findings.push({ code: 'tls_expired', severity: 'high', detail: info.daysToExpiry !== null && info.daysToExpiry < 0 ? `${-info.daysToExpiry}d ago` : auth.slice(0, 200) });
  else if (info.daysToExpiry !== null && info.daysToExpiry < 15) findings.push({ code: 'tls_expiring', severity: 'medium', detail: `${info.daysToExpiry}d left` });
  return findings;
}

function headerValue(headers: http.IncomingHttpHeaders, name: string): string | null {
  const value = headers[name.toLowerCase()];
  if (Array.isArray(value)) return value[0] ?? null;
  return value ?? null;
}

export function findingsFromResponse(url: URL, headers: http.IncomingHttpHeaders): Finding[] {
  const findings: Finding[] = [];
  if (url.protocol === 'https:') {
    findings.push(...hstsFindings(headerValue(headers, 'strict-transport-security')));
    findings.push(...cspFindings(headerValue(headers, 'content-security-policy')));
    const minor = SECURITY_HEADERS.filter(name => name !== 'strict-transport-security' && name !== 'content-security-policy' && !headerValue(headers, name));
    if (minor.length) findings.push({ code: 'missing_headers', severity: 'low', detail: minor.join(', ') });
  }
  const server = headerValue(headers, 'server');
  if (server && /\d/.test(server)) findings.push({ code: 'version_disclosure', severity: 'low', detail: `Server: ${server}` });
  const powered = headerValue(headers, 'x-powered-by');
  if (powered) findings.push({ code: 'version_disclosure', severity: 'low', detail: `X-Powered-By: ${powered}` });
  const cookies = headers['set-cookie'];
  const weak = (Array.isArray(cookies) ? cookies : cookies ? [cookies] : []).map(cookieWeakness).filter((item): item is string => item !== null);
  if (weak.length) findings.push({ code: 'weak_cookie_flags', severity: 'medium', detail: weak.join('; ').slice(0, 300) });
  return findings;
}

function hostOf(url: URL): string {
  return url.hostname.replace(/\.$/, '');
}

function displayUrl(url: URL): string {
  return url.origin + url.pathname;
}

function selectAddress(records: Array<{ address: string; family: number }>, allowPrivate: boolean): { address: string; family: number } | { blocked: string } {
  const open = records.filter(record => addressBlockReason(record.address, false) === null);
  if (open[0]) return open[0];
  if (allowPrivate) {
    const internal = records.filter(record => addressBlockReason(record.address, true) === null);
    if (internal[0]) return internal[0];
  }
  const reasons = records.map(record => `${record.address} (${addressBlockReason(record.address, allowPrivate) ?? 'blocked'})`);
  return { blocked: reasons.join(', ') || 'no address' };
}

function realDeps(): CheckDeps {
  return {
    async lookup(hostname) {
      const records = await lookup(hostname, { all: true, verbatim: true });
      return records.map(record => ({ address: record.address, family: record.family }));
    },
    tls(ip, port, servername) {
      return new Promise(resolve => {
        const socket = tls.connect({ host: ip, port, servername, rejectUnauthorized: false, timeout: TIMEOUT }, () => {
          const cert = socket.getPeerCertificate();
          const hasCert = Object.keys(cert).length > 0;
          const first = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value) ?? '';
          const auth = socket.authorizationError;
          const authorizationError = auth ? (typeof auth === 'string' ? auth : auth.message) : null;
          const daysToExpiry = hasCert && cert.valid_to ? Math.round((Date.parse(cert.valid_to) - Date.now()) / 86_400_000) : null;
          resolve({
            protocol: socket.getProtocol(),
            issuer: hasCert ? (first(cert.issuer?.O) || first(cert.issuer?.CN) || 'unknown') : '',
            subject: hasCert ? (first(cert.subject?.CN) || 'unknown') : '',
            daysToExpiry,
            selfSigned: hasCert && JSON.stringify(cert.issuer ?? {}) === JSON.stringify(cert.subject ?? {}),
            authorized: socket.authorized,
            authorizationError,
          });
          socket.end();
        });
        socket.on('timeout', () => { socket.destroy(); resolve(emptyTls('tls_timeout')); });
        socket.on('error', error => resolve(emptyTls(error.message)));
      });
    },
    exchange(url, ip, family) {
      const secure = url.protocol === 'https:';
      const port = Number(url.port) || (secure ? 443 : 80);
      return new Promise((resolve, reject) => {
        const request = (secure ? https : http).request({
          host: ip, port, family, method: 'GET', servername: url.hostname, rejectUnauthorized: false, timeout: TIMEOUT,
          path: `${url.pathname}${url.search}`,
          headers: { host: url.host, 'user-agent': USER_AGENT, accept: '*/*', connection: 'close' },
        }, response => {
          response.on('error', reject);
          response.resume();
          response.on('end', () => resolve({ status: response.statusCode ?? 0, headers: response.headers }));
        });
        request.on('timeout', () => request.destroy(new Error('timeout')));
        request.on('error', reject);
        request.end();
      });
    },
  };
}

function emptyTls(error: string): TlsInfo {
  return { protocol: null, issuer: '', subject: '', daysToExpiry: null, selfSigned: false, authorized: false, authorizationError: null, error };
}

export async function checkTarget(raw: string, options: CheckOptions = {}): Promise<TargetResult> {
  const checkedAt = new Date().toISOString();
  const allowPrivate = options.allowPrivate === true;
  const deps = options.deps ?? realDeps();
  const fail = (code: string, detail: string): TargetResult =>
    ({ target: raw, origin: raw, ip: null, reachable: false, findings: [{ code, severity: 'info', detail }], checkedAt });

  const canon = canonicalTarget(raw);
  if ('error' in canon) return fail(canon.error, canon.error === 'credentials_in_url' ? 'username or password in the URL' : canon.error === 'unsupported_scheme' ? 'only http and https' : 'not a host or URL');
  const initial = new URL(canon.href);
  const findings: Finding[] = [];
  if (initial.protocol === 'http:') findings.push({ code: 'cleartext_http', severity: 'medium', detail: 'plain HTTP; credentials and tokens would transit in clear' });

  let records: Array<{ address: string; family: number }>;
  try { records = await deps.lookup(initial.hostname); }
  catch (error) { return { ...fail('dns_unresolved', error instanceof Error ? error.message : 'lookup failed'), target: canon.href, origin: canon.origin, findings: [...findings, { code: 'dns_unresolved', severity: 'info', detail: error instanceof Error ? error.message : 'lookup failed' }] }; }
  const selected = selectAddress(records, allowPrivate);
  if ('blocked' in selected) {
    return { target: canon.href, origin: canon.origin, ip: null, reachable: false, checkedAt, findings: [...findings, { code: 'blocked_address', severity: 'info', detail: `${selected.blocked}. Loopback and link-local always stay blocked; RFC1918 needs --allow-private.` }] };
  }

  let reachable = false;
  if (initial.protocol === 'https:') {
    const tlsInfo = await deps.tls(selected.address, Number(initial.port) || 443, initial.hostname);
    findings.push(...findingsFromTls(tlsInfo));
    if (tlsInfo.error) {
      return { target: canon.href, origin: canon.origin, ip: selected.address, reachable: false, findings, checkedAt };
    }
    reachable = true;
  }

  let current = initial;
  let response: ExchangeResult | null = null;
  try {
    for (let redirects = 0; ;) {
      response = await deps.exchange(current, selected.address, selected.family);
      reachable = true;
      if (response.status < 300 || response.status >= 400) break;
      const location = headerValue(response.headers, 'location');
      if (!location) break;
      let next: URL;
      try { next = new URL(location, current); }
      catch { findings.push({ code: 'redirect_invalid', severity: 'info', detail: 'unparseable Location' }); response = null; break; }
      next.hash = '';
      if (current.protocol === 'https:' && next.protocol === 'http:') {
        findings.push({ code: 'redirect_to_http', severity: 'high', detail: displayUrl(next) });
        response = null;
        break;
      }
      if (hostOf(next) !== hostOf(current)) {
        findings.push({ code: 'redirect_off_host', severity: 'info', detail: displayUrl(next) });
        response = null;
        break;
      }
      if (next.port !== current.port || next.protocol !== current.protocol) {
        findings.push({ code: 'redirect_port_or_scheme_change', severity: 'info', detail: displayUrl(next) });
        response = null;
        break;
      }
      redirects += 1;
      if (redirects > MAX_REDIRECTS) {
        findings.push({ code: 'redirect_limit', severity: 'info', detail: displayUrl(next) });
        response = null;
        break;
      }
      current = next;
    }
  } catch (error) {
    findings.push({ code: reachable ? 'http_failed' : 'unreachable', severity: 'info', detail: error instanceof Error ? error.message : 'request failed' });
    response = null;
  }
  if (response && (response.status < 300 || response.status >= 400)) findings.push(...findingsFromResponse(current, response.headers));
  return { target: canon.href, origin: canon.origin, ip: selected.address, reachable, findings, checkedAt };
}

export function formatResult(result: TargetResult): string {
  const lines = [`\n${result.origin}  (${result.ip ?? 'unresolved'})${result.reachable ? '' : ' — not reachable'}`];
  if (!result.findings.length) lines.push('  OK — no issues found');
  for (const finding of result.findings) lines.push(`  [${finding.severity.toUpperCase()}] ${finding.code}: ${finding.detail}`);
  return lines.join('\n');
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const allowPrivate = process.argv.includes('--allow-private');
  const targets = process.argv.slice(2).filter(arg => !arg.startsWith('--'));
  if (!targets.length) {
    console.log('Read-only posture check of hosts you operate.');
    console.log('usage: tsx scripts/posture-check.ts [--allow-private] <host-or-url> [<host-or-url> ...]');
    process.exit(1);
  }
  console.log(`Read-only check of ${targets.length} target(s). One URL each; same-host redirects only; address pinned.`);
  for (const target of targets) {
    console.log(formatResult(await checkTarget(target, { allowPrivate })));
    await sleep(DELAY_MS);
  }
  console.log('\nDone. Header and TLS posture only.');
}
