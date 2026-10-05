import type { FindingSeverity } from '../findings/index.js';

// Reviewed, read-only web checks (PRODUCTION_ROADMAP.md §4). Each is a pure function over an observed
// response view and returns zero or more findings. They distinguish a suspicious response from an
// exploitable issue only as far as a passive read allows; anything stronger is a candidate for replay.

export interface HttpResponseView {
  status: number;
  headers: Record<string, string>;
  body: string;
  requestHost?: string;   // host that was requested, for redirect-target comparison
  requestOrigin?: string; // Origin header the server would have seen, for CORS reflection
  path?: string;          // request path, so a signature is tied to the route that returned it
  cname?: string;         // observed CNAME target; takeover still needs a service fingerprint
  sensitive?: boolean;    // response carries authenticated/sensitive content
}

export interface WebFinding { code: string; severity: FindingSeverity; detail: string }

const header = (v: HttpResponseView, name: string) => v.headers[name.toLowerCase()] ?? v.headers[name] ?? '';

const SECURITY_HEADERS = ['strict-transport-security', 'content-security-policy', 'x-content-type-options', 'x-frame-options', 'referrer-policy'];

export function securityHeaders(v: HttpResponseView): WebFinding[] {
  const lower = Object.fromEntries(Object.entries(v.headers).map(([k, val]) => [k.toLowerCase(), val]));
  const missing = SECURITY_HEADERS.filter(h => !(h in lower));
  return missing.length ? [{ code: 'missing_security_headers', severity: 'info', detail: missing.join(', ') }] : [];
}

export function cors(v: HttpResponseView): WebFinding[] {
  const acao = header(v, 'access-control-allow-origin');
  const acac = header(v, 'access-control-allow-credentials').toLowerCase();
  if (acao === '*' && acac === 'true') return [{ code: 'cors_wildcard_with_credentials', severity: 'high', detail: 'ACAO:* with credentials' }];
  return [];
}

export function cacheExposure(v: HttpResponseView): WebFinding[] {
  if (!v.sensitive) return [];
  const cc = header(v, 'cache-control').toLowerCase();
  if (!cc || /public/.test(cc) || (!/no-store/.test(cc) && !/private/.test(cc)))
    return [{ code: 'sensitive_response_cacheable', severity: 'medium', detail: cc || 'no Cache-Control' }];
  return [];
}

export function unsafeRedirect(v: HttpResponseView): WebFinding[] {
  if (v.status < 300 || v.status >= 400) return [];
  const location = header(v, 'location');
  if (!location) return [];
  try {
    const target = new URL(location, v.requestHost ? `https://${v.requestHost}` : undefined);
    if (v.requestHost && target.hostname !== v.requestHost) return [{ code: 'open_redirect', severity: 'medium', detail: `-> ${target.hostname}` }];
  } catch {
    // A relative Location with no base is same-origin; a malformed absolute one is suspicious.
    if (/^https?:\/\//i.test(location)) return [{ code: 'open_redirect', severity: 'medium', detail: 'malformed absolute redirect' }];
  }
  return [];
}

export function cookieFlags(v: HttpResponseView): WebFinding[] {
  const cookie = header(v, 'set-cookie');
  if (!cookie) return [];
  const weak = ['Secure', 'HttpOnly', 'SameSite'].filter(f => !new RegExp(`;\\s*${f}`, 'i').test(cookie));
  return weak.length ? [{ code: 'weak_cookie_flags', severity: 'medium', detail: `${weak.join(', ')} not set` }] : [];
}

const TAKEOVER_FINGERPRINTS = ['NoSuchBucket', "There isn't a GitHub Pages site here", 'The specified bucket does not exist'];
const AUTH_PATHS = new Set(['/login', '/signin', '/oauth', '/auth', '/callback', '/token']);
const JS_SECRET_RULES: Array<[string, RegExp]> = [
  ['aws_access_key', /\bAKIA[0-9A-Z]{16}\b/],
  ['private_key', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['jwt', /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/],
];

// A dangling name is a candidate only when the body is an unclaimed-service page.
// A normal 404, or the same phrase on a 200 document, is not a takeover.
export function subdomainTakeover(v: HttpResponseView): WebFinding[] {
  if (v.status !== 404 || !v.cname || !v.requestHost || v.cname === v.requestHost) return [];
  const fingerprint = TAKEOVER_FINGERPRINTS.find(phrase => v.body.includes(phrase));
  return fingerprint ? [{ code: 'subdomain_takeover', severity: 'high', detail: 'unclaimed-service fingerprint on a dangling name' }] : [];
}

// Read-only signatures for source-control and environment files. A 200 HTML page at the same path is not a hit.
export function exposedVcs(v: HttpResponseView): WebFinding[] {
  if (v.status !== 200 || !v.path) return [];
  if (v.path === '/.git/config' && /\[core\]/.test(v.body) && /repositoryformatversion\s*=/.test(v.body))
    return [{ code: 'exposed_vcs', severity: 'high', detail: 'git config signature at /.git/config' }];
  if (v.path === '/.env' && !/<html/i.test(v.body) && /^[A-Z][A-Z0-9_]*=\S+$/m.test(v.body))
    return [{ code: 'exposed_vcs', severity: 'high', detail: 'env assignment signature at /.env' }];
  if (v.path === '/.DS_Store' && v.body.startsWith('\u0000\u0000\u0000\u0001Bud1'))
    return [{ code: 'exposed_vcs', severity: 'high', detail: 'DS_Store signature at /.DS_Store' }];
  return [];
}

export function exposedAdmin(v: HttpResponseView): WebFinding[] {
  if (v.status !== 200 || !v.path) return [];
  if (v.path === '/actuator' && v.body.includes('"_links"') && v.body.includes('/actuator/health'))
    return [{ code: 'exposed_admin', severity: 'high', detail: 'actuator index at /actuator' }];
  if ((v.path === '/admin' || v.path === '/debug') && /"users"\s*:/.test(v.body) && /"role"\s*:\s*"admin"/.test(v.body))
    return [{ code: 'exposed_admin', severity: 'high', detail: `privileged listing at ${v.path}` }];
  return [];
}

// Reflected Origin plus credentials. A wildcard ACAO is the separate cors() check; browsers do not send credentials to it.
export function corsCredentialed(v: HttpResponseView): WebFinding[] {
  const acao = header(v, 'access-control-allow-origin');
  const acac = header(v, 'access-control-allow-credentials').toLowerCase();
  if (acac !== 'true' || !acao || acao === '*' || !v.requestOrigin || !v.requestHost) return [];
  let origin: URL;
  try { origin = new URL(v.requestOrigin); } catch { return []; }
  if (origin.origin !== acao || origin.hostname === v.requestHost) return [];
  return [{ code: 'cors_credentialed', severity: 'high', detail: 'reflected origin with credentials' }];
}

export function openRedirectToTakeover(v: HttpResponseView): WebFinding[] {
  if (!v.path || !AUTH_PATHS.has(v.path) || v.status < 300 || v.status >= 400 || !v.requestHost) return [];
  const location = header(v, 'location');
  if (!location) return [];
  try {
    const target = new URL(location, `https://${v.requestHost}`);
    if (target.hostname !== v.requestHost) return [{ code: 'open_redirect_to_takeover', severity: 'high', detail: 'auth redirect leaves the request host' }];
  } catch { return []; }
  return [];
}

// Report the rule and path only. The matched value is never copied into the finding.
export function secretsInJs(v: HttpResponseView): WebFinding[] {
  if (v.status !== 200 || !v.path?.endsWith('.js') || /<html/i.test(v.body)) return [];
  const type = header(v, 'content-type').toLowerCase();
  if (type && !type.includes('javascript') && !type.includes('ecmascript')) return [];
  const findings: WebFinding[] = [];
  for (const [rule, pattern] of JS_SECRET_RULES) {
    if (pattern.test(v.body)) findings.push({ code: 'secrets_in_js', severity: 'high', detail: `${rule} at ${v.path}` });
  }
  return findings;
}

export const DETECTORS = { securityHeaders, cors, cacheExposure, unsafeRedirect, cookieFlags, subdomainTakeover, exposedVcs, exposedAdmin, corsCredentialed, openRedirectToTakeover, secretsInJs } as const;
export type DetectorName = keyof typeof DETECTORS;

export function runAll(v: HttpResponseView): WebFinding[] {
  return Object.values(DETECTORS).flatMap(d => d(v));
}

// Read-only signatures that can be decided from one response. Takeover still needs a CNAME,
// and credentialed CORS still needs the Origin the server reflected. Those stay unobserved.
export function paidReadFindings(v: HttpResponseView): WebFinding[] {
  return [exposedVcs, exposedAdmin, openRedirectToTakeover, secretsInJs].flatMap(detector => detector(v));
}

export const VCS_READ_PATHS = ['/.git/config', '/.env', '/.DS_Store'] as const;
