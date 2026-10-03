import type { FindingSeverity } from '../findings/index.js';

// Reviewed, read-only web checks (PRODUCTION_ROADMAP.md §4). Each is a pure function over an observed
// response view and returns zero or more findings. They distinguish a suspicious response from an
// exploitable issue only as far as a passive read allows; anything stronger is a candidate for replay.

export interface HttpResponseView {
  status: number;
  headers: Record<string, string>;
  body: string;
  requestHost?: string;   // host that was requested, for redirect-target comparison
  sensitive?: boolean;    // response carries authenticated/sensitive content
}

export interface WebFinding { code: string; severity: FindingSeverity; detail: string }

const header = (v: HttpResponseView, name: string) => v.headers[name.toLowerCase()] ?? v.headers[name] ?? '';

const SECURITY_HEADERS = ['strict-transport-security', 'content-security-policy', 'x-content-type-options', 'x-frame-options', 'referrer-policy'];

export function securityHeaders(v: HttpResponseView): WebFinding[] {
  const lower = Object.fromEntries(Object.entries(v.headers).map(([k, val]) => [k.toLowerCase(), val]));
  const missing = SECURITY_HEADERS.filter(h => !(h in lower));
  return missing.length ? [{ code: 'missing_security_headers', severity: missing.includes('content-security-policy') ? 'medium' : 'low', detail: missing.join(', ') }] : [];
}

export function cors(v: HttpResponseView): WebFinding[] {
  const acao = header(v, 'access-control-allow-origin');
  const acac = header(v, 'access-control-allow-credentials').toLowerCase();
  if (acao === '*' && acac === 'true') return [{ code: 'cors_invalid_credentials_configuration', severity: 'info', detail: 'Wildcard origin with credentials is rejected by browsers; these headers do not demonstrate a readable sensitive response.' }];
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
    if (v.requestHost && target.hostname !== v.requestHost) return [{ code: 'external_redirect_observed', severity: 'info', detail: `Redirect to ${target.hostname}; attacker control has not been established.` }];
  } catch {
    // A relative Location with no base is same-origin; a malformed absolute one is suspicious.
    if (/^https?:\/\//i.test(location)) return [{ code: 'malformed_redirect_observed', severity: 'info', detail: 'Malformed absolute Location; exploitability has not been established.' }];
  }
  return [];
}

export function cookieFlags(v: HttpResponseView): WebFinding[] {
  const cookie = header(v, 'set-cookie');
  if (!cookie) return [];
  const weak = ['Secure', 'HttpOnly', 'SameSite'].filter(f => !new RegExp(`;\\s*${f}`, 'i').test(cookie));
  return weak.length ? [{ code: 'weak_cookie_flags', severity: 'medium', detail: `${weak.join(', ')} not set` }] : [];
}

export const DETECTORS = { securityHeaders, cors, cacheExposure, unsafeRedirect, cookieFlags } as const;
export type DetectorName = keyof typeof DETECTORS;

export function runAll(v: HttpResponseView): WebFinding[] {
  return Object.values(DETECTORS).flatMap(d => d(v));
}
