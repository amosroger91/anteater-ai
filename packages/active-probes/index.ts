import { randomBytes } from 'node:crypto';
import { isActiveAction, type ActiveAction } from '../scope-engine/index.js';

// Active vulnerability probes (the injection suite). Each is a DETERMINISTIC oracle over an injected
// fetch: it sends a small, bounded set of parameterized GETs and decides a verdict from how the
// responses differ. Proofs demonstrate the flaw (a reflected marker, a boolean/error oracle, an
// attacker-controlled redirect, an out-of-band callback) and are read-only — never destructive, never
// a DoS. The gateway supplies a SCOPED fetch (authorizeActive + rate limit + kill switch) so a probe
// can only ever reach an in-scope, automation-permitted host. Findings are submittable signals the
// operator reports; the probe never writes VERIFIED/SUBMITTED.

export interface ProbeResponse { status: number; headers: Record<string, string>; body: string }
export type ProbeFetch = (url: string) => Promise<ProbeResponse>;

// Out-of-band interaction for SSRF: an operator-provided collaborator. `payloadUrl` is a unique URL the
// target would fetch; `wasHit` reports whether that token was observed out of band. Absent => SSRF skipped.
export interface Collaborator { payloadUrl(token: string): string; wasHit(token: string, signal?: AbortSignal): Promise<boolean> }

export interface ProbeSignal { code: string; severity: 'medium' | 'high' | 'critical'; detail: string }
export interface ProbeContext { collaborator?: Collaborator; signal?: AbortSignal }

function token(prefix: string): string { return `${prefix}${randomBytes(6).toString('hex')}`; }

// Set one query parameter to a payload, preserving the rest of the URL. Returns a string target the
// scope engine's authorizeActive will re-check before the request is allowed.
export function withParam(target: string, param: string, value: string): string {
  const url = new URL(target);
  url.searchParams.set(param, value);
  return url.toString();
}

const ok = (r: ProbeResponse) => r.status > 0 && r.status < 500;
const htmlish = (r: ProbeResponse) => /html/i.test(r.headers['content-type'] ?? '');
// Two bodies are "the same class" of response when their lengths are within 2%. Deterministic and
// resistant to tiny per-request noise; a boolean-SQLi true/false split is far larger than 2%.
function similar(a: string, b: string): boolean {
  const long = Math.max(a.length, b.length);
  if (long === 0) return true;
  return Math.abs(a.length - b.length) / long <= 0.02;
}

const SQL_ERROR = /SQL syntax|SQLSTATE|unclosed quotation mark|quoted string not properly terminated|ORA-\d{4,5}|PG::\w+Error|psycopg2|near "[^"]*": syntax error|mysqli?_|sqlite3\.OperationalError/i;

// Reflected XSS: inject an HTML-breaking marker and confirm it is reflected UNescaped in an HTML body.
// An escaped or absent reflection is not a finding.
export async function probeReflectedXss(fetchUrl: ProbeFetch, target: string, param: string): Promise<ProbeSignal | null> {
  const marker = token('xss');
  const breaking = `"'><svg/onload=${marker}>`;
  const response = await fetchUrl(withParam(target, param, breaking));
  if (!ok(response) || !htmlish(response)) return null;
  if (response.body.includes(`<svg/onload=${marker}>`)) {
    return { code: 'reflected_xss', severity: 'high', detail: `unescaped reflection of parameter '${param}'` };
  }
  return null;
}

// SQL injection: first an error-based oracle (a single quote provokes a database error string), then a
// boolean oracle (a true condition matches the baseline while a false condition clearly differs). A
// control request with a benign value anchors the comparison. All reads; nothing is mutated.
export async function probeSqli(fetchUrl: ProbeFetch, target: string, param: string): Promise<ProbeSignal | null> {
  const errored = await fetchUrl(withParam(target, param, "1'"));
  if (errored.status < 500 && SQL_ERROR.test(errored.body)) {
    return { code: 'sqli', severity: 'critical', detail: `database error provoked via parameter '${param}'` };
  }
  const base = await fetchUrl(withParam(target, param, '1'));
  const truthy = await fetchUrl(withParam(target, param, "1' OR '1'='1"));
  const falsy = await fetchUrl(withParam(target, param, "1' AND '1'='2"));
  if (ok(base) && ok(truthy) && ok(falsy) && similar(base.body, truthy.body) && !similar(base.body, falsy.body)) {
    return { code: 'sqli', severity: 'critical', detail: `boolean-based SQL injection via parameter '${param}'` };
  }
  return null;
}

// Open redirect: point the parameter at an attacker-controlled host and confirm a 3xx Location that
// leaves for that host. Read-only; the redirect is observed, never followed.
export async function probeOpenRedirect(fetchUrl: ProbeFetch, target: string, param: string): Promise<ProbeSignal | null> {
  const marker = `${token('r')}.example`;
  const response = await fetchUrl(withParam(target, param, `https://${marker}/`));
  if (response.status < 300 || response.status >= 400) return null;
  const location = response.headers['location'] ?? '';
  if (!location) return null;
  try {
    const url = new URL(location, 'https://base.invalid');
    if (url.hostname === marker) return { code: 'open_redirect', severity: 'medium', detail: `redirects to an attacker-controlled host via parameter '${param}'` };
  } catch { /* malformed Location is not a confirmed redirect */ }
  return null;
}

// SSRF: inject a unique collaborator URL and confirm the server fetched it out of band. Requires an
// operator-provided collaborator; without one SSRF cannot be confirmed safely and is skipped.
export async function probeSsrf(fetchUrl: ProbeFetch, target: string, param: string, context: ProbeContext = {}): Promise<ProbeSignal | null> {
  const collaborator = context.collaborator;
  if (!collaborator) return null;
  const mark = token('ssrf');
  await fetchUrl(withParam(target, param, collaborator.payloadUrl(mark)));
  const hit = await collaborator.wasHit(mark, context.signal);
  return hit ? { code: 'ssrf', severity: 'critical', detail: `out-of-band request confirmed via parameter '${param}'` } : null;
}

const PROBES: Record<ActiveAction, (f: ProbeFetch, t: string, p: string, c: ProbeContext) => Promise<ProbeSignal | null>> = {
  probe_xss: (f, t, p) => probeReflectedXss(f, t, p),
  probe_sqli: (f, t, p) => probeSqli(f, t, p),
  probe_redirect: (f, t, p) => probeOpenRedirect(f, t, p),
  probe_ssrf: (f, t, p, c) => probeSsrf(f, t, p, c),
};

// Run one active action across the given parameters of one endpoint, returning the confirmed signals.
// `params` come from the endpoint inventory; a target with no parameters yields nothing to test.
export async function runActiveProbe(action: string, fetchUrl: ProbeFetch, target: string, params: readonly string[], context: ProbeContext = {}): Promise<ProbeSignal[]> {
  if (!isActiveAction(action)) return [];
  const probe = PROBES[action];
  const signals: ProbeSignal[] = [];
  const seen = new Set<string>();
  for (const param of params) {
    context.signal?.throwIfAborted();
    const signal = await probe(fetchUrl, target, param, context);
    if (signal && !seen.has(signal.code + param)) { seen.add(signal.code + param); signals.push(signal); }
  }
  return signals;
}

// Which parameters on a URL are worth probing. Query parameters already present are the candidates;
// an endpoint with none is skipped (active probing invents nothing beyond the reviewed inventory).
export function parametersFor(target: string): string[] {
  try { return [...new URL(target).searchParams.keys()]; } catch { return []; }
}
