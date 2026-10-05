import { z } from 'zod';

// Methodology coverage registry (OWASP WSTG / ASVS) and campaign coverage report.
//
// Purpose (PRODUCTION_ROADMAP.md §3): map every implemented detector to the professional
// methodology, and produce a per-domain report that shows what RAN, what it found, and the
// reason for every gap. "Not observed" / "could not test" must NEVER be reported as passing.
//
// This module is pure and deterministic: coverage is a function of (scan results, registry).
// It performs no network or database I/O, so it is fully testable against fixtures in CI.

// --- Pinned methodology references -----------------------------------------
// Version-pinned subset. IDs are retained verbatim with their framework/version so a report can
// name exactly what it measured. NOTE: the vendored owasp-asvs pin tracks 5.0, which renumbered
// chapters; the ASVS IDs below are 4.0.3 numbering (the stable scheme these detectors map to).
// Aligning the vendored pin or migrating IDs to 5.0 is tracked as roadmap §3 follow-up.
export const METHODOLOGY = {
  'WSTG-CRYP-01': { framework: 'WSTG', version: '4.2', title: 'Testing for Weak Transport Layer Security' },
  'WSTG-CRYP-03': { framework: 'WSTG', version: '4.2', title: 'Testing for Sensitive Information Sent via Unencrypted Channels' },
  'WSTG-CONF-07': { framework: 'WSTG', version: '4.2', title: 'Testing HTTP Strict Transport Security' },
  'WSTG-INFO-02': { framework: 'WSTG', version: '4.2', title: 'Fingerprint Web Server' },
  'WSTG-INFO-08': { framework: 'WSTG', version: '4.2', title: 'Fingerprint Web Application Framework' },
  'WSTG-SESS-02': { framework: 'WSTG', version: '4.2', title: 'Testing for Cookies Attributes' },
  'ASVS-V9.1.1': { framework: 'ASVS', version: '4.0.3', title: 'TLS used for all client connectivity' },
  'ASVS-V3.4.1': { framework: 'ASVS', version: '4.0.3', title: 'Cookie Secure attribute' },
  'ASVS-V3.4.2': { framework: 'ASVS', version: '4.0.3', title: 'Cookie HttpOnly attribute' },
  'ASVS-V3.4.3': { framework: 'ASVS', version: '4.0.3', title: 'Cookie SameSite attribute' },
  'ASVS-V14.4.3': { framework: 'ASVS', version: '4.0.3', title: 'Content-Security-Policy response header' },
  'ASVS-V14.4.4': { framework: 'ASVS', version: '4.0.3', title: 'X-Content-Type-Options: nosniff' },
  'ASVS-V14.4.7': { framework: 'ASVS', version: '4.0.3', title: 'Content sandboxing / framing protection' },
  'WSTG-CONF-04': { framework: 'WSTG', version: '4.2', title: 'Review Old Backup and Unreferenced Files for Sensitive Information' },
  'WSTG-CONF-05': { framework: 'WSTG', version: '4.2', title: 'Enumerate Infrastructure and Application Admin Interfaces' },
  'WSTG-CONF-10': { framework: 'WSTG', version: '4.2', title: 'Test for Subdomain Takeover' },
  'WSTG-CLNT-04': { framework: 'WSTG', version: '4.2', title: 'Testing for Client-side URL Redirect' },
  'WSTG-CLNT-07': { framework: 'WSTG', version: '4.2', title: 'Testing Cross Origin Resource Sharing' },
  'WSTG-INFO-05': { framework: 'WSTG', version: '4.2', title: 'Review Webpage Content for Information Leakage' },
  'ASVS-V14.5.3': { framework: 'ASVS', version: '4.0.3', title: 'CORS Access-Control-Allow-Origin uses a strict allow list' },
} as const satisfies Record<string, { framework: 'WSTG' | 'ASVS'; version: string; title: string }>;
export type MethodologyId = keyof typeof METHODOLOGY;

// --- Check definitions ------------------------------------------------------
// Each check ties one or more detector finding codes to methodology IDs. Per roadmap §3 every
// check declares its prerequisites, scope/action requirement, secure result and cleanup.
export interface Check {
  id: string;
  title: string;
  detector: 'posture';
  methodology: MethodologyId[];
  appliesWhen: 'always' | 'https';     // 'https' checks are N/A (not a gap) on plain-HTTP targets
  action: 'passive-read';              // scope/action requirement; all current checks are read-only
  findingCodes: string[];              // detector codes that make this check a CANDIDATE
  secureResult: string;                // what "passed" means
  cleanup: 'none';
  requiresPaths?: readonly string[];   // every path must have been fetched before a pass
  requiresCname?: boolean;             // a pass needs an observed CNAME, not a homepage GET
  requiresOrigin?: boolean;            // a pass needs the Origin the server was shown
}

export const CHECKS: Check[] = [
  { id: 'transport.tls-weak', title: 'Transport uses a current TLS version', detector: 'posture', methodology: ['WSTG-CRYP-01', 'ASVS-V9.1.1'], appliesWhen: 'https', action: 'passive-read', findingCodes: ['tls_outdated_protocol'], secureResult: 'TLS 1.2+ negotiated', cleanup: 'none' },
  { id: 'transport.cert', title: 'Certificate is valid and trusted', detector: 'posture', methodology: ['WSTG-CRYP-01'], appliesWhen: 'https', action: 'passive-read', findingCodes: ['tls_expired', 'tls_expiring', 'tls_self_signed', 'tls_uninspectable'], secureResult: 'cert not expired, not self-signed, >15d remaining', cleanup: 'none' },
  { id: 'transport.encryption', title: 'Sensitive surface served only over TLS', detector: 'posture', methodology: ['WSTG-CRYP-03', 'ASVS-V9.1.1'], appliesWhen: 'always', action: 'passive-read', findingCodes: ['cleartext_http'], secureResult: 'served over HTTPS', cleanup: 'none' },
  { id: 'headers.hsts', title: 'HSTS enforced', detector: 'posture', methodology: ['WSTG-CONF-07'], appliesWhen: 'https', action: 'passive-read', findingCodes: ['missing_hsts'], secureResult: 'Strict-Transport-Security present', cleanup: 'none' },
  { id: 'headers.csp', title: 'Content-Security-Policy present', detector: 'posture', methodology: ['ASVS-V14.4.3'], appliesWhen: 'https', action: 'passive-read', findingCodes: ['missing_csp'], secureResult: 'Content-Security-Policy present', cleanup: 'none' },
  { id: 'headers.misc', title: 'Supporting security headers set', detector: 'posture', methodology: ['ASVS-V14.4.4', 'ASVS-V14.4.7'], appliesWhen: 'https', action: 'passive-read', findingCodes: ['missing_headers', 'missing_security_headers'], secureResult: 'X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy present', cleanup: 'none' },
  { id: 'info.version-disclosure', title: 'Server/framework version not disclosed', detector: 'posture', methodology: ['WSTG-INFO-02', 'WSTG-INFO-08'], appliesWhen: 'always', action: 'passive-read', findingCodes: ['version_disclosure'], secureResult: 'no version in Server/X-Powered-By', cleanup: 'none' },
  { id: 'session.cookie-attrs', title: 'Cookies carry Secure/HttpOnly/SameSite', detector: 'posture', methodology: ['WSTG-SESS-02', 'ASVS-V3.4.1', 'ASVS-V3.4.2', 'ASVS-V3.4.3'], appliesWhen: 'always', action: 'passive-read', findingCodes: ['weak_cookie_flags'], secureResult: 'all cookie security attributes set', cleanup: 'none' },
  { id: 'dns.subdomain-takeover', title: 'Dangling name is not an unclaimed service page', detector: 'posture', methodology: ['WSTG-CONF-10'], appliesWhen: 'https', action: 'passive-read', findingCodes: ['subdomain_takeover'], secureResult: 'no unclaimed-service fingerprint on a dangling name', cleanup: 'none', requiresCname: true },
  { id: 'files.exposed-vcs', title: 'Source-control and environment files are not served', detector: 'posture', methodology: ['WSTG-CONF-04'], appliesWhen: 'https', action: 'passive-read', findingCodes: ['exposed_vcs'], secureResult: 'git config, env, and DS_Store signatures absent', cleanup: 'none', requiresPaths: ['/.git/config', '/.env', '/.DS_Store'] },
  { id: 'admin.exposed', title: 'Privileged admin or debug content is not public', detector: 'posture', methodology: ['WSTG-CONF-05'], appliesWhen: 'https', action: 'passive-read', findingCodes: ['exposed_admin'], secureResult: 'actuator index and admin listings absent', cleanup: 'none', requiresPaths: ['/actuator', '/admin', '/debug'] },
  { id: 'cors.credentialed', title: 'Credentialed CORS does not reflect another origin', detector: 'posture', methodology: ['WSTG-CLNT-07', 'ASVS-V14.5.3'], appliesWhen: 'https', action: 'passive-read', findingCodes: ['cors_credentialed'], secureResult: 'credentials are not paired with a reflected foreign origin', cleanup: 'none', requiresOrigin: true },
  { id: 'redirect.auth-takeover', title: 'Auth and token redirects stay on the request host', detector: 'posture', methodology: ['WSTG-CLNT-04'], appliesWhen: 'https', action: 'passive-read', findingCodes: ['open_redirect_to_takeover'], secureResult: 'auth redirect target stays on the request host', cleanup: 'none', requiresPaths: ['/login', '/signin', '/oauth', '/auth', '/callback', '/token'] },
  { id: 'client.secrets-in-js', title: 'Served JavaScript does not contain a live-looking key', detector: 'posture', methodology: ['WSTG-INFO-05'], appliesWhen: 'https', action: 'passive-read', findingCodes: ['secrets_in_js'], secureResult: 'no live-looking key pattern in served JavaScript', cleanup: 'none', requiresPaths: ['/app.js'] },
];

// Detector codes that are infrastructural (not a check result): they mean the target could not be assessed.
const UNASSESSABLE = new Set(['invalid_target', 'unsupported_scheme', 'unreachable']);

// --- Scan result shape consumed (a superset is fine) -----------------------
export const ScanFinding = z.object({ code: z.string(), severity: z.string(), detail: z.string() });
export const ScanResult = z.object({
  origin: z.string(), reachable: z.boolean(), findings: z.array(ScanFinding),
  mode: z.string().optional(), executed: z.boolean().optional(),
  probedPaths: z.array(z.string()).optional(),
  sawCname: z.boolean().optional(),
  sawRequestOrigin: z.boolean().optional(),
});
export type ScanResult = z.infer<typeof ScanResult>;

export type CheckStatus = 'passed' | 'candidate' | 'skipped' | 'not_applicable';
export interface CheckCoverage { checkId: string; title: string; methodology: MethodologyId[]; status: CheckStatus; reason: string }
export interface TargetCoverage { origin: string; checks: CheckCoverage[]; applicable: number; executed: number; candidates: number; gaps: number }

export function coverageForTarget(result: ScanResult, checks: Check[] = CHECKS): TargetCoverage {
  const scheme = result.origin.startsWith('https:') ? 'https' : 'http';
  const codes = new Set(result.findings.map(f => f.code));
  const unassessable = result.findings.some(f => UNASSESSABLE.has(f.code)) || !result.reachable;
  const rows: CheckCoverage[] = checks.map(c => {
    const base = { checkId: c.id, title: c.title, methodology: c.methodology };
    if (c.appliesWhen === 'https' && scheme !== 'https') return { ...base, status: 'not_applicable', reason: 'target is plain HTTP' };
    // A concretely observed finding is a candidate even if the HTTP GET failed (e.g. TLS inspected
    // the cert while fetch rejected the bad cert). Only mark skipped when nothing was observed.
    if (c.findingCodes.some(code => codes.has(code))) return { ...base, status: 'candidate', reason: c.findingCodes.filter(code => codes.has(code)).join(', ') };
    if (unassessable) return { ...base, status: 'skipped', reason: 'target could not be assessed (unreachable/invalid)' };
    const probed = new Set(result.probedPaths ?? []);
    const missingPath = c.requiresPaths?.some(required => !probed.has(required)) ?? false;
    if (missingPath || (c.requiresCname && !result.sawCname) || (c.requiresOrigin && !result.sawRequestOrigin)) {
      return { ...base, status: 'skipped', reason: 'not observed' };
    }
    return { ...base, status: 'passed', reason: c.secureResult };
  });
  const applicable = rows.filter(r => r.status !== 'not_applicable').length;
  const executed = rows.filter(r => r.status === 'passed' || r.status === 'candidate').length;
  const candidates = rows.filter(r => r.status === 'candidate').length;
  const gaps = rows.filter(r => r.status === 'skipped').length;
  return { origin: result.origin, checks: rows, applicable, executed, candidates, gaps };
}

export interface CoverageSummary { targets: number; checks: number; executed: number; candidates: number; gaps: number }
export function coverageReport(results: ScanResult[], checks: Check[] = CHECKS): { markdown: string; summary: CoverageSummary; perTarget: TargetCoverage[] } {
  const perTarget = results.map(r => coverageForTarget(r, checks));
  const summary: CoverageSummary = {
    targets: perTarget.length,
    checks: checks.length,
    executed: perTarget.reduce((n, t) => n + t.executed, 0),
    candidates: perTarget.reduce((n, t) => n + t.candidates, 0),
    gaps: perTarget.reduce((n, t) => n + t.gaps, 0),
  };
  const frameworks = [...new Set(Object.values(METHODOLOGY).map(m => `${m.framework} ${m.version}`))].join(', ');
  const icon: Record<CheckStatus, string> = { passed: 'PASS', candidate: 'FLAG', skipped: 'GAP', not_applicable: 'n/a' };
  const lines = [`# Coverage report`, ``, `Methodology: ${frameworks}. ${checks.length} checks across ${perTarget.length} target(s).`,
    `Executed ${summary.executed}, flagged ${summary.candidates}, gaps ${summary.gaps}. A gap is never a pass.`, ``];
  for (const t of perTarget) {
    lines.push(`## ${t.origin}`, `Applicable ${t.applicable} · executed ${t.executed} · flagged ${t.candidates} · gaps ${t.gaps}`, ``,
      `| Check | Methodology | Status | Detail |`, `| --- | --- | --- | --- |`);
    for (const c of t.checks) lines.push(`| ${c.checkId} | ${c.methodology.join(', ')} | ${icon[c.status]} | ${c.reason} |`);
    lines.push('');
  }
  return { markdown: lines.join('\n'), summary, perTarget };
}

// Stale-mapping guard (roadmap §3: detect stale methodology mappings in CI).
export function validateRegistry(checks: Check[] = CHECKS): void {
  const ids = new Set<string>();
  for (const c of checks) {
    if (ids.has(c.id)) throw new Error(`duplicate_check_id:${c.id}`);
    ids.add(c.id);
    if (!c.methodology.length) throw new Error(`check_without_methodology:${c.id}`);
    for (const m of c.methodology) if (!(m in METHODOLOGY)) throw new Error(`unknown_methodology_id:${c.id}:${m}`);
    if (!c.findingCodes.length) throw new Error(`check_without_finding_codes:${c.id}`);
  }
}
