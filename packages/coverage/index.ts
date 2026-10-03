import { z } from 'zod';

// A small, explicitly versioned mapping, not a claim of full WSTG/ASVS compliance.
const base = 'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/';
export const METHODOLOGY: Record<string, { version: string; url: string }> = {
  'WSTG-CONF-07': { version: 'WSTG 4.2', url: base + '02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security' },
  'WSTG-CONF-02': { version: 'WSTG 4.2', url: base + '02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration' },
  'WSTG-CRYP-01': { version: 'WSTG 4.2', url: base + '09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security' },
  'WSTG-SESS-02': { version: 'WSTG 4.2', url: base + '06-Session_Management_Testing/02-Testing_for_Cookies_Attributes' },
};
export const CHECKS = [
  { id: 'transport.encryption', findingCodes: ['cleartext_http', 'redirect_to_http'], methodology: ['WSTG-CRYP-01'], httpsOnly: false },
  { id: 'tls.protocol', findingCodes: ['tls_outdated_protocol'], methodology: ['WSTG-CRYP-01'], httpsOnly: true },
  { id: 'tls.certificate', findingCodes: ['tls_uninspectable', 'tls_self_signed', 'tls_expired', 'tls_expiring', 'tls_name_mismatch', 'tls_untrusted'], methodology: ['WSTG-CRYP-01'], httpsOnly: true },
  { id: 'headers.hsts', findingCodes: ['missing_hsts'], methodology: ['WSTG-CONF-07'], httpsOnly: true },
  { id: 'headers.csp', findingCodes: ['missing_csp'], methodology: ['WSTG-CONF-02'], httpsOnly: false },
  { id: 'headers.baseline', findingCodes: ['missing_headers', 'missing_security_headers'], methodology: ['WSTG-CONF-02'], httpsOnly: false },
  { id: 'headers.disclosure', findingCodes: ['version_disclosure'], methodology: ['WSTG-CONF-02'], httpsOnly: false },
  { id: 'cookies.attributes', findingCodes: ['weak_cookie_flags'], methodology: ['WSTG-SESS-02'], httpsOnly: false },
];
export const ScanResult = z.object({
  origin: z.string(), reachable: z.boolean(), executed: z.boolean().optional(),
  executedChecks: z.array(z.string()).optional(),
  findings: z.array(z.object({ code: z.string(), severity: z.enum(['info', 'low', 'medium', 'high', 'critical']), detail: z.string() })),
});
export type ScanResult = z.infer<typeof ScanResult>;
export type CheckStatus = 'passed' | 'candidate' | 'skipped' | 'not_applicable';
export interface CoverageSummary { targets: number; executed: number; candidates: number; gaps: number; unmapped: number }
export function validateRegistry() {
  if (new Set(CHECKS.map(check => check.id)).size !== CHECKS.length) throw new Error('duplicate_check');
  for (const check of CHECKS) for (const id of check.methodology) if (!METHODOLOGY[id]) throw new Error('unknown_methodology');
}
export function coverageForTarget(result: ScanResult) {
  let protocol = ''; try { protocol = new URL(result.origin).protocol; } catch { /* Invalid targets have no completed checks. */ }
  const codes = new Set(result.findings.map(finding => finding.code));
  const checks = CHECKS.map(check => {
    let status: CheckStatus = 'skipped';
    if (check.httpsOnly && protocol === 'http:') status = 'not_applicable';
    else if (result.executed !== false && protocol) {
      if (check.findingCodes.some(code => codes.has(code))) status = 'candidate';
      else if (result.executedChecks?.includes(check.id)) status = 'passed';
    }
    return { checkId: check.id, status, methodology: check.methodology };
  });
  const mapped = new Set(CHECKS.flatMap(check => check.findingCodes));
  return { origin: result.origin, checks,
    executed: checks.filter(check => check.status === 'passed' || check.status === 'candidate').length,
    candidates: checks.filter(check => check.status === 'candidate').length,
    gaps: checks.filter(check => check.status === 'skipped').length,
    unmappedCodes: [...codes].filter(code => !mapped.has(code)),
  };
}
export function coverageReport(results: ScanResult[]) {
  validateRegistry();
  const perTarget = results.filter(result => result.executed !== false).map(coverageForTarget);
  const summary: CoverageSummary = { targets: perTarget.length, executed: 0, candidates: 0, gaps: 0, unmapped: 0 };
  for (const target of perTarget) {
    summary.executed += target.executed; summary.candidates += target.candidates;
    summary.gaps += target.gaps; summary.unmapped += target.unmappedCodes.length;
  }
  const markdown = '# Passive coverage\n\nWSTG 4.2 subset; not full methodology coverage or an ASVS assessment. A gap is never a pass.\n\n'
    + 'Passing requires an explicit record that the check ran; legacy input without execution metadata retains gaps.\n\n'
    + '```json\n' + JSON.stringify({ summary, perTarget }, null, 2).replace(/`/g, '\\u0060').replace(/</g, '\\u003c') + '\n```\n\n'
    + Object.entries(METHODOLOGY).map(([id, entry]) => `- [${id} (${entry.version})](${entry.url})`).join('\n') + '\n';
  return { summary, perTarget, markdown };
}
