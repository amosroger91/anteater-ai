import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CHECKS, METHODOLOGY, coverageForTarget, coverageReport, validateRegistry, type ScanResult } from '../packages/coverage/index.js';

// Every finding code the posture checker can emit (mirrors scripts/posture-check.ts). If a new
// detector code is added there without a check or infrastructural mapping, this list + test flags it.
const POSTURE_CODES = [
  'cleartext_http', 'tls_uninspectable', 'tls_outdated_protocol', 'tls_self_signed', 'tls_expired',
  'tls_expiring', 'tls_name_mismatch', 'tls_untrusted', 'missing_hsts', 'missing_csp', 'missing_headers', 'version_disclosure',
  'weak_cookie_flags', 'unreachable', 'invalid_target', 'unsupported_scheme',
];
const INFRASTRUCTURAL = new Set(['unreachable', 'invalid_target', 'unsupported_scheme']);

test('registry has no stale methodology mappings', () => {
  assert.doesNotThrow(() => validateRegistry());
});

test('every posture finding code maps to a check or is infrastructural', () => {
  const mapped = new Set(CHECKS.flatMap(c => c.findingCodes));
  for (const code of POSTURE_CODES) assert.ok(mapped.has(code) || INFRASTRUCTURAL.has(code), `unmapped detector code: ${code}`);
});

test('every methodology id referenced exists in the pinned table', () => {
  for (const c of CHECKS) for (const m of c.methodology) assert.ok(m in METHODOLOGY, `${c.id} -> ${m}`);
});

const result = (origin: string, reachable: boolean, codes: string[]): ScanResult =>
  ({ origin, reachable, findings: codes.map(code => ({ code, severity: 'medium', detail: '' })) });

test('a clean HTTPS target passes every applicable check and has no gaps', () => {
  const c = coverageForTarget({ ...result('https://clean.test', true, []), executedChecks: CHECKS.map(check => check.id) });
  assert.equal(c.gaps, 0);
  assert.equal(c.candidates, 0);
  assert.equal(c.executed, CHECKS.length);
  assert.ok(c.checks.every(x => x.status === 'passed'));
});

test('reachability and absence of findings never imply a check ran', () => {
  const report = coverageForTarget(result('https://legacy.test', true, []));
  assert.equal(report.executed, 0);
  assert.equal(report.gaps, CHECKS.length);
  const partial = coverageForTarget({ ...result('https://tls-only.test', true, ['http_failed']), executedChecks: ['tls.protocol', 'tls.certificate'] });
  assert.equal(partial.executed, 2);
  assert.equal(partial.checks.find(check => check.checkId === 'headers.hsts')?.status, 'skipped');
});

test('a finding becomes a candidate, not a pass', () => {
  const c = coverageForTarget(result('https://x.test', true, ['missing_hsts']));
  const hsts = c.checks.find(x => x.checkId === 'headers.hsts');
  assert.equal(hsts?.status, 'candidate');
  assert.equal(c.candidates, 1);
});

test('HTTPS-only checks are N/A (not gaps) on a plain-HTTP target, and cleartext is flagged', () => {
  const c = coverageForTarget(result('http://plain.test', true, ['cleartext_http']));
  assert.equal(c.checks.find(x => x.checkId === 'headers.hsts')?.status, 'not_applicable');
  assert.equal(c.checks.find(x => x.checkId === 'transport.encryption')?.status, 'candidate');
});

test('an unreachable target is skipped, never passed', () => {
  const c = coverageForTarget(result('https://down.test', false, ['unreachable']));
  assert.ok(c.checks.every(x => x.status === 'skipped' || x.status === 'not_applicable'));
  assert.ok(!c.checks.some(x => x.status === 'passed'));
});

test('report summary aggregates and states that a gap is not a pass', () => {
  const r = coverageReport([result('https://a.test', true, []), result('https://b.test', false, ['unreachable'])]);
  assert.equal(r.summary.targets, 2);
  assert.ok(r.markdown.includes('A gap is never a pass'));
  assert.ok(/WSTG 4\.2/.test(r.markdown));
});
