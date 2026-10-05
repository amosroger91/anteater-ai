import { securityHeaders, cors, cacheExposure, unsafeRedirect, cookieFlags, subdomainTakeover, exposedVcs, exposedAdmin, corsCredentialed, openRedirectToTakeover, secretsInJs } from '../packages/web-checks/index.js';
import { responseFixture } from '../packages/fixtures-apps/index.js';
import { detectorGate, type DetectorCase } from '../packages/benchmark/index.js';

// Detector release gate (PRODUCTION_ROADMAP.md §0): every detector must flag its vulnerable fixture
// and pass its patched fixture. Exits non-zero on any failure so CI can block a release.

const cases: DetectorCase[] = [
  { name: 'headers', detector: securityHeaders, code: 'missing_security_headers', vulnerable: responseFixture('headers', 'vulnerable'), patched: responseFixture('headers', 'patched') },
  { name: 'cors', detector: cors, code: 'cors_wildcard_with_credentials', vulnerable: responseFixture('cors', 'vulnerable'), patched: responseFixture('cors', 'patched') },
  { name: 'cache', detector: cacheExposure, code: 'sensitive_response_cacheable', vulnerable: responseFixture('cache', 'vulnerable'), patched: responseFixture('cache', 'patched') },
  { name: 'redirect', detector: unsafeRedirect, code: 'open_redirect', vulnerable: responseFixture('redirect', 'vulnerable'), patched: responseFixture('redirect', 'patched') },
  { name: 'cookie', detector: cookieFlags, code: 'weak_cookie_flags', vulnerable: responseFixture('cookie', 'vulnerable'), patched: responseFixture('cookie', 'patched') },
  { name: 'takeover', detector: subdomainTakeover, code: 'subdomain_takeover', vulnerable: responseFixture('takeover', 'vulnerable'), patched: responseFixture('takeover', 'patched') },
  { name: 'vcs', detector: exposedVcs, code: 'exposed_vcs', vulnerable: responseFixture('vcs', 'vulnerable'), patched: responseFixture('vcs', 'patched') },
  { name: 'admin', detector: exposedAdmin, code: 'exposed_admin', vulnerable: responseFixture('admin', 'vulnerable'), patched: responseFixture('admin', 'patched') },
  { name: 'cors-credentialed', detector: corsCredentialed, code: 'cors_credentialed', vulnerable: responseFixture('cors-credentialed', 'vulnerable'), patched: responseFixture('cors-credentialed', 'patched') },
  { name: 'auth-redirect', detector: openRedirectToTakeover, code: 'open_redirect_to_takeover', vulnerable: responseFixture('auth-redirect', 'vulnerable'), patched: responseFixture('auth-redirect', 'patched') },
  { name: 'js-secret', detector: secretsInJs, code: 'secrets_in_js', vulnerable: responseFixture('js-secret', 'vulnerable'), patched: responseFixture('js-secret', 'patched') },
];

const result = detectorGate(cases);
console.log(`detector gate: ${result.metrics.truePositives}/${result.metrics.detectors} detect vulnerable, ${result.metrics.falsePositives} false positives`);
for (const f of result.failures) console.log(`  FAIL ${f}`);
if (!result.ok) process.exitCode = 1;
else console.log('all detectors pass their vulnerable/patched fixtures');
