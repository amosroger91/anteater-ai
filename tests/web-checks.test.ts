import { test } from 'node:test';
import assert from 'node:assert/strict';
import { securityHeaders, cors, cacheExposure, unsafeRedirect, cookieFlags, subdomainTakeover, exposedVcs, exposedAdmin, corsCredentialed, openRedirectToTakeover, secretsInJs } from '../packages/web-checks/index.js';
import { responseFixture } from '../packages/fixtures-apps/index.js';
import { detectorGate, type DetectorCase } from '../packages/benchmark/index.js';
import { authorize } from '../packages/scope-engine/index.js';
import { parseOpenApi, parseGraphQLIntrospection, mergeInventory, observedEndpoints } from '../packages/api-inventory/index.js';
import { openApiFixture } from '../packages/fixtures-apps/index.js';

test('every web detector flags its vulnerable fixture and passes its patched fixture (release gate)', () => {
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
  assert.deepEqual(result.failures, []);
  assert.equal(result.ok, true);
  assert.equal(result.metrics.falsePositives, 0);
  assert.equal(result.metrics.truePositives, cases.length);
});

test('OpenAPI inventory extracts method+path and rejects remote $ref', () => {
  const endpoints = parseOpenApi(openApiFixture());
  assert.ok(endpoints.some(e => e.method === 'DELETE' && e.path === '/users/{id}'));
  assert.equal(endpoints.filter(e => e.path === '/users').length, 2); // GET + POST
  assert.throws(() => parseOpenApi({ paths: { '/x': { get: { parameters: [{ $ref: 'https://evil.test/a.json' }] } } } }), /remote_ref_rejected/);
});

test('GraphQL introspection yields query/mutation operations and merge dedupes', () => {
  const intro = { data: { __schema: { queryType: { name: 'Query' }, mutationType: { name: 'Mutation' },
    types: [{ name: 'Query', fields: [{ name: 'me' }] }, { name: 'Mutation', fields: [{ name: 'deleteUser' }] }] } } };
  const gql = parseGraphQLIntrospection(intro);
  assert.ok(gql.some(e => e.method === 'MUTATION' && e.path === 'deleteUser'));
  const merged = mergeInventory(parseOpenApi(openApiFixture()), gql, observedEndpoints(['/health', 'not-a-path']));
  assert.ok(merged.some(e => e.path === '/health'));
  assert.ok(!merged.some(e => e.path === 'not-a-path'));
});

const rootPolicy = {
  programId: 'p', revision: 'r', sourceUrl: 'https://example.test/policy', reviewed: true as const,
  expiresAt: '2099-01-01T00:00:00.000Z', allowed: ['app.example.test'], excluded: [],
  allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1,
};

test('paid-detector paths stay denied until the policy grants that exact path', () => {
  const paths = ['/.git/config', '/.env', '/.DS_Store', '/actuator', '/admin', '/debug', '/login', '/oauth', '/callback', '/token', '/app.js'];
  for (const path of paths) {
    const denied = authorize(rootPolicy, `https://app.example.test${path}`, 'inspect_http_target', { GLOBAL_KILL_SWITCH: false });
    assert.equal(denied.allowed, false, path);
    assert.equal(denied.reason, 'prohibited_path', path);
  }
  const granted = { ...rootPolicy, allowedPaths: ['/.git/config'] };
  assert.equal(authorize(granted, 'https://app.example.test/.git/config', 'inspect_http_target', { GLOBAL_KILL_SWITCH: false }).allowed, true);
});

test('lookalike pages are not paid findings, and a JavaScript key is not copied into the detail', () => {
  assert.deepEqual(securityHeaders(responseFixture('headers', 'vulnerable')).map(finding => finding.severity), ['info']);
  assert.deepEqual(subdomainTakeover({ status: 200, headers: {}, body: 'NoSuchBucket', requestHost: 'app.example.test', cname: 'unclaimed.example.test' }), []);
  assert.deepEqual(subdomainTakeover({ status: 404, headers: {}, body: 'NoSuchBucket', requestHost: 'app.example.test' }), []);
  assert.deepEqual(exposedVcs({ status: 200, headers: {}, path: '/.env', body: '<html>APP_ENV=production</html>' }), []);
  assert.deepEqual(exposedAdmin({ status: 200, headers: {}, path: '/admin', body: '<html>admin login</html>' }), []);
  assert.deepEqual(openRedirectToTakeover({ status: 302, headers: { location: 'https://evil.test/' }, path: '/', requestHost: 'app.example.test', body: '' }), []);
  const secret = responseFixture('js-secret', 'vulnerable');
  const findings = secretsInJs(secret);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.detail.includes('AKIA'), false);
  assert.equal(findings[0]?.detail, 'aws_access_key at /app.js');
  assert.equal(findings[0]?.severity, 'high');
});
