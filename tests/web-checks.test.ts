import { test } from 'node:test';
import assert from 'node:assert/strict';
import { securityHeaders, cors, cacheExposure, unsafeRedirect, cookieFlags } from '../packages/web-checks/index.js';
import { responseFixture } from '../packages/fixtures-apps/index.js';
import { detectorGate, type DetectorCase } from '../packages/benchmark/index.js';
import { parseOpenApi, parseGraphQLIntrospection, mergeInventory, observedEndpoints } from '../packages/api-inventory/index.js';
import { openApiFixture } from '../packages/fixtures-apps/index.js';

test('every web detector flags its vulnerable fixture and passes its patched fixture (release gate)', () => {
  const cases: DetectorCase[] = [
    { name: 'headers', detector: securityHeaders, code: 'missing_security_headers', vulnerable: responseFixture('headers', 'vulnerable'), patched: responseFixture('headers', 'patched') },
    { name: 'cors', detector: cors, code: 'cors_wildcard_with_credentials', vulnerable: responseFixture('cors', 'vulnerable'), patched: responseFixture('cors', 'patched') },
    { name: 'cache', detector: cacheExposure, code: 'sensitive_response_cacheable', vulnerable: responseFixture('cache', 'vulnerable'), patched: responseFixture('cache', 'patched') },
    { name: 'redirect', detector: unsafeRedirect, code: 'open_redirect', vulnerable: responseFixture('redirect', 'vulnerable'), patched: responseFixture('redirect', 'patched') },
    { name: 'cookie', detector: cookieFlags, code: 'weak_cookie_flags', vulnerable: responseFixture('cookie', 'vulnerable'), patched: responseFixture('cookie', 'patched') },
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
