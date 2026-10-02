import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CertTransparencyDiscovery, type FetchLike } from '../packages/discovery/adapters.js';
import { toCandidates, partition } from '../packages/discovery/index.js';

const policy = {
  programId: 'p', revision: 'r', sourceUrl: 'https://example.test/policy', reviewed: true as const,
  expiresAt: '2099-01-01T00:00:00Z', allowed: ['*.example.test'], excluded: ['secret.example.test'],
  allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1,
};

const stub = (body: string, ok = true): FetchLike => async () => ({ ok, status: ok ? 200 : 500, async text() { return body; } });

test('CT adapter extracts in-root names, strips wildcards, dedupes, drops cross-domain SANs', async () => {
  const body = JSON.stringify([
    { name_value: '*.example.test\napi.example.test' },
    { name_value: 'api.example.test' },               // duplicate
    { name_value: 'secret.example.test' },
    { name_value: 'cdn.vendor.test' },                // cross-domain SAN -> excluded from this root
  ]);
  const raw = await new CertTransparencyDiscovery(stub(body)).discover(['example.test']);
  const hosts = raw.map(r => r.host).sort();
  assert.deepEqual(hosts, ['api.example.test', 'example.test', 'secret.example.test']);
  assert.ok(raw.every(r => r.source === 'cert-transparency'));
});

test('a failed OSINT source yields no candidates, not a crash', async () => {
  assert.deepEqual(await new CertTransparencyDiscovery(stub('err', false)).discover(['example.test']), []);
  assert.deepEqual(await new CertTransparencyDiscovery(stub('not json')).discover(['example.test']), []);
});

test('CT candidates still pass through scope admission (excluded/apex held)', async () => {
  const raw = await new CertTransparencyDiscovery(stub(JSON.stringify([{ name_value: 'api.example.test\nsecret.example.test\nexample.test' }]))).discover(['example.test']);
  const { admitted, held } = partition(toCandidates(raw, ['example.test']), policy, 'inspect_http_target');
  assert.deepEqual(admitted.map(a => a.candidate.host), ['api.example.test']);
  assert.deepEqual(held.map(h => h.candidate.host).sort(), ['example.test', 'secret.example.test']);
});
