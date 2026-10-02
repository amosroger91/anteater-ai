import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runCampaign } from '../apps/orchestrator/campaign.js';
import { FixtureDiscovery } from '../packages/discovery/index.js';
import { responseFixture, accessControlResponder, ACCESS_CONTROL_CONTRACT } from '../packages/fixtures-apps/index.js';

const policy = {
  programId: 'p', revision: 'r', sourceUrl: 'https://example.test/policy', reviewed: true as const,
  expiresAt: '2099-01-01T00:00:00Z', allowed: ['*.example.test'], excluded: ['secret.example.test'],
  allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1,
};

test('a full campaign: discover -> admit -> job -> check -> cover -> verify, end to end over fixtures', async () => {
  const discovery = new FixtureDiscovery({ 'example.test': [
    { host: 'api.example.test', source: 'cert-transparency', confidence: 0.8 },
    { host: 'secret.example.test', source: 'cert-transparency', confidence: 0.8 },  // excluded
    { host: 'leak.vendor.test', source: 'observed-link', confidence: 0.4 },         // out of scope
  ] });

  const result = await runCampaign({
    roots: ['example.test'], policy, action: 'inspect_http_target', revision: 'rev1', discovery,
    responseFor: () => responseFixture('headers', 'vulnerable'),   // admitted hosts return an insecure response
    verify: { from: 'CANDIDATE', contract: ACCESS_CONTROL_CONTRACT, responder: accessControlResponder('vulnerable') },
  });

  // Only the in-scope subdomain is admitted and queued; excluded/out-of-scope are held, never contacted.
  assert.deepEqual(result.admitted, ['api.example.test']);
  assert.ok(result.held.includes('secret.example.test') && result.held.includes('leak.vendor.test'));
  assert.equal(result.jobs.length, 1);
  assert.ok(result.jobs[0]!.dedupeKey.startsWith('rev1:api.example.test:'));

  // Checks produced findings, coverage counted them, remediation was generated.
  assert.ok(result.coverage.candidates > 0);
  assert.ok(result.results[0]!.findings.some(f => f.code === 'missing_security_headers'));
  assert.ok(result.remediations.some(r => r.code === 'missing_security_headers' && /HSTS|CSP|header/i.test(r.fix)));

  // Deterministic verification reproduced the cross-account read and reached VERIFIED.
  assert.equal(result.verification?.reproduced, true);
  assert.equal(result.verification?.next, 'VERIFIED');
});

test('campaign results are deterministic across repeated runs (reproducible benchmark)', async () => {
  const mk = () => new FixtureDiscovery({ 'example.test': [{ host: 'api.example.test', source: 'cert-transparency', confidence: 0.8 }] });
  const input = () => ({ roots: ['example.test'], policy, action: 'inspect_http_target' as const, revision: 'rev1', discovery: mk(), responseFor: () => responseFixture('headers', 'vulnerable') });
  const a = await runCampaign(input());
  const b = await runCampaign(input());
  assert.deepEqual({ ...a, results: a.results, jobs: a.jobs }, { ...b, results: b.results, jobs: b.jobs });
});

test('a campaign with no in-scope discoveries admits nothing and contacts nothing', async () => {
  const discovery = new FixtureDiscovery({ 'example.test': [{ host: 'leak.vendor.test', source: 'observed-link', confidence: 0.4 }] });
  const result = await runCampaign({ roots: ['example.test'], policy, action: 'inspect_http_target', revision: 'rev1', discovery, responseFor: () => responseFixture('headers', 'patched') });
  assert.deepEqual(result.admitted, []);
  assert.equal(result.jobs.length, 0);
  assert.equal(result.results.length, 0);
});
