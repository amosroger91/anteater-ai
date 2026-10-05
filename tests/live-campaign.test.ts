import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assetIdForHost, planLiveCampaign } from '../apps/orchestrator/live-campaign.js';
import { FixtureDiscovery } from '../packages/discovery/index.js';

const policy = {
  programId: 'lab-staging', revision: 'lab-r1', sourceUrl: 'https://lab.anteater.test/policy', reviewed: true as const,
  expiresAt: '2099-01-01T00:00:00Z', allowed: ['lab-vuln.anteater.test'], excluded: ['secret.anteater.test'],
  allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1,
};

test('live campaign planning admits only the reviewed host and mints a stable asset id', async () => {
  const discovery = new FixtureDiscovery({ 'lab-vuln.anteater.test': [
    { host: 'secret.anteater.test', source: 'cert-transparency', confidence: 0.8 },
    { host: 'leak.vendor.test', source: 'observed-link', confidence: 0.4 },
  ] });
  const plan = await planLiveCampaign({
    roots: ['lab-vuln.anteater.test'], policy, action: 'inspect_http_target', revision: 'lab-r1', discovery,
  });
  assert.deepEqual(plan.admitted, ['lab-vuln.anteater.test']);
  assert.ok(plan.held.includes('secret.anteater.test') && plan.held.includes('leak.vendor.test'));
  assert.equal(plan.jobs.length, 1);
  assert.equal(plan.assets.length, 1);
  assert.equal(plan.assets[0]?.id, 'lab-vuln-anteater-test');
  assert.equal(plan.assets[0]?.url, 'https://lab-vuln.anteater.test');
  assert.equal(assetIdForHost('lab-vuln.anteater.test'), 'lab-vuln-anteater-test');
  assert.ok(plan.jobs[0]?.dedupeKey.startsWith('lab-r1:lab-vuln.anteater.test:'));
});

test('a live plan with nothing in scope queues no asset', async () => {
  const discovery = new FixtureDiscovery({ 'example.test': [{ host: 'leak.vendor.test', source: 'observed-link', confidence: 0.4 }] });
  const plan = await planLiveCampaign({
    roots: ['example.test'], policy, action: 'inspect_http_target', revision: 'lab-r1', discovery,
  });
  assert.deepEqual(plan.admitted, []);
  assert.equal(plan.jobs.length, 0);
  assert.equal(plan.assets.length, 0);
});
