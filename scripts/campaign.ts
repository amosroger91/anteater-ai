import { runCampaign } from '../apps/orchestrator/campaign.js';
import { FixtureDiscovery } from '../packages/discovery/index.js';
import { responseFixture, accessControlResponder, ACCESS_CONTROL_CONTRACT } from '../packages/fixtures-apps/index.js';

// Runnable end-to-end campaign over local fixtures (PRODUCTION_ROADMAP.md §0 wiring). Demonstrates
// discover -> admit -> job -> check -> cover -> verify with no live target. usage: npm run campaign

const policy = {
  programId: 'demo', revision: 'r', sourceUrl: 'https://example.test/policy', reviewed: true,
  expiresAt: '2099-01-01T00:00:00Z', allowed: ['*.example.test'], excluded: ['secret.example.test'],
  allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1,
};
const discovery = new FixtureDiscovery({ 'example.test': [
  { host: 'api.example.test', source: 'cert-transparency', confidence: 0.8 },
  { host: 'secret.example.test', source: 'cert-transparency', confidence: 0.8 },
] });

const result = await runCampaign({
  roots: ['example.test'], policy, action: 'inspect_http_target', revision: 'rev1', discovery,
  responseFor: () => responseFixture('headers', 'vulnerable'),
  verify: { from: 'CANDIDATE', contract: ACCESS_CONTROL_CONTRACT, responder: accessControlResponder('vulnerable') },
});

console.log(JSON.stringify({
  admitted: result.admitted, held: result.held, jobs: result.jobs.length,
  coverage: result.coverage, verified: result.verification?.next, reproduced: result.verification?.reproduced,
  remediations: result.remediations.map(r => r.code),
}, null, 2));
