import { runCampaign, type CampaignResult } from './campaign.js';
import { FixtureDiscovery } from '../../packages/discovery/index.js';
import { responseFixture, accessControlResponder, ACCESS_CONTROL_CONTRACT } from '../../packages/fixtures-apps/index.js';

const policy = {
  programId: 'demo', revision: 'r', sourceUrl: 'https://example.test/policy', reviewed: true,
  expiresAt: '2099-01-01T00:00:00Z', allowed: ['*.example.test'], excluded: ['secret.example.test'],
  allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1,
};

// Local fixture only. Discovery and responses are injected, so this does not open a socket.
export function runLocalFixtureScan(): Promise<CampaignResult> {
  const discovery = new FixtureDiscovery({ 'example.test': [
    { host: 'api.example.test', source: 'cert-transparency', confidence: 0.8 },
    { host: 'secret.example.test', source: 'cert-transparency', confidence: 0.8 },
    { host: 'leak.vendor.test', source: 'observed-link', confidence: 0.4 },
  ] });
  return runCampaign({
    roots: ['example.test'], policy, action: 'inspect_http_target', revision: 'rev1', discovery,
    responseFor: () => responseFixture('headers', 'vulnerable'),
    verify: { from: 'CANDIDATE', contract: ACCESS_CONTROL_CONTRACT, responder: accessControlResponder('vulnerable') },
  });
}

export function publicFixtureScan(result: CampaignResult) {
  return {
    kind: 'fixture' as const,
    contactedNetwork: false,
    admitted: result.admitted,
    held: result.held,
    jobs: result.jobs.length,
    findings: result.results.flatMap(row => row.findings.map(finding => ({
      host: row.origin,
      code: finding.code,
      severity: finding.severity,
    }))),
    coverage: result.coverage,
    verification: result.verification ?? null,
    remediations: result.remediations.map(item => item.code),
  };
}
