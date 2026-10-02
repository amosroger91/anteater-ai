import { discoverAndPartition, type DiscoveryAdapter } from '../../packages/discovery/index.js';
import { candidateJobs, type JobSpec } from '../../packages/discovery/enqueue.js';
import { runAll, type HttpResponseView } from '../../packages/web-checks/index.js';
import { coverageReport, type CoverageSummary, type ScanResult } from '../../packages/coverage/index.js';
import { verifyCandidate, type State, type Responder } from '../../packages/findings/index.js';
import { remediationFor } from '../../packages/remediation/index.js';
import type { Action } from '../../packages/scope-engine/index.js';

// End-to-end campaign composition over the deterministic modules (PRODUCTION_ROADMAP.md §0 wiring):
// discovery -> candidate-only admission -> code-minted jobs -> passive checks -> methodology coverage
// -> deterministic verification -> remediation. Responses and discovery are injected, so this runs
// against fixtures in CI and against the real egress path in production without changing shape.

export interface CampaignInput {
  roots: string[];
  policy: unknown;
  action: Action;
  revision: string;
  discovery: DiscoveryAdapter;
  responseFor: (host: string) => HttpResponseView;
  verify?: { from: State; contract: unknown; responder: Responder };
}

export interface CampaignResult {
  admitted: string[];
  held: string[];
  jobs: JobSpec[];
  results: ScanResult[];
  coverage: CoverageSummary;
  remediations: Array<{ code: string; fix: string }>;
  verification?: { next: State; reproduced: boolean };
}

export async function runCampaign(input: CampaignInput): Promise<CampaignResult> {
  const { admitted, held } = await discoverAndPartition(input.discovery, input.roots, input.policy, input.action);
  const jobs = candidateJobs(admitted.map(a => a.candidate), input.policy, input.action, input.revision);

  const results: ScanResult[] = jobs.map(job => ({
    origin: `https://${job.host}`,
    reachable: true,
    findings: runAll(input.responseFor(job.host)).map(f => ({ code: f.code, severity: f.severity, detail: f.detail })),
  }));

  const report = coverageReport(results);
  const codes = [...new Set(results.flatMap(r => r.findings.map(f => f.code)))];
  const remediations = codes.map(code => ({ code, fix: remediationFor(code).fix }));

  let verification: CampaignResult['verification'];
  if (input.verify) {
    const outcome = await verifyCandidate(input.verify.from, input.verify.contract, input.verify.responder);
    verification = { next: outcome.next, reproduced: outcome.outcome.reproduced };
  }

  return {
    admitted: admitted.map(a => a.candidate.host),
    held: held.map(h => h.candidate.host),
    jobs, results, coverage: report.summary, remediations, verification,
  };
}
