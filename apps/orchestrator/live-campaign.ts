import type pg from 'pg';
import { discoverAndPartition, type DiscoveryAdapter } from '../../packages/discovery/index.js';
import { candidateJobs, type JobSpec } from '../../packages/discovery/enqueue.js';
import { coverageReport, type CoverageSummary, type ScanResult } from '../../packages/coverage/index.js';
import type { Responder, State } from '../../packages/findings/index.js';
import { remediationFor } from '../../packages/remediation/index.js';
import { PolicySchema, type Action } from '../../packages/scope-engine/index.js';
export { assetIdForHost } from '../../packages/shared/asset-id.js';
import { assetIdForHost } from '../../packages/shared/asset-id.js';
import { ProgramSchema, type Program } from '../../packages/bounty-providers/index.js';
import { saveProgram } from '../../packages/research-state/workspace.js';
import { Jobs, recordCampaignCoverage, recordReplay } from '../../packages/research-state/jobs.js';
import { ToolGateway, type GatewayExecutors } from '../../packages/mcp/index.js';
import { executeLeasedJob } from '../../packages/research-state/execution.js';
import type { Config } from '../../packages/shared/config.js';

// Persistent campaign (BOUNTY_EARNINGS_PLAN.md Phase 0.2). Discovery, admission, job specs,
// coverage, and remediation stay the pure composition in campaign.ts. This file adds the queue:
// admitted hosts become assets, Jobs enqueues them, and ToolGateway runs the existing worker
// tools. Held hosts are not saved and not enqueued. A model does not choose the target or action.

export interface LiveCampaignPlan {
  admitted: string[];
  held: string[];
  jobs: JobSpec[];
  assets: Array<{ id: string; url: string; host: string }>;
}

export async function planLiveCampaign(input: {
  roots: string[];
  policy: unknown;
  action: Action;
  revision: string;
  discovery: DiscoveryAdapter;
}): Promise<LiveCampaignPlan> {
  const { admitted, held } = await discoverAndPartition(input.discovery, input.roots, input.policy, input.action);
  const jobs = candidateJobs(admitted.map(row => row.candidate), input.policy, input.action, input.revision);
  const programId = PolicySchema.parse(input.policy).programId;
  const assets = jobs.map(job => ({ id: assetIdForHost(job.host, programId), url: `https://${job.host}`, host: job.host }));
  return {
    admitted: admitted.map(row => row.candidate.host),
    held: held.map(row => row.candidate.host),
    jobs,
    assets,
  };
}

export interface LiveCampaignInput {
  roots: string[];
  program: Omit<Program, 'assets'>;
  action: Action;
  discovery: DiscoveryAdapter;
  verify?: { from: State; contract: unknown; responder: Responder; body: Record<string, unknown> };
}

export interface LiveCampaignResult {
  admitted: string[];
  held: string[];
  jobs: JobSpec[];
  observations: Array<{ host: string; observationId: string; observation: Record<string, unknown> }>;
  coverage: CoverageSummary;
  remediations: Array<{ code: string; fix: string }>;
  verification?: { id: string; next: State; reproduced: boolean };
}

function signalsOf(observation: Record<string, unknown>): ScanResult['findings'] {
  if (!Array.isArray(observation.signals)) return [];
  const findings: ScanResult['findings'] = [];
  for (const signal of observation.signals) {
    if (!signal || typeof signal !== 'object') continue;
    const row = signal as Record<string, unknown>;
    if (typeof row.code !== 'string' || typeof row.severity !== 'string') continue;
    findings.push({ code: row.code, severity: row.severity, detail: typeof row.detail === 'string' ? row.detail : '' });
  }
  return findings;
}

export async function runLiveCampaign(
  deps: { pool: pg.Pool; config: () => Config; executors?: GatewayExecutors },
  input: LiveCampaignInput,
): Promise<LiveCampaignResult> {
  const plan = await planLiveCampaign({
    roots: input.roots, policy: input.program.policy, action: input.action,
    revision: input.program.policy.revision, discovery: input.discovery,
  });
  if (!plan.assets.length) {
    return { admitted: plan.admitted, held: plan.held, jobs: plan.jobs, observations: [], coverage: coverageReport([]).summary, remediations: [] };
  }
  const program = await saveProgram(deps.pool, ProgramSchema.parse({ ...input.program, assets: plan.assets.map(({ id, url }) => ({ id, url })) }));
  const config = deps.config;
  const jobs = new Jobs(deps.pool, config().MAX_CONCURRENT_JOBS, config().JOB_LEASE_SECONDS, () => config().GLOBAL_KILL_SWITCH);
  const gateway = new ToolGateway(deps.pool, config, deps.executors);
  const byAsset = new Map(program.assets.map(asset => [asset.id, new URL(asset.url).hostname]));
  for (const spec of plan.jobs) {
    const asset = program.assets.find(item => new URL(item.url).hostname === spec.host);
    if (!asset) continue;
    await jobs.enqueue(program.id, asset.id, spec.action, spec.dedupeKey);
  }
  const observations: LiveCampaignResult['observations'] = [];
  for (let n = 0; n < 32; n++) {
    const job = await jobs.claim(program.id);
    if (!job) break;
    const result = await executeLeasedJob({ jobs, gateway, job, leaseSeconds: config().JOB_LEASE_SECONDS });
    if (!result.completed) continue;
    observations.push({ host: byAsset.get(job.asset_id) ?? job.asset_id, observationId: result.observationId, observation: result.observation });
  }
  const results: ScanResult[] = observations.map(row => ({
    origin: `https://${row.host}`,
    reachable: typeof row.observation.status === 'number' && row.observation.error === undefined,
    findings: signalsOf(row.observation),
    probedPaths: Array.isArray(row.observation.probedPaths) ? row.observation.probedPaths.filter((path): path is string => typeof path === 'string') : [],
  }));
  const report = coverageReport(results);
  await recordCampaignCoverage(deps.pool, program.id, { ...report.summary }, report.markdown);
  const codes = [...new Set(results.flatMap(result => result.findings.map(finding => finding.code)))];
  const remediations = codes.map(code => ({ code, fix: remediationFor(code).fix }));
  let verification: LiveCampaignResult['verification'];
  if (input.verify) {
    verification = await recordReplay(deps.pool, program.id, input.verify.from, input.verify.contract, input.verify.responder, input.verify.body, { evidenceKey: config().EVIDENCE_KEY });
    const code = typeof input.verify.body.findingType === 'string' ? input.verify.body.findingType : '';
    if (verification.reproduced && code && !remediations.some(item => item.code === code)) {
      remediations.push({ code, fix: remediationFor(code).fix });
    }
  }
  return { admitted: plan.admitted, held: plan.held, jobs: plan.jobs, observations, coverage: report.summary, remediations, verification };
}
