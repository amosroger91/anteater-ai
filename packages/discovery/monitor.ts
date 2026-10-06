import type pg from 'pg';
import { ProgramBudget } from '../budget/index.js';
import { canProceed, type RevocationState } from '../operations/index.js';
import { Jobs } from '../research-state/jobs.js';
import { authorize, PolicySchema } from '../scope-engine/index.js';
import { normalizeHost, partition, toCandidates } from './index.js';
import { discoverWithinBudget, type LiveDiscoverySources } from './live.js';
import { newlyExposed, recordObservedHosts } from './store.js';

// One discovery cycle (BOUNTY_EARNINGS_PLAN.md Phase 2.3). Only an
// automation-permitted program with an enrolled wildcard is scanned. Roots are
// the wildcard apexes, not the concrete assets already in the program. Every
// observed name is recorded. A passive job is queued only for a host that is
// new since the previous run and that the current reviewed policy admits.

export function wildcardApexes(allowed: readonly string[]): string[] {
  const apexes = new Set<string>();
  for (const rule of allowed) {
    if (!rule.startsWith('*.')) continue;
    const apex = normalizeHost(rule.slice(2));
    if (apex) apexes.add(apex);
  }
  return [...apexes].sort();
}

export interface MonitorReport {
  programId: string;
  skipped: string | null;
  candidates: string[];
  admitted: string[];
  held: string[];
  newlyExposed: string[];
  newExposure: string[];
  enqueued: string[];
}

export function monitorBudget(requestsPerSecond: number, now = () => Date.now()): ProgramBudget {
  return new ProgramBudget({
    globalRatePerSec: requestsPerSecond,
    perHostRatePerSec: requestsPerSecond,
    concurrency: 1,
    bodyCapBytes: 8 * 1024 * 1024,
    timeoutMs: 15_000,
  }, now);
}

async function revocationState(pool: pg.Pool): Promise<RevocationState> {
  const control = await pool.query('SELECT global_kill, epoch FROM runtime_control WHERE id=1');
  const row = control.rows[0];
  if (!row) return { globalKill: true, revokedPrograms: [], epoch: 0 };
  const revoked = await pool.query('SELECT program_id FROM revoked_programs');
  return {
    globalKill: row.global_kill === true,
    revokedPrograms: revoked.rows.map((item: { program_id: string }) => item.program_id),
    epoch: Number(row.epoch ?? 0),
  };
}

function empty(programId: string, skipped: string): MonitorReport {
  return { programId, skipped, candidates: [], admitted: [], held: [], newlyExposed: [], newExposure: [], enqueued: [] };
}

export async function runMonitorCycle(input: {
  pool: pg.Pool;
  sources: LiveDiscoverySources;
  budgets?: Map<string, ProgramBudget>;
  now?: () => number;
}): Promise<MonitorReport[]> {
  const budgets = input.budgets ?? new Map<string, ProgramBudget>();
  const programs = await input.pool.query(`SELECT p.id, s.policy FROM programs p
    JOIN scope_rules s ON s.program_id=p.id
    WHERE p.automation_policy='permitted'
    ORDER BY p.id`);
  const jobs = new Jobs(input.pool);
  const reports: MonitorReport[] = [];
  for (const program of programs.rows) {
    const programId = String(program.id);
    const state = await revocationState(input.pool);
    const gate = canProceed(state, programId, state.epoch);
    if (!gate.ok) { reports.push(empty(programId, gate.reason)); continue; }
    const parsed = PolicySchema.safeParse(program.policy);
    if (!parsed.success) { reports.push(empty(programId, 'invalid_policy')); continue; }
    const policy = parsed.data;
    const roots = wildcardApexes(policy.allowed);
    if (!roots.length) { reports.push(empty(programId, 'no_wildcard')); continue; }
    let budget = budgets.get(programId);
    if (!budget) {
      budget = monitorBudget(policy.requestsPerSecond, input.now);
      budgets.set(programId, budget);
    }
    const raw = await discoverWithinBudget(input.sources, roots, budget);
    const discoveredState = await revocationState(input.pool);
    const afterDiscovery = canProceed(discoveredState, programId, discoveredState.epoch);
    if (!afterDiscovery.ok) { reports.push(empty(programId, afterDiscovery.reason)); continue; }
    const candidates = toCandidates(raw, roots);
    const admittedSet = partition(candidates, policy, 'inspect_http_target');
    const seq = await recordObservedHosts(input.pool, programId, candidates);
    const enqueueState = await revocationState(input.pool);
    const beforeEnqueue = canProceed(enqueueState, programId, enqueueState.epoch);
    if (!beforeEnqueue.ok) {
      await input.pool.query('DELETE FROM discovery_runs WHERE program_id=$1 AND seq=$2', [programId, seq]);
      reports.push(empty(programId, beforeEnqueue.reason));
      continue;
    }
    const fresh = new Set(await newlyExposed(input.pool, programId));
    const admitted = admittedSet.admitted.map(row => row.candidate.host);
    const newExposure = admitted.filter(host => fresh.has(host));
    const enqueued: string[] = [];
    for (const host of newExposure) {
      if (!authorize(policy, `https://${host}/`, 'inspect_http_target', { GLOBAL_KILL_SWITCH: false }).allowed) continue;
      const updated = await input.pool.query(`UPDATE assets SET active=true, policy_revision=$3
        WHERE program_id=$1 AND url=$2 RETURNING id`, [programId, `https://${host}`, policy.revision]);
      const assetId = updated.rows[0]?.id;
      if (typeof assetId !== 'string') continue;
      await jobs.enqueue(programId, assetId, 'inspect_http_target');
      const queued = await input.pool.query(`SELECT 1 FROM research_jobs j
        JOIN assets a ON a.id=j.asset_id AND a.program_id=j.program_id
        WHERE j.program_id=$1 AND a.url=$2 AND j.action='inspect_http_target'`, [programId, `https://${host}`]);
      if (queued.rowCount) enqueued.push(host);
    }
    reports.push({
      programId, skipped: null,
      candidates: candidates.map(candidate => candidate.host),
      admitted, held: admittedSet.held.map(row => row.candidate.host),
      newlyExposed: [...fresh], newExposure, enqueued,
    });
  }
  return reports;
}
