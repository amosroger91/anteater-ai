import type pg from 'pg';
import type { Config } from '../shared/config.js';
import { ActionSchema, authorize, PolicySchema, targetForAction } from '../scope-engine/index.js';
import { acquireRate, type Job } from '../research-state/jobs.js';
import { log } from '../shared/log.js';
import { executePassiveHttp, probeAuthorizedGets, parseLabTargetAllow, type PassiveDeps } from '../web-executor/index.js';
import type { ResearchDeps } from '../application-research/index.js';
import { ProgramBudget } from '../budget/index.js';
import { setTimeout as sleep } from 'node:timers/promises';
import { assertExecutionAllowed } from '../research-state/control.js';
import { EXPOSURE_READ_PATHS } from '../web-checks/index.js';
import { createCleanupJournal } from '../application-research/cleanup.js';
import { loadOperatorEnvironment } from '../setup/operator.js';

export interface GatewayExecutors { passive?: PassiveDeps; research?: ResearchDeps }
export class ToolGateway {
  private budgets = new Map<string, ProgramBudget>();
  constructor(private pool: pg.Pool, private config: () => Config, private executors: GatewayExecutors = {}) {}
  private applicationBudget(programId: string, requestsPerSecond: number): ProgramBudget {
    const existing = this.budgets.get(programId);
    if (existing) return existing;
    const rate = Math.max(requestsPerSecond, 0.001);
    const budget = new ProgramBudget({
      globalRatePerSec: rate, perHostRatePerSec: rate, concurrency: Math.max(1, this.config().MAX_CONCURRENT_JOBS),
      bodyCapBytes: this.config().MAX_RESPONSE_BYTES, timeoutMs: 15000,
    });
    this.budgets.set(programId, budget);
    return budget;
  }
  async invoke(job: Job, tool: string, assetId: string, signal?: AbortSignal): Promise<Record<string, unknown>> {
    const config = this.config();
    if (config.GLOBAL_KILL_SWITCH) throw new Error('kill_switch');
    if (!ActionSchema.safeParse(tool).success || tool !== job.action || assetId !== job.asset_id) throw new Error('tool_or_asset_denied');
    const validate = async () => {
      signal?.throwIfAborted();
      await assertExecutionAllowed(this.pool, job.program_id, job.lease_epoch, this.config().GLOBAL_KILL_SWITCH);
      const result = await this.pool.query(`SELECT a.url,s.policy,p.platform FROM assets a
        JOIN programs p ON p.id=a.program_id JOIN scope_rules s ON s.program_id=p.id
        JOIN research_jobs j ON j.asset_id=a.id AND j.program_id=p.id
        WHERE a.id=$1 AND p.id=$2 AND j.id=$3 AND j.lease_token=$4 AND j.status='running' AND j.lease_until>now()
          AND j.action=$5 AND j.lease_epoch=$6 AND a.active=true AND j.policy_revision=s.policy->>'revision' AND a.policy_revision=j.policy_revision`,
        [assetId,job.program_id,job.id,job.lease_token,job.action,job.lease_epoch]);
      const row = result.rows[0];
      if (!row) throw new Error('unknown_asset_or_lost_lease');
      const target = targetForAction(row.url, job.action);
      const decision = authorize(row.policy,target,tool,this.config());
      if (!decision.allowed) { log('TOOL_DENIED',{ program:job.program_id, job:job.id, result:decision.reason }); throw new Error(decision.reason); }
      const policy = PolicySchema.parse(row.policy);
      if (policy.programId !== job.program_id) throw new Error('policy_program_mismatch');
      if (job.policy_revision !== policy.revision) throw new Error('stale_policy_revision');
      return { row, policy, target };
    };
    const { row, policy, target } = await validate();
    const application = job.action === 'research_application';
    if (application && (!config.ENABLE_APPLICATION_RESEARCH || !policy.application)) throw new Error('application_research_not_enabled');
    const fixture = row.platform === 'fixture' && job.program_id === 'fixture-company' && assetId === 'fixture-api' && row.url === 'https://api.example.test';
    if (!fixture && !application && !config.ENABLE_PASSIVE_HTTP) throw new Error('live_executor_not_enabled');
    const reserve = async (requestSignal = signal, requestTarget = target) => {
      requestSignal?.throwIfAborted();
      signal?.throwIfAborted();
      const current = await validate();
      if (current.target !== target || JSON.stringify(current.policy) !== JSON.stringify(policy)) throw new Error('policy_changed');
      const currentConfig = this.config();
      const allowed = authorize(current.policy, requestTarget, tool, currentConfig);
      if (!allowed.allowed) throw new Error(allowed.reason);
      if (application && !currentConfig.ENABLE_APPLICATION_RESEARCH) throw new Error('application_research_not_enabled');
      if (!fixture && !application && !currentConfig.ENABLE_PASSIVE_HTTP) throw new Error('live_executor_not_enabled');
      if (!await acquireRate(this.pool,job.program_id,current.policy.requestsPerSecond,currentConfig.MAX_REQUEST_RATE)) throw new Error('rate_limited');
      await assertExecutionAllowed(this.pool, job.program_id, job.lease_epoch, this.config().GLOBAL_KILL_SWITCH);
    };
    if (application) {
      const { researchApplication } = await import('../application-research/index.js');
      const host = new URL(target).hostname;
      return researchApplication(new URL(target).origin, policy.application!, config, async requestSignal => {
        while (true) {
          requestSignal.throwIfAborted();
          const budget = this.applicationBudget(job.program_id, policy.requestsPerSecond);
          if (!budget.allow(host).ok) {
            await sleep(100, undefined, { signal: requestSignal });
            continue;
          }
          let limited = false;
          try { await reserve(requestSignal); return; }
          catch (error) {
            if (!(error instanceof Error) || error.message !== 'rate_limited') throw error;
            limited = true;
          } finally { budget.done(); }
          if (limited) await sleep(100, undefined, { signal: requestSignal });
        }
      }, signal, {
        ...this.executors.research,
        env: this.executors.research?.env ?? loadOperatorEnvironment(),
        cleanupJournal: this.executors.research?.cleanupJournal ?? createCleanupJournal(this.pool, job.program_id, job.policy_revision, { jobId: job.id, leaseToken: job.lease_token }),
      });
    }
    if (fixture) {
      await reserve();
      log('TOOL_EXECUTED',{program:job.program_id,job:job.id,asset:assetId,result:'fixture'});
      return { kind:'OBSERVATION', fixture:true, assetId, target, status:200, headers:{ 'content-type':'application/json' }, note:'Synthetic response; no network request performed.' };
    }
    const observation = await executePassiveHttp(target, {
      maxBytes: config.MAX_RESPONSE_BYTES, signal, beforeRequest: () => reserve(), deps: this.executors.passive,
      labTargets: parseLabTargetAllow(config.ALLOW_PRIVATE_LAB_TARGETS, config.LAB_TARGET_HOSTS),
    });
    if (job.action === 'inspect_http_target' && observation.error === undefined) {
      const probes = await probeAuthorizedGets({
        host: new URL(target).hostname, policy, killSwitch: config.GLOBAL_KILL_SWITCH, enabled: config.ENABLE_PASSIVE_HTTP,
        paths: EXPOSURE_READ_PATHS, maxBytes: config.MAX_RESPONSE_BYTES, deps: this.executors.passive, signal,
        labTargets: parseLabTargetAllow(config.ALLOW_PRIVATE_LAB_TARGETS, config.LAB_TARGET_HOSTS),
        beforeRequest: async probeTarget => {
          for (let attempt = 0; ; attempt++) {
            try { await reserve(signal, probeTarget); return; }
            catch (error) {
              if (!(error instanceof Error) || error.message !== 'rate_limited' || attempt >= 7) throw error;
              await sleep(250, undefined, { signal });
            }
          }
        },
      });
      observation.signals = [...(Array.isArray(observation.signals) ? observation.signals : []), ...probes.signals];
      observation.probedPaths = probes.probed;
    }
    log('TOOL_EXECUTED',{program:job.program_id,job:job.id,asset:assetId,result:'http-passive'});
    return { ...observation, assetId };
  }
}
