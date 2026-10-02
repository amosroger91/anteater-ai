import type pg from 'pg';
import type { Config } from '../shared/config.js';
import { ActionSchema, authorize, PolicySchema, targetForAction } from '../scope-engine/index.js';
import { acquireRate, type Job } from '../research-state/jobs.js';
import { log } from '../shared/log.js';
import { executePassiveHttp } from '../web-executor/index.js';
import { setTimeout as sleep } from 'node:timers/promises';

export class ToolGateway {
  constructor(private pool: pg.Pool, private config: () => Config) {}
  async invoke(job: Job, tool: string, assetId: string, signal?: AbortSignal): Promise<Record<string, unknown>> {
    const config = this.config();
    if (config.GLOBAL_KILL_SWITCH) throw new Error('kill_switch');
    if (!ActionSchema.safeParse(tool).success || tool !== job.action || assetId !== job.asset_id) throw new Error('tool_or_asset_denied');
    const validate = async () => {
      const result = await this.pool.query(`SELECT a.url,s.policy,p.platform FROM assets a
        JOIN programs p ON p.id=a.program_id JOIN scope_rules s ON s.program_id=p.id
        JOIN research_jobs j ON j.asset_id=a.id AND j.program_id=p.id
        WHERE a.id=$1 AND p.id=$2 AND j.id=$3 AND j.lease_token=$4 AND j.status='running' AND j.lease_until>now()
          AND j.action=$5 AND a.active=true AND j.policy_revision=s.policy->>'revision' AND a.policy_revision=j.policy_revision`,
        [assetId,job.program_id,job.id,job.lease_token,job.action]);
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
    const reserve = async () => {
      signal?.throwIfAborted();
      const current = await validate();
      if (current.target !== target || JSON.stringify(current.policy) !== JSON.stringify(policy)) throw new Error('policy_changed');
      const currentConfig = this.config();
      if (application && !currentConfig.ENABLE_APPLICATION_RESEARCH) throw new Error('application_research_not_enabled');
      if (!fixture && !application && !currentConfig.ENABLE_PASSIVE_HTTP) throw new Error('live_executor_not_enabled');
      if (!await acquireRate(this.pool,job.program_id,current.policy.requestsPerSecond,currentConfig.MAX_REQUEST_RATE)) throw new Error('rate_limited');
      if (this.config().GLOBAL_KILL_SWITCH) throw new Error('kill_switch');
    };
    if (application) {
      const { researchApplication } = await import('../application-research/index.js');
      return researchApplication(new URL(target).origin, policy.application!, config, async requestSignal => {
        while (true) {
          requestSignal.throwIfAborted();
          try { await reserve(); return; }
          catch (error) {
            if (!(error instanceof Error) || error.message !== 'rate_limited') throw error;
            await sleep(100, undefined, { signal: requestSignal });
          }
        }
      }, signal);
    }
    if (fixture) {
      await reserve();
      log('TOOL_EXECUTED',{program:job.program_id,job:job.id,asset:assetId,result:'fixture'});
      return { kind:'OBSERVATION', fixture:true, assetId, target, status:200, headers:{ 'content-type':'application/json' }, note:'Synthetic response; no network request performed.' };
    }
    const observation = await executePassiveHttp(target, { maxBytes: config.MAX_RESPONSE_BYTES, signal, beforeRequest: reserve });
    log('TOOL_EXECUTED',{program:job.program_id,job:job.id,asset:assetId,result:'http-passive'});
    return { ...observation, assetId };
  }
}
