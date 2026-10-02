import type pg from 'pg';
import type { Config } from '../shared/config.js';
import { authorize, PolicySchema } from '../scope-engine/index.js';
import { acquireRate, type Job } from '../research-state/jobs.js';
import { log } from '../shared/log.js';

export class ToolGateway {
  constructor(private pool: pg.Pool, private config: () => Config) {}
  async invoke(job: Job, tool: string, assetId: string) {
    const config = this.config();
    if (config.GLOBAL_KILL_SWITCH) throw new Error('kill_switch');
    if (tool !== 'inspect_http_target' || tool !== job.action || assetId !== job.asset_id) throw new Error('tool_or_asset_denied');
    const result = await this.pool.query(`SELECT a.url,a.active,a.policy_revision,s.policy,p.platform FROM assets a
      JOIN programs p ON p.id=a.program_id JOIN scope_rules s ON s.program_id=p.id
      JOIN research_jobs j ON j.asset_id=a.id AND j.program_id=p.id
      WHERE a.id=$1 AND p.id=$2 AND j.id=$3 AND j.lease_token=$4 AND j.status='running' AND j.lease_until>now()
        AND a.active=true AND j.policy_revision=s.policy->>'revision' AND a.policy_revision=j.policy_revision`,
      [assetId,job.program_id,job.id,job.lease_token]);
    const row = result.rows[0];
    if (!row) throw new Error('unknown_asset_or_lost_lease');
    const decision = authorize(row.policy,row.url,tool,config);
    if (!decision.allowed) { log('TOOL_DENIED',{ program:job.program_id, job:job.id, result:decision.reason }); throw new Error(decision.reason); }
    const policy = PolicySchema.parse(row.policy);
    if (policy.programId !== job.program_id) throw new Error('policy_program_mismatch');
    if (job.policy_revision !== policy.revision) throw new Error('stale_policy_revision');
    // This boundary cannot reach a shell, Docker socket, MCP transport, or target network.
    // Live executors must remain unavailable even when ALLOW_ACTIVE_TESTING=true.
    if (row.platform !== 'fixture' || job.program_id !== 'fixture-company' || assetId !== 'fixture-api' || row.url !== 'https://api.example.test') throw new Error('live_executor_not_implemented');
    if (!await acquireRate(this.pool,job.program_id,policy.requestsPerSecond,config.MAX_REQUEST_RATE)) throw new Error('rate_limited');
    if (this.config().GLOBAL_KILL_SWITCH) throw new Error('kill_switch');
    log('TOOL_EXECUTED',{program:job.program_id,job:job.id,asset:assetId,result:'fixture'});
    return { kind:'OBSERVATION', fixture:true, status:200, headers:{ 'content-type':'application/json' }, note:'Synthetic response; no network request performed.' };
  }
}
