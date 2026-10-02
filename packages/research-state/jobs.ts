import type pg from 'pg';
import { randomUUID } from 'node:crypto';
import type { AnalysisFailure, AnalysisRun } from '../agent-runtime/index.js';
import { transaction } from './db.js';
import { authorize, PolicySchema, targetForAction, type Action } from '../scope-engine/index.js';
import { followUpActions, jobKey } from '../web-executor/planning.js';

export interface Job {
  id: string; program_id: string; asset_id: string; action: Action; policy_revision: string;
  lease_token: string; attempts: number;
}

export class Jobs {
  constructor(private pool: pg.Pool, private concurrency = 1, private leaseSeconds = 30) {}

  async enqueue(program: string, asset: string, action: Action, key?: string) {
    return transaction(this.pool, c => this.enqueueOn(c, program, asset, action, key));
  }

  private async enqueueOn(c: pg.PoolClient, program: string, asset: string, action: Action, key?: string, expectedRevision?: string) {
    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`program:${program}`]);
    const source = await c.query(`SELECT a.url,s.policy FROM assets a JOIN scope_rules s ON s.program_id=a.program_id
      WHERE a.id=$1 AND a.program_id=$2 AND a.active=true FOR SHARE OF a,s`, [asset, program]);
    const row = source.rows[0];
    if (!row) return;
    const parsed = PolicySchema.safeParse(row.policy);
    if (!parsed.success || parsed.data.programId !== program || (expectedRevision && parsed.data.revision !== expectedRevision)) return;
    const target = targetForAction(row.url, action);
    if (!authorize(parsed.data, target, action, { GLOBAL_KILL_SWITCH: false }).allowed) return;
    const dedupeKey = key ?? jobKey(program, asset, parsed.data.revision, target, action);
    const id = randomUUID();
    const inserted = await c.query(`
      INSERT INTO research_jobs(id,program_id,asset_id,action,dedupe_key,policy_revision)
      SELECT $1,$2,$3,$4,$5,s.policy->>'revision'
      FROM assets a JOIN scope_rules s ON s.program_id=a.program_id
      WHERE a.id=$3 AND a.program_id=$2 AND a.active=true
        AND s.policy->'allowedActions' ? $4
      ON CONFLICT(dedupe_key) DO NOTHING`, [id, program, asset, action, dedupeKey]);
    if (inserted.rowCount) await c.query(`INSERT INTO audit_events(id,event,program_id,job_id,asset_id,metadata) VALUES($1,'JOB_QUEUED',$2,$3,$4,$5)`, [randomUUID(), program, id, asset, JSON.stringify({ action, dedupeKey })]);
  }

  async claim(): Promise<Job | undefined> {
    return transaction(this.pool, async c => {
      await c.query('SELECT pg_advisory_xact_lock(784291)');
      await c.query(`UPDATE research_jobs SET status='failed',lease_token=NULL,lease_until=NULL,lease_heartbeat_at=NULL
        WHERE status='running' AND lease_until <= now() AND attempts >= max_attempts`);
      const count = await c.query(`SELECT count(*)::int AS n FROM research_jobs WHERE status='running' AND lease_until > now()`);
      if (count.rows[0].n >= this.concurrency) return undefined;
      const result = await c.query(`UPDATE research_jobs j SET status='running',attempts=j.attempts+1,
        lease_token=$1,lease_until=now()+$2*interval '1 second',lease_heartbeat_at=now()
        WHERE j.id=(SELECT candidate.id FROM research_jobs candidate
          JOIN assets a ON a.id=candidate.asset_id AND a.program_id=candidate.program_id AND a.active=true
          JOIN scope_rules s ON s.program_id=candidate.program_id
          WHERE candidate.attempts<candidate.max_attempts
            AND candidate.policy_revision=s.policy->>'revision'
            AND ((candidate.status='queued' AND candidate.available_at<=now()) OR (candidate.status='running' AND candidate.lease_until<=now()))
          ORDER BY candidate.created_at FOR UPDATE OF candidate SKIP LOCKED LIMIT 1)
        RETURNING j.*`, [randomUUID(), this.leaseSeconds]);
      return result.rows[0] as Job | undefined;
    });
  }

  async heartbeat(job: Job, seconds = this.leaseSeconds) {
    const changed = await this.pool.query(`UPDATE research_jobs SET lease_until=now()+$3*interval '1 second',lease_heartbeat_at=now()
      WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>now()`, [job.id, job.lease_token, seconds]);
    if (!changed.rowCount) throw new Error('lost_lease');
  }

  async complete(job: Job, observation: unknown): Promise<string> {
    const observationId = randomUUID();
    await transaction(this.pool, async c => {
      await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`program:${job.program_id}`]);
      const current = await c.query(`SELECT a.url,s.policy FROM assets a JOIN scope_rules s ON s.program_id=a.program_id
        WHERE a.id=$1 AND a.program_id=$2 AND a.active=true AND a.policy_revision=$3 FOR SHARE OF a,s`, [job.asset_id, job.program_id, job.policy_revision]);
      const row = current.rows[0];
      if (!row || row.policy.revision !== job.policy_revision || !authorize(row.policy, targetForAction(row.url, job.action), job.action, { GLOBAL_KILL_SWITCH: false }).allowed) throw new Error('policy_changed');
      const changed = await c.query(`UPDATE research_jobs SET status='completed',result=$3,lease_token=NULL,lease_until=NULL,lease_heartbeat_at=NULL
        WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>now() RETURNING id`, [job.id, job.lease_token, JSON.stringify(observation)]);
      if (!changed.rowCount) throw new Error('lost_lease');
      await c.query('INSERT INTO observations(id,program_id,job_id,body) VALUES($1,$2,$3,$4)', [observationId, job.program_id, job.id, JSON.stringify(observation)]);
      await c.query('INSERT INTO tool_runs(id,job_id,tool,result) VALUES($1,$2,$3,$4)', [randomUUID(), job.id, job.action, JSON.stringify(observation)]);
      const value = observation && typeof observation === 'object' ? observation as Record<string, unknown> : {};
      if (typeof value.bodySha256 === 'string') {
        await c.query('INSERT INTO evidence(id,finding_id,sha256,body) VALUES($1,NULL,$2,$3)', [randomUUID(), value.bodySha256, JSON.stringify({ jobId: job.id, observationId, target: value.target ?? null, hashScope: value.hashScope ?? 'captured_bytes', bytes: value.bodyBytes ?? null, truncated: value.truncated ?? false })]);
      }
      const signals = Array.isArray(value.signals) ? value.signals.filter(signal => signal && typeof signal === 'object') : [];
      for (const signal of signals) {
        await c.query(`INSERT INTO findings(id,program_id,status,body) VALUES($1,$2,'OBSERVATION',$3)`, [randomUUID(), job.program_id, JSON.stringify({ jobId: job.id, observationId, signal })]);
      }
      await c.query(`INSERT INTO audit_events(id,event,program_id,job_id,asset_id,metadata) VALUES($1,'OBSERVATION_RECORDED',$2,$3,$4,$5)`, [randomUUID(), job.program_id, job.id, job.asset_id, JSON.stringify({ action: job.action, observationId })]);
      for (const action of followUpActions(job.action, observation)) await this.enqueueOn(c, job.program_id, job.asset_id, action, undefined, job.policy_revision);
      await c.query(`INSERT INTO workspace_outbox(program_id) VALUES($1) ON CONFLICT(program_id) DO UPDATE SET revision=workspace_outbox.revision+1`, [job.program_id]);
    });
    return observationId;
  }

  async recordAnalysis(job: Job, observationId: string, run: AnalysisRun) {
    await transaction(this.pool, async c => {
      const runId = randomUUID();
      await c.query(`INSERT INTO agent_runs(id,job_id,role,model,result,raw_text,status,sampling_options,model_digest,prompt_hash,schema_version)
        VALUES($1,$2,'analysis',$3,$4,$5,'accepted',$6,$7,$8,$9)`, [
        runId, job.id, run.model, JSON.stringify(run.analysis), run.rawText, JSON.stringify(run.samplingOptions), run.modelDigest, run.promptHash, run.schemaVersion,
      ]);
      await c.query(`INSERT INTO hypotheses(id,program_id,body,agent_run_id,observation_id,dedupe_key)
        VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, [
        randomUUID(), job.program_id, JSON.stringify(run.analysis), runId, observationId, `${job.id}:analysis:${run.schemaVersion}`,
      ]);
      await c.query(`INSERT INTO workspace_outbox(program_id) VALUES($1) ON CONFLICT(program_id) DO UPDATE SET revision=workspace_outbox.revision+1`, [job.program_id]);
      await c.query(`INSERT INTO audit_events(id,event,program_id,job_id,metadata) VALUES($1,'ANALYSIS_ACCEPTED',$2,$3,$4)`, [randomUUID(), job.program_id, job.id, JSON.stringify({ observationId, label: run.analysis.label })]);
    });
  }

  async recordAnalysisFailure(job: Job, failure: AnalysisFailure) {
    await this.pool.query(`INSERT INTO agent_runs(id,job_id,role,model,result,raw_text,status,sampling_options,model_digest,prompt_hash,schema_version)
      VALUES($1,$2,'analysis',$3,$4,$5,'parse_failed',$6,$7,$8,$9)`, [
      randomUUID(), job.id, failure.model, JSON.stringify({ error: failure.errorCode }), failure.rawText,
      JSON.stringify(failure.samplingOptions), failure.modelDigest, failure.promptHash, failure.schemaVersion,
    ]);
  }

  async defer(job: Job, seconds = 5) {
    await this.pool.query(`UPDATE research_jobs SET status='queued',attempts=GREATEST(attempts-1,0),available_at=now()+$3*interval '1 second',lease_token=NULL,lease_until=NULL,lease_heartbeat_at=NULL
      WHERE id=$1 AND lease_token=$2 AND status='running'`, [job.id, job.lease_token, seconds]);
  }

  async fail(job: Job) {
    await this.pool.query(`UPDATE research_jobs SET status=CASE WHEN attempts>=max_attempts THEN 'failed' ELSE 'queued' END,
      available_at=now()+attempts*interval '5 seconds',lease_token=NULL,lease_until=NULL,lease_heartbeat_at=NULL
      WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>now()`, [job.id, job.lease_token]);
  }
}

export async function acquireRate(pool: pg.Pool, program: string, programRps: number, globalRps: number): Promise<boolean> {
  return transaction(pool, async c => {
    await c.query('SELECT pg_advisory_xact_lock(784292)');
    const keys = ['global', `program:${program}`];
    const blocked = await c.query('SELECT 1 FROM rate_limits WHERE key=ANY($1) AND next_at>now()', [keys]);
    if (blocked.rowCount) return false;
    for (const [key, rps] of [[keys[0], globalRps], [keys[1], programRps]] as const) {
      if (!Number.isFinite(rps) || rps <= 0) throw new Error('invalid_rate');
      await c.query(`INSERT INTO rate_limits(key,next_at) VALUES($1,now()+$2*interval '1 second')
        ON CONFLICT(key) DO UPDATE SET next_at=excluded.next_at`, [key, 1 / rps]);
    }
    return true;
  });
}
