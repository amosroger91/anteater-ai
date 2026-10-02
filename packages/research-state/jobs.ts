import type pg from 'pg';
import { randomUUID } from 'node:crypto';
import type { AnalysisFailure, AnalysisRun } from '../agent-runtime/index.js';
import { transaction } from './db.js';

export type Action = 'inspect_http_target';
export interface Job {
  id: string; program_id: string; asset_id: string; action: Action; policy_revision: string;
  lease_token: string; attempts: number;
}

export class Jobs {
  constructor(private pool: pg.Pool, private concurrency = 1, private leaseSeconds = 30) {}

  async enqueue(program: string, asset: string, action: Action, key: string) {
    await this.pool.query(`
      INSERT INTO research_jobs(id,program_id,asset_id,action,dedupe_key,policy_revision)
      SELECT $1,$2,$3,$4,$5,s.policy->>'revision'
      FROM assets a JOIN scope_rules s ON s.program_id=a.program_id
      WHERE a.id=$3 AND a.program_id=$2 AND a.active=true
        AND s.policy->'allowedActions' ? $4
      ON CONFLICT(dedupe_key) DO NOTHING`, [randomUUID(), program, asset, action, key]);
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
          ORDER BY candidate.created_at FOR UPDATE SKIP LOCKED LIMIT 1)
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
      const changed = await c.query(`UPDATE research_jobs SET status='completed',result=$3,lease_token=NULL,lease_until=NULL,lease_heartbeat_at=NULL
        WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>now() RETURNING id`, [job.id, job.lease_token, JSON.stringify(observation)]);
      if (!changed.rowCount) throw new Error('lost_lease');
      await c.query('INSERT INTO observations(id,program_id,job_id,body) VALUES($1,$2,$3,$4)', [observationId, job.program_id, job.id, JSON.stringify(observation)]);
      await c.query('INSERT INTO tool_runs(id,job_id,tool,result) VALUES($1,$2,$3,$4)', [randomUUID(), job.id, job.action, JSON.stringify(observation)]);
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
