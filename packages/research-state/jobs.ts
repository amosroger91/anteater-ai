import type pg from 'pg';
import { randomUUID } from 'node:crypto';
import { transaction } from './db.js';
export interface Job { id: string; program_id: string; asset_id: string; action: string; lease_token: string; attempts: number }
export class Jobs {
  constructor(private pool: pg.Pool, private concurrency = 1, private leaseSeconds = 30) {}
  async enqueue(program: string, asset: string, action: string, key: string) {
    await this.pool.query(`INSERT INTO research_jobs(id,program_id,asset_id,action,dedupe_key)
      SELECT $1,$2,$3,$4,$5 WHERE EXISTS(SELECT 1 FROM assets WHERE id=$3 AND program_id=$2)
      ON CONFLICT(dedupe_key) DO NOTHING`, [randomUUID(), program, asset, action, key]);
  }
  async claim(): Promise<Job | undefined> {
    return transaction(this.pool, async c => {
      // Serializes the global concurrency decision across processes; row leases survive restarts.
      await c.query('SELECT pg_advisory_xact_lock(784291)');
      await c.query(`UPDATE research_jobs SET status='failed',lease_token=NULL,lease_until=NULL
        WHERE status='running' AND lease_until <= now() AND attempts >= max_attempts`);
      const count = await c.query(`SELECT count(*)::int AS n FROM research_jobs WHERE status='running' AND lease_until > now()`);
      if (count.rows[0].n >= this.concurrency) return undefined;
      const result = await c.query(`UPDATE research_jobs SET status='running',attempts=attempts+1,
        lease_token=$1,lease_until=now()+$2*interval '1 second'
        WHERE id=(SELECT id FROM research_jobs WHERE attempts<max_attempts AND
          ((status='queued' AND available_at<=now()) OR (status='running' AND lease_until<=now()))
          ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *`, [randomUUID(), this.leaseSeconds]);
      return result.rows[0] as Job | undefined;
    });
  }
  async complete(job: Job, body: unknown) {
    await transaction(this.pool, async c => {
      const changed = await c.query(`UPDATE research_jobs SET status='completed',result=$3,lease_token=NULL,lease_until=NULL
        WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>now() RETURNING id`, [job.id,job.lease_token,JSON.stringify(body)]);
      if (!changed.rowCount) throw new Error('lost_lease');
      await c.query('INSERT INTO observations(id,program_id,job_id,body) VALUES($1,$2,$3,$4) ON CONFLICT(job_id) DO NOTHING', [randomUUID(),job.program_id,job.id,JSON.stringify(body)]);
      await c.query('INSERT INTO tool_runs(id,job_id,tool,result) VALUES($1,$2,$3,$4)', [randomUUID(),job.id,job.action,JSON.stringify(body)]);
      await c.query(`INSERT INTO workspace_outbox(program_id) VALUES($1) ON CONFLICT(program_id) DO UPDATE SET revision=workspace_outbox.revision+1`, [job.program_id]);
    });
  }
  async fail(job: Job) {
    await this.pool.query(`UPDATE research_jobs SET status=CASE WHEN attempts>=max_attempts THEN 'failed' ELSE 'queued' END,
      available_at=now()+attempts*interval '5 seconds',lease_token=NULL,lease_until=NULL
      WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>now()`, [job.id,job.lease_token]);
  }
}
export async function acquireRate(pool: pg.Pool, program: string, programRps: number, globalRps: number): Promise<boolean> {
  return transaction(pool, async c => {
    // Global lock provides all-or-nothing reservations and deterministic lock ordering.
    await c.query('SELECT pg_advisory_xact_lock(784292)');
    const keys = ['global', `program:${program}`];
    const blocked = await c.query('SELECT 1 FROM rate_limits WHERE key=ANY($1) AND next_at>now()', [keys]);
    if (blocked.rowCount) return false;
    for (const [key, rps] of [[keys[0],globalRps],[keys[1],programRps]] as const) {
      if (!Number.isFinite(rps) || rps <= 0) throw new Error('invalid_rate');
      await c.query(`INSERT INTO rate_limits(key,next_at) VALUES($1,now()+$2*interval '1 second')
        ON CONFLICT(key) DO UPDATE SET next_at=excluded.next_at`, [key,1/rps]);
    }
    return true;
  });
}
