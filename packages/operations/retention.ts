import type pg from 'pg';
import { transaction } from '../research-state/db.js';

export function retentionDays(value: string | number): number {
  const days = Number(value);
  if (!Number.isInteger(days) || days < 1 || days > 36500) throw new Error('invalid_retention_days');
  return days;
}

const eligible = `o.created_at < now()-$1*interval '1 day'
  AND j.status='completed'
  AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.program_id=o.program_id
    AND (f.body->>'jobId'=o.job_id::text OR f.body->>'observationId'=o.id::text)
    AND f.status IN ('VERIFICATION','VERIFIED','HUMAN_REVIEW','SUBMITTED'))
  AND NOT EXISTS (SELECT 1 FROM resource_cleanup r WHERE r.program_id=o.program_id)`;

export async function sweepRetention(pool: pg.Pool, options: { observationDays: number; deadLetterDays: number; apply: boolean; batchSize?: number }) {
  const observationDays = retentionDays(options.observationDays), deadLetterDays = retentionDays(options.deadLetterDays);
  const batchSize = options.batchSize ?? 100;
  if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > 1000) throw new Error('invalid_retention_batch');
  if (!options.apply) {
    const count = await pool.query(`SELECT count(*)::int AS n FROM observations o JOIN research_jobs j ON j.id=o.job_id WHERE ${eligible}`, [observationDays]);
    const dead = await pool.query("SELECT count(*)::int AS n FROM dead_letter WHERE created_at<now()-$1*interval '1 day'", [deadLetterDays]);
    return { observations: count.rows[0].n as number, deadLetters: dead.rows[0].n as number, programs: [] as string[] };
  }
  const candidates = await pool.query(`SELECT o.id,o.program_id FROM observations o JOIN research_jobs j ON j.id=o.job_id
    WHERE ${eligible} ORDER BY o.created_at,o.id LIMIT $2`, [observationDays, batchSize]);
  let observations = 0;
  const programs = new Set<string>();
  for (const candidate of candidates.rows) {
    const removed = await transaction(pool, async client => {
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`program:${candidate.program_id}`]);
      const selected = await client.query(`SELECT o.id,o.job_id FROM observations o JOIN research_jobs j ON j.id=o.job_id
        WHERE ${eligible} AND o.id=$2 FOR UPDATE OF o,j`, [observationDays, candidate.id]);
      const row = selected.rows[0]; if (!row) return false;
      await client.query(`DELETE FROM evidence WHERE finding_id IN
        (SELECT id FROM findings WHERE program_id=$1 AND (body->>'jobId'=$2 OR body->>'observationId'=$3))
        OR body->>'jobId'=$2 OR body->>'observationId'=$3`, [candidate.program_id, row.job_id, row.id]);
      await client.query(`DELETE FROM findings WHERE program_id=$1 AND (body->>'jobId'=$2 OR body->>'observationId'=$3)`, [candidate.program_id, row.job_id, row.id]);
      await client.query(`DELETE FROM hypotheses WHERE observation_id=$1 OR agent_run_id IN (SELECT id FROM agent_runs WHERE job_id=$2)`, [row.id, row.job_id]);
      await client.query('DELETE FROM agent_runs WHERE job_id=$1', [row.job_id]);
      await client.query('DELETE FROM tool_runs WHERE job_id=$1', [row.job_id]);
      await client.query('UPDATE research_jobs SET result=NULL WHERE id=$1', [row.job_id]);
      await client.query('DELETE FROM observations WHERE id=$1', [row.id]);
      await client.query(`INSERT INTO workspace_outbox(program_id) VALUES($1) ON CONFLICT(program_id) DO UPDATE SET revision=workspace_outbox.revision+1`, [candidate.program_id]);
      return true;
    });
    if (removed) { observations++; programs.add(candidate.program_id); }
  }
  const dead = await pool.query(`DELETE FROM dead_letter WHERE id IN
    (SELECT id FROM dead_letter WHERE created_at<now()-$1*interval '1 day' ORDER BY created_at,id LIMIT $2)`, [deadLetterDays, batchSize]);
  return { observations, deadLetters: dead.rowCount ?? 0, programs: [...programs] };
}
