import type pg from 'pg';
import type { FleetSnapshot } from './index.js';

export async function collectFleetSnapshot(pool: pg.Pool): Promise<FleetSnapshot> {
  const queue = await pool.query(`SELECT COALESCE(EXTRACT(EPOCH FROM (clock_timestamp() - MIN(created_at))), 0) AS age FROM research_jobs WHERE status='queued'`);
  const dead = await pool.query(`SELECT count(*)::int AS n FROM dead_letter`);
  const failed = await pool.query(`SELECT count(*)::int AS n FROM research_jobs WHERE status='failed'`);
  const mailbox = await pool.query(`SELECT count(*)::int AS n FROM dead_letter WHERE error_code='mailbox'`);
  const rate = await pool.query(`SELECT count(*)::int AS n FROM rate_limits WHERE next_at > clock_timestamp()`);
  const gaps = await pool.query(`SELECT count(*)::int AS n FROM programs p WHERE NOT EXISTS (SELECT 1 FROM research_jobs j WHERE j.program_id=p.id AND j.status='completed')`);
  return {
    queueAgeSeconds: Number(queue.rows[0].age),
    coverageGaps: Number(gaps.rows[0].n),
    rateLimitHits: Number(rate.rows[0].n),
    toolFailures: Number(failed.rows[0].n),
    mailboxFailures: Number(mailbox.rows[0].n),
    deadLettered: Number(dead.rows[0].n),
  };
}

export async function paidTotal(pool: pg.Pool): Promise<number> {
  const row = await pool.query(`SELECT COALESCE(SUM(amount), 0)::float8 AS paid FROM submissions WHERE status='paid'`);
  return Number(row.rows[0].paid);
}
