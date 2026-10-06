import type pg from 'pg';

type Database = pg.Pool | pg.PoolClient;
export interface ExecutionControl { epoch: string; globalKill: boolean; revoked: boolean }

/** Missing or unreadable controls never authorize execution. Keep PostgreSQL bigint epochs exact. */
export async function readExecutionControl(db: Database, programId?: string): Promise<ExecutionControl> {
  const result = await db.query(`SELECT global_kill, epoch::text AS epoch,
    EXISTS(SELECT 1 FROM revoked_programs WHERE program_id=$1) AS revoked
    FROM runtime_control WHERE id=1`, [programId ?? null]);
  const row = result.rows[0];
  if (!row || typeof row.global_kill !== 'boolean' || typeof row.revoked !== 'boolean' || !/^\d+$/.test(String(row.epoch))) {
    throw new Error('runtime_control_unavailable');
  }
  return { epoch: String(row.epoch), globalKill: row.global_kill, revoked: row.revoked };
}

export async function assertExecutionAllowed(db: Database, programId?: string, leaseEpoch?: string, processKilled = false): Promise<ExecutionControl> {
  if (processKilled) throw new Error('kill_switch');
  const control = await readExecutionControl(db, programId);
  if (control.globalKill) throw new Error('kill_switch');
  if (control.revoked) throw new Error('program_revoked');
  if (leaseEpoch !== undefined && (!/^\d+$/.test(leaseEpoch) || leaseEpoch !== control.epoch)) throw new Error('lease_superseded_by_revocation');
  return control;
}
