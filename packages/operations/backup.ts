import type pg from 'pg';

export interface BackupBundle { submissions: unknown[]; deadLetter: unknown[] }

export async function exportBackup(pool: pg.Pool): Promise<BackupBundle> {
  const submissions = await pool.query('SELECT id, program_id, finding_id, status, amount, currency, recorded_at FROM submissions ORDER BY recorded_at, id');
  const deadLetter = await pool.query('SELECT id, job_id, reason, error_code, created_at FROM dead_letter ORDER BY created_at, id');
  return { submissions: submissions.rows, deadLetter: deadLetter.rows };
}

export async function restoreBackup(pool: pg.Pool, bundle: BackupBundle): Promise<void> {
  await pool.query('DELETE FROM submissions');
  await pool.query('DELETE FROM dead_letter');
  for (const row of bundle.submissions as Array<Record<string, unknown>>) {
    await pool.query(`INSERT INTO submissions(id, program_id, finding_id, status, amount, currency, recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
      [row.id, row.program_id, row.finding_id, row.status, row.amount, row.currency, row.recorded_at]);
  }
  for (const row of bundle.deadLetter as Array<Record<string, unknown>>) {
    await pool.query(`INSERT INTO dead_letter(id, job_id, reason, error_code, created_at) VALUES($1,$2,$3,$4,$5)`,
      [row.id, row.job_id, row.reason, row.error_code, row.created_at]);
  }
}
