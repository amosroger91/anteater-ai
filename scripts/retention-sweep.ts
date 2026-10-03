import { loadConfig } from '../packages/shared/config.js';
import { connect } from '../packages/research-state/db.js';
import { exportWorkspace } from '../packages/research-state/workspace.js';
import { retentionDays, sweepRetention } from '../packages/operations/retention.js';

const args = process.argv.slice(2);
const days = (name: string, fallback: number) => retentionDays(args.find(arg => arg.startsWith(`--${name}=`))?.slice(name.length + 3) ?? fallback);
const config = loadConfig();
const pool = connect(config.DATABASE_URL);
try {
  const result = await sweepRetention(pool, { observationDays: days('observations-days', 90), deadLetterDays: days('dead-letter-days', 30), apply: args.includes('--apply') });
  if (args.includes('--apply')) {
    const pending = await pool.query('SELECT program_id FROM workspace_outbox ORDER BY program_id');
    for (const row of pending.rows) await exportWorkspace(pool, config.PROGRAMS_DIR, row.program_id);
    console.log(`Removed ${result.observations} observations and associated payloads, ${result.deadLetters} dead letters; exports reconciled. Batch limit: 100.`);
  } else console.log(`Dry run: ${result.observations} eligible observations, ${result.deadLetters} dead letters. Evidence under review and programs with pending cleanup are held. Pass --apply to process one bounded batch.`);
} catch (error) {
  console.error(error instanceof Error ? error.message : 'sweep_failed');
  process.exitCode = 1;
} finally { await pool.end(); }
