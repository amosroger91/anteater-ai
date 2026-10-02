import { loadConfig } from '../packages/shared/config.js';
import { connect } from '../packages/research-state/db.js';
import { retentionPlan, type RetainedRecord } from '../packages/operations/index.js';

// Apply the deterministic retention policy (PRODUCTION_ROADMAP.md §7): delete observations/dead-letter
// rows older than their class window. Dry-run by default; --apply performs deletions.
// usage: tsx scripts/retention-sweep.ts [--apply] [--observations-days=90] [--dead-letter-days=30]

const args = process.argv.slice(2);
const apply = args.includes('--apply');
const num = (name: string, fallback: number) => {
  const found = args.find(a => a.startsWith(`--${name}=`));
  return found ? Number(found.split('=')[1]) || fallback : fallback;
};
const retentionDays = { observation: num('observations-days', 90), 'dead-letter': num('dead-letter-days', 30) };

const pool = connect(loadConfig().DATABASE_URL);
try {
  const records: RetainedRecord[] = [];
  for (const [table, dataClass] of [['observations', 'observation'], ['dead_letter', 'dead-letter']] as const) {
    const rows = await pool.query(`SELECT id, created_at FROM ${table}`);
    for (const r of rows.rows) records.push({ id: `${table}:${r.id}`, dataClass, createdAt: new Date(r.created_at).toISOString() });
  }
  const plan = retentionPlan(records, retentionDays);
  console.log(`retention: ${plan.remove.length} to remove, ${plan.keep.length} kept, ${plan.unclassified.length} unclassified`);
  if (!apply) { console.log('dry run; pass --apply to delete'); }
  else {
    for (const id of plan.remove) {
      const [table, rowId] = id.split(':');
      if (table && rowId) await pool.query(`DELETE FROM ${table} WHERE id=$1`, [rowId]);
    }
    console.log(`deleted ${plan.remove.length} rows`);
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : 'sweep_failed');
  process.exitCode = 1;
} finally { await pool.end(); }
