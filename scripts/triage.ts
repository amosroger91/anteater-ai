import { loadConfig } from '../packages/shared/config.js';
import { connect } from '../packages/research-state/db.js';

// Lists HUMAN_REVIEW and VERIFIED findings. It does not submit them.
const pool = connect(loadConfig().DATABASE_URL);
try {
  const rows = await pool.query(`SELECT id, program_id, status, finding_type, location, rank FROM triage_queue ORDER BY rank DESC, id`);
  if (!rows.rowCount) console.log('triage_empty');
  for (const row of rows.rows) console.log(`${row.id} ${row.program_id} ${row.status} ${row.finding_type} ${row.location} rank=${row.rank}`);
} finally { await pool.end(); }
