import { connect } from '../packages/research-state/db.js';
import { loadConfig } from '../packages/shared/config.js';

const pool = connect(loadConfig().DATABASE_URL);
try {
  const rows = await pool.query(`SELECT id,program_id,created_at,intent FROM resource_cleanup ORDER BY created_at,id LIMIT 100`);
  console.log(JSON.stringify(rows.rows, null, 2));
  console.log('Pending obligations require the original account and currently authorized cleanup rule. A newly authorized assessment reconciles pending records before creating resources. No deletion is performed by this command.');
} finally { await pool.end(); }
