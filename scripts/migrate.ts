import { loadConfig } from '../packages/shared/config.js';
import { connect,migrate } from '../packages/research-state/db.js';
const pool=connect(loadConfig().DATABASE_URL);
try { await migrate(pool); console.log('Schema ready'); }
finally { await pool.end(); }
