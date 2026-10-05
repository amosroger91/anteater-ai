import { loadConfig } from '../packages/shared/config.js';
import { connect } from '../packages/research-state/db.js';
import { collectFleetSnapshot } from '../packages/metrics/collect.js';
import { computeAlerts } from '../packages/metrics/index.js';

const pool = connect(loadConfig().DATABASE_URL);
try {
  const snapshot = await collectFleetSnapshot(pool);
  console.log(JSON.stringify({ snapshot, alerts: computeAlerts(snapshot) }));
} finally { await pool.end(); }
