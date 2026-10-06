import { loadConfig } from '../packages/shared/config.js';
import { connect } from '../packages/research-state/db.js';
import { createDashboardServer } from '../apps/dashboard/server.js';

// Live-progress dashboard (read-only) over main's real tables. Loopback only; starts no campaign and
// contacts no target. usage: npm run dashboard  ->  http://127.0.0.1:4318/
const pool = connect(loadConfig().DATABASE_URL);
const server = createDashboardServer(pool);
const port = Number(process.env.DASHBOARD_PORT) || 4318;
server.listen(port, '127.0.0.1', () => console.log(`Dashboard (read-only): http://127.0.0.1:${port}/`));
const stop = () => { server.close(); void pool.end().finally(() => process.exit(0)); };
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
