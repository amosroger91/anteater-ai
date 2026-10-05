import { execFile } from 'node:child_process';
import type { ProgramBudget } from '../packages/budget/index.js';
import { CertTransparencyDiscovery } from '../packages/discovery/adapters.js';
import { runMonitorCycle } from '../packages/discovery/monitor.js';
import { PassiveDnsDiscovery, SubfinderDiscovery, type ExecLike } from '../packages/discovery/more-adapters.js';
import { connect } from '../packages/research-state/db.js';
import { loadOperatorConfig as loadConfig } from '../packages/setup/operator.js';

// Scheduled discovery (BOUNTY_EARNINGS_PLAN.md Phase 2.3). The process kill
// switch refuses the run before any source is called. Certificate transparency
// uses only https://crt.sh. Subfinder runs only when SUBFINDER_BIN is an
// absolute path. Passive DNS has no documented unauthenticated host here, so
// the default resolver returns no names.

const initial = loadConfig();
if (initial.GLOBAL_KILL_SWITCH) {
  console.error('monitor_refused kill_switch');
  process.exit(2);
}

const execPinned: ExecLike = (bin, args) => new Promise((resolve, reject) => {
  execFile(bin, args, { timeout: 15_000, windowsHide: true, maxBuffer: 1_048_576 }, (error, stdout) => {
    if (error) reject(error);
    else resolve({ stdout: String(stdout) });
  });
});

const sources = {
  certTransparency: new CertTransparencyDiscovery(),
  passiveDns: new PassiveDnsDiscovery(async () => []),
  subfinder: new SubfinderDiscovery(execPinned),
};

const interval = Number(process.env.MONITOR_INTERVAL_MS ?? 60_000);
const waitMs = Number.isFinite(interval) && interval >= 1000 && interval <= 3_600_000 ? interval : 60_000;
const once = process.argv.includes('--once');
let stopped = false;
process.on('SIGINT', () => { stopped = true; });
process.on('SIGTERM', () => { stopped = true; });

const pool = connect(initial.DATABASE_URL);
const budgets = new Map<string, ProgramBudget>();
try {
  do {
    if (loadConfig().GLOBAL_KILL_SWITCH) {
      console.error('monitor_stopped kill_switch');
      break;
    }
    const reports = await runMonitorCycle({ pool, sources, budgets });
    const enqueued = reports.reduce((sum, report) => sum + report.enqueued.length, 0);
    console.log(`monitor_cycle programs=${reports.length} enqueued=${enqueued}`);
    if (once || stopped) break;
    const started = Date.now();
    while (!stopped && Date.now() - started < waitMs) {
      await new Promise(resolve => setTimeout(resolve, Math.min(250, waitMs)));
    }
  } while (!stopped);
} finally {
  await pool.end();
}
