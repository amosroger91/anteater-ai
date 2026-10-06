import { execFile } from 'node:child_process';
import type { ProgramBudget } from '../packages/budget/index.js';
import { CertTransparencyDiscovery } from '../packages/discovery/adapters.js';
import { runMonitorCycle } from '../packages/discovery/monitor.js';
import { PinnedHostListDiscovery, SubfinderDiscovery, type ExecLike } from '../packages/discovery/more-adapters.js';
import type { DiscoveryAdapter } from '../packages/discovery/index.js';
import { connect } from '../packages/research-state/db.js';
import { loadOperatorConfig as loadConfig } from '../packages/setup/operator.js';

// Scheduled discovery (BOUNTY_EARNINGS_PLAN.md Phase 2.3). The process kill
// switch refuses the run before any source is called. The loop repeats until
// SIGINT, SIGTERM, or --once. Subfinder and passive DNS run only when their
// *_BIN values are absolute paths. Certificate transparency uses CT_BIN when
// that path is set, and otherwise only https://crt.sh.

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

function certificateSource(): DiscoveryAdapter {
  const bin = process.env.CT_BIN?.trim();
  if (!bin) return new CertTransparencyDiscovery();
  return new PinnedHostListDiscovery('cert-transparency', execPinned, 'CT_BIN', process.env, 0.7);
}

const sources = {
  certTransparency: certificateSource(),
  passiveDns: new PinnedHostListDiscovery('passive-dns', execPinned, 'PASSIVE_DNS_BIN', process.env, 0.6),
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
    if (!reports.length) console.log('monitor_cycle programs=0 new_exposure=-');
    for (const report of reports) {
      console.log(`monitor_cycle program=${report.programId} skipped=${report.skipped ?? '-'} new_exposure=${report.newExposure.join(',') || '-'} enqueued=${report.enqueued.join(',') || '-'}`);
    }
    if (once || stopped) break;
    const started = Date.now();
    while (!stopped && Date.now() - started < waitMs) {
      await new Promise(resolve => setTimeout(resolve, Math.min(250, waitMs)));
    }
  } while (!stopped);
} finally {
  await pool.end();
}
