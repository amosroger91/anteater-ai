import { execFile } from 'node:child_process';
import { runAggressive } from '../packages/tool-adapters/aggressive.js';
import { loadOperatorConfig as loadConfig } from '../packages/setup/operator.js';
import { connect } from '../packages/research-state/db.js';
import { assertExecutionAllowed } from '../packages/research-state/control.js';

// Snapshot-gated owned-lab runner. A registered program binds the process to fleet revocation.
const config = loadConfig();
const args = process.argv.slice(2);
const host = (args.find(arg => !arg.startsWith('--')) ?? '').trim().toLowerCase();
const requestedProgram = args.find(arg => arg.startsWith('--program='))?.slice('--program='.length);
if (!host) {
  console.error('usage: tsx scripts/aggressive.ts <host> [--program=<registered-program>] --snapshot-confirmed --n8n-attested [--allow-destructive]');
  process.exit(1);
}
const pool = connect(config.DATABASE_URL);
const controller = new AbortController();
const shutdown = () => controller.abort(new Error('cancelled'));
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
let poll: ReturnType<typeof setInterval> | undefined;
let pending: Promise<void> | undefined;
try {
  await assertExecutionAllowed(pool, undefined, undefined, config.GLOBAL_KILL_SWITCH);
  const candidates = await pool.query(`SELECT DISTINCT program_id FROM assets
    WHERE active=true AND (url=$1 OR url=$1 || '/') AND ($2::text IS NULL OR program_id=$2)`, [`https://${host}`, requestedProgram ?? null]);
  if (candidates.rows.length !== 1) throw new Error(candidates.rows.length ? 'aggressive_program_ambiguous' : 'aggressive_registered_program_required');
  const programId = String(candidates.rows[0].program_id);
  let epoch: string | undefined;
  const check = async () => {
    controller.signal.throwIfAborted();
    const control = await assertExecutionAllowed(pool, programId, epoch, loadConfig().GLOBAL_KILL_SWITCH);
    epoch ??= control.epoch;
  };
  await check();
  poll = setInterval(() => {
    if (pending) return;
    pending = check().catch(error => { controller.abort(error); }).finally(() => { pending = undefined; });
  }, 1000);
  const result = await runAggressive({
    host, labHosts: config.LAB_TARGET_HOSTS.split(',').map(item => item.trim()).filter(Boolean),
    snapshotConfirmed: args.includes('--snapshot-confirmed'), n8nAttested: args.includes('--n8n-attested'),
    allowDestructive: args.includes('--allow-destructive'), beforeExecution: check, signal: controller.signal,
    exec: (bin, argv, signal) => new Promise((resolve, reject) => {
      execFile(bin, argv, { signal, timeout: 120_000, windowsHide: true, maxBuffer: 4_194_304 }, (error, stdout) => {
        if (error) reject(error);
        else resolve({ stdout: String(stdout) });
      });
    }),
  });
  if (result.refused) {
    console.error(`aggressive_refused ${result.refused}`);
    process.exitCode = 2;
  } else {
    for (const event of result.audit) console.error(`audit ${event.event} host=${event.host} recovery=${event.recovery}`);
    console.log(`aggressive_findings ${result.findings.length}`);
  }
} catch (caught) {
  const error = controller.signal.aborted ? controller.signal.reason : caught;
  console.error(`aggressive_refused ${error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : 'execution_control_failed'}`);
  process.exitCode = 2;
} finally {
  clearInterval(poll);
  await pending;
  process.removeListener('SIGINT', shutdown);
  process.removeListener('SIGTERM', shutdown);
  await pool.end();
}
