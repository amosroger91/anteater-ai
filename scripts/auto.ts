import { spawn, type ChildProcess } from 'node:child_process';
import { loadOperatorEnvironment } from '../packages/setup/operator.js';

// "Press go." One command that runs the whole autonomous chain over the programs you have loaded
// (handle-driven, authorized-only): preflight -> intake -> worker + monitor, looping until Ctrl-C.
// Findings land in a ranked, de-duped, submit-ready queue (`npm run triage`); you submit the good ones.
//
//   npm run auto -- --arm            continuous, live passive testing enabled
//   npm run auto -- --arm --once     one pass, then show the queue and exit
//   npm run auto                     dry: runs preflight only, tells you what's missing
//
// --arm turns the engine on for this run (kill switch off, passive HTTP on). Without it, nothing is
// contacted. It only ever engages programs you listed that permit automation; it never auto-discovers
// programs, and it never submits — that stays your call.

const args = process.argv.slice(2);
const arm = args.includes('--arm');
const once = args.includes('--once');
const research = args.includes('--research');

const env: NodeJS.ProcessEnv = { ...loadOperatorEnvironment() };
if (arm) {
  env.GLOBAL_KILL_SWITCH = 'false';
  env.ENABLE_PASSIVE_HTTP = 'true';
  if (research) env.ENABLE_APPLICATION_RESEARCH = 'true';
}

const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const children: ChildProcess[] = [];

function run(script: string, extra: string[] = []): Promise<number> {
  const argv = extra.length ? ['run', script, '--', ...extra] : ['run', script];
  return new Promise(resolve => {
    const child = spawn(npm, argv, { env, stdio: 'inherit', shell: process.platform === 'win32' });
    children.push(child);
    child.on('exit', code => resolve(code ?? 1));
    child.on('error', () => resolve(1));
  });
}

function startBackground(script: string): ChildProcess {
  const child = spawn(npm, ['run', script], { env, stdio: 'inherit', shell: process.platform === 'win32' });
  children.push(child);
  return child;
}

let stopping = false;
function shutdown(): void {
  if (stopping) return;
  stopping = true;
  for (const child of children) { try { child.kill(); } catch { /* already gone */ } }
}
process.on('SIGINT', () => { shutdown(); process.exit(0); });
process.on('SIGTERM', () => { shutdown(); process.exit(0); });

console.log(arm
  ? 'auto: ARMED — live passive testing is on for this run.'
  : 'auto: dry run (not armed). Pass --arm to turn the engine on.');

// 1) Readiness gate. It prints exactly what is missing (DB, flags, credentials, handles) and stops.
const preflight = await run('preflight');
if (preflight !== 0) {
  console.error('auto: not ready — fix the failing preflight items above, then re-run. (Nothing was contacted.)');
  process.exit(preflight);
}
if (!arm) {
  console.log('auto: preflight passed. Re-run with --arm to actually run the campaign.');
  process.exit(0);
}

// 2) Pull scope for the authorized programs you listed and queue their jobs.
const intake = await run('intake:h1');
if (intake !== 0) { console.error('auto: intake failed.'); process.exit(intake); }

// 3) Run the engine.
if (once) {
  await run('worker', ['--once']);
  console.log('\nauto: one pass complete. Ranked submit-ready queue:\n');
  await run('triage');
  process.exit(0);
}

console.log('auto: starting worker + monitor + dashboard. Ctrl-C to stop.');
console.log('auto: live progress at http://127.0.0.1:4318/  ·  ranked queue: `npm run triage`');
startBackground('worker');
startBackground('monitor');
startBackground('dashboard');
// Keep the orchestrator alive until a child dies or the operator stops it.
await new Promise<void>(resolve => {
  for (const child of children) child.on('exit', () => { if (!stopping) { shutdown(); resolve(); } });
});
process.exit(0);
