import { readFile } from 'node:fs/promises';
import { loadConfig } from '../packages/shared/config.js';
import { loadOperatorEnvironment } from '../packages/setup/operator.js';
import { connect, migrate } from '../packages/research-state/db.js';
import { saveProgram } from '../packages/research-state/workspace.js';
import { Jobs } from '../packages/research-state/jobs.js';
import { autoIntakeHackerOne } from '../packages/program-intake/auto.js';
import { log } from '../packages/shared/log.js';

// Autonomous HackerOne intake for programs YOU have enrolled in (BOUNTY_EARNINGS_PLAN.md Phase 1).
// Reads handles you chose (never discovers them), pulls each program's published scope, skips any that
// is not automation-permitted, and saves the permitted programs + enqueues passive jobs. The worker
// then tests in scope. Picks up the wizard profile via loadOperatorEnvironment.
//
// Required (env or saved setup profile): HACKERONE_API_USERNAME, HACKERONE_API_TOKEN (hacker API
// credentials) and ANTEATER_APPROVER (the named person recorded as the human who approved intake).
// Handles: a file (one handle per line, # comments) via --handles=<path> (default programs/handles.txt),
//          or HACKERONE_HANDLES as a comma-separated list.
// usage: npm run intake:h1

const env = loadOperatorEnvironment();
const user = env.HACKERONE_API_USERNAME;
const token = env.HACKERONE_API_TOKEN;
if (!user || !token) {
  console.error('set HACKERONE_API_USERNAME and HACKERONE_API_TOKEN (HackerOne hacker API credentials), or save them in setup');
  process.exit(1);
}
const approver = (env.ANTEATER_APPROVER ?? '').trim();
if (!approver) {
  console.error('set ANTEATER_APPROVER to the name of the person approving this intake (or save an approver in setup); intake will not self-approve');
  process.exit(1);
}

async function loadHandles(): Promise<string[]> {
  const fromEnv = env.HACKERONE_HANDLES;
  if (fromEnv) return fromEnv.split(',').map(h => h.trim()).filter(Boolean);
  const path = process.argv.find(a => a.startsWith('--handles='))?.slice(10) ?? 'programs/handles.txt';
  try {
    const text = await readFile(path, 'utf8');
    return text.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#'));
  } catch { return []; }
}

const authorization = 'Basic ' + Buffer.from(`${user}:${token}`).toString('base64');
const config = loadConfig(env);
const pool = connect(config.DATABASE_URL);
try {
  const handles = await loadHandles();
  if (!handles.length) { console.error('no handles: list programs you are enrolled in (programs/handles.txt or HACKERONE_HANDLES)'); process.exit(1); }
  await migrate(pool);
  const { compiled, skipped } = await autoIntakeHackerOne({ authorization, handles, approver });
  const jobs = new Jobs(pool, config.MAX_CONCURRENT_JOBS, config.JOB_LEASE_SECONDS);
  let programs = 0, assets = 0, enqueued = 0;
  for (const intake of compiled) {
    for (const program of intake.programs) {
      await saveProgram(pool, program);
      programs += 1;
      for (const asset of program.assets) {
        assets += 1;
        await jobs.enqueue(program.id, asset.id, 'inspect_http_target');
        enqueued += 1;
      }
      log('PROGRAM_INTAKE', { program: program.id, result: intake.automation, asset: String(program.assets.length) });
    }
  }
  console.log(`intake: ${programs} program(s), ${assets} in-scope asset(s), ${enqueued} job(s) queued`);
  for (const s of skipped) console.log(`  skipped ${s.handle}: ${s.reason}`);
  if (!config.ENABLE_PASSIVE_HTTP) console.log('note: ENABLE_PASSIVE_HTTP is off — jobs are queued but the worker will not contact targets until it is enabled.');
} catch (error) {
  console.error(error instanceof Error ? error.message : 'intake_failed');
  process.exitCode = 1;
} finally {
  await pool.end();
}
