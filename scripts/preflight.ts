import { readFile } from 'node:fs/promises';
import { evaluatePreflight, parseHandles } from '../packages/preflight/index.js';
import { connect, migrationFiles } from '../packages/research-state/db.js';
import { PolicySchema } from '../packages/scope-engine/index.js';
import { loadConfig } from '../packages/shared/config.js';

// Read-only gate for the first live run. It does not call HackerOne and it does not scan.
const handlePath = process.argv.find(arg => arg.startsWith('--handles='))?.slice('--handles='.length) ?? 'programs/handles.txt';

let config: ReturnType<typeof loadConfig>;
try {
  config = loadConfig();
} catch (error) {
  console.error(`fail config ${error instanceof Error ? error.message : 'invalid'}`);
  process.exit(1);
}

let handleText = '';
try { handleText = await readFile(handlePath, 'utf8'); } catch { handleText = ''; }

let dbReachable = false;
let pendingMigrations = [...migrationFiles];
const programs: { id: string; requestsPerSecond: number | null }[] = [];
const pool = connect(config.DATABASE_URL);
try {
  await pool.query('SELECT 1');
  dbReachable = true;
  try {
    const applied = await pool.query('SELECT version FROM schema_migrations');
    const have = new Set(applied.rows.map(row => String(row.version)));
    pendingMigrations = migrationFiles.filter(version => !have.has(version));
  } catch {
    pendingMigrations = [...migrationFiles];
  }
  if (!pendingMigrations.length) {
    const rows = await pool.query(`SELECT p.id, s.policy FROM programs p JOIN scope_rules s ON s.program_id=p.id ORDER BY p.id`);
    for (const row of rows.rows) {
      const parsed = PolicySchema.safeParse(row.policy);
      programs.push({ id: String(row.id), requestsPerSecond: parsed.success ? parsed.data.requestsPerSecond : null });
    }
  }
} catch {
  dbReachable = false;
  pendingMigrations = [...migrationFiles];
} finally {
  await pool.end();
}

const report = evaluatePreflight({
  killSwitch: config.GLOBAL_KILL_SWITCH,
  passiveHttp: config.ENABLE_PASSIVE_HTTP,
  dbReachable,
  pendingMigrations: dbReachable ? pendingMigrations : [...migrationFiles],
  hackerOneUser: (process.env.HACKERONE_API_USERNAME?.trim() ?? '').length > 0,
  hackerOneToken: (process.env.HACKERONE_API_TOKEN?.trim() ?? '').length > 0,
  handles: parseHandles(handleText),
  programs,
});
for (const line of report.lines) console.log(line);
if (!report.ok) process.exitCode = 1;
