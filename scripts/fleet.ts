import { loadConfig } from '../packages/shared/config.js';
import { connect } from '../packages/research-state/db.js';
import { runFleetIteration } from '../packages/operations/fleet.js';

// Dry scheduling pass. It does not invoke tools and it does not contact a host.
const config = loadConfig();
if (config.GLOBAL_KILL_SWITCH) {
  console.error('fleet_refused kill_switch');
  process.exit(2);
}
const pool = connect(config.DATABASE_URL);
try {
  const control = await pool.query('SELECT global_kill, epoch FROM runtime_control WHERE id=1');
  const revoked = await pool.query('SELECT program_id FROM revoked_programs');
  const programs = await pool.query(`SELECT id FROM programs WHERE automation_policy='permitted' ORDER BY id`);
  const row = control.rows[0];
  const state = {
    globalKill: row?.global_kill === true,
    revokedPrograms: revoked.rows.map((item: { program_id: string }) => item.program_id),
    epoch: Number(row?.epoch ?? 0),
  };
  const report = await runFleetIteration({
    programIds: programs.rows.map((item: { id: string }) => item.id),
    state, leaseEpoch: state.epoch,
    globalTake: () => true, programTake: () => true, run: async () => {},
  });
  console.log(`fleet_dry_run ran=${report.ran.length} skipped=${report.skipped.length} dead_lettered=${report.deadLettered.length}`);
} finally { await pool.end(); }
