import { loadConfig } from '../packages/shared/config.js';
import { connect } from '../packages/research-state/db.js';
import { submitFinding } from '../packages/research-state/jobs.js';

// A person submits a finding that is already in HUMAN_REVIEW or VERIFIED.
// usage: tsx scripts/submit-finding.ts --id=<uuid> --reviewer=<name>
const id = process.argv.find(arg => arg.startsWith('--id='))?.slice(5);
const reviewer = process.argv.find(arg => arg.startsWith('--reviewer='))?.slice(11);
if (!id || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id) || !reviewer) {
  console.error('usage: tsx scripts/submit-finding.ts --id=<uuid> --reviewer=<name>');
  process.exitCode = 1;
} else {
  const pool = connect(loadConfig().DATABASE_URL);
  try {
    await submitFinding(pool, id, reviewer);
    console.log('submitted');
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'submit_failed');
    process.exitCode = 1;
  } finally { await pool.end(); }
}
