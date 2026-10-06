import { formatQueueEntry, formatSuppressedEntry, recordKnownIssue } from '../packages/ledger/index.js';
import { loadConfig } from '../packages/shared/config.js';
import { connect } from '../packages/research-state/db.js';

// Lists the ranked submit-ready queue. It does not submit.
// A known issue is recorded with --known-issue and then stays out of the queue.
const flag = (name: string) => process.argv.find(arg => arg.startsWith(`--${name}=`))?.slice(name.length + 3);
const pool = connect(loadConfig().DATABASE_URL);
try {
  if (process.argv.includes('--known-issue')) {
    const programId = flag('program');
    const findingType = flag('type');
    const location = flag('location');
    const note = flag('note');
    if (!programId || !findingType || !location) {
      console.error('usage: npm run triage -- --known-issue --program=<id> --type=<finding-type> --location=<url>');
      process.exitCode = 1;
    } else {
      await recordKnownIssue(pool, { programId, findingType, location, ...(note ? { note } : {}) });
      console.log('known_issue_recorded');
    }
  } else {
    const queued = await pool.query(`SELECT id, program_id, status, finding_type, location, confidence, payout_tier, rank, evidence_sha, evidence_steps
      FROM triage_queue ORDER BY rank DESC, id`);
    const suppressed = await pool.query(`SELECT id, program_id, finding_type, location, dedupe_status FROM triage_suppressed ORDER BY id`);
    if (!queued.rowCount) console.log('triage_empty');
    else console.log(`triage_queue ${queued.rowCount}`);
    for (const row of queued.rows) {
      for (const line of formatQueueEntry({
        id: String(row.id),
        programId: String(row.program_id),
        status: String(row.status),
        findingType: String(row.finding_type),
        location: String(row.location),
        tier: Number(row.payout_tier),
        confidence: Number(row.confidence),
        rank: Number(row.rank),
        evidenceSha: row.evidence_sha === null || row.evidence_sha === undefined ? null : String(row.evidence_sha),
        evidenceSteps: Number(row.evidence_steps),
      })) console.log(line);
    }
    if (suppressed.rowCount) {
      console.log(`triage_suppressed ${suppressed.rowCount}`);
      for (const row of suppressed.rows) {
        console.log(formatSuppressedEntry({
          id: String(row.id),
          programId: String(row.program_id),
          findingType: String(row.finding_type),
          location: String(row.location),
          dedupeStatus: String(row.dedupe_status),
        }));
      }
    }
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : 'triage_failed');
  process.exitCode = 1;
} finally { await pool.end(); }
