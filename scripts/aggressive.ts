import { execFile } from 'node:child_process';
import { runAggressive } from '../packages/tool-adapters/aggressive.js';
import { loadOperatorConfig as loadConfig } from '../packages/setup/operator.js';

// Snapshot-gated lab runner (BOUNTY_EARNINGS_PLAN.md Phase 4.5).
// Refuses unless the host is in LAB_TARGET_HOSTS, the operator passes
// --snapshot-confirmed, and --n8n-attested. Missing the snapshot does nothing.
// This process does not invent either attestation.

const config = loadConfig();
const args = process.argv.slice(2);
const host = args.find(arg => !arg.startsWith('--')) ?? '';
const snapshotConfirmed = args.includes('--snapshot-confirmed');
const n8nAttested = args.includes('--n8n-attested');
const allowDestructive = args.includes('--allow-destructive');
if (!host) {
  console.error('usage: tsx scripts/aggressive.ts <host> --snapshot-confirmed --n8n-attested [--allow-destructive]');
  process.exit(1);
}

const result = await runAggressive({
  host,
  labHosts: config.LAB_TARGET_HOSTS.split(',').map(item => item.trim()).filter(Boolean),
  snapshotConfirmed,
  n8nAttested,
  allowDestructive,
  exec: (bin, argv) => new Promise((resolve, reject) => {
    execFile(bin, argv, { timeout: 120_000, windowsHide: true, maxBuffer: 4_194_304 }, (error, stdout) => {
      if (error) reject(error);
      else resolve({ stdout: String(stdout) });
    });
  }),
});
if (result.refused) {
  console.error(`aggressive_refused ${result.refused}`);
  process.exit(2);
}
for (const event of result.audit) console.error(`audit ${event.event} host=${event.host} recovery=${event.recovery}`);
console.log(`aggressive_findings ${result.findings.length}`);
