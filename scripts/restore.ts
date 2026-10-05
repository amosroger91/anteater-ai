import { readFile } from 'node:fs/promises';
import { loadConfig } from '../packages/shared/config.js';
import { connect } from '../packages/research-state/db.js';
import { restoreBackup, type BackupBundle } from '../packages/operations/backup.js';

const path = process.argv.find(arg => arg.startsWith('--in='))?.slice(5);
if (!path) {
  console.error('usage: tsx scripts/restore.ts --in=<file>');
  process.exit(1);
}
const bundle = JSON.parse(await readFile(path, 'utf8')) as BackupBundle;
if (!Array.isArray(bundle.submissions) || !Array.isArray(bundle.deadLetter)) throw new Error('backup_invalid');
const pool = connect(loadConfig().DATABASE_URL);
try {
  await restoreBackup(pool, bundle);
  console.log('backup_restored');
} finally { await pool.end(); }
