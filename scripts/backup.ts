import { writeFile } from 'node:fs/promises';
import { loadConfig } from '../packages/shared/config.js';
import { connect } from '../packages/research-state/db.js';
import { exportBackup } from '../packages/operations/backup.js';

const path = process.argv.find(arg => arg.startsWith('--out='))?.slice(6);
if (!path) {
  console.error('usage: tsx scripts/backup.ts --out=<file>');
  process.exit(1);
}
const pool = connect(loadConfig().DATABASE_URL);
try {
  await writeFile(path, JSON.stringify(await exportBackup(pool)));
  console.log('backup_written');
} finally { await pool.end(); }
