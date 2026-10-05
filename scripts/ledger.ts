import { loadConfig } from '../packages/shared/config.js';
import { connect } from '../packages/research-state/db.js';
import { paidTotal } from '../packages/metrics/collect.js';
import { netEconomics } from '../packages/metrics/index.js';

const value = (name: string) => {
  const raw = process.argv.find(arg => arg.startsWith(`--${name}=`))?.slice(name.length + 3);
  const number = raw === undefined ? 0 : Number(raw);
  if (!Number.isFinite(number) || number < 0) throw new Error('ledger_refused');
  return number;
};

const pool = connect(loadConfig().DATABASE_URL);
try {
  const economics = netEconomics({ paid: await paidTotal(pool), humanHours: value('hours'), hourlyRate: value('rate'), infra: value('infra') });
  console.log(JSON.stringify({ ...economics, source: 'submissions_table' }));
} catch (error) {
  console.error(error instanceof Error ? error.message : 'ledger_failed');
  process.exitCode = 1;
} finally { await pool.end(); }
