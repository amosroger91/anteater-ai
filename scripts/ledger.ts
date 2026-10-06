import { netPaidMinusInfra, recordLedgerEvent } from '../packages/ledger/index.js';
import { paidTotal } from '../packages/metrics/collect.js';
import { connect } from '../packages/research-state/db.js';
import { loadConfig } from '../packages/shared/config.js';

// net = paid − infra. Recording a later outcome (--record) appends a submissions row.
// It does not submit a finding. Submission stays on npm run finding:submit.
const flag = (name: string) => process.argv.find(arg => arg.startsWith(`--${name}=`))?.slice(name.length + 3);
const numberFlag = (name: string) => {
  const raw = flag(name);
  const number = raw === undefined ? 0 : Number(raw);
  if (!Number.isFinite(number) || number < 0) throw new Error('ledger_refused');
  return number;
};

const pool = connect(loadConfig().DATABASE_URL);
try {
  if (process.argv.includes('--record')) {
    const findingId = flag('finding');
    const status = flag('status');
    const amountRaw = flag('amount');
    const currency = flag('currency') ?? null;
    const amount = amountRaw === undefined ? null : Number(amountRaw);
    if (!findingId || !status || (amountRaw !== undefined && !Number.isFinite(amount))) throw new Error('ledger_refused');
    await recordLedgerEvent(pool, { findingId, status, amount, currency });
    console.log('ledger_recorded');
  }
  const economics = netPaidMinusInfra(await paidTotal(pool), numberFlag('infra'));
  console.log(JSON.stringify({ ...economics, source: 'submissions_table' }));
} catch (error) {
  console.error(error instanceof Error ? error.message : 'ledger_failed');
  process.exitCode = 1;
} finally { await pool.end(); }
