import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildNucleiArgs } from '../packages/tool-adapters/index.js';
import { parseNucleiJsonl, runAggressive } from '../packages/tool-adapters/aggressive.js';
import { transition } from '../packages/findings/index.js';

const env = { NUCLEI_BIN: '/opt/nuclei' };
const lab = ['lab.example.test'];
const jsonl = JSON.stringify({
  'template-id': 'exposed-panel',
  host: 'https://lab.example.test/admin',
  info: { severity: 'high', name: 'Exposed panel' },
  'extracted-results': ['do-not-keep-this-secret'],
}) + '\n';

test('aggressive preflight does nothing without a snapshot and never enables destructive tags off the lab', async () => {
  let calls = 0;
  const exec = async () => { calls += 1; return { stdout: jsonl }; };
  const missing = await runAggressive({ host: 'lab.example.test', labHosts: lab, snapshotConfirmed: false, n8nAttested: true, allowDestructive: false, env, exec });
  assert.equal(missing.refused, 'snapshot_required');
  assert.equal(missing.executed, false);
  assert.equal(calls, 0);
  const outside = await runAggressive({ host: 'app.example.test', labHosts: lab, snapshotConfirmed: true, n8nAttested: true, allowDestructive: true, env, exec });
  assert.equal(outside.refused, 'host_not_in_lab');
  assert.equal(calls, 0);
  assert.throws(() => buildNucleiArgs({ url: 'https://app.example.test', destructive: 'true' }), /nuclei_destructive_refused/);
});

test('a stubbed nuclei run keeps exclude-tags, drops them only on the lab, and does not keep extracted secrets', async () => {
  const seen: string[][] = [];
  const exec = async (_bin: string, args: string[]) => { seen.push(args); return { stdout: jsonl }; };
  const passive = await runAggressive({ host: 'lab.example.test', labHosts: lab, snapshotConfirmed: true, n8nAttested: true, allowDestructive: false, env, exec });
  assert.equal(passive.executed, true);
  assert.ok(seen[0]?.includes('-exclude-tags'));
  assert.deepEqual(passive.findings, [{ template: 'exposed-panel', location: 'https://lab.example.test/admin', severity: 'high' }]);
  assert.equal(JSON.stringify(passive.findings).includes('do-not-keep-this-secret'), false);
  assert.equal(transition('CANDIDATE', 'HUMAN_REVIEW', 'scanner').ok, true);
  assert.equal(transition('CANDIDATE', 'VERIFIED', 'scanner').ok, false);
  const loud = await runAggressive({ host: 'lab.example.test', labHosts: lab, snapshotConfirmed: true, n8nAttested: true, allowDestructive: true, env, exec });
  assert.equal(loud.destructive, true);
  assert.equal(loud.audit[0]?.recovery, 'qm rollback');
  assert.equal(seen[1]?.includes('-exclude-tags'), false);
  assert.equal(parseNucleiJsonl('').length, 0);
});
