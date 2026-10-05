import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect, migrate } from '../../packages/research-state/db.js';
import { recordScannerFinding } from '../../packages/research-state/jobs.js';
import { saveProgram } from '../../packages/research-state/workspace.js';
import { loadConfig } from '../../packages/shared/config.js';
import { runAggressive } from '../../packages/tool-adapters/aggressive.js';
import { randomUUID } from 'node:crypto';

test('stubbed nuclei JSONL is stored as human review and never as verified', async () => {
  const base = loadConfig();
  const admin = connect(base.DATABASE_URL);
  const schema = 'test_' + randomUUID().replaceAll('-', '');
  await admin.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(base.DATABASE_URL);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = connect(url.toString());
  try {
    await migrate(pool);
    await saveProgram(pool, {
      id: 'lab-aggressive', name: 'Lab', platform: 'owned-lab', programUrl: 'https://lab.example.test/program', categories: ['web'],
      policy: {
        programId: 'lab-aggressive', revision: 'r1', sourceUrl: 'https://lab.example.test/policy', reviewed: true,
        expiresAt: '2099-01-01T00:00:00.000Z', allowed: ['lab.example.test'], excluded: [],
        allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1,
      },
      assets: [{ id: 'lab-example-test', url: 'https://lab.example.test' }],
    });
    const result = await runAggressive({
      host: 'lab.example.test', labHosts: ['lab.example.test'], snapshotConfirmed: true, n8nAttested: true, allowDestructive: false,
      env: { NUCLEI_BIN: '/opt/nuclei' },
      exec: async () => ({ stdout: '{"template-id":"exposed-panel","host":"https://lab.example.test/admin","info":{"severity":"high"}}\n' }),
    });
    assert.equal(result.executed, true);
    const stored = await recordScannerFinding(pool, 'lab-aggressive', result.findings[0]!);
    assert.equal(stored.status, 'HUMAN_REVIEW');
    const row = await pool.query('SELECT status, body FROM findings WHERE id=$1', [stored.id]);
    assert.equal(row.rows[0].status, 'HUMAN_REVIEW');
    assert.equal(JSON.stringify(row.rows[0].body).includes('extracted'), false);
    await assert.rejects(pool.query(`INSERT INTO findings(id,program_id,status,body,verified_by) VALUES($1,'lab-aggressive','VERIFIED','{}','scanner')`, [randomUUID()]), /verifier_required/);
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin.end();
  }
});
