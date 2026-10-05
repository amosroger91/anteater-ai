import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { connect, migrate } from '../../packages/research-state/db.js';
import { Jobs } from '../../packages/research-state/jobs.js';
import { saveProgram } from '../../packages/research-state/workspace.js';
import { loadConfig } from '../../packages/shared/config.js';
import { collectFleetSnapshot, paidTotal } from '../../packages/metrics/collect.js';
import { netEconomics } from '../../packages/metrics/index.js';
import { exportBackup, restoreBackup } from '../../packages/operations/backup.js';

test('fixture economics, a metrics snapshot, backup restore, and crash recovery stay inside the lab database', async () => {
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
      id: 'lab-fleet', name: 'Lab', platform: 'owned-lab', programUrl: 'https://lab.example.test/program', categories: ['web'],
      policy: {
        programId: 'lab-fleet', revision: 'r1', sourceUrl: 'https://lab.example.test/policy', reviewed: true,
        expiresAt: '2099-01-01T00:00:00.000Z', allowed: ['lab.example.test'], excluded: [],
        allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1,
      },
      assets: [{ id: 'lab-example-test', url: 'https://lab.example.test' }],
    });
    const crashed = randomUUID();
    await pool.query(`INSERT INTO research_jobs(id, program_id, asset_id, action, dedupe_key, status, attempts, max_attempts, policy_revision, lease_until, lease_token)
      VALUES($1,'lab-fleet','lab-example-test','inspect_http_target','crash-lease','running',1,3,'r1', clock_timestamp() - interval '2 minutes', $2)`, [crashed, randomUUID()]);
    await pool.query(`INSERT INTO research_jobs(id, program_id, asset_id, action, dedupe_key, status, attempts, max_attempts, policy_revision, created_at, available_at)
      VALUES($1,'lab-fleet','lab-example-test','inspect_http_target','old-queue','queued',0,3,'r1', clock_timestamp() - interval '1 hour', clock_timestamp() + interval '1 day')`, [randomUUID()]);
    await pool.query(`INSERT INTO research_jobs(id, program_id, asset_id, action, dedupe_key, status, policy_revision)
      VALUES($1,'lab-fleet','lab-example-test','inspect_http_target','failed-tool','failed','r1')`, [randomUUID()]);
    await pool.query(`INSERT INTO dead_letter(id, reason, error_code) VALUES($1,'mailbox down','mailbox')`, [randomUUID()]);
    await pool.query(`INSERT INTO rate_limits(key, next_at) VALUES('global', clock_timestamp() + interval '1 minute')`);
    const snapshot = await collectFleetSnapshot(pool);
    assert.ok(snapshot.queueAgeSeconds > 3000);
    assert.equal(snapshot.toolFailures, 1);
    assert.equal(snapshot.mailboxFailures, 1);
    assert.equal(snapshot.deadLettered, 1);
    assert.equal(snapshot.rateLimitHits, 1);
    assert.ok(snapshot.coverageGaps >= 1);
    const submission = randomUUID();
    await pool.query(`INSERT INTO submissions(id, program_id, status, amount, currency) VALUES($1,'lab-fleet','paid',100,'USD')`, [submission]);
    assert.equal(await paidTotal(pool), 100);
    assert.deepEqual(netEconomics({ paid: await paidTotal(pool), humanHours: 2, hourlyRate: 50, infra: 10 }), { paid: 100, labor: 100, infra: 10, net: -10 });
    const bundle = await exportBackup(pool);
    await pool.query('DELETE FROM submissions');
    await pool.query('DELETE FROM dead_letter');
    assert.equal(await paidTotal(pool), 0);
    await restoreBackup(pool, bundle);
    assert.equal(await paidTotal(pool), 100);
    assert.equal((await pool.query(`SELECT count(*)::int AS n FROM dead_letter WHERE error_code='mailbox'`)).rows[0].n, 1);
    const jobs = new Jobs(pool, 1, 30, () => false);
    const claimed = await jobs.claim();
    assert.equal(claimed?.id, crashed);
    assert.equal(claimed?.attempts, 2);
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin.end();
  }
});
