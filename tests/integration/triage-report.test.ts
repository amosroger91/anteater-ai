import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { connect, migrate } from '../../packages/research-state/db.js';
import { recordCampaignCoverage, recordReplay, retestStored, submitFinding } from '../../packages/research-state/jobs.js';
import { saveProgram } from '../../packages/research-state/workspace.js';
import { loadConfig } from '../../packages/shared/config.js';
import { decrypt } from '../../packages/evidence/index.js';
import { renderReport } from '../../packages/report/index.js';
import { remediationFor } from '../../packages/remediation/index.js';
import type { Responder } from '../../packages/findings/index.js';

const contract = {
  findingType: 'cross_account_read',
  steps: [{ id: 'read', expectStatus: 200, expectBodyIncludes: ['owned-marker'] }],
  counterTest: { id: 'control', expectStatus: 404 },
  repeatCount: 1,
};
const leak: Responder = async step => step === 'read' ? { status: 200, body: 'owned-marker' } : { status: 404, body: 'missing' };
const key = 'cd'.repeat(32);

test('a finding moves to submitted with a clean report, and a duplicate is kept out of triage', async () => {
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
      id: 'lab-report', name: 'Lab', platform: 'owned-lab', programUrl: 'https://lab.example.test/program', categories: ['web'],
      policy: {
        programId: 'lab-report', revision: 'r1', sourceUrl: 'https://lab.example.test/policy', reviewed: true,
        expiresAt: '2099-01-01T00:00:00.000Z', allowed: ['lab.example.test'], excluded: [],
        allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1,
      },
      assets: [{ id: 'lab-example-test', url: 'https://lab.example.test' }],
    });
    await recordCampaignCoverage(pool, 'lab-report', { targets: 1, checks: 1, executed: 1, candidates: 0, gaps: 0 }, '# Coverage report\n');
    const verified = await recordReplay(pool, 'lab-report', 'CANDIDATE', contract, leak, {
      findingType: 'cross_account_read', location: 'https://lab.example.test/api/documents/1', severity: 'high', estimatedPayout: 1000, confidence: 0.8,
    }, { evidenceKey: key });
    assert.equal(verified.next, 'VERIFIED');
    const evidence = await pool.query('SELECT body FROM evidence WHERE finding_id=$1', [verified.id]);
    assert.equal(JSON.stringify(evidence.rows[0].body).includes('owned-marker'), false);
    assert.equal(decrypt(evidence.rows[0].body.sealed, key).includes('owned-marker'), false);
    const stored = (await pool.query('SELECT body FROM findings WHERE id=$1', [verified.id])).rows[0].body;
    const report = renderReport(
      { id: verified.id, type: stored.findingType, location: stored.location, severity: stored.severity },
      { steps: stored.replay.evidence },
      remediationFor('cross_account_read'),
    );
    assert.match(report, /## Impact/);
    assert.match(report, /## Reproduction/);
    assert.match(report, /## Remediation/);
    assert.equal(report.includes('owned-marker'), false);
    const queued = await pool.query('SELECT id FROM triage_queue WHERE id=$1', [verified.id]);
    assert.equal(queued.rowCount, 1);
    await submitFinding(pool, verified.id, 'Ada Lovelace');
    const duplicate = await recordReplay(pool, 'lab-report', 'CANDIDATE', contract, leak, {
      findingType: 'cross_account_read', location: 'https://lab.example.test/api/documents/1', severity: 'high', estimatedPayout: 1000, confidence: 0.5,
    });
    assert.equal((await pool.query('SELECT id FROM triage_queue WHERE id=$1', [duplicate.id])).rowCount, 0);
    const other = await recordReplay(pool, 'lab-report', 'CANDIDATE', contract, leak, {
      findingType: 'cross_account_read', location: 'https://lab.example.test/api/documents/2', severity: 'high', estimatedPayout: 500, confidence: 0.5,
    });
    assert.equal((await pool.query('SELECT id FROM triage_queue WHERE id=$1', [other.id])).rowCount, 1);
    const outage = await retestStored(pool, verified.id, async () => { throw new Error('offline'); });
    assert.equal(outage.fixed, false);
    assert.equal(outage.inconclusive, true);
    const fixed = await retestStored(pool, verified.id, async () => ({ status: 404, body: 'gone' }));
    assert.equal(fixed.fixed, true);
    assert.equal(fixed.inconclusive, false);
    const coverage = await pool.query(`SELECT metadata->>'markdown' AS markdown FROM audit_events WHERE event='CAMPAIGN_COVERAGE'`);
    assert.match(coverage.rows[0].markdown, /Coverage report/);
    assert.equal((await pool.query("SELECT status FROM findings WHERE id=$1", [verified.id])).rows[0].status, 'SUBMITTED');
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin.end();
  }
});
