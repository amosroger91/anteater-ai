import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { PERMITTED_POLICY } from '../../fixtures/automation-policy.js';
import type { LiveDiscoverySources } from '../../packages/discovery/live.js';
import { runMonitorCycle } from '../../packages/discovery/monitor.js';
import type { RawCandidate } from '../../packages/discovery/index.js';
import { netPaidMinusInfra, recordLedgerEvent } from '../../packages/ledger/index.js';
import { compileIntake, intakeApprovalSource, type IntakeApproval } from '../../packages/program-intake/compile.js';
import { hackerOneProgramUrls, rateRulesFromPolicy, type RawProgram } from '../../packages/program-intake/hackerone.js';
import { sha256Hex } from '../../packages/provenance/index.js';
import { paidTotal } from '../../packages/metrics/collect.js';
import { connect, migrate } from '../../packages/research-state/db.js';
import { recordReplay, submitFinding } from '../../packages/research-state/jobs.js';
import { saveProgram, type ProgramIntakeRecord } from '../../packages/research-state/workspace.js';
import { remediationFor } from '../../packages/remediation/index.js';
import { renderReport } from '../../packages/report/index.js';
import { loadConfig } from '../../packages/shared/config.js';
import type { Responder } from '../../packages/findings/index.js';

const approvalBase = {
  approver: 'Ada Lovelace',
  approvedAt: '2026-01-01T00:00:00.000Z',
  revision: '2026-10',
  expiresAt: '2099-01-01T00:00:00.000Z',
};

function raw(handle: string, scopes: RawProgram['scopes']): RawProgram {
  return {
    platform: 'hackerone', handle, name: handle, programUrl: `https://hackerone.com/${handle}`,
    sourceUrl: hackerOneProgramUrls(handle).program, policyText: PERMITTED_POLICY, submissionState: 'open',
    openScope: false, goldStandardSafeHarbor: false, scopes, exclusions: [], rate: rateRulesFromPolicy(PERMITTED_POLICY),
  };
}

function sign(program: RawProgram): IntakeApproval {
  return { ...approvalBase, sourceSha256: sha256Hex(intakeApprovalSource(program, approvalBase)) };
}

function intakeOf(compiled: { handle: string; automation: ProgramIntakeRecord['automationPolicy']; sourceSha256: string }): ProgramIntakeRecord {
  return { automationPolicy: compiled.automation, platformHandle: compiled.handle, approver: approvalBase.approver, sourceSha256: compiled.sourceSha256, approvedAt: approvalBase.approvedAt, revision: approvalBase.revision };
}

const scope = (identifier: string, eligible = true, assetType = 'URL') => ({
  assetType, identifier, eligibleForSubmission: eligible, eligibleForBounty: eligible, instruction: null,
});

const contract = {
  findingType: 'cross_account_read',
  steps: [{ id: 'read', expectStatus: 200, expectBodyIncludes: ['owned-marker'] }],
  counterTest: { id: 'control', expectStatus: 404 },
  repeatCount: 1,
};
const leak: Responder = async step => step === 'read' ? { status: 200, body: 'owned-marker' } : { status: 404, body: 'missing' };

test('a wildcard dry run queues only new in-scope names and produces a de-duplicated submit-ready report', async () => {
  process.env.ENABLE_PASSIVE_HTTP = 'true';
  process.env.GLOBAL_KILL_SWITCH = 'false';
  const base = loadConfig();
  assert.equal(base.ENABLE_PASSIVE_HTTP, true);
  assert.equal(base.GLOBAL_KILL_SWITCH, false);
  const network: string[] = [];
  const priorFetch = globalThis.fetch;
  globalThis.fetch = (async (input: unknown) => {
    network.push(String(input));
    throw new Error('network_forbidden');
  }) as typeof fetch;
  const admin = connect(base.DATABASE_URL);
  const schema = 'test_' + randomUUID().replaceAll('-', '');
  await admin.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(base.DATABASE_URL);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = connect(url.toString());
  const phases: RawCandidate[][] = [
    [
      { host: 'app.wild.example.test', source: 'subfinder', confidence: 0.75 },
      { host: 'secret.wild.example.test', source: 'subfinder', confidence: 0.75 },
      { host: 'evil.example', source: 'subfinder', confidence: 0.75 },
    ],
    [
      { host: 'app.wild.example.test', source: 'subfinder', confidence: 0.75 },
      { host: 'secret.wild.example.test', source: 'subfinder', confidence: 0.75 },
      { host: 'evil.example', source: 'subfinder', confidence: 0.75 },
    ],
    [
      { host: 'app.wild.example.test', source: 'subfinder', confidence: 0.75 },
      { host: 'secret.wild.example.test', source: 'subfinder', confidence: 0.75 },
      { host: 'evil.example', source: 'subfinder', confidence: 0.75 },
      { host: 'new.wild.example.test', source: 'cert-transparency', confidence: 0.7 },
    ],
  ];
  let calls = 0;
  const discover = async (roots: string[]) => {
    calls += 1;
    if (roots.some(root => root !== 'wild.example.test')) throw new Error(`refused_root:${roots.join(',')}`);
    return phases[Math.min(Math.floor((calls - 1) / 3), phases.length - 1)] ?? [];
  };
  const sources: LiveDiscoverySources = { certTransparency: { discover }, passiveDns: { discover }, subfinder: { discover } };
  try {
    await migrate(pool);
    const programRaw = raw('wildco', [
      scope('*.wild.example.test', true, 'WILDCARD'),
      scope('https://app.wild.example.test'),
      scope('https://secret.wild.example.test', false),
    ]);
    const compiled = compileIntake(programRaw, sign(programRaw));
    const program = compiled.programs[0];
    assert.ok(program);
    assert.equal(compiled.refused, null);
    await saveProgram(pool, program, intakeOf(compiled));

    const first = (await runMonitorCycle({ pool, sources })).find(report => report.programId === program.id);
    const second = (await runMonitorCycle({ pool, sources })).find(report => report.programId === program.id);
    const third = (await runMonitorCycle({ pool, sources })).find(report => report.programId === program.id);
    assert.deepEqual(first?.newExposure, ['app.wild.example.test']);
    assert.deepEqual(first?.enqueued, ['app.wild.example.test']);
    assert.deepEqual(second?.newExposure, []);
    assert.deepEqual(second?.enqueued, []);
    assert.deepEqual(third?.newExposure, ['new.wild.example.test']);
    assert.deepEqual(third?.enqueued, ['new.wild.example.test']);
    assert.equal(calls, 9);
    const jobs = await pool.query(`SELECT a.url FROM research_jobs j JOIN assets a ON a.id=j.asset_id AND a.program_id=j.program_id ORDER BY a.url`);
    assert.deepEqual(jobs.rows.map(row => row.url), ['https://app.wild.example.test', 'https://new.wild.example.test']);
    assert.equal((await pool.query(`SELECT active FROM assets WHERE url='https://evil.example'`)).rows[0].active, false);
    assert.equal((await pool.query(`SELECT active FROM assets WHERE url='https://secret.wild.example.test'`)).rows[0].active, false);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM observations')).rows[0].n, 0);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM tool_runs')).rows[0].n, 0);
    assert.deepEqual(network, []);

    const verified = await recordReplay(pool, program.id, 'CANDIDATE', contract, leak, {
      findingType: 'cross_account_read', location: 'https://new.wild.example.test/api/documents/1', severity: 'high', estimatedPayout: 10, confidence: 0.8,
    });
    assert.equal(verified.next, 'VERIFIED');
    const stored = (await pool.query('SELECT body FROM findings WHERE id=$1', [verified.id])).rows[0].body;
    const report = renderReport(
      { id: verified.id, type: stored.findingType, location: stored.location, severity: stored.severity, status: verified.next },
      { steps: stored.replay.evidence },
      remediationFor('cross_account_read'),
    );
    assert.ok(report);
    assert.match(report, /## Severity/);
    assert.match(report, /## Affected asset\nhttps:\/\/new\.wild\.example\.test/);
    assert.match(report, /## Reproduction/);
    assert.match(report, /## Impact/);
    assert.match(report, /## Remediation/);
    assert.equal(report.includes('owned-marker'), false);
    const queued = (await pool.query('SELECT payout_tier, rank, dedupe_status, evidence_steps FROM triage_queue WHERE id=$1', [verified.id])).rows[0];
    assert.equal(Number(queued.payout_tier), 3);
    assert.equal(Number(queued.rank), 2.4);
    assert.equal(queued.dedupe_status, 'clear');
    assert.equal(Number(queued.evidence_steps), 2);
    const infoId = randomUUID();
    await pool.query(`INSERT INTO findings(id, program_id, status, body) VALUES($1,$2,'HUMAN_REVIEW',$3)`, [
      infoId, program.id, JSON.stringify({ findingType: 'missing_security_headers', location: 'https://app.wild.example.test/', severity: 'info', confidence: 1, estimatedPayout: 5000 }),
    ]);
    assert.equal((await pool.query('SELECT id FROM triage_queue WHERE id=$1', [infoId])).rowCount, 0);

    await submitFinding(pool, verified.id, 'Ada Lovelace');
    assert.equal((await pool.query(`SELECT status FROM submissions WHERE finding_id=$1 AND status='submitted'`, [verified.id])).rowCount, 1);
    const duplicate = await recordReplay(pool, program.id, 'CANDIDATE', contract, leak, {
      findingType: 'cross_account_read', location: 'https://new.wild.example.test/api/documents/1', severity: 'high', estimatedPayout: 1000, confidence: 0.9,
    });
    assert.equal((await pool.query('SELECT id FROM triage_queue WHERE id=$1', [duplicate.id])).rowCount, 0);
    assert.equal((await pool.query('SELECT dedupe_status FROM triage_suppressed WHERE id=$1', [duplicate.id])).rows[0].dedupe_status, 'prior_submission');
    await recordLedgerEvent(pool, { findingId: verified.id, status: 'paid', amount: 250, currency: 'USD' });
    assert.deepEqual(netPaidMinusInfra(await paidTotal(pool), 40), { paid: 250, infra: 40, net: 210 });
  } finally {
    globalThis.fetch = priorFetch;
    await pool.end();
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin.end();
  }
});
