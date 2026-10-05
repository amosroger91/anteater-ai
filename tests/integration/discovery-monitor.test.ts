import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { MANUAL_ONLY_POLICY, PERMITTED_POLICY } from '../../fixtures/automation-policy.js';
import type { LiveDiscoverySources } from '../../packages/discovery/live.js';
import { runMonitorCycle } from '../../packages/discovery/monitor.js';
import type { RawCandidate } from '../../packages/discovery/index.js';
import { compileIntake, intakeApprovalSource, type IntakeApproval } from '../../packages/program-intake/compile.js';
import { hackerOneProgramUrls, rateRulesFromPolicy, type RawProgram } from '../../packages/program-intake/hackerone.js';
import { sha256Hex } from '../../packages/provenance/index.js';
import { connect, migrate } from '../../packages/research-state/db.js';
import { saveProgram, type ProgramIntakeRecord } from '../../packages/research-state/workspace.js';
import { loadConfig } from '../../packages/shared/config.js';

const approvalBase = {
  approver: 'Ada Lovelace',
  approvedAt: '2026-01-01T00:00:00.000Z',
  revision: '2026-10',
  expiresAt: '2099-01-01T00:00:00.000Z',
};

function raw(handle: string, policyText: string, scopes: RawProgram['scopes']): RawProgram {
  return {
    platform: 'hackerone', handle, name: handle, programUrl: `https://hackerone.com/${handle}`,
    sourceUrl: hackerOneProgramUrls(handle).program, policyText, submissionState: 'open',
    openScope: false, goldStandardSafeHarbor: false, scopes, exclusions: [], rate: rateRulesFromPolicy(policyText),
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

test('one monitor cycle raises a newly exposed in-scope host and never queues an out-of-scope name', async () => {
  const base = loadConfig();
  const admin = connect(base.DATABASE_URL);
  const schema = 'test_' + randomUUID().replaceAll('-', '');
  await admin.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(base.DATABASE_URL);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = connect(url.toString());
  const seen = [
    { host: 'staging.example.test', source: 'cert-transparency', confidence: 0.7 },
    { host: 'secret.example.test', source: 'cert-transparency', confidence: 0.7 },
    { host: 'outside.example', source: 'cert-transparency', confidence: 0.7 },
  ] satisfies RawCandidate[];
  let calls = 0;
  const allowedRoots = new Set(['app.example.test', 'staging.example.test']);
  const guard = (roots: string[]) => {
    calls += 1;
    if (roots.some(root => !allowedRoots.has(root))) throw new Error(`refused_root:${roots.join(',')}`);
  };
  const sources: LiveDiscoverySources = {
    certTransparency: { async discover(roots) { guard(roots); return seen; } },
    passiveDns: { async discover(roots) { guard(roots); return seen.map(row => ({ ...row, source: 'passive-dns' })); } },
    subfinder: { async discover(roots) { guard(roots); return seen.map(row => ({ ...row, source: 'subfinder' })); } },
  };
  try {
    await migrate(pool);
    const permittedRaw = raw('acme', PERMITTED_POLICY, [
      scope('https://app.example.test'),
      scope('*.example.test', true, 'WILDCARD'),
      scope('https://secret.example.test', false),
    ]);
    const permitted = compileIntake(permittedRaw, sign(permittedRaw));
    const program = permitted.programs[0];
    assert.ok(program);
    assert.equal(permitted.automation, 'permitted');
    await saveProgram(pool, program, intakeOf(permitted));

    const manualRaw = raw('manual', MANUAL_ONLY_POLICY, [scope('https://manual.example.test')]);
    const manual = compileIntake(manualRaw, sign(manualRaw));
    const manualProgram = manual.programs[0];
    assert.ok(manualProgram);
    await saveProgram(pool, manualProgram, intakeOf(manual));

    const revokedRaw = raw('beta', PERMITTED_POLICY, [scope('https://beta.example.test')]);
    const revoked = compileIntake(revokedRaw, sign(revokedRaw));
    const revokedProgram = revoked.programs[0];
    assert.ok(revokedProgram);
    await saveProgram(pool, revokedProgram, intakeOf(revoked));
    await pool.query('INSERT INTO revoked_programs(program_id) VALUES ($1)', [revokedProgram.id]);

    const first = await runMonitorCycle({ pool, sources });
    const acme = first.find(report => report.programId === program.id);
    const beta = first.find(report => report.programId === revokedProgram.id);
    assert.ok(acme);
    assert.equal(acme.skipped, null);
    assert.deepEqual([...acme.candidates].sort(), ['outside.example', 'secret.example.test', 'staging.example.test']);
    assert.deepEqual(acme.admitted, ['staging.example.test']);
    assert.deepEqual([...acme.held].sort(), ['outside.example', 'secret.example.test']);
    assert.deepEqual(acme.enqueued, ['staging.example.test']);
    assert.equal(beta?.skipped, 'program_revoked');
    assert.equal(calls, 3);

    const jobs = await pool.query(`SELECT a.url, j.action FROM research_jobs j JOIN assets a ON a.id=j.asset_id AND a.program_id=j.program_id ORDER BY a.url`);
    assert.deepEqual(jobs.rows, [{ url: 'https://staging.example.test', action: 'inspect_http_target' }]);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM observations')).rows[0].n, 0);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM tool_runs')).rows[0].n, 0);
    const secret = (await pool.query(`SELECT active, first_seen IS NOT NULL AS seen FROM assets WHERE url='https://secret.example.test'`)).rows[0];
    assert.equal(secret.active, false);
    assert.equal(secret.seen, true);
    const outside = (await pool.query(`SELECT active FROM assets WHERE url='https://outside.example'`)).rows[0];
    assert.equal(outside.active, false);
    const staging = (await pool.query(`SELECT active FROM assets WHERE url='https://staging.example.test'`)).rows[0];
    assert.equal(staging.active, true);

    const second = await runMonitorCycle({ pool, sources });
    assert.deepEqual(second.find(report => report.programId === program.id)?.enqueued, []);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM research_jobs')).rows[0].n, 1);
    assert.equal(calls, 9);

    await pool.query('UPDATE runtime_control SET global_kill=true WHERE id=1');
    const stopped = await runMonitorCycle({ pool, sources });
    assert.ok(stopped.every(report => report.skipped === 'global_kill' && report.enqueued.length === 0));
    assert.equal(calls, 9);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM research_jobs')).rows[0].n, 1);
    assert.equal((await pool.query(`SELECT count(*)::int AS n FROM assets WHERE url='https://manual.example.test'`)).rows[0].n, 1);
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  }
});
