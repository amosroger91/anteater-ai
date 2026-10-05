import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { MANUAL_ONLY_POLICY, PERMITTED_POLICY, PROHIBITED_POLICY } from '../../fixtures/automation-policy.js';
import { connect, migrate } from '../../packages/research-state/db.js';
import { Jobs } from '../../packages/research-state/jobs.js';
import { saveProgram, type ProgramIntakeRecord } from '../../packages/research-state/workspace.js';
import { loadConfig } from '../../packages/shared/config.js';
import { compileIntake, intakeApprovalSource, type IntakeApproval } from '../../packages/program-intake/compile.js';
import { hackerOneProgramUrls, rateRulesFromPolicy, type RawProgram } from '../../packages/program-intake/hackerone.js';
import { sha256Hex } from '../../packages/provenance/index.js';

const approvalBase = {
  approver: 'Ada Lovelace',
  approvedAt: '2026-01-01T00:00:00.000Z',
  revision: '2026-10',
  expiresAt: '2099-01-01T00:00:00.000Z',
};

function raw(handle: string, policyText: string, host: string): RawProgram {
  return {
    platform: 'hackerone', handle, name: handle, programUrl: `https://hackerone.com/${handle}`,
    sourceUrl: hackerOneProgramUrls(handle).program, policyText, submissionState: 'open',
    openScope: false, goldStandardSafeHarbor: false,
    scopes: [{ assetType: 'URL', identifier: `https://${host}`, eligibleForSubmission: true, eligibleForBounty: true, instruction: null }],
    exclusions: [], rate: rateRulesFromPolicy(policyText),
  };
}

function sign(program: RawProgram): IntakeApproval {
  return { ...approvalBase, sourceSha256: sha256Hex(intakeApprovalSource(program, approvalBase)) };
}

function intakeOf(compiled: { handle: string; automation: ProgramIntakeRecord['automationPolicy']; sourceSha256: string }): ProgramIntakeRecord {
  return { automationPolicy: compiled.automation, platformHandle: compiled.handle, approver: approvalBase.approver, sourceSha256: compiled.sourceSha256, approvedAt: approvalBase.approvedAt, revision: approvalBase.revision };
}

test('intake columns record approval, and a prohibited or manual-only program cannot take the active action', async () => {
  const base = loadConfig();
  const admin = connect(base.DATABASE_URL);
  const schema = 'test_' + randomUUID().replaceAll('-', '');
  await admin.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(base.DATABASE_URL);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = connect(url.toString());
  try {
    await migrate(pool);
    await migrate(pool);
    const columns = await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='programs' AND column_name IN ('automation_policy','platform_handle') ORDER BY column_name`);
    assert.deepEqual(columns.rows.map(row => row.column_name), ['automation_policy', 'platform_handle']);
    assert.equal((await pool.query(`SELECT to_regclass('program_approvals') IS NOT NULL AS present`)).rows[0].present, true);

    const manualRaw = raw('acme', MANUAL_ONLY_POLICY, 'app.example.test');
    const manual = compileIntake(manualRaw, sign(manualRaw));
    const manualProgram = manual.programs[0];
    assert.ok(manualProgram);
    const prohibitedRaw = raw('acme', PROHIBITED_POLICY, 'app.example.test');
    const prohibited = compileIntake(prohibitedRaw, sign(prohibitedRaw));
    assert.equal(prohibited.programs.length, 0);
    await assert.rejects(saveProgram(pool, manualProgram, intakeOf({ ...manual, automation: 'prohibited' })), /automation_prohibited/);
    await assert.rejects(saveProgram(pool, { ...manualProgram, policy: { ...manualProgram.policy, allowedActions: [...manualProgram.policy.allowedActions, 'research_application'] } }, intakeOf(manual)), /research_application_forbidden/);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM programs')).rows[0].n, 0);

    await saveProgram(pool, manualProgram, intakeOf(manual));
    const stored = (await pool.query('SELECT automation_policy, platform_handle FROM programs WHERE id=$1', [manualProgram.id])).rows[0];
    assert.equal(stored.automation_policy, 'manual-only');
    assert.equal(stored.platform_handle, 'acme');
    const approval = (await pool.query('SELECT approver, source_sha256, revision FROM program_approvals WHERE program_id=$1', [manualProgram.id])).rows[0];
    assert.equal(approval.approver, 'Ada Lovelace');
    assert.equal(approval.source_sha256, manual.sourceSha256);
    assert.equal(approval.revision, '2026-10');

    const jobs = new Jobs(pool);
    const assetId = manualProgram.assets[0]?.id;
    assert.ok(assetId);
    await jobs.enqueue(manualProgram.id, assetId, 'research_application');
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM research_jobs')).rows[0].n, 0);
    await jobs.enqueue(manualProgram.id, assetId, 'inspect_http_target');
    assert.deepEqual((await pool.query("SELECT action FROM research_jobs")).rows.map(row => row.action), ['inspect_http_target']);

    const permittedRaw = raw('beta', PERMITTED_POLICY, 'beta.example.test');
    const permitted = compileIntake(permittedRaw, sign(permittedRaw));
    const permittedProgram = permitted.programs[0];
    assert.ok(permittedProgram);
    assert.ok(permittedProgram.policy.allowedActions.includes('research_application'));
    await saveProgram(pool, permittedProgram, intakeOf(permitted));
    await jobs.enqueue(permittedProgram.id, permittedProgram.assets[0]!.id, 'research_application');
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM research_jobs WHERE action='research_application'")).rows[0].n, 1);
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  }
});
