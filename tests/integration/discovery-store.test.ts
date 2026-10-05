import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { PERMITTED_POLICY } from '../../fixtures/automation-policy.js';
import type { Candidate } from '../../packages/discovery/index.js';
import { newlyExposed, recordObservedHosts } from '../../packages/discovery/store.js';
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

function raw(): RawProgram {
  return {
    platform: 'hackerone', handle: 'acme', name: 'acme', programUrl: 'https://hackerone.com/acme',
    sourceUrl: hackerOneProgramUrls('acme').program, policyText: PERMITTED_POLICY, submissionState: 'open',
    openScope: false, goldStandardSafeHarbor: false,
    scopes: [{ assetType: 'URL', identifier: 'https://app.example.test', eligibleForSubmission: true, eligibleForBounty: true, instruction: null }],
    exclusions: [], rate: rateRulesFromPolicy(PERMITTED_POLICY),
  };
}

function sign(program: RawProgram): IntakeApproval {
  return { ...approvalBase, sourceSha256: sha256Hex(intakeApprovalSource(program, approvalBase)) };
}

function intakeOf(compiled: { handle: string; automation: ProgramIntakeRecord['automationPolicy']; sourceSha256: string }): ProgramIntakeRecord {
  return { automationPolicy: compiled.automation, platformHandle: compiled.handle, approver: approvalBase.approver, sourceSha256: compiled.sourceSha256, approvedAt: approvalBase.approvedAt, revision: approvalBase.revision };
}

function candidate(host: string, observedAt: string): Candidate {
  return { host, source: 'cert-transparency', confidence: 0.7, relation: host === 'app.example.test' ? 'submitted' : 'subdomain', observedAt };
}

test('observed hosts keep first and last seen, and newlyExposed diffs the last two runs', async () => {
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
    const columns = await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='assets' AND column_name IN ('first_seen','last_seen','source','confidence') ORDER BY column_name`);
    assert.deepEqual(columns.rows.map(row => row.column_name), ['confidence', 'first_seen', 'last_seen', 'source']);
    assert.equal((await pool.query(`SELECT to_regclass('discovery_runs') IS NOT NULL AS present`)).rows[0].present, true);

    const programRaw = raw();
    const compiled = compileIntake(programRaw, sign(programRaw));
    const program = compiled.programs[0];
    assert.ok(program);
    await saveProgram(pool, program, intakeOf(compiled));

    await assert.rejects(recordObservedHosts(pool, program.id, [candidate('not a host', '2026-10-05T00:00:00.000Z')]), /invalid_candidate/);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM discovery_runs')).rows[0].n, 0);

    await recordObservedHosts(pool, program.id, [
      candidate('app.example.test', '2026-10-05T00:00:00.000Z'),
      candidate('staging.example.test', '2026-10-05T00:00:00.000Z'),
      candidate('secret.example.test', '2026-10-05T00:00:00.000Z'),
    ]);
    assert.deepEqual(await newlyExposed(pool, program.id), ['app.example.test', 'secret.example.test', 'staging.example.test']);
    const known = (await pool.query(`SELECT active, first_seen FROM assets WHERE program_id=$1 AND url='https://app.example.test'`, [program.id])).rows[0];
    assert.equal(known.active, true);
    assert.ok(known.first_seen);
    const held = (await pool.query(`SELECT active, source, confidence FROM assets WHERE program_id=$1 AND url='https://secret.example.test'`, [program.id])).rows[0];
    assert.equal(held.active, false);
    assert.equal(held.source, 'cert-transparency');
    assert.equal(Number(held.confidence), 0.7);

    await recordObservedHosts(pool, program.id, [
      candidate('app.example.test', '2026-10-06T00:00:00.000Z'),
      candidate('staging.example.test', '2026-10-06T00:00:00.000Z'),
      candidate('secret.example.test', '2026-10-06T00:00:00.000Z'),
      candidate('outside.example', '2026-10-06T00:00:00.000Z'),
    ]);
    assert.deepEqual(await newlyExposed(pool, program.id), ['outside.example']);
    const seen = (await pool.query(`SELECT first_seen, last_seen FROM assets WHERE program_id=$1 AND url='https://staging.example.test'`, [program.id])).rows[0];
    assert.equal(new Date(seen.first_seen).toISOString(), '2026-10-05T00:00:00.000Z');
    assert.equal(new Date(seen.last_seen).toISOString(), '2026-10-06T00:00:00.000Z');
    assert.equal((await pool.query(`SELECT count(*)::int AS n FROM research_jobs`)).rows[0].n, 0);
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  }
});
