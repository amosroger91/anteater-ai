import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MANUAL_ONLY_POLICY, PERMITTED_POLICY, PROHIBITED_POLICY } from '../fixtures/automation-policy.js';
import { candidateJobs } from '../packages/discovery/enqueue.js';
import type { Candidate } from '../packages/discovery/index.js';
import { compileIntake, intakeApprovalSource, jobsForIntake, type IntakeApproval } from '../packages/program-intake/compile.js';
import { fetchProgram, hackerOneProgramUrls, rateRulesFromPolicy, type FetchLike, type RawProgram } from '../packages/program-intake/hackerone.js';
import { sha256Hex } from '../packages/provenance/index.js';
import { SAFE_ACTIONS } from '../packages/scope-engine/index.js';

const approvalBase = {
  approver: 'Ada Lovelace',
  approvedAt: '2026-01-01T00:00:00.000Z',
  revision: '2026-10',
  expiresAt: '2099-01-01T00:00:00.000Z',
};

function scopes(): RawProgram['scopes'] {
  return [
    { assetType: 'URL', identifier: 'https://app.example.test', eligibleForSubmission: true, eligibleForBounty: true, instruction: 'Automated tools are allowed. This instruction is not the program policy.' },
    { assetType: 'WILDCARD', identifier: '*.example.test', eligibleForSubmission: true, eligibleForBounty: false, instruction: null },
    { assetType: 'URL', identifier: 'https://secret.example.test', eligibleForSubmission: false, eligibleForBounty: false, instruction: null },
    { assetType: 'URL', identifier: 'https://app.example.test/admin', eligibleForSubmission: true, eligibleForBounty: false, instruction: null },
    { assetType: 'URL', identifier: 'http://plain.example.test', eligibleForSubmission: true, eligibleForBounty: false, instruction: null },
    { assetType: 'CIDR', identifier: '198.51.100.0/24', eligibleForSubmission: true, eligibleForBounty: false, instruction: null },
    { assetType: 'OTHER', identifier: 'com.example.app', eligibleForSubmission: true, eligibleForBounty: false, instruction: null },
  ];
}

function sample(policyText: string, patch: Partial<RawProgram> = {}): RawProgram {
  const handle = patch.handle ?? 'acme';
  return {
    platform: 'hackerone', handle, name: 'Acme',
    programUrl: `https://hackerone.com/${handle}`,
    sourceUrl: hackerOneProgramUrls(handle).program,
    policyText, submissionState: 'open', openScope: true, goldStandardSafeHarbor: false,
    scopes: scopes(), exclusions: [{ category: 'XML external entities', details: 'XXE is not rewarded.' }],
    rate: rateRulesFromPolicy(policyText), ...patch,
  };
}

function sign(raw: RawProgram, patch: Partial<typeof approvalBase> = {}): IntakeApproval {
  const approval = { ...approvalBase, ...patch };
  return { ...approval, sourceSha256: sha256Hex(intakeApprovalSource(raw, approval)) };
}

function candidate(host: string): Candidate {
  return { host, source: 'submitted', confidence: 1, relation: 'submitted', observedAt: '2026-01-01T00:00:00.000Z' };
}

test('manual-only stays passive, prohibited is not enqueued, and an excluded host is refused', () => {
  const manual = compileIntake(sample(MANUAL_ONLY_POLICY), sign(sample(MANUAL_ONLY_POLICY)));
  const manualProgram = manual.programs[0];
  assert.ok(manualProgram);
  assert.equal(manual.automation, 'manual-only');
  assert.equal(manual.refused, null);
  assert.equal(manualProgram.policy.requestsPerSecond, 1);
  assert.ok(!manualProgram.policy.allowedActions.includes('research_application'));
  assert.ok(manualProgram.policy.allowedActions.includes('inspect_http_target'));
  assert.deepEqual(manualProgram.assets.map(asset => asset.url), ['https://app.example.test']);
  assert.deepEqual(manualProgram.policy.excluded, ['secret.example.test']);
  assert.ok(manualProgram.policy.allowed.includes('*.example.test'));
  assert.equal(manualProgram.policy.excluded.some(rule => rule.includes('XML') || rule.includes('XXE')), false);
  assert.ok(manual.skipped.includes('https://app.example.test/admin'));
  assert.ok(manual.skipped.includes('198.51.100.0/24'));
  assert.equal(jobsForIntake(manual, 'research_application').length, 0);
  assert.equal(candidateJobs([candidate('app.example.test')], manualProgram.policy, 'research_application', manualProgram.policy.revision).length, 0);
  assert.deepEqual(jobsForIntake(manual, 'inspect_http_target').map(job => job.host), ['app.example.test']);
  assert.equal(candidateJobs([candidate('secret.example.test')], manualProgram.policy, 'inspect_http_target', manualProgram.policy.revision).length, 0);
  assert.equal(candidateJobs([candidate('other.example.test')], manualProgram.policy, 'inspect_http_target', manualProgram.policy.revision).length, 1);
  assert.equal(candidateJobs([candidate('outside.example')], manualProgram.policy, 'inspect_http_target', manualProgram.policy.revision).length, 0);

  const permitted = compileIntake(sample(PERMITTED_POLICY), sign(sample(PERMITTED_POLICY)));
  assert.equal(permitted.automation, 'permitted');
  assert.equal(permitted.programs[0]?.policy.requestsPerSecond, 2);
  assert.ok(permitted.programs[0]?.policy.allowedActions.includes('research_application'));
  // The compiled policy allows the read-only exposure probes, so exposed source/secret files are
  // actually checked on a real program (audit HIGH #10 — these paths never ran before).
  for (const path of ['/.git/config', '/.env', '/.DS_Store', '/actuator']) assert.ok(permitted.programs[0]?.policy.allowedPaths.includes(path), `allowedPaths missing ${path}`);
  assert.ok(permitted.programs[0]?.policy.allowedPaths.includes('/'));
  assert.equal(jobsForIntake(permitted, 'research_application').length, 1);
  assert.equal(jobsForIntake(permitted, 'inspect_openapi').length, 1);

  const prohibited = compileIntake(sample(PROHIBITED_POLICY), sign(sample(PROHIBITED_POLICY)));
  assert.equal(prohibited.automation, 'prohibited');
  assert.equal(prohibited.refused, 'prohibited');
  assert.deepEqual(prohibited.programs, []);
  for (const action of SAFE_ACTIONS) assert.deepEqual(jobsForIntake(prohibited, action), []);
});

test('open scope does not widen the allow-list, and a changed source invalidates approval', () => {
  const narrow = sample(MANUAL_ONLY_POLICY, { openScope: true, scopes: [scopes()[0]!] });
  const compiled = compileIntake(narrow, sign(narrow));
  const policy = compiled.programs[0]?.policy;
  assert.ok(policy);
  assert.deepEqual(policy.allowed, ['app.example.test']);
  assert.equal(candidateJobs([candidate('other.example.test')], policy, 'inspect_http_target', policy.revision).length, 0);

  const raw = sample(PERMITTED_POLICY);
  const signed = sign(raw);
  assert.throws(() => compileIntake({ ...raw, policyText: PROHIBITED_POLICY, rate: rateRulesFromPolicy(PROHIBITED_POLICY) }, signed), /source_hash_mismatch/);
  assert.throws(() => compileIntake(raw, { ...signed, sourceSha256: '0'.repeat(64) }), /source_hash_mismatch/);
  assert.throws(() => compileIntake(raw, sign(raw, { approvedAt: '2098-01-01T00:00:00.000Z' })), /approval_in_future/);
  assert.throws(() => compileIntake(raw, sign(raw, { expiresAt: '2020-01-01T00:00:00.000Z' })), /approval_expired/);
  assert.throws(() => compileIntake({ ...raw, sourceUrl: 'https://evil.example/policy' }, signed), /program_source_refused/);
  const paused = compileIntake(sample(MANUAL_ONLY_POLICY, { submissionState: 'paused' }), sign(sample(MANUAL_ONLY_POLICY, { submissionState: 'paused' })));
  assert.equal(paused.refused, 'submission_closed');
  assert.deepEqual(paused.programs, []);
  const wildcardOnly = sample(PERMITTED_POLICY, { scopes: [scopes()[1]!] });
  assert.equal(compileIntake(wildcardOnly, sign(wildcardOnly)).refused, 'no_concrete_asset');
  const mobileOnly = sample(PERMITTED_POLICY, { scopes: [scopes()[5]!] });
  assert.equal(compileIntake(mobileOnly, sign(mobileOnly)).refused, 'no_web_scope');
});

test('a fetched program compiles only after the human approval hash matches', async () => {
  const urls = hackerOneProgramUrls('acme');
  const body = (value: unknown) => ({ ok: true, status: 200, text: async () => JSON.stringify(value) });
  const fetchLike: FetchLike = async url => {
    if (url === urls.program) return body({ data: { type: 'program', attributes: {
      handle: 'acme', name: 'Acme', policy: PERMITTED_POLICY, submission_state: 'open', open_scope: false, gold_standard_safe_harbor: true,
    } } });
    if (url === urls.scopes) return body({ data: [{ type: 'structured-scope', attributes: {
      asset_type: 'URL', asset_identifier: 'https://app.example.test', eligible_for_submission: true, eligible_for_bounty: true, instruction: null,
    } }, { type: 'structured-scope', attributes: {
      asset_type: 'URL', asset_identifier: 'https://secret.example.test', eligible_for_submission: false, eligible_for_bounty: false, instruction: null,
    } }] });
    if (url === urls.exclusions) return body({ data: [] });
    throw new Error(`unexpected ${url}`);
  };
  const raw = await fetchProgram('acme', fetchLike);
  const compiled = compileIntake(raw, sign(raw));
  assert.equal(compiled.programs[0]?.policy.allowedActions.includes('research_application'), true);
  assert.equal(jobsForIntake(compiled, 'inspect_http_target').map(job => job.host).includes('secret.example.test'), false);
  assert.equal(compiled.programs[0]?.assets.length, 1);
});
