import { test } from 'node:test';
import assert from 'node:assert/strict';
import { autoIntakeHackerOne, autoApproval } from '../packages/program-intake/auto.js';
import { compileIntake, jobsForIntake } from '../packages/program-intake/index.js';
import type { FetchLike } from '../packages/program-intake/hackerone.js';

// A HackerOne hacker-API stub: routes by pathname and returns JSON:API shapes fetchProgram expects.
function program(handle: string, policy: string, assetHost: string) {
  return {
    [`/v1/hackers/programs/${handle}`]: { data: { type: 'program', attributes: {
      handle, name: handle, policy, submission_state: 'open', open_scope: true, gold_standard_safe_harbor: true } } },
    [`/v1/hackers/programs/${handle}/structured_scopes`]: { data: [{ type: 'structured-scope', attributes: {
      asset_type: 'url', asset_identifier: assetHost, eligible_for_submission: true, eligible_for_bounty: true, instruction: null } }], links: { next: null } },
    [`/v1/hackers/programs/${handle}/scope_exclusions`]: { data: [], links: { next: null } },
  };
}

const routes: Record<string, unknown> = {
  ...program('good-co', 'Testing allowed. Automated tools are allowed. Please be reasonable.', 'app.good-co.test'),
  ...program('noauto-co', 'No automated scanning. Manual testing only.', 'app.noauto-co.test'),
};

const stub: FetchLike = async (url) => {
  const path = new URL(url).pathname;
  const body = routes[path];
  if (body === undefined) return { ok: false, status: 404, async text() { return '{}'; } };
  return { ok: true, status: 200, async text() { return JSON.stringify(body); } };
};

test('auto-approval compiles a chosen program with no human sign-off', async () => {
  const { compiled, skipped } = await autoIntakeHackerOne({ authorization: 'Basic x', handles: ['good-co'], fetchLike: stub });
  assert.equal(skipped.length, 0);
  assert.equal(compiled.length, 1);
  const program = compiled[0]!.programs[0]!;
  assert.equal(program.id, 'h1-good-co');
  assert.deepEqual(program.assets.map(a => a.url), ['https://app.good-co.test']);
  // Passive jobs are produced; the automation gate lets a permitted program also allow research.
  assert.ok(jobsForIntake(compiled[0]!, 'inspect_http_target').length === 1);
  assert.ok(jobsForIntake(compiled[0]!, 'research_application').length === 1);
});

test('a program that forbids automated scanning is refused automatically', async () => {
  const { compiled, skipped } = await autoIntakeHackerOne({ authorization: 'Basic x', handles: ['noauto-co'], fetchLike: stub });
  assert.equal(compiled.length, 0);
  assert.deepEqual(skipped, [{ handle: 'noauto-co', reason: 'prohibited' }]);
});

test('mixed handles: the permitted program is taken, the prohibited one skipped', async () => {
  const { compiled, skipped } = await autoIntakeHackerOne({ authorization: 'Basic x', handles: ['good-co', 'noauto-co'], fetchLike: stub });
  assert.deepEqual(compiled.flatMap(c => c.programs.map(p => p.id)), ['h1-good-co']);
  assert.deepEqual(skipped.map(s => s.handle), ['noauto-co']);
});

test('empty handle list is refused (never discovers programs on its own)', async () => {
  await assert.rejects(autoIntakeHackerOne({ authorization: 'Basic x', handles: [], fetchLike: stub }), /no_handles/);
});

test('autoApproval binds to the exact scope so a changed program must be re-reviewed', () => {
  const raw = {
    platform: 'hackerone' as const, handle: 'good-co', name: 'good-co', programUrl: 'https://hackerone.com/good-co',
    sourceUrl: 'https://api.hackerone.com/v1/hackers/programs/good-co', policyText: 'Automated tools are allowed.',
    submissionState: 'open', openScope: true, goldStandardSafeHarbor: true,
    scopes: [{ assetType: 'url', identifier: 'app.good-co.test', eligibleForSubmission: true, eligibleForBounty: true, instruction: null }],
    exclusions: [], rate: { requestsPerSecond: 1, published: null },
  };
  const at = Date.UTC(2026, 0, 1);
  const a1 = autoApproval(raw, 'hackerone-api', at);
  const a2 = autoApproval(raw, 'hackerone-api', at);
  assert.match(a1.sourceSha256, /^[0-9a-f]{64}$/);
  assert.equal(a1.sourceSha256, a2.sourceSha256);                                   // deterministic for a given scope
  const changed = autoApproval({ ...raw, policyText: 'Automated tools are allowed. Scope expanded.' }, 'hackerone-api', at);
  assert.notEqual(changed.sourceSha256, a1.sourceSha256);                           // changed scope ⇒ new hash ⇒ re-review
});
