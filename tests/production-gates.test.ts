import { test } from 'node:test';
import assert from 'node:assert/strict';
import { campaignSource, compileDomains } from '../packages/application-research/intake.js';
import { mutatingGet, underPath, ApplicationSchema } from '../packages/application-research/profile.js';
import { allowedRequest } from '../packages/application-research/transport.js';
import { cleanupAccepted } from '../packages/application-research/verification.js';
import { sha256Hex } from '../packages/provenance/index.js';
import { retryableTransportError } from '../packages/web-executor/index.js';
import { retest } from '../packages/findings/retest.js';
import { GitleaksAdapter } from '../packages/discovery/more-adapters.js';
import { NUCLEI, resolveInvocation } from '../packages/tool-adapters/index.js';
import { guardModelContext } from '../packages/inert/index.js';
import { deletableRetentionIds } from '../packages/operations/index.js';

const base = {
  revision: '2026-10', reviewed: true as const, sourceUrl: 'https://example.test/policy', expiresAt: '2099-01-01T00:00:00.000Z',
  allowed: ['example.test', '*.example.test'], excluded: ['secret.example.test'],
  application: { readPathPrefixes: ['/', '/api'] },
  approval: { approver: 'ada', sourceSha256: '0'.repeat(64), approvedAt: '2020-01-01T00:00:00.000Z' },
};

function approve<T extends { approval: { sourceSha256: string } }>(raw: T): T {
  const draft = { ...raw, approval: { ...raw.approval, sourceSha256: '0'.repeat(64) } };
  return { ...draft, approval: { ...draft.approval, sourceSha256: sha256Hex(campaignSource(draft)) } };
}

test('root is one document and state-changing GET segments stay blocked', () => {
  assert.equal(underPath('/', '/'), true);
  assert.equal(underPath('/login', '/'), false);
  assert.equal(underPath('/api/documents', '/api'), true);
  assert.equal(underPath('/apiv2', '/api'), false);
  assert.equal(mutatingGet('/delete-account'), true);
  assert.equal(mutatingGet('/api/users/remove-me'), true);
  assert.equal(mutatingGet('/api/documents'), false);
  const narrow = ApplicationSchema.parse({});
  assert.equal(allowedRequest('https://lab.example.test', narrow, 'https://lab.example.test/', 'GET', 'discover'), true);
  assert.equal(allowedRequest('https://lab.example.test', narrow, 'https://lab.example.test/login', 'GET', 'discover'), false);
  assert.equal(allowedRequest('https://lab.example.test', narrow, 'https://lab.example.test/delete-account', 'GET', 'discover'), false);
});

test('cleanup accepts 404 only when create did not succeed', () => {
  assert.equal(cleanupAccepted(true, 204), true);
  assert.equal(cleanupAccepted(true, 404), false);
  assert.equal(cleanupAccepted(false, 404), true);
  assert.equal(cleanupAccepted(false, 500), false);
});

test('campaign load admits one exact host and requires the approval hash', () => {
  const signed = approve(base);
  const { programs, held } = compileDomains(['app.example.test', 'example.test', 'secret.example.test', 'other.test'], signed);
  assert.deepEqual(held, ['secret.example.test', 'other.test']);
  assert.deepEqual(programs.map(program => program.policy.allowed), [['app.example.test'], ['example.test']]);
  assert.ok(programs.every(program => program.policy.allowedPaths.includes('/') && program.policy.allowedPaths.includes('/api')));
  assert.throws(() => compileDomains(['example.test'], { ...signed, expiresAt: '2098-01-01T00:00:00.000Z' }), /source_hash_mismatch/);
  assert.throws(() => compileDomains(['example.test'], approve({ ...base, application: { readPathPrefixes: ['/login'] } })), /root_path_required/);
});

test('transport failures retry and an outage is not a fix', async () => {
  assert.equal(retryableTransportError({ error: 'econnreset' }), 'econnreset');
  assert.equal(retryableTransportError({ status: 200 }), undefined);
  const contract = { findingType: 'demo', steps: [{ id: 'read', expectStatus: 200, expectBodyIncludes: ['secret'] }], counterTest: { id: 'control', expectStatus: 403 }, repeatCount: 1 };
  const outage = await retest(contract, async () => { throw new Error('offline'); });
  assert.equal(outage.fixed, false);
  assert.equal(outage.reason, 'step_unavailable');
  const controlFailed = await retest(contract, async step => step === 'read' ? { status: 200, body: 'secret-data' } : { status: 200, body: 'open' });
  assert.equal(controlFailed.fixed, false);
  assert.equal(controlFailed.reason, 'counter_test_failed');
  assert.equal((await retest(contract, async step => step === 'read' ? { status: 404, body: 'gone' } : { status: 403, body: 'denied' })).fixed, true);
});

test('gitleaks findings survive a non-zero exit and nuclei stays on the passive allowlist', async () => {
  const found = await new GitleaksAdapter(async () => { throw Object.assign(new Error('leaks'), { stdout: '[{"RuleID":"aws","File":"cfg"}]' }); }, 'GITLEAKS_BIN', { GITLEAKS_BIN: '/opt/gitleaks' }).scan('/repo');
  assert.deepEqual(found, [{ rule: 'aws', file: 'cfg', redacted: true }]);
  assert.deepEqual(await new GitleaksAdapter(async () => { throw new Error('broken'); }, 'GITLEAKS_BIN', { GITLEAKS_BIN: '/opt/gitleaks' }).scan('/repo'), []);
  const invocation = resolveInvocation(NUCLEI, { url: 'https://app.example.test' }, { NUCLEI_BIN: '/opt/nuclei' });
  assert.ok(invocation.args.includes('-disable-redirects'));
  assert.deepEqual(invocation.args.slice(invocation.args.indexOf('-tags'), invocation.args.indexOf('-tags') + 2), ['-tags', 'ssl,misconfig,exposure,tech']);
  assert.throws(() => resolveInvocation(NUCLEI, { url: 'https://app.example.test', tags: 'cve' }, { NUCLEI_BIN: '/opt/nuclei' }), /nuclei_tags_not_allowlisted/);
});

test('secret redaction is stable across calls and cited observations are kept', () => {
  const text = 'password=one and password=two';
  const first = guardModelContext(text);
  const second = guardModelContext(text);
  assert.equal(first.redacted, second.redacted);
  assert.equal(first.redacted.includes('password='), false);
  const removable = deletableRetentionIds(['observations:cited', 'observations:old', 'dead_letter:gone', 'programs:nope'], new Set(['cited']));
  assert.deepEqual(removable, ['observations:old', 'dead_letter:gone']);
});
