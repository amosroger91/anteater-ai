import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PassiveDnsDiscovery, SubfinderDiscovery, GitleaksAdapter, type ExecLike } from '../packages/discovery/more-adapters.js';
import { candidateJobs } from '../packages/discovery/enqueue.js';
import { toCandidates } from '../packages/discovery/index.js';
import { resolveInvocation, NUCLEI, getAdapter } from '../packages/tool-adapters/index.js';
import { TokenBucket, Concurrency, ProgramBudget, assertBodyWithinCap } from '../packages/budget/index.js';
import { redactUrl, redactHeaders, preserveEvidence, encrypt, decrypt } from '../packages/evidence/index.js';
import { remediationFor } from '../packages/remediation/index.js';
import { retest } from '../packages/findings/retest.js';
import { accessControlResponder, ACCESS_CONTROL_CONTRACT } from '../packages/fixtures-apps/index.js';

const policy = {
  programId: 'p', revision: 'r', sourceUrl: 'https://example.test/policy', reviewed: true as const,
  expiresAt: '2099-01-01T00:00:00Z', allowed: ['*.example.test'], excluded: ['secret.example.test'],
  allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1,
};

test('§1 passive DNS keeps only in-root names', async () => {
  const resolver = async () => ['api.example.test', 'cdn.vendor.test', 'bad_host'];
  const raw = await new PassiveDnsDiscovery(resolver).discover(['example.test']);
  assert.deepEqual(raw.map(r => r.host), ['api.example.test']);
});

test('§1 Subfinder/Gitleaks require an absolute pinned binary and never execute otherwise', async () => {
  const exec: ExecLike = async () => ({ stdout: '{"host":"api.example.test"}' });
  assert.deepEqual(await new SubfinderDiscovery(exec, 'SUBFINDER_BIN', {}).discover(['example.test']), []); // unset binary -> no run
  const ok = await new SubfinderDiscovery(exec, 'SUBFINDER_BIN', { SUBFINDER_BIN: '/opt/subfinder' }).discover(['example.test']);
  assert.deepEqual(ok.map(r => r.host), ['api.example.test']);
  const leaks = await new GitleaksAdapter(async () => ({ stdout: '[{"RuleID":"aws","File":"cfg"}]' }), 'GITLEAKS_BIN', { GITLEAKS_BIN: '/opt/gitleaks' }).scan('/repo');
  assert.deepEqual(leaks, [{ rule: 'aws', file: 'cfg', redacted: true }]);
});

test('§1 candidateJobs mints code-only dedupe keys and only for in-scope hosts', () => {
  const cands = toCandidates([
    { host: 'api.example.test', source: 'subfinder', confidence: 0.8 },
    { host: 'secret.example.test', source: 'subfinder', confidence: 0.8 },
  ], ['example.test']);
  const jobs = candidateJobs(cands, policy, 'inspect_http_target', 'rev1');
  assert.deepEqual(jobs.map(j => j.host), ['api.example.test']);     // excluded host not queued
  assert.ok(jobs[0]!.dedupeKey.startsWith('rev1:api.example.test:inspect_http_target:'));
});

test('§4 tool adapter requires an absolute binary and rejects shell metacharacters', () => {
  assert.throws(() => resolveInvocation(NUCLEI, { url: 'https://x.test' }, {}), /tool_binary_unset/);
  assert.throws(() => resolveInvocation(NUCLEI, { url: 'https://x.test' }, { NUCLEI_BIN: 'nuclei' }), /must_be_absolute/);
  const inv = resolveInvocation(NUCLEI, { url: 'https://x.test' }, { NUCLEI_BIN: '/opt/nuclei' });
  assert.ok(inv.args.includes('-u') && inv.args.includes('https://x.test'));
  assert.throws(() => resolveInvocation(NUCLEI, { url: 'https://x.test; rm -rf /' }, { NUCLEI_BIN: '/opt/nuclei' }), /unsafe_argument/);
  assert.equal(getAdapter('nuclei').id, 'nuclei');
});

test('§4 budgets enforce rate, concurrency and body caps', () => {
  const bucket = new TokenBucket(1, 1, 0);
  assert.equal(bucket.tryTake(0), true);
  assert.equal(bucket.tryTake(0), false);          // burst spent
  assert.equal(bucket.tryTake(1000), true);        // refilled after 1s
  const c = new Concurrency(1);
  assert.equal(c.tryAcquire(), true);
  assert.equal(c.tryAcquire(), false);
  c.release(); assert.equal(c.tryAcquire(), true);
  assert.throws(() => assertBodyWithinCap(100, 10), /body_cap_exceeded/);
  let t = 0; const budget = new ProgramBudget({ globalRatePerSec: 1, perHostRatePerSec: 1, concurrency: 2, bodyCapBytes: 1024, timeoutMs: 10000 }, () => t);
  assert.equal(budget.allow('a.example.test').ok, true); budget.done();
});

test('§5 evidence redacts secrets, hashes bodies, and round-trips encryption', () => {
  assert.equal(redactUrl('https://x.test/a?token=abc&id=1'), 'https://x.test/a?token=REDACTED&id=REDACTED');
  assert.equal(redactHeaders({ Authorization: 'Bearer x', 'X-Ok': 'y' }).Authorization, 'REDACTED');
  const rec = preserveEvidence({ method: 'GET', url: 'https://x.test/a?s=1', status: 200, headers: { 'content-type': 'application/json' }, body: 'secret', role: 'user-a', detectorVersion: 'v1' });
  assert.equal(rec.path, 'https://x.test/a?s=REDACTED');
  assert.match(rec.bodySha256, /^[0-9a-f]{64}$/);
  const keyHex = '0'.repeat(64);
  const blob = encrypt('test-user-pii', keyHex);
  assert.equal(decrypt(blob, keyHex), 'test-user-pii');
  assert.throws(() => decrypt(blob, '1'.repeat(64)), /./); // wrong key fails the auth tag
});

test('§5 remediation is deterministic and retest confirms a fix only when it no longer reproduces', async () => {
  assert.match(remediationFor('open_redirect').fix, /allow-list/);
  assert.equal(remediationFor('unknown_code').reference, 'OWASP WSTG/ASVS');
  assert.equal((await retest(ACCESS_CONTROL_CONTRACT, accessControlResponder('patched'))).fixed, true);
  assert.equal((await retest(ACCESS_CONTROL_CONTRACT, accessControlResponder('vulnerable'))).fixed, false);
});
