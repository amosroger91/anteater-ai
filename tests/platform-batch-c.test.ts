import { test } from 'node:test';
import assert from 'node:assert/strict';
import { appendEvent, verifyChain, type AuditRecord } from '../packages/audit/index.js';
import { computeAlerts, DEFAULT_THRESHOLDS } from '../packages/metrics/index.js';
import { RevocationStore } from '../packages/operations/store.js';
import { sanitize, guardModelContext } from '../packages/inert/index.js';
import { moduleAuthorized, analyzeIamPolicy, analyzeK8sManifest, scanSecrets } from '../packages/modules/index.js';

test('§7 audit chain detects tampering with any record', () => {
  const chain: AuditRecord[] = [];
  chain.push(appendEvent(chain, { event: 'policy_approved', who: 'alice' }));
  chain.push(appendEvent(chain, { event: 'job_started', job: 'j1' }));
  chain.push(appendEvent(chain, { event: 'job_completed', job: 'j1' }));
  assert.deepEqual(verifyChain(chain), { ok: true, brokenAt: -1 });
  const tampered = structuredClone(chain);
  tampered[1] = { ...tampered[1]!, event: { event: 'job_started', job: 'ATTACKER' } };
  assert.equal(verifyChain(tampered).ok, false);
  assert.equal(verifyChain(tampered).brokenAt, 1);
});

test('§7 metrics fire alerts only above threshold', () => {
  const quiet = { queueAgeSeconds: 10, coverageGaps: 0, rateLimitHits: 0, toolFailures: 0, mailboxFailures: 0, deadLettered: 0 };
  assert.deepEqual(computeAlerts(quiet), []);
  const noisy = { ...quiet, queueAgeSeconds: 5000, toolFailures: 9, deadLettered: 3 };
  const codes = computeAlerts(noisy, DEFAULT_THRESHOLDS).map(a => a.code).sort();
  assert.deepEqual(codes, ['deadLettered', 'queueAgeSeconds', 'toolFailures']);
});

test('§7 revocation store: kill, program revoke, and epoch bump each stop work via canProceed', () => {
  const store = new RevocationStore();
  assert.equal(store.check('p1', store.epoch).ok, true);
  const lease = store.epoch;
  store.bumpEpoch();
  assert.equal(store.check('p1', lease).reason, 'lease_superseded_by_revocation');
  store.revoke('p2');
  assert.equal(store.check('p2', store.epoch).reason, 'program_revoked');
  store.kill();
  assert.equal(store.check('p1', store.epoch).reason, 'global_kill');
});

test('§7 inert: scripts/handlers stripped, secrets kept out of model context', () => {
  const dirty = `<div onclick="steal()">hi</div><script>evil()</script><a href="javascript:x()">y</a>`;
  const clean = sanitize(dirty);
  assert.ok(!/script|onclick|javascript:/i.test(clean));
  const guard = guardModelContext('user token Bearer abcdef123456 and AKIAIOSFODNN7EXAMPLE');
  assert.equal(guard.safe, false);
  assert.ok(guard.hits.includes('aws_access_key') && guard.hits.includes('bearer_token'));
  assert.ok(!/AKIAIOSFODNN7EXAMPLE/.test(guard.redacted));
});

test('§6 module authorization: a web policy authorizes no module; an explicit profile does', () => {
  assert.equal(moduleAuthorized({ reviewed: true, allowed: ['*.example.test'] }, 'cloud'), false);
  assert.equal(moduleAuthorized({ reviewed: true, modules: ['cloud'] }, 'cloud'), true);
  assert.equal(moduleAuthorized({ reviewed: true, modules: ['cloud'] }, 'k8s'), false);
});

test('§6 analyzers flag over-permissive IAM, unsafe k8s, and exposed secrets', () => {
  assert.ok(analyzeIamPolicy({ Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }).some(f => f.code === 'iam_admin_wildcard'));
  assert.deepEqual(analyzeIamPolicy({ Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:...' }] }), []);
  const k8s = analyzeK8sManifest({ spec: { hostNetwork: true, containers: [{ name: 'c', securityContext: { privileged: true, runAsUser: 0 } }], volumes: [{ hostPath: { path: '/' } }] } });
  assert.ok(k8s.some(f => f.code === 'k8s_privileged') && k8s.some(f => f.code === 'k8s_host_path') && k8s.some(f => f.code === 'k8s_no_limits'));
  assert.ok(scanSecrets('DB_PASSWORD=hunter2supersecret').some(f => f.code.startsWith('secret_')));
  assert.deepEqual(scanSecrets('DEBUG=true'), []);
});
