import { test } from 'node:test';
import assert from 'node:assert/strict';
import { transition, replay, verifyCandidate, dedupeFindings, duplicateReason, severityTier, buildChain, chainSeverity, type Responder, type Finding } from '../packages/findings/index.js';

test('scanners and models cannot reach VERIFIED or SUBMITTED', () => {
  assert.equal(transition('VERIFICATION', 'VERIFIED', 'model').ok, false);
  assert.equal(transition('VERIFICATION', 'VERIFIED', 'scanner').ok, false);
  assert.equal(transition('VERIFIED', 'SUBMITTED', 'model').ok, false);
  assert.equal(transition('VERIFICATION', 'VERIFIED', 'verifier').ok, true);
  assert.equal(transition('VERIFIED', 'SUBMITTED', 'human').ok, true);
});

test('illegal transitions are rejected regardless of actor', () => {
  assert.equal(transition('OBSERVATION', 'VERIFIED', 'verifier').ok, false);
  assert.equal(transition('SUBMITTED', 'CANDIDATE', 'human').ok, false);
  assert.equal(transition('CANDIDATE', 'HUMAN_REVIEW', 'model').ok, true);
});

// Attack step: stranger reads victim's resource. Control: stranger stays denied (403) elsewhere.
const contract = {
  findingType: 'cross_account_read',
  steps: [{ id: 'attack', expectStatus: 200, expectBodyIncludes: ['secret-token'] }],
  counterTest: { id: 'control', expectStatus: 403 },
  repeatCount: 2,
};

test('replay reproduces when the attack leaks AND the control holds', async () => {
  const vulnerable: Responder = async (id) => id === 'attack'
    ? { status: 200, body: '{"data":"secret-token"}' }
    : { status: 403, body: 'forbidden' };                 // control: stranger properly denied
  assert.equal((await replay(contract, vulnerable)).reproduced, true);
});

test('replay does NOT reproduce when the control also leaks (not isolable)', async () => {
  const everyoneLeaks: Responder = async () => ({ status: 200, body: '{"data":"secret-token"}' });
  const out = await replay(contract, everyoneLeaks);
  assert.equal(out.reproduced, false);
  assert.match(out.reason, /counter_test_failed/);
});

test('replay fails closed when the attack step is flaky across iterations', async () => {
  let n = 0;
  const flaky: Responder = async (id) => {
    if (id === 'control') return { status: 403, body: 'forbidden' };
    n++; return n <= 1 ? { status: 200, body: 'secret-token' } : { status: 403, body: 'rotated' };
  };
  assert.equal((await replay(contract, flaky)).reproduced, false);
});

test('verifyCandidate reaches VERIFIED only through a reproduced replay, else HUMAN_REVIEW', async () => {
  const good: Responder = async (id) => id === 'attack' ? { status: 200, body: 'secret-token' } : { status: 403, body: 'no' };
  const patched: Responder = async () => ({ status: 403, body: 'forbidden' });
  const ok = await verifyCandidate('CANDIDATE', contract, good);
  assert.equal(ok.next, 'VERIFIED');
  assert.equal(ok.transition.ok, true);
  const no = await verifyCandidate('CANDIDATE', contract, patched);
  assert.equal(no.next, 'HUMAN_REVIEW');
});

test('dedupe collapses same type+location', () => {
  const f = (id: string, loc: string): Finding => ({ id, type: 'missing_hsts', location: loc, severity: 'medium' });
  assert.equal(dedupeFindings([f('1', '/a'), f('2', '/a'), f('3', '/b')]).length, 2);
});

test('chain severity is the deterministic member max and cannot be raised by a suggested order', () => {
  const members: Finding[] = [
    { id: 'a', type: 'info-leak', location: '/x', severity: 'low' },
    { id: 'b', type: 'idor', location: '/y', severity: 'high' },
  ];
  assert.equal(chainSeverity(members), 'high');
  const chain = buildChain(members, ['b', 'a']);        // model-suggested order accepted
  assert.deepEqual(chain.members, ['b', 'a']);
  assert.equal(chain.severity, 'high');                  // but severity still the member max, not inflated
  const ignored = buildChain(members, ['b']);            // invalid suggestion ignored
  assert.deepEqual(ignored.members, ['a', 'b']);
});

test('a prior submission or known issue suppresses the same lead, and another program does not', () => {
  const finding = { programId: 'h1-acme', type: 'exposed_vcs', location: 'https://app.example.test/.git/config' };
  const sent = [{ programId: 'h1-acme', type: 'exposed_vcs', location: 'https://app.example.test/.git/config' }];
  const known = [{ programId: 'h1-acme', type: 'exposed_admin', location: 'https://app.example.test/admin' }];
  assert.equal(duplicateReason(finding, sent, known), 'prior_submission');
  assert.equal(duplicateReason({ ...finding, type: 'exposed_admin', location: 'https://app.example.test/admin' }, [], known), 'known_issue');
  assert.equal(duplicateReason({ ...finding, programId: 'h1-other' }, sent, known), null);
  assert.equal(duplicateReason({ ...finding, location: 'https://app.example.test/.env' }, sent, known), null);
  assert.equal(severityTier('high'), 3);
  assert.equal(severityTier('info'), 0);
  assert.equal(severityTier('informational'), 0);
  assert.equal(severityTier('weird'), null);
});
