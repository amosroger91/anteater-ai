import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formatQueueEntry, formatSuppressedEntry, netPaidMinusInfra, payoutTier, rankScore } from '../packages/ledger/index.js';

test('payout tier follows severity, and info stays at zero even with a dollar estimate', () => {
  assert.equal(payoutTier('high', 10), 3);
  assert.equal(payoutTier('info', 5000), 0);
  assert.equal(payoutTier('informational'), 0);
  assert.equal(payoutTier(undefined, 1000), 3);
  assert.equal(payoutTier(undefined, 0), 0);
  assert.equal(rankScore(3, 0.8), 2.4);
  assert.equal(rankScore(3, Number.NaN), 1.5);
});

test('net is paid minus infra', () => {
  assert.deepEqual(netPaidMinusInfra(250, 40), { paid: 250, infra: 40, net: 210 });
  assert.deepEqual(netPaidMinusInfra(0, 0), { paid: 0, infra: 0, net: 0 });
  assert.throws(() => netPaidMinusInfra(10, -1), /ledger_refused/);
});

test('the queue printer names the finding id for finding:submit and a suppressed row has no submit command', () => {
  const lines = formatQueueEntry({
    id: '11111111-1111-1111-1111-111111111111', programId: 'h1-acme', status: 'VERIFIED', findingType: 'exposed_vcs',
    location: 'https://app.example.test/.git/config', tier: 3, confidence: 0.8, rank: 2.4, evidenceSha: 'abc123abc123ffff', evidenceSteps: 2,
  });
  assert.match(lines[0] ?? '', /dedupe=clear evidence=abc123abc123 steps=2/);
  assert.match(lines[1] ?? '', /^npm run finding:submit -- --id=11111111-1111-1111-1111-111111111111 --reviewer=$/);
  const suppressed = formatSuppressedEntry({ id: '22222222-2222-2222-2222-222222222222', programId: 'h1-acme', findingType: 'exposed_vcs', location: 'https://app.example.test/.git/config', dedupeStatus: 'prior_submission' });
  assert.match(suppressed, /dedupe=prior_submission/);
  assert.equal(suppressed.includes('finding:submit'), false);
});
