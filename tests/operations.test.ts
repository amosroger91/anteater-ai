import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canProceed, retentionPlan, classifyFailure, type RevocationState } from '../packages/operations/index.js';
import { retentionDays } from '../packages/operations/retention.js';

test('retention rejects invalid windows rather than accepting destructive defaults', () => {
  for (const value of [0, -1, 0.5, Infinity, NaN, '', 'oops']) assert.throws(() => retentionDays(value), /invalid_retention_days/);
  assert.equal(retentionDays('90'), 90);
});

const base: RevocationState = { globalKill: false, revokedPrograms: [], epoch: 5 };

test('global kill, program revocation, and epoch bump each stop in-flight work', () => {
  assert.equal(canProceed(base, 'p1', 5).ok, true);
  assert.equal(canProceed({ ...base, globalKill: true }, 'p1', 5).reason, 'global_kill');
  assert.equal(canProceed({ ...base, revokedPrograms: ['p1'] }, 'p1', 5).reason, 'program_revoked');
  // a lease minted at epoch 4 is superseded once the fleet epoch is bumped to 5
  assert.equal(canProceed(base, 'p1', 4).reason, 'lease_superseded_by_revocation');
});

test('retention deletes aged records, keeps fresh, and never auto-deletes an unclassified class', () => {
  const day = 86_400_000, now = Date.now();
  const rec = (id: string, dataClass: string, ageDays: number) => ({ id, dataClass, createdAt: new Date(now - ageDays * day).toISOString() });
  const plan = retentionPlan([
    rec('old', 'evidence', 400), rec('fresh', 'evidence', 5), rec('mystery', 'unknown-class', 999),
  ], { evidence: 90 }, now);
  assert.deepEqual(plan.remove, ['old']);
  assert.ok(plan.keep.includes('fresh') && plan.keep.includes('mystery'));
  assert.deepEqual(plan.unclassified, ['mystery']);
});

test('non-retryable scope errors dead-letter immediately; transient retries until exhausted', () => {
  assert.equal(classifyFailure(0, 3, 'out_of_scope').disposition, 'dead_letter');
  assert.equal(classifyFailure(1, 3, 'timeout').disposition, 'retry');
  assert.equal(classifyFailure(3, 3, 'timeout').disposition, 'dead_letter');
});
