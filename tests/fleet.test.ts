import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runFleetIteration } from '../packages/operations/fleet.js';
import { netEconomics } from '../packages/metrics/index.js';

const ids = Array.from({ length: 10 }, (_, index) => `program-${index + 1}`);
const open = { globalKill: false, revokedPrograms: [] as string[], epoch: 1 };

test('a fleet pass runs every permitted program, stops on kill, and dead-letters a policy denial', async () => {
  const all = await runFleetIteration({
    programIds: ids, state: open, leaseEpoch: 1, globalTake: () => true, programTake: () => true, run: async () => {},
  });
  assert.equal(all.ran.length, 10);
  const killed = await runFleetIteration({
    programIds: ids, state: { ...open, globalKill: true }, leaseEpoch: 1, globalTake: () => true, programTake: () => true, run: async () => { throw new Error('ran'); },
  });
  assert.deepEqual(killed.ran, []);
  assert.equal(killed.skipped.every(item => item.reason === 'global_kill'), true);
  let left = 2;
  const budgeted = await runFleetIteration({
    programIds: ids, state: open, leaseEpoch: 1,
    globalTake: () => { if (left <= 0) return false; left -= 1; return true; },
    programTake: () => true, run: async () => {},
  });
  assert.equal(budgeted.ran.length, 2);
  assert.equal(budgeted.skipped.filter(item => item.reason === 'global_budget').length, 8);
  const dead: string[] = [];
  const denied = await runFleetIteration({
    programIds: ['keep', 'drop'], state: { ...open, revokedPrograms: ['revoked'] }, leaseEpoch: 1,
    globalTake: () => true, programTake: () => true,
    run: async id => { if (id === 'drop') throw new Error('policy_denied'); },
    deadLetter: async id => { dead.push(id); },
  });
  assert.deepEqual(denied.ran, ['keep']);
  assert.deepEqual(denied.deadLettered, [{ programId: 'drop', code: 'policy_denied' }]);
  assert.deepEqual(dead, ['drop']);
  const revoked = await runFleetIteration({
    programIds: ['revoked'], state: { ...open, revokedPrograms: ['revoked'] }, leaseEpoch: 1,
    globalTake: () => true, programTake: () => true, run: async () => { throw new Error('ran'); },
  });
  assert.equal(revoked.skipped[0]?.reason, 'program_revoked');
  assert.deepEqual(netEconomics({ paid: 100, humanHours: 2, hourlyRate: 50, infra: 10 }), { paid: 100, labor: 100, infra: 10, net: -10 });
});
