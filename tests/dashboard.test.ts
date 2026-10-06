import { test } from 'node:test';
import assert from 'node:assert/strict';
import type pg from 'pg';
import { dashboardState } from '../apps/dashboard/service.js';

type FakeRows = { rows: unknown[] };
const okPool = {
  async query(sql: string): Promise<FakeRows> {
    if (sql.includes('FROM programs')) return { rows: [{ n: 3 }] };
    if (sql.includes('FROM assets')) return { rows: [{ n: 7 }] };
    if (sql.includes('FROM research_jobs')) return { rows: [{ k: 'queued', n: 2 }, { k: 'completed', n: 5 }] };
    if (sql.includes('FROM observations')) return { rows: [{ n: 4 }] };
    if (sql.includes('FROM findings')) return { rows: [{ k: 'OBSERVATION', n: 1 }, { k: 'VERIFIED', n: 0 }] };
    if (sql.includes('FROM submissions')) return { rows: [{ k: 'submitted', n: 1 }] };
    return { rows: [] };
  },
} as unknown as Pick<pg.Pool, 'query'>;

test('dashboardState maps counts and status groups from the database', async () => {
  const s = await dashboardState(okPool);
  assert.equal(s.programs, 3);
  assert.equal(s.assets, 7);
  assert.deepEqual(s.jobs, { queued: 2, completed: 5 });
  assert.equal(s.observations, 4);
  assert.deepEqual(s.findings, { OBSERVATION: 1, VERIFIED: 0 });
  assert.deepEqual(s.submissions, { submitted: 1 });
  assert.match(s.generatedAt, /^\d{4}-\d{2}-\d{2}T/);
});

test('a missing/unreachable table yields zeros instead of crashing', async () => {
  const brokenPool = { async query(): Promise<FakeRows> { throw new Error('relation does not exist'); } } as unknown as Pick<pg.Pool, 'query'>;
  const s = await dashboardState(brokenPool);
  assert.equal(s.programs, 0);
  assert.equal(s.assets, 0);
  assert.deepEqual(s.jobs, {});
  assert.deepEqual(s.findings, {});
  assert.deepEqual(s.submissions, {});
});
