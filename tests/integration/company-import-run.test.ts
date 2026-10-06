import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { CompanyImportService } from '../../apps/setup/company-import.js';
import { blankProfile } from '../../packages/setup/profile.js';
import { connect, migrate } from '../../packages/research-state/db.js';
import { loadConfig } from '../../packages/shared/config.js';
import { PolicySchema } from '../../packages/scope-engine/index.js';
import { evaluatePreflight } from '../../packages/preflight/index.js';
import type { FetchLike } from '../../packages/program-intake/hackerone.js';

// The two-button turnkey flow, end to end against a real database: importing a company through the
// setup UI must (1) save the program AND queue a passive job for each in-scope asset, so the engine
// actually tests it when `auto` runs, and (2) satisfy the readiness gate with no programs/handles.txt
// at all. These were the integration seams between "press import" and "press go".

const reply = (body: unknown) => ({ ok: true, status: 200, text: async () => JSON.stringify(body) });
const listed = (handle: string) => ({ type: 'program', attributes: { handle, name: handle, submission_state: 'open' } });
const api: FetchLike = async value => {
  const path = new URL(value).pathname;
  if (path === '/v1/hackers/programs') return reply({ data: [listed('acme')], links: {} });
  const handle = path.split('/')[4]!;
  if (path.endsWith('/structured_scopes')) return reply({ data: [{ type: 'structured-scope', attributes: {
    asset_type: 'URL', asset_identifier: `https://${handle}.example.test`, eligible_for_submission: true,
  } }] });
  if (path.endsWith('/scope_exclusions')) return reply({ data: [] });
  return reply({ data: { type: 'program', attributes: { ...listed(handle).attributes, policy: 'Automated tools are allowed.' } } });
};

async function idle(service: CompanyImportService, id: string) {
  // The real DB path (migrate + save + enqueue) takes real time, so poll on a wall-clock deadline
  // rather than microtasks — unlike the unit test, whose persist stub settles instantly.
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const state = service.status(id);
    if (!['fetching', 'preparing', 'saving'].includes(state.phase)) return state;
    await sleep(25);
  }
  throw new Error('import_did_not_settle');
}

test('importing a company saves it and queues a passive job, and that is enough for preflight to pass', async () => {
  const base = loadConfig();
  const admin = connect(base.DATABASE_URL);
  const schema = 'test_' + randomUUID().replaceAll('-', '');
  await admin.query(`CREATE SCHEMA ${schema}`);
  const schemaUrl = new URL(base.DATABASE_URL);
  schemaUrl.searchParams.set('options', `-c search_path=${schema}`);
  const pool = connect(schemaUrl.toString());
  try {
    await migrate(pool);
    const service = new CompanyImportService(
      () => ({ ...blankProfile(), hackeroneUsername: 'researcher', hackeroneToken: 'private-test-token' }),
      { env: { DATABASE_URL: schemaUrl.toString() }, fetchLike: api },
    );
    const { id } = service.fetch();
    await idle(service, id);
    service.preview({ id, handles: ['acme'], approver: 'Scope Reviewer' });
    await idle(service, id);
    service.confirm({ id, approved: true });
    const settled = await idle(service, id);
    assert.equal(settled.phase, 'done', `import failed: ${settled.error ?? 'unknown'}`);
    assert.deepEqual(settled.imported, ['acme']);

    // (1) The program was saved and a passive job was queued for its one in-scope asset.
    const programs = await pool.query('SELECT id FROM programs');
    assert.equal(programs.rowCount, 1);
    const jobs = await pool.query(`SELECT j.action, a.url FROM research_jobs j JOIN assets a ON a.id=j.asset_id`);
    assert.deepEqual(jobs.rows.map(row => ({ action: row.action, url: row.url })),
      [{ action: 'inspect_http_target', url: 'https://acme.example.test' }]);

    // (2) Readiness passes on the imported program with no handles file at all.
    const rows = await pool.query(`SELECT p.id, s.policy FROM programs p JOIN scope_rules s ON s.program_id=p.id`);
    const dbPrograms = rows.rows.map(row => {
      const parsed = PolicySchema.safeParse(row.policy);
      return { id: String(row.id), requestsPerSecond: parsed.success ? parsed.data.requestsPerSecond : null };
    });
    const facts = {
      killSwitch: false, passiveHttp: true, dbReachable: true, pendingMigrations: [],
      hackerOneUser: true, hackerOneToken: true, handles: [], programs: dbPrograms,
    };
    assert.equal(evaluatePreflight(facts).ok, true);                              // imported programs are a valid roster
    assert.equal(evaluatePreflight({ ...facts, programs: [] }).ok, false);        // but nothing imported and no handles is not
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin.end();
  }
});
