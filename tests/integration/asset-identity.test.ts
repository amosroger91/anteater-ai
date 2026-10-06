import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture } from '../../fixtures/program.js';
import { ProgramSchema } from '../../packages/bounty-providers/index.js';
import { recordObservedHosts } from '../../packages/discovery/store.js';
import { connect, migrate } from '../../packages/research-state/db.js';
import { Jobs } from '../../packages/research-state/jobs.js';
import { saveProgram } from '../../packages/research-state/workspace.js';
import { assetIdForHost } from '../../packages/shared/asset-id.js';
import { loadConfig } from '../../packages/shared/config.js';

test('new asset IDs preserve legacy foreign keys and distinguish formerly colliding hosts', async () => {
  const base = loadConfig();
  const admin = connect(base.DATABASE_URL);
  const schema = 'test_' + randomUUID().replaceAll('-', '');
  await admin.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(base.DATABASE_URL);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = connect(url.toString());
  try {
    await migrate(pool);
    await saveProgram(pool, fixture);
    await new Jobs(pool).enqueue(fixture.id, 'fixture-api', 'inspect_http_target');
    const imported = ProgramSchema.parse({ ...fixture, assets: [
      { id: assetIdForHost('api.example.test', fixture.id), url: 'https://api.example.test' },
      ...['a.b-c.example.test', 'a-b.c.example.test'].map(host => ({
        id: assetIdForHost(host, fixture.id), url: `https://${host}`,
      })),
    ] });
    const saved = await saveProgram(pool, imported);
    assert.equal(saved.assets[0]?.id, 'fixture-api');
    assert.notEqual(saved.assets[1]?.id, saved.assets[2]?.id);
    assert.equal((await pool.query('SELECT asset_id FROM research_jobs')).rows[0]?.asset_id, 'fixture-api');
    await recordObservedHosts(pool, fixture.id, ['api.example.test', 'a.b-c.example.test', 'a-b.c.example.test'].map(host => ({
      host, source: 'cert-transparency', confidence: 1, relation: 'subdomain', observedAt: new Date().toISOString(),
    })));
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM assets')).rows[0]?.n, 3);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM assets WHERE active=true')).rows[0]?.n, 3);
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  }
});
