import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type { RequestOptions } from 'node:https';
import { randomUUID } from 'node:crypto';
import { connect, migrate } from '../../packages/research-state/db.js';
import { loadConfig } from '../../packages/shared/config.js';
import { FixtureDiscovery } from '../../packages/discovery/index.js';
import type { PassiveDeps } from '../../packages/web-executor/index.js';
import { runLiveCampaign } from '../../apps/orchestrator/live-campaign.js';

const SECRET = 'SUPERSECRETVALUE';

function canned(): { deps: PassiveDeps; paths: string[] } {
  const paths: string[] = [];
  const bodies: Record<string, { status: number; body: string }> = {
    '/': { status: 200, body: 'ok' },
    '/.git/config': { status: 200, body: `[core]\n\trepositoryformatversion = 0\nPASSWORD=${SECRET}\n` },
    '/.env': { status: 404, body: 'not found' },
    '/.DS_Store': { status: 404, body: 'not found' },
  };
  const deps: PassiveDeps = {
    lookup: async () => [{ address: '93.184.216.34', family: 4 }],
    request: (input: RequestOptions, callback) => {
      const path = String(input.path ?? '/');
      paths.push(path);
      const cannedBody = bodies[path] ?? { status: 404, body: 'missing' };
      const request = new EventEmitter() as ClientRequest;
      request.destroy = () => request;
      request.end = (() => {
        queueMicrotask(() => {
          const response = new PassThrough() as unknown as IncomingMessage;
          response.statusCode = cannedBody.status;
          response.headers = { 'content-type': 'application/octet-stream' };
          callback(response);
          response.emit('data', Buffer.from(cannedBody.body));
          response.emit('end');
        });
        return request;
      }) as ClientRequest['end'];
      return request;
    },
  };
  return { deps, paths };
}

test('an authorized source-file signature is stored as an observation and the file contents are not', async () => {
  const base = loadConfig();
  const admin = connect(base.DATABASE_URL);
  const schema = 'test_' + randomUUID().replaceAll('-', '');
  await admin.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(base.DATABASE_URL);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = connect(url.toString());
  try {
    await migrate(pool);
    const config = loadConfig({
      GLOBAL_KILL_SWITCH: 'false', ENABLE_PASSIVE_HTTP: 'true', ENABLE_APPLICATION_RESEARCH: 'false',
      ALLOW_PRIVATE_LAB_TARGETS: 'false', ALLOW_ACTIVE_TESTING: 'false', DATABASE_URL: url.toString(),
      LLM_PROVIDER: 'fixture', MAX_REQUEST_RATE: '10',
    });
    const passive = canned();
    const result = await runLiveCampaign({ pool, config: () => config, executors: { passive: passive.deps } }, {
      roots: ['lab.example.test'],
      action: 'inspect_http_target',
      discovery: new FixtureDiscovery(),
      program: {
        id: 'lab-reads', name: 'Lab reads', platform: 'owned-lab', programUrl: 'https://lab.example.test/program', categories: ['web'],
        policy: {
          programId: 'lab-reads', revision: 'r1', sourceUrl: 'https://lab.example.test/policy', reviewed: true,
          expiresAt: '2099-01-01T00:00:00.000Z', allowed: ['lab.example.test'], excluded: [],
          allowedActions: ['inspect_http_target'], allowedPaths: ['/', '/.git/config', '/.env', '/.DS_Store'],
          schemes: ['https'], ports: [443], requestsPerSecond: 10,
        },
      },
    });
    assert.deepEqual(result.admitted, ['lab.example.test']);
    assert.ok(passive.paths.includes('/.git/config') && passive.paths.includes('/.env') && passive.paths.includes('/.DS_Store'));
    assert.equal(passive.paths.filter(path => path === '/').length, 1);
    const finding = await pool.query(`SELECT status, body FROM findings WHERE body->'signal'->>'code' = 'exposed_vcs'`);
    assert.equal(finding.rowCount, 1);
    assert.equal(finding.rows[0].status, 'OBSERVATION');
    assert.equal(finding.rows[0].body.signal.detail, 'git config signature at /.git/config');
    const stored = JSON.stringify((await pool.query('SELECT body FROM observations')).rows) + JSON.stringify(finding.rows);
    assert.ok(!stored.includes(SECRET));
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM findings WHERE status IN ('VERIFIED','SUBMITTED')")).rows[0].n, 0);
    const coverage = await pool.query(`SELECT metadata->>'markdown' AS markdown FROM audit_events WHERE event = 'CAMPAIGN_COVERAGE'`);
    assert.match(coverage.rows[0].markdown, /files\.exposed-vcs/);
    assert.match(coverage.rows[0].markdown, /not observed/);
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin.end();
  }
});
