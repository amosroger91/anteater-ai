import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type { RequestOptions } from 'node:https';
import { randomUUID } from 'node:crypto';
import { connect, migrate } from '../../packages/research-state/db.js';
import { Jobs } from '../../packages/research-state/jobs.js';
import { saveProgram } from '../../packages/research-state/workspace.js';
import { ProgramSchema } from '../../packages/bounty-providers/index.js';
import { ToolGateway } from '../../packages/mcp/index.js';
import type { PassiveDeps } from '../../packages/web-executor/index.js';
import { loadConfig } from '../../packages/shared/config.js';
import { executeLeasedJob } from '../../packages/research-state/execution.js';

// End-to-end active-probe vertical against a real database: a program with a REVIEWED parameterized
// endpoint and probe_sqli in its allowed actions, armed with ALLOW_ACTIVE_TESTING, runs the boolean
// SQL-injection oracle through the scoped gateway and lands a submittable HUMAN_REVIEW finding.

// A deliberately injectable endpoint: an OR-true condition returns the full listing (like the benign
// baseline), an AND-false condition returns an empty listing. A single quote does not error. This is
// how a boolean-based SQLi target behaves; a non-injectable app would return the same page for all.
function injectableSqlDeps(): PassiveDeps {
  const full = '<ul><li>a</li><li>b</li><li>c</li><li>d</li><li>e</li><li>f</li></ul>';
  const empty = '<ul></ul>';
  return {
    lookup: async () => [{ address: '93.184.216.34', family: 4 }],
    request: (input: RequestOptions, callback) => {
      const q = new URL('https://x' + String(input.path ?? '/')).searchParams.get('q') ?? '';
      const body = q.includes("OR '1'='1") || q === '1' ? full : empty;
      const request = new EventEmitter() as ClientRequest;
      const response = new PassThrough() as unknown as IncomingMessage;
      response.statusCode = 200;
      response.headers = { 'content-type': 'text/html' };
      request.destroy = () => request;
      request.end = (() => {
        queueMicrotask(() => { callback(response); response.emit('data', Buffer.from(body)); response.emit('end'); });
        return request;
      }) as ClientRequest['end'];
      return request;
    },
  };
}

test('an armed active probe confirms boolean SQL injection on a reviewed endpoint and files it for review', async () => {
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
      GLOBAL_KILL_SWITCH: 'false', ENABLE_PASSIVE_HTTP: 'true', ALLOW_ACTIVE_TESTING: 'true',
      DATABASE_URL: url.toString(), LLM_PROVIDER: 'fixture', MAX_REQUEST_RATE: '10',
    });
    const program = await saveProgram(pool, ProgramSchema.parse({
      id: 'lab-active', name: 'Lab active', platform: 'owned-lab', programUrl: 'https://lab.example.test/program', categories: ['web'],
      policy: {
        programId: 'lab-active', revision: 'r1', sourceUrl: 'https://lab.example.test/policy', reviewed: true,
        expiresAt: '2099-01-01T00:00:00.000Z', allowed: ['lab.example.test'], excluded: [],
        allowedActions: ['inspect_http_target', 'probe_sqli'], allowedPaths: ['/'],
        schemes: ['https'], ports: [443], requestsPerSecond: 10,
        activeEndpoints: ['https://lab.example.test/search?q=1'],
      },
      assets: [{ id: 'asset-lab-active', url: 'https://lab.example.test' }],
    }));
    const jobs = new Jobs(pool, 1, 30);
    await jobs.enqueue(program.id, program.assets[0]!.id, 'probe_sqli');
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM research_jobs WHERE action='probe_sqli'")).rows[0].n, 1);

    const gateway = new ToolGateway(pool, () => config, { passive: injectableSqlDeps() });
    const job = await jobs.claim();
    assert.ok(job, 'probe_sqli job should be claimable');
    const result = await executeLeasedJob({ jobs, gateway, job: job!, leaseSeconds: 30 });
    assert.equal(result.completed, true);

    const finding = await pool.query(`SELECT status, body FROM findings WHERE body->'signal'->>'code' = 'sqli'`);
    assert.equal(finding.rowCount, 1);
    assert.equal(finding.rows[0].status, 'HUMAN_REVIEW');                         // submittable, not stuck at OBSERVATION
    assert.match(finding.rows[0].body.signal.detail, /boolean-based SQL injection/);
    // The confirmed finding is not auto-verified/submitted; a human still submits.
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM findings WHERE status IN ('VERIFIED','SUBMITTED')")).rows[0].n, 0);
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin.end();
  }
});
