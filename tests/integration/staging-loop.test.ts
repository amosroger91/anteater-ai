import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { randomUUID } from 'node:crypto';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type { RequestOptions } from 'node:https';
import { connect, migrate } from '../../packages/research-state/db.js';
import { recordReplay, submitFinding } from '../../packages/research-state/jobs.js';
import { loadConfig } from '../../packages/shared/config.js';
import { remediationFor } from '../../packages/remediation/index.js';
import type { PassiveDeps } from '../../packages/web-executor/index.js';
import type { Responder } from '../../packages/findings/index.js';
import { FixtureDiscovery } from '../../packages/discovery/index.js';
import { runLiveCampaign } from '../../apps/orchestrator/live-campaign.js';

const LAB_IDOR_CONTRACT = {
  findingType: 'cross_account_read',
  steps: [{ id: 'user1-reads-user2', expectStatus: 200, expectBodyIncludes: ['bob-secret-token'] }],
  counterTest: { id: 'user1-reads-missing-user', expectStatus: 404, expectBodyIncludes: ['not_found'] },
  repeatCount: 2,
};

function reservePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') { server.close(); reject(new Error('no_port')); return; }
      server.close(() => resolve(address.port));
    });
  });
}

async function startLab(variant: 'vulnerable' | 'patched') {
  const port = await reservePort();
  const child: ChildProcess = spawn(process.execPath, ['infrastructure/lab/app.mjs'], {
    env: { ...process.env, PORT: String(port), VARIANT: variant },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  const close = () => { child.kill(); return once(child, 'exit'); };
  let log = '';
  child.stdout?.on('data', chunk => { log += chunk.toString(); });
  child.stderr?.on('data', chunk => { log += chunk.toString(); });
  const deadline = Date.now() + 8000;
  try {
    while (Date.now() < deadline) {
      if (child.exitCode !== null) throw new Error(`lab_exit_${child.exitCode}:${log}`);
      try {
        const response = await labGet(port, '/', {});
        if (response.status === 200 && response.body.includes(`"variant":"${variant}"`)) return { port, close };
      } catch { /* not listening yet */ }
      await new Promise(resolve => setTimeout(resolve, 40));
    }
    throw new Error(`lab_timeout:${log}`);
  } catch (error) {
    child.kill();
    throw error;
  }
}

function labGet(port: number, path: string, headers: Record<string, string>): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: '127.0.0.1', port, path, method: 'GET', headers }, response => {
      const chunks: Buffer[] = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
    });
    request.on('error', reject);
    request.end();
  });
}

function labResponder(port: number): Responder {
  return async stepId => {
    const path = stepId === 'user1-reads-user2' ? '/api/users/2' : '/api/users/999';
    const response = await labGet(port, path, { 'x-user': '1' });
    return { status: response.status, body: response.body };
  };
}

function passiveFromLab(port: number): PassiveDeps & { options: () => RequestOptions | undefined; paths: string[] } {
  let options: RequestOptions | undefined;
  const paths: string[] = [];
  const deps: PassiveDeps = {
    lookup: async () => [{ address: '93.184.216.34', family: 4 }],
    request: (input, callback) => {
      options = input;
      paths.push(String(input.path ?? '/'));
      const request = new EventEmitter() as ClientRequest;
      request.destroy = () => request;
      request.end = (() => {
        const upstream = http.request({ host: '127.0.0.1', port, path: String(input.path ?? '/'), method: 'GET' }, upstreamResponse => {
          const chunks: Buffer[] = [];
          upstreamResponse.on('data', chunk => chunks.push(chunk));
          upstreamResponse.on('end', () => {
            const response = new PassThrough() as unknown as IncomingMessage;
            response.statusCode = upstreamResponse.statusCode ?? 0;
            response.headers = { 'content-type': String(upstreamResponse.headers['content-type'] ?? 'application/json') };
            callback(response);
            response.emit('data', Buffer.concat(chunks));
            response.emit('end');
          });
        });
        upstream.on('error', error => request.emit('error', error));
        upstream.end();
        return request;
      }) as ClientRequest['end'];
      return request;
    },
  };
  return Object.assign(deps, { options: () => options, paths });
}

test('staging loop discovers the owned lab, replays the seeded IDOR, and submits only with a human', async () => {
  const base = loadConfig();
  const admin = connect(base.DATABASE_URL);
  const schema = 'test_' + randomUUID().replaceAll('-', '');
  await admin.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(base.DATABASE_URL);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = connect(url.toString());
  let vulnerable: Awaited<ReturnType<typeof startLab>> | undefined;
  let patched: Awaited<ReturnType<typeof startLab>> | undefined;
  try {
    vulnerable = await startLab('vulnerable');
    patched = await startLab('patched');
    const passive = passiveFromLab(vulnerable.port);
    await migrate(pool);
    const config = loadConfig({
      GLOBAL_KILL_SWITCH: 'false',
      ENABLE_PASSIVE_HTTP: 'true',
      ENABLE_APPLICATION_RESEARCH: 'false',
      ALLOW_PRIVATE_LAB_TARGETS: 'false',
      ALLOW_ACTIVE_TESTING: 'false',
      DATABASE_URL: url.toString(),
      LLM_PROVIDER: 'fixture',
    });
    const policy = {
      programId: 'lab-staging', revision: 'lab-r1', sourceUrl: 'https://lab.anteater.test/policy', reviewed: true as const,
      expiresAt: '2099-01-01T00:00:00Z', allowed: ['lab-vuln.anteater.test'], excluded: [] as string[],
      allowedActions: ['inspect_http_target'] as ['inspect_http_target'], allowedPaths: ['/'] as ['/'],
      schemes: ['https'] as ['https'], ports: [443] as [443], requestsPerSecond: 5,
    };
    const discovery = new FixtureDiscovery({ 'lab-vuln.anteater.test': [
      { host: 'leak.vendor.test', source: 'observed-link', confidence: 0.4 },
      { host: 'secret.anteater.test', source: 'cert-transparency', confidence: 0.6 },
    ] });
    const result = await runLiveCampaign({ pool, config: () => config, executors: { passive } }, {
      roots: ['lab-vuln.anteater.test'],
      action: 'inspect_http_target',
      discovery,
      program: {
        id: 'lab-staging', name: 'Owned lab', platform: 'owned-lab', programUrl: 'https://lab.anteater.test/program',
        categories: ['web'], policy,
      },
      verify: {
        from: 'CANDIDATE',
        contract: LAB_IDOR_CONTRACT,
        responder: labResponder(vulnerable.port),
        body: {
          findingType: 'cross_account_read',
          location: 'https://lab-vuln.anteater.test/api/users/2',
          variant: 'vulnerable',
          remediation: remediationFor('cross_account_read'),
        },
      },
    });

    assert.deepEqual(result.admitted, ['lab-vuln.anteater.test']);
    assert.ok(result.held.includes('leak.vendor.test') && result.held.includes('secret.anteater.test'));
    const assets = await pool.query('SELECT id, url FROM assets WHERE active=true ORDER BY id');
    assert.deepEqual(assets.rows, [{ id: 'lab-vuln-anteater-test', url: 'https://lab-vuln.anteater.test' }]);
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM research_jobs WHERE status='completed'")).rows[0].n, 1);
    assert.equal(passive.options()?.host, '93.184.216.34');
    assert.ok(passive.paths.length > 0);
    assert.ok(!passive.paths.some(path => path === '/.git/config' || path === '/.env' || path === '/.DS_Store'));
    assert.equal(result.observations[0]?.observation.ip, '93.184.216.34');
    assert.match(String(result.observations[0]?.observation.bodySnippet), /anteater-lab/);
    assert.match(String(result.observations[0]?.observation.bodySnippet), /vulnerable/);
    assert.equal(result.verification?.reproduced, true);
    assert.equal(result.verification?.next, 'VERIFIED');
    assert.ok(result.remediations.some(item => item.code === 'cross_account_read' && /object-level authorization/i.test(item.fix)));

    const findingId = result.verification?.id;
    assert.ok(findingId);
    const evidence = await pool.query('SELECT sha256, body FROM evidence WHERE finding_id=$1', [findingId]);
    assert.equal(evidence.rowCount, 1);
    assert.match(evidence.rows[0].sha256, /^[a-f0-9]{64}$/);
    assert.equal(evidence.rows[0].body.replay.reproduced, true);
    assert.ok(!JSON.stringify(evidence.rows[0].body).includes('bob-secret-token'));
    assert.equal((await pool.query('SELECT status FROM findings WHERE id=$1', [findingId])).rows[0].status, 'VERIFIED');

    const rejected = await recordReplay(pool, 'lab-staging', 'CANDIDATE', LAB_IDOR_CONTRACT, labResponder(patched.port), {
      findingType: 'cross_account_read', location: 'https://lab-patched.anteater.test/api/users/2', variant: 'patched',
    });
    assert.equal(rejected.reproduced, false);
    assert.equal(rejected.next, 'HUMAN_REVIEW');
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM findings WHERE status='VERIFIED'")).rows[0].n, 1);

    await assert.rejects(pool.query(`INSERT INTO findings(id,program_id,status,body,verified_by) VALUES($1,'lab-staging','VERIFIED','{}','scanner')`, [randomUUID()]), /verifier_required/);
    await assert.rejects(pool.query(`UPDATE findings SET status='SUBMITTED', human_reviewer='Ada Lovelace' WHERE id=$1`, [findingId]), /human_required/);
    await assert.rejects(submitFinding(pool, findingId, ' '), /human_reviewer_required/);
    await submitFinding(pool, findingId, 'Ada Lovelace');
    const submitted = await pool.query("SELECT id, human_reviewer, body->>'findingType' AS type FROM findings WHERE status='SUBMITTED'");
    assert.equal(submitted.rowCount, 1);
    assert.equal(submitted.rows[0].id, findingId);
    assert.equal(submitted.rows[0].human_reviewer, 'Ada Lovelace');
    assert.equal(submitted.rows[0].type, 'cross_account_read');
    assert.equal((await pool.query('SELECT status FROM findings WHERE id=$1', [rejected.id])).rows[0].status, 'HUMAN_REVIEW');
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM findings WHERE status='SUBMITTED' AND body->'signal' IS NOT NULL")).rows[0].n, 0);
  } finally {
    await vulnerable?.close();
    await patched?.close();
    await pool.end();
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin.end();
  }
});
