import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type { RequestOptions } from 'node:https';
import { executePassiveHttp, probeAuthorizedGets, type PassiveDeps } from '../packages/web-executor/index.js';

const SECRET = 'SUPERSECRETVALUE';
const GIT_BODY = `[core]\n\trepositoryformatversion = 0\nPASSWORD=${SECRET}\n`;

function policy(paths: string[]) {
  return {
    programId: 'lab-reads', revision: 'r1', sourceUrl: 'https://lab.example.test/policy', reviewed: true as const,
    expiresAt: '2099-01-01T00:00:00.000Z', allowed: ['lab.example.test'], excluded: [] as string[],
    allowedActions: ['inspect_http_target'] as ['inspect_http_target'], allowedPaths: paths,
    schemes: ['https'] as ['https'], ports: [443] as [443], requestsPerSecond: 1,
  };
}

function transport(bodies: Record<string, { status: number; body: string }>) {
  const paths: string[] = [];
  let lookups = 0;
  const deps: PassiveDeps = {
    lookup: async () => { lookups++; return [{ address: '93.184.216.34', family: 4 }]; },
    request: (input: RequestOptions, callback) => {
      const path = String(input.path ?? '/');
      paths.push(path);
      const canned = bodies[path] ?? { status: 404, body: 'missing' };
      const request = new EventEmitter() as ClientRequest;
      const response = new PassThrough() as unknown as IncomingMessage;
      response.statusCode = canned.status;
      response.headers = { 'content-type': 'application/octet-stream' };
      request.destroy = () => request;
      request.end = (() => {
        queueMicrotask(() => {
          callback(response);
          response.emit('data', Buffer.from(canned.body));
          response.emit('end');
        });
        return request;
      }) as ClientRequest['end'];
      return request;
    },
  };
  return { deps, paths, lookups: () => lookups };
}

const paths = ['/.git/config', '/.env', '/.DS_Store'] as const;

test('a policy that omits a path, a kill switch, or a disabled adapter makes no request', async () => {
  const stub = transport({ '/.git/config': { status: 200, body: GIT_BODY } });
  const denied = await probeAuthorizedGets({
    host: 'lab.example.test', policy: policy(['/']), killSwitch: false, enabled: true, paths, maxBytes: 4096, deps: stub.deps, reserve: async () => true,
  });
  assert.deepEqual(denied, { probed: [], signals: [] });
  const killed = await probeAuthorizedGets({
    host: 'lab.example.test', policy: policy([...paths]), killSwitch: true, enabled: true, paths, maxBytes: 4096, deps: stub.deps, reserve: async () => true,
  });
  assert.deepEqual(killed.probed, []);
  const disabled = await probeAuthorizedGets({
    host: 'lab.example.test', policy: policy([...paths]), killSwitch: false, enabled: false, paths, maxBytes: 4096, deps: stub.deps, reserve: async () => true,
  });
  assert.deepEqual(disabled.probed, []);
  const budget = await probeAuthorizedGets({
    host: 'lab.example.test', policy: policy([...paths]), killSwitch: false, enabled: true, paths, maxBytes: 4096, deps: stub.deps, reserve: async () => false,
  });
  assert.deepEqual(budget.probed, []);
  assert.equal(stub.lookups(), 0);
  assert.deepEqual(stub.paths, []);
});

test('an authorized git config is an observation signal and the file contents stay out of it', async () => {
  const stub = transport({
    '/.git/config': { status: 200, body: GIT_BODY },
    '/.env': { status: 404, body: 'not found' },
    '/.DS_Store': { status: 404, body: 'not found' },
  });
  const found = await probeAuthorizedGets({
    host: 'lab.example.test', policy: policy([...paths]), killSwitch: false, enabled: true, paths, maxBytes: 4096, deps: stub.deps, reserve: async () => true,
  });
  assert.deepEqual(found.probed, [...paths]);
  assert.deepEqual(found.signals, [{ code: 'exposed_vcs', severity: 'high', detail: 'git config signature at /.git/config' }]);
  assert.ok(!JSON.stringify(found).includes(SECRET));
  const direct = await executePassiveHttp('https://lab.example.test/.git/config', { maxBytes: 4096, deps: stub.deps });
  assert.equal(direct.bodySnippet, null);
  assert.ok(!JSON.stringify(direct).includes(SECRET));
  assert.ok((direct.signals as Array<{ code: string }>).some(signal => signal.code === 'exposed_vcs'));
});

test('a patched signature is fetched and produces no source-file finding', async () => {
  const stub = transport({
    '/.git/config': { status: 404, body: 'not found' },
    '/.env': { status: 200, body: '<html>not found</html>' },
    '/.DS_Store': { status: 200, body: 'not a store' },
  });
  const clean = await probeAuthorizedGets({
    host: 'lab.example.test', policy: policy([...paths]), killSwitch: false, enabled: true, paths, maxBytes: 4096, deps: stub.deps, reserve: async () => true,
  });
  assert.deepEqual(clean.probed, [...paths]);
  assert.deepEqual(clean.signals, []);
});

// A dangling-CNAME subdomain serving an unclaimed-service 404 is a takeover candidate, decided from the
// one response plus the resolved CNAME metadata.
function respondRoot(status: number, body: string, cname?: string): PassiveDeps {
  return {
    lookup: async () => [{ address: '93.184.216.34', family: 4 }],
    ...(cname ? { resolveCname: async () => cname } : {}),
    request: (_input: RequestOptions, callback) => {
      const request = new EventEmitter() as ClientRequest;
      const response = new PassThrough() as unknown as IncomingMessage;
      response.statusCode = status;
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

test('a dangling CNAME with an unclaimed-service 404 is a subdomain_takeover signal', async () => {
  const obs = await executePassiveHttp('https://dangling.lab.example.test/', {
    maxBytes: 4096, deps: respondRoot(404, "There isn't a GitHub Pages site here.", 'victim.github.io'),
  });
  assert.equal(obs.status, 404);
  assert.ok((obs.signals as Array<{ code: string }>).some(signal => signal.code === 'subdomain_takeover'));
});

test('the same unclaimed-service 404 is not a takeover without a resolved CNAME', async () => {
  const obs = await executePassiveHttp('https://dangling.lab.example.test/', {
    maxBytes: 4096, deps: respondRoot(404, "There isn't a GitHub Pages site here."),   // no resolveCname dep
  });
  assert.ok(!(obs.signals as Array<{ code: string }>).some(signal => signal.code === 'subdomain_takeover'));
});
