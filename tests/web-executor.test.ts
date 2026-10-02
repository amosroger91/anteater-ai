import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type { RequestOptions } from 'node:https';
import { createHash } from 'node:crypto';
import { executePassiveHttp, type PassiveDeps } from '../packages/web-executor/index.js';
import { followUpActions, jobKey } from '../packages/web-executor/planning.js';

function transport(body: Buffer, config: { status?: number; noEnd?: boolean; location?: string } = {}) {
  let options: RequestOptions | undefined;
  let calls = 0;
  let destroyed = false;
  const deps: PassiveDeps = {
    lookup: async () => [{ address: '93.184.216.34', family: 4 }],
    request: (input, callback) => {
      calls++; options = input;
      const request = new EventEmitter() as ClientRequest;
      const response = new PassThrough() as unknown as IncomingMessage;
      response.statusCode = config.status ?? 200;
      response.headers = { 'content-type': 'text/html', 'set-cookie': ['session=super-secret; Secure; HttpOnly'], ...(config.location ? { location: config.location } : {}) };
      request.destroy = () => { destroyed = true; response.destroy(); return request; };
      const abort = () => { request.emit('error', new Error('aborted')); request.destroy(); };
      input.signal?.addEventListener('abort', abort, { once: true });
      request.end = (() => {
        queueMicrotask(() => {
          callback(response);
          response.emit('data', body);
          if (!config.noEnd && !destroyed) response.emit('end');
        });
        return request;
      }) as ClientRequest['end'];
      return request;
    },
  };
  return { deps, options: () => options, calls: () => calls, destroyed: () => destroyed };
}

test('passive executor pins one public IP and retains hashes without cookie values', async () => {
  const body = Buffer.from('<html>bounded evidence</html>');
  const stub = transport(body);
  const stages: string[] = [];
  const resolve = stub.deps.lookup;
  stub.deps.lookup = async hostname => { stages.push('dns'); return resolve(hostname); };
  const result = await executePassiveHttp('https://api.example.test/', { maxBytes: 1024, deps: stub.deps, beforeRequest: async () => { stages.push('gate'); } });
  assert.deepEqual(stages, ['dns', 'gate']);
  assert.equal(stub.options()?.host, '93.184.216.34');
  assert.equal(stub.options()?.servername, 'api.example.test');
  assert.equal(stub.options()?.rejectUnauthorized, true);
  assert.equal(stub.options()?.method, 'GET');
  assert.equal(result.bodySha256, createHash('sha256').update(body).digest('hex'));
  assert.equal(result.hashScope, 'captured_bytes');
  assert.equal(result.truncated, false);
  assert.ok(!JSON.stringify(result).includes('super-secret'));
});

test('oversized response stops the download and hashes exactly the retained prefix', async () => {
  const stub = transport(Buffer.alloc(5000, 97), { noEnd: true });
  const result = await executePassiveHttp('https://api.example.test/', { maxBytes: 1024, deps: stub.deps });
  assert.equal(stub.destroyed(), true);
  assert.equal(result.bodyBytes, 1024);
  assert.equal(result.truncated, true);
  assert.equal(result.bodySha256, createHash('sha256').update(Buffer.alloc(1024, 97)).digest('hex'));
});

test('redirects are recorded once with query secrets removed and never followed', async () => {
  const stub = transport(Buffer.from('redirect'), { status: 302, location: 'https://other.example.test/login?token=secret#secret' });
  const result = await executePassiveHttp('https://api.example.test/', { maxBytes: 1024, deps: stub.deps });
  assert.equal(stub.calls(), 1);
  assert.equal((result.headers as Record<string, string>).location, 'https://other.example.test/login');
  assert.deepEqual(followUpActions('inspect_http_target', result), []);
});

test('private answers, revoked policies and prior cancellation make zero HTTP requests', async () => {
  const stub = transport(Buffer.alloc(0));
  stub.deps.lookup = async () => [{ address: '127.0.0.1', family: 4 }, { address: '169.254.169.254', family: 4 }, { address: '::ffff:10.0.0.1', family: 6 }];
  const result = await executePassiveHttp('https://api.example.test/', { maxBytes: 1024, deps: stub.deps });
  assert.equal(result.error, 'blocked_address');
  stub.deps.lookup = async () => [{ address: '93.184.216.34', family: 4 }];
  await assert.rejects(executePassiveHttp('https://api.example.test/', { maxBytes: 1024, deps: stub.deps, beforeRequest: async () => { throw new Error('excluded'); } }), /excluded/);
  await assert.rejects(executePassiveHttp('https://api.example.test/', { maxBytes: 1024, deps: stub.deps, signal: AbortSignal.abort() }));
  assert.equal(stub.calls(), 0);
});

test('total deadline bounds DNS and a response that never ends', async () => {
  const stub = transport(Buffer.from('drip'), { noEnd: true });
  await assert.rejects(executePassiveHttp('https://api.example.test/', { maxBytes: 1024, deps: stub.deps, timeoutMs: 20 }));
  assert.equal(stub.destroyed(), true);
  stub.deps.lookup = () => new Promise(() => {});
  await assert.rejects(executePassiveHttp('https://api.example.test/', { maxBytes: 1024, deps: stub.deps, timeoutMs: 20 }), /request_timeout/);
});

test('follow-ups depend on successful web features, never model labels or arbitrary links', () => {
  assert.deepEqual(followUpActions('inspect_http_target', { status: 200, contentType: 'text/html', bodySnippet: 'Swagger /admin https://evil.test/' }), ['inspect_robots', 'inspect_sitemap', 'inspect_openapi']);
  assert.deepEqual(followUpActions('inspect_http_target', { status: 401, contentType: 'text/html' }), []);
  assert.deepEqual(followUpActions('inspect_sitemap', { status: 200, contentType: 'text/html' }), []);
  assert.deepEqual(followUpActions('inspect_http_target', { label: 'input_reflection', followUp: 'human_review' }), []);
});

test('dedupe keys preserve fixture replay and change with policy or target identity', () => {
  assert.equal(jobKey('fixture-company', 'fixture-api', 'fixture-v1', 'https://api.example.test/', 'inspect_http_target'), 'fixture-v1:inspect');
  const key = jobKey('program', 'api', 'v1', 'https://api.example.test/', 'inspect_http_target');
  assert.notEqual(key, jobKey('program', 'api', 'v2', 'https://api.example.test/', 'inspect_http_target'));
  assert.notEqual(key, jobKey('program', 'api', 'v1', 'https://other.example.test/', 'inspect_http_target'));
});
