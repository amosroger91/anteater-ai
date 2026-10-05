import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type { RequestOptions } from 'node:https';
import { executePassiveHttp, type PassiveDeps } from '../packages/web-executor/index.js';
import { addressBlockReason } from '../scripts/posture-check.js';

function transport(body: Buffer, config: { status?: number; noEnd?: boolean; location?: string; lookup?: PassiveDeps['lookup'] } = {}) {
  let options: RequestOptions | undefined;
  let calls = 0;
  let lookups = 0;
  const deps: PassiveDeps = {
    lookup: config.lookup ?? (async () => {
      lookups++;
      return lookups === 1
        ? [{ address: '93.184.216.34', family: 4 }]
        : [{ address: '127.0.0.1', family: 4 }];
    }),
    request: (input, callback) => {
      calls++; options = input;
      const request = new EventEmitter() as ClientRequest;
      const response = new PassThrough() as unknown as IncomingMessage;
      response.statusCode = config.status ?? 200;
      response.headers = { 'content-type': 'text/html', ...(config.location ? { location: config.location } : {}) };
      let destroyed = false;
      request.destroy = () => { destroyed = true; response.destroy(); return request; };
      const abort = () => { request.emit('error', new Error('aborted')); request.destroy(); };
      input.signal?.addEventListener('abort', abort, { once: true });
      request.end = (() => {
        queueMicrotask(() => {
          if (destroyed) return;
          callback(response);
          response.emit('data', body);
          if (!config.noEnd && !destroyed) response.emit('end');
        });
        return request;
      }) as ClientRequest['end'];
      return request;
    },
  };
  return { deps, options: () => options, calls: () => calls, lookups: () => lookups };
}

test('a second DNS answer cannot move the connected address', async () => {
  const stub = transport(Buffer.from('ok'));
  const result = await executePassiveHttp('https://api.example.test/', { maxBytes: 1024, deps: stub.deps });
  assert.equal(stub.lookups(), 1);
  assert.equal(stub.calls(), 1);
  assert.equal(stub.options()?.host, '93.184.216.34');
  assert.equal(result.ip, '93.184.216.34');
  assert.notEqual(result.ip, '127.0.0.1');
});

test('a redirect to another host is recorded once and not followed', async () => {
  const stub = transport(Buffer.from('redirect'), { status: 302, location: 'https://evil.example.test/steal' });
  const result = await executePassiveHttp('https://api.example.test/', { maxBytes: 1024, deps: stub.deps });
  assert.equal(stub.calls(), 1);
  assert.equal((result.headers as Record<string, string>).location, 'https://evil.example.test/steal');
  assert.equal(stub.options()?.host, '93.184.216.34');
});

test('private and reserved addresses are refused before any request', async () => {
  const refused = ['127.0.0.1', '10.1.2.3', '172.16.5.5', '192.168.60.26', '100.64.1.1', '169.254.169.254', '0.0.0.0', '224.0.0.1', '::1', 'fc00::1', '::ffff:10.0.0.1'];
  for (const ip of refused) assert.ok(addressBlockReason(ip), ip);
  assert.equal(addressBlockReason('93.184.216.34'), null);
  assert.equal(addressBlockReason('192.168.60.26', true), null);
  assert.ok(addressBlockReason('127.0.0.1', true));
  const stub = transport(Buffer.alloc(0), { lookup: async () => refused.map(address => ({ address, family: address.includes(':') ? 6 : 4 })) });
  const result = await executePassiveHttp('https://api.example.test/', { maxBytes: 1024, deps: stub.deps });
  assert.equal(result.error, 'blocked_address');
  assert.equal(stub.calls(), 0);
});

test('the body cap stops the read and the deadline aborts a stuck response', async () => {
  const capped = transport(Buffer.alloc(5000, 97), { noEnd: true });
  const result = await executePassiveHttp('https://api.example.test/', { maxBytes: 1024, deps: capped.deps });
  assert.equal(result.truncated, true);
  assert.equal(result.bodyBytes, 1024);
  const stuck = transport(Buffer.from('drip'), { noEnd: true });
  await assert.rejects(executePassiveHttp('https://api.example.test/', { maxBytes: 1024, deps: stuck.deps, timeoutMs: 20 }));
  stuck.deps.lookup = () => new Promise(() => {});
  await assert.rejects(executePassiveHttp('https://api.example.test/', { maxBytes: 1024, deps: stuck.deps, timeoutMs: 20 }), /request_timeout/);
});
