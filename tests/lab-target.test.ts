import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type { RequestOptions } from 'node:https';
import { executePassiveHttp, labPrivateAllowed, parseLabTargetAllow, type PassiveDeps } from '../packages/web-executor/index.js';
import { loadConfig } from '../packages/shared/config.js';

function transport(address: string) {
  let options: RequestOptions | undefined;
  let calls = 0;
  const deps: PassiveDeps = {
    lookup: async () => [{ address, family: 4 }],
    request: (input, callback) => {
      calls++; options = input;
      const request = new EventEmitter() as ClientRequest;
      const response = new PassThrough() as unknown as IncomingMessage;
      response.statusCode = 200;
      response.headers = { 'content-type': 'text/plain' };
      request.destroy = () => request;
      request.end = (() => {
        queueMicrotask(() => { callback(response); response.emit('data', Buffer.from('lab')); response.emit('end'); });
        return request;
      }) as ClientRequest['end'];
      return request;
    },
  };
  return { deps, options: () => options, calls: () => calls };
}

const labAllow = parseLabTargetAllow(true, 'Lab.Anteater.Test, other.example.test');

test('committed defaults keep the kill switch on and live flags off', () => {
  const defaults = loadConfig({});
  assert.equal(defaults.GLOBAL_KILL_SWITCH, true);
  assert.equal(defaults.ENABLE_PASSIVE_HTTP, false);
  assert.equal(defaults.ENABLE_APPLICATION_RESEARCH, false);
  assert.equal(defaults.ALLOW_PRIVATE_LAB_TARGETS, false);
  assert.equal(defaults.LAB_TARGET_HOSTS, '');
});

test('a non-lab private host stays blocked when the lab flag is on', async () => {
  assert.equal(labPrivateAllowed('evil.example.test', labAllow), false);
  assert.equal(labPrivateAllowed('lab.anteater.test', labAllow), true);
  assert.equal(labPrivateAllowed('lab.anteater.test', parseLabTargetAllow(false, 'lab.anteater.test')), false);
  const outsider = transport('192.168.60.26');
  const blocked = await executePassiveHttp('https://evil.example.test/', { maxBytes: 1024, deps: outsider.deps, labTargets: labAllow });
  assert.equal(blocked.error, 'blocked_address');
  assert.equal(outsider.calls(), 0);
  const unlisted = transport('10.1.2.3');
  const stillBlocked = await executePassiveHttp('https://lab.anteater.test/', {
    maxBytes: 1024, deps: unlisted.deps, labTargets: parseLabTargetAllow(true, 'other.example.test'),
  });
  assert.equal(stillBlocked.error, 'blocked_address');
  assert.equal(unlisted.calls(), 0);
});

test('the lab flag allows an allow-listed private address and still refuses loopback', async () => {
  const lab = transport('192.168.60.26');
  const result = await executePassiveHttp('https://lab.anteater.test/', { maxBytes: 1024, deps: lab.deps, labTargets: labAllow });
  assert.equal(lab.calls(), 1);
  assert.equal(lab.options()?.host, '192.168.60.26');
  assert.equal(result.ip, '192.168.60.26');
  const flaggedOff = transport('192.168.60.26');
  const denied = await executePassiveHttp('https://lab.anteater.test/', {
    maxBytes: 1024, deps: flaggedOff.deps, labTargets: parseLabTargetAllow(false, 'lab.anteater.test'),
  });
  assert.equal(denied.error, 'blocked_address');
  assert.equal(flaggedOff.calls(), 0);
  const loopback = transport('127.0.0.1');
  const local = await executePassiveHttp('https://lab.anteater.test/', { maxBytes: 1024, deps: loopback.deps, labTargets: labAllow });
  assert.equal(local.error, 'blocked_address');
  assert.equal(loopback.calls(), 0);
});
