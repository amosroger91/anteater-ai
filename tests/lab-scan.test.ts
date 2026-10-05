import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import type { ClientRequest, IncomingMessage } from 'node:http';
import { once } from 'node:events';
import { blankProfile, mergeProfile } from '../packages/setup/profile.js';
import { createSetupServer, type SetupStore } from '../apps/setup/server.js';
import { scanSavedLab } from '../apps/setup/lab-scan.js';
import type { PassiveDeps } from '../packages/web-executor/index.js';

const request = {
  approver: 'Example Reviewer',
  hackeroneUsername: 'example-researcher',
  hackeroneToken: 'example-token-value',
  clearHackeroneToken: false,
  labHosts: 'lab.anteater.test',
  allowPrivateLabTargets: false,
  accountKey: 'ab'.repeat(32),
  evidenceKey: 'cd'.repeat(32),
  clearAccountKey: false,
  clearEvidenceKey: false,
  mailboxHost: '',
  mailboxUsername: '',
  mailboxPassword: '',
  clearMailboxPassword: false,
  mailboxDomain: '',
};

function transport(address: string) {
  const calls: string[] = [];
  const deps: PassiveDeps = {
    lookup: async () => [{ address, family: 4 }],
    request: (input, callback) => {
      calls.push(String(input.path));
      const request = new EventEmitter() as ClientRequest;
      const response = new PassThrough() as unknown as IncomingMessage;
      response.statusCode = 200;
      response.headers = { 'content-type': 'text/html' };
      request.destroy = () => { response.destroy(); return request; };
      request.end = (() => {
        queueMicrotask(() => {
          callback(response);
          response.emit('data', Buffer.from('<html>lab</html>'));
          response.emit('end');
        });
        return request;
      }) as ClientRequest['end'];
      return request;
    },
  };
  return { deps, calls };
}

test('a saved lab host is scanned with read-only requests, and any other host is refused', async () => {
  const profile = mergeProfile(blankProfile(), request);
  const live = transport('93.184.216.34');
  const scan = await scanSavedLab(profile, 'Lab.Anteater.Test', live.deps);
  assert.equal(scan.contactedNetwork, true);
  assert.deepEqual(live.calls, ['/', '/robots.txt', '/sitemap.xml', '/.well-known/openapi.json']);
  assert.equal(scan.checks[0]?.status, 200);
  assert.ok(scan.checks[0]?.findings.some(finding => finding.code === 'missing_headers'));
  assert.equal(JSON.stringify(scan).includes('example-token-value'), false);
  const refused = transport('93.184.216.34');
  await assert.rejects(() => scanSavedLab(profile, 'evil.example.test', refused.deps), /host_not_saved/);
  assert.equal(refused.calls.length, 0);
});

test('a private answer is not requested unless the saved lab flag is on', async () => {
  const blocked = transport('10.1.2.3');
  const profile = mergeProfile(blankProfile(), request);
  const denied = await scanSavedLab(profile, 'lab.anteater.test', blocked.deps);
  assert.equal(denied.contactedNetwork, false);
  assert.equal(denied.checks[0]?.error, 'blocked_address');
  assert.equal(blocked.calls.length, 0);
  const allowed = transport('10.1.2.3');
  const opened = await scanSavedLab(mergeProfile(blankProfile(), { ...request, allowPrivateLabTargets: true }), 'lab.anteater.test', allowed.deps);
  assert.equal(opened.contactedNetwork, true);
  assert.equal(allowed.calls.length, 4);
});

test('the scanner route refuses a host that was not saved and accepts one that was', async () => {
  const memory = { profile: mergeProfile(blankProfile(), request) };
  const store: SetupStore = { read: () => memory.profile, write: profile => { memory.profile = profile; } };
  const server = createSetupServer(store, { labDeps: transport('93.184.216.34').deps });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  try {
    const missing = await fetch(`http://127.0.0.1:${port}/api/scan/lab`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: `http://127.0.0.1:${port}` },
      body: JSON.stringify({ host: 'evil.example.test' }),
    });
    assert.equal(missing.status, 400);
    assert.equal((await missing.json()).error, 'host_not_saved');
    const scanned = await fetch(`http://127.0.0.1:${port}/api/scan/lab`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: `http://127.0.0.1:${port}` },
      body: JSON.stringify({ host: 'lab.anteater.test' }),
    });
    const body = await scanned.json();
    assert.equal(scanned.status, 200);
    assert.equal(body.contactedNetwork, true);
    assert.equal(body.checks.length, 4);
    assert.equal(JSON.stringify(body).includes('example-token-value'), false);
  } finally {
    server.close();
    await once(server, 'close');
  }
});
