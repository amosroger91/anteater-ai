import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { applyProfile, blankProfile, mergeProfile, profileStatus } from '../packages/setup/profile.js';
import { FileSetupStore, rawKeyProtector } from '../packages/setup/store.js';
import { loadConfig } from '../packages/shared/config.js';
import { createSetupServer, type SetupStore } from '../apps/setup/server.js';

const token = 'example-token-value';
const key = 'ab'.repeat(32);

function request(partial: Record<string, unknown> = {}) {
  return {
    approver: 'Example Reviewer',
    hackeroneUsername: 'example-researcher',
    hackeroneToken: token,
    clearHackeroneToken: false,
    labHosts: 'Lab.Anteater.Test',
    allowPrivateLabTargets: true,
    accountKey: key,
    evidenceKey: key,
    clearAccountKey: false,
    clearEvidenceKey: false,
    mailboxHost: '',
    mailboxUsername: '',
    mailboxPassword: '',
    clearMailboxPassword: false,
    mailboxDomain: '',
    ...partial,
  };
}

test('a saved profile reports what is present and does not return secrets', () => {
  const status = profileStatus(mergeProfile(blankProfile(), request()));
  assert.equal(status.programReady, true);
  assert.equal(status.labHosts, 'lab.anteater.test');
  assert.equal(status.hackeroneTokenSaved, true);
  assert.equal(JSON.stringify(status).includes(token), false);
  assert.equal(JSON.stringify(status).includes(key), false);
});

test('a blank secret field keeps the stored value, and a clear flag removes it', () => {
  const saved = mergeProfile(blankProfile(), request());
  const kept = mergeProfile(saved, request({ hackeroneToken: '', mailboxPassword: '' }));
  assert.equal(kept.hackeroneToken, token);
  const cleared = mergeProfile(saved, request({ hackeroneToken: '', clearHackeroneToken: true }));
  assert.equal(cleared.hackeroneToken, '');
  assert.equal(profileStatus(cleared).programReady, false);
});

test('private lab access requires a hostname, and the environment wins over the file', () => {
  assert.throws(() => mergeProfile(blankProfile(), request({ labHosts: '', allowPrivateLabTargets: true })), /lab_hosts_required/);
  assert.throws(() => mergeProfile(blankProfile(), request({ labHosts: '192.168.60.26' })), /invalid_lab_host/);
  const env = applyProfile({ ENABLE_PASSIVE_HTTP: 'false', LAB_TARGET_HOSTS: 'other.example.test' }, mergeProfile(blankProfile(), request()));
  assert.equal(env.LAB_TARGET_HOSTS, 'other.example.test');
  assert.equal(env.ENABLE_PASSIVE_HTTP, 'false');
  assert.equal(env.ALLOW_PRIVATE_LAB_TARGETS, 'true');
  assert.equal(loadConfig(env).GLOBAL_KILL_SWITCH, true);
  assert.equal(loadConfig(env).LAB_TARGET_HOSTS, 'other.example.test');
});

test('the setup file round-trips without writing the token in the clear', () => {
  const directory = mkdtempSync(join(tmpdir(), 'anteater-setup-'));
  const store = new FileSetupStore(directory, rawKeyProtector);
  store.write(mergeProfile(blankProfile(), request()));
  const opened = store.read();
  assert.equal(opened?.hackeroneToken, token);
  const onDisk = readFileSync(join(directory, 'setup.json'), 'utf8');
  assert.equal(onDisk.includes(token), false);
  assert.equal(onDisk.includes(key), false);
});

test('the loopback wizard saves a profile and its status hides the token', async () => {
  const memory: { profile: ReturnType<typeof blankProfile> | null } = { profile: null };
  const store: SetupStore = {
    read: () => memory.profile,
    write: profile => { memory.profile = profile; },
  };
  const server = createSetupServer(store);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  try {
    const page = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /Anteater setup/);
    const saved = await fetch(`http://127.0.0.1:${port}/api/setup`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: `http://127.0.0.1:${port}` },
      body: JSON.stringify(request()),
    });
    const body = await saved.json();
    assert.equal(saved.status, 200);
    assert.equal(body.hackeroneTokenSaved, true);
    assert.equal(JSON.stringify(body).includes(token), false);
    const status = await (await fetch(`http://127.0.0.1:${port}/api/status`)).json();
    assert.equal(status.programReady, true);
    assert.equal(JSON.stringify(status).includes(token), false);
    const scanner = await fetch(`http://127.0.0.1:${port}/run`);
    assert.equal(scanner.status, 200);
    assert.match(await scanner.text(), /Fixture scan/);
    const scan = await fetch(`http://127.0.0.1:${port}/api/scan/fixture`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: `http://127.0.0.1:${port}` },
      body: '{}',
    });
    const scanBody = await scan.json();
    assert.equal(scan.status, 200);
    assert.equal(scanBody.contactedNetwork, false);
    assert.deepEqual(scanBody.admitted, ['api.example.test']);
    assert.ok(scanBody.held.includes('secret.example.test'));
    assert.equal(scanBody.verification.reproduced, true);
    const rejected = await fetch(`http://127.0.0.1:${port}/api/scan/fixture`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://evil.example' },
      body: '{}',
    });
    assert.equal(rejected.status, 403);
  } finally {
    server.close();
    await once(server, 'close');
  }
});
