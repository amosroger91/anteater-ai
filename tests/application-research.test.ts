import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApplicationSchema } from '../packages/application-research/profile.js';
import { RequestGate, type Exchange } from '../packages/application-research/transport.js';

test('cleanup has a bounded reserved allowance after the ordinary budget and deadline', async () => {
  const app = ApplicationSchema.parse({ maxRequests: 5 }); const controller = new AbortController();
  let calls = 0;
  const exchange: Exchange = async input => { await input.beforeConnect(); calls++; return { status: 404, headers: {}, body: Buffer.alloc(0), truncated: false }; };
  const gate = new RequestGate('https://app.example.test', app, controller.signal, async () => {}, exchange, true);
  for (let i = 0; i < 5; i++) await gate.send('owner', 'discover', 'https://app.example.test/');
  await assert.rejects(gate.send('owner', 'discover', 'https://app.example.test/'), /request_budget/);
  controller.abort(new Error('assessment_deadline'));
  const cleanup = 'https://app.example.test/cleanup/owned-marker'; gate.ownedDeletes.add(cleanup);
  for (let i = 0; i < 10; i++) await gate.send('owner', 'verify', cleanup, 'DELETE', {}, undefined, true);
  await assert.rejects(gate.send('owner', 'verify', cleanup, 'DELETE', {}, undefined, true), /request_budget/);
  assert.equal(calls, 15);
});

test('reserved cleanup cannot bypass scope, active opt-in, or current revocation', async () => {
  const app = ApplicationSchema.parse({}); let requests = 0;
  const exchange: Exchange = async input => { await input.beforeConnect(); requests++; return { status: 204, headers: {}, body: Buffer.alloc(0), truncated: false }; };
  const url = 'https://app.example.test/cleanup/owned-marker';
  const gate = new RequestGate('https://app.example.test', app, new AbortController().signal, async () => { throw new Error('kill_switch'); }, exchange, true);
  await assert.rejects(gate.send('owner', 'verify', url, 'DELETE', {}, undefined, true), /cleanup_denied/);
  gate.ownedDeletes.add(url);
  await assert.rejects(gate.send('owner', 'verify', url, 'DELETE', {}, undefined, true), /kill_switch/);
  const disabled = new RequestGate(gate.origin, app, gate.signal, async () => {}, exchange, false); disabled.ownedDeletes.add(url);
  await assert.rejects(disabled.send('owner', 'verify', url, 'DELETE', {}, undefined, true), /active_testing_disabled/);
  assert.equal(requests, 0);
});

test('account IDs must be unique and canonical principal mapping is explicit', () => {
  const account = { id: 'same', usernameEnv: 'USER', passwordEnv: 'PASSWORD' };
  assert.equal(ApplicationSchema.safeParse({ auth: { accounts: [account, account] } }).success, false);
  assert.equal(ApplicationSchema.parse({}).auth.principalPointer, '/id');
});
