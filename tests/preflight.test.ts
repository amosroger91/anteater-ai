import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePreflight, parseHandles, type PreflightFacts } from '../packages/preflight/index.js';

const ready: PreflightFacts = {
  killSwitch: false,
  passiveHttp: true,
  dbReachable: true,
  pendingMigrations: [],
  hackerOneUser: true,
  hackerOneToken: true,
  handles: ['acme'],
  programs: [{ id: 'h1-acme', requestsPerSecond: 2 }],
};

test('parseHandles keeps enrolled handles and drops comments', () => {
  assert.deepEqual(parseHandles('# comment\nacme\n\nother-program\n'), ['acme', 'other-program']);
});

test('preflight passes only when the live flags, database, credentials, handles, and rates are ready', () => {
  const pass = evaluatePreflight(ready);
  assert.equal(pass.ok, true);
  assert.match(pass.lines.join('\n'), /ok kill_switch GLOBAL_KILL_SWITCH=false/);
  assert.equal(evaluatePreflight({ ...ready, programs: [] }).ok, true);
  assert.equal(evaluatePreflight({ ...ready, killSwitch: true }).ok, false);
  assert.equal(evaluatePreflight({ ...ready, passiveHttp: false }).ok, false);
  assert.equal(evaluatePreflight({ ...ready, dbReachable: false, pendingMigrations: ['013_lead_readiness.sql'] }).ok, false);
  assert.equal(evaluatePreflight({ ...ready, pendingMigrations: ['013_lead_readiness.sql'] }).ok, false);
  assert.equal(evaluatePreflight({ ...ready, hackerOneToken: false }).ok, false);
  assert.equal(evaluatePreflight({ ...ready, handles: [] }).ok, false);
  assert.equal(evaluatePreflight({ ...ready, handles: ['bad handle'] }).ok, false);
  assert.equal(evaluatePreflight({ ...ready, programs: [{ id: 'h1-acme', requestsPerSecond: 50 }] }).ok, false);
  assert.equal(evaluatePreflight({ ...ready, programs: [{ id: 'h1-acme', requestsPerSecond: null }] }).ok, false);
  const secret = 'super-secret-token';
  assert.equal(pass.lines.join('\n').includes(secret), false);
});
