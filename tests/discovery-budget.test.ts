import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ProgramBudget } from '../packages/budget/index.js';
import { CertTransparencyDiscovery, type FetchLike } from '../packages/discovery/adapters.js';
import { discoverWithinBudget, type LiveDiscoverySources } from '../packages/discovery/live.js';
import { PassiveDnsDiscovery, SubfinderDiscovery, type ExecLike } from '../packages/discovery/more-adapters.js';
import { partition, toCandidates } from '../packages/discovery/index.js';

const policy = {
  programId: 'p', revision: 'r', sourceUrl: 'https://example.test/policy', reviewed: true as const,
  expiresAt: '2099-01-01T00:00:00.000Z', allowed: ['*.example.test', 'app.example.test'], excluded: ['secret.example.test'],
  allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1,
};

function budget(rate: number, now: () => number) {
  return new ProgramBudget({ globalRatePerSec: rate, perHostRatePerSec: rate, concurrency: 1, bodyCapBytes: 1024, timeoutMs: 1000 }, now);
}

test('a budgeted cycle calls only documented sources and partition still holds the out-of-scope name', async () => {
  const urls: string[] = [];
  const fetchLike: FetchLike = async url => {
    urls.push(url);
    return { ok: true, status: 200, async text() { return JSON.stringify([{ name_value: 'staging.example.test\nsecret.example.test\noutside.example' }]); } };
  };
  const resolved: string[] = [];
  const resolver = async (host: string) => {
    resolved.push(host);
    return ['staging.example.test', 'secret.example.test'];
  };
  const execArgs: string[][] = [];
  const exec: ExecLike = async (_bin, args) => {
    execArgs.push(args);
    return { stdout: '{"host":"staging.example.test"}\n{"host":"secret.example.test"}\n' };
  };
  const sources: LiveDiscoverySources = {
    certTransparency: new CertTransparencyDiscovery(fetchLike),
    passiveDns: new PassiveDnsDiscovery(resolver),
    subfinder: new SubfinderDiscovery(exec, 'SUBFINDER_BIN', { SUBFINDER_BIN: '/opt/subfinder' }),
  };
  const raw = await discoverWithinBudget(sources, ['example.test'], budget(10, () => 0));
  assert.equal(urls.length, 1);
  const crt = new URL(urls[0] ?? '');
  assert.equal(crt.origin, 'https://crt.sh');
  assert.equal(resolved.length, 1);
  assert.equal(execArgs.length, 1);
  assert.ok(execArgs[0]?.includes('example.test'));
  const { admitted, held } = partition(toCandidates(raw, ['example.test']), policy, 'inspect_http_target');
  assert.ok(admitted.some(row => row.candidate.host === 'staging.example.test'));
  assert.ok(held.some(row => row.candidate.host === 'secret.example.test'));
  assert.equal(admitted.some(row => row.candidate.host === 'secret.example.test'), false);
});

test('a denied root is not passed to any discovery adapter', async () => {
  let calls = 0;
  const sources: LiveDiscoverySources = {
    certTransparency: { async discover() { calls += 1; return []; } },
    passiveDns: { async discover() { calls += 1; return []; } },
    subfinder: { async discover() { calls += 1; return []; } },
  };
  const limited = budget(1, () => 0);
  await discoverWithinBudget(sources, ['one.example.test', 'two.example.test'], limited);
  assert.equal(calls, 3);
  await discoverWithinBudget(sources, ['three.example.test'], limited);
  assert.equal(calls, 3);
});

test('subfinder is not executed when its binary is unset, even if the budget allows the root', async () => {
  let execs = 0;
  const exec: ExecLike = async () => { execs += 1; return { stdout: '' }; };
  const sources: LiveDiscoverySources = {
    certTransparency: { async discover() { return []; } },
    passiveDns: new PassiveDnsDiscovery(async () => []),
    subfinder: new SubfinderDiscovery(exec, 'SUBFINDER_BIN', {}),
  };
  await discoverWithinBudget(sources, ['app.example.test'], budget(10, () => 0));
  assert.equal(execs, 0);
});
