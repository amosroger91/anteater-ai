import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { DashboardService, type Assessment } from '../apps/dashboard/service.js';
import { createDashboard } from '../apps/dashboard/server.js';
import http from 'node:http';

const input = { name: 'Authorized assessment', targets: ['app.example.test'], sourceUrl: 'https://example.test/policy', expiresAt: '2099-01-01T00:00:00Z', reviewed: true };
async function finished(service: DashboardService) {
  for (let i = 0; service.state().active && i < 100; i++) await sleep(10);
  assert.equal(service.state().active, null);
}
test('dashboard fails closed, stores bounded metadata, and restores completed history', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anteater-dashboard-')); let calls = 0;
  const service = new DashboardService(directory, async (_, options) => {
    await options.beforeRequest?.(); calls++;
    return { status: 200, contentType: 'application/json', bodySnippet: 'must not be stored', signals: [] };
  }, 1);
  try {
    await service.init();
    await assert.rejects(service.start(input), /disabled/);
    service.setEnabled(true);
    for (const targets of [['127.0.0.1'], ['app.example.test/private'], ['*.example.test'], ['2130706433'], ['user:pass@example.test']]) await assert.rejects(service.start({ ...input, targets }));
    await assert.rejects(service.start({ ...input, expiresAt: '2000-01-01T00:00:00Z' }));
    await service.start(input); await finished(service);
    assert.equal(calls, 1);
    assert.ok(!JSON.stringify(service.state()).includes('must not be stored'));
    assert.equal(service.state().assessments[0]?.targets[0]?.coverage?.checks.find(check => check.checkId === 'headers.csp')?.status, 'skipped');
    const restored = new DashboardService(directory); await restored.init();
    assert.equal(restored.state().assessments.length, 1); assert.equal(restored.enabled, false);
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
});

test('dashboard serializes starts and stop cancels in-flight work', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anteater-dashboard-'));
  let started!: () => void; const entered = new Promise<void>(resolve => { started = resolve; });
  const service = new DashboardService(directory, async (_, options) => {
    started(); await sleep(5000, undefined, { signal: options.signal }); return {};
  }, 1);
  try {
    await service.init(); service.setEnabled(true);
    const first = service.start(input); await assert.rejects(service.start(input), /already_running/); await first; await entered;
    service.setEnabled(false); await finished(service);
    assert.equal(service.state().assessments[0]?.status, 'cancelled');
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
});

test('dashboard marks interrupted history without silently resuming requests', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anteater-dashboard-'));
  const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  try {
    const run: Assessment = { id, name: 'Interrupted', status: 'running', createdAt: new Date().toISOString(), demo: false,
      sourceUrl: input.sourceUrl, expiresAt: input.expiresAt, targets: [{ url: 'https://app.example.test/', status: 'running', findings: [] }] };
    await writeFile(join(directory, id + '.json'), JSON.stringify(run));
    const service = new DashboardService(directory); await service.init();
    assert.equal(service.state().assessments[0]?.status, 'interrupted');
    assert.equal(service.state().assessments[0]?.targets[0]?.status, 'interrupted');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('dashboard HTTP requires local session, correct host and same-origin writes', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anteater-dashboard-'));
  const app = await createDashboard(new DashboardService(directory, undefined, 1), 0);
  try {
    assert.equal((await fetch(app.origin + '/api/state')).status, 401);
    const home = await fetch(app.origin); const cookie = home.headers.get('set-cookie')!.split(';')[0]!;
    assert.match(home.headers.get('content-security-policy')!, /frame-ancestors 'none'/);
    const post = (origin: string) => fetch(app.origin + '/api/controls', { method: 'POST', headers: { cookie, origin, 'content-type': 'application/json' }, body: '{"enabled":true}' });
    assert.equal((await post('https://outside.test')).status, 403);
    assert.equal((await post(app.origin)).status, 200);
    const wrongHostStatus = await new Promise<number | undefined>((resolve, reject) => {
      http.get(app.origin + '/api/state', { headers: { cookie, host: 'evil.test' } }, response => { response.resume(); resolve(response.statusCode); }).on('error', reject);
    });
    assert.equal(wrongHostStatus, 403);
    const state = await (await fetch(app.origin + '/api/state', { headers: { cookie } })).json(); assert.equal(state.enabled, true);
  } finally { await app.close(); await rm(directory, { recursive: true, force: true }); }
});
