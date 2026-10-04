import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { CampaignService } from '../packages/campaigns/service.js';
import { CampaignError, prepareScope } from '../packages/campaigns/contracts.js';
import { createDashboard } from '../apps/dashboard/server.js';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const input = { name: 'Portal baseline', targets: ['app.example.test'], excluded: [], sourceUrl: 'https://example.test/policy', expiresAt: '2099-01-01T00:00:00Z', reviewed: true };
async function finish(service: CampaignService) {
  for (let i = 0; service.state().active && i < 200; i++) await sleep(10);
  assert.equal(service.state().active, null);
}
const executor = async () => ({ status: 200, signals: [], contentType: 'text/html' });

test('scope preview canonicalizes hosts, removes duplicates and exclusions, and preserves input line errors', () => {
  const preview = prepareScope({ ...input, targets: ['APP.example.test', '', 'https://app.example.test/', 'api.example.test'], excluded: ['api.example.test'] });
  assert.deepEqual(preview.targets, ['https://app.example.test/']);
  assert.equal(preview.maxRequests, 1); assert.match(preview.warnings[0]!, /Line 3/);
  assert.throws(() => prepareScope({ ...input, targets: ['', 'app.example.test/path'] }), error => error instanceof CampaignError && error.issues[0]?.line === 2);
  assert.throws(() => prepareScope({ ...input, excluded: input.targets }), /no_included_targets/);
  assert.throws(() => prepareScope({ ...input, expiresAt: '2000-01-01T00:00:00Z' }), /expired_authorization/);
});

test('projects and incomplete drafts persist; concurrent edits require the current revision', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anteater-projects-')); const service = new CampaignService(directory, executor, 1);
  try {
    await service.init();
    const project = await service.saveProject({ name: 'Portal', scope: input });
    const results = await Promise.allSettled([1, 2].map(() => service.saveProject({ id: project.id, expectedRevision: 1, name: 'Portal updated', scope: input })));
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
    const draft = await service.saveDraft({ fields: { name: 'Work in progress', sourceUrl: 'unfinished' } });
    await assert.rejects(service.saveDraft({ id: draft.id, expectedRevision: 9, fields: {} }), /draft_changed/);
    await assert.rejects(service.saveDraft({ fields: { reviewed: true } }), /invalid_assessment_input/);
    const restored = new CampaignService(directory); await restored.init();
    assert.equal(restored.state().projects[0]?.revision, 2);
    assert.equal(restored.state().drafts[0]?.fields.sourceUrl, 'unfinished');
    assert.equal(restored.enabled, false);
    service.setEnabled(true);
    await assert.rejects(service.start({ ...input, projectId: project.id, projectRevision: 1 }), /project_changed/);
    const id = await service.start({ ...input, projectId: project.id, projectRevision: 2 }); await finish(service);
    await service.saveProject({ id: project.id, expectedRevision: 2, name: 'Renamed project', scope: { ...input, targets: ['other.example.test'] } });
    assert.equal(service.assessments.get(id)?.projectName, 'Portal updated');
    assert.equal(service.assessments.get(id)?.targets[0]?.url, 'https://app.example.test/');
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
});

test('submission keys prevent duplicate execution concurrently and after restart', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anteater-dedup-')); let requests = 0;
  const service = new CampaignService(directory, async () => { requests++; return executor(); }, 1);
  try {
    await service.init(); service.setEnabled(true); const key = randomUUID();
    const ids = await Promise.all([service.start(input, false, key), service.start(input, false, key)]);
    assert.equal(ids[0], ids[1]); await finish(service); assert.equal(requests, 1);
    const restored = new CampaignService(directory); await restored.init();
    assert.equal(await restored.start(input, false, key), ids[0], 'replay does not require enabling requests');
    await assert.rejects(restored.start({ ...input, name: 'Changed input' }, false, key), /idempotency_key_conflict/);
    await service.archive(ids[0]!, true); assert.ok(service.assessments.get(ids[0]!)?.archivedAt);
    await service.archive(ids[0]!, false); assert.equal(service.assessments.get(ids[0]!)?.archivedAt, undefined);
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
});

test('failed and truncated targets produce completed with gaps while all failures produce failed', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anteater-outcomes-'));
  const service = new CampaignService(directory, async target => target.includes('broken') ? { error: 'certificate_expired' } : { status: 200, truncated: true, signals: [] }, 1);
  try {
    await service.init(); service.setEnabled(true);
    const partial = await service.start({ ...input, targets: ['app.example.test', 'broken.example.test'] }); await finish(service);
    assert.equal(service.assessments.get(partial)?.status, 'completed_with_gaps');
    assert.ok(service.assessments.get(partial)?.targets.every(target => target.startedAt && target.finishedAt));
    const failed = await service.start({ ...input, targets: ['broken.example.test'] }); await finish(service);
    assert.equal(service.assessments.get(failed)?.status, 'failed');
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
});

test('legacy migration backs up original bytes once and rejects unknown schema versions', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anteater-migration-')); const id = randomUUID();
  try {
    const original = JSON.stringify({ id, name: 'Legacy', demo: false, status: 'running', createdAt: new Date().toISOString(), sourceUrl: input.sourceUrl, expiresAt: input.expiresAt, targets: [{ url: 'https://app.example.test/', status: 'queued', findings: [] }] });
    const path = join(directory, id + '.json'); await writeFile(path, original);
    await new CampaignService(directory).init(); await new CampaignService(directory).init();
    assert.equal(await readFile(join(directory, id + '.legacy-backup.json'), 'utf8'), original);
    const migrated = JSON.parse(await readFile(path, 'utf8')); assert.equal(migrated.schemaVersion, 1); assert.equal(migrated.status, 'interrupted');
    await writeFile(path, JSON.stringify({ ...migrated, schemaVersion: 999 }));
    await assert.rejects(new CampaignService(directory).init());
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('event streams require a session and reconnect with a complete current snapshot', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anteater-events-'));
  const service = new CampaignService(directory, executor, 1); const app = await createDashboard(service, 0);
  const controllers: AbortController[] = [];
  try {
    assert.equal((await fetch(app.origin + '/api/events')).status, 401);
    const cookie = (await fetch(app.origin)).headers.get('set-cookie')!.split(';')[0]!;
    for (const enabled of [false, true]) {
      service.setEnabled(enabled);
      const controller = new AbortController(); controllers.push(controller);
      const response = await fetch(app.origin + '/api/events', { headers: { cookie, 'Last-Event-ID': 'old-process:9999' }, signal: controller.signal });
      assert.match(response.headers.get('content-type')!, /text\/event-stream/);
      const reader = response.body!.getReader(); let text = '';
      while (!text.includes('data: ')) text += new TextDecoder().decode((await reader.read()).value);
      const snapshot = JSON.parse(text.split('data: ')[1]!.split('\n')[0]!);
      assert.equal(snapshot.enabled, enabled); assert.equal(snapshot.health.storage, 'ready');
      await reader.cancel(); controller.abort();
    }
  } finally { controllers.forEach(controller => controller.abort()); await app.close(); await rm(directory, { recursive: true, force: true }); }
});

test('CLI uses the dashboard service and retries the same submission without a second request', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anteater-cli-')); let requests = 0;
  const service = new CampaignService(directory, async () => { requests++; return executor(); }, 1);
  const app = await createDashboard(service, 0);
  const cli = (...args: string[]) => promisify(execFile)(process.execPath, ['--import', 'tsx', 'scripts/assessment.ts', ...args], {
    env: { ...process.env, ANTEATER_DASHBOARD_URL: app.origin }, timeout: 15000,
  });
  try {
    const path = join(directory, 'input.json'); await writeFile(path, JSON.stringify(input));
    const preview = JSON.parse((await cli('preview', path)).stdout); assert.equal(preview.maxRequests, 1);
    service.setEnabled(true); const key = `--key=${randomUUID()}`;
    const first = JSON.parse((await cli('start', path, key)).stdout); await finish(service);
    service.setEnabled(false);
    const retry = JSON.parse((await cli('start', path, key)).stdout);
    assert.equal(retry.id, first.id); assert.equal(requests, 1);
    assert.equal(JSON.parse((await cli('list')).stdout).assessments.length, 1);
  } finally { await app.close(); await rm(directory, { recursive: true, force: true }); }
});

test('workspace write failure disables execution and is visible in health without publishing unsaved data', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anteater-storage-failure-'));
  const service = new CampaignService(directory, executor, 1);
  try {
    await service.init(); service.setEnabled(true);
    await mkdir(join(directory, 'workspace.json'));
    await assert.rejects(service.saveDraft({ fields: { name: 'Cannot save' } }));
    assert.equal(service.state().health.storage, 'error'); assert.equal(service.enabled, false);
    assert.equal(service.state().drafts.length, 0);
    await assert.rejects(service.start(input), /assessment_storage_failed/);
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
});
