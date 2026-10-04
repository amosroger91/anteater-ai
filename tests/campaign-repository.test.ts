import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileCampaignRepository } from '../packages/campaigns/repository.js';
import { CampaignService } from '../packages/campaigns/service.js';

test('file repository snapshots validate persistence and do not share mutable state', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anteater-repository-'));
  try {
    const repository = new FileCampaignRepository(directory);
    const initial = await repository.initialize(); assert.equal(initial.assessments.length, 0);
    const workspace = { schemaVersion:1 as const, projects:[], drafts:[] };
    await repository.saveWorkspace(workspace);
    const state = await repository.initialize(); state.workspace.schemaVersion = 999 as 1;
    assert.equal((await repository.initialize()).workspace.schemaVersion, 1);
    await assert.rejects(repository.saveWorkspace(state.workspace));
    assert.equal((await repository.initialize()).workspace.schemaVersion, 1);
    await writeFile(join(directory, 'workspace.json'), '{broken');
    await assert.rejects(repository.initialize(), /invalid_workspace_file/);
  } finally { await rm(directory, { recursive:true, force:true }); }
});

test('campaign service accepts a repository boundary and persists restart recovery through it', async () => {
  const saved: string[] = [];
  const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const service = new CampaignService('unused', undefined, 1, {
    async initialize() { return { workspace:{ schemaVersion:1, projects:[], drafts:[] }, assessments:[{
      id, name:'Interrupted', demo:false, createdAt:'2026-10-03T00:00:00Z', status:'running',
      sourceUrl:'https://example.test/policy', expiresAt:'2099-01-01T00:00:00Z', targets:[{ url:'https://app.example.test/', status:'running', findings:[] }],
    }] }; },
    async saveAssessment(assessment) { saved.push(assessment.status); },
    async saveWorkspace() { throw new Error('unexpected_workspace_write'); },
  });
  await service.init();
  assert.deepEqual(saved, ['interrupted']); assert.equal(service.assessments.get(id)?.status, 'interrupted');
  assert.equal(service.enabled, false); await service.close();
});
