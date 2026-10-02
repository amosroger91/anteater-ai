import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture } from '../fixtures/program.js';
import { FileProgramProvider, ProgramSchema } from '../packages/bounty-providers/index.js';
import { authorize, targetForAction } from '../packages/scope-engine/index.js';

test('file provider validates all programs and rejects collisions and excessive input', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anteater-manifest-'));
  const path = join(dir, 'programs.json');
  try {
    await writeFile(path, JSON.stringify({ programs: [fixture] }));
    assert.equal((await new FileProgramProvider(path).discover())[0]?.id, fixture.id);
    await writeFile(path, JSON.stringify([fixture, fixture]));
    await assert.rejects(new FileProgramProvider(path).discover(), /duplicate_program_id/);
    await writeFile(path, ' '.repeat(1048577));
    await assert.rejects(new FileProgramProvider(path).discover(), /too_large/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('program manifests reject out-of-scope, credential-bearing and path-bearing asset origins', () => {
  for (const url of ['https://evil.test', 'https://user:secret@api.example.test', 'https://api.example.test/admin', 'http://api.example.test', 'https://payments.example.test']) {
    assert.equal(ProgramSchema.safeParse({ ...fixture, assets: [{ id: 'api', url }] }).success, false);
  }
  assert.equal(ProgramSchema.safeParse({ ...fixture, policy: { ...fixture.policy, programId: 'other' } }).success, false);
});

test('fixed follow-up paths require both an action grant and an exact path grant', () => {
  const policy = { ...fixture.policy, allowedActions: ['inspect_http_target', 'inspect_robots'], allowedPaths: ['/', '/robots.txt'] };
  const config = { GLOBAL_KILL_SWITCH: false };
  assert.equal(targetForAction('https://api.example.test', 'inspect_robots'), 'https://api.example.test/robots.txt');
  assert.equal(authorize(policy, 'https://api.example.test/robots.txt', 'inspect_robots', config).allowed, true);
  assert.equal(authorize(fixture.policy, 'https://api.example.test/robots.txt', 'inspect_robots', config).allowed, false);
  assert.equal(authorize({ ...policy, allowedPaths: ['/'] }, 'https://api.example.test/robots.txt', 'inspect_robots', config).allowed, false);
  for (const path of ['/a/../robots.txt', '/%72obots.txt', '//robots.txt', '/robots.txt?token=secret']) {
    assert.equal(authorize(policy, `https://api.example.test${path}`, 'inspect_robots', config).allowed, false);
  }
  assert.throws(() => targetForAction('https://user:secret@api.example.test', 'inspect_robots'));
});
