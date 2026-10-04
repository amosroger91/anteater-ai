import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { connect, migrate } from '../../packages/research-state/db.js';
import { saveProgram } from '../../packages/research-state/workspace.js';
import { loadConfig } from '../../packages/shared/config.js';
import { fixture } from '../../fixtures/program.js';
import { Jobs } from '../../packages/research-state/jobs.js';

test('campaign foundation migrations preserve policy, project, target and idempotency boundaries', async t => {
  const admin = connect(loadConfig().DATABASE_URL), schema = 'test_' + randomUUID().replaceAll('-', '');
  await admin.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(loadConfig().DATABASE_URL); url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = connect(url.href);
  const project = randomUUID(), policy = randomUUID(), run = randomUUID(), key = randomUUID(), target = randomUUID();
  const insertRun = (id: string, projectId = project, policyId = policy, program = fixture.id, idempotency = randomUUID()) => pool.query(`
    INSERT INTO campaign_runs(id,project_id,program_id,policy_revision_id,name,mode,status,created_by,idempotency_key,input_sha256,budget)
    VALUES($1,$2,$3,$4,'Baseline','passive','queued','local-operator',$5,$6,'{"maxRequests":1}')`, [id, projectId, program, policyId, idempotency, 'b'.repeat(64)]);
  try {
    await migrate(pool); await migrate(pool); await saveProgram(pool, fixture);
    await pool.query("INSERT INTO campaign_projects(id,program_id,name) VALUES($1,$2,'Portal')", [project, fixture.id]);
    await pool.query(`INSERT INTO campaign_policy_revisions(id,project_id,revision,source_sha256,source_url,policy,reviewed_by,expires_at)
      VALUES($1,$2,'v1',$3,'https://example.test/policy','{}','local-operator','2099-01-01')`, [policy, project, 'a'.repeat(64)]);
    await insertRun(run, project, policy, fixture.id, key);
    await pool.query("INSERT INTO campaign_targets(id,campaign_id,target_index,url,status) VALUES($1,$2,0,'https://app.example.test/','queued')", [target, run]);
    await t.test('repeat migration is harmless and policy revisions cannot be overwritten', async () => {
      assert.equal((await pool.query("SELECT count(*)::int AS count FROM schema_migrations WHERE version='007_campaign_foundation.sql'")).rows[0].count, 1);
      await assert.rejects(pool.query("UPDATE campaign_policy_revisions SET policy='{}' WHERE id=$1", [policy]), /immutable/);
    });
    await t.test('idempotency is unique per project/operator and policy cannot cross project boundaries', async () => {
      await assert.rejects(insertRun(randomUUID(), project, policy, fixture.id, key), /unique constraint/);
      const other = randomUUID(); await pool.query("INSERT INTO campaign_projects(id,program_id,name) VALUES($1,$2,'Other')", [other, fixture.id]);
      await assert.rejects(insertRun(randomUUID(), other), /foreign key constraint/);
      assert.equal((await pool.query('SELECT count(*)::int AS count FROM campaign_runs')).rows[0].count, 1);
    });
    await t.test('existing jobs link only to their program and a target in the same campaign', async () => {
      const jobs = new Jobs(pool); await jobs.enqueue(fixture.id, 'fixture-api', 'inspect_http_target', randomUUID());
      const job = (await pool.query('SELECT id FROM research_jobs LIMIT 1')).rows[0].id;
      const otherRun = randomUUID(); await insertRun(otherRun);
      await assert.rejects(pool.query('INSERT INTO campaign_job_links(job_id,campaign_id,program_id,target_id) VALUES($1,$2,$3,$4)', [job, otherRun, fixture.id, target]), /foreign key constraint/);
      await assert.rejects(pool.query('INSERT INTO campaign_job_links(job_id,campaign_id,program_id,target_id) VALUES($1,$2,$3,$4)', [job, run, 'different-program', target]), /foreign key constraint/);
      await pool.query('INSERT INTO campaign_job_links(job_id,campaign_id,program_id,target_id) VALUES($1,$2,$3,$4)', [job, run, fixture.id, target]);
      assert.equal((await pool.query('SELECT count(*)::int AS count FROM research_jobs')).rows[0].count, 1);
      assert.equal(await jobs.claim(), undefined, 'campaign-linked work waits for the campaign-aware admission path');
    });
    await t.test('event sequence collisions and invalid run states are rejected', async () => {
      const event = () => pool.query("INSERT INTO campaign_events(campaign_id,sequence,type,payload) VALUES($1,1,'campaign.created','{}')", [run]);
      await event(); await assert.rejects(event(), /unique constraint/);
      await assert.rejects(pool.query("UPDATE campaign_runs SET status='made_up' WHERE id=$1", [run]), /check constraint/);
      await assert.rejects(pool.query('UPDATE campaign_runs SET stop_epoch=-1 WHERE id=$1', [run]), /check constraint/);
    });
  } finally { await pool.end(); await admin.query(`DROP SCHEMA ${schema} CASCADE`); await admin.end(); }
});
