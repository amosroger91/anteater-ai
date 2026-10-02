import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,readFile,writeFile,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { connect,migrate } from '../../packages/research-state/db.js';
import { saveProgram,exportWorkspace } from '../../packages/research-state/workspace.js';
import { Jobs,acquireRate } from '../../packages/research-state/jobs.js';
import { ToolGateway } from '../../packages/mcp/index.js';
import { loadConfig } from '../../packages/shared/config.js';
import { fixture } from '../../fixtures/program.js';
import { ProgramSchema } from '../../packages/bounty-providers/index.js';

test('PostgreSQL leases, gateway, rate limits, recovery and Markdown',async t=>{
  // Separate schema: never truncate an operator database.
  const base=loadConfig(); const admin=connect(base.DATABASE_URL);
  const schema='test_'+randomUUID().replaceAll('-','');
  await admin.query(`CREATE SCHEMA ${schema}`);
  const url=new URL(base.DATABASE_URL); url.searchParams.set('options',`-c search_path=${schema}`);
  const pool=connect(url.toString()); const root=await mkdtemp(join(tmpdir(),'anteater-'));
  try {
    await migrate(pool); await migrate(pool); await saveProgram(pool,fixture);
    const jobs=new Jobs(pool,1,30);
    const enqueue=async(key:string)=>jobs.enqueue(fixture.id,'fixture-api','inspect_http_target',key);
    await t.test('enqueue deduplicates; parallel workers respect global limit',async()=>{
      await Promise.all([enqueue('one'),enqueue('one'),enqueue('two')]);
      assert.equal((await pool.query('SELECT count(*)::int AS n FROM research_jobs')).rows[0].n,2);
      const claims=await Promise.all([jobs.claim(),jobs.claim(),jobs.claim()]);
      assert.equal(claims.filter(Boolean).length,1);
    });
    await pool.query("UPDATE research_jobs SET lease_until=now()-interval '1 second' WHERE status='running'");
    const recovered=await jobs.claim(); assert.ok(recovered); assert.equal(recovered.attempts,2);
    await t.test('restart recovers expired lease and fences old owner',async()=>{
      await assert.rejects(jobs.complete({...recovered,lease_token:randomUUID()},{}),/lost_lease/);
    });
    let config=loadConfig({GLOBAL_KILL_SWITCH:'false'});
    const gateway=new ToolGateway(pool,()=>config);
    await t.test('gateway rejects arbitrary commands and asset identifiers',async()=>{
      await assert.rejects(gateway.invoke(recovered,'shell','fixture-api'),/denied/);
      await assert.rejects(gateway.invoke(recovered,recovered.action,'unknown'),/denied/);
      config={...config,GLOBAL_KILL_SWITCH:true};
      await assert.rejects(gateway.invoke(recovered,recovered.action,recovered.asset_id),/kill_switch/);
      config={...config,GLOBAL_KILL_SWITCH:false};
    });
    await t.test('fresh policy exclusions are enforced at invocation',async()=>{
      await pool.query('UPDATE scope_rules SET policy=$1',[JSON.stringify({...fixture.policy,excluded:['api.example.test']})]);
      await assert.rejects(gateway.invoke(recovered,recovered.action,recovered.asset_id),/excluded/);
      await saveProgram(pool,fixture);
    });
    await t.test('fixture runs and observation persists atomically',async()=>{
      const output=await gateway.invoke(recovered,recovered.action,recovered.asset_id);
      assert.equal(output.fixture,true); await jobs.complete(recovered,output);
      assert.equal((await pool.query('SELECT count(*)::int AS n FROM observations')).rows[0].n,1);
      await assert.rejects(gateway.invoke(recovered,recovered.action,recovered.asset_id),/lost_lease/);
    });
    await t.test('shared rate reservation permits only one concurrent request',async()=>{
      await pool.query('DELETE FROM rate_limits');
      const reservations=await Promise.all([acquireRate(pool,fixture.id,0.01,0.01),acquireRate(pool,fixture.id,0.01,0.01)]);
      assert.equal(reservations.filter(Boolean).length,1);
    });
    await t.test('Markdown replay preserves operator notes and clears outbox',async()=>{
      await exportWorkspace(pool,root,fixture.id);
      const notes=join(root,fixture.id,'NOTES.md'); await writeFile(notes,'My notes');
      await saveProgram(pool,fixture); await exportWorkspace(pool,root,fixture.id);
      assert.equal(await readFile(notes,'utf8'),'My notes');
      assert.match(await readFile(join(root,fixture.id,'RECON.md'),'utf8'),/Synthetic/);
      assert.equal((await pool.query('SELECT count(*)::int AS n FROM workspace_outbox')).rows[0].n,0);
      await assert.rejects(exportWorkspace(pool,root,'../escape'),/invalid_program_id/);
    });
    await t.test('exhausted crashed job becomes failed',async()=>{
      const last=await jobs.claim(); assert.ok(last);
      await pool.query("UPDATE research_jobs SET attempts=max_attempts,lease_until=now()-interval '1 second' WHERE id=$1",[last.id]);
      assert.equal(await jobs.claim(),undefined);
      assert.equal((await pool.query('SELECT status FROM research_jobs WHERE id=$1',[last.id])).rows[0].status,'failed');
    });
    await t.test('completion persists evidence, audit and only policy-allowed follow-ups atomically', async () => {
      const program = ProgramSchema.parse({ ...fixture, policy: { ...fixture.policy, revision: 'depth-v1',
        allowedActions: ['inspect_http_target', 'inspect_robots', 'inspect_sitemap', 'inspect_openapi'], allowedPaths: ['/', '/robots.txt'] } });
      await saveProgram(pool, program);
      await jobs.enqueue(program.id, 'fixture-api', 'inspect_http_target');
      const job = await jobs.claim(); assert.ok(job);
      const observation = { status: 200, contentType: 'text/html', bodySnippet: 'Swagger documentation', bodySha256: 'a'.repeat(64), hashScope: 'captured_bytes', bodyBytes: 42, truncated: true, signals: [{ code: 'missing_hsts', severity: 'low' }] };
      const id = await jobs.complete(job, observation);
      assert.deepEqual((await pool.query("SELECT action FROM research_jobs WHERE status='queued'")).rows.map(row => row.action), ['inspect_robots']);
      const evidence = (await pool.query('SELECT sha256,body FROM evidence')).rows[0];
      assert.equal(evidence.sha256, observation.bodySha256); assert.equal(evidence.body.observationId, id); assert.equal(evidence.body.truncated, true);
      assert.equal((await pool.query("SELECT count(*)::int AS n FROM findings WHERE status='OBSERVATION'")).rows[0].n, 1);
      const before = (await pool.query('SELECT count(*)::int AS n FROM audit_events')).rows[0].n;
      await assert.rejects(jobs.complete(job, observation), /lost_lease/);
      assert.equal((await pool.query('SELECT count(*)::int AS n FROM audit_events')).rows[0].n, before);
      await exportWorkspace(pool, root, program.id);
      assert.match(await readFile(join(root, program.id, 'AUDIT.md'), 'utf8'), /OBSERVATION_RECORDED/);
      assert.match(await readFile(join(root, program.id, 'HYPOTHESES.md'), 'utf8'), /operator triage/);
    });
    await t.test('policy updates invalidate stale work and allow a new root job', async () => {
      const stale = await jobs.claim(); assert.ok(stale);
      const program = ProgramSchema.parse({ ...fixture, policy: { ...fixture.policy, revision: 'depth-v2' } });
      await saveProgram(pool, program);
      await assert.rejects(jobs.complete(stale, {}), /policy_changed/);
      await jobs.enqueue(program.id, 'fixture-api', 'inspect_http_target');
      const fresh = await jobs.claim(); assert.ok(fresh); assert.equal(fresh.policy_revision, 'depth-v2');
      await jobs.complete(fresh, { kind: 'OBSERVATION', fixture: true });
    });
    await t.test('nonfixture network execution needs its separate opt-in even with active testing set', async () => {
      const program = ProgramSchema.parse({ ...fixture, id: 'reviewed-web', platform: 'operator',
        policy: { ...fixture.policy, programId: 'reviewed-web' }, assets: [{ id: 'reviewed-api', url: 'https://api.example.test' }] });
      await saveProgram(pool, program);
      await jobs.enqueue(program.id, 'reviewed-api', 'inspect_http_target');
      const job = await jobs.claim(); assert.ok(job);
      config = { ...config, ALLOW_ACTIVE_TESTING: true };
      await pool.query('DELETE FROM rate_limits');
      await assert.rejects(gateway.invoke(job, job.action, job.asset_id), /live_executor_not_enabled/);
      assert.equal((await pool.query('SELECT count(*)::int AS n FROM rate_limits')).rows[0].n, 0);
      await pool.query("UPDATE research_jobs SET status='failed',lease_token=NULL,lease_until=NULL WHERE id=$1", [job.id]);
    });
    await t.test('several workers fill available slots without exceeding fleet concurrency', async () => {
      const parallel = new Jobs(pool, 3, 30);
      await Promise.all(Array.from({ length: 5 }, (_, i) => parallel.enqueue(fixture.id, 'fixture-api', 'inspect_http_target', `parallel:${i}`)));
      const claims = await Promise.all(Array.from({ length: 6 }, () => parallel.claim()));
      assert.equal(claims.filter(Boolean).length, 3);
    });
    await t.test('changing an asset URL retires leases tied to the former target', async () => {
      const program = ProgramSchema.parse({ ...fixture, policy: { ...fixture.policy, revision: 'depth-v2' }, assets: [{ id: 'fixture-api', url: 'https://new.example.test' }] });
      await saveProgram(pool, program);
      assert.equal((await pool.query("SELECT count(*)::int AS n FROM research_jobs WHERE asset_id='fixture-api' AND status IN ('queued','running')")).rows[0].n, 0);
      await jobs.enqueue(program.id, 'fixture-api', 'inspect_http_target');
      assert.ok(await jobs.claim());
    });
  } finally { await pool.end(); await admin.query(`DROP SCHEMA ${schema} CASCADE`); await admin.end(); await rm(root,{recursive:true,force:true}); }
});
