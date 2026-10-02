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
  } finally { await pool.end(); await admin.query(`DROP SCHEMA ${schema} CASCADE`); await admin.end(); await rm(root,{recursive:true,force:true}); }
});
