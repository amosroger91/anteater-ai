import EmbeddedPostgres from 'embedded-postgres';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';

const directory=await mkdtemp(join(tmpdir(),'anteater-postgres-'));
const password=randomBytes(24).toString('hex');
const port=55439;
const postgres=new EmbeddedPostgres({databaseDir:join(directory,'data'),user:'anteater',password,port,persistent:true,
  postgresFlags:['-h','127.0.0.1'],onLog:()=>{},onError:()=>{}});
const env={...process.env,DATABASE_URL:`postgresql://anteater:${password}@127.0.0.1:${port}/anteater`,GLOBAL_KILL_SWITCH:'false'};
const run=(args:string[])=>new Promise<void>((resolve,reject)=>{
  const child=spawn(process.execPath,['--import','tsx',...args],{env,stdio:'inherit'});
  child.on('error',reject); child.on('exit',code=>code===0?resolve():reject(new Error(`verification_exit_${code}`)));
});
let started=false;
try {
  await postgres.initialise(); await postgres.start(); started=true;
  await postgres.createDatabase('anteater');
  console.log('Temporary PostgreSQL ready on loopback.');
  await run(['--test','tests/integration/state.test.ts']);
  await run(['apps/orchestrator/worker.ts','--once']);
  await run(['apps/orchestrator/demo.ts']);
  const client=postgres.getPgClient('anteater');
  await client.connect();
  try {
    const counts=await client.query("SELECT (SELECT count(*) FROM research_jobs WHERE status='completed') AS jobs,(SELECT count(*) FROM observations) AS observations");
    if(counts.rows[0].jobs !== '1' || counts.rows[0].observations !== '1') throw new Error('fixture_replay_duplicated_work');
  } finally { await client.end(); }
  console.log('Integration and idempotent fixture replay passed.');
} finally {
  if(started) await postgres.stop();
  // Retain the temporary database for diagnostics. No recursive filesystem deletion here.
  console.log(`Stopped temporary PostgreSQL; diagnostic data: ${directory}`);
}
