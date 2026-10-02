import { randomUUID } from 'node:crypto';
import { loadConfig } from '../../packages/shared/config.js';
import { log } from '../../packages/shared/log.js';
import { connect, migrate } from '../../packages/research-state/db.js';
import { saveProgram, exportWorkspace } from '../../packages/research-state/workspace.js';
import { Jobs } from '../../packages/research-state/jobs.js';
import { ToolGateway } from '../../packages/mcp/index.js';
import { FixtureProvider } from '../../packages/bounty-providers/index.js';
import { FixtureLLM } from '../../packages/llm/index.js';
import { analyzeObservation } from '../../packages/agent-runtime/index.js';

const config = loadConfig();
const pool = connect(config.DATABASE_URL);
try {
  if (config.GLOBAL_KILL_SWITCH) throw new Error('kill_switch: set GLOBAL_KILL_SWITCH=false explicitly for the fixture demo');
  await migrate(pool);
  const provider = new FixtureProvider();
  const programs = await provider.discover();
  for (const program of programs) {
    await saveProgram(pool,program);
    log('PROGRAM_DISCOVERED',{program:program.id,result:'fixture'});
    const jobs = new Jobs(pool,config.MAX_CONCURRENT_JOBS,config.JOB_LEASE_SECONDS);
    await jobs.enqueue(program.id,'fixture-api','inspect_http_target','fixture-v1:inspect');
    const job = await jobs.claim();
    if (job) {
      log('JOB_STARTED',{program:program.id,job:job.id});
      try {
        const observation = await new ToolGateway(pool,loadConfig).invoke(job,job.action,job.asset_id);
        const analysis = await analyzeObservation(new FixtureLLM(),observation);
        await jobs.complete(job,{...observation,analysis});
        await pool.query('INSERT INTO agent_runs(id,job_id,role,model,result) VALUES($1,$2,$3,$4,$5)',[randomUUID(),job.id,'analysis',analysis.model,JSON.stringify(analysis)]);
        log('JOB_COMPLETED',{program:program.id,job:job.id});
      } catch (error) { await jobs.fail(job); throw error; }
    }
    await exportWorkspace(pool,config.PROGRAMS_DIR,program.id);
    log('WORKSPACE_EXPORTED',{program:program.id});
  }
} catch (error) {
  // Controlled errors only; don't print database connection strings or arbitrary upstream payloads.
  log('DEMO_FAILED',{result:error instanceof Error && /^[a-z_]+(?::.*)?$/.test(error.message) ? error.message : 'operation_failed'});
  process.exitCode=1;
} finally { await pool.end(); }
