import { loadConfig } from '../../packages/shared/config.js';
import { log } from '../../packages/shared/log.js';
import { connect, migrate } from '../../packages/research-state/db.js';
import { saveProgram, exportWorkspace } from '../../packages/research-state/workspace.js';
import { Jobs } from '../../packages/research-state/jobs.js';
import { ToolGateway } from '../../packages/mcp/index.js';
import { FixtureProvider } from '../../packages/bounty-providers/index.js';
import { FixtureLLM } from '../../packages/llm/index.js';
import { analyzeObservation, analysisPromptHash, boundedObservation } from '../../packages/agent-runtime/index.js';

const config = loadConfig();
const pool = connect(config.DATABASE_URL);
try {
  if (config.GLOBAL_KILL_SWITCH) throw new Error('kill_switch: set GLOBAL_KILL_SWITCH=false explicitly for the fixture demo');
  await migrate(pool);
  const provider = new FixtureProvider();
  const programs = await provider.discover();
  for (const program of programs) {
    await saveProgram(pool, program);
    log('PROGRAM_DISCOVERED', { program: program.id, result: 'fixture' });
    const jobs = new Jobs(pool, config.MAX_CONCURRENT_JOBS, config.JOB_LEASE_SECONDS);
    await jobs.enqueue(program.id, 'fixture-api', 'inspect_http_target', 'fixture-v1:inspect');
    const job = await jobs.claim();
    if (job) {
      log('JOB_STARTED', { program: program.id, job: job.id });
      let observationId: string | undefined;
      let observation: unknown;
      try {
        observation = await new ToolGateway(pool, loadConfig).invoke(job, job.action, job.asset_id);
        observationId = await jobs.complete(job, observation);
      } catch (error) {
        if (error instanceof Error && error.message === 'rate_limited') await jobs.defer(job);
        else await jobs.fail(job);
        log('JOB_FAILED', { program: program.id, job: job.id, result: error instanceof Error && /^[a-z_]+$/.test(error.message) ? error.message : 'operation_failed' });
      }
      if (observationId) {
        try {
          const analysis = await analyzeObservation(new FixtureLLM(), observation);
          await jobs.recordAnalysis(job, observationId, analysis);
          log('ANALYSIS_ACCEPTED', { program: program.id, job: job.id, result: `label:${analysis.analysis.label}` });
        } catch (error) {
          const failed = error as { response?: { text?: string; model?: string; modelDigest?: string; samplingOptions?: Record<string, unknown> }; input?: string; cause?: unknown };
          const response = failed.response;
          await jobs.recordAnalysisFailure(job, {
            rawText: response?.text ?? null,
            model: response?.model ?? 'unknown', modelDigest: response?.modelDigest ?? null,
            samplingOptions: response?.samplingOptions ?? {}, promptHash: analysisPromptHash(boundedObservation(observation)), schemaVersion: '1', status: 'parse_failed',
            errorCode: typeof failed.cause === 'string' ? failed.cause : 'analysis_parse_failed',
          });
          log('ANALYSIS_FAILED', { program: program.id, job: job.id, result: 'parse_failed' });
        }
      }
    }
    await exportWorkspace(pool, config.PROGRAMS_DIR, program.id);
    log('WORKSPACE_EXPORTED', { program: program.id });
  }
} catch (error) {
  log('DEMO_FAILED', { result: error instanceof Error && /^[a-z_]+(?::.*)?$/.test(error.message) ? error.message : 'operation_failed' });
  process.exitCode = 1;
} finally { await pool.end(); }
