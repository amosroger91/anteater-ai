import { setTimeout as sleep } from 'node:timers/promises';
import { loadConfig } from '../../packages/shared/config.js';
import { log } from '../../packages/shared/log.js';
import { connect, migrate } from '../../packages/research-state/db.js';
import { saveProgram, exportWorkspace } from '../../packages/research-state/workspace.js';
import { Jobs, type Job } from '../../packages/research-state/jobs.js';
import { ToolGateway } from '../../packages/mcp/index.js';
import { FixtureProvider } from '../../packages/bounty-providers/index.js';
import { FixtureLLM, OllamaProvider, type LLMProvider } from '../../packages/llm/index.js';
import { analyzeObservation, analysisPromptHash, boundedObservation } from '../../packages/agent-runtime/index.js';

const config = loadConfig();
const pool = connect(config.DATABASE_URL);
let stopping = false;
process.on('SIGINT', () => { stopping = true; });
process.on('SIGTERM', () => { stopping = true; });

function modelProvider(): LLMProvider {
  return process.env.LLM_PROVIDER === 'ollama'
    ? new OllamaProvider(config.OLLAMA_URL, config.LLM_MODEL, config.OLLAMA_MODEL_DIGEST)
    : new FixtureLLM();
}

async function processJob(jobs: Jobs, job: Job, provider: LLMProvider) {
  let heartbeatTimer: ReturnType<typeof setInterval> | undefined;
  try {
    heartbeatTimer = setInterval(() => { void jobs.heartbeat(job).catch(() => undefined); }, Math.max(1000, Math.floor(config.JOB_LEASE_SECONDS * 500)));
    const observation = await new ToolGateway(pool, loadConfig).invoke(job, job.action, job.asset_id);
    const observationId = await jobs.complete(job, observation);
    clearInterval(heartbeatTimer); heartbeatTimer = undefined;
    try {
      const analysis = await analyzeObservation(provider, observation);
      await jobs.recordAnalysis(job, observationId, analysis);
      log('ANALYSIS_ACCEPTED', { program: job.program_id, job: job.id, result: `label:${analysis.analysis.label}` });
    } catch (error) {
      const failed = error as { response?: { text?: string; model?: string; modelDigest?: string; samplingOptions?: Record<string, unknown> }; cause?: unknown };
      const response = failed.response;
      await jobs.recordAnalysisFailure(job, {
        rawText: response?.text ?? null, model: response?.model ?? 'unknown', modelDigest: response?.modelDigest ?? null,
        samplingOptions: response?.samplingOptions ?? {}, promptHash: analysisPromptHash(boundedObservation(observation)), schemaVersion: '1', status: 'parse_failed',
        errorCode: typeof failed.cause === 'string' ? failed.cause : 'analysis_parse_failed',
      });
      log('ANALYSIS_FAILED', { program: job.program_id, job: job.id, result: 'parse_failed' });
    }
  } catch (error) {
    if (error instanceof Error && error.message === 'rate_limited') await jobs.defer(job);
    else await jobs.fail(job);
    log('JOB_FAILED', { program: job.program_id, job: job.id, result: error instanceof Error && /^[a-z_]+$/.test(error.message) ? error.message : 'operation_failed' });
  } finally {
    if (heartbeatTimer) clearInterval(heartbeatTimer);
  }
}

try {
  if (config.GLOBAL_KILL_SWITCH) throw new Error('kill_switch');
  await migrate(pool);
  const provider = new FixtureProvider();
  const programs = await provider.discover();
  const jobs = new Jobs(pool, config.MAX_CONCURRENT_JOBS, config.JOB_LEASE_SECONDS);
  const llm = modelProvider();
  for (const program of programs) await saveProgram(pool, program);
  const once = process.argv.includes('--once');
  while (!stopping) {
    for (const program of programs) {
      await jobs.enqueue(program.id, 'fixture-api', 'inspect_http_target', 'fixture-v1:inspect');
      const job = await jobs.claim();
      if (job) {
        log('JOB_STARTED', { program: program.id, job: job.id });
        await processJob(jobs, job, llm);
      }
      await exportWorkspace(pool, config.PROGRAMS_DIR, program.id);
    }
    if (once) break;
    await sleep(1000);
  }
} catch (error) {
  log('WORKER_FAILED', { result: error instanceof Error && /^[a-z_]+(?::.*)?$/.test(error.message) ? error.message : 'operation_failed' });
  process.exitCode = 1;
} finally { await pool.end(); }
