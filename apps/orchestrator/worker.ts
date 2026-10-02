import { setTimeout as sleep } from 'node:timers/promises';
import { loadConfig } from '../../packages/shared/config.js';
import { log } from '../../packages/shared/log.js';
import { connect, migrate } from '../../packages/research-state/db.js';
import { saveProgram, exportWorkspace } from '../../packages/research-state/workspace.js';
import { Jobs, type Job } from '../../packages/research-state/jobs.js';
import { ToolGateway } from '../../packages/mcp/index.js';
import { FileProgramProvider, FixtureProvider } from '../../packages/bounty-providers/index.js';
import { FixtureLLM, OllamaProvider, type LLMProvider } from '../../packages/llm/index.js';
import { analyzeObservation, analysisPromptHash, boundedObservation } from '../../packages/agent-runtime/index.js';

const config = loadConfig();
const pool = connect(config.DATABASE_URL);
const shutdown = new AbortController();
process.on('SIGINT', () => shutdown.abort());
process.on('SIGTERM', () => shutdown.abort());

async function processJob(jobs: Jobs, gateway: ToolGateway, job: Job, provider: LLMProvider) {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  shutdown.signal.addEventListener('abort', cancel, { once: true });
  if (shutdown.signal.aborted) cancel();
  let heartbeatBusy = false;
  const heartbeat = setInterval(() => {
    if (heartbeatBusy) return;
    heartbeatBusy = true;
    void jobs.heartbeat(job).catch(() => controller.abort()).finally(() => { heartbeatBusy = false; });
  }, Math.max(1000, Math.floor(config.JOB_LEASE_SECONDS * 500)));
  let observation: unknown;
  let observationId: string;
  try {
    observation = await gateway.invoke(job, job.action, job.asset_id, controller.signal);
    controller.signal.throwIfAborted();
    // Completion, evidence and allowed follow-up jobs commit together.
    observationId = await jobs.complete(job, observation);
  } catch (error) {
    if (shutdown.signal.aborted || (error instanceof Error && error.message === 'rate_limited')) await jobs.defer(job);
    else await jobs.fail(job);
    log('JOB_FAILED', { program: job.program_id, job: job.id, result: error instanceof Error && /^[a-z_]+$/.test(error.message) ? error.message : 'operation_failed' });
    return;
  } finally {
    clearInterval(heartbeat);
    shutdown.signal.removeEventListener('abort', cancel);
  }
  // Analysis is separate: its failure must never retry a completed HTTP request.
  try {
    const analysis = await analyzeObservation(provider, observation);
    await jobs.recordAnalysis(job, observationId, analysis);
    log('ANALYSIS_ACCEPTED', { program: job.program_id, job: job.id, result: `label:${analysis.analysis.label}` });
  } catch (error) {
    const failed = error as { response?: { text?: string; model?: string; modelDigest?: string; samplingOptions?: Record<string, unknown> }; input?: string; cause?: unknown };
    const response = failed.response;
    await jobs.recordAnalysisFailure(job, {
      rawText: response?.text ?? null, model: response?.model ?? 'unknown', modelDigest: response?.modelDigest ?? null,
      samplingOptions: response?.samplingOptions ?? {}, promptHash: analysisPromptHash(failed.input ?? boundedObservation(observation)), schemaVersion: '1', status: 'parse_failed',
      errorCode: typeof failed.cause === 'string' ? failed.cause : 'analysis_parse_failed',
    });
    log('ANALYSIS_FAILED', { program: job.program_id, job: job.id, result: 'parse_failed' });
  }
}

try {
  if (config.GLOBAL_KILL_SWITCH) throw new Error('kill_switch');
  if (config.PROGRAM_SOURCE === 'file' && !config.PROGRAMS_FILE) throw new Error('programs_file_required');
  await migrate(pool);
  const provider = config.PROGRAM_SOURCE === 'file' ? new FileProgramProvider(config.PROGRAMS_FILE!) : new FixtureProvider();
  const programs = await provider.discover();
  const jobs = new Jobs(pool, config.MAX_CONCURRENT_JOBS, config.JOB_LEASE_SECONDS);
  const gateway = new ToolGateway(pool, loadConfig);
  const llm = config.LLM_PROVIDER === 'ollama'
    ? new OllamaProvider(config.OLLAMA_URL, config.LLM_MODEL, config.OLLAMA_MODEL_DIGEST)
    : new FixtureLLM();
  for (const program of programs) {
    await saveProgram(pool, program);
    for (const asset of program.assets) await jobs.enqueue(program.id, asset.id, 'inspect_http_target');
  }
  const once = process.argv.includes('--once');
  do {
    // Claim across programs, then process one bounded batch. The database enforces the fleet limit.
    const claimed: Job[] = [];
    for (let i = 0; i < config.MAX_CONCURRENT_JOBS && !shutdown.signal.aborted; i++) {
      const job = await jobs.claim();
      if (!job) break;
      claimed.push(job);
      log('JOB_STARTED', { program: job.program_id, job: job.id });
    }
    const outcomes = await Promise.allSettled(claimed.map(job => processJob(jobs, gateway, job, llm)));
    if (outcomes.some(outcome => outcome.status === 'rejected')) throw new Error('job_persistence_failed');
    // Sweep every pending export, including a different program claimed from shared state.
    const pending = await pool.query('SELECT program_id FROM workspace_outbox ORDER BY program_id');
    for (const row of pending.rows) await exportWorkspace(pool, config.PROGRAMS_DIR, row.program_id);
    if (once || shutdown.signal.aborted) break;
    try { await sleep(1000, undefined, { signal: shutdown.signal }); } catch { break; }
  } while (!shutdown.signal.aborted);
} catch (error) {
  log('WORKER_FAILED', { result: error instanceof Error && /^[a-z_]+(?::.*)?$/.test(error.message) ? error.message : 'operation_failed' });
  process.exitCode = 1;
} finally { await pool.end(); }
