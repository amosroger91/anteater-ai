import { setTimeout as sleep } from 'node:timers/promises';
import { loadOperatorConfig as loadConfig } from '../../packages/setup/operator.js';
import { log } from '../../packages/shared/log.js';
import { connect, migrate } from '../../packages/research-state/db.js';
import { saveProgram, exportWorkspace } from '../../packages/research-state/workspace.js';
import { Jobs, type Job } from '../../packages/research-state/jobs.js';
import { ToolGateway } from '../../packages/mcp/index.js';
import { FileProgramProvider, FixtureProvider } from '../../packages/bounty-providers/index.js';
import { FixtureLLM, OllamaProvider, type LLMProvider } from '../../packages/llm/index.js';
import { analyzeObservation, analysisPromptHash, boundedObservation } from '../../packages/agent-runtime/index.js';
import { loadCampaign } from '../../packages/application-research/intake.js';
import { retryableTransportError } from '../../packages/web-executor/index.js';

const config = loadConfig();
const pool = connect(config.DATABASE_URL);
const shutdown = new AbortController();
process.on('SIGINT', () => shutdown.abort());
process.on('SIGTERM', () => shutdown.abort());

async function persistAnalysis(jobs: Jobs, job: Job, observationId: string, observation: unknown, provider: LLMProvider) {
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

async function recoverAnalyses(jobs: Jobs, provider: LLMProvider) {
  if (loadConfig().GLOBAL_KILL_SWITCH || shutdown.signal.aborted) return;
  const pending = await pool.query<{ observation_id: string; body: unknown; id: string; program_id: string; asset_id: string; action: Job['action']; policy_revision: string; lease_token: string | null; attempts: number }>(`
    SELECT o.id AS observation_id, o.body, j.id, j.program_id, j.asset_id, j.action, j.policy_revision, j.lease_token, j.attempts
    FROM observations o JOIN research_jobs j ON j.id=o.job_id
    WHERE j.status='completed' AND NOT EXISTS (SELECT 1 FROM agent_runs r WHERE r.job_id=j.id)
    ORDER BY o.created_at LIMIT $1`, [config.MAX_CONCURRENT_JOBS]);
  for (const row of pending.rows) {
    const job: Job = { id: row.id, program_id: row.program_id, asset_id: row.asset_id, action: row.action, policy_revision: row.policy_revision, lease_token: row.lease_token ?? '', attempts: row.attempts };
    await persistAnalysis(jobs, job, row.observation_id, row.body, provider);
  }
}

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
    const transport = retryableTransportError(observation);
    if (transport) {
      await jobs.fail(job);
      log('JOB_RETRY', { program: job.program_id, job: job.id, result: transport });
      return;
    }
    // Completion, evidence and allowed follow-up jobs commit together.
    observationId = await jobs.complete(job, observation);
  } catch (error) {
    const message = error instanceof Error ? error.message : '';
    const defer = shutdown.signal.aborted || message === 'rate_limited' || message === 'kill_switch';
    if (defer) await jobs.defer(job);
    else await jobs.fail(job, /^[a-z0-9_]+$/.test(message) ? message : undefined);
    log(defer ? 'JOB_DEFERRED' : 'JOB_FAILED', { program: job.program_id, job: job.id, result: /^[a-z0-9_]+$/.test(message) ? message : 'operation_failed' });
    return;
  } finally {
    clearInterval(heartbeat);
    shutdown.signal.removeEventListener('abort', cancel);
  }
  await persistAnalysis(jobs, job, observationId, observation, provider);
}

try {
  if (config.GLOBAL_KILL_SWITCH) throw new Error('kill_switch');
  if (config.PROGRAM_SOURCE === 'file' && !config.PROGRAMS_FILE) throw new Error('programs_file_required');
  await migrate(pool);
  const provider = config.PROGRAM_SOURCE === 'file' ? new FileProgramProvider(config.PROGRAMS_FILE!) : new FixtureProvider();
  const args = process.argv.slice(2);
  const domainsFile = args.find(arg => arg.startsWith('--domains='))?.slice(10);
  const profileFile = args.find(arg => arg.startsWith('--profile='))?.slice(10);
  const research = args.includes('--research') || domainsFile || profileFile;
  if (research && (!domainsFile || !profileFile)) throw new Error('domains_and_profile_required');
  if (research && !config.ENABLE_APPLICATION_RESEARCH) throw new Error('application_research_not_enabled');
  const campaign = research ? await loadCampaign(domainsFile!, profileFile!) : { programs: await provider.discover(), held: [] as string[] };
  if (campaign.held.length) log('CANDIDATES_HELD', { result: `held:${campaign.held.length}` });
  const jobs = new Jobs(pool, config.MAX_CONCURRENT_JOBS, config.JOB_LEASE_SECONDS, () => loadConfig().GLOBAL_KILL_SWITCH || shutdown.signal.aborted);
  const gateway = new ToolGateway(pool, loadConfig);
  const llm = config.LLM_PROVIDER === 'ollama'
    ? new OllamaProvider(config.OLLAMA_URL, config.LLM_MODEL, config.OLLAMA_MODEL_DIGEST)
    : new FixtureLLM();
  for (const program of campaign.programs) {
    await saveProgram(pool, program);
    for (const asset of program.assets) await jobs.enqueue(program.id, asset.id, research ? 'research_application' : 'inspect_http_target');
  }
  const once = process.argv.includes('--once');
  do {
    // Claim across programs, then process one bounded batch. The database enforces the fleet limit.
    await recoverAnalyses(jobs, llm);
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
