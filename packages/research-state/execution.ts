import { retryableTransportError } from '../web-executor/index.js';
import type { ToolGateway } from '../mcp/index.js';
import type { Job, Jobs } from './jobs.js';

export type JobExecution = { completed: true; observation: Record<string, unknown>; observationId: string } | { completed: false; retry: string };

/** Both campaign and fleet workers use the same lease renewal, cancellation and persistence path. */
export async function executeLeasedJob(input: {
  jobs: Jobs; gateway: ToolGateway; job: Job; leaseSeconds: number; signal?: AbortSignal;
}): Promise<JobExecution> {
  const { jobs, gateway, job } = input;
  const controller = new AbortController();
  const cancel = () => controller.abort(input.signal?.reason ?? new Error('cancelled'));
  input.signal?.addEventListener('abort', cancel, { once: true });
  if (input.signal?.aborted) cancel();
  let heartbeat: ReturnType<typeof setInterval> | undefined;
  let pending: Promise<void> | undefined;
  const stopHeartbeat = async () => { clearInterval(heartbeat); await pending; };
  try {
    controller.signal.throwIfAborted();
    await jobs.heartbeat(job);
    heartbeat = setInterval(() => {
      if (pending) return;
      pending = jobs.heartbeat(job).catch(error => { controller.abort(error); }).finally(() => { pending = undefined; });
    }, Math.max(100, Math.min(1000, Math.floor(input.leaseSeconds * 500))));
    const observation = await gateway.invoke(job, job.action, job.asset_id, controller.signal);
    await stopHeartbeat();
    controller.signal.throwIfAborted();
    const transport = retryableTransportError(observation);
    if (transport) { await jobs.fail(job); return { completed: false, retry: transport }; }
    const observationId = await jobs.complete(job, observation);
    return { completed: true, observation, observationId };
  } catch (caught) {
    await stopHeartbeat();
    const error = controller.signal.aborted ? controller.signal.reason : caught;
    const code = error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : undefined;
    if (input.signal?.aborted || code === 'rate_limited' || code === 'kill_switch' || code === 'lease_superseded_by_revocation') await jobs.defer(job);
    else await jobs.fail(job, code);
    throw error;
  } finally {
    await stopHeartbeat();
    input.signal?.removeEventListener('abort', cancel);
  }
}
