import { replay, type Responder } from './index.js';

// Retest a previously reproduced finding against the same contract (PRODUCTION_ROADMAP.md §5).
// After a fix, the reproduction must NO LONGER reproduce. A finding is "fixed" only when the
// deterministic replay fails to reproduce it; otherwise it remains open.

export interface RetestResult { fixed: boolean; inconclusive: boolean; reason: string }

export async function retest(rawContract: unknown, responder: Responder): Promise<RetestResult> {
  let outcome: Awaited<ReturnType<typeof replay>>;
  try { outcome = await replay(rawContract, responder); }
  catch { return { fixed: false, inconclusive: true, reason: 'step_unavailable' }; }
  if (outcome.reproduced) return { fixed: false, inconclusive: false, reason: 'still_reproduces' };
  // An outage or a failed control is inconclusive. It is not evidence that the finding was fixed.
  if (outcome.reason.startsWith('step_unavailable')) return { fixed: false, inconclusive: true, reason: 'step_unavailable' };
  if (outcome.reason.startsWith('counter_test_failed')) return { fixed: false, inconclusive: true, reason: 'counter_test_failed' };
  return { fixed: true, inconclusive: false, reason: outcome.reason };
}
