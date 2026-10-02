import { replay, type Responder } from './index.js';

// Retest a previously reproduced finding against the same contract (PRODUCTION_ROADMAP.md §5).
// After a fix, the reproduction must NO LONGER reproduce. A finding is "fixed" only when the
// deterministic replay fails to reproduce it; otherwise it remains open.

export interface RetestResult { fixed: boolean; reason: string }

export async function retest(rawContract: unknown, responder: Responder): Promise<RetestResult> {
  const outcome = await replay(rawContract, responder);
  return outcome.reproduced ? { fixed: false, reason: 'still_reproduces' } : { fixed: true, reason: outcome.reason };
}
