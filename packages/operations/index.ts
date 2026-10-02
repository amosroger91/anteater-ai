// Production operations: fleet revocation, retention, and dead-letter decisions (PRODUCTION_ROADMAP.md §7).
//
// These are the deterministic DECISION functions a worker/operator consults. The transport that
// propagates a revocation across a fleet, and the store that holds retained records, are infra; the
// rules for "may this proceed", "what must be deleted", and "retry or dead-letter" live here, pure
// and testable, so the policy cannot drift between workers.

export interface RevocationState {
  globalKill: boolean;        // fleet-wide stop
  revokedPrograms: string[];  // individually revoked programs
  epoch: number;              // bumping this cancels every lease minted at a lower epoch
}

export interface ProceedCheck { ok: boolean; reason: string }

// A worker calls this before every action, with the epoch its lease was minted at. A kill, a program
// revocation, or an epoch bump (revocation issued after the lease) all stop in-flight work.
export function canProceed(state: RevocationState, programId: string, leaseEpoch: number): ProceedCheck {
  if (state.globalKill) return { ok: false, reason: 'global_kill' };
  if (state.revokedPrograms.includes(programId)) return { ok: false, reason: 'program_revoked' };
  if (leaseEpoch < state.epoch) return { ok: false, reason: 'lease_superseded_by_revocation' };
  return { ok: true, reason: 'ok' };
}

// --- Retention -------------------------------------------------------------

export interface RetainedRecord { id: string; dataClass: string; createdAt: string }

// Deterministic retention: a record is deleted once older than its class's retention window. An
// unknown class is KEPT (never auto-deleted without an explicit policy) and reported for review.
export function retentionPlan(records: RetainedRecord[], retentionDays: Record<string, number>, now = Date.now()): { remove: string[]; keep: string[]; unclassified: string[] } {
  const remove: string[] = [], keep: string[] = [], unclassified: string[] = [];
  for (const r of records) {
    const days = retentionDays[r.dataClass];
    if (days === undefined) { keep.push(r.id); unclassified.push(r.id); continue; }
    const ageDays = (now - Date.parse(r.createdAt)) / 86_400_000;
    (ageDays > days ? remove : keep).push(r.id);
  }
  return { remove, keep, unclassified };
}

// --- Dead-letter -----------------------------------------------------------

// Errors that will never succeed on retry: a scope/policy denial is deterministic, so retrying wastes
// requests against a target. These go straight to the dead-letter queue.
export const NON_RETRYABLE = new Set(['policy_denied', 'out_of_scope', 'excluded', 'expired_policy', 'kill_switch', 'invalid_or_missing_policy', 'prohibited_action']);

export type FailureDisposition = 'retry' | 'dead_letter';
export function classifyFailure(attempts: number, maxAttempts: number, errorCode: string): { disposition: FailureDisposition; reason: string } {
  if (NON_RETRYABLE.has(errorCode)) return { disposition: 'dead_letter', reason: `non_retryable:${errorCode}` };
  if (attempts >= maxAttempts) return { disposition: 'dead_letter', reason: 'attempts_exhausted' };
  return { disposition: 'retry', reason: 'transient' };
}
