import { sha256Hex } from '../provenance/index.js';
import { fetchProgram, type FetchLike } from './hackerone.js';
import { compileIntake, intakeApprovalSource, type CompiledIntake, type IntakeApproval } from './compile.js';

// Handle-driven autonomous intake (BOUNTY_EARNINGS_PLAN.md Phase 1). The operator chooses which
// programs to engage by enrolling in them on HackerOne and listing their handles — that human choice
// is the authorization-of-record. Everything after is automated: pull the published scope, record
// provenance from the fetch itself, and compile in-scope assets. Programs that forbid automation are
// refused by compileIntake. This module never discovers programs on its own.

// Auto-generate the intake approval from the fetched program. The approver is the API source, and the
// source hash binds the approval to exactly the scope that was fetched (re-review on any change).
export function autoApproval(raw: unknown, approver = 'hackerone-api', now = Date.now(), ttlDays = 7): IntakeApproval {
  if (!Number.isInteger(ttlDays) || ttlDays < 1 || ttlDays > 90) throw new Error('invalid_ttl');
  const approvedAt = new Date(now - 1000).toISOString();                 // never in the future
  const expiresAt = new Date(now + ttlDays * 86_400_000).toISOString();
  const revision = `auto-${approvedAt.slice(0, 10)}`;
  const fields = { approver, approvedAt, revision, expiresAt };
  const source = intakeApprovalSource(raw, fields);
  return { ...fields, sourceSha256: sha256Hex(source) };
}

export interface AutoIntakeResult { compiled: CompiledIntake[]; skipped: Array<{ handle: string; reason: string }> }

export interface AutoIntakeInput {
  authorization: string;                 // the operator's HackerOne hacker-API Authorization header
  handles: readonly string[];            // programs the operator has enrolled in (required; never discovered)
  fetchLike?: FetchLike;
  approver?: string;
  now?: number;
  ttlDays?: number;
  signal?: AbortSignal;
}

export async function autoIntakeHackerOne(input: AutoIntakeInput): Promise<AutoIntakeResult> {
  if (!input.handles.length) throw new Error('no_handles');
  const fetchLike = input.fetchLike ?? (fetch as unknown as FetchLike);
  const now = input.now ?? Date.now();
  const approver = input.approver ?? 'hackerone-api';
  const ttlDays = input.ttlDays ?? 7;
  const compiled: CompiledIntake[] = [];
  const skipped: Array<{ handle: string; reason: string }> = [];
  for (const handle of [...new Set(input.handles)]) {
    try {
      const raw = await fetchProgram(handle, fetchLike, { authorization: input.authorization, signal: input.signal });
      const result = compileIntake(raw, autoApproval(raw, approver, now, ttlDays), now);
      // Only automation-permitted programs may be engaged, exactly as the setup-UI path requires.
      // Anything manual-only or prohibited is skipped rather than queued — a program's automation
      // rule is the line this project exists to hold, and breaking it can get an account banned.
      if (result.automation !== 'permitted') { skipped.push({ handle, reason: result.refused ?? result.automation }); continue; }
      if (result.programs.length) compiled.push(result);
      else skipped.push({ handle, reason: result.refused ?? 'no_program' });
    } catch (error) {
      skipped.push({ handle, reason: error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : 'intake_failed' });
    }
  }
  return { compiled, skipped };
}
