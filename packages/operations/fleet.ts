import { canProceed, NON_RETRYABLE, type RevocationState } from './index.js';

export interface FleetReport {
  ran: string[];
  skipped: Array<{ programId: string; reason: string }>;
  deadLettered: Array<{ programId: string; code: string }>;
}

// One pass across programs. The caller supplies the work. This function does not contact a host.
export async function runFleetIteration(input: {
  programIds: string[];
  state: RevocationState;
  leaseEpoch: number;
  globalTake: () => boolean;
  programTake: (programId: string) => boolean;
  run: (programId: string) => Promise<void>;
  deadLetter?: (programId: string, code: string) => Promise<void>;
}): Promise<FleetReport> {
  const report: FleetReport = { ran: [], skipped: [], deadLettered: [] };
  for (const programId of input.programIds) {
    const gate = canProceed(input.state, programId, input.leaseEpoch);
    if (!gate.ok) { report.skipped.push({ programId, reason: gate.reason }); continue; }
    if (!input.globalTake()) { report.skipped.push({ programId, reason: 'global_budget' }); continue; }
    if (!input.programTake(programId)) { report.skipped.push({ programId, reason: 'program_budget' }); continue; }
    try {
      await input.run(programId);
      report.ran.push(programId);
    } catch (error) {
      const code = error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : 'unknown';
      if (NON_RETRYABLE.has(code)) {
        await input.deadLetter?.(programId, code);
        report.deadLettered.push({ programId, code });
      } else report.skipped.push({ programId, reason: 'retryable' });
    }
  }
  return report;
}
