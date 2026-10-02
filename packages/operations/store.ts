import { canProceed, type RevocationState, type ProceedCheck } from './index.js';

// In-process revocation store (PRODUCTION_ROADMAP.md §7). Holds the authoritative kill/revocation
// state a worker consults via canProceed. A production fleet backs this with a shared store and a
// notification channel; the decision semantics are identical and live in ./index.ts.

export class RevocationStore {
  private globalKill = false;
  private revoked = new Set<string>();
  private epochValue = 0;

  kill(): void { this.globalKill = true; }
  clearKill(): void { this.globalKill = false; }
  revoke(programId: string): void { this.revoked.add(programId); }
  // Bumping the epoch supersedes every lease minted before now — cancelling in-flight work.
  bumpEpoch(): number { return ++this.epochValue; }
  get epoch(): number { return this.epochValue; }

  snapshot(): RevocationState {
    return { globalKill: this.globalKill, revokedPrograms: [...this.revoked], epoch: this.epochValue };
  }
  check(programId: string, leaseEpoch: number): ProceedCheck {
    return canProceed(this.snapshot(), programId, leaseEpoch);
  }
}
