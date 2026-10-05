import { ProgramBudget } from '../budget/index.js';
import { normalizeHost, RawCandidateSchema, type DiscoveryAdapter, type RawCandidate } from './index.js';

// Live discovery (BOUNTY_EARNINGS_PLAN.md Phase 2.1). The three adapters stay injectable.
// One program-budget token gates each root. When the budget denies that root, none of the
// adapters see it. Returned names are still candidates; admission stays partition().

export interface LiveDiscoverySources {
  certTransparency: DiscoveryAdapter;
  passiveDns: DiscoveryAdapter;
  subfinder: DiscoveryAdapter;
}

const SOURCE_ORDER = ['certTransparency', 'passiveDns', 'subfinder'] as const;

export async function discoverWithinBudget(sources: LiveDiscoverySources, roots: string[], budget: ProgramBudget, signal?: AbortSignal): Promise<RawCandidate[]> {
  const raw: RawCandidate[] = [];
  for (const root of roots) {
    const host = normalizeHost(root);
    if (!host) continue;
    const gate = budget.allow(host);
    if (!gate.ok) continue;
    try {
      for (const name of SOURCE_ORDER) {
        const found = await sources[name].discover([host], signal);
        for (const item of found) raw.push(RawCandidateSchema.parse(item));
      }
    } finally {
      budget.done();
    }
  }
  return raw;
}
