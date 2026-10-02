import { z } from 'zod';
import { authorize, type Action } from '../scope-engine/index.js';

// Attack-surface discovery: candidate model + candidate-only admission (PRODUCTION_ROADMAP.md §1).
//
// The safety invariant: discovery only ever produces CANDIDATES. A discovered host is contacted
// for testing only after the current reviewed policy authorizes that exact host — admission reuses
// the deterministic scope engine, so a discovered child, CNAME target or linked third party can
// never inherit testing permission by accident. Network discovery adapters (certificate
// transparency, passive DNS, Subfinder) plug in behind DiscoveryAdapter; the fixture adapter keeps
// CI deterministic and offline, matching the project's fixture-first pattern.

const HOST = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;

export const SOURCES = ['submitted', 'cert-transparency', 'passive-dns', 'subfinder', 'observed-link'] as const;
export type Source = typeof SOURCES[number];

export const RawCandidateSchema = z.object({
  host: z.string().max(253),
  source: z.enum(SOURCES),
  confidence: z.number().min(0).max(1).default(0.5),
}).strict();
export type RawCandidate = z.infer<typeof RawCandidateSchema>;

export type Relation = 'submitted' | 'subdomain' | 'external';
export interface Candidate { host: string; source: Source; confidence: number; relation: Relation; observedAt: string }

export interface DiscoveryAdapter { discover(roots: string[], signal?: AbortSignal): Promise<RawCandidate[]> }

// Normalize + validate a raw host. Returns null for anything malformed or IDN-encoded (rejected,
// never silently "fixed"), so a bad discovery entry cannot become a target.
export function normalizeHost(raw: string): string | null {
  const host = raw.trim().toLowerCase().replace(/\.$/, '');
  if (!host || host.length > 253 || host.includes('xn--') || !HOST.test(host)) return null;
  return host;
}

function relationTo(host: string, roots: Set<string>): Relation {
  if (roots.has(host)) return 'submitted';
  for (const root of roots) if (host.endsWith('.' + root)) return 'subdomain';
  return 'external';
}

// Deduplicate by canonical host, keeping the highest-confidence observation and its source.
export function dedupe(candidates: Candidate[]): Candidate[] {
  const best = new Map<string, Candidate>();
  for (const c of candidates) {
    const prior = best.get(c.host);
    if (!prior || c.confidence > prior.confidence) best.set(c.host, c);
  }
  return [...best.values()].sort((a, b) => a.host.localeCompare(b.host));
}

export function toCandidates(raws: RawCandidate[], roots: string[], now = () => new Date().toISOString()): Candidate[] {
  const rootSet = new Set(roots);
  const out: Candidate[] = [];
  for (const raw of raws) {
    const host = normalizeHost(raw.host);
    if (!host) continue;
    out.push({ host, source: raw.source, confidence: raw.confidence, relation: relationTo(host, rootSet), observedAt: now() });
  }
  return dedupe(out);
}

export interface Admission { candidate: Candidate; admitted: boolean; reason: string }

// Admit a candidate for testing ONLY if the reviewed policy authorizes that exact host+action.
// The kill switch is an execution gate, not a scope decision, so admission is evaluated with it off;
// the tool gateway still enforces the live kill switch before any request.
export function admit(candidate: Candidate, policy: unknown, action: Action, now = Date.now()): Admission {
  const decision = authorize(policy, `https://${candidate.host}`, action, { GLOBAL_KILL_SWITCH: false }, now);
  return { candidate, admitted: decision.allowed, reason: decision.reason };
}

export interface Partition { admitted: Admission[]; held: Admission[] }
export function partition(candidates: Candidate[], policy: unknown, action: Action, now = Date.now()): Partition {
  const all = candidates.map(c => admit(c, policy, action, now));
  return { admitted: all.filter(a => a.admitted), held: all.filter(a => !a.admitted) };
}

// Change detection between runs (roadmap §1: "detect changes between runs").
export interface CandidateDiff { added: string[]; removed: string[] }
export function diffCandidates(previous: Candidate[], current: Candidate[]): CandidateDiff {
  const before = new Set(previous.map(c => c.host));
  const after = new Set(current.map(c => c.host));
  return {
    added: [...after].filter(h => !before.has(h)).sort(),
    removed: [...before].filter(h => !after.has(h)).sort(),
  };
}

// Offline fixture adapter for CI. Returns only seeded candidates; performs no network lookup.
export class FixtureDiscovery implements DiscoveryAdapter {
  constructor(private seed: Record<string, RawCandidate[]> = {}) {}
  async discover(roots: string[]): Promise<RawCandidate[]> {
    const out: RawCandidate[] = [];
    for (const root of roots) {
      out.push({ host: root, source: 'submitted', confidence: 1 });
      for (const extra of this.seed[root] ?? []) out.push(RawCandidateSchema.parse(extra));
    }
    return out;
  }
}

// Run discovery and return admitted vs held in one call. Held candidates are reported, never contacted.
export async function discoverAndPartition(adapter: DiscoveryAdapter, roots: string[], policy: unknown, action: Action, signal?: AbortSignal): Promise<Partition & { candidates: Candidate[] }> {
  const normalizedRoots = roots.map(normalizeHost).filter((h): h is string => h !== null);
  const raws = (await adapter.discover(normalizedRoots, signal)).map(r => RawCandidateSchema.parse(r));
  const candidates = toCandidates(raws, normalizedRoots);
  return { candidates, ...partition(candidates, policy, action) };
}
