import { z } from 'zod';

// Finding lifecycle: state machine + deterministic verification (PRODUCTION_ROADMAP.md §5).
//
// Invariants this module enforces, in pure code:
//  - Scanners and models may only create/advance OBSERVATION -> HYPOTHESIS -> CANDIDATE, or flag
//    HUMAN_REVIEW. They can never reach VERIFIED or SUBMITTED.
//  - Only a deterministic replay can mark a candidate VERIFIED (reproduced against evidence AND the
//    secure counter-test holding), and only across the required repeat count.
//  - Only an authenticated human can reach SUBMITTED.
//  - A model may SUGGEST a chain, but severity is always recomputed deterministically from members
//    and can never be raised by model input.
// Mirrors the findings.status CHECK and findings_verified_check / SUBMITTED constraints in the DB.

export const STATES = ['OBSERVATION', 'HYPOTHESIS', 'CANDIDATE', 'VERIFICATION', 'VERIFIED', 'REJECTED', 'HUMAN_REVIEW', 'SUBMITTED'] as const;
export type State = typeof STATES[number];
export type Actor = 'scanner' | 'model' | 'verifier' | 'human';

export type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
const SEV_RANK: Record<FindingSeverity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const GRAPH: Record<State, State[]> = {
  OBSERVATION: ['HYPOTHESIS', 'REJECTED'],
  HYPOTHESIS: ['CANDIDATE', 'REJECTED'],
  CANDIDATE: ['VERIFICATION', 'HUMAN_REVIEW', 'REJECTED'],
  VERIFICATION: ['VERIFIED', 'HUMAN_REVIEW', 'REJECTED'],
  VERIFIED: ['HUMAN_REVIEW', 'SUBMITTED', 'REJECTED'],
  HUMAN_REVIEW: ['VERIFICATION', 'SUBMITTED', 'REJECTED'],
  REJECTED: [],
  SUBMITTED: [],
};

// Which actors may DRIVE a transition into a given target state. Sensitive states are locked down.
const ACTOR_FOR_TARGET: Record<State, Actor[]> = {
  OBSERVATION: ['scanner', 'model', 'verifier', 'human'],
  HYPOTHESIS: ['scanner', 'model', 'verifier', 'human'],
  CANDIDATE: ['scanner', 'model', 'verifier', 'human'],
  VERIFICATION: ['verifier', 'human'],
  VERIFIED: ['verifier'],            // ONLY deterministic replay
  REJECTED: ['scanner', 'model', 'verifier', 'human'],
  HUMAN_REVIEW: ['scanner', 'model', 'verifier', 'human'],
  SUBMITTED: ['human'],              // ONLY an authenticated person
};

export interface TransitionResult { ok: boolean; reason: string }
export function transition(from: State, to: State, actor: Actor): TransitionResult {
  if (!GRAPH[from].includes(to)) return { ok: false, reason: `illegal_transition:${from}->${to}` };
  if (!ACTOR_FOR_TARGET[to].includes(actor)) return { ok: false, reason: `actor_not_permitted:${actor}->${to}` };
  return { ok: true, reason: 'ok' };
}

// --- Deterministic verification contract -----------------------------------

export const ReproStepSchema = z.object({
  id: z.string().min(1),
  expectStatus: z.number().int().optional(),
  expectBodyIncludes: z.array(z.string()).default([]),
}).strict();
export type ReproStep = z.infer<typeof ReproStepSchema>;

export const ContractSchema = z.object({
  findingType: z.string().min(1),
  preconditions: z.array(z.string()).default([]),
  steps: z.array(ReproStepSchema).min(1),
  // A control that must HOLD for the positive result to be trustworthy (e.g. a properly-protected
  // resource still denies the attacker). If this control fails, the finding is not isolable.
  counterTest: ReproStepSchema,
  repeatCount: z.number().int().min(1).max(5).default(2),
  cleanup: z.enum(['none', 'delete-created-resources']).default('none'),
  maxSideEffects: z.number().int().min(0).default(0),
}).strict();
export type Contract = z.infer<typeof ContractSchema>;

export interface StepResponse { status: number; body: string; unavailable?: boolean }
export type Responder = (stepId: string, iteration: number) => Promise<StepResponse>;

function stepMatches(step: ReproStep, r: StepResponse): boolean {
  if (step.expectStatus !== undefined && r.status !== step.expectStatus) return false;
  return step.expectBodyIncludes.every(s => r.body.includes(s));
}

export interface VerifyOutcome { reproduced: boolean; reason: string; evidence: Array<{ step: string; iteration: number; status: number }> }

// Replay a contract against an injected responder (a fixture in tests, the egress replayer in prod).
// Deterministic: reproduced iff every attack step matches AND the control holds, on EVERY iteration.
export async function replay(rawContract: unknown, responder: Responder): Promise<VerifyOutcome> {
  const contract = ContractSchema.parse(rawContract);
  const evidence: VerifyOutcome['evidence'] = [];
  for (let i = 0; i < contract.repeatCount; i++) {
    for (const step of contract.steps) {
      let r: StepResponse;
      try { r = await responder(step.id, i); }
      catch { return { reproduced: false, reason: `step_unavailable:${step.id}@${i}`, evidence }; }
      if (r.unavailable || r.status === 0 || r.status >= 500) return { reproduced: false, reason: `step_unavailable:${step.id}@${i}`, evidence };
      evidence.push({ step: step.id, iteration: i, status: r.status });
      if (!stepMatches(step, r)) return { reproduced: false, reason: `step_failed:${step.id}@${i}`, evidence };
    }
    let counter: StepResponse;
    try { counter = await responder(contract.counterTest.id, i); }
    catch { return { reproduced: false, reason: `step_unavailable:${contract.counterTest.id}@${i}`, evidence }; }
    if (counter.unavailable || counter.status === 0 || counter.status >= 500) return { reproduced: false, reason: `step_unavailable:${contract.counterTest.id}@${i}`, evidence };
    evidence.push({ step: contract.counterTest.id, iteration: i, status: counter.status });
    // The control must HOLD; if it does not, the positive result is not isolable (e.g. everything leaks).
    if (!stepMatches(contract.counterTest, counter)) return { reproduced: false, reason: `counter_test_failed@${i}`, evidence };
  }
  return { reproduced: true, reason: 'reproduced', evidence };
}

// Verify a candidate and compute its next state. VERIFIED is reachable ONLY through a reproduced replay.
export async function verifyCandidate(from: State, rawContract: unknown, responder: Responder): Promise<{ next: State; outcome: VerifyOutcome; transition: TransitionResult }> {
  const outcome = await replay(rawContract, responder);
  const next: State = outcome.reproduced ? 'VERIFIED' : 'HUMAN_REVIEW';
  const viaVerification = transition(from, 'VERIFICATION', 'verifier');
  const final = viaVerification.ok ? transition('VERIFICATION', next, 'verifier') : viaVerification;
  return { next, outcome, transition: final };
}

// --- Dedup, grouping, chaining ---------------------------------------------

export interface Finding { id: string; type: string; location: string; severity: FindingSeverity; related?: string[] }

export function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();
  for (const f of findings) { const key = `${f.type}|${f.location}`; if (!seen.has(key)) seen.set(key, f); }
  return [...seen.values()];
}

// Chain severity is the max of members — deterministic. A model's suggested ordering is accepted for
// presentation, but severity is recomputed here and can never be raised above the member maximum.
export function chainSeverity(members: Finding[]): FindingSeverity {
  return members.reduce<FindingSeverity>((acc, f) => (SEV_RANK[f.severity] > SEV_RANK[acc] ? f.severity : acc), 'info');
}

export interface Chain { members: string[]; severity: FindingSeverity }
export function buildChain(members: Finding[], suggestedOrder?: string[]): Chain {
  const byId = new Map(members.map(f => [f.id, f]));
  const ordered = suggestedOrder?.every(id => byId.has(id)) && suggestedOrder.length === members.length
    ? suggestedOrder.map(id => byId.get(id)!)   // accept a valid model-suggested ordering
    : members;                                  // otherwise ignore the suggestion
  return { members: ordered.map(f => f.id), severity: chainSeverity(members) };
}
