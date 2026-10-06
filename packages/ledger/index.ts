import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { z } from 'zod';
import { severityTier } from '../findings/index.js';

// Submission ledger. One row per status change. Net for the operator command is paid minus infra.
// Labor stays in packages/metrics netEconomics and is not folded into this figure.

export const SUBMISSION_STATES = ['submitted', 'triaged', 'accepted', 'duplicate', 'informational', 'paid'] as const;
export type SubmissionState = typeof SUBMISSION_STATES[number];

const UUID = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
const PROGRAM_ID = z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
const MONEY = z.number().finite().nonnegative();

type Queryable = Pick<pg.Pool | pg.PoolClient, 'query'>;

const SubmissionWrite = z.object({
  id: UUID,
  programId: PROGRAM_ID,
  findingId: UUID.nullable(),
  status: z.enum(SUBMISSION_STATES),
  amount: MONEY.nullable(),
  currency: z.string().regex(/^[A-Z]{3}$/).nullable(),
}).strict().superRefine((row, ctx) => {
  if (row.status === 'paid' && (row.amount === null || row.currency === null)) ctx.addIssue({ code: 'custom', message: 'paid_requires_amount' });
  if ((row.amount === null) !== (row.currency === null)) ctx.addIssue({ code: 'custom', message: 'amount_currency_pair' });
});

const LedgerRequest = z.object({
  findingId: UUID,
  status: z.enum(SUBMISSION_STATES),
  amount: MONEY.nullable(),
  currency: z.string().regex(/^[A-Z]{3}$/).nullable(),
}).strict();

export const KnownIssueSchema = z.object({
  programId: PROGRAM_ID,
  findingType: z.string().trim().min(1).max(120),
  location: z.string().trim().min(1).max(2000),
  note: z.string().trim().min(1).max(500).optional(),
}).strict();

// Severity names win. A missing name falls back to the dollar estimate. Info stays tier 0.
export function payoutTier(severity: string | undefined, estimatedPayout?: number): number {
  const named = severityTier(severity);
  if (named !== null) return named;
  if (estimatedPayout === undefined || !Number.isFinite(estimatedPayout) || estimatedPayout <= 0) return 0;
  if (estimatedPayout >= 5000) return 4;
  if (estimatedPayout >= 1000) return 3;
  if (estimatedPayout >= 250) return 2;
  return 1;
}

export function rankScore(tier: number, confidence: number): number {
  const safe = Number.isFinite(confidence) && confidence >= 0 && confidence <= 1 ? confidence : 0.5;
  return Math.round(tier * safe * 10000) / 10000;
}

export function netPaidMinusInfra(paid: number, infra: number): { paid: number; infra: number; net: number } {
  if (!Number.isFinite(paid) || !Number.isFinite(infra) || paid < 0 || infra < 0) throw new Error('ledger_refused');
  return { paid, infra, net: paid - infra };
}

export function formatQueueEntry(row: {
  id: string;
  programId: string;
  status: string;
  findingType: string;
  location: string;
  tier: number;
  confidence: number;
  rank: number;
  evidenceSha: string | null;
  evidenceSteps: number;
}): string[] {
  const sha = row.evidenceSha ? row.evidenceSha.slice(0, 12) : 'none';
  return [
    `${row.id} program=${row.programId} status=${row.status} type=${row.findingType} location=${row.location} tier=${row.tier} confidence=${row.confidence} rank=${row.rank} dedupe=clear evidence=${sha} steps=${row.evidenceSteps}`,
    `npm run finding:submit -- --id=${row.id} --reviewer=`,
  ];
}

export function formatSuppressedEntry(row: { id: string; programId: string; findingType: string; location: string; dedupeStatus: string }): string {
  return `suppressed ${row.id} program=${row.programId} type=${row.findingType} location=${row.location} dedupe=${row.dedupeStatus}`;
}

export async function insertSubmission(db: Queryable, input: unknown): Promise<void> {
  const parsed = SubmissionWrite.safeParse(input);
  if (!parsed.success) throw new Error('ledger_refused');
  const row = parsed.data;
  await db.query(
    `INSERT INTO submissions(id, program_id, finding_id, status, amount, currency) VALUES($1,$2,$3,$4,$5,$6)`,
    [row.id, row.programId, row.findingId, row.status, row.amount, row.currency],
  );
}

export async function recordLedgerEvent(pool: pg.Pool, input: unknown): Promise<void> {
  const parsed = LedgerRequest.safeParse(input);
  if (!parsed.success) throw new Error('ledger_refused');
  const request = parsed.data;
  const found = await pool.query('SELECT program_id FROM findings WHERE id=$1', [request.findingId]);
  const programId = found.rows[0]?.program_id;
  if (typeof programId !== 'string') throw new Error('finding_missing');
  await insertSubmission(pool, {
    id: randomUUID(),
    programId,
    findingId: request.findingId,
    status: request.status,
    amount: request.amount,
    currency: request.currency,
  });
}

export async function recordKnownIssue(pool: pg.Pool, input: unknown): Promise<void> {
  const parsed = KnownIssueSchema.safeParse(input);
  if (!parsed.success) throw new Error('known_issue_refused');
  const row = parsed.data;
  await pool.query(
    `INSERT INTO known_issues(id, program_id, finding_type, location, note) VALUES($1,$2,$3,$4,$5)
     ON CONFLICT (program_id, finding_type, location) DO NOTHING`,
    [randomUUID(), row.programId, row.findingType, row.location, row.note ?? null],
  );
}
