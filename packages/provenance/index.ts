import { createHash } from 'node:crypto';
import { z } from 'zod';

// Policy provenance (PRODUCTION_ROADMAP.md §0). Records WHO approved a scope, the source it was
// approved from, a hash of that exact source, and when — so imported page text or model output can
// never stand in for an authenticated approval. Pure and deterministic.

export const ApprovalSchema = z.object({
  approver: z.string().min(1).max(200),
  sourceUrl: z.string().url(),
  sourceSha256: z.string().regex(/^[0-9a-f]{64}$/),
  approvedAt: z.iso.datetime(),
  revision: z.string().min(1),
  expiresAt: z.iso.datetime(),
}).strict();
export type Approval = z.infer<typeof ApprovalSchema>;

export const sha256Hex = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');

export interface ProvenanceCheck { ok: boolean; reason: string }

// An approval is valid only if it parses, has not expired, and the reviewed source text still hashes
// to the approved hash. A changed source invalidates the approval — a re-review is required.
export function verifyApproval(rawApproval: unknown, sourceText: string, now = Date.now()): ProvenanceCheck {
  const parsed = ApprovalSchema.safeParse(rawApproval);
  if (!parsed.success) return { ok: false, reason: 'invalid_approval_record' };
  const a = parsed.data;
  if (Date.parse(a.approvedAt) > now) return { ok: false, reason: 'approval_in_future' };
  if (Date.parse(a.expiresAt) <= now) return { ok: false, reason: 'approval_expired' };
  if (sha256Hex(sourceText) !== a.sourceSha256) return { ok: false, reason: 'source_hash_mismatch' };
  return { ok: true, reason: 'approved' };
}
