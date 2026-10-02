import { createHash } from 'node:crypto';

// Tamper-evident audit log (PRODUCTION_ROADMAP.md §7). Each record hashes the previous record's hash
// plus its own canonical content, forming a chain: altering or removing any record breaks every hash
// after it. Pure; the DB stores prev_hash/hash columns (005_ops.sql).

const GENESIS = '0'.repeat(64);

// Canonical JSON with sorted keys so the hash is stable regardless of property order.
function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
}

export interface AuditRecord { event: unknown; prevHash: string; hash: string }

export function hashRecord(prevHash: string, event: unknown): string {
  return createHash('sha256').update(prevHash).update('\n').update(canonical(event)).digest('hex');
}

export function appendEvent(chain: AuditRecord[], event: unknown): AuditRecord {
  const prevHash = chain.length ? chain[chain.length - 1]!.hash : GENESIS;
  return { event, prevHash, hash: hashRecord(prevHash, event) };
}

export function verifyChain(chain: AuditRecord[]): { ok: boolean; brokenAt: number } {
  let prev = GENESIS;
  for (let i = 0; i < chain.length; i++) {
    const r = chain[i]!;
    if (r.prevHash !== prev || r.hash !== hashRecord(r.prevHash, r.event)) return { ok: false, brokenAt: i };
    prev = r.hash;
  }
  return { ok: true, brokenAt: -1 };
}
