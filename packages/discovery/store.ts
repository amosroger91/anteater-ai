import { z } from 'zod';
import type pg from 'pg';
import { transaction } from '../research-state/db.js';
import { assetIdForHost } from '../shared/asset-id.js';
import { dedupe, diffCandidates, normalizeHost, SOURCES, type Candidate } from './index.js';

// Persist observed hosts and diff the last two discovery snapshots
// (BOUNTY_EARNINGS_PLAN.md Phase 2.2). A new row stays inactive. Activation
// is a later admission decision, not a side effect of seeing the name.

const Snapshot = z.object({
  host: z.string(),
  source: z.enum(SOURCES),
  confidence: z.number().min(0).max(1),
  relation: z.enum(['submitted', 'subdomain', 'external']),
  observedAt: z.iso.datetime(),
}).strict();

function assertProgramId(programId: string) {
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(programId)) throw new Error('invalid_program_id');
}

function readRun(value: unknown): Candidate[] {
  if (!Array.isArray(value)) throw new Error('invalid_discovery_run');
  return value.map(item => {
    const parsed = Snapshot.safeParse(item);
    if (!parsed.success || normalizeHost(parsed.data.host) !== parsed.data.host) throw new Error('invalid_discovery_run');
    return parsed.data;
  });
}

export async function recordObservedHosts(pool: pg.Pool, programId: string, candidates: Candidate[]): Promise<number> {
  assertProgramId(programId);
  const observed = dedupe(candidates.map(item => {
    const parsed = Snapshot.safeParse(item);
    if (!parsed.success || normalizeHost(parsed.data.host) !== parsed.data.host) throw new Error('invalid_candidate');
    return parsed.data;
  }));
  return transaction(pool, async client => {
    const scope = await client.query(`SELECT policy->>'revision' AS revision FROM scope_rules WHERE program_id=$1`, [programId]);
    const revision = scope.rows[0]?.revision;
    if (typeof revision !== 'string' || revision.length === 0) throw new Error('missing_scope');
    for (const candidate of observed) {
      const id = assetIdForHost(candidate.host, programId);
      await client.query(`INSERT INTO assets(id,program_id,url,active,policy_revision,first_seen,last_seen,source,confidence)
        VALUES ($1,$2,$3,false,$4,$5,$5,$6,$7)
        ON CONFLICT (program_id, url) DO UPDATE SET
          source=EXCLUDED.source,
          confidence=EXCLUDED.confidence,
          first_seen=CASE
            WHEN assets.first_seen IS NULL THEN EXCLUDED.first_seen
            WHEN EXCLUDED.first_seen < assets.first_seen THEN EXCLUDED.first_seen
            ELSE assets.first_seen
          END,
          last_seen=CASE
            WHEN assets.last_seen IS NULL OR EXCLUDED.last_seen > assets.last_seen THEN EXCLUDED.last_seen
            ELSE assets.last_seen
          END`,
        [id, programId, `https://${candidate.host}`, revision, candidate.observedAt, candidate.source, candidate.confidence]);
    }
    const run = await client.query(`INSERT INTO discovery_runs(program_id,hosts,finished_at) VALUES ($1,$2::jsonb,clock_timestamp()) RETURNING seq`, [programId, JSON.stringify(observed)]);
    const seq = run.rows[0]?.seq;
    if (typeof seq !== 'string' && typeof seq !== 'number') throw new Error('discovery_run_not_recorded');
    return Number(seq);
  });
}

export async function newlyExposed(pool: pg.Pool, programId: string): Promise<string[]> {
  assertProgramId(programId);
  const runs = await pool.query(`SELECT hosts FROM discovery_runs WHERE program_id=$1 ORDER BY seq DESC LIMIT 2`, [programId]);
  const current = runs.rows[0] ? readRun(runs.rows[0].hosts) : [];
  const previous = runs.rows[1] ? readRun(runs.rows[1].hosts) : [];
  return diffCandidates(previous, current).added;
}
