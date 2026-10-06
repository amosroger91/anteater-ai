import { randomUUID } from 'node:crypto';
import type pg from 'pg';

export interface CleanupIntent { origin: string; ownerId: string; marker: string; cleanupUrl: string }
export interface PendingCleanup extends CleanupIntent { id: string; policyRevision: string }
export interface CleanupJournal {
  readonly policyRevision: string;
  prepare(intent: CleanupIntent): Promise<string>;
  pending(origin: string): Promise<PendingCleanup[]>;
  complete(id: string): Promise<void>;
}

// Only marker metadata is stored. Cookies, passwords, access tokens, and response bodies never
// enter the journal. The creator's live job lease prevents another worker from deleting an object
// while verification is in progress; expired or finished work can be recovered by the next job.
export function createCleanupJournal(pool: pg.Pool, programId: string, policyRevision: string,
  owner: { jobId: string; leaseToken: string | null }): CleanupJournal {
  return {
    policyRevision,
    async prepare(intent) {
      const origin = new URL(intent.origin);
      const cleanup = new URL(intent.cleanupUrl);
      if (origin.origin !== intent.origin || origin.protocol !== 'https:' || cleanup.origin !== origin.origin ||
        !/^[a-z0-9-]+$/.test(intent.ownerId) || !/^anteater-owned-[a-f0-9]{32}$/.test(intent.marker)) throw new Error('invalid_cleanup_intent');
      const id = randomUUID();
      const inserted = await pool.query(`INSERT INTO resource_cleanup
        (id,program_id,policy_revision,origin,owner_id,marker,cleanup_url,job_id,job_lease_token)
        SELECT $1,$2,$3,$4,$5,$6,$7,j.id,j.lease_token FROM research_jobs j
        WHERE j.id=$8 AND j.program_id=$2 AND j.lease_token=$9 AND j.status='running' AND j.lease_until>now()
          AND j.policy_revision=$3`,
      [id,programId,policyRevision,intent.origin,intent.ownerId,intent.marker,intent.cleanupUrl,owner.jobId,owner.leaseToken]);
      if (inserted.rowCount !== 1) throw new Error('cleanup_journal_lost_lease');
      return id;
    },
    async pending(origin) {
      const result = await pool.query(`WITH eligible AS (
        SELECT c.id FROM resource_cleanup c WHERE c.program_id=$1 AND c.origin=$2
          AND NOT EXISTS (SELECT 1 FROM research_jobs j WHERE j.id=c.job_id AND j.lease_token=c.job_lease_token
            AND j.status='running' AND j.lease_until>now())
          AND EXISTS (SELECT 1 FROM research_jobs current_job WHERE current_job.id=$3 AND current_job.program_id=$1
            AND current_job.lease_token=$4 AND current_job.status='running' AND current_job.lease_until>now())
        ORDER BY c.created_at,c.id LIMIT 100 FOR UPDATE OF c SKIP LOCKED
      ) UPDATE resource_cleanup c SET job_id=$3,job_lease_token=$4,updated_at=now()
        FROM eligible WHERE c.id=eligible.id RETURNING c.id,c.origin,c.owner_id,c.marker,c.cleanup_url,c.policy_revision`,
      [programId,origin,owner.jobId,owner.leaseToken]);
      return result.rows.map(row => ({ id: row.id, origin: row.origin, ownerId: row.owner_id,
        marker: row.marker, cleanupUrl: row.cleanup_url, policyRevision: row.policy_revision }));
    },
    async complete(id) {
      const removed = await pool.query(`DELETE FROM resource_cleanup c WHERE c.id=$1 AND c.program_id=$2
        AND c.job_id=$3 AND c.job_lease_token=$4 AND EXISTS (SELECT 1 FROM research_jobs j
          WHERE j.id=$3 AND j.lease_token=$4 AND j.status='running' AND j.lease_until>now())`,
      [id,programId,owner.jobId,owner.leaseToken]);
      if (removed.rowCount !== 1) throw new Error('cleanup_journal_lost_lease');
    },
  };
}
