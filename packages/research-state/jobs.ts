import type pg from 'pg';
import { createHash, randomUUID } from 'node:crypto';
import type { AnalysisFailure, AnalysisRun } from '../agent-runtime/index.js';
import { ContractSchema, transition, verifyCandidate, type Responder, type State } from '../findings/index.js';
import { retest, type RetestResult } from '../findings/retest.js';
import { encrypt } from '../evidence/index.js';
import { transaction } from './db.js';
import { authorize, PolicySchema, targetForAction, type Action } from '../scope-engine/index.js';
import { followUpActions, jobKey } from '../web-executor/planning.js';
import { hashRecord } from '../audit/index.js';
import { insertSubmission } from '../ledger/index.js';
import { NON_RETRYABLE } from '../operations/index.js';
import { assertExecutionAllowed, readExecutionControl } from './control.js';

const GENESIS = '0'.repeat(64);
// Exact-content-signature exposure codes that are submittable on sight (readable source/secrets/admin
// surface). A match is routed to HUMAN_REVIEW rather than left at OBSERVATION. Positional/weaker signals
// (e.g. open_redirect_to_takeover) are deliberately excluded and stay OBSERVATION.
const SUBMITTABLE_EXPOSURE = new Set(['exposed_vcs', 'exposed_admin', 'secrets_in_js']);

export interface Job {
  id: string; program_id: string; asset_id: string; action: Action; policy_revision: string;
  lease_token: string; lease_epoch: string; attempts: number;
}

export class Jobs {
  constructor(private pool: pg.Pool, private concurrency = 1, private leaseSeconds = 30, private killed: () => boolean = () => false) {}

  async enqueue(program: string, asset: string, action: Action, key?: string) {
    if (this.killed() || await this.databaseKilled(this.pool, program)) return;
    return transaction(this.pool, c => this.enqueueOn(c, program, asset, action, key));
  }

  private async databaseKilled(c: pg.Pool | pg.PoolClient = this.pool, program?: string): Promise<boolean> {
    const control = await readExecutionControl(c, program);
    return control.globalKill || control.revoked;
  }

  private async enqueueOn(c: pg.PoolClient, program: string, asset: string, action: Action, key?: string, expectedRevision?: string) {
    if (this.killed() || await this.databaseKilled(c, program)) return;
    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`program:${program}`]);
    const source = await c.query(`SELECT a.url,s.policy FROM assets a JOIN scope_rules s ON s.program_id=a.program_id
      WHERE a.id=$1 AND a.program_id=$2 AND a.active=true FOR SHARE OF a,s`, [asset, program]);
    const row = source.rows[0];
    if (!row) return;
    const parsed = PolicySchema.safeParse(row.policy);
    if (!parsed.success || parsed.data.programId !== program || (expectedRevision && parsed.data.revision !== expectedRevision)) return;
    const target = targetForAction(row.url, action);
    if (this.killed() || !authorize(parsed.data, target, action, { GLOBAL_KILL_SWITCH: false }).allowed) return;
    const dedupeKey = key ?? jobKey(program, asset, parsed.data.revision, target, action);
    const id = randomUUID();
    const inserted = await c.query(`
      INSERT INTO research_jobs(id,program_id,asset_id,action,dedupe_key,policy_revision)
      SELECT $1,$2,$3,$4,$5,s.policy->>'revision'
      FROM assets a JOIN scope_rules s ON s.program_id=a.program_id
      WHERE a.id=$3 AND a.program_id=$2 AND a.active=true
        AND s.policy->'allowedActions' ? $4
      ON CONFLICT(dedupe_key) DO NOTHING`, [id, program, asset, action, dedupeKey]);
    if (inserted.rowCount) await writeAudit(c, program, 'JOB_QUEUED', { jobId: id, assetId: asset, metadata: { action, dedupeKey } });
  }

  async claim(programId?: string): Promise<Job | undefined> {
    if (this.killed() || await this.databaseKilled(this.pool, programId)) return undefined;
    return transaction(this.pool, async c => {
      if (this.killed() || await this.databaseKilled(c, programId)) return undefined;
      await c.query('SELECT pg_advisory_xact_lock(784291)');
      await c.query(`UPDATE research_jobs SET status='failed',lease_token=NULL,lease_until=NULL,lease_heartbeat_at=NULL
        WHERE status='running' AND lease_until <= now() AND attempts >= max_attempts`);
      const count = await c.query(`SELECT count(*)::int AS n FROM research_jobs WHERE status='running' AND lease_until > now()`);
      if (count.rows[0].n >= this.concurrency) return undefined;
      const result = await c.query(`UPDATE research_jobs j SET status='running',attempts=j.attempts+1,
        lease_token=$1,lease_until=now()+$2*interval '1 second',lease_heartbeat_at=now(),
        lease_epoch=(SELECT epoch FROM runtime_control WHERE id=1 AND global_kill=false)
        WHERE j.id=(SELECT candidate.id FROM research_jobs candidate
          JOIN assets a ON a.id=candidate.asset_id AND a.program_id=candidate.program_id AND a.active=true
          JOIN scope_rules s ON s.program_id=candidate.program_id
          WHERE candidate.attempts<candidate.max_attempts AND ($3::text IS NULL OR candidate.program_id=$3)
            AND EXISTS(SELECT 1 FROM runtime_control WHERE id=1 AND global_kill=false)
            AND candidate.policy_revision=s.policy->>'revision'
            AND NOT EXISTS (SELECT 1 FROM revoked_programs revoked WHERE revoked.program_id=candidate.program_id)
            AND ((candidate.status='queued' AND candidate.available_at<=now()) OR (candidate.status='running' AND candidate.lease_until<=now()))
          ORDER BY candidate.created_at FOR UPDATE OF candidate SKIP LOCKED LIMIT 1)
        RETURNING j.*`, [randomUUID(), this.leaseSeconds, programId ?? null]);
      return result.rows[0] as Job | undefined;
    });
  }

  async heartbeat(job: Job, seconds = this.leaseSeconds) {
    await assertExecutionAllowed(this.pool, job.program_id, job.lease_epoch, this.killed());
    const changed = await this.pool.query(`UPDATE research_jobs SET lease_until=now()+$3*interval '1 second',lease_heartbeat_at=now()
      WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>now()
        AND lease_epoch=$4 AND EXISTS(SELECT 1 FROM runtime_control WHERE id=1 AND global_kill=false AND epoch=$4)
        AND NOT EXISTS(SELECT 1 FROM revoked_programs WHERE program_id=$5)`, [job.id, job.lease_token, seconds, job.lease_epoch, job.program_id]);
    if (!changed.rowCount) throw new Error('lost_lease');
  }

  async complete(job: Job, observation: unknown): Promise<string> {
    const observationId = randomUUID();
    await transaction(this.pool, async c => {
      await assertExecutionAllowed(c, job.program_id, job.lease_epoch, this.killed());
      await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`program:${job.program_id}`]);
      const current = await c.query(`SELECT a.url,s.policy FROM assets a JOIN scope_rules s ON s.program_id=a.program_id
        WHERE a.id=$1 AND a.program_id=$2 AND a.active=true AND a.policy_revision=$3 FOR SHARE OF a,s`, [job.asset_id, job.program_id, job.policy_revision]);
      const row = current.rows[0];
      if (!row || row.policy.revision !== job.policy_revision || !authorize(row.policy, targetForAction(row.url, job.action), job.action, { GLOBAL_KILL_SWITCH: false }).allowed) throw new Error('policy_changed');
      const changed = await c.query(`UPDATE research_jobs SET status='completed',result=$3,lease_token=NULL,lease_until=NULL,lease_heartbeat_at=NULL
        WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>now()
          AND lease_epoch=$4 AND EXISTS(SELECT 1 FROM runtime_control WHERE id=1 AND global_kill=false AND epoch=$4)
          AND NOT EXISTS(SELECT 1 FROM revoked_programs WHERE program_id=$5)
        RETURNING id`, [job.id, job.lease_token, JSON.stringify(observation), job.lease_epoch, job.program_id]);
      if (!changed.rowCount) throw new Error('lost_lease');
      await c.query('INSERT INTO observations(id,program_id,job_id,body) VALUES($1,$2,$3,$4)', [observationId, job.program_id, job.id, JSON.stringify(observation)]);
      await c.query('INSERT INTO tool_runs(id,job_id,tool,result) VALUES($1,$2,$3,$4)', [randomUUID(), job.id, job.action, JSON.stringify(observation)]);
      const value = observation && typeof observation === 'object' ? observation as Record<string, unknown> : {};
      if (typeof value.bodySha256 === 'string') {
        await c.query('INSERT INTO evidence(id,finding_id,sha256,body) VALUES($1,NULL,$2,$3)', [randomUUID(), value.bodySha256, JSON.stringify({ jobId: job.id, observationId, target: value.target ?? null, hashScope: value.hashScope ?? 'captured_bytes', bytes: value.bodyBytes ?? null, truncated: value.truncated ?? false })]);
      }
      const signals = Array.isArray(value.signals) ? value.signals.filter(signal => signal && typeof signal === 'object') : [];
      for (const signal of signals) {
        // Exact-content-signature exposures (readable source/secrets/actuator) are high-confidence,
        // read-only, and directly submittable, so they go straight to HUMAN_REVIEW for the operator to
        // report. Weaker/positional signals stay OBSERVATION. Neither can reach VERIFIED/SUBMITTED here.
        const code = (signal as Record<string, unknown>).code;
        const submittable = typeof code === 'string' && SUBMITTABLE_EXPOSURE.has(code);
        if (submittable) await c.query(`INSERT INTO findings(id,program_id,status,body,verified_by) VALUES($1,$2,'HUMAN_REVIEW',$3,'exposure-signature-v1')`, [randomUUID(), job.program_id, JSON.stringify({ jobId: job.id, observationId, signal })]);
        else await c.query(`INSERT INTO findings(id,program_id,status,body) VALUES($1,$2,'OBSERVATION',$3)`, [randomUUID(), job.program_id, JSON.stringify({ jobId: job.id, observationId, signal })]);
      }
      if (value.executor === 'application-browser' && Array.isArray(value.findings)) for (const item of value.findings) {
        const finding = item as { verifier?: string; code?: string; evidence?: unknown[] };
        if (finding.verifier !== 'owner-boundary-v1' || finding.code !== 'cross_account_resource_read' || !Array.isArray(finding.evidence)) continue;
        const findingId = randomUUID();
        await c.query(`INSERT INTO findings(id,program_id,status,body,verified_by) VALUES($1,$2,'HUMAN_REVIEW',$3,'owner-boundary-v1')`, [findingId, job.program_id, JSON.stringify({ observationId, jobId: job.id, ...finding })]);
        for (const rawEvidence of finding.evidence) {
          const evidence = rawEvidence as { sha256?: string };
          if (typeof evidence.sha256 === 'string' && /^[a-f0-9]{64}$/.test(evidence.sha256)) await c.query('INSERT INTO evidence(id,finding_id,sha256,body) VALUES($1,$2,$3,$4)', [randomUUID(), findingId, evidence.sha256, JSON.stringify(rawEvidence)]);
        }
      }
      await writeAudit(c, job.program_id, 'OBSERVATION_RECORDED', { jobId: job.id, assetId: job.asset_id, metadata: { action: job.action, observationId } });
      for (const action of followUpActions(job.action, observation)) await this.enqueueOn(c, job.program_id, job.asset_id, action, undefined, job.policy_revision);
      await c.query(`INSERT INTO workspace_outbox(program_id) VALUES($1) ON CONFLICT(program_id) DO UPDATE SET revision=workspace_outbox.revision+1`, [job.program_id]);
    });
    return observationId;
  }

  async recordAnalysis(job: Job, observationId: string, run: AnalysisRun) {
    await transaction(this.pool, async c => {
      const runId = randomUUID();
      await c.query(`INSERT INTO agent_runs(id,job_id,role,model,result,raw_text,status,sampling_options,model_digest,prompt_hash,schema_version)
        VALUES($1,$2,'analysis',$3,$4,$5,'accepted',$6,$7,$8,$9)`, [
        runId, job.id, run.model, JSON.stringify(run.analysis), run.rawText, JSON.stringify(run.samplingOptions), run.modelDigest, run.promptHash, run.schemaVersion,
      ]);
      await c.query(`INSERT INTO hypotheses(id,program_id,body,agent_run_id,observation_id,dedupe_key)
        VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, [
        randomUUID(), job.program_id, JSON.stringify(run.analysis), runId, observationId, `${job.id}:analysis:${run.schemaVersion}`,
      ]);
      await c.query(`INSERT INTO workspace_outbox(program_id) VALUES($1) ON CONFLICT(program_id) DO UPDATE SET revision=workspace_outbox.revision+1`, [job.program_id]);
      await writeAudit(c, job.program_id, 'ANALYSIS_ACCEPTED', { jobId: job.id, metadata: { observationId, label: run.analysis.label } });
    });
  }

  async recordAnalysisFailure(job: Job, failure: AnalysisFailure) {
    await this.pool.query(`INSERT INTO agent_runs(id,job_id,role,model,result,raw_text,status,sampling_options,model_digest,prompt_hash,schema_version)
      VALUES($1,$2,'analysis',$3,$4,$5,'parse_failed',$6,$7,$8,$9)`, [
      randomUUID(), job.id, failure.model, JSON.stringify({ error: failure.errorCode }), failure.rawText,
      JSON.stringify(failure.samplingOptions), failure.modelDigest, failure.promptHash, failure.schemaVersion,
    ]);
  }

  async defer(job: Job, seconds = 5) {
    await this.pool.query(`UPDATE research_jobs SET status='queued',attempts=GREATEST(attempts-1,0),available_at=now()+$3*interval '1 second',lease_token=NULL,lease_until=NULL,lease_heartbeat_at=NULL
      WHERE id=$1 AND lease_token=$2 AND status='running'`, [job.id, job.lease_token, seconds]);
  }

  async fail(job: Job, code?: string) {
    if (code && NON_RETRYABLE.has(code)) {
      await transaction(this.pool, async c => {
        const changed = await c.query(`UPDATE research_jobs SET status='failed',lease_token=NULL,lease_until=NULL,lease_heartbeat_at=NULL
          WHERE id=$1 AND lease_token=$2 AND status='running'`, [job.id, job.lease_token]);
        if (changed.rowCount) await c.query('INSERT INTO dead_letter(id,job_id,reason,error_code) VALUES($1,$2,$3,$4)', [randomUUID(), job.id, `non_retryable:${code}`, code]);
      });
      return;
    }
    await this.pool.query(`UPDATE research_jobs SET status=CASE WHEN attempts>=max_attempts THEN 'failed' ELSE 'queued' END,
      available_at=now()+attempts*interval '5 seconds',lease_token=NULL,lease_until=NULL,lease_heartbeat_at=NULL
      WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>now()`, [job.id, job.lease_token]);
  }
}

async function writeAudit(c: pg.PoolClient, programId: string, event: string, fields: { jobId?: string; assetId?: string; metadata: Record<string, unknown> }) {
  await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`audit:${programId}`]);
  const previous = await c.query('SELECT hash FROM audit_events WHERE program_id=$1 AND hash IS NOT NULL ORDER BY created_at DESC, id DESC LIMIT 1', [programId]);
  const prevHash = typeof previous.rows[0]?.hash === 'string' ? previous.rows[0].hash : GENESIS;
  const body = { event, ...fields.metadata };
  const hash = hashRecord(prevHash, body);
  await c.query(`INSERT INTO audit_events(id,event,program_id,job_id,asset_id,metadata,prev_hash,hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, [
    randomUUID(), event, programId, fields.jobId ?? null, fields.assetId ?? null, JSON.stringify(fields.metadata), prevHash, hash,
  ]);
}

// VERIFIED is written only after deterministic replay, and only with the verifier actor.
// The caller supplies a responder; it does not supply the next state.
export async function recordReplay(pool: pg.Pool, programId: string, from: State, rawContract: unknown, responder: Responder, body: Record<string, unknown>, options?: { evidenceKey?: string }) {
  const contract = ContractSchema.parse(rawContract);
  const result = await verifyCandidate(from, contract, responder);
  if (!result.transition.ok) throw new Error(result.transition.reason);
  const id = randomUUID();
  const replay = { reproduced: result.outcome.reproduced, reason: result.outcome.reason, evidence: result.outcome.evidence };
  const evidenceBody = { findingId: id, replay };
  const sha = createHash('sha256').update(JSON.stringify(evidenceBody)).digest('hex');
  const sealed = options?.evidenceKey ? encrypt(JSON.stringify(evidenceBody), options.evidenceKey) : undefined;
  const stored = { ...body, contract, replay };
  await transaction(pool, async c => {
    if (result.next === 'VERIFIED') {
      if (!result.outcome.reproduced) throw new Error('verifier_invariant');
      await c.query(`SELECT set_config('anteater.actor', 'verifier', true)`);
      await c.query(`INSERT INTO findings(id,program_id,status,body,verified_by) VALUES($1,$2,'VERIFIED',$3,'deterministic-replay')`, [id, programId, JSON.stringify(stored)]);
      await writeAudit(c, programId, 'FINDING_VERIFIED', { metadata: { findingId: id, reason: result.outcome.reason } });
    } else {
      await c.query(`INSERT INTO findings(id,program_id,status,body) VALUES($1,$2,'HUMAN_REVIEW',$3)`, [id, programId, JSON.stringify(stored)]);
      await writeAudit(c, programId, 'FINDING_HELD', { metadata: { findingId: id, next: result.next, reason: result.outcome.reason } });
    }
    await c.query(`INSERT INTO evidence(id,finding_id,sha256,body) VALUES($1,$2,$3,$4)`, [randomUUID(), id, sha, JSON.stringify(sealed ? { ...evidenceBody, sealed } : evidenceBody)]);
  });
  return { id, next: result.next, reproduced: result.outcome.reproduced };
}

export async function recordCampaignCoverage(pool: pg.Pool, programId: string, summary: Record<string, number>, markdown: string) {
  await transaction(pool, async c => {
    await writeAudit(c, programId, 'CAMPAIGN_COVERAGE', { metadata: { ...summary, markdown } });
  });
}

export async function retestStored(pool: pg.Pool, findingId: string, responder: Responder): Promise<RetestResult> {
  const row = await pool.query('SELECT body FROM findings WHERE id=$1', [findingId]);
  const contract = row.rows[0]?.body?.contract;
  if (!contract) return { fixed: false, inconclusive: true, reason: 'contract_missing' };
  return retest(contract, responder);
}

// A scanner may raise HUMAN_REVIEW. It cannot write VERIFIED or SUBMITTED.
export async function recordScannerFinding(pool: pg.Pool, programId: string, finding: { template: string; location: string; severity: string }) {
  const review = ['medium', 'high', 'critical'].includes(finding.severity);
  if (review && !transition('CANDIDATE', 'HUMAN_REVIEW', 'scanner').ok) throw new Error('scanner_cannot_review');
  const id = randomUUID();
  await pool.query(`INSERT INTO findings(id,program_id,status,body) VALUES($1,$2,$3,$4)`, [id, programId, review ? 'HUMAN_REVIEW' : 'OBSERVATION', JSON.stringify({
    findingType: 'nuclei', location: finding.location, severity: finding.severity, template: finding.template, confidence: review ? 0.4 : 0.2,
  })]);
  return { id, status: review ? 'HUMAN_REVIEW' as const : 'OBSERVATION' as const };
}

export async function submitFinding(pool: pg.Pool, findingId: string, reviewer: string) {
  const name = reviewer.trim();
  if (name.length < 2 || name.length > 200) throw new Error('human_reviewer_required');
  await transaction(pool, async c => {
    await c.query(`SELECT set_config('anteater.actor', 'human', true)`);
    const updated = await c.query(`UPDATE findings SET status='SUBMITTED', human_reviewer=$2 WHERE id=$1 AND status IN ('HUMAN_REVIEW','VERIFIED') RETURNING program_id`, [findingId, name]);
    const programId = updated.rows[0]?.program_id;
    if (!updated.rowCount || typeof programId !== 'string') throw new Error('finding_not_reviewable');
    // The submissions row is what a later run matches, so the same lead cannot re-enter the queue.
    await insertSubmission(c, { id: randomUUID(), programId, findingId, status: 'submitted', amount: null, currency: null });
  });
}

export async function acquireRate(pool: pg.Pool, program: string, programRps: number, globalRps: number): Promise<boolean> {
  return transaction(pool, async c => {
    await c.query('SELECT pg_advisory_xact_lock(784292)');
    const keys = ['global', `program:${program}`];
    const blocked = await c.query('SELECT 1 FROM rate_limits WHERE key=ANY($1) AND next_at>now()', [keys]);
    if (blocked.rowCount) return false;
    for (const [key, rps] of [[keys[0], globalRps], [keys[1], programRps]] as const) {
      if (!Number.isFinite(rps) || rps <= 0) throw new Error('invalid_rate');
      await c.query(`INSERT INTO rate_limits(key,next_at) VALUES($1,now()+$2*interval '1 second')
        ON CONFLICT(key) DO UPDATE SET next_at=excluded.next_at`, [key, 1 / rps]);
    }
    return true;
  });
}
