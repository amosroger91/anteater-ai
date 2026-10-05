import { randomBytes, createHash } from 'node:crypto';
import { ownershipRoster, planOwnershipContract } from '../authz/index.js';
import { verifyCandidate, type Responder } from '../findings/index.js';
import type { Application } from './profile.js';
import { jsonPointer } from './profile.js';
import { publicUrl, type ExchangeResponse, type Purpose } from './transport.js';

export interface OwnershipSession {
  id: string;
  purpose: Purpose;
  gate: { origin: string; app: { maxRequests: number }; count: number; ownedDeletes: Set<string> };
  request(url: string, method?: string, body?: unknown): Promise<ExchangeResponse>;
}

export interface VerifiedFinding {
  code: 'cross_account_resource_read'; status: 'HUMAN_REVIEW'; verifier: 'owner-boundary-v1'; severity: 'high';
  boundary: 'cross-user' | 'cross-tenant';
  rule: string; owner: string; other: string; evidence: Array<{ step: string; method: string; url: string; status: number; sha256: string }>;
}
const digest = (body: Buffer) => createHash('sha256').update(body).digest('hex');
// A 404 only means "already gone" when the create itself did not succeed.
export function cleanupAccepted(createdOk: boolean, status: number): boolean {
  if (status === 200 || status === 202 || status === 204) return true;
  return !createdOk && status === 404;
}
function pairSessions(app: Application, sessions: OwnershipSession[]): { owner: OwnershipSession; other: OwnershipSession; crossTenant: boolean } | undefined {
  const byId = new Map(sessions.map(session => [session.id, session]));
  const roster = ownershipRoster(app.auth.accounts.map(account => ({ id: account.id, role: account.role, tenant: account.tenant })));
  if (roster) {
    const owner = byId.get(roster.owner.id);
    const other = byId.get(roster.peer.id);
    if (owner && other) return { owner, other, crossTenant: roster.crossTenant };
  }
  if (sessions.length < 2) return undefined;
  const owner = sessions[0];
  const other = sessions[1];
  if (!owner || !other) return undefined;
  return { owner, other, crossTenant: false };
}

export function sessionResponder(reads: Record<string, () => Promise<{ status: number; body: string }>>): Responder {
  return async stepId => {
    const read = reads[stepId];
    if (!read) return { status: 0, body: '', unavailable: true };
    try { return await read(); }
    catch { return { status: 0, body: '', unavailable: true }; }
  };
}

export async function verifyOwnership(app: Application, sessions: OwnershipSession[], gaps: string[]): Promise<VerifiedFinding[]> {
  const findings: VerifiedFinding[] = [];
  if (!app.privateResources.length) return findings;
  const pair = pairSessions(app, sessions);
  if (!pair || !app.auth.sessionPath) { gaps.push('ownership_checks_require_two_identity_validated_accounts'); return findings; }
  const { owner, other, crossTenant } = pair;
  owner.purpose = 'verify'; other.purpose = 'verify';
  for (const rule of app.privateResources) {
    const marker = `anteater-owned-${randomBytes(16).toString('hex')}`;
    const evidence: VerifiedFinding['evidence'] = [];
    const cleanup = new URL(rule.cleanupPath.replaceAll('{marker}', encodeURIComponent(marker)), owner.gate.origin).href;
    let createAttempted = false;
    let createdOk = false;
    const record = (step: string, method: string, url: string, response: ExchangeResponse) => {
      evidence.push({ step, method, url: publicUrl(url), status: response.status, sha256: digest(response.body) });
      try { return !response.truncated && response.status >= 200 && response.status < 300 && jsonPointer(JSON.parse(response.body.toString()), rule.markerPointer) === marker; } catch { return false; }
    };
    try {
      if (owner.gate.app.maxRequests - owner.gate.count < 10) { gaps.push('verification_budget_exhausted'); break; }
      const createUrl = new URL(rule.createPath, owner.gate.origin).href;
      owner.gate.ownedDeletes.add(cleanup);
      // A timeout can happen after the server commits the create, so cleanup is attempted after
      // every create attempt, including transport failures and unusable create responses.
      createAttempted = true;
      const created = await owner.request(createUrl, 'POST', { ...rule.body, [rule.markerField]: marker });
      if (created.status < 200 || created.status >= 300 || created.truncated) { gaps.push('test_resource_creation_failed'); continue; }
      createdOk = true;
      let id: unknown; try { id = jsonPointer(JSON.parse(created.body.toString()), rule.idPointer); } catch { gaps.push('unsupported_resource_id'); continue; }
      if ((typeof id !== 'string' && typeof id !== 'number') || !/^[a-zA-Z0-9_-]{1,128}$/.test(String(id))) { gaps.push('unsupported_resource_id'); continue; }
      const url = new URL(rule.readPath.replaceAll('{id}', String(id)), owner.gate.origin).href;
      const baseline = await owner.request(url);
      if (!record('owner_baseline', 'GET', url, baseline)) { gaps.push('ownership_baseline_failed'); continue; }
      const cross = await other.request(url);
      if (!record('other_account', 'GET', url, cross)) continue;
      const repeated = await other.request(url);
      if (!record('repeat_other_account', 'GET', url, repeated)) { gaps.push('unstable_candidate'); continue; }
      const missingUrl = new URL(rule.readPath.replaceAll('{id}', `missing-${randomBytes(16).toString('hex')}`), owner.gate.origin).href;
      const control = await other.request(missingUrl);
      const sameMarker = record('nonexistent_control', 'GET', missingUrl, control);
      if (sameMarker || ![403, 404].includes(control.status)) { gaps.push('ambiguous_negative_control'); continue; }
      const ownerAgain = await owner.request(url);
      if (!record('repeat_owner', 'GET', url, ownerAgain)) { gaps.push('unstable_owner_baseline'); continue; }
      const contract = planOwnershipContract({ id: rule.name, victimStepId: 'other-read', controlStepId: 'missing-control', marker }, 2, 404);
      const replay = await verifyCandidate('CANDIDATE', contract, sessionResponder({
        'other-read': async () => { const response = await other.request(url); return { status: response.status, body: response.body.toString() }; },
        'missing-control': async () => { const response = await other.request(missingUrl); return { status: response.status, body: response.body.toString() }; },
      }));
      if (!replay.outcome.reproduced) { gaps.push('ownership_replay_not_reproduced'); continue; }
      const base = { code: 'cross_account_resource_read' as const, status: 'HUMAN_REVIEW' as const, verifier: 'owner-boundary-v1' as const, severity: 'high' as const, rule: rule.name, owner: owner.id, other: other.id, evidence };
      findings.push({ ...base, boundary: 'cross-user' });
      if (crossTenant) findings.push({ ...base, boundary: 'cross-tenant' });
    } catch (error) {
      if (error instanceof Error && error.message === 'kill_switch') throw error;
      gaps.push('verification_interrupted');
    }
    finally {
      if (createAttempted) {
        try {
          const response = await owner.request(cleanup, 'DELETE');
          if (!cleanupAccepted(createdOk, response.status)) gaps.push('cleanup_failed');
        }
        catch (error) {
          owner.gate.ownedDeletes.delete(cleanup);
          if (error instanceof Error && error.message === 'kill_switch') throw error;
          gaps.push('cleanup_failed');
        }
      }
      owner.gate.ownedDeletes.delete(cleanup);
    }
  }
  owner.purpose = 'discover'; other.purpose = 'discover';
  return findings;
}
