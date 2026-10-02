import { randomBytes, createHash } from 'node:crypto';
import type { Application } from './profile.js';
import { jsonPointer } from './profile.js';
import type { BrowserSession } from './browser.js';
import { publicUrl, type ExchangeResponse } from './transport.js';

export interface VerifiedFinding {
  code: 'cross_account_resource_read'; status: 'HUMAN_REVIEW'; verifier: 'owner-boundary-v1'; severity: 'high';
  rule: string; owner: string; other: string; evidence: Array<{ step: string; method: string; url: string; status: number; sha256: string }>;
}
const digest = (body: Buffer) => createHash('sha256').update(body).digest('hex');
export async function verifyOwnership(app: Application, sessions: BrowserSession[], gaps: string[]): Promise<VerifiedFinding[]> {
  const findings: VerifiedFinding[] = [];
  if (!app.privateResources.length) return findings;
  if (sessions.length < 2 || !app.auth.sessionPath) { gaps.push('ownership_checks_require_two_identity_validated_accounts'); return findings; }
  const [owner, other] = sessions as [BrowserSession, BrowserSession];
  owner.purpose = 'verify'; other.purpose = 'verify';
  for (const rule of app.privateResources) {
    const marker = `anteater-owned-${randomBytes(16).toString('hex')}`;
    const evidence: VerifiedFinding['evidence'] = [];
    const cleanup = new URL(rule.cleanupPath.replaceAll('{marker}', encodeURIComponent(marker)), owner.gate.origin).href;
    let createAttempted = false;
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
      findings.push({ code: 'cross_account_resource_read', status: 'HUMAN_REVIEW', verifier: 'owner-boundary-v1', severity: 'high', rule: rule.name, owner: owner.id, other: other.id, evidence });
    } catch { gaps.push('verification_interrupted'); }
    finally {
      if (createAttempted) {
        try { const response = await owner.request(cleanup, 'DELETE'); if (![200, 202, 204, 404].includes(response.status)) gaps.push('cleanup_failed'); }
        catch { gaps.push('cleanup_failed'); }
      }
      owner.gate.ownedDeletes.delete(cleanup);
    }
  }
  owner.purpose = 'discover'; other.purpose = 'discover';
  return findings;
}
