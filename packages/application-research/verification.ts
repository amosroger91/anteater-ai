import { randomBytes, randomUUID, createHash } from 'node:crypto';
import type { Application } from './profile.js';
import { jsonPointer } from './profile.js';
import type { BrowserSession } from './browser.js';
import { publicUrl, type ExchangeResponse } from './transport.js';
import { principalHash, ruleHash, type CleanupIntent, type CleanupJournal } from './cleanup.js';

export interface VerifiedFinding {
  code: 'cross_account_resource_read'; status: 'HUMAN_REVIEW'; verifier: 'owner-boundary-v1'; severity: 'high';
  rule: string; owner: string; other: string; evidence: Array<{ step: string; method: string; url: string; status: number; sha256: string }>;
}
const digest = (body: Buffer) => createHash('sha256').update(body).digest('hex');
async function cleanupResource(owner: BrowserSession, intent: CleanupIntent, journal: CleanupJournal, gaps: string[], creationSettled = true) {
  owner.gate.ownedDeletes.add(intent.cleanupUrl);
  try {
    const response = await owner.request(intent.cleanupUrl, 'DELETE', undefined, true);
    // 202 is only acceptance, not completion. A second owner-bound marker delete must
    // confirm absence; APIs with different semantics leave an operator-visible obligation.
    const absent = response.status === 404 || ([200, 204].includes(response.status)
      && (await owner.request(intent.cleanupUrl, 'DELETE', undefined, true)).status === 404);
    if (absent && creationSettled) await journal.complete(intent.id);
    else gaps.push('cleanup_unconfirmed');
  } catch { gaps.push('cleanup_failed'); }
  finally { owner.gate.ownedDeletes.delete(intent.cleanupUrl); }
}

export async function verifyOwnership(app: Application, sessions: BrowserSession[], gaps: string[], journal?: CleanupJournal): Promise<VerifiedFinding[]> {
  const findings: VerifiedFinding[] = [];
  if (!journal) { if (app.privateResources.length) gaps.push('cleanup_journal_required'); return findings; }
  // Reconcile old obligations before creating anything else, including after a failed job/restart.
  for (const intent of await journal.pending()) {
    const rule = app.privateResources.find(rule => ruleHash(rule) === intent.ruleHash);
    const owner = sessions.find(session => session.principalId && session.gate.origin === intent.origin
      && principalHash(intent.origin, session.principalId) === intent.ownerHash);
    if (!rule || !owner || new URL(rule.cleanupPath.replaceAll('{marker}', encodeURIComponent(intent.marker)), intent.origin).href !== intent.cleanupUrl) {
      gaps.push('cleanup_requires_original_owner_and_current_rule'); continue;
    }
    const previousPurpose = owner.purpose; owner.purpose = 'verify';
    try {
      if (!await owner.identityUnchanged(app)) { gaps.push('cleanup_identity_changed'); continue; }
      await cleanupResource(owner, intent, journal, gaps);
    } catch { gaps.push('cleanup_failed'); }
    finally { owner.purpose = previousPurpose; }
  }
  if ((await journal.pending()).length) { gaps.push('cleanup_pending_operator_action'); return findings; }
  if (!app.privateResources.length) return findings;
  if (sessions.length < 2 || !app.auth.sessionPath) { gaps.push('ownership_checks_require_two_identity_validated_accounts'); return findings; }
  const [owner, other] = sessions as [BrowserSession, BrowserSession];
  if (!owner.principalId || !other.principalId || owner.principalId === other.principalId) { gaps.push('ownership_checks_require_distinct_principals'); return findings; }
  owner.purpose = 'verify'; other.purpose = 'verify';
  for (const rule of app.privateResources) {
    if ((await journal.pending()).length) { gaps.push('cleanup_pending_operator_action'); break; }
    const marker = `anteater-owned-${randomBytes(16).toString('hex')}`;
    const evidence: VerifiedFinding['evidence'] = [];
    const cleanup = new URL(rule.cleanupPath.replaceAll('{marker}', encodeURIComponent(marker)), owner.gate.origin).href;
    let createAttempted = false;
    let creationSettled = false;
    const intent: CleanupIntent = { id: randomUUID(), origin: owner.gate.origin,
      ownerHash: principalHash(owner.gate.origin, owner.principalId), ruleHash: ruleHash(rule), marker, cleanupUrl: cleanup };
    const record = (step: string, method: string, url: string, response: ExchangeResponse) => {
      evidence.push({ step, method, url: publicUrl(url), status: response.status, sha256: digest(response.body) });
      try { return !response.truncated && response.status >= 200 && response.status < 300 && jsonPointer(JSON.parse(response.body.toString()), rule.markerPointer) === marker; } catch { return false; }
    };
    try {
      if (owner.gate.app.maxRequests - owner.gate.count < 14) { gaps.push('verification_budget_exhausted'); break; }
      if (!await owner.identityUnchanged(app) || !await other.identityUnchanged(app)) { gaps.push('verification_identity_changed'); break; }
      const createUrl = new URL(rule.createPath, owner.gate.origin).href;
      await journal.prepare(intent);
      // A timeout can happen after the server commits the create, so cleanup is attempted after
      // every create attempt, including transport failures and unusable create responses.
      createAttempted = true;
      const created = await owner.request(createUrl, 'POST', { ...rule.body, [rule.markerField]: marker });
      creationSettled = true;
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
      if (!await owner.identityUnchanged(app) || !await other.identityUnchanged(app)) { gaps.push('verification_identity_changed'); continue; }
      findings.push({ code: 'cross_account_resource_read', status: 'HUMAN_REVIEW', verifier: 'owner-boundary-v1', severity: 'high', rule: rule.name, owner: owner.id, other: other.id, evidence });
    } catch { gaps.push('verification_interrupted'); }
    finally {
      if (createAttempted) {
        await cleanupResource(owner, intent, journal, gaps, creationSettled);
      }
      owner.gate.ownedDeletes.delete(cleanup);
    }
    if ((await journal.pending()).length) { gaps.push('cleanup_pending_operator_action'); break; }
  }
  owner.purpose = 'discover'; other.purpose = 'discover';
  return findings;
}
