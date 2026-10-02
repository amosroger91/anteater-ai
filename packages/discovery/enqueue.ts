import { createHash } from 'node:crypto';
import { authorize, type Action } from '../scope-engine/index.js';
import type { Candidate } from './index.js';

// Turn admitted candidates into job specifications (PRODUCTION_ROADMAP.md §1). The dedupe key is
// minted here by code (revision:host:action), never from model/discovery text, and admission is
// re-checked at spec time so an asset is queued only if the CURRENT reviewed policy authorizes that
// exact host and action.

export interface JobSpec { host: string; action: Action; dedupeKey: string }

export function candidateJobs(candidates: Candidate[], policy: unknown, action: Action, revision: string): JobSpec[] {
  const specs = new Map<string, JobSpec>();
  for (const c of candidates) {
    if (!authorize(policy, `https://${c.host}`, action, { GLOBAL_KILL_SWITCH: false }).allowed) continue;
    const dedupeKey = `${revision}:${c.host}:${action}:${createHash('sha256').update(`${revision}|${c.host}|${action}`).digest('hex').slice(0, 16)}`;
    if (!specs.has(dedupeKey)) specs.set(dedupeKey, { host: c.host, action, dedupeKey });
  }
  return [...specs.values()].sort((a, b) => a.host.localeCompare(b.host));
}
