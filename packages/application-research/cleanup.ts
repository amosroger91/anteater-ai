import { createHash } from 'node:crypto';
import type { Application } from './profile.js';

export interface CleanupIntent {
  id: string; origin: string; ownerHash: string; ruleHash: string; marker: string; cleanupUrl: string;
}
// Persistence must finish before the create request is allowed. Never store credentials here.
export interface CleanupJournal {
  pending(): Promise<CleanupIntent[]>;
  prepare(intent: CleanupIntent): Promise<void>;
  complete(id: string): Promise<void>;
}
export const principalHash = (origin: string, principal: string) => createHash('sha256').update(JSON.stringify([origin, principal])).digest('hex');
export const ruleHash = (rule: Application['privateResources'][number]) => createHash('sha256').update(JSON.stringify(rule)).digest('hex');
