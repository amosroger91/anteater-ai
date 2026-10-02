import { createHash } from 'node:crypto';
import type { Action } from '../scope-engine/index.js';

export function followUpActions(action: Action, observation: unknown): Action[] {
  if (action !== 'inspect_http_target' || !observation || typeof observation !== 'object') return [];
  const value = observation as Record<string, unknown>;
  if (value.error || typeof value.status !== 'number' || value.status < 200 || value.status >= 300) return [];
  const headers = value.headers as Record<string, unknown> | undefined;
  const contentType = String(value.contentType ?? headers?.['content-type'] ?? '');
  const snippet = typeof value.bodySnippet === 'string' ? value.bodySnippet : '';
  const actions: Action[] = [];
  if (/html|text\//i.test(contentType)) actions.push('inspect_robots', 'inspect_sitemap');
  if (/json|openapi|swagger/i.test(`${contentType}\n${snippet}`)) actions.push('inspect_openapi');
  return actions;
}

export function jobKey(program: string, asset: string, revision: string, target: string, action: Action): string {
  // Preserve the original demo key so upgrading does not replay an already completed fixture.
  if (program === 'fixture-company' && asset === 'fixture-api' && revision === 'fixture-v1' && target === 'https://api.example.test/' && action === 'inspect_http_target') return 'fixture-v1:inspect';
  return `web-v1:${createHash('sha256').update(JSON.stringify([program, asset, revision, target, action])).digest('hex')}`;
}
