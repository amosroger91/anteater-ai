import { z } from 'zod';
import type { Config } from '../shared/config.js';

const domain = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const pattern = z.string().max(253).refine(s => domain.test(s.startsWith('*.') ? s.slice(2) : s) && !s.includes('xn--'));
export const PolicySchema = z.object({
  programId: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  revision: z.string().min(1),
  sourceUrl: z.string().url(),
  reviewed: z.literal(true),
  expiresAt: z.iso.datetime(),
  allowed: z.array(pattern).min(1),
  excluded: z.array(pattern),
  allowedActions: z.array(z.enum(['inspect_http_target'])).min(1),
  schemes: z.array(z.enum(['https'])).min(1),
  ports: z.array(z.literal(443)).min(1),
  requestsPerSecond: z.number().positive().max(10),
}).strict();
export type Policy = z.infer<typeof PolicySchema>;
export type Decision = { allowed: boolean; reason: string };
const matches = (host: string, rule: string) => rule.startsWith('*.') ? host.endsWith('.' + rule.slice(2)) && host !== rule.slice(2) : host === rule;

export function authorize(rawPolicy: unknown, target: string, action: string, config: Config, now = Date.now()): Decision {
  const deny = (reason: string): Decision => ({ allowed: false, reason });
  if (config.GLOBAL_KILL_SWITCH) return deny('kill_switch');
  const parsed = PolicySchema.safeParse(rawPolicy);
  if (!parsed.success) return deny('invalid_or_missing_policy');
  const p = parsed.data;
  if (Date.parse(p.expiresAt) <= now) return deny('expired_policy');
  if (!p.allowedActions.includes(action as 'inspect_http_target')) return deny('prohibited_action');
  // Conservative MVP: no implicit URL normalization, credentials, encoded hosts, paths, queries, or redirects.
  if (!/^https:\/\/[a-z0-9.-]+(?::443)?\/?$/.test(target)) return deny('unsupported_target_form');
  let url: URL;
  try { url = new URL(target); } catch { return deny('invalid_url'); }
  if (!domain.test(url.hostname) || url.hostname.includes('xn--')) return deny('unsupported_hostname');
  if (p.excluded.some(rule => matches(url.hostname, rule))) return deny('excluded');
  if (!p.allowed.some(rule => matches(url.hostname, rule))) return deny('out_of_scope');
  return { allowed: true, reason: 'explicit_scope_match' };
}
