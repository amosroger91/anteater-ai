import { z } from 'zod';
import type { Config } from '../shared/config.js';

const domain = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const pattern = z.string().max(253).refine(s => domain.test(s.startsWith('*.') ? s.slice(2) : s) && !s.includes('xn--'));
export const SAFE_ACTIONS = ['inspect_http_target', 'inspect_robots', 'inspect_sitemap', 'inspect_openapi'] as const;
export const ActionSchema = z.enum(SAFE_ACTIONS);
export type Action = typeof SAFE_ACTIONS[number];
const path = z.string().regex(/^\/[A-Za-z0-9._~/-]*$/).max(512).refine(value => !value.includes('//') && !value.split('/').some(part => part === '.' || part === '..'));
export const PolicySchema = z.object({
  programId: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  revision: z.string().min(1),
  sourceUrl: z.string().url(),
  reviewed: z.literal(true),
  expiresAt: z.iso.datetime(),
  allowed: z.array(pattern).min(1),
  excluded: z.array(pattern),
  allowedActions: z.array(ActionSchema).min(1),
  allowedPaths: z.array(path).min(1).default(['/']),
  schemes: z.array(z.enum(['https'])).min(1),
  ports: z.array(z.literal(443)).min(1),
  requestsPerSecond: z.number().positive().max(10),
}).strict();
export type Policy = z.infer<typeof PolicySchema>;
export type Decision = { allowed: boolean; reason: string };
const matches = (host: string, rule: string) => rule.startsWith('*.') ? host.endsWith('.' + rule.slice(2)) && host !== rule.slice(2) : host === rule;

export function authorize(rawPolicy: unknown, target: string, action: string, config: Pick<Config, 'GLOBAL_KILL_SWITCH'> & Partial<Config>, now = Date.now()): Decision {
  const deny = (reason: string): Decision => ({ allowed: false, reason });
  if (config.GLOBAL_KILL_SWITCH) return deny('kill_switch');
  const parsed = PolicySchema.safeParse(rawPolicy);
  if (!parsed.success) return deny('invalid_or_missing_policy');
  const p = parsed.data;
  if (Date.parse(p.expiresAt) <= now) return deny('expired_policy');
  if (!p.allowedActions.includes(action as Action)) return deny('prohibited_action');
  // Targets are generated from a reviewed policy. Reject credentials, queries and fragments so
  // an executor cannot be steered outside the explicitly reviewed path set.
  if (!/^https:\/\/[a-z0-9.-]+(?::443)?(?:\/[A-Za-z0-9._~/-]*)?$/.test(target)) return deny('unsupported_target_form');
  let url: URL;
  try { url = new URL(target); } catch { return deny('invalid_url'); }
  const rawPath = target.slice(target.indexOf('://') + 3).replace(/^[^/]+/, '') || '/';
  if (!path.safeParse(rawPath).success || rawPath !== url.pathname) return deny('unsupported_target_form');
  if (url.username || url.password || url.search || url.hash) return deny('unsupported_target_form');
  if (!domain.test(url.hostname) || url.hostname.includes('xn--')) return deny('unsupported_hostname');
  if (!p.schemes.includes(url.protocol.slice(0, -1) as 'https')) return deny('prohibited_scheme');
  const port = Number(url.port || 443);
  if (!p.ports.includes(port as 443)) return deny('prohibited_port');
  if (!p.allowedPaths.includes(url.pathname)) return deny('prohibited_path');
  if (p.excluded.some(rule => matches(url.hostname, rule))) return deny('excluded');
  if (!p.allowed.some(rule => matches(url.hostname, rule))) return deny('out_of_scope');
  return { allowed: true, reason: 'explicit_scope_match' };
}

const ACTION_PATHS: Record<Action, string> = {
  inspect_http_target: '/',
  inspect_robots: '/robots.txt',
  inspect_sitemap: '/sitemap.xml',
  inspect_openapi: '/.well-known/openapi.json',
};

export function targetForAction(assetUrl: string, action: Action): string {
  if (!ActionSchema.safeParse(action).success || !/^https:\/\/[a-z0-9.-]+(?::443)?\/?$/.test(assetUrl)) throw new Error('unsupported_asset_origin');
  const url = new URL(assetUrl);
  url.search = '';
  url.hash = '';
  url.pathname = ACTION_PATHS[action];
  return url.toString();
}
