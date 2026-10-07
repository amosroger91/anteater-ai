import { z } from 'zod';
import type { Config } from '../shared/config.js';
import { ApplicationSchema } from '../application-research/profile.js';

const domain = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const pattern = z.string().max(253).refine(s => domain.test(s.startsWith('*.') ? s.slice(2) : s) && !s.includes('xn--'));
// Passive/bounded actions: a single reviewed path each, never a query string.
export const SAFE_ACTIONS = ['inspect_http_target', 'inspect_robots', 'inspect_sitemap', 'inspect_openapi', 'research_application'] as const;
export type PassiveAction = typeof SAFE_ACTIONS[number];
// Active probes: parameterized requests (paths + query strings) bounded by the in-scope host set, not
// the reviewed passive path allowlist. Each is a paid vulnerability class and runs only when the program
// permits that action AND ALLOW_ACTIVE_TESTING is on. Proofs demonstrate the flaw; they never destroy.
export const ACTIVE_ACTIONS = ['probe_sqli', 'probe_xss', 'probe_ssrf', 'probe_redirect'] as const;
export type ActiveAction = typeof ACTIVE_ACTIONS[number];
export const ALL_ACTIONS = [...SAFE_ACTIONS, ...ACTIVE_ACTIONS] as const;
export const ActionSchema = z.enum(ALL_ACTIONS);
export type Action = typeof ALL_ACTIONS[number];
export function isActiveAction(action: string): action is ActiveAction {
  return (ACTIVE_ACTIONS as readonly string[]).includes(action);
}
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
  application: ApplicationSchema.optional(),
  // Reviewed parameterized endpoints the operator has approved for ACTIVE probing (injection suite).
  // Each is re-checked by authorizeActive at request time (in-scope host, https/443). Optional/absent
  // means none, so a program is never actively probed until specific endpoints are reviewed in.
  activeEndpoints: z.array(z.string().url().max(2048)).max(500).optional(),
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

// Authorize a single ACTIVE probe request. Unlike the passive authorizer this permits any path and a
// query string, because active testing is bounded by the in-scope HOST set rather than the reviewed
// passive path allowlist. Everything else still holds: kill switch, the ALLOW_ACTIVE_TESTING gate, the
// program must permit this exact action, scheme/port, host must be in `allowed` and not `excluded`, and
// the policy must be reviewed and unexpired. Credentials and fragments are still rejected.
export function authorizeActive(rawPolicy: unknown, target: string, action: string, config: Pick<Config, 'GLOBAL_KILL_SWITCH'> & Partial<Config>, now = Date.now()): Decision {
  const deny = (reason: string): Decision => ({ allowed: false, reason });
  if (config.GLOBAL_KILL_SWITCH) return deny('kill_switch');
  if (!config.ALLOW_ACTIVE_TESTING) return deny('active_testing_disabled');
  if (!isActiveAction(action)) return deny('not_an_active_action');
  const parsed = PolicySchema.safeParse(rawPolicy);
  if (!parsed.success) return deny('invalid_or_missing_policy');
  const p = parsed.data;
  if (Date.parse(p.expiresAt) <= now) return deny('expired_policy');
  if (!p.allowedActions.includes(action as Action)) return deny('prohibited_action');
  let url: URL;
  try { url = new URL(target); } catch { return deny('invalid_url'); }
  if (url.username || url.password || url.hash) return deny('unsupported_target_form');
  if (!domain.test(url.hostname) || url.hostname.includes('xn--')) return deny('unsupported_hostname');
  if (!p.schemes.includes(url.protocol.slice(0, -1) as 'https')) return deny('prohibited_scheme');
  const port = Number(url.port || 443);
  if (!p.ports.includes(port as 443)) return deny('prohibited_port');
  if (p.excluded.some(rule => matches(url.hostname, rule))) return deny('excluded');
  if (!p.allowed.some(rule => matches(url.hostname, rule))) return deny('out_of_scope');
  return { allowed: true, reason: 'active_scope_match' };
}

const ACTION_PATHS: Record<PassiveAction, string> = {
  inspect_http_target: '/',
  inspect_robots: '/robots.txt',
  inspect_sitemap: '/sitemap.xml',
  inspect_openapi: '/.well-known/openapi.json',
  research_application: '/',
};

export function targetForAction(assetUrl: string, action: Action): string {
  if (isActiveAction(action)) throw new Error('active_action_has_no_fixed_path');
  if (!ActionSchema.safeParse(action).success || !/^https:\/\/[a-z0-9.-]+(?::443)?\/?$/.test(assetUrl)) throw new Error('unsupported_asset_origin');
  const url = new URL(assetUrl);
  url.search = '';
  url.hash = '';
  url.pathname = ACTION_PATHS[action];
  return url.toString();
}
