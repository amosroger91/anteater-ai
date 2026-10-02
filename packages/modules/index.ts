import { z } from 'zod';
import type { FindingSeverity } from '../findings/index.js';

// Additional asset-class modules as read-only, offline config analyzers (PRODUCTION_ROADMAP.md §6).
// Each module has its OWN authorization boundary: a web-domain grant authorizes none of them. These
// analyze operator-supplied configuration; they never reach a cloud API, cluster or credential here.

export interface ModuleFinding { code: string; severity: FindingSeverity; detail: string }

// --- Module authorization boundary -----------------------------------------
export const ModuleProfileSchema = z.object({
  reviewed: z.literal(true),
  modules: z.array(z.enum(['cloud', 'k8s', 'secrets', 'network', 'cicd', 'supply-chain'])).min(1),
}).strict();

// A web policy (no module profile) authorizes nothing here; a module runs only if its own reviewed
// profile explicitly lists it.
export function moduleAuthorized(profile: unknown, moduleId: string): boolean {
  const parsed = ModuleProfileSchema.safeParse(profile);
  return parsed.success && parsed.data.modules.includes(moduleId as 'cloud');
}

// --- Cloud IAM (offline policy analysis) -----------------------------------
export function analyzeIamPolicy(doc: unknown): ModuleFinding[] {
  const parsed = z.object({ Statement: z.array(z.object({
    Effect: z.string(), Action: z.union([z.string(), z.array(z.string())]).optional(), Resource: z.union([z.string(), z.array(z.string())]).optional(),
  }).passthrough()) }).safeParse(doc);
  if (!parsed.success) return [];
  const findings: ModuleFinding[] = [];
  const has = (v: string | string[] | undefined, needle: string) => (Array.isArray(v) ? v : [v ?? '']).includes(needle);
  for (const s of parsed.data.Statement) {
    if (s.Effect !== 'Allow') continue;
    if (has(s.Action, '*') && has(s.Resource, '*')) findings.push({ code: 'iam_admin_wildcard', severity: 'high', detail: 'Allow Action:* on Resource:*' });
    else if (has(s.Action, '*')) findings.push({ code: 'iam_action_wildcard', severity: 'medium', detail: 'Allow Action:*' });
    else if (has(s.Resource, '*')) findings.push({ code: 'iam_resource_wildcard', severity: 'low', detail: 'Allow on Resource:*' });
  }
  return findings;
}

// --- Kubernetes manifest (offline analysis) --------------------------------
export function analyzeK8sManifest(doc: unknown): ModuleFinding[] {
  const parsed = z.object({ spec: z.object({
    hostNetwork: z.boolean().optional(),
    containers: z.array(z.object({
      name: z.string().optional(),
      securityContext: z.object({ privileged: z.boolean().optional(), runAsUser: z.number().optional() }).partial().optional(),
      resources: z.object({ limits: z.record(z.string(), z.unknown()).optional() }).optional(),
    }).passthrough()).optional(),
    volumes: z.array(z.object({ hostPath: z.unknown().optional() }).passthrough()).optional(),
  }).passthrough() }).safeParse(doc);
  if (!parsed.success) return [];
  const findings: ModuleFinding[] = [];
  const spec = parsed.data.spec;
  if (spec.hostNetwork) findings.push({ code: 'k8s_host_network', severity: 'high', detail: 'hostNetwork: true' });
  if (spec.volumes?.some(v => v.hostPath !== undefined)) findings.push({ code: 'k8s_host_path', severity: 'high', detail: 'hostPath volume mounted' });
  for (const c of spec.containers ?? []) {
    if (c.securityContext?.privileged) findings.push({ code: 'k8s_privileged', severity: 'high', detail: `container ${c.name ?? '?'} privileged` });
    if (c.securityContext?.runAsUser === 0) findings.push({ code: 'k8s_run_as_root', severity: 'medium', detail: `container ${c.name ?? '?'} runAsUser 0` });
    if (!c.resources?.limits) findings.push({ code: 'k8s_no_limits', severity: 'low', detail: `container ${c.name ?? '?'} has no resource limits` });
  }
  return findings;
}

// --- Secret exposure in a supplied config string ---------------------------
const SECRET_RULES: Array<[string, RegExp]> = [
  ['aws_access_key', /\bAKIA[0-9A-Z]{16}\b/],
  ['private_key', /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/],
  ['generic_secret', /(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['"]?[^\s'"]{6,}/i],
];
export function scanSecrets(config: string): ModuleFinding[] {
  return SECRET_RULES.filter(([, re]) => re.test(config)).map(([code]) => ({ code: `secret_${code}`, severity: 'high' as const, detail: 'secret-shaped value in configuration' }));
}
