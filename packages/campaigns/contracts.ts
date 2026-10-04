import { createHash } from 'node:crypto';
import { z } from 'zod';
import { authorize, PolicySchema } from '../scope-engine/index.js';

export class CampaignError extends Error {
  constructor(message: string, readonly issues: Array<{ field: string; line?: number; message: string }> = []) { super(message); }
}
export const ScopeInput = z.object({
  targets: z.array(z.string().trim().max(512)).min(1).max(25),
  excluded: z.array(z.string().trim().max(512)).max(25).default([]),
  sourceUrl: z.string().url().max(2048).refine(value => { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password; }, 'Use an HTTPS authorization URL without credentials.'),
  expiresAt: z.iso.datetime(),
});
export const AssessmentInput = ScopeInput.extend({
  name: z.string().trim().min(1).max(80), reviewed: z.literal(true),
  projectId: z.uuid().optional(), projectRevision: z.number().int().positive().optional(),
}).strict();
export type AssessmentInput = z.infer<typeof AssessmentInput>;
export const StatusSchema = z.enum(['queued', 'running', 'stopping', 'completed', 'completed_with_gaps', 'failed', 'cancelled', 'interrupted']);
export type Status = z.infer<typeof StatusSchema>;
export const CoverageSchema = z.object({
  origin: z.string(), checks: z.array(z.object({ checkId: z.string(), status: z.enum(['passed','candidate','skipped','not_applicable']), methodology: z.array(z.string()) })),
  executed: z.number().int().nonnegative(), candidates: z.number().int().nonnegative(), gaps: z.number().int().nonnegative(), unmappedCodes: z.array(z.string()),
});
export const TargetSchema = z.object({
  url: z.string().url(), status: StatusSchema, httpStatus: z.number().int().min(100).max(599).optional(),
  error: z.string().max(200).optional(), bodySha256: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  startedAt: z.iso.datetime().optional(), finishedAt: z.iso.datetime().optional(),
  findings: z.array(z.object({ code: z.string().max(100), severity: z.enum(['info','low','medium','high','critical']), detail: z.string().max(1024), fix: z.string() })).max(20),
  coverage: CoverageSchema.optional(),
});
export type Target = z.infer<typeof TargetSchema>;
export const AssessmentSchema = z.object({
  schemaVersion: z.literal(1).default(1), id: z.uuid(), name: z.string().min(1).max(80), demo: z.boolean(),
  createdAt: z.iso.datetime(), finishedAt: z.iso.datetime().optional(), updatedAt: z.iso.datetime().optional(), status: StatusSchema,
  sourceUrl: z.string().url(), expiresAt: z.iso.datetime(), targets: z.array(TargetSchema).min(1).max(25),
  excluded: z.array(z.string()).default([]), policyRevision: z.string().optional(),
  projectId: z.uuid().optional(), projectRevision: z.number().int().positive().optional(), projectName: z.string().max(80).optional(),
  archivedAt: z.iso.datetime().optional(), idempotencyKey: z.uuid().optional(), inputHash: z.string().regex(/^[a-f0-9]{64}$/).optional(),
});
export type Assessment = z.input<typeof AssessmentSchema>;

export function parse<T>(schema: z.ZodType<T>, raw: unknown): T {
  const result = schema.safeParse(raw);
  if (!result.success) throw new CampaignError('invalid_assessment_input', result.error.issues.map(issue => ({ field: issue.path.join('.'), message: issue.message })));
  return result.data;
}
export function normalizeHosts(values: string[], field = 'targets') {
  const urls: string[] = []; const warnings: string[] = []; const issues: CampaignError['issues'] = [];
  for (const [index, raw] of values.entries()) {
    const entry = raw.trim().toLowerCase();
    if (!entry) continue;
    const candidate = entry.startsWith('https://') ? entry : `https://${entry}`;
    try {
      if (!/^https:\/\/[a-z0-9.-]+\/?$/.test(candidate)) throw new Error();
      const url = new URL(candidate);
      if (url.hostname !== candidate.slice(8).replace(/\/$/, '') || !PolicySchema.shape.allowed.safeParse([url.hostname]).success) throw new Error();
      const canonical = url.origin + '/';
      if (urls.includes(canonical)) warnings.push(`Line ${index + 1}: duplicate ${url.hostname} removed.`);
      else urls.push(canonical);
    } catch { issues.push({ field, line: index + 1, message: 'Enter an exact public hostname or HTTPS origin. Paths, wildcards, credentials and IP addresses are not supported.' }); }
  }
  if (issues.length) throw new CampaignError('invalid_targets', issues);
  return { urls, warnings };
}
export function prepareScope(raw: unknown, checkExpiry = true) {
  const scope = parse(ScopeInput, raw);
  const included = normalizeHosts(scope.targets), excluded = normalizeHosts(scope.excluded, 'excluded');
  const targets = included.urls.filter(url => !excluded.urls.includes(url));
  if (!targets.length) throw new CampaignError('no_included_targets', [{ field: 'targets', message: 'At least one target must remain after applying exclusions.' }]);
  if (checkExpiry && Date.parse(scope.expiresAt) <= Date.now()) throw new CampaignError('expired_authorization', [{ field: 'expiresAt', message: 'Review and extend the authorization before starting.' }]);
  const revision = createHash('sha256').update(JSON.stringify({ targets, excluded: excluded.urls, sourceUrl: scope.sourceUrl, expiresAt: scope.expiresAt })).digest('hex');
  const policy = PolicySchema.parse({ programId: 'dashboard', revision, sourceUrl: scope.sourceUrl, reviewed: true, expiresAt: scope.expiresAt,
    allowed: targets.map(url => new URL(url).hostname), excluded: excluded.urls.map(url => new URL(url).hostname),
    allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1 });
  for (const target of targets) if (!authorize(policy, target, 'inspect_http_target', { GLOBAL_KILL_SWITCH: false }, checkExpiry ? Date.now() : 0).allowed) throw new CampaignError('target_or_policy_denied');
  return { policy, targets, excluded: excluded.urls, warnings: [...included.warnings, ...excluded.warnings],
    maxRequests: targets.length, maxBytesPerResponse: 65536, deadlineSeconds: 10, minimumDelayMs: 1100,
    action: 'One HTTPS GET per included host. No redirects, login or resource creation.',
  };
}

export const DraftFields = z.object({ name: z.string().max(80).default(''), targets: z.array(z.string().max(512)).max(25).default([]),
  excluded: z.array(z.string().max(512)).max(25).default([]), sourceUrl: z.string().max(2048).default(''), expiresAt: z.string().max(100).default(''),
  projectId: z.uuid().optional(), projectRevision: z.number().int().positive().optional() }).strict();
export const ProjectSchema = z.object({ id: z.uuid(), name: z.string().trim().min(1).max(80), revision: z.number().int().positive(),
  createdAt: z.iso.datetime(), updatedAt: z.iso.datetime(), scope: ScopeInput });
export const DraftSchema = z.object({ id: z.uuid(), revision: z.number().int().positive(), updatedAt: z.iso.datetime(), fields: DraftFields });
export const WorkspaceSchema = z.object({ schemaVersion: z.literal(1), projects: z.array(ProjectSchema).max(100), drafts: z.array(DraftSchema).max(100) }).strict();
export type Workspace = z.infer<typeof WorkspaceSchema>;
