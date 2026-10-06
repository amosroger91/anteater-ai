import { z } from 'zod';
import { canonicalJson } from '../audit/index.js';
import { assetIdForHost } from '../shared/asset-id.js';
import { ApplicationSchema } from '../application-research/profile.js';
import { CampaignSchema, campaignSource } from '../application-research/intake.js';
import { ProgramSchema, type Program } from '../bounty-providers/index.js';
import { candidateJobs, type JobSpec } from '../discovery/enqueue.js';
import type { Candidate } from '../discovery/index.js';
import { sha256Hex, verifyApproval } from '../provenance/index.js';
import { authorize, targetForAction, type Action } from '../scope-engine/index.js';
import { classifyAutomation, type AutomationClass } from './classify.js';
import { hackerOneProgramUrls, rateRulesFromPolicy, RawProgramSchema, type RawProgram } from './hackerone.js';

// Reviewed campaign compile (BOUNTY_EARNINGS_PLAN.md Phase 1.3). The human supplies the
// approval fields. verifyApproval must match this canonical source. A prohibited program
// produces no enqueueable program. Manual-only never receives research_application.
// Reward-category exclusions from the platform are not host denials and are not scanned.

const PASSIVE_ACTIONS = ['inspect_http_target', 'inspect_robots', 'inspect_sitemap', 'inspect_openapi'] as const;
const WEB_TYPES = new Set(['url', 'wildcard']);
const DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export const IntakeApprovalSchema = z.object({
  approver: z.string().min(1).max(200).refine(value => value.trim().length > 0),
  sourceSha256: z.string().regex(/^[0-9a-f]{64}$/i),
  approvedAt: z.iso.datetime(),
  revision: z.string().min(1).max(100),
  expiresAt: z.iso.datetime(),
}).strict();
export type IntakeApproval = z.infer<typeof IntakeApprovalSchema>;

export interface CompiledIntake {
  automation: AutomationClass;
  handle: string;
  sourceSha256: string;
  programs: Program[];
  skipped: string[];
  refused: 'prohibited' | 'submission_closed' | 'no_web_scope' | 'no_concrete_asset' | null;
}

interface WebScope { allowed: string[]; excluded: string[]; concrete: string[]; skipped: string[] }

function parse<T>(schema: z.ZodType<T>, value: unknown, code: string): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new Error(code);
  return parsed.data;
}

// HTTPS origin or a *.host wildcard. Paths, other schemes, and non-web asset types are not scope.
export function webRule(assetType: string, identifier: string): { rule: string; concrete: boolean } | null {
  if (!WEB_TYPES.has(assetType.trim().toLowerCase())) return null;
  let host = identifier.trim();
  if (host.includes('://') || host.startsWith('//')) {
    let url: URL;
    try { url = new URL(host); } catch { return null; }
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) return null;
    if (url.port && url.port !== '443') return null;
    if (url.pathname !== '/' && url.pathname !== '') return null;
    host = url.hostname;
  }
  host = host.toLowerCase().replace(/\.$/, '');
  if (host.includes('xn--')) return null;
  const wildcard = host.startsWith('*.');
  const name = wildcard ? host.slice(2) : host;
  if (!DOMAIN.test(name)) return null;
  return { rule: wildcard ? `*.${name}` : name, concrete: !wildcard };
}

function hostExcluded(host: string, excluded: string[]): boolean {
  if (!excluded.length) return false;
  const decision = authorize({
    programId: 'intake-scope', revision: 'intake', sourceUrl: 'https://api.hackerone.com/v1/hackers/programs/intake-scope',
    reviewed: true, expiresAt: '2099-01-01T00:00:00.000Z', allowed: [host], excluded,
    allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1,
  }, `https://${host}/`, 'inspect_http_target', { GLOBAL_KILL_SWITCH: false });
  return decision.reason === 'excluded';
}

function webScope(raw: RawProgram): WebScope {
  const allowed = new Set<string>();
  const excluded = new Set<string>();
  const concrete = new Set<string>();
  const skipped: string[] = [];
  for (const scope of raw.scopes) {
    const rule = webRule(scope.assetType, scope.identifier);
    if (!rule) { skipped.push(scope.identifier); continue; }
    if (!scope.eligibleForSubmission) {
      excluded.add(rule.rule);
      concrete.delete(rule.rule);
      continue;
    }
    if (excluded.has(rule.rule)) continue;
    allowed.add(rule.rule);
    if (rule.concrete) concrete.add(rule.rule);
  }
  for (const rule of excluded) allowed.delete(rule);
  const excludedList = [...excluded].sort();
  return {
    allowed: [...allowed].sort(),
    excluded: excludedList,
    concrete: [...concrete].filter(host => !hostExcluded(host, excludedList)).sort(),
    skipped: [...new Set(skipped)].sort(),
  };
}

function assertDocument(raw: RawProgram) {
  const urls = hackerOneProgramUrls(raw.handle);
  const rate = rateRulesFromPolicy(raw.policyText);
  if (raw.sourceUrl !== urls.program || raw.programUrl !== `https://hackerone.com/${raw.handle}`) throw new Error('program_source_refused');
  if (rate.requestsPerSecond !== raw.rate.requestsPerSecond || rate.published !== raw.rate.published) throw new Error('program_rate_mismatch');
}

type ApprovalFields = { approver: string; approvedAt: string; revision: string; expiresAt: string };

export function intakeApprovalSource(rawInput: unknown, approvalInput: ApprovalFields): string {
  const raw = parse(RawProgramSchema, rawInput, 'invalid_program');
  assertDocument(raw);
  const approval = parse(z.object({
    approver: IntakeApprovalSchema.shape.approver,
    approvedAt: IntakeApprovalSchema.shape.approvedAt,
    revision: IntakeApprovalSchema.shape.revision,
    expiresAt: IntakeApprovalSchema.shape.expiresAt,
  }).strict(), {
    approver: approvalInput.approver, approvedAt: approvalInput.approvedAt,
    revision: approvalInput.revision, expiresAt: approvalInput.expiresAt,
  }, 'invalid_approval_record');
  const automation = classifyAutomation(raw.policyText);
  const scope = webScope(raw);
  const rewardExclusions = [...raw.exclusions].sort((a, b) => a.category.localeCompare(b.category) || a.details.localeCompare(b.details));
  const base = {
    platform: raw.platform, handle: raw.handle, sourceUrl: raw.sourceUrl,
    revision: approval.revision, expiresAt: approval.expiresAt, approver: approval.approver, approvedAt: approval.approvedAt,
    automation, policySha256: sha256Hex(raw.policyText), submissionState: raw.submissionState,
    openScope: raw.openScope, goldStandardSafeHarbor: raw.goldStandardSafeHarbor,
    allowed: scope.allowed, excluded: scope.excluded, requestsPerSecond: raw.rate.requestsPerSecond,
    ratePublished: raw.rate.published, rewardExclusions,
  };
  if (!scope.allowed.length) return canonicalJson({ ...base, campaign: null });
  const profile = CampaignSchema.parse({
    revision: approval.revision, reviewed: true, sourceUrl: raw.sourceUrl, expiresAt: approval.expiresAt,
    allowed: scope.allowed, excluded: scope.excluded, requestsPerSecond: raw.rate.requestsPerSecond,
    approval: { approver: approval.approver, sourceSha256: '0'.repeat(64), approvedAt: approval.approvedAt },
  });
  return canonicalJson({ ...base, campaign: JSON.parse(campaignSource(profile)) });
}

function refusal(raw: RawProgram, automation: AutomationClass, scope: WebScope): CompiledIntake['refused'] {
  if (automation === 'prohibited') return 'prohibited';
  if (raw.submissionState !== 'open') return 'submission_closed';
  if (!scope.allowed.length) return 'no_web_scope';
  if (!scope.concrete.length) return 'no_concrete_asset';
  return null;
}

function passivePaths(): string[] {
  const origin = 'https://path.example.test';
  return [...new Set(PASSIVE_ACTIONS.map(action => new URL(targetForAction(origin, action)).pathname))];
}

function buildProgram(raw: RawProgram, approval: IntakeApproval, automation: AutomationClass, scope: WebScope, source: string): Program | undefined {
  const id = `h1-${raw.handle.replaceAll('_', '-')}`;
  const allowedActions = automation === 'permitted' ? [...PASSIVE_ACTIONS, 'research_application' as const] : [...PASSIVE_ACTIONS];
  const policy = {
    programId: id, revision: `${approval.revision}:${sha256Hex(source).slice(0, 16)}`, sourceUrl: raw.sourceUrl,
    reviewed: true as const, expiresAt: approval.expiresAt, allowed: scope.allowed, excluded: scope.excluded,
    allowedActions, allowedPaths: passivePaths(), schemes: ['https' as const], ports: [443 as const],
    requestsPerSecond: raw.rate.requestsPerSecond, application: ApplicationSchema.parse({}),
  };
  const assets = scope.concrete.filter(host => authorize(policy, `https://${host}/`, 'inspect_http_target', { GLOBAL_KILL_SWITCH: false }).allowed)
    .map(host => ({ id: assetIdForHost(host, id), url: `https://${host}` }));
  if (!assets.length) return undefined;
  return ProgramSchema.parse({
    id, name: raw.name, platform: 'hackerone', programUrl: raw.programUrl, categories: ['WEB_APPLICATION'], policy, assets,
  });
}

export function compileIntake(rawInput: unknown, approvalInput: unknown, now = Date.now()): CompiledIntake {
  const raw = parse(RawProgramSchema, rawInput, 'invalid_program');
  const approval = parse(IntakeApprovalSchema, approvalInput, 'invalid_approval_record');
  assertDocument(raw);
  const source = intakeApprovalSource(raw, approval);
  const check = verifyApproval({
    approver: approval.approver, sourceUrl: raw.sourceUrl, sourceSha256: approval.sourceSha256.toLowerCase(),
    approvedAt: approval.approvedAt, revision: approval.revision, expiresAt: approval.expiresAt,
  }, source, now);
  if (!check.ok) throw new Error(check.reason);
  const automation = classifyAutomation(raw.policyText);
  const scope = webScope(raw);
  const refused = refusal(raw, automation, scope);
  const program = refused ? undefined : buildProgram(raw, approval, automation, scope, source);
  return {
    automation, handle: raw.handle, sourceSha256: approval.sourceSha256.toLowerCase(),
    programs: program ? [program] : [], skipped: scope.skipped,
    refused: program ? null : (refused ?? 'no_concrete_asset'),
  };
}

const OBSERVED_AT = '2026-01-01T00:00:00.000Z';

export function jobsForIntake(compiled: CompiledIntake, action: Action): JobSpec[] {
  if (compiled.automation === 'prohibited' || compiled.refused || compiled.programs.length === 0) return [];
  if (compiled.automation === 'manual-only' && action === 'research_application') return [];
  const specs: JobSpec[] = [];
  for (const program of compiled.programs) {
    const candidates: Candidate[] = program.assets.map(asset => ({
      host: new URL(asset.url).hostname, source: 'submitted', confidence: 1, relation: 'submitted', observedAt: OBSERVED_AT,
    }));
    specs.push(...candidateJobs(candidates, program.policy, action, program.policy.revision));
  }
  return specs;
}
