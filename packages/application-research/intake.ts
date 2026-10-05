import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { ApplicationSchema, AuthSchema } from './profile.js';
import { PolicySchema } from '../scope-engine/index.js';
import { ProgramSchema, type Program } from '../bounty-providers/index.js';
import { canonicalJson } from '../audit/index.js';
import { verifyApproval } from '../provenance/index.js';

const ApprovalFields = z.object({
  approver: z.string().min(1).max(200),
  sourceSha256: z.string().regex(/^[0-9a-f]{64}$/i),
  approvedAt: z.iso.datetime(),
}).strict();
export const CampaignSchema = z.object({
  revision: z.string().min(1).max(100), reviewed: z.literal(true), sourceUrl: z.string().url(), expiresAt: z.iso.datetime(),
  allowed: PolicySchema.shape.allowed, excluded: PolicySchema.shape.excluded.default([]),
  requestsPerSecond: z.number().positive().max(10).default(1),
  application: ApplicationSchema.default(() => ApplicationSchema.parse({})),
  authByDomain: z.record(z.string(), AuthSchema).default({}),
  approval: ApprovalFields,
}).strict();
export type Campaign = z.infer<typeof CampaignSchema>;
const hostMatches = (host: string, rule: string) => rule.startsWith('*.') ? host.endsWith('.' + rule.slice(2)) && host !== rule.slice(2) : host === rule;

// Hash the campaign with the signature blanked, then store that digest in approval.sourceSha256.
export function campaignSource(raw: unknown): string {
  const profile = CampaignSchema.parse(raw);
  return canonicalJson({ ...profile, approval: { ...profile.approval, sourceSha256: '' } });
}
export function parseDomains(text: string): string[] {
  if (Buffer.byteLength(text) > 1048576) throw new Error('domain_list_too_large');
  const domains = new Set<string>();
  for (const entry of text.replace(/^\uFEFF/, '').split(/\r?\n/)) {
    const line = entry.trim();
    if (!line || line.startsWith('#')) continue;
    const value = line.toLowerCase();
    if (!/^(?:https:\/\/)?[a-z0-9.-]+\/?$/.test(value)) throw new Error('invalid_domain_entry');
    const url = new URL(value.startsWith('https://') ? value : `https://${value}`);
    if (url.hostname.includes('xn--') || !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(url.hostname)) throw new Error('invalid_domain_entry');
    domains.add(url.hostname);
  }
  if (!domains.size || domains.size > 1000) throw new Error('invalid_domain_count');
  return [...domains].sort();
}
export function compileDomains(domains: string[], rawProfile: unknown): { programs: Program[]; held: string[] } {
  const profile = CampaignSchema.parse(rawProfile);
  const approval = verifyApproval({
    approver: profile.approval.approver, sourceUrl: profile.sourceUrl, sourceSha256: profile.approval.sourceSha256.toLowerCase(),
    approvedAt: profile.approval.approvedAt, revision: profile.revision, expiresAt: profile.expiresAt,
  }, campaignSource(rawProfile));
  if (!approval.ok) throw new Error(approval.reason);
  if (!profile.application.readPathPrefixes.includes('/')) throw new Error('root_path_required');
  const held: string[] = [];
  const programs: Program[] = [];
  for (const domain of domains) {
    if (!profile.allowed.some(rule => hostMatches(domain, rule)) || profile.excluded.some(rule => hostMatches(domain, rule))) {
      held.push(domain);
      continue;
    }
    const id = `domain-${createHash('sha256').update(domain).digest('hex').slice(0, 24)}`;
    const application = { ...profile.application, auth: profile.authByDomain[domain] ?? profile.application.auth };
    // One stored host. The path list is the crawl limit, and it always includes the root document.
    const allowedPaths = [...new Set(application.readPathPrefixes)];
    const revision = `${profile.revision}:${createHash('sha256').update(JSON.stringify({ profile, domain, application, allowedPaths })).digest('hex').slice(0, 16)}`;
    programs.push(ProgramSchema.parse({ id, name: domain, platform: 'domain-list', programUrl: `https://${domain}/`, categories: ['WEB_APPLICATION', 'API'],
      policy: { programId: id, revision, sourceUrl: profile.sourceUrl, reviewed: true, expiresAt: profile.expiresAt,
        allowed: [domain], excluded: profile.excluded, allowedActions: ['research_application'], allowedPaths, schemes: ['https'], ports: [443], requestsPerSecond: profile.requestsPerSecond, application },
      assets: [{ id: `${id}-web`, url: `https://${domain}` }] }));
  }
  return { programs, held };
}
export async function loadCampaign(domainsFile: string, profileFile: string) {
  const [domains, profile] = await Promise.all([readFile(domainsFile, 'utf8'), readFile(profileFile, 'utf8')]);
  if (Buffer.byteLength(profile) > 1048576) throw new Error('profile_too_large');
  return compileDomains(parseDomains(domains), JSON.parse(profile));
}
