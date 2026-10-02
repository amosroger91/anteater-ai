import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { ApplicationSchema, AuthSchema } from './profile.js';
import { PolicySchema } from '../scope-engine/index.js';
import { ProgramSchema, type Program } from '../bounty-providers/index.js';

export const CampaignSchema = z.object({
  revision: z.string().min(1).max(100), reviewed: z.literal(true), sourceUrl: z.string().url(), expiresAt: z.iso.datetime(),
  allowed: PolicySchema.shape.allowed, excluded: PolicySchema.shape.excluded.default([]),
  requestsPerSecond: z.number().positive().max(10).default(1),
  application: ApplicationSchema.default(() => ApplicationSchema.parse({})),
  authByDomain: z.record(z.string(), AuthSchema).default({}),
}).strict();
export type Campaign = z.infer<typeof CampaignSchema>;
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
export function compileDomains(domains: string[], rawProfile: unknown): Program[] {
  const profile = CampaignSchema.parse(rawProfile);
  if (Date.parse(profile.expiresAt) <= Date.now()) throw new Error('expired_policy');
  return domains.map(domain => {
    const id = `domain-${createHash('sha256').update(domain).digest('hex').slice(0, 24)}`;
    const application = { ...profile.application, auth: profile.authByDomain[domain] ?? profile.application.auth };
    // Hash every policy-relevant option so a changed profile cannot reuse a stale job key.
    const revision = `${profile.revision}:${createHash('sha256').update(JSON.stringify({ profile, domain, application })).digest('hex').slice(0, 16)}`;
    return ProgramSchema.parse({ id, name: domain, platform: 'domain-list', programUrl: `https://${domain}/`, categories: ['WEB_APPLICATION', 'API'],
      policy: { programId: id, revision, sourceUrl: profile.sourceUrl, reviewed: true, expiresAt: profile.expiresAt,
        allowed: profile.allowed, excluded: profile.excluded, allowedActions: ['research_application'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: profile.requestsPerSecond, application },
      assets: [{ id: `${id}-web`, url: `https://${domain}` }] });
  });
}
export async function loadCampaign(domainsFile: string, profileFile: string) {
  const [domains, profile] = await Promise.all([readFile(domainsFile, 'utf8'), readFile(profileFile, 'utf8')]);
  if (Buffer.byteLength(profile) > 1048576) throw new Error('profile_too_large');
  return compileDomains(parseDomains(domains), JSON.parse(profile));
}
