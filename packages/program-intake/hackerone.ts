import { z } from 'zod';

// HackerOne hacker API (BOUNTY_EARNINGS_PLAN.md Phase 1.1).
// Documented host: https://api.hackerone.com — GET /v1/hackers/programs/{handle},
// /structured_scopes, and /scope_exclusions. fetchLike is injectable. A live call
// needs the caller's Authorization header; this module does not read the environment
// and does not follow a redirect or a link off that host.

const API_HOST = 'api.hackerone.com';
export const MAX_RESPONSE_BYTES = 1_048_576;
const MAX_TOTAL_BYTES = 4_194_304;
const MAX_PAGES = 20;
const HANDLE = /^[a-z0-9]+(?:[-_][a-z0-9]+)*$/;

export type FetchLike = (url: string, init?: { method?: 'GET'; signal?: AbortSignal; redirect?: 'error'; headers?: Record<string, string> }) => Promise<{ ok: boolean; status: number; text(): Promise<string>; body?: ReadableStream<Uint8Array> | null }>;

export async function readIntakeText(response: Awaited<ReturnType<FetchLike>>, limit: number): Promise<string> {
  if (!response.body) {
    const text = await response.text();
    if (Buffer.byteLength(text) > limit) throw new Error('program_response_too_large');
    return text;
  }
  const reader = response.body.getReader(); const chunks: Buffer[] = []; let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      bytes += value.byteLength;
      if (bytes > limit) throw new Error('program_response_too_large');
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks, bytes).toString('utf8');
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}

export interface FetchProgramOptions {
  authorization?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}

const ScopeSchema = z.object({
  assetType: z.string().min(1).max(80),
  identifier: z.string().min(1).max(2000),
  eligibleForSubmission: z.boolean(),
  eligibleForBounty: z.boolean(),
  instruction: z.string().max(20_000).nullable(),
}).strict();

const ExclusionSchema = z.object({
  category: z.string().min(1).max(200),
  details: z.string().max(8000),
}).strict();

const RateSchema = z.object({
  requestsPerSecond: z.number().positive().max(10),
  published: z.string().max(300).nullable(),
}).strict();

export const RawProgramSchema = z.object({
  platform: z.literal('hackerone'),
  handle: z.string().regex(HANDLE),
  name: z.string().min(1).max(200),
  programUrl: z.string().url(),
  sourceUrl: z.string().url(),
  policyText: z.string().max(MAX_RESPONSE_BYTES),
  submissionState: z.string().min(1).max(40),
  openScope: z.boolean(),
  goldStandardSafeHarbor: z.boolean(),
  scopes: z.array(ScopeSchema).max(2000),
  exclusions: z.array(ExclusionSchema).max(500),
  rate: RateSchema,
}).strict();
export type RawProgram = z.infer<typeof RawProgramSchema>;

const RemoteProgram = z.object({
  data: z.object({
    type: z.literal('program'),
    attributes: z.object({
      handle: z.string().min(1).max(80),
      name: z.string().min(1).max(200),
      policy: z.string().max(MAX_RESPONSE_BYTES),
      submission_state: z.string().min(1).max(40),
      open_scope: z.boolean().nullable().optional(),
      gold_standard_safe_harbor: z.boolean().nullable().optional(),
    }),
  }),
});

const RemoteScope = z.object({
  type: z.literal('structured-scope'),
  attributes: z.object({
    asset_type: z.string().min(1).max(80),
    asset_identifier: z.string().min(1).max(2000),
    eligible_for_submission: z.boolean(),
    eligible_for_bounty: z.boolean().optional(),
    instruction: z.string().max(20_000).nullable().optional(),
  }),
});

const RemoteExclusion = z.object({
  type: z.literal('scope-exclusion'),
  attributes: z.object({
    category: z.string().min(1).max(200),
    details: z.string().max(8000).nullable().optional(),
  }),
});

const RemotePage = z.object({
  data: z.array(z.unknown()).max(100),
  links: z.object({ next: z.string().max(2000).nullable().optional() }).optional(),
});

export function hackerOneProgramUrls(handle: string): { program: string; scopes: string; exclusions: string } {
  if (!HANDLE.test(handle)) throw new Error('invalid_program_handle');
  const program = `https://${API_HOST}/v1/hackers/programs/${encodeURIComponent(handle)}`;
  return {
    program,
    scopes: `${program}/structured_scopes?page%5Bsize%5D=100`,
    exclusions: `${program}/scope_exclusions`,
  };
}

function pinnedUrl(raw: string, handle: string, kind: 'program' | 'scopes' | 'exclusions'): string {
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error('program_host_refused'); }
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const expected = {
    program: `/v1/hackers/programs/${handle}`,
    scopes: `/v1/hackers/programs/${handle}/structured_scopes`,
    exclusions: `/v1/hackers/programs/${handle}/scope_exclusions`,
  }[kind];
  if (url.protocol !== 'https:' || host !== API_HOST || url.port || url.username || url.password || url.hash || path !== expected) {
    throw new Error('program_host_refused');
  }
  return raw;
}

function timeoutOf(value: number | undefined): number {
  if (value === undefined) return 15_000;
  if (!Number.isInteger(value) || value < 1 || value > 60_000) throw new Error('invalid_timeout');
  return value;
}

function authorizationHeader(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (!/^[\x21-\x7E ]{1,500}$/.test(value)) throw new Error('invalid_authorization');
  return value;
}

function parseRemote<S extends z.ZodType>(schema: S, value: unknown): z.infer<S> {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new Error('program_response_invalid');
  return parsed.data;
}

// The strictest published per-second figure, never above the scope engine's cap of 10.
// A missing figure stays at 1. "per minute" is not read as permission to go faster.
export function rateRulesFromPolicy(policyText: string): { requestsPerSecond: number; published: string | null } {
  const text = policyText.replace(/\s+/g, ' ');
  const found: { value: number; phrase: string }[] = [];
  const pattern = /(\d+(?:\.\d+)?)\s*(?:requests?|reqs?)\s*(?:per|\/)\s*seconds?|\b(\d+(?:\.\d+)?)\s*rps\b/gi;
  for (const match of text.matchAll(pattern)) {
    const value = Number(match[1] ?? match[2]);
    if (!Number.isFinite(value) || value <= 0 || value > 10_000) continue;
    found.push({ value, phrase: match[0].slice(0, 300) });
  }
  if (!found.length) return { requestsPerSecond: 1, published: null };
  const strictest = found.reduce((best, item) => item.value < best.value ? item : best);
  return { requestsPerSecond: Math.min(strictest.value, 10), published: strictest.phrase };
}

async function getJson(fetchLike: FetchLike, url: string, handle: string, kind: 'program' | 'scopes' | 'exclusions', options: { authorization?: string; timeoutMs: number; signal?: AbortSignal }, total: { bytes: number }): Promise<unknown> {
  const pinned = pinnedUrl(url, handle, kind);
  const headers: Record<string, string> = { accept: 'application/json', 'user-agent': 'anteater-program-intake' };
  if (options.authorization) headers.authorization = options.authorization;
  const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(options.timeoutMs)]) : AbortSignal.timeout(options.timeoutMs);
  const response = await fetchLike(pinned, { method: 'GET', signal, redirect: 'error', headers });
  if (!response.ok) throw new Error(`program_http_${response.status}`);
  const text = await readIntakeText(response, MAX_RESPONSE_BYTES);
  const size = Buffer.byteLength(text);
  if (size > MAX_RESPONSE_BYTES) throw new Error('program_response_too_large');
  total.bytes += size;
  if (total.bytes > MAX_TOTAL_BYTES) throw new Error('program_response_too_large');
  try { return JSON.parse(text) as unknown; } catch { throw new Error('program_response_invalid'); }
}

async function readList<S extends z.ZodType>(fetchLike: FetchLike, firstUrl: string, handle: string, kind: 'scopes' | 'exclusions', options: { authorization?: string; timeoutMs: number; signal?: AbortSignal }, total: { bytes: number }, item: S): Promise<Array<z.infer<S>>> {
  const items: Array<z.infer<S>> = [];
  const seen = new Set<string>();
  let url: string | null = firstUrl;
  for (let page = 0; page < MAX_PAGES && url; page += 1) {
    if (seen.has(url)) throw new Error('program_scope_incomplete');
    seen.add(url);
    const body: z.infer<typeof RemotePage> = parseRemote(RemotePage, await getJson(fetchLike, url, handle, kind, options, total));
    items.push(...body.data.map(entry => parseRemote(item, entry)));
    const next = body.links?.next;
    if (next === undefined || next === null || next === '') url = null;
    else url = next;
  }
  if (url) throw new Error('program_scope_incomplete');
  return items;
}

export async function fetchProgram(handle: string, fetchLike: FetchLike = fetch as unknown as FetchLike, options: FetchProgramOptions = {}): Promise<RawProgram> {
  if (!HANDLE.test(handle)) throw new Error('invalid_program_handle');
  const urls = hackerOneProgramUrls(handle);
  const call = {
    authorization: authorizationHeader(options.authorization),
    timeoutMs: timeoutOf(options.timeoutMs),
    signal: options.signal,
  };
  const total = { bytes: 0 };
  const program = parseRemote(RemoteProgram, await getJson(fetchLike, urls.program, handle, 'program', call, total));
  if (program.data.attributes.handle !== handle) throw new Error('program_handle_mismatch');
  const scopes = await readList(fetchLike, urls.scopes, handle, 'scopes', call, total, RemoteScope);
  const exclusions = await readList(fetchLike, urls.exclusions, handle, 'exclusions', call, total, RemoteExclusion);
  return RawProgramSchema.parse({
    platform: 'hackerone',
    handle,
    name: program.data.attributes.name,
    programUrl: `https://hackerone.com/${handle}`,
    sourceUrl: urls.program,
    policyText: program.data.attributes.policy,
    submissionState: program.data.attributes.submission_state,
    openScope: program.data.attributes.open_scope === true,
    goldStandardSafeHarbor: program.data.attributes.gold_standard_safe_harbor === true,
    scopes: scopes.map(scope => ({
      assetType: scope.attributes.asset_type,
      identifier: scope.attributes.asset_identifier,
      eligibleForSubmission: scope.attributes.eligible_for_submission,
      eligibleForBounty: scope.attributes.eligible_for_bounty ?? false,
      instruction: scope.attributes.instruction ?? null,
    })),
    exclusions: exclusions.map(exclusion => ({
      category: exclusion.attributes.category,
      details: exclusion.attributes.details ?? '',
    })),
    rate: rateRulesFromPolicy(program.data.attributes.policy),
  });
}
