import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { parseCsv, type Row } from './posture-scan.js';

// Review queue for one explicitly named public program at a time.
//
// A dump record is not permission to scan. This file stores the program, its
// in-scope assets, and its exclusions. reviewed stays false until an operator
// marks one exact host. Promotion writes only those hosts to targets.csv as
// passive rows. Wildcards are never expanded. The inbox is JSON, so
// posture:scan rejects it (that runner requires a url column).
//
// Refresh updates programs already in the inbox. It does not add the rest of
// the dump and it does not write targets.csv.
//
// usage:
//   tsx scripts/bounty-inbox.ts fetch <platform> <handle>
//   tsx scripts/bounty-inbox.ts refresh
//   tsx scripts/bounty-inbox.ts review <platform> <handle> <asset> [--revoke]
//   tsx scripts/bounty-inbox.ts promote [--csv=targets.csv]
//   tsx scripts/bounty-inbox.ts list

const DUMP_HOST = 'raw.githubusercontent.com';
const DUMP_PREFIX = '/arkadiyt/bounty-targets-data/master/data/';
const MAX_BYTES = 40_000_000;
const MAX_PROGRAMS = 25;
const MAX_ASSETS = 500;
const INSTRUCTION_LIMIT = 400;
const HOST = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const CLOSED = new Set(['paused', 'disabled', 'closed', 'suspended', 'closing', 'archived', 'sandboxed', 'soft_launched', 'missing']);

export const PLATFORMS = ['hackerone', 'bugcrowd', 'intigriti', 'yeswehack', 'federacy'] as const;
export type Platform = (typeof PLATFORMS)[number];

const DUMP_FILES: Record<Platform, string> = {
  hackerone: 'hackerone_data.json',
  bugcrowd: 'bugcrowd_data.json',
  intigriti: 'intigriti_data.json',
  yeswehack: 'yeswehack_data.json',
  federacy: 'federacy_data.json',
};

export interface InboxAsset {
  identifier: string;
  type: string;
  inScope: boolean;
  maxSeverity: string | null;
  instruction: string;
  reviewed: boolean;
}
export interface InboxProgram {
  platform: Platform;
  handle: string;
  name: string;
  programUrl: string;
  submissionState: string;
  open: boolean;
  offersBounties: boolean | null;
  sourceUrl: string;
  fetchedAt: string;
  assets: InboxAsset[];
}
export interface InboxFile { schema: 1; programs: InboxProgram[] }

export function dumpUrl(platform: Platform): string {
  return `https://${DUMP_HOST}${DUMP_PREFIX}${DUMP_FILES[platform]}`;
}

export function assertDumpUrl(value: string): void {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.hostname !== DUMP_HOST || !url.pathname.startsWith(DUMP_PREFIX) || url.username || url.password || url.search || url.hash) {
    throw new Error('unexpected_dump_url');
  }
}

function isPlatform(value: string): value is Platform {
  return (PLATFORMS as readonly string[]).includes(value);
}

function text(value: unknown, limit: number): string {
  if (typeof value !== 'string') return '';
  return value.replace(/[\u0000-\u001f]+/g, ' ').trim().slice(0, limit);
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function field(raw: Record<string, unknown>, key: string): string {
  return text(raw[key], 300);
}

export function programsFromDump(data: unknown): unknown[] {
  if (Array.isArray(data)) return data;
  const body = record(data);
  if (body && Array.isArray(body.programs)) return body.programs;
  throw new Error('unrecognized_dump');
}

export function programHandle(platform: Platform, raw: Record<string, unknown>): string | null {
  if (platform === 'hackerone' || platform === 'intigriti') return field(raw, 'handle') || null;
  if (platform === 'yeswehack') return field(raw, 'id') || null;
  const url = field(raw, 'url');
  if (url) {
    try {
      const slug = new URL(url).pathname.split('/').filter(Boolean).pop();
      if (slug) return decodeURIComponent(slug).toLowerCase();
    } catch { /* fall through to handle or id */ }
  }
  return (field(raw, 'handle') || field(raw, 'id') || '').toLowerCase() || null;
}

function assetOf(entry: unknown, inScope: boolean): InboxAsset | null {
  const raw = record(entry);
  if (!raw) return null;
  const identifier = field(raw, 'asset_identifier') || field(raw, 'endpoint') || field(raw, 'target') || field(raw, 'uri') || field(raw, 'name');
  if (!identifier) return null;
  const severity = field(raw, 'max_severity') || field(raw, 'impact');
  return {
    identifier,
    type: (field(raw, 'asset_type') || field(raw, 'type') || 'unknown').toLowerCase(),
    inScope,
    maxSeverity: severity || null,
    instruction: text(raw.instruction ?? raw.description, INSTRUCTION_LIMIT),
    reviewed: false,
  };
}

function readSide(value: unknown, inScope: boolean): InboxAsset[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap(entry => {
    const asset = assetOf(entry, inScope);
    return asset ? [asset] : [];
  });
}

export function isOpenProgram(raw: Record<string, unknown>, state: string): boolean {
  if (CLOSED.has(state.toLowerCase())) return false;
  if (raw.disabled === true || raw.public === false) return false;
  const confidentiality = field(raw, 'confidentiality_level');
  if (confidentiality && confidentiality !== 'public') return false;
  return true;
}

export function normalizeProgram(platform: Platform, value: unknown, fetchedAt: string): InboxProgram {
  const raw = record(value);
  if (!raw) throw new Error('unrecognized_program');
  const handle = programHandle(platform, raw);
  if (!handle) throw new Error('program_handle_missing');
  const targets = record(raw.targets);
  if (!targets) throw new Error('unrecognized_program');
  const assets = [
    ...readSide(targets.in_scope ?? targets.inScope, true),
    ...readSide(targets.out_of_scope ?? targets.outOfScope, false),
  ];
  if (assets.length > MAX_ASSETS) throw new Error('program_too_large');
  const submissionState = field(raw, 'submission_state') || field(raw, 'status') || (raw.disabled === true ? 'disabled' : 'unknown');
  const offers = raw.offers_bounties;
  return {
    platform,
    handle: handle.toLowerCase(),
    name: field(raw, 'name') || handle,
    programUrl: field(raw, 'url'),
    submissionState,
    open: isOpenProgram(raw, submissionState),
    offersBounties: typeof offers === 'boolean' ? offers : null,
    sourceUrl: dumpUrl(platform),
    fetchedAt,
    assets,
  };
}

export function findRawProgram(platform: Platform, data: unknown, handle: string): unknown {
  const wanted = handle.trim().toLowerCase();
  const found = programsFromDump(data).find(entry => {
    const raw = record(entry);
    return raw !== null && programHandle(platform, raw)?.toLowerCase() === wanted;
  });
  if (!found) throw new Error(`program_not_found:${platform}/${wanted}`);
  return found;
}

function exclusionHost(identifier: string): { host: string; wildcard: boolean } | null {
  const trimmed = identifier.trim().toLowerCase();
  if (!trimmed) return null;
  const wildcard = trimmed.startsWith('*.') || trimmed.includes('://*.');
  const withoutWildcard = trimmed.replace(/^\*\./, '').replace('://*.', '://');
  try {
    const url = new URL(withoutWildcard.includes('://') ? withoutWildcard : `https://${withoutWildcard}`);
    const host = url.hostname.replace(/\.$/, '').replace(/^\*\./, '');
    return host ? { host, wildcard: wildcard || url.hostname.startsWith('*.') } : null;
  } catch {
    return null;
  }
}

export function isExcluded(hostname: string, exclusions: readonly string[]): boolean {
  const host = hostname.toLowerCase();
  return exclusions.some(rule => {
    const parsed = exclusionHost(rule);
    if (!parsed) return false;
    if (parsed.wildcard) return host === parsed.host || host.endsWith(`.${parsed.host}`);
    return host === parsed.host;
  });
}

export function promotableUrl(identifier: string, exclusions: readonly string[]): string | null {
  const trimmed = identifier.trim();
  if (!trimmed || /[\s*]/.test(trimmed)) return null;
  let url: URL;
  try { url = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`); }
  catch { return null; }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password || url.search || url.hash) return null;
  if (url.pathname !== '/' && url.pathname !== '') return null;
  const host = url.hostname.replace(/\.$/, '').toLowerCase();
  if (!HOST.test(host) || host.includes('xn--') || isExcluded(host, exclusions)) return null;
  url.hostname = host;
  url.hash = '';
  return url.href;
}

export function exclusionIdentifiers(program: InboxProgram): string[] {
  return program.assets.filter(asset => !asset.inScope).map(asset => asset.identifier);
}

export function mergeProgram(previous: InboxProgram | undefined, incoming: InboxProgram): InboxProgram {
  const reviewed = new Set((previous?.assets ?? []).filter(asset => asset.reviewed && asset.inScope).map(asset => asset.identifier.trim().toLowerCase()));
  return {
    ...incoming,
    assets: incoming.assets.map(asset => ({
      ...asset,
      reviewed: asset.inScope && reviewed.has(asset.identifier.trim().toLowerCase()) && promotableUrl(asset.identifier, exclusionIdentifiers(incoming)) !== null,
    })),
  };
}

export function reviewAsset(program: InboxProgram, identifier: string, reviewed: boolean): InboxProgram {
  const wanted = identifier.trim().toLowerCase();
  const asset = program.assets.find(item => item.identifier.trim().toLowerCase() === wanted);
  if (!asset) throw new Error('asset_not_in_program');
  if (!asset.inScope) throw new Error('asset_out_of_scope');
  if (promotableUrl(asset.identifier, exclusionIdentifiers(program)) === null) throw new Error('asset_not_promotable');
  return {
    ...program,
    assets: program.assets.map(item => item === asset ? { ...item, reviewed } : item),
  };
}

export function promotionRows(programs: readonly InboxProgram[]): Row[] {
  const rows: Row[] = [];
  const seen = new Set<string>();
  for (const program of programs) {
    if (!program.open) continue;
    const exclusions = exclusionIdentifiers(program);
    for (const asset of program.assets) {
      if (!asset.inScope || !asset.reviewed) continue;
      const url = promotableUrl(asset.identifier, exclusions);
      if (!url || seen.has(url)) continue;
      seen.add(url);
      rows.push({ url, mode: 'passive', notes: `reviewed ${program.platform}/${program.handle}; passive posture only` });
    }
  }
  return rows;
}

function csvField(value: string): string {
  return /[",\n\r]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

export function mergeScanCsv(existing: string | null, rows: readonly Row[]): string {
  const current = existing ? parseCsv(existing) : [];
  const present = new Set(current.map(row => {
    try { return new URL(row.url.includes('://') ? row.url : `https://${row.url}`).href; }
    catch { return row.url; }
  }));
  const added = rows.filter(row => !present.has(row.url));
  const lines = ['url,mode,notes', ...current.map(row => [row.url, row.mode, row.notes].map(csvField).join(',')), ...added.map(row => [row.url, row.mode, row.notes].map(csvField).join(','))];
  return `${lines.join('\n')}\n`;
}

export function emptyInbox(): InboxFile {
  return { schema: 1, programs: [] };
}

export function upsertProgram(inbox: InboxFile, program: InboxProgram): InboxFile {
  const without = inbox.programs.filter(item => !(item.platform === program.platform && item.handle === program.handle));
  if (!inbox.programs.some(item => item.platform === program.platform && item.handle === program.handle) && without.length >= MAX_PROGRAMS) {
    throw new Error('inbox_full');
  }
  return { schema: 1, programs: [...without, program].sort((a, b) => `${a.platform}/${a.handle}`.localeCompare(`${b.platform}/${b.handle}`)) };
}

export function refreshInbox(inbox: InboxFile, dumps: ReadonlyMap<Platform, unknown>, fetchedAt: string): InboxFile {
  return {
    schema: 1,
    programs: inbox.programs.map(program => {
      const dump = dumps.get(program.platform);
      if (!dump) return program;
      try {
        return mergeProgram(program, normalizeProgram(program.platform, findRawProgram(program.platform, dump, program.handle), fetchedAt));
      } catch (error) {
        if (error instanceof Error && error.message.startsWith('program_not_found:')) {
          return { ...program, submissionState: 'missing', open: false, fetchedAt, assets: program.assets.map(asset => ({ ...asset, reviewed: false })) };
        }
        throw error;
      }
    }),
  };
}

async function readInbox(path: string): Promise<InboxFile> {
  try {
    const parsed = JSON.parse(await readFile(path, 'utf8')) as Partial<InboxFile>;
    if (parsed.schema !== 1 || !Array.isArray(parsed.programs)) throw new Error('invalid_inbox');
    return { schema: 1, programs: parsed.programs };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return emptyInbox();
    throw error;
  }
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${randomUUID()}.tmp`;
  await writeFile(temporary, JSON.stringify(value, null, 2), { flag: 'wx' });
  await rename(temporary, path);
}

async function loadDump(platform: Platform): Promise<unknown> {
  const url = dumpUrl(platform);
  assertDumpUrl(url);
  const response = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(60_000), headers: { 'user-agent': 'anteater-bounty-inbox' } });
  assertDumpUrl(response.url);
  if (!response.ok) throw new Error('dump_unavailable');
  const text = await response.text();
  if (text.length > MAX_BYTES) throw new Error('dump_too_large');
  return JSON.parse(text) as unknown;
}

function flagValue(flags: Map<string, string>, name: string, fallback: string): string {
  return flags.get(name) || fallback;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const args = process.argv.slice(2);
  const flags = new Map(args.filter(arg => arg.startsWith('--')).map(arg => {
    const split = arg.indexOf('=');
    return split === -1 ? [arg.slice(2), ''] as const : [arg.slice(2, split), arg.slice(split + 1)] as const;
  }));
  const positionals = args.filter(arg => !arg.startsWith('--'));
  const command = positionals[0] ?? '';
  const inboxPath = resolve(flagValue(flags, 'inbox', 'bounty-inbox.json'));
  const csvPath = resolve(flagValue(flags, 'csv', 'targets.csv'));
  try {
    if (inboxPath === csvPath) throw new Error('inbox_is_scan_csv');
    if (command === 'fetch') {
      const platform = positionals[1] ?? '';
      const handle = positionals[2] ?? '';
      if (!isPlatform(platform) || !handle) throw new Error('usage: fetch <hackerone|bugcrowd|intigriti|yeswehack|federacy> <handle>');
      const inbox = await readInbox(inboxPath);
      const incoming = normalizeProgram(platform, findRawProgram(platform, await loadDump(platform), handle), new Date().toISOString());
      const previous = inbox.programs.find(program => program.platform === platform && program.handle === incoming.handle);
      const next = upsertProgram(inbox, mergeProgram(previous, incoming));
      await writeJson(inboxPath, next);
      const stored = next.programs.find(program => program.platform === incoming.platform && program.handle === incoming.handle)!;
      console.log(`Stored ${stored.platform}/${stored.handle} (${stored.assets.length} assets, open=${stored.open}). Nothing was added to the scan CSV.`);
    } else if (command === 'refresh') {
      const inbox = await readInbox(inboxPath);
      const platforms = [...new Set(inbox.programs.map(program => program.platform))];
      const dumps = new Map<Platform, unknown>();
      for (const platform of platforms) dumps.set(platform, await loadDump(platform));
      const next = refreshInbox(inbox, dumps, new Date().toISOString());
      await writeJson(inboxPath, next);
      console.log(`Refreshed ${next.programs.length} inbox program(s). The scan CSV was not changed.`);
    } else if (command === 'review') {
      const platform = positionals[1] ?? '';
      const handle = (positionals[2] ?? '').toLowerCase();
      const asset = positionals[3] ?? '';
      if (!isPlatform(platform) || !handle || !asset) throw new Error('usage: review <platform> <handle> <asset> [--revoke]');
      const inbox = await readInbox(inboxPath);
      const program = inbox.programs.find(item => item.platform === platform && item.handle === handle);
      if (!program) throw new Error('program_not_in_inbox');
      const next = upsertProgram(inbox, reviewAsset(program, asset, !flags.has('revoke')));
      await writeJson(inboxPath, next);
      console.log(`${flags.has('revoke') ? 'Cleared' : 'Marked'} ${platform}/${handle} ${asset}. Promotion is a separate command.`);
    } else if (command === 'promote') {
      const inbox = await readInbox(inboxPath);
      const rows = promotionRows(inbox.programs);
      if (!rows.length) throw new Error('nothing_reviewed');
      let existing: string | null = null;
      try { existing = await readFile(csvPath, 'utf8'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      const before = existing ? parseCsv(existing).length : 0;
      const rendered = mergeScanCsv(existing, rows);
      const added = parseCsv(rendered).length - before;
      await mkdir(dirname(csvPath), { recursive: true });
      const temporary = `${csvPath}.${randomUUID()}.tmp`;
      await writeFile(temporary, rendered, { flag: 'wx' });
      await rename(temporary, csvPath);
      console.log(`Added ${added} new passive row(s) to ${csvPath}. ${rows.length} reviewed host(s) were eligible.`);
    } else if (command === 'list') {
      const inbox = await readInbox(inboxPath);
      if (!inbox.programs.length) console.log('Inbox is empty. Fetch one program by handle.');
      for (const program of inbox.programs) {
        const promotable = program.assets.filter(asset => asset.inScope && promotableUrl(asset.identifier, exclusionIdentifiers(program))).length;
        const reviewed = program.assets.filter(asset => asset.reviewed).length;
        console.log(`${program.platform}/${program.handle}  open=${program.open}  assets=${program.assets.length}  promotable=${promotable}  reviewed=${reviewed}`);
        for (const asset of program.assets) {
          const state = !asset.inScope ? 'excluded' : promotableUrl(asset.identifier, exclusionIdentifiers(program)) === null ? 'held' : asset.reviewed ? 'reviewed' : 'unreviewed';
          console.log(`  [${state}] ${asset.identifier}  ${asset.type}${asset.maxSeverity ? `  max=${asset.maxSeverity}` : ''}`);
        }
      }
    } else {
      console.log('usage: bounty-inbox.ts <fetch|refresh|review|promote|list>');
      process.exitCode = 1;
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'inbox_failed');
    process.exitCode = 1;
  }
}
