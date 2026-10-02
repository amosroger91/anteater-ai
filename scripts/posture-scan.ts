import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, writeFile, mkdir, readdir, stat, unlink } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import { canonicalTarget, checkTarget, worstSeverity, type Finding, type Severity, type TargetResult } from './posture-check.js';
import { authorize, PolicySchema } from '../packages/scope-engine/index.js';
import { loadConfig } from '../packages/shared/config.js';

// CSV batch runner. Each row is one URL, not a domain: a bare host is checked as
// https://that-host/ only. The note is stored with the result.
//
// mode=passive runs the read-only check.
// mode=aggressive also runs a pinned nuclei binary through an operator-owned egress
// proxy with redirects disabled. Every row must be authorized by the supplied reviewed policy JSON.
//
// usage: tsx scripts/posture-scan.ts [targets.csv] --policy=policy.json [--out=posture-results]
//        [--confirm-aggressive] [--allow-private] [--egress-proxy=http://127.0.0.1:8080] [--rate=20]

const exec = promisify(execFile);
const DEFAULT_TAGS = 'ssl,misconfig,exposure,tech';
const DEFAULT_EXCLUDE = 'dos,intrusive,fuzz';
const DENIED_TAGS = new Set(['dos', 'intrusive', 'fuzz', 'brute', 'dos', 'headless']);
const SAFE_TAGS = new Set(['ssl', 'misconfig', 'exposure', 'tech']);
const TAG_LIST = /^[a-z0-9]+(?:-[a-z0-9]+)*(?:,[a-z0-9]+(?:-[a-z0-9]+)*)*$/;

type Mode = 'passive' | 'aggressive';
export interface Row { url: string; mode: Mode; notes: string }
export interface Scanned extends TargetResult {
  mode: Mode; executed: boolean; notes: string;
  scanner?: { name: string; version: string; tags: string; excludeTags: string; rate: number; templateDigest?: string };
}
interface ExecFailure extends Error { code?: string; stdout?: string | Buffer; stderr?: string | Buffer }

export function parseCsvRecords(text: string): string[][] {
  const src = text.replace(/^\uFEFF/, '');
  const records: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < src.length; i++) {
    const char = src[i]!;
    if (quoted) {
      if (char === '"') {
        if (src[i + 1] === '"') { field += '"'; i += 1; }
        else quoted = false;
      } else field += char;
    } else if (char === '"') quoted = true;
    else if (char === ',') { row.push(field); field = ''; }
    else if (char === '\n') { row.push(field); records.push(row); row = []; field = ''; }
    else if (char !== '\r') field += char;
  }
  if (quoted) throw new Error('csv_unterminated_quote');
  if (field.length || row.length) { row.push(field); records.push(row); }
  return records.filter(record => record.some(cell => cell.trim()));
}

export function parseCsv(text: string): Row[] {
  const records = parseCsvRecords(text).filter(record => !(record[0] ?? '').trim().startsWith('#'));
  if (!records.length) return [];
  const header = records[0]!.map(cell => cell.trim().toLowerCase());
  const column = (name: string) => header.indexOf(name);
  const urlColumn = column('url');
  const modeColumn = column('mode');
  const notesColumn = column('notes');
  if (urlColumn === -1) throw new Error('csv_missing_url_column (expected header: url,mode,notes)');
  const rows: Row[] = [];
  const modes = new Map<string, Mode>();
  for (const record of records.slice(1)) {
    const url = (record[urlColumn] ?? '').trim();
    if (!url) continue;
    const rawMode = (modeColumn === -1 ? '' : record[modeColumn] ?? '').trim().toLowerCase();
    if (rawMode && rawMode !== 'passive' && rawMode !== 'aggressive') throw new Error(`invalid_mode:${rawMode} (use passive|aggressive)`);
    const mode = (rawMode || 'passive') as Mode;
    const canon = canonicalTarget(url);
    const key = 'href' in canon ? canon.href : url;
    const prior = modes.get(key);
    if (prior && prior !== mode) throw new Error(`duplicate_target_mode_conflict:${key}`);
    if (prior) continue;
    modes.set(key, mode);
    rows.push({ url, mode, notes: notesColumn === -1 ? '' : (record[notesColumn] ?? '').trim() });
  }
  return rows;
}

export function parseRate(raw: string): number {
  if (!/^[1-9]\d*$/.test(raw)) throw new Error('invalid_rate (use an integer from 1 to 150)');
  const rate = Number(raw);
  if (rate > 150) throw new Error('invalid_rate (use an integer from 1 to 150)');
  return rate;
}

export function parseTagList(raw: string, label: string): string {
  if (!TAG_LIST.test(raw)) throw new Error(`invalid_${label}`);
  const values = raw.split(',');
  if (label === 'tags' && (values.some(value => DENIED_TAGS.has(value)) || values.some(value => !SAFE_TAGS.has(value)))) throw new Error('unsafe_tags');
  return raw;
}

export function pinnedNucleiTarget(url: string, ip: string): { target: string; hostname: string } {
  const parsed = new URL(url);
  const hostname = parsed.hostname;
  parsed.hostname = ip;
  return { target: parsed.toString(), hostname };
}

export function nucleiArgs(url: string, tags: string, excludeTags: string, rate: number, proxy?: string, templates?: string, pin?: { ip: string; hostname: string }): string[] {
  const args = ['-u', url, '-jsonl', '-silent', '-disable-update-check', '-no-interactsh', '-tags', tags, '-exclude-tags', excludeTags, '-rate-limit', String(rate), '-timeout', '10'];
  if (pin) args.push('-sni', pin.hostname, '-H', `Host: ${pin.hostname}`);
  if (proxy) args.push('-proxy', proxy);
  if (templates) args.push('-templates', templates);
  return args;
}

const NUCLEI_SEV: Record<string, Severity> = { info: 'info', low: 'low', medium: 'medium', high: 'high', critical: 'critical' };
function safeDetail(value: string): string {
  return value.replace(/[\r\n]/g, ' ').replace(/([?&][^=&#\s]+)=([^&#\s]*)/g, '$1=REDACTED').slice(0, 400);
}

export function aggressiveOutcome(stdout: string, stderr: string, target: string, code?: string): { findings: Finding[]; failed: boolean } {
  if (code === 'ENOENT') return { findings: [{ code: 'scanner_error', severity: 'info', detail: 'nuclei_not_installed' }], failed: true };
  const recovered = findingsFromNuclei(stdout, target);
  if (recovered.length) return { findings: recovered, failed: false };
  const line = stderr.trim().split('\n').filter(Boolean)[0] ?? 'nuclei_failed';
  return { findings: [{ code: 'scanner_error', severity: 'info', detail: line.slice(0, 200) }], failed: true };
}

export function findingsFromNuclei(stdout: string, target: string): Finding[] {
  const findings: Finding[] = [];
  for (const line of stdout.split('\n').filter(Boolean)) {
    try {
      const event = JSON.parse(line) as { 'template-id'?: string; info?: { severity?: string }; 'matched-at'?: string };
      const detail = safeDetail(String(event['matched-at'] ?? target));
      findings.push({ code: event['template-id'] ?? 'nuclei', severity: NUCLEI_SEV[event.info?.severity ?? 'info'] ?? 'info', detail });
    } catch { /* a banner or progress line is not a finding */ }
  }
  return findings;
}

function outputText(value: string | Buffer | undefined): string {
  if (!value) return '';
  return typeof value === 'string' ? value : value.toString('utf8');
}

export interface FindingDiff { added: Finding[]; resolved: Finding[]; changed: Array<{ code: string; from: string; to: string }> }

export function diffFindings(previous: Finding[] | undefined, current: Finding[]): FindingDiff {
  if (!previous) return { added: [], resolved: [], changed: [] };
  const group = (items: Finding[]) => {
    const map = new Map<string, Finding[]>();
    for (const item of items) {
      const list = map.get(item.code);
      if (list) list.push(item);
      else map.set(item.code, [item]);
    }
    for (const list of map.values()) list.sort((a, b) => `${a.severity}\t${a.detail}`.localeCompare(`${b.severity}\t${b.detail}`));
    return map;
  };
  const before = group(previous);
  const after = group(current);
  const added: Finding[] = [];
  const resolved: Finding[] = [];
  const changed: FindingDiff['changed'] = [];
  for (const code of new Set([...before.keys(), ...after.keys()])) {
    const left = before.get(code) ?? [];
    const right = after.get(code) ?? [];
    const pairs = Math.min(left.length, right.length);
    for (let i = 0; i < pairs; i++) {
      const from = left[i]!;
      const to = right[i]!;
      if (from.severity !== to.severity || from.detail !== to.detail) changed.push({ code, from: `${from.severity}: ${from.detail}`, to: `${to.severity}: ${to.detail}` });
    }
    resolved.push(...left.slice(pairs));
    added.push(...right.slice(pairs));
  }
  return { added, resolved, changed };
}

export function baselineKey(target: string): string {
  const canon = canonicalTarget(target);
  return 'href' in canon ? canon.href : target;
}

export function nextBaseline(previous: Scanned[], current: Scanned[]): Scanned[] {
  const wanted = new Set(current.map(row => baselineKey(row.target)));
  const map = new Map<string, Scanned>();
  for (const row of previous) {
    if (row.executed === false) continue;
    const key = baselineKey(row.target);
    if (wanted.has(key)) map.set(key, row);
  }
  for (const row of current) {
    if (!row.executed) continue;
    map.set(baselineKey(row.target), row);
  }
  return [...map.values()].sort((a, b) => baselineKey(a.target).localeCompare(baselineKey(b.target)));
}

async function nucleiVersion(): Promise<string> {
  const binary = process.env.NUCLEI_BIN;
  if (!binary || !isAbsolute(binary)) return 'unconfigured';
  try {
    const { stdout, stderr } = await exec(binary, ['-version', '-disable-update-check'], { encoding: 'utf8', timeout: 15000, windowsHide: true });
    return `${stdout}${stderr}`.trim().split('\n').slice(0, 4).join(' | ') || 'unknown';
  } catch (error) {
    const failed = error as ExecFailure;
    const text = `${outputText(failed.stdout)}${outputText(failed.stderr)}`.trim();
    return text.split('\n').slice(0, 4).join(' | ') || 'unknown';
  }
}

async function runAggressive(url: string, ip: string, tags: string, excludeTags: string, rate: number, proxy: string, templates: string): Promise<{ findings: Finding[]; version: string; failed: boolean }> {
  const binary = process.env.NUCLEI_BIN;
  if (!binary || !isAbsolute(binary)) return { findings: [{ code: 'scanner_error', severity: 'info', detail: 'nuclei_binary_must_be_absolute_NUCLEI_BIN' }], version: 'unconfigured', failed: true };
  const pin = pinnedNucleiTarget(url, ip);
  const args = nucleiArgs(pin.target, tags, excludeTags, rate, proxy, templates, { ip, hostname: pin.hostname });
  try {
    const { stdout } = await exec(binary, args, { encoding: 'utf8', timeout: 20 * 60_000, maxBuffer: 32 * 1024 * 1024, windowsHide: true });
    return { findings: findingsFromNuclei(stdout, url), version: await nucleiVersion(), failed: false };
  } catch (error) {
    const failed = error as ExecFailure;
    const outcome = aggressiveOutcome(outputText(failed.stdout), outputText(failed.stderr) || failed.message, url, failed.code);
    return { ...outcome, version: outcome.failed ? (failed.code === 'ENOENT' ? 'not_installed' : 'unknown') : await nucleiVersion() };
  }
}

async function loadPrevious(path: string): Promise<Scanned[]> {
  try {
    const parsed: unknown = JSON.parse(await readFile(path, 'utf8'));
    if (!Array.isArray(parsed)) throw new Error('baseline_not_array');
    return parsed as Scanned[];
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw new Error('baseline_corrupt_or_unreadable');
  }
}

export function policyAllowsPosture(policy: unknown, target: string, config = loadConfig()): boolean {
  return authorize(policy, target, 'inspect_http_target', config).allowed;
}

async function pruneResults(outDir: string, retentionDays: number) {
  const cutoff = Date.now() - retentionDays * 86_400_000;
  for (const name of await readdir(outDir)) {
    if (!/^scan-.*\.json$/.test(name)) continue;
    const path = join(outDir, name);
    if ((await stat(path)).mtimeMs < cutoff) await unlink(path);
  }
}

function heldResult(row: Row, canon: { href: string; origin: string }): Scanned {
  return { target: canon.href, origin: canon.origin, ip: null, reachable: false, findings: [], checkedAt: new Date().toISOString(), mode: 'aggressive', executed: false, notes: row.notes };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const args = process.argv.slice(2);
  const flags = new Map(args.filter(arg => arg.startsWith('--')).map(arg => {
    const split = arg.indexOf('=');
    return split === -1 ? [arg.slice(2), ''] as const : [arg.slice(2, split), arg.slice(split + 1)] as const;
  }));
  const csvPath = args.find(arg => !arg.startsWith('--')) ?? 'targets.csv';
  const outDir = flags.get('out') || 'posture-results';
  const policyPath = flags.get('policy');
  const confirmAggressive = flags.has('confirm-aggressive');
  const allowPrivate = flags.has('allow-private');
  try {
    if (!policyPath) throw new Error('policy_required (use --policy=reviewed-policy.json)');
    const policy = PolicySchema.parse(JSON.parse(await readFile(resolve(policyPath), 'utf8')));
    const config = loadConfig();
    const tags = parseTagList(flags.get('tags') || DEFAULT_TAGS, 'tags');
    const requestedExclude = parseTagList(flags.get('exclude-tags') || DEFAULT_EXCLUDE, 'exclude_tags');
    const excludeTags = [...new Set([...DEFAULT_EXCLUDE.split(','), ...requestedExclude.split(',')])].join(',');
    const requestedRate = parseRate(flags.get('rate') || '20');
    const policyRate = Math.floor(policy.requestsPerSecond);
    if (confirmAggressive && policyRate < 1) throw new Error('policy_rate_too_low_for_scanner');
    const rate = Math.min(requestedRate, Math.max(1, policyRate));
    const proxy = flags.get('egress-proxy');
    const templates = process.env.NUCLEI_TEMPLATES;
    const templateDigest = process.env.NUCLEI_TEMPLATE_DIGEST;
    if (confirmAggressive && (!proxy || !/^https?:\/\/127\.0\.0\.1(?::\d+)?$/.test(proxy))) throw new Error('egress_proxy_required_on_loopback');
    if (confirmAggressive && (!templates || !isAbsolute(templates) || !templateDigest || !/^[a-f0-9]{40,128}$/i.test(templateDigest))) throw new Error('pinned_nuclei_templates_required');
    const rows = parseCsv(await readFile(csvPath, 'utf8'));
    if (!rows.length) throw new Error(`no targets in ${csvPath}`);
    const aggressive = rows.filter(row => row.mode === 'aggressive');
    console.log(`${rows.length} target(s): ${rows.length - aggressive.length} passive, ${aggressive.length} aggressive. Each row is one URL.`);
    if (aggressive.length && !confirmAggressive) console.log(`Aggressive rows are HELD. Re-run with --confirm-aggressive to execute them (tags=${tags}, exclude-tags=${excludeTags}, rate=${rate}).`);

    const results: Scanned[] = [];
    for (const row of rows) {
      const canon = canonicalTarget(row.url);
      if (!('href' in canon)) {
        results.push({ target: row.url, origin: row.url, ip: null, reachable: false, findings: [{ code: canon.error, severity: 'info', detail: canon.error }], checkedAt: new Date().toISOString(), mode: row.mode, executed: true, notes: row.notes });
      } else if (!authorize(policy, canon.href, 'inspect_http_target', config).allowed) {
        results.push({ target: canon.href, origin: canon.origin, ip: null, reachable: false, findings: [{ code: 'policy_denied', severity: 'info', detail: 'target is outside the reviewed policy or the kill switch is active' }], checkedAt: new Date().toISOString(), mode: row.mode, executed: false, notes: row.notes });
      } else if (row.mode === 'passive') {
        const checked = await checkTarget(canon.href, { allowPrivate });
        results.push({ ...checked, mode: 'passive', executed: true, notes: row.notes });
      } else if (confirmAggressive) {
        console.log(`  [aggressive] scanning ${canon.href} (nuclei tags=${tags}, same-host redirects, no interactsh, rate=${rate})...`);
        const checked = await checkTarget(canon.href, { allowPrivate });
        const active = checked.reachable
          ? await runAggressive(canon.href, checked.ip!, tags, excludeTags, rate, proxy!, templates!)
          : { findings: [{ code: 'scanner_not_run', severity: 'info' as const, detail: 'passive reachability check did not authorize scanner execution' }], version: 'not_run', failed: false };
        results.push({
          ...checked, findings: [...checked.findings, ...active.findings], reachable: checked.reachable,
          mode: 'aggressive', executed: true, notes: row.notes,
          scanner: { name: 'nuclei', version: active.version, tags, excludeTags, rate, templateDigest },
        });
      } else results.push(heldResult(row, canon));
      await sleep(1000);
    }

    const latest = join(outDir, 'latest.json');
    const previous = await loadPrevious(latest);
    const baseline = nextBaseline(previous, results);
    const previousByKey = new Map(previous.filter(row => row.executed !== false).map(row => [baselineKey(row.target), row]));
    await mkdir(outDir, { recursive: true });
    await pruneResults(outDir, Math.min(365, Math.max(1, Number(flags.get('retention-days') || '30'))));
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    await writeFile(join(outDir, `scan-${stamp}.json`), JSON.stringify(results, null, 2), { mode: 0o600 });
    await writeFile(latest, JSON.stringify(baseline, null, 2), { mode: 0o600 });

    console.log('\n=== Summary ===');
    let worst = 0;
    let scannerFailed = false;
    const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    for (const result of results) {
      if (!result.executed) { console.log(`\n${result.target}  — aggressive, HELD (not run)`); continue; }
      const severity = worstSeverity(result.findings);
      worst = Math.max(worst, rank[severity]);
      if (result.findings.some(finding => finding.code === 'scanner_error')) scannerFailed = true;
      const diff = diffFindings(previousByKey.get(baselineKey(result.target))?.findings, result.findings);
      console.log(`\n${result.target}  [${result.mode}]  worst=${severity}${result.findings.length ? '' : '  OK'}${result.notes ? `  — ${result.notes}` : ''}`);
      for (const finding of result.findings) console.log(`  [${finding.severity.toUpperCase()}] ${finding.code}: ${finding.detail}`);
      if (diff.added.length) console.log(`  NEW since last run: ${diff.added.map(finding => finding.code).join(', ')}`);
      if (diff.changed.length) console.log(`  CHANGED since last run: ${diff.changed.map(change => `${change.code} (${change.from} -> ${change.to})`).join('; ')}`);
      if (diff.resolved.length) console.log(`  resolved since last run: ${diff.resolved.map(finding => finding.code).join(', ')}`);
    }
    console.log(`\nSaved ${results.length} row(s) to scan-${stamp}.json. Baseline ${latest} has ${baseline.length} executed target(s).`);
    if (worst >= rank.high || scannerFailed) process.exitCode = 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'scan_failed');
    process.exitCode = 1;
  }
}
