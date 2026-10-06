import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { platform } from 'node:process';
import { z } from 'zod';
import { writeFile } from 'node:fs/promises';
import { installedModelDigest } from '../packages/llm/index.js';

// Local model advisor and installer for the analysis role.
//
// Posture (see docs/DETERMINISTIC_MODEL.md):
//  - Hugging Face output is UNTRUSTED DATA. This script surfaces candidates and the exact
//    command to fetch one; it never auto-pulls a model a live search selected.
//  - A model earns the analysis role by passing the schema + grounding + eval contract, not by
//    ranking high here. Popularity and recency are shown to inform a human, not to decide.
//  - State-changing actions (installing Ollama, pulling weights) print what they will run and
//    execute only with --confirm. Nothing is piped from the network into a shell.

const exec = promisify(execFile);
const HF = 'https://huggingface.co';
const NET_TIMEOUT = 15000;
const MAX_BODY = 4 * 1024 * 1024;

// Ollama model refs: library tags (`qwen3:4b`) or HF GGUF refs (`hf.co/owner/repo:Q4_K_M`).
const MODEL_REF = /^(?:hf\.co\/)?[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)?(?::[A-Za-z0-9._-]+)?$/i;
const HF_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._-]*$/;
// Preferred quantizations for a 4096-context classifier, best first. Q4_K_M mirrors the repo default.
const QUANTS = ['Q4_K_M', 'Q5_K_M', 'Q4_K_S', 'Q5_K_S', 'Q4_0', 'Q8_0', 'Q6_K', 'Q3_K_M'];

type Args = { command: string; positionals: string[]; flags: Map<string, string | true> };
function parseArgs(argv: string[]): Args {
  const [command = 'advise', ...rest] = argv;
  const positionals: string[] = [];
  const flags = new Map<string, string | true>();
  for (const token of rest) {
    if (token.startsWith('--')) {
      const eq = token.indexOf('=');
      if (eq === -1) flags.set(token.slice(2), true);
      else flags.set(token.slice(2, eq), token.slice(eq + 1));
    } else positionals.push(token);
  }
  return { command, positionals, flags };
}

async function hfGet(path: string, query: Record<string, string> = {}): Promise<unknown> {
  const url = new URL(path, HF);
  if (url.origin !== HF) throw new Error('refusing_non_huggingface_host');
  for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);
  const response = await fetch(url, {
    redirect: 'error',
    signal: AbortSignal.timeout(NET_TIMEOUT),
    headers: { accept: 'application/json', 'user-agent': 'anteater-model-advisor' },
  });
  if (!response.ok) throw new Error(`huggingface_http_${response.status}`);
  const text = await response.text();
  if (text.length > MAX_BODY) throw new Error('huggingface_response_too_large');
  return JSON.parse(text);
}

// --- GPU / VRAM detection -------------------------------------------------

interface Gpu { name: string; vramGb: number | undefined; source: string }

async function detectGpu(override: string | undefined): Promise<Gpu> {
  if (override !== undefined) {
    const gb = Number(override);
    if (!Number.isFinite(gb) || gb <= 0 || gb > 1024) throw new Error('invalid_vram_override');
    return { name: 'operator-specified', vramGb: gb, source: '--vram' };
  }
  try {
    const { stdout } = await exec('nvidia-smi',
      ['--query-gpu=name,memory.total', '--format=csv,noheader,nounits'],
      { timeout: 5000, windowsHide: true });
    const line = stdout.trim().split('\n')[0] ?? '';
    const [name, mib] = line.split(',').map(s => s.trim());
    const vramGb = mib && Number.isFinite(Number(mib)) ? Number(mib) / 1024 : undefined;
    return { name: name || 'NVIDIA GPU', vramGb, source: 'nvidia-smi' };
  } catch {
    return { name: 'unknown (no NVIDIA utility)', vramGb: undefined, source: 'none' };
  }
}

// Weights should leave room for the KV cache (small at ctx 4096) and runtime overhead.
function weightBudgetGb(vramGb: number | undefined): number | undefined {
  if (vramGb === undefined) return undefined;
  const usable = Math.max(0, vramGb - 1.5);
  return Math.round(usable * 0.8 * 10) / 10;
}

async function ollamaVersion(): Promise<string | undefined> {
  try {
    const { stdout } = await exec('ollama', ['--version'], { timeout: 5000, windowsHide: true });
    return stdout.trim().split('\n')[0];
  } catch { return undefined; }
}

// --- Hugging Face recommendation (read-only) ------------------------------

const ListItem = z.object({
  id: z.string().max(200),
  downloads: z.number().optional(),
  likes: z.number().optional(),
  lastModified: z.string().max(40).optional(),
  tags: z.array(z.string().max(120)).max(200).optional(),
}).passthrough();
const ListResponse = z.array(ListItem).max(200);

const TreeEntry = z.object({
  type: z.string().max(20),
  path: z.string().max(400),
  size: z.number().optional(),
  lfs: z.object({ size: z.number().optional() }).passthrough().optional(),
}).passthrough();
const TreeResponse = z.array(TreeEntry).max(5000);

interface Candidate {
  id: string; downloads: number; lastModified: string; license: string;
  quant: string; fileGb: number; fits: boolean | undefined; domain: 'security' | 'general';
}

function licenseOf(tags: string[] | undefined): string {
  const tag = (tags ?? []).find(t => t.startsWith('license:'));
  return tag ? tag.slice('license:'.length) : 'unknown';
}

async function pickQuant(id: string, budgetGb: number | undefined): Promise<{ quant: string; fileGb: number } | undefined> {
  let entries;
  try { entries = TreeResponse.parse(await hfGet(`/api/models/${id}/tree/main`, { recursive: 'true' })); }
  catch { return undefined; }
  const ggufs = entries
    .filter(e => e.type === 'file' && /\.gguf$/i.test(e.path)
      && !/-\d{5}-of-\d{5}/.test(e.path)      // sharded weight parts can't be pulled by a single tag
      && !/mmproj|projector|vision|tokeniz|lora/i.test(e.path))  // side files, not the model
    .map(e => ({ path: e.path, gb: (e.lfs?.size ?? e.size ?? 0) / 1e9 }))
    .filter(e => e.gb >= 0.2);               // below this is not a real weight file
  if (!ggufs.length) return undefined;
  // Only recommend a file whose name carries a known quant; otherwise the hf.co:<tag> ref is a guess. Prefer the best quant that fits.
  const named = QUANTS.flatMap(q => { const f = ggufs.find(x => x.path.toUpperCase().includes(q)); return f ? [{ quant: q, gb: f.gb }] : []; });
  if (!named.length) return undefined;
  const fitting = named.find(f => budgetGb === undefined || f.gb <= budgetGb) ?? named[0]!;
  return { quant: fitting.quant, fileGb: Math.round(fitting.gb * 10) / 10 };
}

async function query(search: string, domain: 'security' | 'general', limit: number, budgetGb: number | undefined): Promise<Candidate[]> {
  const list = ListResponse.parse(await hfGet('/api/models', {
    search, filter: 'gguf', sort: 'downloads', direction: '-1', limit: String(limit), full: 'true',
  }));
  const out: Candidate[] = [];
  for (const item of list) {
    if (!HF_ID.test(item.id)) continue;
    const quant = await pickQuant(item.id, budgetGb);
    if (!quant) continue;
    out.push({
      id: item.id, downloads: item.downloads ?? 0, lastModified: (item.lastModified ?? '').slice(0, 10),
      license: licenseOf(item.tags), quant: quant.quant, fileGb: quant.fileGb,
      fits: budgetGb === undefined ? undefined : quant.fileGb <= budgetGb, domain,
    });
  }
  return out;
}

async function recommend(budgetGb: number | undefined, limit: number, domain: 'all' | 'security' | 'general'): Promise<Candidate[]> {
  const batches: Promise<Candidate[]>[] = [];
  // General small instruct models are the reliable schema-fillers for the analysis role.
  if (domain !== 'security') batches.push(query('instruct', 'general', limit, budgetGb));
  // Security-domain and uncensored candidates: several searches, because these rank low on downloads.
  if (domain !== 'general') for (const term of ['cybersecurity', 'security', 'pentest', 'hacking', 'abliterated'])
    batches.push(query(term, 'security', limit, budgetGb));
  const seen = new Set<string>();
  const merged = (await Promise.all(batches)).flat().filter(c => (seen.has(c.id) ? false : seen.add(c.id)));
  return merged
    .sort((a, b) => Number(b.fits ?? true) - Number(a.fits ?? true) || b.downloads - a.downloads)
    .slice(0, domain === 'all' ? 14 : 18);
}

function printCandidates(candidates: Candidate[]) {
  if (!candidates.length) { console.log('  (no GGUF candidates returned)'); return; }
  for (const c of candidates) {
    const fit = c.fits === undefined ? '?' : c.fits ? 'fits' : 'TOO BIG';
    console.log(`  [${c.domain === 'security' ? 'sec' : 'gen'}] ${c.id}`);
    console.log(`        ${c.quant} ~${c.fileGb} GB (${fit}) · license ${c.license} · ${c.downloads.toLocaleString()} dl · updated ${c.lastModified || 'n/a'}`);
    console.log(`        review, then:  ollama pull hf.co/${c.id}:${c.quant}`);
  }
}

// --- State-changing actions (gated by --confirm) --------------------------

function installPlan(): { label: string; file: string; args: string[] } {
  if (platform === 'win32') return { label: 'winget install Ollama.Ollama', file: 'winget', args: ['install', '--id', 'Ollama.Ollama', '-e', '--accept-package-agreements', '--accept-source-agreements'] };
  if (platform === 'darwin') return { label: 'brew install ollama', file: 'brew', args: ['install', 'ollama'] };
  return { label: 'verified Ollama package required (remote shell installers are disabled)', file: '', args: [] };
}

async function run(file: string, args: string[]) {
  const child = execFile(file, args, { windowsHide: true, timeout: 20 * 60_000 });
  child.stdout?.pipe(process.stdout);
  child.stderr?.pipe(process.stderr);
  await new Promise<void>((resolve, reject) => {
    child.on('error', reject);
    child.on('exit', code => code === 0 ? resolve() : reject(new Error(`exit_${code}`)));
  });
}

// --- Commands -------------------------------------------------------------

const args = parseArgs(process.argv.slice(2));
const confirm = args.flags.get('confirm') === true;
const vram = typeof args.flags.get('vram') === 'string' ? (args.flags.get('vram') as string) : undefined;
const limit = Math.min(50, Math.max(5, Number(args.flags.get('limit') ?? 30) || 30));

try {
  if (args.command === 'detect') {
    const gpu = await detectGpu(vram);
    const version = await ollamaVersion();
    console.log(`GPU: ${gpu.name}${gpu.vramGb ? ` (${gpu.vramGb.toFixed(1)} GB VRAM, via ${gpu.source})` : ` (VRAM unknown — pass --vram=<GB>)`}`);
    console.log(`Weight budget at ctx 4096: ${weightBudgetGb(gpu.vramGb)?.toFixed(1) ?? 'unknown'} GB`);
    console.log(`Ollama: ${version ?? 'not installed (run: npm run ollama:install -- --confirm)'}`);

  } else if (args.command === 'recommend' || args.command === 'advise') {
    const gpu = await detectGpu(vram);
    const budget = weightBudgetGb(gpu.vramGb);
    const version = await ollamaVersion();
    console.log(`GPU: ${gpu.name}${gpu.vramGb ? ` (${gpu.vramGb.toFixed(1)} GB VRAM)` : ' (VRAM unknown — pass --vram=<GB> for fit filtering)'}`);
    console.log(`Weight budget at ctx 4096: ${budget?.toFixed(1) ?? 'unknown'} GB · Ollama: ${version ?? 'not installed'}\n`);
    const domainFlag = args.flags.get('domain');
    const domain = domainFlag === 'security' || domainFlag === 'general' ? domainFlag : 'all';
    console.log(`Hugging Face GGUF candidates [domain=${domain}] (UNTRUSTED suggestions — must pass the eval contract before use):`);
    printCandidates(await recommend(budget, limit, domain));
    console.log('\nThe repo default qwen3:4b (Q4_K_M, ~2.5 GB) is the proven baseline:  ollama pull qwen3:4b');
    console.log('A model is chosen by schema-valid rate + grounding + label accuracy at temperature 0, not by rank here.');

  } else if (args.command === 'install-ollama') {
    if (await ollamaVersion()) { console.log('Ollama already installed.'); process.exit(0); }
    const plan = installPlan();
    console.log(`Platform ${platform}. This will run:\n  ${plan.label}`);
    if (!confirm) { console.log('\nRe-run with --confirm to execute. Nothing was installed.'); process.exit(0); }
    if (!plan.file) throw new Error('verified_installer_required');
    await run(plan.file, plan.args);
    console.log('Ollama install command finished. Verify with: npm run models:setup -- detect');

  } else if (args.command === 'pull') {
    const model = args.positionals[0];
    if (!model || !MODEL_REF.test(model)) throw new Error('usage: pull <model-ref> [--confirm]  (e.g. qwen3:4b or hf.co/owner/repo:Q4_K_M)');
    if (!(await ollamaVersion())) throw new Error('ollama_not_installed');
    console.log(`This will download weights and run:\n  ollama pull ${model}`);
    if (!confirm) { console.log('\nRe-run with --confirm to execute. Nothing was downloaded.'); process.exit(0); }
    await run('ollama', ['pull', model]);
    const digest = await installedModelDigest(process.env.OLLAMA_URL ?? 'http://127.0.0.1:11434', model);
    await writeFile('models.lock.json', `${JSON.stringify({ model, digest, recordedAt: new Date().toISOString() }, null, 2)}\n`, { mode: 0o600 });
    console.log(`Pulled ${model} and recorded immutable digest ${digest} in models.lock.json`);

  } else {
    console.log('usage: model-setup.ts [detect|advise|recommend|install-ollama|pull <ref>] [--vram=<GB>] [--limit=<n>] [--domain=all|security|general] [--confirm]');
    process.exitCode = 1;
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : 'operation_failed');
  process.exitCode = 1;
}
