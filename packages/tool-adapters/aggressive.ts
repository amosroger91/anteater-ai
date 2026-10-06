import { resolveInvocation, NUCLEI } from './index.js';

export interface AggressiveInput {
  host: string;
  labHosts: readonly string[];
  snapshotConfirmed: boolean;
  n8nAttested: boolean;
  allowDestructive: boolean;
  env?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  beforeExecution: () => Promise<void>;
  exec: (bin: string, args: string[], signal?: AbortSignal) => Promise<{ stdout: string }>;
}

export interface NucleiFinding { template: string; location: string; severity: string }

export interface AggressiveResult {
  refused: string | null;
  executed: boolean;
  destructive: boolean;
  findings: NucleiFinding[];
  audit: Array<{ event: 'AGGRESSIVE_DESTRUCTIVE'; host: string; recovery: 'qm rollback' }>;
}

export function aggressivePreflight(input: Pick<AggressiveInput, 'host' | 'labHosts' | 'snapshotConfirmed' | 'n8nAttested' | 'allowDestructive'>): { ok: true; destructive: boolean } | { ok: false; reason: string } {
  const host = input.host.trim().toLowerCase();
  if (!input.snapshotConfirmed) return { ok: false, reason: 'snapshot_required' };
  if (!input.n8nAttested) return { ok: false, reason: 'n8n_attestation_required' };
  if (!host || host.includes('/') || !input.labHosts.some(item => item.trim().toLowerCase() === host)) return { ok: false, reason: 'host_not_in_lab' };
  return { ok: true, destructive: input.allowDestructive };
}

export function parseNucleiJsonl(text: string): NucleiFinding[] {
  const findings: NucleiFinding[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let raw: unknown;
    try { raw = JSON.parse(line); } catch { throw new Error('nuclei_output_invalid'); }
    if (!raw || typeof raw !== 'object') throw new Error('nuclei_output_invalid');
    const row = raw as Record<string, unknown>;
    const template = typeof row['template-id'] === 'string' ? row['template-id'] : '';
    if (!/^[a-z0-9][a-z0-9_-]{0,80}$/.test(template)) throw new Error('nuclei_output_invalid');
    const host = typeof row.host === 'string' ? row.host : '';
    let location = '';
    try {
      const url = new URL(host);
      if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error('nuclei_output_invalid');
      location = `${url.origin}${url.pathname}`;
    } catch (error) {
      if (error instanceof Error && error.message === 'nuclei_output_invalid') throw error;
      throw new Error('nuclei_output_invalid');
    }
    const info = row.info && typeof row.info === 'object' ? row.info as Record<string, unknown> : {};
    const severity = typeof info.severity === 'string' && ['info', 'low', 'medium', 'high', 'critical'].includes(info.severity) ? info.severity : 'info';
    findings.push({ template, location, severity });
  }
  return findings;
}

export async function runAggressive(input: AggressiveInput): Promise<AggressiveResult> {
  const decision = aggressivePreflight(input);
  if (!decision.ok) return { refused: decision.reason, executed: false, destructive: false, findings: [], audit: [] };
  input.signal?.throwIfAborted();
  await input.beforeExecution();
  const host = input.host.trim().toLowerCase();
  const invocation = resolveInvocation(NUCLEI, {
    url: `https://${host}`,
    destructive: decision.destructive ? 'true' : 'false',
    labAuthorized: 'true',
  }, input.env);
  input.signal?.throwIfAborted();
  const result = await input.exec(invocation.bin, invocation.args, input.signal);
  input.signal?.throwIfAborted();
  await input.beforeExecution();
  const findings = parseNucleiJsonl(result.stdout);
  const audit = decision.destructive ? [{ event: 'AGGRESSIVE_DESTRUCTIVE' as const, host, recovery: 'qm rollback' as const }] : [];
  return { refused: null, executed: true, destructive: decision.destructive, findings, audit };
}
