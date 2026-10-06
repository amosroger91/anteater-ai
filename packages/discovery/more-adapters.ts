import { isAbsolute } from 'node:path';
import { normalizeHost, type DiscoveryAdapter, type RawCandidate } from './index.js';

// Additional §1 discovery adapters: passive DNS (injectable resolver) and external tools behind the
// pinned-binary pattern (absolute path from an env var, like NUCLEI_BIN). Tools are never executed
// implicitly; exec is injected so CI stays offline and no arbitrary binary becomes callable.

export type Resolver = (host: string) => Promise<string[]>;        // names -> child names observed passively
export type ExecLike = (bin: string, args: string[]) => Promise<{ stdout: string }>;

export class PassiveDnsDiscovery implements DiscoveryAdapter {
  constructor(private resolve: Resolver, private confidence = 0.6) {}
  async discover(roots: string[]): Promise<RawCandidate[]> {
    const out = new Map<string, RawCandidate>();
    for (const root of roots) {
      const normRoot = normalizeHost(root);
      if (!normRoot) continue;
      let names: string[] = [];
      try { names = await this.resolve(normRoot); } catch { continue; }
      for (const name of names) {
        const host = normalizeHost(name);
        if (host && (host === normRoot || host.endsWith('.' + normRoot)) && !out.has(host)) out.set(host, { host, source: 'passive-dns', confidence: this.confidence });
      }
    }
    return [...out.values()];
  }
}

// Line-oriented host list from a pinned absolute binary (PASSIVE_DNS_BIN, CT_BIN). One host per
// line, or a JSON object with a host field. A relative or unset path does not execute.
export class PinnedHostListDiscovery implements DiscoveryAdapter {
  constructor(
    private source: 'passive-dns' | 'cert-transparency',
    private exec: ExecLike,
    private binEnv: string,
    private env: NodeJS.ProcessEnv = process.env,
    private confidence = 0.6,
  ) {}

  async discover(roots: string[]): Promise<RawCandidate[]> {
    const bin = this.env[this.binEnv];
    if (!bin || !isAbsolute(bin)) return [];
    const out = new Map<string, RawCandidate>();
    for (const root of roots) {
      const normRoot = normalizeHost(root);
      if (!normRoot) continue;
      let stdout = '';
      try { ({ stdout } = await this.exec(bin, ['-d', normRoot])); } catch { continue; }
      for (const line of stdout.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        let raw = trimmed;
        if (trimmed.startsWith('{')) {
          try { raw = String((JSON.parse(trimmed) as { host?: unknown }).host ?? ''); } catch { continue; }
        }
        const host = normalizeHost(raw);
        if (host && (host === normRoot || host.endsWith('.' + normRoot)) && !out.has(host)) {
          out.set(host, { host, source: this.source, confidence: this.confidence });
        }
      }
    }
    return [...out.values()];
  }
}

// Subfinder adapter. The binary MUST be an absolute path supplied via SUBFINDER_BIN; the run is
// injected. One JSON-line host per record ({"host":"..."}).
export class SubfinderDiscovery implements DiscoveryAdapter {
  constructor(private exec: ExecLike, private binEnv = 'SUBFINDER_BIN', private env: NodeJS.ProcessEnv = process.env) {}
  args(root: string): string[] { return ['-silent', '-oJ', '-d', root]; }
  async discover(roots: string[]): Promise<RawCandidate[]> {
    const bin = this.env[this.binEnv];
    if (!bin || !isAbsolute(bin)) return [];
    const out = new Map<string, RawCandidate>();
    for (const root of roots) {
      const normRoot = normalizeHost(root);
      if (!normRoot) continue;
      let stdout = '';
      try { ({ stdout } = await this.exec(bin, this.args(normRoot))); } catch { continue; }
      for (const line of stdout.split('\n').filter(Boolean)) {
        try {
          const host = normalizeHost(String((JSON.parse(line) as { host?: string }).host ?? ''));
          if (host && (host === normRoot || host.endsWith('.' + normRoot)) && !out.has(host)) out.set(host, { host, source: 'subfinder', confidence: 0.75 });
        } catch { /* not a JSON line */ }
      }
    }
    return [...out.values()];
  }
}

// Gitleaks over an operator-owned repository path. Returns secret FINDINGS (not candidates): discovered
// credentials are reported, never used against any host. Binary pinned via GITLEAKS_BIN.
export interface SecretFinding { rule: string; file: string; redacted: true }
export class GitleaksAdapter {
  constructor(private exec: ExecLike, private binEnv = 'GITLEAKS_BIN', private env: NodeJS.ProcessEnv = process.env) {}
  args(repoPath: string): string[] { return ['detect', '--no-banner', '--report-format', 'json', '--source', repoPath]; }
  async scan(repoPath: string): Promise<SecretFinding[]> {
    const bin = this.env[this.binEnv];
    if (!bin || !isAbsolute(bin) || !isAbsolute(repoPath)) return [];
    let stdout = '';
    try { ({ stdout } = await this.exec(bin, this.args(repoPath))); }
    catch (error) {
      // Gitleaks exits non-zero when it finds a leak and still writes the report to stdout.
      const leaked = error && typeof error === 'object' && 'stdout' in error ? (error as { stdout?: unknown }).stdout : '';
      if (typeof leaked !== 'string' || !leaked.trim()) return [];
      stdout = leaked;
    }
    try {
      const rows = JSON.parse(stdout) as Array<{ RuleID?: string; File?: string }>;
      // Never emit the secret value itself — only the rule and file, redacted by construction.
      return rows.map(r => ({ rule: r.RuleID ?? 'secret', file: r.File ?? 'unknown', redacted: true as const }));
    } catch { return []; }
  }
}
