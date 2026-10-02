import { z } from 'zod';
import type { ModuleFinding } from './index.js';

// §6 network / CI-CD / supply-chain analyzers. Offline analysis of operator-supplied inventories and
// configs; no live probing. Each requires its own reviewed module profile (see moduleAuthorized).

// --- Network service inventory ---------------------------------------------
const RISKY_PORTS: Record<number, string> = { 23: 'telnet', 3389: 'rdp', 6379: 'redis', 9200: 'elasticsearch', 27017: 'mongodb', 5432: 'postgres', 3306: 'mysql', 11211: 'memcached' };

export interface ServiceEntry { host: string; port: number; service: string; tls: boolean }
export function analyzeNetworkInventory(services: ServiceEntry[]): ModuleFinding[] {
  const findings: ModuleFinding[] = [];
  for (const s of services) {
    if (RISKY_PORTS[s.port]) findings.push({ code: 'exposed_sensitive_service', severity: 'high', detail: `${RISKY_PORTS[s.port]} on ${s.host}:${s.port}` });
    if (!s.tls && !['dns', 'ntp'].includes(s.service.toLowerCase())) findings.push({ code: 'plaintext_service', severity: 'medium', detail: `${s.service} on ${s.host}:${s.port} without TLS` });
  }
  return findings;
}

// --- CI/CD pipeline config -------------------------------------------------
export function analyzeCiCd(config: unknown): ModuleFinding[] {
  const text = JSON.stringify(config ?? '');
  const findings: ModuleFinding[] = [];
  if (/pull_request_target/.test(text) && /secrets\./.test(text)) findings.push({ code: 'cicd_secrets_on_pr_target', severity: 'high', detail: 'secrets exposed to pull_request_target workflow' });
  if (/curl\s+[^|]*\|\s*(sudo\s+)?(sh|bash)/.test(text)) findings.push({ code: 'cicd_curl_pipe_shell', severity: 'high', detail: 'remote script piped to a shell' });
  // Unpinned actions: uses: owner/repo@branch instead of @<40-hex-sha>.
  const uses = z.object({}).passthrough().safeParse(config);
  if (uses.success) for (const m of text.matchAll(/"uses"\s*:\s*"([^"]+)"/g)) {
    const ref = m[1] ?? '';
    if (!/@[0-9a-f]{40}$/.test(ref)) findings.push({ code: 'cicd_unpinned_action', severity: 'medium', detail: `unpinned action ${ref}` });
  }
  return findings;
}

// --- Supply-chain dependencies ---------------------------------------------
export interface DependencyEntry { name: string; version: string; pinned: boolean; advisory?: string }
export function analyzeDependencies(deps: DependencyEntry[]): ModuleFinding[] {
  const findings: ModuleFinding[] = [];
  for (const d of deps) {
    if (d.advisory) findings.push({ code: 'dependency_known_vulnerable', severity: 'high', detail: `${d.name}@${d.version}: ${d.advisory}` });
    if (!d.pinned) findings.push({ code: 'dependency_unpinned', severity: 'low', detail: `${d.name} is not pinned (${d.version})` });
  }
  return findings;
}
