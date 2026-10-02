import { z } from 'zod';
import { lookup } from 'node:dns/promises';
import { normalizeHost, type DiscoveryAdapter, type RawCandidate } from './index.js';

// Passive certificate-transparency discovery via crt.sh (read-only OSINT, no credentials).
// fetch is injectable so CI exercises parsing offline; a live call is pinned to crt.sh, size-capped
// and time-bounded. Discovered names are only ever CANDIDATES — admission still runs through the
// scope engine before anything is contacted.

const CRTSH = 'https://crt.sh';
const TIMEOUT = 15000;
const MAX_BODY = 8 * 1024 * 1024;

const CrtRow = z.object({ name_value: z.string().max(4000) }).passthrough();
const CrtResponse = z.array(CrtRow).max(50000);

export type FetchLike = (url: string, init?: { signal?: AbortSignal; redirect?: 'error'; headers?: Record<string, string> }) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

export class CertTransparencyDiscovery implements DiscoveryAdapter {
  constructor(private fetchImpl: FetchLike = fetch as unknown as FetchLike, private confidence = 0.7) {}

  async discover(roots: string[], signal?: AbortSignal): Promise<RawCandidate[]> {
    const out = new Map<string, RawCandidate>();
    for (const root of roots) {
      const normRoot = normalizeHost(root);
      if (!normRoot) continue;
      const url = `${CRTSH}/?q=${encodeURIComponent('%.' + normRoot)}&output=json`;
      let rows;
      try {
        const composite = signal ? AbortSignal.any([signal, AbortSignal.timeout(TIMEOUT)]) : AbortSignal.timeout(TIMEOUT);
        const response = await this.fetchImpl(url, { signal: composite, redirect: 'error', headers: { accept: 'application/json', 'user-agent': 'anteater-discovery' } });
        if (!response.ok) continue;
        const text = await response.text();
        if (text.length > MAX_BODY) continue;
        rows = CrtResponse.parse(JSON.parse(text));
      } catch { continue; }                       // a failed OSINT source is a gap, not a crash
      for (const row of rows) {
        for (const name of row.name_value.split(/\s+/)) {
          const host = normalizeHost(name.replace(/^\*\./, ''));
          // Keep only names within the submitted root; cross-domain SANs stay out of this root's candidates.
          if (host && (host === normRoot || host.endsWith('.' + normRoot)) && !out.has(host)) {
            out.set(host, { host, source: 'cert-transparency', confidence: this.confidence });
          }
        }
      }
    }
    return [...out.values()];
  }
}

// Confirm a candidate currently resolves (liveness only — does not discover new names, never contacts
// the host). Useful to raise confidence or drop dead entries before admission.
export async function resolves(host: string): Promise<boolean> {
  const normalized = normalizeHost(host);
  if (!normalized) return false;
  try { await lookup(normalized); return true; } catch { return false; }
}
