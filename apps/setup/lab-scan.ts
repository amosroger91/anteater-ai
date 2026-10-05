import { authorize, targetForAction, type Action } from '../../packages/scope-engine/index.js';
import { executePassiveHttp, parseLabTargetAllow, type PassiveDeps } from '../../packages/web-executor/index.js';
import type { SetupProfile } from '../../packages/setup/profile.js';

const STEPS: Array<{ action: Action; path: string }> = [
  { action: 'inspect_http_target', path: '/' },
  { action: 'inspect_robots', path: '/robots.txt' },
  { action: 'inspect_sitemap', path: '/sitemap.xml' },
  { action: 'inspect_openapi', path: '/.well-known/openapi.json' },
];

function savedHosts(profile: SetupProfile): string[] {
  return profile.labHosts.split(',').map(host => host.trim()).filter(Boolean);
}

// The policy exists only for the host the operator clicked. It is not stored as a program approval.
function policyFor(host: string) {
  return {
    programId: 'owned-lab',
    revision: 'operator-scan',
    sourceUrl: `https://${host}/`,
    reviewed: true as const,
    expiresAt: '2099-01-01T00:00:00.000Z',
    allowed: [host],
    excluded: [] as string[],
    allowedActions: STEPS.map(step => step.action),
    allowedPaths: STEPS.map(step => step.path),
    schemes: ['https'] as const,
    ports: [443] as const,
    requestsPerSecond: 1,
  };
}

export interface LabCheck {
  path: string;
  status: number;
  error: string | null;
  findings: Array<{ code: string; severity: string; detail: string }>;
}

export interface LabScan {
  host: string;
  contactedNetwork: boolean;
  privateLab: boolean;
  checks: LabCheck[];
}

function findingsOf(value: unknown): LabCheck['findings'] {
  if (!value || typeof value !== 'object' || !('signals' in value) || !Array.isArray(value.signals)) return [];
  return value.signals.slice(0, 20).map(signal => {
    const row = signal as { code?: unknown; severity?: unknown; detail?: unknown };
    return {
      code: typeof row.code === 'string' ? row.code : 'observation',
      severity: typeof row.severity === 'string' ? row.severity : 'info',
      detail: typeof row.detail === 'string' ? row.detail.slice(0, 180) : '',
    };
  });
}

export async function scanSavedLab(profile: SetupProfile, rawHost: string, deps?: PassiveDeps): Promise<LabScan> {
  const host = rawHost.trim().toLowerCase().replace(/\.$/, '');
  if (!savedHosts(profile).includes(host)) throw new Error('host_not_saved');
  const policy = policyFor(host);
  const labTargets = parseLabTargetAllow(profile.allowPrivateLabTargets, profile.labHosts);
  const checks: LabCheck[] = [];
  let contactedNetwork = false;
  for (const step of STEPS) {
    const target = targetForAction(`https://${host}/`, step.action);
    // The click is the operator starting this pass. The saved kill-switch default is not changed.
    const decision = authorize(policy, target, step.action, { GLOBAL_KILL_SWITCH: false });
    if (!decision.allowed) {
      checks.push({ path: step.path, status: 0, error: decision.reason, findings: [] });
      continue;
    }
    const observation = await executePassiveHttp(target, {
      maxBytes: 65_536,
      timeoutMs: 10_000,
      labTargets,
      ...(deps ? { deps } : {}),
      beforeRequest: async () => {
        const again = authorize(policy, target, step.action, { GLOBAL_KILL_SWITCH: false });
        if (!again.allowed) throw new Error(again.reason);
      },
    });
    const error = typeof observation.error === 'string' ? observation.error : null;
    const status = typeof observation.status === 'number' ? observation.status : 0;
    if (typeof observation.status === 'number') contactedNetwork = true;
    checks.push({ path: step.path, status, error, findings: findingsOf(observation) });
    if (error === 'blocked_address') break;
  }
  return { host, contactedNetwork, privateLab: profile.allowPrivateLabTargets, checks };
}
