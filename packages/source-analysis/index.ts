import type { FindingSeverity } from '../findings/index.js';

// Owned-source static analysis (PRODUCTION_ROADMAP.md §4). Analyzes an extracted route manifest for
// authorization gaps. A code match is only a HYPOTHESIS — it must be confirmed by runtime evidence
// (the replay verifier) before it can become a candidate, let alone VERIFIED.

export interface SourceRoute { method: string; path: string; middleware: string[] }
export interface SourceFinding { code: string; severity: FindingSeverity; detail: string; status: 'HYPOTHESIS' }

// Routes that mutate state or expose data but carry none of the known authorization middleware are
// flagged as hypotheses to probe at runtime.
export function analyzeRoutes(routes: SourceRoute[], authzMiddleware: string[]): SourceFinding[] {
  const authz = new Set(authzMiddleware.map(m => m.toLowerCase()));
  const findings: SourceFinding[] = [];
  for (const route of routes) {
    const guarded = route.middleware.some(m => authz.has(m.toLowerCase()));
    if (guarded) continue;
    const mutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(route.method.toUpperCase());
    findings.push({
      code: mutating ? 'route_mutating_without_authz' : 'route_read_without_authz',
      severity: mutating ? 'high' : 'medium',
      detail: `${route.method} ${route.path} has no authorization middleware`,
      status: 'HYPOTHESIS',
    });
  }
  return findings;
}

// Bind a source repository to the deployment it analyzes; a mismatch means the hypothesis cannot be
// trusted against that target.
export function boundToDeployment(repoOrigin: string, deploymentOrigin: string, mapping: Record<string, string>): boolean {
  return mapping[repoOrigin] === deploymentOrigin;
}
