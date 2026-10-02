// Authenticated multi-role access-control analysis (PRODUCTION_ROADMAP.md §2), deterministic core.
// Builds actor/resource/action matrices from observed routes + policy, finds cross-role reads worth
// testing, and plans an ownership verification CONTRACT (reused by the findings replay verifier).
// The live browser sessions live in application-research; this module is the pure planning/decision
// layer, unit-testable without a browser.

export interface Route { method: string; path: string; rolesAllowed: string[] }
export interface MatrixCell { role: string; method: string; path: string; shouldAccess: boolean }

export function buildMatrix(routes: Route[], roles: string[]): MatrixCell[] {
  const cells: MatrixCell[] = [];
  for (const route of routes) for (const role of roles)
    cells.push({ role, method: route.method, path: route.path, shouldAccess: route.rolesAllowed.includes(role) });
  return cells;
}

// Cross-role reads worth testing: a role that should NOT access a GET route is a candidate for a
// broken-access-control probe (replayed only as an authorized read against disposable data).
export interface CrossRoleProbe { attackerRole: string; method: string; path: string }
export function findCrossRoleReads(routes: Route[], roles: string[]): CrossRoleProbe[] {
  const out: CrossRoleProbe[] = [];
  for (const route of routes) {
    if (route.method.toUpperCase() !== 'GET') continue;      // default-safe: only read probes
    for (const role of roles) if (!route.rolesAllowed.includes(role)) out.push({ attackerRole: role, method: 'GET', path: route.path });
  }
  return out;
}

// Plan an ownership-verification contract: the attacker reads the victim's resource (bug if the
// secret marker appears) and the control must stay denied (403), proving the attacker session is
// genuinely unprivileged. Mirrors the §5 contract so verifyCandidate can run it.
export interface Resource { id: string; victimStepId: string; controlStepId: string; marker: string }
export function planOwnershipContract(resource: Resource, repeatCount = 2) {
  return {
    findingType: 'cross_account_read',
    preconditions: [`resource:${resource.id}`],
    steps: [{ id: resource.victimStepId, expectStatus: 200, expectBodyIncludes: [resource.marker] }],
    counterTest: { id: resource.controlStepId, expectStatus: 403 },
    repeatCount,
    cleanup: 'delete-created-resources' as const,
    maxSideEffects: 0,
  };
}
