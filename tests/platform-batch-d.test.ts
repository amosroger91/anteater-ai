import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildMatrix, findCrossRoleReads, planOwnershipContract, type Route } from '../packages/authz/index.js';
import { identityConfirmed, classifyAuthGap } from '../packages/session/index.js';
import { analyzeRoutes, boundToDeployment } from '../packages/source-analysis/index.js';
import { analyzeNetworkInventory, analyzeCiCd, analyzeDependencies } from '../packages/modules/infra.js';
import { verifyCandidate } from '../packages/findings/index.js';

const routes: Route[] = [
  { method: 'GET', path: '/admin/users', rolesAllowed: ['admin'] },
  { method: 'GET', path: '/me', rolesAllowed: ['admin', 'user'] },
  { method: 'POST', path: '/admin/users', rolesAllowed: ['admin'] },
];

test('§2 matrix + cross-role reads identify a user probing an admin-only GET', () => {
  const cells = buildMatrix(routes, ['admin', 'user']);
  assert.equal(cells.find(c => c.role === 'user' && c.path === '/admin/users')?.shouldAccess, false);
  const probes = findCrossRoleReads(routes, ['admin', 'user']);
  assert.ok(probes.some(p => p.attackerRole === 'user' && p.path === '/admin/users'));
  assert.ok(!probes.some(p => p.method !== 'GET')); // only read probes by default
});

test('§2 ownership contract verifies a cross-account read via the deterministic replayer', async () => {
  const contract = planOwnershipContract({ id: 'r1', victimStepId: 'attack', controlStepId: 'control', marker: 'secret-token' });
  const vulnerable = async (id: string) => id === 'attack' ? { status: 200, body: 'secret-token' } : { status: 403, body: 'no' };
  const patched = async () => ({ status: 403, body: 'no' });
  assert.equal((await verifyCandidate('CANDIDATE', contract, vulnerable)).next, 'VERIFIED');
  assert.equal((await verifyCandidate('CANDIDATE', contract, patched)).next, 'HUMAN_REVIEW');
});

test('§2 identity needs a marker, not just 200; auth gaps are classified not bypassed', () => {
  assert.equal(identityConfirmed({ status: 200, body: 'welcome', url: '/' }, { bodyIncludes: 'account-123' }), false);
  assert.equal(identityConfirmed({ status: 200, body: 'hi account-123', url: '/' }, { bodyIncludes: 'account-123' }), true);
  assert.equal(classifyAuthGap('Please enter your 2FA code'), 'mfa');
  assert.equal(classifyAuthGap('Registration is disabled'), 'blocked_signup');
  assert.equal(classifyAuthGap('normal page'), 'none');
});

test('§4 source analysis flags unguarded routes as HYPOTHESIS only', () => {
  const findings = analyzeRoutes([
    { method: 'POST', path: '/transfer', middleware: ['bodyParser'] },
    { method: 'GET', path: '/me', middleware: ['requireAuth'] },
  ], ['requireAuth', 'requireRole']);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.code, 'route_mutating_without_authz');
  assert.equal(findings[0]!.status, 'HYPOTHESIS');
  assert.equal(boundToDeployment('git@repo', 'https://app.test', { 'git@repo': 'https://app.test' }), true);
  assert.equal(boundToDeployment('git@repo', 'https://other.test', { 'git@repo': 'https://app.test' }), false);
});

test('§6 infra analyzers flag risky services, CI/CD and dependencies', () => {
  const net = analyzeNetworkInventory([{ host: 'db', port: 6379, service: 'redis', tls: false }]);
  assert.ok(net.some(f => f.code === 'exposed_sensitive_service') && net.some(f => f.code === 'plaintext_service'));
  const ci = analyzeCiCd({ on: 'pull_request_target', jobs: { a: { steps: [{ run: 'echo ${{ secrets.TOKEN }}' }, { uses: 'actions/checkout@v4' }] } } });
  assert.ok(ci.some(f => f.code === 'cicd_secrets_on_pr_target'));
  assert.ok(ci.some(f => f.code === 'cicd_unpinned_action'));
  const deps = analyzeDependencies([{ name: 'lodash', version: '4.17.20', pinned: true, advisory: 'CVE-2021-23337' }, { name: 'x', version: '^1', pinned: false }]);
  assert.ok(deps.some(f => f.code === 'dependency_known_vulnerable') && deps.some(f => f.code === 'dependency_unpinned'));
});
