import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { IncomingHttpHeaders } from 'node:http';
import { AccountStore, publicAccountLabel } from '../packages/application-research/accounts.js';
import { ApplicationSchema, AuthSchema } from '../packages/application-research/profile.js';
import { RequestGate } from '../packages/application-research/transport.js';
import { verifyOwnership, type OwnershipSession } from '../packages/application-research/verification.js';
import { findCrossRoleReads, ownershipRoster, routesFromResources } from '../packages/authz/index.js';
import { startResearchLab } from '../fixtures/research-lab.js';

const account = (id: string, role: 'user' | 'admin', tenant: string) => ({
  id, usernameEnv: `LAB_USER_${id.toUpperCase()}`, passwordEnv: `LAB_PASS_${id.toUpperCase()}`, role, tenant,
});

const profile = {
  maxPages: 4, maxDepth: 0, maxRequests: 40, maxDurationSeconds: 30,
  readPathPrefixes: ['/', '/api'],
  auth: {
    loginPath: '/login', sessionPath: '/api/me',
    accounts: [account('a', 'user', 'acme'), account('b', 'user', 'other'), account('c', 'admin', 'acme')],
  },
  privateResources: [{ name: 'private-document', createPath: '/api/documents', readPath: '/api/documents/{id}', cleanupPath: '/api/documents/by-marker/{marker}', ownerOnly: true as const }],
};

test('accounts carry roles and the encrypted store does not put the password in a label', async () => {
  const parsed = ApplicationSchema.parse(profile);
  assert.deepEqual(parsed.auth.accounts.map(item => item.role), ['user', 'user', 'admin']);
  assert.equal(AuthSchema.parse({ accounts: [{ id: 'a', usernameEnv: 'LAB_USER_A', passwordEnv: 'LAB_PASS_A' }] }).accounts[0]?.role, 'user');
  assert.equal(AuthSchema.safeParse({ accounts: [account('a', 'user', 'acme'), account('b', 'user', 'acme'), account('c', 'admin', 'acme'), account('d', 'user', 'acme')] }).success, false);
  const roster = ownershipRoster(parsed.auth.accounts);
  assert.equal(roster?.crossTenant, true);
  assert.equal(roster?.admin.role, 'admin');
  const routes = routesFromResources(parsed.privateResources, [{ method: 'GET', path: '/api/me', rolesAllowed: ['user', 'admin'] }]);
  const probes = findCrossRoleReads(routes, ['user', 'admin']);
  assert.ok(probes.some(probe => probe.attackerRole === 'admin' && probe.path === '/api/documents/{id}'));
  assert.ok(!probes.some(probe => probe.attackerRole === 'user' && probe.path === '/api/documents/{id}'));
  const dir = await mkdtemp(join(tmpdir(), 'anteater-accounts-'));
  try {
    const store = new AccountStore(dir, 'ab'.repeat(32));
    const saved = await store.prepare('lab.example.test', 'a', 'example.test');
    const label = JSON.stringify(publicAccountLabel(saved));
    assert.equal(label.includes(saved.password), false);
    assert.equal(label.includes(saved.username), false);
    const names = await readdir(dir);
    const raw = await readFile(join(dir, names[0] ?? ''), 'utf8');
    assert.equal(raw.includes(saved.password), false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

function sessionCookie(headers: IncomingHttpHeaders): string {
  const raw = headers['set-cookie'];
  const line = Array.isArray(raw) ? raw[0] : raw;
  const match = /session=([^;]+)/.exec(line ?? '');
  if (!match?.[1]) throw new Error('no_session');
  return `session=${match[1]}`;
}

async function login(lab: Awaited<ReturnType<typeof startResearchLab>>, email: string, password: string) {
  const response = await lab.exchange({
    url: new URL('https://lab.example.test/api/login'), method: 'POST',
    headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify({ email, password })),
    signal: AbortSignal.timeout(5000), maxBytes: 65536, beforeConnect: async () => {},
  });
  return sessionCookie(response.headers);
}

function boundSession(id: string, cookie: string, gate: RequestGate): OwnershipSession {
  const session: OwnershipSession = {
    id, purpose: 'discover', gate,
    request(url, method = 'GET', body) {
      const headers: Record<string, string> = { cookie };
      const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
      if (payload) headers['content-type'] = 'application/json';
      return gate.send(id, session.purpose, url, method, headers, payload);
    },
  };
  return session;
}

test('cross-user and cross-tenant reads are found, patched reads are rejected, and cleanup leaves nothing', async () => {
  const app = ApplicationSchema.parse(profile);
  for (const vulnerable of [true, false]) {
    const lab = await startResearchLab({ vulnerable });
    try {
      const cookies = {
        a: await login(lab, 'alice@example.test', 'alice-password'),
        b: await login(lab, 'bob@example.test', 'bob-password'),
        c: await login(lab, 'admin@example.test', 'admin-password'),
      };
      assert.equal(new Set(Object.values(cookies)).size, 3);
      const gate = new RequestGate('https://lab.example.test', app, AbortSignal.timeout(15000), async () => {}, lab.exchange, true);
      const gaps: string[] = [];
      const findings = await verifyOwnership(app, [boundSession('a', cookies.a, gate), boundSession('b', cookies.b, gate), boundSession('c', cookies.c, gate)], gaps);
      assert.equal(lab.records.size, 0);
      if (vulnerable) {
        assert.deepEqual(findings.map(finding => finding.boundary).sort(), ['cross-tenant', 'cross-user']);
        assert.ok(findings.every(finding => finding.owner === 'a' && finding.other === 'b'));
        assert.equal(JSON.stringify(findings).includes('alice-password'), false);
      } else {
        assert.equal(findings.length, 0);
      }
    } finally { await lab.close(); }
  }
});

test('a malformed create id still deletes the resource by marker', async () => {
  const app = ApplicationSchema.parse(profile);
  const lab = await startResearchLab({ vulnerable: true, missingIdOnCreate: true });
  try {
    const cookies = {
      a: await login(lab, 'alice@example.test', 'alice-password'),
      b: await login(lab, 'bob@example.test', 'bob-password'),
    };
    const gate = new RequestGate('https://lab.example.test', app, AbortSignal.timeout(15000), async () => {}, lab.exchange, true);
    const gaps: string[] = [];
    const findings = await verifyOwnership(app, [boundSession('a', cookies.a, gate), boundSession('b', cookies.b, gate), boundSession('c', 'session=unused', gate)], gaps);
    assert.equal(findings.length, 0);
    assert.ok(gaps.includes('unsupported_resource_id'));
    assert.equal(lab.records.size, 0);
    assert.ok(lab.requests.some(request => request.method === 'DELETE' && request.path.startsWith('/api/documents/by-marker/')));
  } finally { await lab.close(); }
});
