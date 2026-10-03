import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startResearchLab, FixtureCleanupJournal } from '../../fixtures/research-lab.js';
import { researchApplication } from '../../packages/application-research/index.js';
import { ApplicationSchema } from '../../packages/application-research/profile.js';
import { launchResearchBrowser } from '../../packages/application-research/browser.js';
import { loadConfig } from '../../packages/shared/config.js';

const app = ApplicationSchema.parse({ maxPages: 5, maxDepth: 1, maxRequests: 120, maxDurationSeconds: 60,
  auth: { loginPath: '/login', sessionPath: '/api/me', accounts: [{ id: 'a', usernameEnv: 'LAB_USER_A', passwordEnv: 'LAB_PASS_A' }, { id: 'b', usernameEnv: 'LAB_USER_B', passwordEnv: 'LAB_PASS_B' }] },
  privateResources: [{ name: 'private-document', createPath: '/api/documents', readPath: '/api/documents/{id}', cleanupPath: '/api/documents/by-marker/{marker}', ownerOnly: true }] });
const env = { LAB_USER_A: 'alice@example.test', LAB_PASS_A: 'alice-password', LAB_USER_B: 'bob@example.test', LAB_PASS_B: 'bob-password' };
const config = loadConfig({ GLOBAL_KILL_SWITCH: 'false', ALLOW_ACTIVE_TESTING: 'true', ENABLE_APPLICATION_RESEARCH: 'true' });

test('same-principal sessions never create resources or report cross-account access', { timeout: 60000 }, async () => {
  const browser = await launchResearchBrowser(); const lab = await startResearchLab({ vulnerable: false });
  try {
    const result = await researchApplication('https://lab.example.test', app, config, async () => {}, undefined, {
      browser, exchange: lab.exchange, cleanupJournal: new FixtureCleanupJournal(),
      env: { ...env, LAB_USER_B: env.LAB_USER_A, LAB_PASS_B: env.LAB_PASS_A },
    });
    assert.equal(result.findings.length, 0);
    assert.ok(result.coverage.gaps.includes('ownership_checks_require_distinct_principals'));
    assert.ok(!lab.requests.some(request => request.method === 'POST' && request.path === '/api/documents'));
  } finally { await browser.close(); await lab.close(); }
});

test('different login aliases for one server principal never pass the distinct-user gate', { timeout: 60000 }, async () => {
  const browser = await launchResearchBrowser(); const lab = await startResearchLab({ vulnerable: false });
  try {
    const exchange: typeof lab.exchange = async input => {
      const response = await lab.exchange(input);
      if (input.url.pathname === '/api/me' && response.status === 200) response.body = Buffer.from(JSON.stringify({ ...JSON.parse(response.body.toString()), id: 'same-canonical-subject' }));
      return response;
    };
    const result = await researchApplication('https://lab.example.test', app, config, async () => {}, undefined, { browser, exchange, env, cleanupJournal: new FixtureCleanupJournal() });
    assert.equal(result.findings.length, 0);
    assert.ok(result.coverage.gaps.includes('ownership_checks_require_distinct_principals'));
    assert.ok(!lab.requests.some(request => request.method === 'POST' && request.path === '/api/documents'));
  } finally { await browser.close(); await lab.close(); }
});

test('interrupted creation retains durable intent and the next run reconciles before creating', { timeout: 90000 }, async () => {
  const browser = await launchResearchBrowser(); const lab = await startResearchLab({ vulnerable: false });
  const journal = new FixtureCleanupJournal(); const controller = new AbortController();
  try {
    const exchange: typeof lab.exchange = async input => {
      assert.ok(input.method !== 'POST' || input.url.pathname !== '/api/documents' || journal.records.size > 0, 'intent saved before create');
      const response = await lab.exchange(input);
      if (input.method === 'POST' && input.url.pathname === '/api/documents') controller.abort(new Error('shutdown'));
      return response;
    };
    await assert.rejects(researchApplication('https://lab.example.test', app, config, async () => {
      if (controller.signal.aborted) throw new Error('kill_switch');
    }, controller.signal, { browser, exchange, env, cleanupJournal: journal }), /shutdown/);
    assert.equal(journal.records.size, 1);
    assert.equal(lab.records.size, 1);
    const boundary = lab.requests.length;
    await researchApplication('https://lab.example.test', app, config, async () => {}, undefined, { browser, exchange: lab.exchange, env, cleanupJournal: journal });
    assert.equal(journal.records.size, 0);
    assert.equal(lab.records.size, 0);
    const writes = lab.requests.slice(boundary).filter(request => request.path.startsWith('/api/documents') && request.method !== 'GET');
    assert.equal(writes[0]?.method, 'DELETE');
  } finally { await browser.close(); await lab.close(); }
});

test('asynchronous deletion remains pending and blocks further resource creation', { timeout: 60000 }, async () => {
  const browser = await launchResearchBrowser(); const lab = await startResearchLab({ vulnerable: false });
  const journal = new FixtureCleanupJournal();
  try {
    const exchange: typeof lab.exchange = async input => input.method === 'DELETE'
      ? { status: 202, headers: {}, body: Buffer.from(''), truncated: false } : lab.exchange(input);
    const profile = ApplicationSchema.parse({ ...app, privateResources: [...app.privateResources, { ...app.privateResources[0], name: 'second-probe' }] });
    const result = await researchApplication('https://lab.example.test', profile, config, async () => {}, undefined, { browser, exchange, env, cleanupJournal: journal });
    assert.equal(journal.records.size, 1);
    assert.equal(lab.records.size, 1);
    assert.equal(lab.requests.filter(request => request.method === 'POST' && request.path === '/api/documents').length, 1);
    assert.ok(result.coverage.gaps.includes('cleanup_unconfirmed'));
    assert.equal(result.coverage.pendingCleanup.length, 1);
  } finally { await browser.close(); await lab.close(); }
});

test('real browser discovers API traffic, logs in twice and distinguishes vulnerable from patched access', { timeout: 120000 }, async () => {
  const browser = await launchResearchBrowser();
  try {
    for (const vulnerable of [true, false]) {
      const lab = await startResearchLab({ vulnerable });
      try {
        const result = await researchApplication('https://lab.example.test', app, config, async () => {}, undefined, { browser, cleanupJournal: new FixtureCleanupJournal(), exchange: lab.exchange, env });
        assert.equal(result.coverage.sessions.filter(session => session.identityValidated).length, 2, JSON.stringify(result.coverage));
        assert.ok(result.endpoints.some(endpoint => endpoint.url.includes('/api/catalog')));
        assert.equal(result.findings.length, vulnerable ? 1 : 0, JSON.stringify(result.coverage));
        if (vulnerable) assert.equal(result.findings[0]?.evidence.length, 5);
        assert.equal(lab.records.size, 0, 'owned resource cleaned up');
        assert.ok((result.coverage.blocked.out_of_scope_or_method ?? 0) > 0);
        assert.ok(!lab.requests.some(request => request.path === '/leak'));
        assert.ok(!JSON.stringify(result).includes('alice-password'));
      } finally { await lab.close(); }
    }
  } finally { await browser.close(); }
});

test('signup creates isolated accounts, verifies email and reuses encrypted identities on restart', { timeout: 120000 }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anteater-browser-'));
  const browser = await launchResearchBrowser(); const lab = await startResearchLab({ signup: true, vulnerable: true });
  const profile = ApplicationSchema.parse({ ...app, auth: { loginPath: '/login', signupPath: '/register', sessionPath: '/api/me', signupEnabled: true,
    mailbox: { host: 'mail.example.test', usernameEnv: 'MAIL_USER', passwordEnv: 'MAIL_PASS', emailDomain: 'example.test' } } });
  const settings = { ...config, CREDENTIAL_STORE: dir, ACCOUNT_KEY: 'a'.repeat(64) };
  try {
    for (let repeat = 0; repeat < 2; repeat++) {
      const result = await researchApplication('https://lab.example.test', profile, settings, async () => {}, undefined,
        { browser, cleanupJournal: new FixtureCleanupJournal(), exchange: lab.exchange, mailbox: async account => lab.verification(account.username) });
      assert.equal(result.coverage.sessions.filter(session => session.identityValidated).length, 2, JSON.stringify(result.coverage));
      assert.equal(result.findings.length, 1);
      assert.equal(lab.registrations(), 2);
    }
  } finally { await browser.close(); await lab.close(); await rm(dir, { recursive: true, force: true }); }
});

test('interactive login challenges are reported and never cause credential submission', { timeout: 60000 }, async () => {
  const browser = await launchResearchBrowser(); const lab = await startResearchLab({ challenge: true });
  try {
    const result = await researchApplication('https://lab.example.test', app, config, async () => {}, undefined, { browser, cleanupJournal: new FixtureCleanupJournal(), exchange: lab.exchange, env });
    assert.ok(result.coverage.sessions.some(session => session.reason === 'interactive_challenge'));
    assert.ok(!lab.requests.some(request => request.path === '/api/login'));
    assert.equal(result.findings.length, 0);
    assert.ok(result.endpoints.some(endpoint => endpoint.url.includes('/api/catalog')));
  } finally { await browser.close(); await lab.close(); }
});

test('ownership verification requires cleanup and deletes by marker if create omits its ID', { timeout: 60000 }, async () => {
  const browser = await launchResearchBrowser(); const lab = await startResearchLab({ vulnerable: true, missingIdOnCreate: true });
  try {
    const unsafeProfile = { ...app, privateResources: [{ ...app.privateResources[0], cleanupPath: undefined }] };
    assert.equal(ApplicationSchema.safeParse(unsafeProfile).success, false, 'profiles without cleanup must fail validation');
    const result = await researchApplication('https://lab.example.test', app, config, async () => {}, undefined, { browser, cleanupJournal: new FixtureCleanupJournal(), exchange: lab.exchange, env });
    assert.equal(result.findings.length, 0);
    assert.ok(result.coverage.gaps.includes('unsupported_resource_id'));
    assert.equal(lab.records.size, 0, 'a created test object is removed even when its ID cannot be parsed');
    assert.ok(lab.requests.some(request => request.method === 'DELETE' && request.path.startsWith('/api/documents/by-marker/')));
  } finally { await browser.close(); await lab.close(); }
});
