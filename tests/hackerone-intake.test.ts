import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PERMITTED_POLICY } from '../fixtures/automation-policy.js';
import { fetchProgram, hackerOneProgramUrls, MAX_RESPONSE_BYTES, rateRulesFromPolicy, type FetchLike } from '../packages/program-intake/hackerone.js';

const urls = hackerOneProgramUrls('acme');

function json(body: unknown, status = 200) {
  return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(body) };
}

function programBody(policy = PERMITTED_POLICY) {
  return { data: { id: 9, type: 'program', attributes: {
    handle: 'acme', name: 'Acme', currency: 'usd', policy, submission_state: 'open',
    open_scope: false, gold_standard_safe_harbor: false, offers_bounties: true,
  } } };
}

function scopeBody(next?: string) {
  return { data: [{ id: '1', type: 'structured-scope', attributes: {
    asset_type: 'URL', asset_identifier: 'https://app.example.test', eligible_for_bounty: true,
    eligible_for_submission: true, instruction: 'Primary site', max_severity: 'critical',
  } }, { id: '2', type: 'structured-scope', attributes: {
    asset_type: 'URL', asset_identifier: 'https://secret.example.test', eligible_for_bounty: false,
    eligible_for_submission: false, instruction: null,
  } }], links: next ? { self: urls.scopes, next } : { self: urls.scopes } };
}

function exclusionBody() {
  return { data: [{ id: '9', type: 'scope-exclusion', attributes: {
    category: 'Denial of service', details: 'Volumetric denial of service is not rewarded.', created_at: '2024-01-01T00:00:00.000Z',
  } }] };
}

function router(pages: Record<string, { status?: number; body?: unknown; text?: string }>) {
  const calls: Array<{ url: string; init?: { method?: string; redirect?: string; headers?: Record<string, string>; signal?: AbortSignal } }> = [];
  let errorBodyReads = 0;
  const fetchLike: FetchLike = async (url, init) => {
    calls.push({ url, init });
    const page = pages[url];
    if (!page) throw new Error(`unexpected ${url}`);
    if (page.text !== undefined) return { ok: true, status: 200, text: async () => page.text ?? '' };
    if ((page.status ?? 200) >= 400) return { ok: false, status: page.status ?? 500, text: async () => { errorBodyReads += 1; return 'secret'; } };
    return json(page.body);
  };
  return { fetchLike, calls, errorReads: () => errorBodyReads };
}

const pages = () => ({
  [urls.program]: { body: programBody() },
  [urls.scopes]: { body: scopeBody() },
  [urls.exclusions]: { body: exclusionBody() },
});

test('fetchProgram reads only the documented HackerOne API and parses scope, exclusions, and rate', async () => {
  const client = router(pages());
  const program = await fetchProgram('acme', client.fetchLike);
  assert.deepEqual(client.calls.map(call => call.url), [urls.program, urls.scopes, urls.exclusions]);
  assert.ok(client.calls.every(call => call.init?.method === 'GET' && call.init.redirect === 'error' && new URL(call.url).hostname === 'api.hackerone.com'));
  assert.equal(client.calls[0]?.init?.headers?.authorization, undefined);
  assert.equal(program.platform, 'hackerone');
  assert.equal(program.handle, 'acme');
  assert.equal(program.sourceUrl, urls.program);
  assert.equal(program.programUrl, 'https://hackerone.com/acme');
  assert.equal(program.policyText, PERMITTED_POLICY);
  assert.equal(program.rate.requestsPerSecond, 2);
  assert.match(program.rate.published ?? '', /2 requests per second/);
  assert.equal(program.scopes[1]?.eligibleForSubmission, false);
  assert.deepEqual(program.exclusions, [{ category: 'Denial of service', details: 'Volumetric denial of service is not rewarded.' }]);
});

test('a published rate uses the strictest per-second figure and ignores per-minute text', () => {
  assert.deepEqual(rateRulesFromPolicy('No numeric limit is published.'), { requestsPerSecond: 1, published: null });
  assert.equal(rateRulesFromPolicy('10 requests per second, or 2 requests per second on the API.').requestsPerSecond, 2);
  assert.equal(rateRulesFromPolicy('100 requests per second.').requestsPerSecond, 10);
  assert.equal(rateRulesFromPolicy('60 requests per minute.').requestsPerSecond, 1);
  assert.equal(rateRulesFromPolicy('Keep it to 1 rps.').requestsPerSecond, 1);
});

test('fetchProgram refuses another host, a bad handle, a huge body, and an unread error', async () => {
  const evil = 'https://evil.example/steal';
  const redirected = router({ ...pages(), [urls.scopes]: { body: scopeBody(evil) } });
  await assert.rejects(fetchProgram('acme', redirected.fetchLike), /program_host_refused/);
  assert.ok(redirected.calls.every(call => new URL(call.url).hostname === 'api.hackerone.com'));
  assert.equal(redirected.calls.some(call => call.url === evil), false);

  const idle = router(pages());
  await assert.rejects(fetchProgram('../admin', idle.fetchLike), /invalid_program_handle/);
  await assert.rejects(fetchProgram('Acme', idle.fetchLike), /invalid_program_handle/);
  await assert.rejects(fetchProgram('acme', idle.fetchLike, { authorization: 'Basic x\r\nHost: evil' }), /invalid_authorization/);
  assert.equal(idle.calls.length, 0);

  const huge = router({ ...pages(), [urls.program]: { text: 'x'.repeat(MAX_RESPONSE_BYTES + 1) } });
  await assert.rejects(fetchProgram('acme', huge.fetchLike), /program_response_too_large/);

  const denied = router({ ...pages(), [urls.program]: { status: 401 } });
  await assert.rejects(fetchProgram('acme', denied.fetchLike), /program_http_401/);
  assert.equal(denied.errorReads(), 0);

  const garbage = router({ ...pages(), [urls.program]: { text: 'not-json' } });
  await assert.rejects(fetchProgram('acme', garbage.fetchLike), /program_response_invalid/);

  const swapped = router({ ...pages(), [urls.program]: { body: { data: { type: 'program', attributes: { ...programBody().data.attributes, handle: 'other' } } } } });
  await assert.rejects(fetchProgram('acme', swapped.fetchLike), /program_handle_mismatch/);
});

test('scope pagination stays on the documented program path', async () => {
  const second = `${urls.scopes}&page%5Bnumber%5D=2`;
  const client = router({
    ...pages(),
    [urls.scopes]: { body: scopeBody(second) },
    [second]: { body: { data: [{ type: 'structured-scope', attributes: {
      asset_type: 'WILDCARD', asset_identifier: '*.example.test', eligible_for_submission: true, eligible_for_bounty: false, instruction: null,
    } }] } },
  });
  const program = await fetchProgram('acme', client.fetchLike, { authorization: 'Basic dGVzdDp0ZXN0', timeoutMs: 1000 });
  assert.equal(program.scopes.length, 3);
  assert.equal(client.calls[0]?.init?.headers?.authorization, 'Basic dGVzdDp0ZXN0');
  assert.ok(client.calls.every(call => new URL(call.url).pathname.startsWith('/v1/hackers/programs/acme')));

});

test('the request deadline aborts a fetch that never returns', async () => {
  const hanging: FetchLike = (_url, init) => new Promise((_resolve, reject) => {
    const signal = init?.signal;
    if (!signal) { reject(new Error('missing_signal')); return; }
    const fail = () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
    if (signal.aborted) fail();
    else signal.addEventListener('abort', fail, { once: true });
  });
  // AbortSignal.timeout does not keep the event loop alive by itself.
  const keepAlive = setInterval(() => {}, 1000);
  try {
    await assert.rejects(fetchProgram('acme', hanging, { timeoutMs: 30 }), /aborted/);
  } finally {
    clearInterval(keepAlive);
  }
});
