import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import { CompanyImportService } from '../apps/setup/company-import.js';
import { blankProfile } from '../packages/setup/profile.js';
import { listHackerOneCompanies } from '../packages/program-intake/directory.js';
import type { FetchLike } from '../packages/program-intake/hackerone.js';

const reply = (body: unknown) => ({ ok: true, status: 200, text: async () => JSON.stringify(body) });
const listed = (handle: string) => ({ type: 'program', attributes: { handle, name: handle, submission_state: 'open' } });
const api: FetchLike = async value => {
  const path = new URL(value).pathname;
  if (path === '/v1/hackers/programs') return reply({ data: [listed('one'), listed('two'), listed('manual')], links: {} });
  const handle = path.split('/')[4]!;
  if (path.endsWith('/structured_scopes')) return reply({ data: [{ type: 'structured-scope', attributes: {
    asset_type: 'URL', asset_identifier: `https://${handle}.example.test`, eligible_for_submission: true,
  } }] });
  if (path.endsWith('/scope_exclusions')) return reply({ data: [] });
  return reply({ data: { type: 'program', attributes: {
    ...listed(handle).attributes, policy: handle === 'manual' ? 'Contact us before testing.' : 'Automated tools are allowed.',
  } } });
};
async function idle(service: CompanyImportService, id: string) {
  for (let n = 0; n < 100; n++) {
    const state = service.status(id);
    if (!['fetching', 'preparing', 'saving'].includes(state.phase)) return state;
    await setImmediate();
  }
  throw new Error('import_did_not_settle');
}

test('company selection is only persisted after explicit confirmation of the server scope snapshot', async () => {
  const writes: string[] = [];
  const service = new CompanyImportService(() => ({ ...blankProfile(), hackeroneUsername: 'researcher', hackeroneToken: 'private-test-token' }), {
    env: {}, fetchLike: api,
    persist: async (raws, approver, _signal, done) => {
      assert.equal(approver, 'Scope Reviewer');
      for (const raw of raws) { writes.push(raw.handle); done(raw.handle); }
    },
  });
  const { id } = service.fetch();
  const directory = await idle(service, id);
  assert.equal(directory.companies.length, 3);
  assert.equal(JSON.stringify(directory).includes('private-test-token'), false);
  assert.throws(() => service.confirm({ id, approved: true }), /no_approved_scope/);
  assert.throws(() => service.preview({ id, handles: ['injected'], approver: 'Scope Reviewer' }), /company_not_in_snapshot/);
  service.preview({ id, handles: ['one', 'manual'], approver: 'Scope Reviewer' });
  const review = await idle(service, id);
  assert.deepEqual(review.scopes.map(scope => scope.handle), ['one']);
  assert.deepEqual(review.scopes[0]?.assets, ['https://one.example.test']);
  assert.deepEqual(review.skipped, [{ handle: 'manual', reason: 'manual-only' }]);
  assert.deepEqual(writes, []);
  assert.throws(() => service.confirm({ id, approved: false }));
  service.confirm({ id, approved: true });
  assert.deepEqual((await idle(service, id)).imported, ['one']);
  service.confirm({ id, approved: true });
  assert.deepEqual(writes, ['one']);
});

test('directory pagination never forwards account credentials to another host', async () => {
  let calls = 0;
  await assert.rejects(listHackerOneCompanies('Basic dXNlcjp0b2tlbg==', new AbortController().signal, async () => {
    calls++;
    return reply({ data: [listed('one')], links: { next: 'https://other.example/v1/hackers/programs' } });
  }), /program_host_refused/);
  assert.equal(calls, 1);
});

test('directory follows all pinned pages and does not return partial results on failure', async () => {
  const base = 'https://api.hackerone.com/v1/hackers/programs';
  const rows = await listHackerOneCompanies('Basic dXNlcjp0b2tlbg==', new AbortController().signal, async value =>
    new URL(value).searchParams.has('page[number]') ? reply({ data: [listed('two')], links: {} }) :
      reply({ data: [listed('one')], links: { next: base + '?page%5Bnumber%5D=2&page%5Bsize%5D=100' } }));
  assert.deepEqual(rows.map(row => row.handle), ['one', 'two']);
  await assert.rejects(listHackerOneCompanies('Basic dXNlcjp0b2tlbg==', new AbortController().signal, async value =>
    new URL(value).searchParams.has('page[number]') ? { ok: false, status: 429, text: async () => '' } :
      reply({ data: [listed('one')], links: { next: base + '?page%5Bnumber%5D=2' } })), /program_http_429/);
});
