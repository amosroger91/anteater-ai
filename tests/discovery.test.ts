import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeHost, toCandidates, dedupe, admit, partition, diffCandidates, discoverAndPartition, FixtureDiscovery, type Candidate } from '../packages/discovery/index.js';

const policy = {
  programId: 'p', revision: 'r', sourceUrl: 'https://example.test/policy', reviewed: true as const,
  expiresAt: '2099-01-01T00:00:00Z', allowed: ['*.example.test'], excluded: ['secret.example.test'],
  allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1,
};
const cand = (host: string): Candidate => ({ host, source: 'cert-transparency', confidence: 0.5, relation: 'subdomain', observedAt: '2026-01-01T00:00:00Z' });

test('normalizeHost rejects malformed and IDN hosts, lowercases and strips trailing dot', () => {
  assert.equal(normalizeHost('API.example.test.'), 'api.example.test');
  assert.equal(normalizeHost('xn--80ak6aa92e.test'), null);
  for (const bad of ['', 'no_dots', '-bad.test', 'http://x.test', '1.2.3.4', 'a..b.test']) assert.equal(normalizeHost(bad), null);
});

test('a discovered in-scope subdomain is admitted; out-of-scope and excluded are held, never contacted', () => {
  const { admitted, held } = partition([cand('api.example.test'), cand('other.test'), cand('secret.example.test')], policy, 'inspect_http_target');
  assert.deepEqual(admitted.map(a => a.candidate.host), ['api.example.test']);
  assert.deepEqual(held.map(h => h.candidate.host).sort(), ['other.test', 'secret.example.test']);
  assert.equal(held.find(h => h.candidate.host === 'secret.example.test')?.reason, 'excluded');
});

test('a CNAME/external host cannot inherit permission from a root it points at', () => {
  // cdn.vendor.test is not under *.example.test, so even if discovery saw it it stays held.
  const { admitted } = partition([cand('cdn.vendor.test')], policy, 'inspect_http_target');
  assert.equal(admitted.length, 0);
});

test('relation is classified against submitted roots', () => {
  const c = toCandidates([
    { host: 'example.test', source: 'submitted', confidence: 1 },
    { host: 'api.example.test', source: 'subfinder', confidence: 0.6 },
    { host: 'cdn.vendor.test', source: 'observed-link', confidence: 0.4 },
  ], ['example.test']);
  assert.equal(c.find(x => x.host === 'example.test')?.relation, 'submitted');
  assert.equal(c.find(x => x.host === 'api.example.test')?.relation, 'subdomain');
  assert.equal(c.find(x => x.host === 'cdn.vendor.test')?.relation, 'external');
});

test('dedupe keeps the highest-confidence observation per host', () => {
  const merged = dedupe([{ ...cand('api.example.test'), confidence: 0.3, source: 'passive-dns' }, { ...cand('api.example.test'), confidence: 0.9, source: 'subfinder' }]);
  assert.equal(merged.length, 1);
  assert.equal(merged[0]?.confidence, 0.9);
  assert.equal(merged[0]?.source, 'subfinder');
});

test('diffCandidates reports added and removed hosts between runs', () => {
  const d = diffCandidates([cand('a.example.test'), cand('b.example.test')], [cand('b.example.test'), cand('c.example.test')]);
  assert.deepEqual(d.added, ['c.example.test']);
  assert.deepEqual(d.removed, ['a.example.test']);
});

test('end-to-end: fixture discovery admits seeded in-scope and holds seeded out-of-scope', async () => {
  const adapter = new FixtureDiscovery({ 'example.test': [
    { host: 'api.example.test', source: 'cert-transparency', confidence: 0.8 },
    { host: 'leak.vendor.test', source: 'observed-link', confidence: 0.4 },
  ] });
  const { candidates, admitted, held } = await discoverAndPartition(adapter, ['example.test'], policy, 'inspect_http_target');
  assert.ok(candidates.some(c => c.host === 'api.example.test'));
  // Under a *.example.test grant the apex is NOT in scope, so only the subdomain is admitted.
  assert.deepEqual(admitted.map(a => a.candidate.host), ['api.example.test']);
  assert.deepEqual(held.map(h => h.candidate.host).sort(), ['example.test', 'leak.vendor.test']);
});
