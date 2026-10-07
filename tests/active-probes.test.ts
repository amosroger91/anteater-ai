import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  probeReflectedXss, probeSqli, probeOpenRedirect, probeSsrf, runActiveProbe, withParam, parametersFor,
  type ProbeFetch, type Collaborator,
} from '../packages/active-probes/index.js';

const TARGET = 'https://app.example.test/search?q=1';
const html = (body: string) => ({ status: 200, headers: { 'content-type': 'text/html; charset=utf-8' }, body });
const escapeHtml = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const value = (url: string, param = 'q') => new URL(url).searchParams.get(param) ?? '';

// --- Reflected XSS ---------------------------------------------------------
test('reflected XSS is confirmed only when the marker reflects unescaped in HTML', async () => {
  const vulnerable: ProbeFetch = async url => html(`<h1>Results for ${value(url)}</h1>`);
  const escaped: ProbeFetch = async url => html(`<h1>Results for ${escapeHtml(value(url))}</h1>`);
  const json: ProbeFetch = async url => ({ status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ q: value(url) }) });
  assert.equal((await probeReflectedXss(vulnerable, TARGET, 'q'))?.code, 'reflected_xss');
  assert.equal(await probeReflectedXss(escaped, TARGET, 'q'), null);        // entity-encoded reflection is safe
  assert.equal(await probeReflectedXss(json, TARGET, 'q'), null);           // reflection outside an HTML context is not this finding
});

// --- SQL injection ---------------------------------------------------------
test('SQL injection: error-based and boolean-based oracles confirm; a literal-handling app does not', async () => {
  const errorBased: ProbeFetch = async url => value(url).includes("'")
    ? { status: 200, headers: { 'content-type': 'text/html' }, body: 'You have an error in your SQL syntax near ...' }
    : html('<p>1 result</p>');
  assert.equal((await probeSqli(errorBased, TARGET, 'q'))?.code, 'sqli');

  // Boolean-based: OR-true returns the full listing (like the benign baseline), AND-false returns an empty page.
  const booleanBased: ProbeFetch = async url => {
    const v = value(url);
    if (v.includes("OR '1'='1") || v === '1') return html('<ul><li>a</li><li>b</li><li>c</li><li>d</li><li>e</li></ul>');
    return html('<ul></ul>');
  };
  assert.equal((await probeSqli(booleanBased, TARGET, 'q'))?.code, 'sqli');

  // Not injectable: every value is treated as a literal id -> same empty result, no SQL error.
  const safe: ProbeFetch = async () => html('<ul></ul>');
  assert.equal(await probeSqli(safe, TARGET, 'q'), null);
});

// --- Open redirect ---------------------------------------------------------
test('open redirect is confirmed when a 3xx Location leaves for the attacker host', async () => {
  const vulnerable: ProbeFetch = async url => ({ status: 302, headers: { location: value(url, 'next') }, body: '' });
  const safe: ProbeFetch = async () => ({ status: 302, headers: { location: 'https://app.example.test/home' }, body: '' });
  const noRedirect: ProbeFetch = async () => html('<p>ok</p>');
  const redirectTarget = 'https://app.example.test/login?next=1';
  assert.equal((await probeOpenRedirect(vulnerable, redirectTarget, 'next'))?.code, 'open_redirect');
  assert.equal(await probeOpenRedirect(safe, redirectTarget, 'next'), null);
  assert.equal(await probeOpenRedirect(noRedirect, redirectTarget, 'next'), null);
});

// --- SSRF ------------------------------------------------------------------
test('SSRF needs an out-of-band hit, and is skipped without a collaborator', async () => {
  const fetchUrl: ProbeFetch = async () => html('<p>fetched</p>');
  const hitting: Collaborator = { payloadUrl: t => `https://oob.example/${t}`, wasHit: async () => true };
  const quiet: Collaborator = { payloadUrl: t => `https://oob.example/${t}`, wasHit: async () => false };
  assert.equal((await probeSsrf(fetchUrl, 'https://app.example.test/fetch?url=x', 'url', { collaborator: hitting }))?.code, 'ssrf');
  assert.equal(await probeSsrf(fetchUrl, 'https://app.example.test/fetch?url=x', 'url', { collaborator: quiet }), null);
  assert.equal(await probeSsrf(fetchUrl, 'https://app.example.test/fetch?url=x', 'url', {}), null);   // no collaborator -> skipped
});

// --- Dispatch + param discovery -------------------------------------------
test('runActiveProbe dispatches by action over the endpoint parameters, and parametersFor reads the query', async () => {
  const vulnerable: ProbeFetch = async url => html(`<h1>${value(url, 'term')}</h1>`);
  const signals = await runActiveProbe('probe_xss', vulnerable, 'https://app.example.test/s?term=1', ['term']);
  assert.deepEqual(signals.map(s => s.code), ['reflected_xss']);
  assert.deepEqual(await runActiveProbe('inspect_http_target', vulnerable, 'https://app.example.test/s?term=1', ['term']), []); // not an active action
  assert.deepEqual(parametersFor('https://app.example.test/s?term=1&page=2'), ['term', 'page']);
  assert.equal(withParam('https://app.example.test/s?term=1', 'term', "a'b"), 'https://app.example.test/s?term=a%27b');
});
