import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startResearchLab } from '../../fixtures/research-lab.js';
import { BrowserSession, launchResearchBrowser } from '../../packages/application-research/browser.js';
import { ApplicationSchema } from '../../packages/application-research/profile.js';
import { RequestGate } from '../../packages/application-research/transport.js';

test('browser routing blocks off-scope subresources, frames, workers, and websockets', { timeout: 60000 }, async () => {
  const browser = await launchResearchBrowser();
  const lab = await startResearchLab({ egressProbes: true });
  const app = ApplicationSchema.parse({ readPathPrefixes: ['/', '/api'], maxPages: 1, maxDepth: 0, maxRequests: 30, maxDurationSeconds: 20 });
  try {
    const gate = new RequestGate('https://lab.example.test', app, AbortSignal.timeout(20000), async () => {}, lab.exchange, false);
    const session = await BrowserSession.create(browser, 'egress', gate);
    try {
      await session.visit('https://lab.example.test/');
      await session.page.waitForTimeout(500);
      await session.settle();
      const offScope = ['/frame', '/sub.js', '/sub', '/worker.js', '/socket', '/leak'];
      for (const path of offScope) assert.ok(!lab.requests.some(request => request.path === path), path);
      assert.ok(lab.requests.some(request => request.path === '/api/catalog'));
      assert.ok((gate.blocked.out_of_scope_or_method ?? 0) > 0);
      assert.ok((gate.blocked.websocket ?? 0) > 0);
      assert.ok(gate.endpoints.every(endpoint => endpoint.url.startsWith('https://lab.example.test')));
      assert.ok(!gate.endpoints.some(endpoint => /outside\.test|worker\.js|\/frame|\/sub/.test(endpoint.url)));
    } finally { await session.close(); }
  } finally { await browser.close(); await lab.close(); }
});
