import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { LLMProvider, LLMResponse } from '../packages/llm/index.js';
import { FixtureLLM } from '../packages/llm/index.js';
import { runAgent, planFollowUps, researchCatalog, type AgentExecutor, type AgentActionDef } from '../packages/agent/index.js';

// A scripted model that returns a fixed sequence of JSON replies.
function scriptedModel(replies: string[]): LLMProvider {
  let i = 0;
  return { async generate(): Promise<LLMResponse> { return { text: replies[Math.min(i++, replies.length - 1)] ?? '{}', model: 'scripted' }; } };
}

const policy = {
  programId: 'p', revision: 'r', sourceUrl: 'https://example.test/policy', reviewed: true as const,
  expiresAt: '2099-01-01T00:00:00Z', allowed: ['*.example.test'], excluded: [],
  allowedActions: ['inspect_http_target', 'inspect_robots', 'inspect_sitemap', 'inspect_openapi'],
  allowedPaths: ['/', '/robots.txt', '/sitemap.xml', '/.well-known/openapi.json'],
  schemes: ['https'], ports: [443], requestsPerSecond: 1,
};

const catalog: AgentActionDef[] = researchCatalog();

test('the agent loop runs model-chosen catalog actions through the scope gate, then stops', async () => {
  const calls: string[] = [];
  const executor: AgentExecutor = async (id, action) => { calls.push(id); return { ran: action }; };
  const model = scriptedModel(['{"actionId":"robots"}', '{"actionId":"nope"}', '{"actionId":"openapi"}', '{"actionId":"stop"}']);
  const result = await runAgent({ host: 'api.example.test', policy, catalog, model, executor, maxSteps: 10 });
  assert.equal(result.stopped, 'model_stop');
  assert.deepEqual(calls, ['robots', 'openapi']);          // the invalid "nope" id was ignored, loop continued
  assert.ok(result.steps.every(s => s.authorized));         // only scope-authorized actions executed
});

test('an action the policy forbids is recorded unauthorized and never executed', async () => {
  const calls: string[] = [];
  const executor: AgentExecutor = async (id) => { calls.push(id); return {}; };
  // Catalog offers an action the policy does not allow (research_application is not in allowedActions).
  const withDenied: AgentActionDef[] = [...catalog, { id: 'app', action: 'research_application', description: 'full app research' }];
  const model = scriptedModel(['{"actionId":"app"}', '{"actionId":"stop"}']);
  const result = await runAgent({ host: 'api.example.test', policy, catalog: withDenied, model, executor });
  const step = result.steps.find(s => s.actionId === 'app');
  assert.equal(step?.authorized, false);
  assert.equal(step?.reason, 'prohibited_action');
  assert.equal(calls.length, 0);                            // the gate blocked it; executor never called
});

test('the loop is budget-bounded even if the model never says stop', async () => {
  const executor: AgentExecutor = async () => ({});
  const model = scriptedModel(['{"actionId":"robots"}']);  // always picks robots, never stops
  const result = await runAgent({ host: 'api.example.test', policy, catalog, model, executor, maxSteps: 3 });
  assert.equal(result.stopped, 'budget_exhausted');
  assert.equal(result.steps.length, 3);
});

test('planFollowUps maps model-chosen ids to actions and drops anything off-catalog', async () => {
  const model = scriptedModel(['{"actionIds":["openapi","bogus","robots"]}']);
  const actions = await planFollowUps(model, { kind: 'OBSERVATION', status: 200, contentType: 'application/json' });
  assert.deepEqual(actions, ['inspect_openapi', 'inspect_robots']);  // bogus dropped, order preserved, deduped
});

test('planFollowUps returns nothing for a non-conforming model (safe default)', async () => {
  const actions = await planFollowUps(new FixtureLLM(), { kind: 'OBSERVATION', status: 200 });
  assert.deepEqual(actions, []);  // FixtureLLM returns an analysis object, not actionIds -> no follow-ups
});
