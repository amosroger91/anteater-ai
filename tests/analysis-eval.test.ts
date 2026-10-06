import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FixtureLLM, AnalysisSchema, type LLMProvider, type LLMResponse } from '../packages/llm/index.js';
import { FROZEN_CASES, scoreProvider } from '../packages/analysis-eval/index.js';

test('the frozen set is well-formed and includes poisoned cases', () => {
  assert.ok(FROZEN_CASES.length >= 6);
  for (const c of FROZEN_CASES) assert.ok(AnalysisSchema.shape.label.options.includes(c.expectedLabel), c.name);
  assert.ok(FROZEN_CASES.some(c => c.poisoned));
});

test('fixture provider is schema-valid and grounded on every case, and injection-safe', async () => {
  const report = await scoreProvider(new FixtureLLM());
  assert.equal(report.schemaValidRate, 1);     // FixtureLLM returns a valid closed object every time
  assert.equal(report.groundingRate, 1);       // empty evidence is trivially grounded
  assert.equal(report.injectionSafe, true);    // poisoned bodies cannot escape the closed form
  assert.equal(report.poisonedContained, report.poisoned);
});

// A model that fabricates evidence not present in the input must be REJECTED (not accepted), proving
// the grounding gate counts in the score rather than being assumed.
test('ungrounded (hallucinated) evidence lowers schema-valid rate — it is rejected', async () => {
  const hallucinator: LLMProvider = {
    async generate(): Promise<LLMResponse> {
      return { text: JSON.stringify({ label: 'error_detail', evidence: ['this-string-is-not-in-the-observation'], followUp: 'human_review' }), model: 'stub' };
    },
  };
  const report = await scoreProvider(hallucinator);
  assert.equal(report.accepted, 0);            // every case rejected on the substring check
  assert.equal(report.schemaValidRate, 0);
  assert.equal(report.injectionSafe, true);    // rejected output is contained (produced nothing usable)
});

// A model that tries to break the schema (non-enum label) is rejected; poisoned cases stay contained.
test('schema-breaking output is rejected and poisoned cases remain contained', async () => {
  const breaker: LLMProvider = {
    async generate(): Promise<LLMResponse> {
      return { text: JSON.stringify({ label: 'critical', evidence: [], followUp: 'none' }), model: 'stub' };
    },
  };
  const report = await scoreProvider(breaker);
  assert.equal(report.accepted, 0);
  assert.equal(report.injectionSafe, true);
});
