import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MANUAL_ONLY_POLICY, PERMITTED_POLICY, PROHIBITED_POLICY } from '../fixtures/automation-policy.js';
import { classifyAutomation } from '../packages/program-intake/classify.js';

test('automation class follows explicit phrases and defaults to manual-only', () => {
  assert.equal(classifyAutomation(PERMITTED_POLICY), 'permitted');
  assert.equal(classifyAutomation('Automated tools allowed.'), 'permitted');
  assert.equal(classifyAutomation(MANUAL_ONLY_POLICY), 'manual-only');
  assert.equal(classifyAutomation(''), 'manual-only');
  assert.equal(classifyAutomation('   \n'), 'manual-only');
  assert.equal(classifyAutomation('Please rate limit your testing.'), 'manual-only');
  assert.equal(classifyAutomation(PROHIBITED_POLICY), 'prohibited');
  assert.equal(classifyAutomation('Do not use scanners.'), 'prohibited');
  assert.equal(classifyAutomation("Don't use scanners or any automation."), 'prohibited');
  assert.equal(classifyAutomation('Automated tools are allowed. No automated scanning of production.'), 'prohibited');
  assert.equal(classifyAutomation('We have no automated tools allowed on this program.'), 'prohibited');
  assert.equal(classifyAutomation('Automated tools are allowed only with written permission.'), 'manual-only');
  assert.equal(classifyAutomation('AUTOMATED TOOLS ARE ALLOWED.'), 'permitted');
});
