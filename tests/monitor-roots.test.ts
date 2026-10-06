import { test } from 'node:test';
import assert from 'node:assert/strict';
import { wildcardApexes } from '../packages/discovery/monitor.js';

test('enrolled wildcards enumerate their apex and concrete hosts are not discovery roots', () => {
  assert.deepEqual(wildcardApexes(['app.example.test', '*.example.test', '*.cdn.example.test']), ['cdn.example.test', 'example.test']);
  assert.deepEqual(wildcardApexes(['app.example.test']), []);
  assert.deepEqual(wildcardApexes(['*.', '*.xn--80ak6aa92e.test']), []);
});
