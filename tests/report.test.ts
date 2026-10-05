import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderReport } from '../packages/report/index.js';
import { remediationFor } from '../packages/remediation/index.js';

test('a review report names impact, reproduction, and remediation without copying a marker', () => {
  const report = renderReport(
    { id: '11111111-1111-1111-1111-111111111111', type: 'cross_account_read', location: 'https://lab.example.test/api/documents/1', severity: 'high' },
    { steps: [{ step: 'read', status: 200 }, { step: 'control', status: 404 }] },
    remediationFor('cross_account_read'),
  );
  assert.match(report, /## Impact/);
  assert.match(report, /## Reproduction/);
  assert.match(report, /## Remediation/);
  assert.match(report, /object-level authorization/);
  assert.equal(report.includes('owned-marker'), false);
});
