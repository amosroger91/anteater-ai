import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderReport } from '../packages/report/index.js';
import { remediationFor } from '../packages/remediation/index.js';

test('a verified finding renders a reviewer draft and other states do not', () => {
  const finding = { id: '11111111-1111-1111-1111-111111111111', type: 'cross_account_read', location: 'https://lab.example.test/api/documents/1', severity: 'high', status: 'VERIFIED' };
  const report = renderReport(finding, { steps: [{ step: 'read', status: 200 }, { step: 'control', status: 404 }] }, remediationFor('cross_account_read'));
  assert.ok(report);
  assert.match(report, /^# cross account read/);
  assert.match(report, /## Severity\nhigh/);
  assert.match(report, /## Affected asset\nhttps:\/\/lab\.example\.test/);
  assert.match(report, /## Reproduction/);
  assert.match(report, /## Impact/);
  assert.match(report, /## Remediation/);
  assert.match(report, /object-level authorization/);
  assert.equal(report.includes('owned-marker'), false);
  const review = renderReport({ ...finding, status: 'HUMAN_REVIEW' }, { steps: [] }, remediationFor('cross_account_read'));
  assert.match(review ?? '', /## Affected asset/);
  for (const status of ['OBSERVATION', 'CANDIDATE', 'SUBMITTED', 'REJECTED']) {
    assert.equal(renderReport({ ...finding, status }, { steps: [{ step: 'read', status: 200 }] }, remediationFor('cross_account_read')), null);
  }
});
