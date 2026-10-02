import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyApproval, sha256Hex } from '../packages/provenance/index.js';

const source = 'Scope: *.example.test; excludes payments.example.test';
const approval = {
  approver: 'alice@kscomputing', sourceUrl: 'https://example.test/policy', sourceSha256: sha256Hex(source),
  approvedAt: '2026-01-01T00:00:00Z', revision: 'r1', expiresAt: '2099-01-01T00:00:00Z',
};

test('a valid approval verifies against the exact reviewed source', () => {
  assert.deepEqual(verifyApproval(approval, source), { ok: true, reason: 'approved' });
});

test('a changed source invalidates the approval (re-review required)', () => {
  assert.equal(verifyApproval(approval, source + ' and also *.evil.test').reason, 'source_hash_mismatch');
});

test('expired or malformed approvals fail closed', () => {
  assert.equal(verifyApproval({ ...approval, expiresAt: '2000-01-01T00:00:00Z' }, source).reason, 'approval_expired');
  assert.equal(verifyApproval({ approver: '' }, source).reason, 'invalid_approval_record');
});
