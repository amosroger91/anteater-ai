import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assetIdForHost } from '../packages/shared/asset-id.js';

test('hostname labels and program boundaries cannot collapse into one asset ID', () => {
  assert.notEqual(assetIdForHost('a.b-c.test', 'first'), assetIdForHost('a-b.c.test', 'first'));
  assert.notEqual(assetIdForHost('a.b-c.test', 'first'), assetIdForHost('a.b-c.test', 'second'));
  assert.equal(assetIdForHost('A.B-C.TEST.', 'first'), assetIdForHost('a.b-c.test', 'first'));
  assert.match(assetIdForHost('a.b-c.test', 'first'), /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
});

test('asset IDs reject URLs and invalid hostnames instead of normalizing into a target', () => {
  for (const host of ['https://example.test', 'example.test/path', 'example..test', '-bad.test']) {
    assert.throws(() => assetIdForHost(host, 'first'), /invalid_asset_host/);
  }
  assert.throws(() => assetIdForHost('example.test', 'bad/id'), /invalid_program_id/);
});
