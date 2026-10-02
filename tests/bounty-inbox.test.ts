import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertDumpUrl, dumpUrl, isExcluded, mergeProgram, mergeScanCsv, normalizeProgram, promotionRows, promotableUrl, refreshInbox, reviewAsset, upsertProgram, emptyInbox, type InboxProgram } from '../scripts/bounty-inbox.js';
import { parseCsv } from '../scripts/posture-scan.js';

const fetchedAt = '2026-10-02T00:00:00.000Z';

const hackerone = {
  handle: 'Example',
  name: 'Example Program',
  url: 'https://hackerone.com/example',
  offers_bounties: true,
  submission_state: 'open',
  targets: {
    in_scope: [
      { asset_identifier: 'api.example.com', asset_type: 'URL', max_severity: 'critical', instruction: 'No automated scanning of checkout.' },
      { asset_identifier: '*.example.com', asset_type: 'WILDCARD', instruction: 'Do not expand this.' },
      { asset_identifier: 'https://example.com/only-this-path', asset_type: 'URL' },
      { asset_identifier: 'https://www.example.com/', asset_type: 'URL' },
    ],
    out_of_scope: [
      { asset_identifier: 'payments.example.com', asset_type: 'URL', instruction: 'Out of scope.' },
    ],
  },
};

function program(): InboxProgram {
  return normalizeProgram('hackerone', hackerone, fetchedAt);
}

test('one named program keeps exclusions beside the hosts and does not expand wildcards', () => {
  const stored = program();
  assert.equal(stored.handle, 'example');
  assert.equal(stored.open, true);
  assert.equal(stored.assets.filter(asset => asset.inScope).length, 4);
  assert.equal(stored.assets.some(asset => asset.identifier === 'payments.example.com' && !asset.inScope), true);
  assert.equal(promotableUrl('api.example.com', ['payments.example.com']), 'https://api.example.com/');
  assert.equal(promotableUrl('*.example.com', []), null);
  assert.equal(promotableUrl('https://example.com/only-this-path', []), null);
  assert.equal(promotableUrl('payments.example.com', ['payments.example.com']), null);
  assert.equal(isExcluded('a.payments.example.com', ['*.payments.example.com']), true);
  assert.equal(promotionRows([stored]).length, 0);
});

test('review is per exact host and promotion writes passive rows only', () => {
  let stored = program();
  assert.throws(() => reviewAsset(stored, '*.example.com', true), /asset_not_promotable/);
  assert.throws(() => reviewAsset(stored, 'payments.example.com', true), /asset_out_of_scope/);
  assert.throws(() => reviewAsset(stored, 'other.example.net', true), /asset_not_in_program/);
  stored = reviewAsset(stored, 'api.example.com', true);
  stored = reviewAsset(stored, 'https://www.example.com/', true);
  const rows = promotionRows([stored]);
  assert.deepEqual(rows.map(row => row.url), ['https://api.example.com/', 'https://www.example.com/']);
  assert.equal(rows.every(row => row.mode === 'passive'), true);
  const csv = mergeScanCsv('url,mode,notes\nhttps://api.example.com/,aggressive,already there\n', rows);
  const parsed = parseCsv(csv);
  assert.equal(parsed.length, 2);
  assert.equal(parsed.find(row => row.url === 'https://api.example.com/')?.mode, 'aggressive');
  assert.equal(parsed.some(row => row.url === 'https://www.example.com/' && row.mode === 'passive'), true);
});

test('refresh preserves review, drops it when scope changes, and ignores other programs', () => {
  const reviewed = reviewAsset(program(), 'api.example.com', true);
  const incoming = normalizeProgram('hackerone', hackerone, '2026-10-02T01:00:00.000Z');
  const merged = mergeProgram(reviewed, incoming);
  assert.equal(merged.assets.find(asset => asset.identifier === 'api.example.com')?.reviewed, true);
  assert.equal(merged.assets.find(asset => asset.identifier === 'https://www.example.com/')?.reviewed, false);

  const moved = structuredClone(hackerone);
  moved.targets.in_scope = moved.targets.in_scope.filter(asset => asset.asset_identifier !== 'api.example.com');
  moved.targets.out_of_scope.push({ asset_identifier: 'api.example.com', asset_type: 'URL', instruction: 'Now excluded.' });
  const cleared = mergeProgram(reviewed, normalizeProgram('hackerone', moved, fetchedAt));
  assert.equal(cleared.assets.find(asset => asset.identifier === 'api.example.com')?.reviewed, false);

  const inbox = upsertProgram(emptyInbox(), reviewed);
  const dump = [hackerone, { ...hackerone, handle: 'other', name: 'Other' }];
  const refreshed = refreshInbox(inbox, new Map([['hackerone', dump]]), fetchedAt);
  assert.equal(refreshed.programs.length, 1);
  assert.equal(refreshed.programs[0]?.handle, 'example');
});

test('a closed program and the inbox file itself cannot feed the scanner', () => {
  const closed = normalizeProgram('hackerone', { ...hackerone, submission_state: 'paused' }, fetchedAt);
  const reviewed = reviewAsset({ ...closed, open: true }, 'api.example.com', true);
  assert.equal(promotionRows([{ ...reviewed, open: false }]).length, 0);
  const inbox = { schema: 1, programs: [reviewed] };
  assert.throws(() => parseCsv(JSON.stringify(inbox, null, 2)), /csv_missing_url_column/);
  assert.equal(dumpUrl('hackerone'), 'https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/hackerone_data.json');
  assert.throws(() => assertDumpUrl('https://example.test/domains.txt'), /unexpected_dump_url/);
  assert.throws(() => upsertProgram({ schema: 1, programs: Array.from({ length: 25 }, (_, index) => ({ ...program(), handle: `p${index}` })) }, { ...program(), handle: 'extra' }), /inbox_full/);
});
