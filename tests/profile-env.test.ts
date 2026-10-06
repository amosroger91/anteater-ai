import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyProfile, type SetupProfile } from '../packages/setup/profile.js';

const profile = {
  approver: 'Roger', hackeroneUsername: 'ciberpirata', hackeroneToken: 'tok',
  accountKey: '', evidenceKey: '', labHosts: '', allowPrivateLabTargets: false,
  mailboxUsername: '', mailboxPassword: '', mailboxHost: '', mailboxDomain: '',
} as unknown as SetupProfile;

test('applyProfile populates both HackerOne username env names and the token', () => {
  const env = applyProfile({}, profile);
  assert.equal(env.HACKERONE_USERNAME, 'ciberpirata');
  assert.equal(env.HACKERONE_API_USERNAME, 'ciberpirata'); // the alias preflight + intake:h1 read
  assert.equal(env.HACKERONE_API_TOKEN, 'tok');
});

test('applyProfile never overwrites a value already in the environment', () => {
  const env = applyProfile({ HACKERONE_API_USERNAME: 'preset' }, profile);
  assert.equal(env.HACKERONE_API_USERNAME, 'preset');
});
