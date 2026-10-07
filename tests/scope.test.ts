import { test } from 'node:test';
import assert from 'node:assert/strict';
import { authorize, authorizeActive } from '../packages/scope-engine/index.js';
import { loadConfig } from '../packages/shared/config.js';
import { fixture } from '../fixtures/program.js';
const config=loadConfig({GLOBAL_KILL_SWITCH:'false'});
test('authorized subdomain is allowed',()=>assert.equal(authorize(fixture.policy,'https://api.example.test','inspect_http_target',config).allowed,true));
for (const url of ['https://payments.example.test','https://example.test','https://evil-example.test','https://example.test.evil.test','https://unknown.test','http://api.example.test','https://api.example.test:8443','https://user@api.example.test','https://api.example.test/path','https://api.example.test?next=evil','https://api.example.test.','https://127.0.0.1','https://2130706433','https://[::1]','https://%61pi.example.test','https://api.example.test\\@evil.test','https://API.example.test','https://xn--x.example.test']) {
  test(`blocks ${url}`,()=>assert.equal(authorize(fixture.policy,url,'inspect_http_target',config).allowed,false));
}
test('kill switch defaults closed',()=>assert.equal(authorize(fixture.policy,'https://api.example.test','inspect_http_target',loadConfig({})).reason,'kill_switch'));
for (const policy of [undefined,{}, {...fixture.policy,allowed:['*']},{...fixture.policy,allowed:['*.test/path']},{...fixture.policy,reviewed:false},{...fixture.policy,expiresAt:'2000-01-01T00:00:00Z'},{...fixture.policy,unexpected:true}]) {
  test('missing, malformed, expired or unreviewed policy fails closed',()=>assert.equal(authorize(policy,'https://api.example.test','inspect_http_target',config).allowed,false));
}
test('unsupported action stays denied with active flag on',()=>assert.equal(authorize(fixture.policy,'https://api.example.test','shell', {...config,ALLOW_ACTIVE_TESTING:true}).allowed,false));
test('excluded wildcard takes precedence',()=>assert.equal(authorize({...fixture.policy,excluded:['*.example.test']},'https://api.example.test','inspect_http_target',config).allowed,false));
test('exact hostname scope does not permit subdomains',()=>assert.equal(authorize({...fixture.policy,allowed:['api.example.test']},'https://sub.api.example.test','inspect_http_target',config).allowed,false));
test('configuration rejects misspelled booleans, disabling authorization and bad limits',()=>{
  for(const env of [{GLOBAL_KILL_SWITCH:'False'},{REQUIRE_SCOPE:'false'},{REQUIRE_PROGRAM_POLICY:'false'},{MAX_REQUEST_RATE:'0'},{MAX_CONCURRENT_JOBS:'NaN'},{OLLAMA_URL:'https://external.test'}]) assert.throws(()=>loadConfig(env));
});

// Active-probe authorization (injection suite): parameterized requests bounded by HOST scope, gated by
// ALLOW_ACTIVE_TESTING, while the passive invariants above are unchanged.
const activeConfig = loadConfig({ GLOBAL_KILL_SWITCH: 'false', ALLOW_ACTIVE_TESTING: 'true' });
const activePolicy = { ...fixture.policy, allowedActions: [...fixture.policy.allowedActions, 'probe_sqli'] };
test('active probe on an in-scope host with a query string is allowed when active testing is on', () =>
  assert.equal(authorizeActive(activePolicy, 'https://api.example.test/search?q=1', 'probe_sqli', activeConfig).allowed, true));
test('active probe reaches a non-allowlisted path (host scope, not the passive path allowlist)', () =>
  assert.equal(authorizeActive(activePolicy, 'https://api.example.test/admin/users?id=1', 'probe_sqli', activeConfig).allowed, true));
test('active probe is denied when ALLOW_ACTIVE_TESTING is off', () =>
  assert.equal(authorizeActive(activePolicy, 'https://api.example.test/search?q=1', 'probe_sqli', loadConfig({ GLOBAL_KILL_SWITCH: 'false' })).reason, 'active_testing_disabled'));
test('active probe denied when the program does not permit that action', () =>
  assert.equal(authorizeActive(fixture.policy, 'https://api.example.test/search?q=1', 'probe_sqli', activeConfig).reason, 'prohibited_action'));
test('active probe stays bounded by host scope and exclusions', () => {
  assert.equal(authorizeActive(activePolicy, 'https://evil.test/search?q=1', 'probe_sqli', activeConfig).allowed, false);
  assert.equal(authorizeActive({ ...activePolicy, excluded: ['*.example.test'] }, 'https://api.example.test/x?q=1', 'probe_sqli', activeConfig).reason, 'excluded');
  assert.equal(authorizeActive(activePolicy, 'https://api.example.test/x?q=1', 'probe_sqli', loadConfig({ ALLOW_ACTIVE_TESTING: 'true' })).reason, 'kill_switch');
});
test('passive authorize still rejects a query string; the active relaxation is separate', () =>
  assert.equal(authorize(activePolicy, 'https://api.example.test/x?q=1', 'inspect_http_target', activeConfig).allowed, false));
