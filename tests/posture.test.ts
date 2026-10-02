import { test } from 'node:test';
import assert from 'node:assert/strict';
import { addressBlockReason, canonicalTarget, checkTarget, cookieWeakness, cspFindings, findingsFromResponse, findingsFromTls, hstsFindings, type CheckDeps, type ExchangeResult, type Finding, type TlsInfo } from '../scripts/posture-check.js';
import { aggressiveOutcome, diffFindings, findingsFromNuclei, nextBaseline, nucleiArgs, parseCsv, parseRate, parseTagList, policyAllowsPosture, type Scanned } from '../scripts/posture-scan.js';
import { fixture } from '../fixtures/program.js';
import { loadConfig } from '../packages/shared/config.js';

const trusted: TlsInfo = { protocol: 'TLSv1.3', issuer: 'Example CA', subject: 'app.example', daysToExpiry: 90, selfSigned: false, authorized: true, authorizationError: null };

function harness(responses: Record<string, ExchangeResult>, addresses = [{ address: '93.184.216.34', family: 4 }], tlsInfo: TlsInfo = trusted) {
  const calls: string[] = [];
  const deps: CheckDeps = {
    async lookup() { return addresses; },
    async tls() { calls.push('tls'); return tlsInfo; },
    async exchange(url) {
      calls.push(url.href);
      const response = responses[url.href];
      if (!response) throw new Error(`unexpected ${url.href}`);
      return response;
    },
  };
  return { deps, calls };
}

test('address policy blocks loopback and link-local, and blocks private space unless asked', () => {
  assert.equal(addressBlockReason('93.184.216.34'), null);
  assert.equal(addressBlockReason('127.0.0.1', true), 'loopback');
  assert.equal(addressBlockReason('169.254.169.254', true), 'link-local');
  assert.equal(addressBlockReason('10.1.1.1'), 'private');
  assert.equal(addressBlockReason('10.1.1.1', true), null);
  assert.equal(addressBlockReason('172.16.5.5'), 'private');
  assert.equal(addressBlockReason('172.32.5.5'), null);
  assert.equal(addressBlockReason('192.168.1.1'), 'private');
  assert.equal(addressBlockReason('100.64.0.1'), 'private');
  assert.equal(addressBlockReason('0.0.0.1'), 'unspecified');
  assert.equal(addressBlockReason('224.0.0.1'), 'multicast');
  assert.equal(addressBlockReason('255.255.255.255'), 'reserved');
  assert.equal(addressBlockReason('::1', true), 'loopback');
  assert.equal(addressBlockReason('fe80::1', true), 'link-local');
  assert.equal(addressBlockReason('fd00::1'), 'private');
  assert.equal(addressBlockReason('::ffff:127.0.0.1', true), 'loopback');
  assert.equal(addressBlockReason('::ffff:7f00:1', true), 'loopback');
  assert.equal(addressBlockReason('::ffff:10.0.0.1'), 'private');
  assert.equal(addressBlockReason('::ffff:a00:1', true), null);
});

test('canonical target is one URL and rejects credentials', () => {
  const bare = canonicalTarget('Example.COM');
  const path = canonicalTarget('https://example.com/a#frag');
  assert.ok('href' in bare && bare.href === 'https://example.com/');
  assert.ok('href' in path && path.href === 'https://example.com/a');
  assert.deepEqual(canonicalTarget('https://user:secret@example.com/'), { error: 'credentials_in_url' });
});

test('hsts, csp, and every set-cookie are classified', () => {
  assert.equal(hstsFindings(null)[0]?.code, 'missing_hsts');
  assert.equal(hstsFindings('max-age=0')[0]?.code, 'hsts_disabled');
  assert.equal(hstsFindings('max-age=100')[0]?.code, 'hsts_short_max_age');
  assert.equal(hstsFindings('max-age=31536000')[0]?.code, 'hsts_host_only');
  assert.equal(hstsFindings('max-age=31536000; includeSubDomains').length, 0);
  assert.equal(cspFindings(null)[0]?.code, 'missing_csp');
  assert.equal(cspFindings("script-src *")[0]?.code, 'csp_weak');
  assert.equal(cspFindings("default-src *")[0]?.code, 'csp_weak');
  assert.equal(cspFindings("default-src 'self'").length, 0);
  assert.equal(cookieWeakness('id=1'), 'id missing secure, httponly, samesite');
  assert.equal(cookieWeakness('id=1; Secure; HttpOnly; SameSite=Lax'), null);
  const cookies = findingsFromResponse(new URL('https://app.example/'), { 'set-cookie': ['a=1; Secure; HttpOnly; SameSite=Lax', 'b=2'] });
  assert.match(cookies.find(finding => finding.code === 'weak_cookie_flags')?.detail ?? '', /b missing/);
  assert.equal(cookies.some(finding => finding.code === 'missing_hsts'), true);
});

test('a bad certificate stays reachable when the GET succeeds', async () => {
  const { deps } = harness(
    { 'https://self-signed.example/': { status: 200, headers: { 'strict-transport-security': 'max-age=31536000; includeSubDomains', 'content-security-policy': "default-src 'self'" } } },
    undefined,
    { protocol: 'TLSv1.3', issuer: 'self', subject: 'self', daysToExpiry: 10, selfSigned: true, authorized: false, authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT' },
  );
  const result = await checkTarget('https://self-signed.example', { deps });
  assert.equal(result.reachable, true);
  assert.equal(result.findings.some(finding => finding.code === 'unreachable'), false);
  assert.equal(result.findings.some(finding => finding.code === 'tls_self_signed'), true);
  assert.equal(result.findings.some(finding => finding.code === 'tls_untrusted'), false);
});

test('same-host redirect is scored on the final response only', async () => {
  const { deps, calls } = harness({
    'https://app.example/': { status: 302, headers: { location: '/login' } },
    'https://app.example/login': { status: 200, headers: { 'strict-transport-security': 'max-age=31536000; includeSubDomains', 'content-security-policy': "default-src 'self'" } },
  });
  const result = await checkTarget('https://app.example', { deps });
  assert.deepEqual(calls.filter(call => call.startsWith('https')), ['https://app.example/', 'https://app.example/login']);
  assert.equal(result.findings.some(finding => finding.code === 'missing_hsts'), false);
});

test('off-host and downgrade redirects are not followed', async () => {
  const off = harness({ 'https://app.example/': { status: 302, headers: { location: 'https://elsewhere.example/login?token=secret' } } });
  const offResult = await checkTarget('https://app.example', { deps: off.deps });
  assert.deepEqual(off.calls.filter(call => call.startsWith('https')), ['https://app.example/']);
  assert.equal(offResult.findings.find(finding => finding.code === 'redirect_off_host')?.detail, 'https://elsewhere.example/login');
  assert.equal(offResult.findings.some(finding => finding.code === 'missing_hsts'), false);

  const down = harness({ 'https://app.example/': { status: 301, headers: { location: 'http://app.example/' } } });
  const downResult = await checkTarget('https://app.example', { deps: down.deps });
  assert.deepEqual(down.calls.filter(call => call.startsWith('http')), ['https://app.example/']);
  assert.equal(downResult.findings.some(finding => finding.code === 'redirect_to_http'), true);

  const port = harness({ 'https://app.example/': { status: 302, headers: { location: 'https://app.example:8443/login' } } });
  const portResult = await checkTarget('https://app.example', { deps: port.deps });
  assert.equal(port.calls.filter(call => call.startsWith('https')).length, 1);
  assert.equal(portResult.findings.some(finding => finding.code === 'redirect_port_or_scheme_change'), true);
});

test('private and link-local answers are not contacted', async () => {
  const internal = harness({}, [{ address: '10.0.0.8', family: 4 }]);
  const blocked = await checkTarget('https://app.staging.internal', { deps: internal.deps });
  assert.deepEqual(internal.calls, []);
  assert.equal(blocked.findings[0]?.code, 'blocked_address');

  const allowed = harness({ 'https://app.staging.internal/': { status: 200, headers: {} } }, [{ address: '10.0.0.8', family: 4 }]);
  const opened = await checkTarget('https://app.staging.internal', { allowPrivate: true, deps: allowed.deps });
  assert.equal(opened.ip, '10.0.0.8');
  assert.equal(allowed.calls.includes('tls'), true);

  const linkLocal = harness({}, [{ address: '169.254.169.254', family: 4 }]);
  const metadata = await checkTarget('https://metadata.example', { allowPrivate: true, deps: linkLocal.deps });
  assert.deepEqual(linkLocal.calls, []);
  assert.equal(metadata.findings[0]?.code, 'blocked_address');
});

test('csv accepts a BOM, quoted commas, and rejects conflicting modes', () => {
  const rows = parseCsv('\uFEFFurl,mode,notes\nhttps://example.com,passive,"neutral host, demo"\n# comment\nhttps://example.com,passive,duplicate\n');
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.notes, 'neutral host, demo');
  assert.throws(() => parseCsv('url,mode,notes\nhttps://example.com,passive,a\nhttps://example.com,aggressive,b\n'), /duplicate_target_mode_conflict/);
  assert.throws(() => parseCsv('url,mode,notes\nhttps://example.com,blast,a\n'), /invalid_mode/);
});

test('rate must be a positive integer and nuclei stays on the posture allowlist', () => {
  assert.equal(parseRate('20'), 20);
  assert.throws(() => parseRate('0'), /invalid_rate/);
  assert.throws(() => parseRate('151'), /invalid_rate/);
  const args = nucleiArgs('https://example.com/', 'ssl,misconfig,exposure,tech', 'dos,intrusive,fuzz', 20);
  assert.equal(args.includes('-no-interactsh'), true);
  assert.equal(args.includes('-follow-host-redirects'), true);
  assert.equal(args.includes('-follow-redirects'), false);
  assert.equal(args[args.indexOf('-tags') + 1], 'ssl,misconfig,exposure,tech');
  assert.throws(() => parseTagList('dos', 'tags'), /unsafe_tags/);
  assert.throws(() => parseTagList('ssl,headless', 'tags'), /unsafe_tags/);
});

test('posture policy authorization fails closed outside the reviewed scope', () => {
  const config=loadConfig({GLOBAL_KILL_SWITCH:'false'});
  assert.equal(policyAllowsPosture(fixture.policy,'https://api.example.test',config),true);
  assert.equal(policyAllowsPosture(fixture.policy,'https://payments.example.test',config),false);
});

test('nuclei JSONL survives a non-zero exit and an empty failure does not', () => {
  const findings = findingsFromNuclei('not json\n{"template-id":"tls-missing","info":{"severity":"medium"},"matched-at":"https://example.com/"}\n', 'https://example.com/');
  assert.equal(findings[0]?.code, 'tls-missing');
  const recovered = aggressiveOutcome('{"template-id":"tls-missing","info":{"severity":"low"}}\n', 'exit 1', 'https://example.com/', '1');
  assert.equal(recovered.failed, false);
  assert.equal(recovered.findings[0]?.code, 'tls-missing');
  const failed = aggressiveOutcome('', 'template load failed', 'https://example.com/', '1');
  assert.equal(failed.failed, true);
  assert.equal(failed.findings[0]?.detail, 'template load failed');
  assert.equal(aggressiveOutcome('', '', 'https://example.com/', 'ENOENT').findings[0]?.detail, 'nuclei_not_installed');
});

test('severity changes are visible and a held row does not wipe the baseline', () => {
  const previous: Finding[] = [{ code: 'missing_hsts', severity: 'low', detail: 'old' }];
  const current: Finding[] = [{ code: 'missing_hsts', severity: 'medium', detail: 'no Strict-Transport-Security' }];
  const diff = diffFindings(previous, current);
  assert.equal(diff.changed[0]?.code, 'missing_hsts');
  assert.equal(diff.added.length, 0);
  assert.equal(diffFindings(undefined, current).added.length, 0);

  const executed: Scanned = { target: 'https://example.com/', origin: 'https://example.com', ip: '1.1.1.1', reachable: true, findings: current, checkedAt: 't', mode: 'passive', executed: true, notes: 'demo' };
  const held: Scanned = { target: 'https://example.com/', origin: 'https://example.com', ip: null, reachable: false, findings: [], checkedAt: 't2', mode: 'aggressive', executed: false, notes: 'held' };
  const baseline = nextBaseline([executed], [held]);
  assert.equal(baseline.length, 1);
  assert.equal(baseline[0]?.findings[0]?.code, 'missing_hsts');
  assert.equal(nextBaseline([executed], []).length, 0);
});

test('untrusted CA and hostname mismatch stay distinct', () => {
  assert.equal(findingsFromTls({ ...trusted, authorized: false, authorizationError: 'unable to get local issuer certificate' })[0]?.code, 'tls_untrusted');
  assert.equal(findingsFromTls({ ...trusted, authorized: false, authorizationError: "Hostname does not match certificate's altnames" }).some(finding => finding.code === 'tls_name_mismatch'), true);
  assert.equal(findingsFromTls({ ...trusted, protocol: 'TLSv1.1', daysToExpiry: -2 }).some(finding => finding.code === 'tls_outdated_protocol'), true);
  assert.equal(findingsFromTls({ ...trusted, protocol: 'TLSv1.1', daysToExpiry: -2 }).some(finding => finding.code === 'tls_expired'), true);
});
