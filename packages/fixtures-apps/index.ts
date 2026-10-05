import type { HttpResponseView } from '../web-checks/index.js';
import type { Responder } from '../findings/index.js';

// Versioned local vulnerable/patched fixtures (PRODUCTION_ROADMAP.md §0). Every detector must flag
// the vulnerable variant and pass the patched one before release; these are the offline corpus CI
// and the detector gate run against. No network, no real targets.

export type Variant = 'vulnerable' | 'patched';

const SECURE_HEADERS = {
  'strict-transport-security': 'max-age=63072000', 'content-security-policy': "default-src 'self'",
  'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer',
};

// §4 header / CORS / cache / redirect / cookie response fixtures.
export function responseFixture(scenario: 'headers' | 'cors' | 'cache' | 'redirect' | 'cookie' | 'takeover' | 'vcs' | 'admin' | 'cors-credentialed' | 'auth-redirect' | 'js-secret', variant: Variant): HttpResponseView {
  const secure = variant === 'patched';
  switch (scenario) {
    case 'headers':
      return { status: 200, body: 'ok', headers: secure ? { ...SECURE_HEADERS } : {} };
    case 'cors':
      return { status: 200, body: 'ok', headers: secure ? { 'access-control-allow-origin': 'https://app.example.test' } : { 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' } };
    case 'cache':
      return { status: 200, body: 'secret', sensitive: true, headers: secure ? { 'cache-control': 'no-store' } : { 'cache-control': 'public, max-age=3600' } };
    case 'redirect':
      return { status: 302, body: '', requestHost: 'app.example.test', headers: { location: secure ? 'https://app.example.test/home' : 'https://evil.test/phish' } };
    case 'cookie':
      return { status: 200, body: 'ok', headers: { 'set-cookie': secure ? 'sid=1; Secure; HttpOnly; SameSite=Lax' : 'sid=1' } };
    case 'takeover':
      return { status: 404, body: secure ? 'not found' : 'NoSuchBucket: The specified bucket does not exist', requestHost: 'app.example.test', cname: 'unclaimed.example.test', headers: {} };
    case 'vcs':
      return { status: secure ? 404 : 200, body: secure ? 'not found' : '[core]\n\trepositoryformatversion = 0\n', path: '/.git/config', headers: {} };
    case 'admin':
      return { status: secure ? 404 : 200, body: secure ? 'not found' : '{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"}}}', path: '/actuator', headers: {} };
    case 'cors-credentialed':
      return { status: 200, body: 'ok', requestHost: 'app.example.test', requestOrigin: secure ? 'https://app.example.test' : 'https://evil.test', headers: { 'access-control-allow-origin': secure ? 'https://app.example.test' : 'https://evil.test', 'access-control-allow-credentials': 'true' } };
    case 'auth-redirect':
      return { status: 302, body: '', path: '/login', requestHost: 'app.example.test', headers: { location: secure ? 'https://app.example.test/home' : 'https://evil.test/phish' } };
    case 'js-secret':
      return { status: 200, body: secure ? 'const key = "not-a-key";' : 'const key = "AKIA1234567890ABCDEF";', path: '/app.js', headers: { 'content-type': 'application/javascript' } };
  }
}

// §2/§5 access-control fixtures. The ATTACK is "a stranger reads the victim's resource": the bug is
// present when that returns the secret. The control ("stranger reads a properly-protected resource")
// must stay denied (403) so we know the stranger session is genuinely unprivileged. A vulnerable app
// leaks the victim resource to the stranger; a patched app denies it.
export function accessControlResponder(variant: Variant): Responder {
  return async (stepId: string) => {
    if (stepId === 'stranger-reads-control') return { status: 403, body: 'forbidden' };
    // stepId === 'stranger-reads-victim'
    return variant === 'patched' ? { status: 403, body: 'forbidden' } : { status: 200, body: '{"data":"secret-token"}' };
  };
}

export const ACCESS_CONTROL_CONTRACT = {
  findingType: 'cross_account_read',
  steps: [{ id: 'stranger-reads-victim', expectStatus: 200, expectBodyIncludes: ['secret-token'] }],
  counterTest: { id: 'stranger-reads-control', expectStatus: 403 },
  repeatCount: 2,
};

// §4 API inventory fixture: a small OpenAPI document.
export function openApiFixture() {
  return {
    openapi: '3.0.0', info: { title: 'fixture', version: '1' },
    paths: {
      '/users': { get: {}, post: {} },
      '/users/{id}': { get: {}, delete: {} },
      '/login': { post: {} },
    },
  };
}
