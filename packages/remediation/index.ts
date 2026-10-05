// Remediation guidance generated from the finding code + methodology (PRODUCTION_ROADMAP.md §5).
// Deterministic lookup; reviewer-editable. No model text, no severity claims — just the fix.

export interface Remediation { summary: string; fix: string; reference: string }

const GUIDANCE: Record<string, Remediation> = {
  missing_security_headers: { summary: 'Response lacks baseline security headers.', fix: 'Set HSTS, CSP, X-Content-Type-Options: nosniff, X-Frame-Options/frame-ancestors, and Referrer-Policy at the edge.', reference: 'OWASP ASVS V14.4' },
  missing_csp: { summary: 'No Content-Security-Policy.', fix: "Add a restrictive CSP (start with default-src 'self') and tighten per route.", reference: 'OWASP ASVS V14.4.3' },
  missing_hsts: { summary: 'HSTS not enforced.', fix: 'Send Strict-Transport-Security: max-age=63072000; includeSubDomains on all HTTPS responses.', reference: 'OWASP WSTG-CONF-07' },
  cors_wildcard_with_credentials: { summary: 'CORS allows any origin with credentials.', fix: 'Reflect only an explicit allow-list of origins; never combine Access-Control-Allow-Origin: * with credentials.', reference: 'OWASP WSTG-CLNT' },
  sensitive_response_cacheable: { summary: 'Sensitive response is cacheable.', fix: 'Set Cache-Control: no-store (or private) on authenticated responses.', reference: 'OWASP WSTG-ATHN' },
  open_redirect: { summary: 'Redirect target is attacker-controllable.', fix: 'Allow redirects only to a server-side allow-list of paths/hosts; reject absolute off-site targets.', reference: 'OWASP WSTG-CLNT-04' },
  weak_cookie_flags: { summary: 'Session cookie missing security attributes.', fix: 'Set Secure, HttpOnly and SameSite on session cookies.', reference: 'OWASP WSTG-SESS-02' },
  tls_outdated_protocol: { summary: 'Outdated TLS protocol negotiated.', fix: 'Disable TLS 1.0/1.1; require TLS 1.2+ with modern ciphers.', reference: 'OWASP WSTG-CRYP-01' },
  cross_account_read: { summary: 'A user can read another account’s resource.', fix: 'Enforce object-level authorization on every read; derive ownership server-side, never from client input.', reference: 'OWASP WSTG-ATHZ / ASVS V4' },
  subdomain_takeover: { summary: 'A dangling name serves an unclaimed-service page.', fix: 'Remove the dangling DNS record or claim the service. Do not leave a CNAME pointed at an unclaimed name.', reference: 'OWASP WSTG-CONF-10' },
  exposed_vcs: { summary: 'A source-control or environment file is served.', fix: 'Stop publishing /.git, /.env, and /.DS_Store. Rotate any credential that was in the file.', reference: 'OWASP WSTG-CONF-04' },
  exposed_admin: { summary: 'A privileged admin or debug page is public.', fix: 'Require authentication on admin, debug, and actuator routes, or remove them from the public host.', reference: 'OWASP WSTG-CONF-05' },
  cors_credentialed: { summary: 'Credentialed CORS reflects another origin.', fix: 'Allow credentials only for an explicit origin allow-list. Do not copy the request Origin into Access-Control-Allow-Origin.', reference: 'OWASP WSTG-CLNT-07' },
  open_redirect_to_takeover: { summary: 'An auth or token route redirects off the request host.', fix: 'Keep login, OAuth, and token redirects on a server-side allow-list of same-host paths.', reference: 'OWASP WSTG-CLNT-04' },
  secrets_in_js: { summary: 'Served JavaScript matches a live-looking key pattern.', fix: 'Remove the key from client code, rotate it, and load secrets only on the server.', reference: 'OWASP WSTG-INFO-05' },
};

const FALLBACK: Remediation = { summary: 'Reviewed finding.', fix: 'See the mapped methodology entry for guidance.', reference: 'OWASP WSTG/ASVS' };

export function remediationFor(code: string): Remediation {
  return GUIDANCE[code] ?? FALLBACK;
}
