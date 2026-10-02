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
};

const FALLBACK: Remediation = { summary: 'Reviewed finding.', fix: 'See the mapped methodology entry for guidance.', reference: 'OWASP WSTG/ASVS' };

export function remediationFor(code: string): Remediation {
  return GUIDANCE[code] ?? FALLBACK;
}
