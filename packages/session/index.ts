// Session validation and auth-gap classification (PRODUCTION_ROADMAP.md §2), deterministic core.
// A 200 or the login form disappearing does NOT prove identity: a stable account marker must be
// observed. Blocked auth conditions become per-domain coverage GAPS, never bypass attempts.

export interface IdentitySignal { status: number; body: string; url: string }
export interface IdentityMarker { bodyIncludes?: string; urlIncludes?: string }

export function identityConfirmed(signal: IdentitySignal, marker: IdentityMarker): boolean {
  if (signal.status >= 400) return false;
  const byBody = marker.bodyIncludes ? signal.body.includes(marker.bodyIncludes) : false;
  const byUrl = marker.urlIncludes ? signal.url.includes(marker.urlIncludes) : false;
  // Require at least one explicit marker; status alone is never sufficient.
  return byBody || byUrl;
}

export type AuthGap = 'mfa' | 'captcha' | 'sso' | 'consent' | 'blocked_signup' | 'expired_secret' | 'lockout' | 'none';

const GAP_SIGNS: Array<[AuthGap, RegExp]> = [
  ['mfa', /\b(mfa|two[- ]?factor|2fa|one[- ]?time (code|password)|authenticator)\b/i],
  ['captcha', /\b(captcha|recaptcha|hcaptcha|are you (a )?human)\b/i],
  ['sso', /\b(single sign[- ]?on|sso|saml|continue with (google|github|okta|microsoft))\b/i],
  ['consent', /\b(accept (all )?cookies|consent|gdpr|privacy preferences)\b/i],
  ['blocked_signup', /\b(registration (is )?(disabled|closed)|invite[- ]only|signups? (are )?disabled)\b/i],
  ['expired_secret', /\b(session expired|token expired|please log ?in again|credentials expired)\b/i],
  ['lockout', /\b(account (is )?locked|too many attempts|temporarily (locked|blocked))\b/i],
];

// Classify a blocked-auth signal into a coverage gap. Callers REPORT the gap and move on; they never
// attempt to bypass MFA/CAPTCHA/SSO, and one blocked domain must not stop the rest of the campaign.
export function classifyAuthGap(text: string): AuthGap {
  for (const [gap, re] of GAP_SIGNS) if (re.test(text)) return gap;
  return 'none';
}
