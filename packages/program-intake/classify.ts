// Program automation class (BOUNTY_EARNINGS_PLAN.md Phase 1.2). Explicit phrases only.
// A rate-limit sentence is not permission. Ambiguous text stays manual-only, and any
// prohibition wins over a permission phrase in the same policy.

export type AutomationClass = 'permitted' | 'manual-only' | 'prohibited';

const PROHIBITED = [
  'no automated',
  'do not use scanners',
  'dont use scanners',
  'do not use automated',
  'dont use automated',
  'do not scan',
  'dont scan',
  'no scanners',
  'scanners are prohibited',
  'scanning is prohibited',
  'scanning is not allowed',
  'automated scanning is prohibited',
  'automated tools are prohibited',
  'automated testing is prohibited',
  'automated tools are not allowed',
  'automated tools are not permitted',
  'automation is prohibited',
  'automation is not allowed',
  'automation is not permitted',
  'use of automated tools is prohibited',
  'use of automated tools is not permitted',
  'use of scanners is prohibited',
];

const PERMITTED = [
  'automated tools allowed',
  'automated tools are allowed',
  'automated tools are permitted',
  'automation is allowed',
  'automation is permitted',
  'automated scanning is allowed',
  'automated scanning is permitted',
  'you may use automated tools',
  'scanners are allowed',
  'scanners are permitted',
  'use of automated tools is permitted',
  'use of automated tools is allowed',
];

// A permission phrase that is immediately qualified is not a grant.
const QUALIFIER = /^(?:only|except|with prior|with written|after approval|if approved)\b/;

function normalize(policyText: string): string {
  return policyText.toLowerCase().replace(/['’]/g, '').replace(/[^a-z0-9]+/g, ' ').replace(/ +/g, ' ').trim();
}

function hasPhrase(text: string, phrase: string): boolean {
  return ` ${text} `.includes(` ${phrase} `);
}

function permits(text: string, phrase: string): boolean {
  const padded = ` ${text} `;
  const needle = ` ${phrase} `;
  let from = 0;
  while (from < padded.length) {
    const at = padded.indexOf(needle, from);
    if (at < 0) return false;
    if (!QUALIFIER.test(padded.slice(at + needle.length))) return true;
    from = at + needle.length;
  }
  return false;
}

export function classifyAutomation(policyText: string): AutomationClass {
  const text = normalize(policyText);
  if (PROHIBITED.some(phrase => hasPhrase(text, phrase))) return 'prohibited';
  if (PERMITTED.some(phrase => permits(text, phrase))) return 'permitted';
  return 'manual-only';
}
