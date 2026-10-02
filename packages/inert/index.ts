// Keep observed content inert and keep secrets out of model context (PRODUCTION_ROADMAP.md §7).
// Page/tool output is untrusted data: scripts and event handlers are stripped before it is shown or
// summarized, and anything secret-shaped is redacted before any text can enter a model prompt.

export function sanitize(html: string): string {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/\son\w+\s*=\s*"[^"]*"/gi, '')
    .replace(/\son\w+\s*=\s*'[^']*'/gi, '')
    .replace(/\son\w+\s*=\s*[^\s>]+/gi, '')
    .replace(/javascript:/gi, 'blocked:');
}

const SECRET_PATTERNS: Array<[string, RegExp]> = [
  ['aws_access_key', /\bAKIA[0-9A-Z]{16}\b/g],
  ['private_key', /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/g],
  ['bearer_token', /\bBearer\s+[A-Za-z0-9._-]{12,}/gi],
  ['password_assignment', /\b(?:password|passwd|secret|api[_-]?key)\s*[:=]\s*\S+/gi],
  ['jwt', /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g],
];

export interface ContextGuard { safe: boolean; redacted: string; hits: string[] }

// Redact secret-shaped content before text enters a model prompt. Returns the redacted text and
// which patterns fired, so a caller can refuse to send if anything matched.
export function guardModelContext(text: string): ContextGuard {
  let redacted = text;
  const hits: string[] = [];
  for (const [name, pattern] of SECRET_PATTERNS) {
    if (pattern.test(redacted)) { hits.push(name); redacted = redacted.replace(pattern, `[REDACTED:${name}]`); }
    pattern.lastIndex = 0;
  }
  return { safe: hits.length === 0, redacted, hits };
}
