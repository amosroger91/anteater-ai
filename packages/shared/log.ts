// Structured metadata only. Never log prompts, URLs with query strings, credentials, or raw tool output.
export function log(event: string, fields: { program?: string; job?: string; asset?: string; result?: string; durationMs?: number } = {}) {
  console.log(JSON.stringify({ timestamp: new Date().toISOString(), event, ...fields }));
}
