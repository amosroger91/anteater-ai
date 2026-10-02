import { createHash, randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';

// Minimal, redacted, encryptable evidence (PRODUCTION_ROADMAP.md §5). Query-string values and
// sensitive headers are stripped; bodies are kept only as hashes; anything that could identify a
// test user is encrypted at rest (AES-256-GCM). Raw authenticated bodies never persist in the clear.

const DROP_HEADERS = new Set(['authorization', 'cookie', 'set-cookie', 'proxy-authorization', 'x-api-key']);

export function redactUrl(raw: string): string {
  try {
    const url = new URL(raw);
    for (const key of [...url.searchParams.keys()]) url.searchParams.set(key, 'REDACTED');
    return `${url.origin}${url.pathname}${url.search}`;
  } catch { return raw.split('?')[0] ?? raw; }
}

export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k] = DROP_HEADERS.has(k.toLowerCase()) ? 'REDACTED' : v;
  return out;
}

export const sha256 = (data: string | Buffer): string => createHash('sha256').update(data).digest('hex');

export interface EvidenceRecord {
  method: string; path: string; status: number; contentType: string;
  bodySha256: string; role: string; timestamp: string; detectorVersion: string;
}

export function preserveEvidence(input: {
  method: string; url: string; status: number; headers: Record<string, string>; body: string; role: string; detectorVersion: string;
}, now = () => new Date().toISOString()): EvidenceRecord {
  return {
    method: input.method, path: redactUrl(input.url), status: input.status,
    contentType: input.headers['content-type'] ?? input.headers['Content-Type'] ?? 'unknown',
    bodySha256: sha256(input.body), role: input.role, timestamp: now(), detectorVersion: input.detectorVersion,
  };
}

// AES-256-GCM. keyHex is 64 hex chars (32 bytes). Output: base64(iv | tag | ciphertext).
function key(keyHex: string): Buffer {
  if (!/^[0-9a-f]{64}$/i.test(keyHex)) throw new Error('evidence_key_must_be_32_bytes_hex');
  return Buffer.from(keyHex, 'hex');
}
export function encrypt(plaintext: string, keyHex: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key(keyHex), iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64');
}
export function decrypt(blob: string, keyHex: string): string {
  const raw = Buffer.from(blob, 'base64');
  const iv = raw.subarray(0, 12), tag = raw.subarray(12, 28), ct = raw.subarray(28);
  const decipher = createDecipheriv('aes-256-gcm', key(keyHex), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}
