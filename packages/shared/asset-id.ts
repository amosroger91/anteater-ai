import { createHash } from 'node:crypto';

// Dots and hyphens are meaningful hostname characters. Hash the full program/host
// tuple rather than flattening labels; keep a short prefix for readable exports.
export function assetIdForHost(host: string, programId: string): string {
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(programId)) throw new Error('invalid_program_id');
  const canonical = host.toLowerCase().replace(/\.$/, '');
  if (canonical.length > 253 || canonical.includes('xn--') ||
    !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(canonical)) {
    throw new Error('invalid_asset_host');
  }
  const digest = createHash('sha256').update(JSON.stringify([programId, canonical])).digest('hex');
  return `asset-${programId.slice(0, 40).replace(/-+$/, '')}-${digest}`;
}
