import { z } from 'zod';

// API surface inventory (PRODUCTION_ROADMAP.md §4). Bounded parsing of OpenAPI and GraphQL
// introspection plus observed links. Remote $ref fetching is rejected (SSRF/scope risk); parsing is
// size- and count-bounded. Pure and deterministic.

const MAX_OPS = 5000;
export interface Endpoint { method: string; path: string; source: 'openapi' | 'graphql' | 'observed' }

const METHODS = new Set(['get', 'put', 'post', 'delete', 'patch', 'head', 'options', 'trace']);

export function parseOpenApi(doc: unknown): Endpoint[] {
  const text = JSON.stringify(doc);
  if (text.length > 5_000_000) throw new Error('openapi_too_large');
  // Reject remote references outright; only local (#/...) refs are allowed.
  if (/"\$ref"\s*:\s*"https?:\/\//i.test(text)) throw new Error('remote_ref_rejected');
  const parsed = z.object({ paths: z.record(z.string(), z.record(z.string(), z.unknown())).optional() }).passthrough().safeParse(doc);
  if (!parsed.success || !parsed.data.paths) return [];
  const out: Endpoint[] = [];
  for (const [path, item] of Object.entries(parsed.data.paths)) {
    for (const method of Object.keys(item)) {
      if (METHODS.has(method.toLowerCase())) out.push({ method: method.toUpperCase(), path, source: 'openapi' });
      if (out.length >= MAX_OPS) return out;
    }
  }
  return out;
}

export function parseGraphQLIntrospection(doc: unknown): Endpoint[] {
  const parsed = z.object({ data: z.object({ __schema: z.object({
    queryType: z.object({ name: z.string() }).nullish(),
    mutationType: z.object({ name: z.string() }).nullish(),
    types: z.array(z.object({ name: z.string(), fields: z.array(z.object({ name: z.string() })).nullish() })).default([]),
  }) }) }).safeParse(doc);
  if (!parsed.success) return [];
  const schema = parsed.data.data.__schema;
  const out: Endpoint[] = [];
  for (const kind of [schema.queryType, schema.mutationType]) {
    if (!kind) continue;
    const type = schema.types.find(t => t.name === kind.name);
    for (const field of type?.fields ?? []) {
      out.push({ method: kind === schema.mutationType ? 'MUTATION' : 'QUERY', path: field.name, source: 'graphql' });
      if (out.length >= MAX_OPS) return out;
    }
  }
  return out;
}

export function observedEndpoints(paths: string[]): Endpoint[] {
  return paths.filter(p => p.startsWith('/')).slice(0, MAX_OPS).map(path => ({ method: 'GET', path, source: 'observed' as const }));
}

export function mergeInventory(...groups: Endpoint[][]): Endpoint[] {
  const seen = new Map<string, Endpoint>();
  for (const e of groups.flat()) { const key = `${e.method} ${e.path}`; if (!seen.has(key)) seen.set(key, e); }
  return [...seen.values()].sort((a, b) => `${a.path} ${a.method}`.localeCompare(`${b.path} ${b.method}`));
}
