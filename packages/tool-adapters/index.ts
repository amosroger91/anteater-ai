import { isAbsolute } from 'node:path';

// Pinned tool-adapter framework (PRODUCTION_ROADMAP.md §4). No arbitrary shell, no unrestricted
// template set, no imported tool becomes callable automatically. Each adapter declares the env var
// holding its ABSOLUTE binary path, a fixed argument builder, and a pinned version/template hash.
// This module only builds and validates invocations; it never executes anything.

export interface AdapterSpec {
  id: string;
  binEnv: string;                 // env var that must hold an absolute path to the binary
  version: string;                // pinned, recorded on every run
  templateHash?: string;          // pinned template-set hash where applicable
  buildArgs: (input: Record<string, string>) => string[];
}

export interface ResolvedInvocation { id: string; bin: string; args: string[]; version: string; templateHash?: string }

export function resolveInvocation(spec: AdapterSpec, input: Record<string, string>, env: NodeJS.ProcessEnv = process.env): ResolvedInvocation {
  const bin = env[spec.binEnv];
  if (!bin) throw new Error(`tool_binary_unset:${spec.binEnv}`);
  if (!isAbsolute(bin)) throw new Error(`tool_binary_must_be_absolute:${spec.binEnv}`);
  const args = spec.buildArgs(input);
  // No argument may smuggle a shell metacharacter; adapters pass argv arrays to execFile, never a shell string.
  for (const a of args) if (/[;&|`$><\n]/.test(a)) throw new Error(`unsafe_argument:${spec.id}`);
  return { id: spec.id, bin, args, version: spec.version, templateHash: spec.templateHash };
}

// Built-in pinned adapters. Dangerous template classes are excluded by construction.
export const NUCLEI: AdapterSpec = {
  id: 'nuclei', binEnv: 'NUCLEI_BIN', version: 'pinned-by-operator',
  buildArgs: (i) => ['-u', i.url ?? '', '-jsonl', '-silent', '-disable-update-check', '-no-interactsh',
    '-exclude-tags', i.excludeTags ?? 'dos,intrusive,fuzz', '-rate-limit', i.rate ?? '20', '-timeout', '10'],
};

export const REGISTRY: Record<string, AdapterSpec> = { nuclei: NUCLEI };

export function getAdapter(id: string): AdapterSpec {
  const spec = REGISTRY[id];
  if (!spec) throw new Error(`unknown_adapter:${id}`);
  return spec;
}
