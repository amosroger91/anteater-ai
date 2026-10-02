import { open } from 'node:fs/promises';
import { z } from 'zod';
import { fixture } from '../../fixtures/program.js';
import { PolicySchema, targetForAction, authorize } from '../scope-engine/index.js';

const AssetSchema = z.object({
  id: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  url: z.string().url(),
}).strict();

export const ProgramSchema = z.object({
  id: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  name: z.string().min(1).max(200),
  platform: z.string().min(1).max(80),
  programUrl: z.string().url(),
  categories: z.array(z.string().min(1).max(80)).max(50),
  policy: PolicySchema,
  assets: z.array(AssetSchema).min(1).max(1000),
}).strict().superRefine((program, ctx) => {
  if (program.policy.programId !== program.id) ctx.addIssue({ code: 'custom', path: ['policy', 'programId'], message: 'policy programId must match program id' });
  const ids = new Set<string>();
  for (const asset of program.assets) {
    if (ids.has(asset.id)) ctx.addIssue({ code: 'custom', path: ['assets'], message: `duplicate asset id: ${asset.id}` });
    ids.add(asset.id);
    try {
      const target = targetForAction(asset.url, 'inspect_http_target');
      const checkPolicy = { ...program.policy, allowedActions: ['inspect_http_target'], allowedPaths: ['/'] };
      if (!authorize(checkPolicy, target, 'inspect_http_target', { GLOBAL_KILL_SWITCH: false }).allowed) throw new Error('invalid_asset');
    } catch { ctx.addIssue({ code: 'custom', path: ['assets'], message: 'assets must be canonical HTTPS origins inside unexpired reviewed scope' }); }
  }
});

export type Program = z.infer<typeof ProgramSchema>;
export interface BountyProvider { discover(): Promise<readonly Program[]> }

// The fixture is deliberately retained as the safe default. Discovery data never implies authorization.
export class FixtureProvider implements BountyProvider {
  async discover(): Promise<readonly Program[]> { return [ProgramSchema.parse(structuredClone(fixture))]; }
}

/** Load reviewed program manifests from an operator-controlled file. No URL fetching occurs here. */
export class FileProgramProvider implements BountyProvider {
  constructor(private file: string, private maxPrograms = 100) {}

  async discover(): Promise<readonly Program[]> {
    const handle = await open(this.file, 'r');
    let content: string;
    try {
      const buffer = Buffer.alloc(1048577);
      let size = 0;
      while (size < buffer.length) {
        const { bytesRead } = await handle.read(buffer, size, buffer.length - size, null);
        if (!bytesRead) break;
        size += bytesRead;
      }
      if (size > 1048576) throw new Error('program_manifest_too_large');
      content = buffer.subarray(0, size).toString('utf8');
    } finally { await handle.close(); }
    const raw: unknown = JSON.parse(content);
    const values = Array.isArray(raw) ? raw : (raw && typeof raw === 'object' && 'programs' in raw ? (raw as { programs?: unknown }).programs : undefined);
    if (!Array.isArray(values) || values.length === 0 || values.length > this.maxPrograms) throw new Error('invalid_program_manifest');
    const programs = values.map(value => ProgramSchema.parse(value));
    const ids = new Set(programs.map(program => program.id));
    if (ids.size !== programs.length) throw new Error('duplicate_program_id');
    const assets = programs.flatMap(program => program.assets.map(asset => asset.id));
    if (new Set(assets).size !== assets.length) throw new Error('duplicate_asset_id');
    return programs;
  }
}
