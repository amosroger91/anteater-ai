import { z } from 'zod';

const id = z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
export const DependencyCatalog = z.object({
  schemaVersion: z.literal(1),
  executionPolicy: z.literal('source-only'),
  reviewedAt: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  dependencies: z.array(z.object({
    id,
    repository: z.string().regex(/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git$/),
    branch: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._/-]*$/).refine(s => !s.includes('..') && !s.includes('//') && !s.endsWith('/')),
    category: z.enum(['guidance','web-testing','web-data','api-testing','web-development','source-analysis','password-data']),
    license: z.string().min(1),
    purpose: z.string().min(1),
    include: z.array(z.string().regex(/^\/[a-zA-Z0-9_./-]+$/).refine(s => !s.includes('..') && !s.includes('//') && !s.includes('/.git/'))),
    execution: z.literal('disabled'),
  }).strict()).min(1),
}).strict().superRefine((value, ctx) => {
  for (const field of ['id','repository'] as const) {
    const values=value.dependencies.map(d=>d[field]);
    if (new Set(values).size!==values.length) ctx.addIssue({code:'custom',message:`duplicate_${field}`});
  }
});
export type Dependency = z.infer<typeof DependencyCatalog>['dependencies'][number];

export function selectDependencies(dependencies: Dependency[], ids: string[]): Dependency[] {
  if (!ids.length) return dependencies;
  const selected=ids.map(value=>dependencies.find(d=>d.id===value));
  if (selected.some(d=>!d)) throw new Error('unknown_dependency');
  return [...new Set(selected)] as Dependency[];
}

export function sparsePatterns(dependency: Dependency): string {
  // Keep root files (licenses, manifests, entry points) and only selected subtrees.
  // Entire corpora, browser binaries, and recursive submodules are never implicitly pulled.
  return ['/*','!/*/',...dependency.include].join('\n')+'\n';
}

export function parseGitlinks(output: string): Map<string,string> {
  const entries=new Map<string,string>();
  for (const line of output.split('\n').filter(Boolean)) {
    const match=/^160000 ([a-f0-9]{40}) 0\t(vendor\/[a-z0-9-]+)$/.exec(line);
    if (!match) throw new Error('invalid_dependency_gitlink');
    entries.set(match[2]!,match[1]!);
  }
  return entries;
}

export function validateSelectedPaths(dependency: Dependency, trackedFiles: string[]): void {
  for (const selection of dependency.include) {
    const relative=selection.slice(1);
    const found=selection.endsWith('/') ? trackedFiles.some(file=>file.startsWith(relative)) : trackedFiles.includes(relative);
    if (!found) throw new Error(`missing_upstream_path:${dependency.id}:${selection}`);
  }
}
