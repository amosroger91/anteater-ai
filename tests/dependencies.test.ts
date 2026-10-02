import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { DependencyCatalog, parseGitlinks, selectDependencies, sparsePatterns, validateSelectedPaths } from '../packages/shared/dependencies.js';

const raw=JSON.parse(await readFile(new URL('../dependencies/catalog.json',import.meta.url),'utf8'));
const catalog=DependencyCatalog.parse(raw);
test('catalog is non-executable, unique, web-focused and uses public GitHub HTTPS origins',()=>{
  assert.ok(catalog.dependencies.length>=25);
  assert.equal(catalog.executionPolicy,'source-only');
  for (const d of catalog.dependencies) assert.equal(d.execution,'disabled');
});
test('catalog rejects executable, credential-bearing or unsafe source declarations',()=>{
  for (const changes of [
    {id:'../escape'}, {repository:'file:///tmp/repository'}, {repository:'https://user:token@github.com/a/b.git'},
    {repository:'https://github.com.evil.test/a/b.git'}, {execution:'enabled'},
    {branch:'--upload-pack=evil'}, {include:['/../../escape']}, {include:['/foo\n/*']},
  ]) assert.equal(DependencyCatalog.safeParse({...raw,dependencies:[{...raw.dependencies[0],...changes}]}).success,false);
  assert.equal(DependencyCatalog.safeParse({...raw,dependencies:[raw.dependencies[0],raw.dependencies[0]]}).success,false);
});
test('password data is deliberately sparse and cannot change execution policy',()=>{
  const d=catalog.dependencies.find(d=>d.id==='seclists')!;
  const patterns=sparsePatterns(d);
  assert.match(patterns,/Passwords\/Common-Credentials\/10k-most-common.txt/);
  assert.ok(!d.include.includes('/Passwords/'));
  assert.ok(!d.include.some(p=>p.includes('Web-Shells')));
});
test('selection rejects unknown dependencies before any sync',()=>{
  assert.throws(()=>selectDependencies(catalog.dependencies,['seclists','../bad']),/unknown_dependency/);
  assert.equal(selectDependencies(catalog.dependencies,['seclists','seclists']).length,1);
});
test('only pinned stage-zero gitlinks can represent dependencies',()=>{
  const sha='a'.repeat(40);
  assert.equal(parseGitlinks(`160000 ${sha} 0\tvendor/seclists`).get('vendor/seclists'),sha);
  for (const input of [`100644 ${sha} 0\tvendor/seclists`,`160000 main 0\tvendor/seclists`,`160000 ${sha} 1\tvendor/seclists`,`160000 ${sha} 0\tvendor/../bad`]) assert.throws(()=>parseGitlinks(input));
});
test('upstream directory moves or removed wordlists cannot silently produce empty imports',()=>{
  const dep={...catalog.dependencies[0]!,include:['/src/','/words.txt']};
  assert.doesNotThrow(()=>validateSelectedPaths(dep,['src/index.ts','words.txt']));
  assert.throws(()=>validateSelectedPaths(dep,['src/index.ts','other.txt']),/missing_upstream_path/);
  assert.throws(()=>validateSelectedPaths(dep,['src-other/index.ts','words.txt']),/missing_upstream_path/);
});
