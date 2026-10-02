import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, mkdir, lstat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DependencyCatalog, parseGitlinks, selectDependencies, sparsePatterns, validateSelectedPaths } from '../packages/shared/dependencies.js';

const exec = promisify(execFile);
const root = resolve(fileURLToPath(new URL('..',import.meta.url)));
const catalog = DependencyCatalog.parse(JSON.parse(await readFile(join(root,'dependencies/catalog.json'),'utf8')));
const [command='list',...ids] = process.argv.slice(2);
const dependencies=selectDependencies(catalog.dependencies,ids);
const emptyConfig=process.platform==='win32'?'NUL':'/dev/null';
const hooks=join(root,'.git','anteater-empty-hooks');
const git = async (args:string[],cwd=root) => (await exec('git',[
  '-c',`core.hooksPath=${hooks}`,'-c','core.symlinks=false','-c','protocol.file.allow=never',
  '-c','protocol.ext.allow=never','-c','submodule.recurse=false',...args],{
  cwd,timeout:300000,maxBuffer:8*1024*1024,windowsHide:true,
  env:{...process.env,GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:emptyConfig,GIT_CONFIG_COUNT:'0',GIT_TEMPLATE_DIR:hooks},
})).stdout.trim();

await mkdir(hooks,{recursive:true});
const pins=parseGitlinks(await git(['ls-files','--stage','--','vendor']));

async function verifyRegistry() {
  if (pins.size!==catalog.dependencies.length) throw new Error('catalog_gitlink_count_mismatch');
  const settings=(await git(['config','-f','.gitmodules','--list'])).split('\n').map(line=>{
    const equals=line.indexOf('='); return [line.slice(0,equals),line.slice(equals+1)] as const;
  });
  const configKeys=settings.map(([key])=>key);
  const config=new Map(settings);
  const expected=catalog.dependencies.flatMap(d=>['path','url','branch'].map(key=>`submodule.${d.id}.${key}`));
  if (configKeys.length!==expected.length || expected.some(key=>!configKeys.includes(key))) throw new Error('unexpected_submodule_configuration');
  for (const d of catalog.dependencies) {
    if (!pins.has(`vendor/${d.id}`)) throw new Error(`missing_pin:${d.id}`);
    for (const [key,value] of [['path',`vendor/${d.id}`],['url',d.repository],['branch',d.branch]]) {
      if (config.get(`submodule.${d.id}.${key}`)!==value) throw new Error(`submodule_configuration_mismatch:${d.id}`);
    }
  }
}

if (command==='list') {
  for (const d of dependencies) console.log(`${d.id}\t${d.category}\t${pins.get(`vendor/${d.id}`)??'unregistered'}\t${d.repository}`);
} else if (command==='check') {
  await verifyRegistry();
  console.log(`Verified ${catalog.dependencies.length} pinned, source-only web dependencies.`);
} else if (command==='sync') {
  await verifyRegistry();
  const vendor=join(root,'vendor'); await mkdir(vendor,{recursive:true});
  if ((await lstat(vendor)).isSymbolicLink()) throw new Error('vendor_symlink');
  for (const d of dependencies) {
    const directory=join(vendor,d.id); const pin=pins.get(`vendor/${d.id}`)!;
    let exists=false; let fresh=false;
    try { const stat=await lstat(directory); if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error('unsafe_dependency_path'); exists=true; }
    catch (error) { if ((error as NodeJS.ErrnoException).code!=='ENOENT') throw error; }
    if (!exists) {
      console.log(`Fetching ${d.id} source...`);
      await git(['clone','--filter=blob:none','--depth=1','--no-checkout','--branch',d.branch,'--',d.repository,directory]);
      fresh=true;
    } else {
      // Empty directories from a normal parent checkout can be initialized without deletion.
      const { readdir }=await import('node:fs/promises');
      if (!(await readdir(directory)).length) {
        await git(['clone','--filter=blob:none','--depth=1','--no-checkout','--branch',d.branch,'--',d.repository,directory]);
        fresh=true;
      }
    }
    if (await git(['remote','get-url','origin'],directory)!==d.repository) throw new Error(`origin_mismatch:${d.id}`);
    const actualTop=await git(['rev-parse','--show-prefix'],directory);
    if (actualTop) throw new Error(`not_dependency_repository:${d.id}`);
    // A fresh --no-checkout clone reports tracked files as deleted until the initial checkout.
    if (!fresh && await git(['status','--porcelain','--untracked-files=normal'],directory)) throw new Error(`dirty_dependency:${d.id}`);
    try { await git(['cat-file','-e',`${pin}^{commit}`],directory); }
    catch { await git(['fetch','--depth=1','--filter=blob:none','origin',pin],directory); }
    validateSelectedPaths(d,(await git(['ls-tree','-r','--name-only',pin],directory)).split('\n'));
    await git(['config','core.sparseCheckout','true'],directory);
    await git(['config','core.sparseCheckoutCone','false'],directory);
    const sparsePath=resolve(directory,await git(['rev-parse','--git-path','info/sparse-checkout'],directory));
    const { writeFile }=await import('node:fs/promises');
    const { dirname }=await import('node:path');
    await mkdir(dirname(sparsePath),{recursive:true});
    await writeFile(sparsePath,sparsePatterns(d));
    await git(['checkout','--detach',pin],directory);
    await git(['read-tree','-mu','HEAD'],directory);
    await git(['config','anteater.materialized','true'],directory);
    await git(['submodule','init','--',`vendor/${d.id}`]);
    await git(['submodule','absorbgitdirs','--',`vendor/${d.id}`]);
    if (await git(['rev-parse','HEAD'],directory)!==pin) throw new Error(`pin_mismatch:${d.id}`);
    console.log(`Ready ${d.id} @ ${pin.slice(0,12)} (source only)`);
  }
} else {
  throw new Error('usage: dependencies.ts list|check|sync [dependency-id ...]');
}
