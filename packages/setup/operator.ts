import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { loadConfig, type Config } from '../shared/config.js';
import { windowsKeyProtector } from './dpapi.js';
import { applyProfile } from './profile.js';
import { FileSetupStore, setupDirectory } from './store.js';

// Operator commands pick up the local setup file. Tests and verify:local pass a plain env,
// or set ANTEATER_USE_SETUP=false, and keep the committed defaults.
export function loadOperatorConfig(env: NodeJS.ProcessEnv = process.env): Config {
  if (env.ANTEATER_USE_SETUP === 'false') return loadConfig(env);
  const directory = setupDirectory(env);
  if (!existsSync(join(directory, 'setup.json'))) return loadConfig(env);
  const profile = new FileSetupStore(directory, windowsKeyProtector).read();
  if (!profile) return loadConfig(env);
  return loadConfig(applyProfile(env, profile));
}
