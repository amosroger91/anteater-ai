import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { loadConfig, type Config } from '../shared/config.js';
import { windowsKeyProtector } from './dpapi.js';
import { applyProfile } from './profile.js';
import { FileSetupStore, setupDirectory, type KeyProtector } from './store.js';

// Operator commands pick up the local setup file. Tests and verify:local pass a plain env,
// or set ANTEATER_USE_SETUP=false, and keep the committed defaults.
export function loadOperatorEnvironment(env: NodeJS.ProcessEnv = process.env, keys: KeyProtector = windowsKeyProtector): NodeJS.ProcessEnv {
  if (env.ANTEATER_USE_SETUP === 'false') return { ...env };
  const directory = setupDirectory(env);
  if (!existsSync(join(directory, 'setup.json'))) return { ...env };
  const profile = new FileSetupStore(directory, keys).read();
  return profile ? applyProfile(env, profile) : { ...env };
}

// Credential consumers receive the resolved environment explicitly. Config deliberately
// excludes mailbox/API credentials so serializing ordinary configuration cannot expose them.
export function loadOperatorConfig(env: NodeJS.ProcessEnv = process.env): Config {
  return loadConfig(loadOperatorEnvironment(env));
}
