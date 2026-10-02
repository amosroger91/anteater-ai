import { z } from 'zod';

const bool = (fallback: string) => z.enum(['true', 'false']).default(fallback as 'true' | 'false').transform(v => v === 'true');
const schema = z.object({
  DATABASE_URL: z.string().url().refine(v => /^postgres(ql)?:/.test(v)).default('postgresql://anteater:local-fixture-only@127.0.0.1:55432/anteater'),
  GLOBAL_KILL_SWITCH: bool('true'),
  REQUIRE_SCOPE: z.literal('true').default('true'),
  REQUIRE_PROGRAM_POLICY: z.literal('true').default('true'),
  ALLOW_ACTIVE_TESTING: bool('false'),
  ENABLE_PASSIVE_HTTP: bool('false'),
  PROGRAM_SOURCE: z.enum(['fixture', 'file']).default('fixture'),
  PROGRAMS_FILE: z.string().min(1).optional(),
  MAX_CONCURRENT_JOBS: z.coerce.number().int().min(1).max(16).default(1),
  MAX_RESPONSE_BYTES: z.coerce.number().int().min(1024).max(1048576).default(65536),
  MAX_REQUEST_RATE: z.coerce.number().positive().max(10).default(1),
  JOB_LEASE_SECONDS: z.coerce.number().int().min(5).max(300).default(30),
  PROGRAMS_DIR: z.string().min(1).default('programs'),
  OLLAMA_URL: z.string().url().default('http://127.0.0.1:11434').refine(v => {
    const u = new URL(v);
    return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname) && !u.username && !u.password && u.pathname === '/' && !u.search && !u.hash;
  }, 'Local loopback Ollama endpoint required'),
  LLM_MODEL: z.string().min(1).default('qwen3:4b'),
  LLM_PROVIDER: z.enum(['fixture', 'ollama']).default('fixture'),
  OLLAMA_MODEL_DIGEST: z.string().regex(/^sha256:[a-f0-9]{64}$/i).optional(),
});
export const loadConfig = (env: NodeJS.ProcessEnv = process.env) => schema.parse(env);
export type Config = ReturnType<typeof loadConfig>;
