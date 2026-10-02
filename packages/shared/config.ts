import { z } from 'zod';

const bool = (fallback: string) => z.enum(['true', 'false']).default(fallback as 'true' | 'false').transform(v => v === 'true');
const schema = z.object({
  DATABASE_URL: z.string().url().refine(v => /^postgres(ql)?:/.test(v)).default('postgresql://anteater:local-fixture-only@127.0.0.1:55432/anteater'),
  GLOBAL_KILL_SWITCH: bool('true'),
  REQUIRE_SCOPE: z.literal('true').default('true'),
  REQUIRE_PROGRAM_POLICY: z.literal('true').default('true'),
  ALLOW_ACTIVE_TESTING: bool('false'),
  MAX_CONCURRENT_JOBS: z.coerce.number().int().min(1).max(16).default(1),
  MAX_REQUEST_RATE: z.coerce.number().positive().max(10).default(1),
  JOB_LEASE_SECONDS: z.coerce.number().int().min(5).max(300).default(30),
  PROGRAMS_DIR: z.string().min(1).default('programs'),
  OLLAMA_URL: z.string().url().default('http://127.0.0.1:11434').refine(v => {
    const u = new URL(v);
    return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname) && !u.username && !u.password && u.pathname === '/' && !u.search && !u.hash;
  }, 'Local loopback Ollama endpoint required'),
  LLM_MODEL: z.string().min(1).default('qwen3:4b'),
});
export const loadConfig = (env: NodeJS.ProcessEnv = process.env) => schema.parse(env);
export type Config = ReturnType<typeof loadConfig>;
