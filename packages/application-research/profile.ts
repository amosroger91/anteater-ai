import { z } from 'zod';

export const safePath = z.string().max(512).regex(/^\/[A-Za-z0-9._~/{}/-]*$/)
  .refine(value => !value.includes('//') && !value.split('/').some(part => part === '.' || part === '..'));
const envName = z.string().regex(/^[A-Z][A-Z0-9_]{0,100}$/);
export const MailboxSchema = z.object({
  host: z.string().regex(/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i), port: z.number().int().min(1).max(65535).default(993),
  usernameEnv: envName, passwordEnv: envName, folder: z.string().default('INBOX'),
  emailDomain: z.string().regex(/^[a-z0-9.-]+\.[a-z]{2,}$/),
  timeoutSeconds: z.number().int().min(1).max(120).default(45),
}).strict();
export const AuthSchema = z.object({
  loginPath: safePath.optional(), signupPath: safePath.optional(),
  loginWritePaths: z.array(safePath).max(30).default(['/login', '/signin', '/api/login']),
  signupWritePaths: z.array(safePath).max(30).default(['/register', '/signup', '/api/register']),
  verificationPaths: z.array(safePath).max(20).default(['/verify', '/verify-email']),
  accounts: z.array(z.object({ id: z.string().regex(/^[a-z0-9-]+$/), usernameEnv: envName, passwordEnv: envName }).strict()).max(2).default([]),
  signupEnabled: z.boolean().default(false), mailbox: MailboxSchema.optional(),
  sessionPath: safePath.optional(), identityPointer: z.string().startsWith('/').default('/email'),
}).strict();
export const ApplicationSchema = z.object({
  readPathPrefixes: z.array(safePath).min(1).max(100).default(['/']),
  excludedPaths: z.array(safePath).max(100).default(['/logout', '/signout', '/delete', '/unsubscribe']),
  maxPages: z.number().int().min(1).max(100).default(12),
  maxDepth: z.number().int().min(0).max(5).default(2),
  maxRequests: z.number().int().min(5).max(2000).default(150),
  maxDurationSeconds: z.number().int().min(10).max(1800).default(180),
  maxResponseBytes: z.number().int().min(1024).max(2097152).default(524288),
  auth: AuthSchema.default(() => AuthSchema.parse({})),
  privateResources: z.array(z.object({
    name: z.string().min(1).max(80), createPath: safePath,
    readPath: safePath.refine(value => value.includes('{id}')),
    idPointer: z.string().startsWith('/').default('/id'), markerField: z.string().regex(/^[a-zA-Z][a-zA-Z0-9_]*$/).default('title'),
    markerPointer: z.string().startsWith('/').default('/title'),
    body: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])).default({}),
    // Cleanup must be possible even when create succeeds but returns an unreadable/malformed ID.
    // The unique marker is known before creation, so the executor can always attempt an owner-bound delete.
    ownerOnly: z.literal(true), cleanupPath: safePath.refine(value => value.includes('{marker}')),
  }).strict()).max(5).default([]),
}).strict();
export type Application = z.infer<typeof ApplicationSchema>;
export type Auth = z.infer<typeof AuthSchema>;
export type Mailbox = z.infer<typeof MailboxSchema>;
// "/" is only the root document. Any other prefix also covers its children.
export const underPath = (path: string, prefix: string) => path === prefix || (prefix !== '/' && path.startsWith(prefix.endsWith('/') ? prefix : prefix + '/'));
const MUTATING_GET = /^(?:logout|signout|log-out|sign-out|delete|remove|unsubscribe|purchase|checkout|reset|deauth)/i;
export const mutatingGet = (path: string) => path.split('/').some(part => part.length > 0 && MUTATING_GET.test(part));
export function jsonPointer(value: unknown, pointer: string): unknown {
  return pointer.split('/').slice(1).reduce<unknown>((current, part) => {
    const key = part.replaceAll('~1', '/').replaceAll('~0', '~');
    return current && typeof current === 'object' && Object.hasOwn(current, key) ? (current as Record<string, unknown>)[key] : undefined;
  }, value);
}
