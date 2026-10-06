import { z } from 'zod';

// Operator setup. This is not a program approval and it does not disable the kill switch.
const hostName = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const handle = z.string().regex(/^[a-z0-9]+(?:[-_][a-z0-9]+)*$/);
const hexKey = z.string().regex(/^[a-f0-9]{64}$/);
const orEmpty = (schema: z.ZodString) => z.union([z.literal(''), schema]);

export const SetupProfileSchema = z.object({
  approver: z.string().trim().max(200).default(''),
  hackeroneUsername: z.string().trim().max(80).default(''),
  hackeroneToken: orEmpty(z.string().min(8).max(200).regex(/^\S+$/)).default(''),
  labHosts: z.string().default(''),
  allowPrivateLabTargets: z.boolean().default(false),
  accountKey: orEmpty(hexKey).default(''),
  evidenceKey: orEmpty(hexKey).default(''),
  mailboxHost: z.string().default(''),
  mailboxUsername: z.string().trim().max(200).default(''),
  mailboxPassword: z.string().max(200).default(''),
  mailboxDomain: z.string().default(''),
}).strict();
export type SetupProfile = z.infer<typeof SetupProfileSchema>;

export const SetupRequestSchema = SetupProfileSchema.extend({
  clearHackeroneToken: z.boolean().default(false),
  clearMailboxPassword: z.boolean().default(false),
  clearAccountKey: z.boolean().default(false),
  clearEvidenceKey: z.boolean().default(false),
}).strict();
export type SetupRequest = z.infer<typeof SetupRequestSchema>;

export function blankProfile(): SetupProfile {
  return SetupProfileSchema.parse({});
}

export function normalizeLabHosts(raw: string): string {
  const parts = raw.split(',').map(part => part.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean);
  if (parts.some(part => part.includes('xn--') || !hostName.test(part))) throw new Error('invalid_lab_host');
  return [...new Set(parts)].join(',');
}

function normalizeHost(raw: string, code: string): string {
  const host = raw.trim().toLowerCase().replace(/\.$/, '');
  if (!host) return '';
  if (host.includes('xn--') || !hostName.test(host)) throw new Error(code);
  return host;
}

export function normalizeProfile(input: SetupProfile): SetupProfile {
  const profile: SetupProfile = {
    approver: input.approver.trim(),
    hackeroneUsername: input.hackeroneUsername.trim().toLowerCase(),
    hackeroneToken: input.hackeroneToken,
    labHosts: normalizeLabHosts(input.labHosts),
    allowPrivateLabTargets: input.allowPrivateLabTargets,
    accountKey: input.accountKey,
    evidenceKey: input.evidenceKey,
    mailboxHost: normalizeHost(input.mailboxHost, 'invalid_mailbox_host'),
    mailboxUsername: input.mailboxUsername.trim(),
    mailboxPassword: input.mailboxPassword,
    mailboxDomain: normalizeHost(input.mailboxDomain, 'invalid_mailbox_domain'),
  };
  if (profile.approver && profile.approver.length < 2) throw new Error('invalid_approver');
  if (profile.hackeroneUsername && !handle.safeParse(profile.hackeroneUsername).success) throw new Error('invalid_hackerone_username');
  if (profile.allowPrivateLabTargets && !profile.labHosts) throw new Error('lab_hosts_required');
  const mailbox = [profile.mailboxHost, profile.mailboxUsername, profile.mailboxDomain];
  const mailboxFilled = mailbox.filter(Boolean).length;
  if (mailboxFilled !== 0 && mailboxFilled !== mailbox.length) throw new Error('mailbox_incomplete');
  if (profile.mailboxPassword && mailboxFilled !== mailbox.length) throw new Error('mailbox_incomplete');
  return SetupProfileSchema.parse(profile);
}

export function mergeProfile(previous: SetupProfile, request: SetupRequest): SetupProfile {
  return normalizeProfile({
    ...request,
    hackeroneToken: request.clearHackeroneToken ? '' : (request.hackeroneToken || previous.hackeroneToken),
    mailboxPassword: request.clearMailboxPassword ? '' : (request.mailboxPassword || previous.mailboxPassword),
    accountKey: request.clearAccountKey ? '' : (request.accountKey || previous.accountKey),
    evidenceKey: request.clearEvidenceKey ? '' : (request.evidenceKey || previous.evidenceKey),
  });
}

export interface SetupStatus {
  approver: string;
  hackeroneUsername: string;
  hackeroneTokenSaved: boolean;
  accountKeySaved: boolean;
  evidenceKeySaved: boolean;
  labHosts: string;
  allowPrivateLabTargets: boolean;
  mailboxHost: string;
  mailboxUsername: string;
  mailboxPasswordSaved: boolean;
  mailboxDomain: string;
  keysReady: boolean;
  labReady: boolean;
  programReady: boolean;
}

export function profileStatus(profile: SetupProfile | null): SetupStatus {
  const current = profile ?? blankProfile();
  const keysReady = current.accountKey.length > 0 && current.evidenceKey.length > 0;
  return {
    approver: current.approver,
    hackeroneUsername: current.hackeroneUsername,
    hackeroneTokenSaved: current.hackeroneToken.length > 0,
    accountKeySaved: current.accountKey.length > 0,
    evidenceKeySaved: current.evidenceKey.length > 0,
    labHosts: current.labHosts,
    allowPrivateLabTargets: current.allowPrivateLabTargets,
    mailboxHost: current.mailboxHost,
    mailboxUsername: current.mailboxUsername,
    mailboxPasswordSaved: current.mailboxPassword.length > 0,
    mailboxDomain: current.mailboxDomain,
    keysReady,
    labReady: keysReady && current.labHosts.length > 0,
    programReady: keysReady && current.approver.length >= 2 && current.hackeroneUsername.length > 0 && current.hackeroneToken.length > 0,
  };
}

// Explicit environment values win. The kill switch is not a stored field.
export function applyProfile(env: NodeJS.ProcessEnv, profile: SetupProfile): NodeJS.ProcessEnv {
  const next: NodeJS.ProcessEnv = { ...env };
  const set = (key: string, value: string) => {
    if (!value || next[key] !== undefined) return;
    next[key] = value;
  };
  set('ACCOUNT_KEY', profile.accountKey);
  set('EVIDENCE_KEY', profile.evidenceKey);
  set('LAB_TARGET_HOSTS', profile.labHosts);
  if (profile.allowPrivateLabTargets) set('ALLOW_PRIVATE_LAB_TARGETS', 'true');
  set('MAILBOX_USERNAME', profile.mailboxUsername);
  set('MAILBOX_PASSWORD', profile.mailboxPassword);
  set('HACKERONE_USERNAME', profile.hackeroneUsername);
  set('HACKERONE_API_TOKEN', profile.hackeroneToken);
  set('ANTEATER_APPROVER', profile.approver);
  return next;
}
