import { mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { z } from 'zod';
import { PolicySchema, authorize } from '../../packages/scope-engine/index.js';
import { executePassiveHttp, type PassiveOptions } from '../../packages/web-executor/index.js';
import { coverageForTarget } from '../../packages/coverage/index.js';
import { remediationFor } from '../../packages/remediation/index.js';

export const AssessmentInput = z.object({
  name: z.string().trim().min(1).max(80), targets: z.array(z.string().trim().min(1).max(253)).min(1).max(25),
  sourceUrl: z.string().url().max(2048), expiresAt: z.iso.datetime(), reviewed: z.literal(true),
}).strict();
export type AssessmentInput = z.infer<typeof AssessmentInput>;
type Status = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'interrupted';
export interface Target {
  url: string; status: Status; httpStatus?: number; error?: string; bodySha256?: string;
  findings: Array<{ code: string; severity: string; detail: string; fix: string }>;
  coverage?: ReturnType<typeof coverageForTarget>;
}
export interface Assessment {
  id: string; name: string; demo: boolean; createdAt: string; finishedAt?: string; status: Status;
  sourceUrl: string; expiresAt: string; targets: Target[];
}
type Executor = (target: string, options: PassiveOptions) => Promise<Record<string, unknown>>;
const signalSchema = z.object({ code: z.string().max(100), severity: z.enum(['info', 'low', 'medium', 'high', 'critical']), detail: z.string().max(1024) });

export class DashboardService {
  enabled = false;
  readonly assessments = new Map<string, Assessment>();
  private controller?: AbortController;
  private active?: string;
  private task?: Promise<void>;
  private storageError?: string;
  constructor(readonly directory: string, private executor: Executor = executePassiveHttp, private delayMs = 1100) {}
  async init() {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const names = (await readdir(this.directory)).filter(name => /^[a-f0-9-]{36}\.json$/.test(name));
    if (names.length > 100) throw new Error('assessment_history_limit');
    for (const name of names) {
      const assessment = JSON.parse(await readFile(join(this.directory, name), 'utf8')) as Assessment;
      if (assessment.id + '.json' !== name || !Array.isArray(assessment.targets)) throw new Error('invalid_assessment_file');
      if (assessment.status === 'running' || assessment.status === 'queued') {
        assessment.status = 'interrupted'; assessment.finishedAt = new Date().toISOString();
        for (const target of assessment.targets) if (['running', 'queued'].includes(target.status)) target.status = 'interrupted';
        await this.save(assessment);
      }
      this.assessments.set(assessment.id, assessment);
    }
  }
  state() {
    return { enabled: this.enabled, active: this.active ?? null, storageError: this.storageError ?? null,
      assessments: [...this.assessments.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt)) };
  }
  setEnabled(value: boolean) { this.enabled = value; if (!value) this.controller?.abort(); }
  cancel(id: string) { if (this.active === id) this.controller?.abort(); }
  async close() { this.setEnabled(false); await this.task; }
  async start(raw: unknown, demo = false) {
    if (this.active) throw new Error('assessment_already_running');
    if (this.storageError) throw new Error('assessment_storage_failed');
    if (this.assessments.size >= 100) throw new Error('assessment_history_limit');
    if (!demo && !this.enabled) throw new Error('passive_requests_disabled');
    const input = AssessmentInput.parse(raw);
    const urls = [...new Set(input.targets.map(target => {
      const candidate = target.startsWith('https://') ? target : `https://${target}`;
      if (!/^https:\/\/[a-z0-9.-]+\/?$/.test(candidate)) throw new Error('enter_exact_https_hosts');
      const url = new URL(candidate);
      if (url.hostname !== candidate.slice(8).replace(/\/$/, '')) throw new Error('invalid_target');
      return url.origin + '/';
    }))];
    const policy = PolicySchema.parse({ programId: 'dashboard', revision: randomUUID(), sourceUrl: input.sourceUrl,
      reviewed: true, expiresAt: input.expiresAt, allowed: urls.map(url => new URL(url).hostname), excluded: [],
      allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1 });
    for (const url of urls) if (!authorize(policy, url, 'inspect_http_target', { GLOBAL_KILL_SWITCH: false }).allowed) throw new Error('target_or_policy_denied');
    const assessment: Assessment = { id: randomUUID(), name: input.name, demo, status: 'queued', createdAt: new Date().toISOString(),
      sourceUrl: input.sourceUrl, expiresAt: input.expiresAt, targets: urls.map(url => ({ url, status: 'queued', findings: [] })) };
    // Reserve before the first await so simultaneous requests cannot start two campaigns.
    this.active = assessment.id; this.controller = new AbortController();
    try { await this.save(assessment); }
    catch (error) { this.active = undefined; this.controller = undefined; throw error; }
    this.assessments.set(assessment.id, assessment);
    const controller = this.controller!;
    this.task = this.run(assessment, policy, controller).catch(() => {
      this.storageError = 'Results could not be saved. Live requests are disabled; check the data directory.';
      this.enabled = false; assessment.status = 'interrupted'; controller.abort();
    }).finally(() => { this.active = undefined; this.controller = undefined; });
    return assessment.id;
  }
  async demo() {
    return this.start({ name: 'Sample web assessment', targets: ['app.example.test', 'api.example.test', 'legacy.example.test'],
      sourceUrl: 'https://example.test/owned-lab', expiresAt: '2099-01-01T00:00:00Z', reviewed: true }, true);
  }
  private async run(assessment: Assessment, policy: z.infer<typeof PolicySchema>, controller: AbortController) {
    const signal = controller.signal;
    assessment.status = 'running'; await this.save(assessment);
    for (const [index, target] of assessment.targets.entries()) {
      if (signal.aborted) break;
      target.status = 'running'; await this.save(assessment);
      try {
        const beforeRequest = async () => {
          signal.throwIfAborted();
          if (!authorize(policy, target.url, 'inspect_http_target', { GLOBAL_KILL_SWITCH: !this.enabled }).allowed) throw new Error('policy_expired_or_requests_disabled');
        };
        let observation: Record<string, unknown>;
        if (assessment.demo) {
          await sleep(this.delayMs, undefined, { signal });
          observation = index === 2 ? { error: 'certificate_expired' } : { status: 200, contentType: 'text/html', signals: index === 0
            ? [{ code: 'missing_hsts', severity: 'medium', detail: 'Strict-Transport-Security was not present.' }, { code: 'missing_csp', severity: 'medium', detail: 'Content-Security-Policy was not present.' }] : [] };
        } else {
          await beforeRequest();
          observation = await this.executor(target.url, { maxBytes: 65536, signal, timeoutMs: 10000, beforeRequest });
        }
        signal.throwIfAborted();
        if (observation.error) { target.status = 'failed'; target.error = String(observation.error).slice(0, 120); }
        else {
          target.status = 'completed'; target.httpStatus = Number(observation.status);
          if (typeof observation.bodySha256 === 'string') target.bodySha256 = observation.bodySha256;
          const findings = z.array(signalSchema).max(20).parse(observation.signals ?? []);
          target.findings = findings.map(finding => ({ ...finding, fix: remediationFor(finding.code).fix }));
          const executedChecks = ['transport.encryption', 'headers.hsts', 'headers.disclosure', 'cookies.attributes'];
          if (/html/i.test(String(observation.contentType))) executedChecks.push('headers.csp', 'headers.baseline');
          target.coverage = coverageForTarget({ origin: target.url, reachable: true, findings, executedChecks });
        }
      } catch (error) {
        target.status = signal.aborted ? 'cancelled' : 'failed';
        target.error = signal.aborted ? 'cancelled_by_operator' : error instanceof Error && /^[a-z_]+$/.test(error.message) ? error.message : 'assessment_request_failed';
      }
      await this.save(assessment);
      if (!assessment.demo && index < assessment.targets.length - 1 && !signal.aborted) {
        try { await sleep(this.delayMs, undefined, { signal }); } catch { break; }
      }
    }
    for (const target of assessment.targets) if (['queued', 'running'].includes(target.status)) target.status = 'cancelled';
    assessment.status = signal.aborted ? 'cancelled' : 'completed';
    assessment.finishedAt = new Date().toISOString(); await this.save(assessment);
  }
  private async save(assessment: Assessment) {
    const path = join(this.directory, assessment.id + '.json');
    const temporary = path + '.tmp';
    await writeFile(temporary, JSON.stringify(assessment, null, 2), { mode: 0o600 });
    await rename(temporary, path);
  }
}
