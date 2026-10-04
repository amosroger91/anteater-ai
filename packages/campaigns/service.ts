import { copyFile, mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { z } from 'zod';
import { authorize, PolicySchema } from '../scope-engine/index.js';
import { executePassiveHttp, type PassiveOptions } from '../web-executor/index.js';
import { coverageForTarget } from '../coverage/index.js';
import { remediationFor } from '../remediation/index.js';

import { AssessmentInput, AssessmentSchema, CampaignError, DraftFields, WorkspaceSchema, parse, prepareScope, type Assessment, type Workspace } from './contracts.js';
export { AssessmentInput, type Assessment, type Target } from './contracts.js';
type Executor = (target: string, options: PassiveOptions) => Promise<Record<string, unknown>>;
const signalSchema = z.object({ code: z.string().max(100), severity: z.enum(['info', 'low', 'medium', 'high', 'critical']), detail: z.string().max(1024) });

export class CampaignService {
  enabled = false;
  readonly assessments = new Map<string, Assessment>();
  private controller?: AbortController;
  private active?: string;
  private task?: Promise<void>;
  private storageError?: string;
  private workspace: Workspace = { schemaVersion: 1, projects: [], drafts: [] };
  private mutations: Promise<unknown> = Promise.resolve();
  private pendingKeys = new Map<string, { hash: string; promise: Promise<string> }>();
  private listeners = new Set<() => void>();
  private revision = 0;
  constructor(readonly directory: string, private executor: Executor = executePassiveHttp, private delayMs = 1100) {}
  async init() {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    try { this.workspace = WorkspaceSchema.parse(JSON.parse(await readFile(join(this.directory, 'workspace.json'), 'utf8'))); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error('invalid_workspace_file'); }
    const names = (await readdir(this.directory)).filter(name => /^[a-f0-9-]{36}\.json$/.test(name));
    if (names.length > 100) throw new Error('assessment_history_limit');
    for (const name of names) {
      const raw = JSON.parse(await readFile(join(this.directory, name), 'utf8'));
      const assessment = AssessmentSchema.parse(raw);
      if (assessment.id + '.json' !== name) throw new Error('invalid_assessment_file');
      if (raw.schemaVersion === undefined) {
        await copyFile(join(this.directory, name), join(this.directory, `${assessment.id}.legacy-backup.json`), 1).catch(error => { if (error.code !== 'EEXIST') throw error; });
      }
      if (['running', 'queued', 'stopping'].includes(assessment.status)) {
        assessment.status = 'interrupted'; assessment.finishedAt = new Date().toISOString();
        for (const target of assessment.targets) if (['running', 'queued'].includes(target.status)) { target.status = 'interrupted'; target.finishedAt = assessment.finishedAt; }
        await this.save(assessment);
      } else {
        // Older reports called mixed-success runs completed. Preserve their evidence,
        // but use the same outcome rules as newly executed campaigns.
        if (assessment.status === 'completed') assessment.status = assessment.targets.every(target => target.status === 'failed') ? 'failed'
          : assessment.targets.some(target => ['failed', 'completed_with_gaps'].includes(target.status)) ? 'completed_with_gaps' : 'completed';
        if (raw.schemaVersion === undefined || raw.status !== assessment.status) await this.save(assessment);
      }
      this.assessments.set(assessment.id, assessment);
    }
  }
  state() {
    return { enabled: this.enabled, active: this.active ?? null, storageError: this.storageError ?? null,
      revision: this.revision, projects: structuredClone(this.workspace.projects), drafts: structuredClone(this.workspace.drafts),
      health: { storage: this.storageError ? 'error' : 'ready', execution: this.active ? 'working' : 'idle', mode: 'local-passive', historyUsed: this.assessments.size, historyLimit: 100 },
      assessments: [...this.assessments.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt)) };
  }
  subscribe(listener: () => void) { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; }
  private changed() { this.revision++; for (const listener of this.listeners) listener(); }
  private storageFailed() {
    this.storageError = 'Results could not be saved. Live requests are disabled; check the data directory.';
    this.setEnabled(false);
  }
  setEnabled(value: boolean) {
    if (value && this.storageError) throw new CampaignError('assessment_storage_failed');
    this.enabled = value; if (!value && this.active) this.cancel(this.active); this.changed();
  }
  cancel(id: string) {
    if (this.active === id) { const run = this.assessments.get(id); if (run) run.status = 'stopping'; this.controller?.abort(); this.changed(); }
  }
  async close() { this.setEnabled(false); await this.task; await this.mutations; }
  preview(raw: unknown) { return prepareScope(raw); }
  private mutate<T>(action: () => Promise<T>): Promise<T> {
    const next = this.mutations.then(action); this.mutations = next.catch(() => {}); return next;
  }
  async saveProject(raw: unknown) {
    const input = parse(z.object({ id: z.uuid().optional(), expectedRevision: z.number().int().positive().optional(), name: z.string().trim().min(1).max(80), scope: z.unknown() }).strict(), raw);
    const prepared = prepareScope(input.scope, false);
    return this.mutate(async () => {
      const previous = this.workspace.projects.find(project => project.id === input.id);
      if (input.id && !previous) throw new CampaignError('project_not_found');
      if (previous && input.expectedRevision !== previous.revision) throw new CampaignError('project_changed_reload_before_saving');
      if (!previous && this.workspace.projects.length >= 100) throw new CampaignError('project_limit');
      const now = new Date().toISOString();
      const project = { id: previous?.id ?? randomUUID(), name: input.name, revision: (previous?.revision ?? 0) + 1,
        createdAt: previous?.createdAt ?? now, updatedAt: now, scope: { targets: prepared.targets.map(url => new URL(url).hostname),
          excluded: prepared.excluded.map(url => new URL(url).hostname), sourceUrl: prepared.policy.sourceUrl, expiresAt: prepared.policy.expiresAt } };
      await this.saveWorkspace({ ...this.workspace, projects: [...this.workspace.projects.filter(item => item.id !== project.id), project] });
      return project;
    });
  }
  async saveDraft(raw: unknown) {
    const input = parse(z.object({ id: z.uuid().optional(), expectedRevision: z.number().int().positive().optional(), fields: DraftFields }).strict(), raw);
    return this.mutate(async () => {
      const previous = this.workspace.drafts.find(draft => draft.id === input.id);
      if (input.id && !previous) throw new CampaignError('draft_not_found');
      if (previous && previous.revision !== input.expectedRevision) throw new CampaignError('draft_changed_reload_before_saving');
      if (!previous && this.workspace.drafts.length >= 100) throw new CampaignError('draft_limit');
      const draft = { id: previous?.id ?? randomUUID(), revision: (previous?.revision ?? 0) + 1, updatedAt: new Date().toISOString(), fields: input.fields };
      await this.saveWorkspace({ ...this.workspace, drafts: [...this.workspace.drafts.filter(item => item.id !== draft.id), draft] });
      return draft;
    });
  }
  async archive(id: string, archived: boolean) {
    return this.mutate(async () => {
      const run = this.assessments.get(id); if (!run) throw new CampaignError('assessment_not_found');
      if (this.active === id) throw new CampaignError('stop_assessment_before_archiving');
      const updated = { ...run, archivedAt: archived ? new Date().toISOString() : undefined };
      await this.save(updated); this.assessments.set(id, updated); this.changed();
    });
  }
  async start(raw: unknown, demo = false, key?: string): Promise<string> {
    if (key) parse(z.uuid(), key);
    const input = parse(AssessmentInput, raw);
    const hash = createHash('sha256').update(JSON.stringify(input)).digest('hex');
    if (key) {
      const previous = [...this.assessments.values()].find(run => run.idempotencyKey === key);
      if (previous) { if (previous.inputHash !== hash) throw new CampaignError('idempotency_key_conflict'); return previous.id; }
      const pending = this.pendingKeys.get(key);
      if (pending) { if (pending.hash !== hash) throw new CampaignError('idempotency_key_conflict'); return pending.promise; }
    }
    const promise = this.startNew(input, demo, key, hash);
    if (key) this.pendingKeys.set(key, { hash, promise });
    try { return await promise; } finally { if (key) this.pendingKeys.delete(key); }
  }
  private async startNew(input: AssessmentInput, demo: boolean, key: string | undefined, hash: string) {
    if (this.active) throw new Error('assessment_already_running');
    if (this.storageError) throw new Error('assessment_storage_failed');
    if (this.assessments.size >= 100) throw new Error('assessment_history_limit');
    if (!demo && !this.enabled) throw new Error('passive_requests_disabled');
    const prepared = prepareScope(input);
    const project = input.projectId ? this.workspace.projects.find(project => project.id === input.projectId) : undefined;
    if (input.projectId && !project) throw new CampaignError('project_not_found');
    if (project && input.projectRevision !== project.revision) throw new CampaignError('project_changed_reload_before_starting');
    const { policy, targets: urls } = prepared;
    const assessment: Assessment = { schemaVersion: 1, id: randomUUID(), name: input.name, demo, status: 'queued', createdAt: new Date().toISOString(),
      sourceUrl: input.sourceUrl, expiresAt: input.expiresAt, targets: urls.map(url => ({ url, status: 'queued', findings: [] })),
      excluded: prepared.excluded, policyRevision: policy.revision, idempotencyKey: key, inputHash: hash,
      projectId: project?.id, projectRevision: project?.revision, projectName: project?.name };
    // Reserve before the first await so simultaneous requests cannot start two campaigns.
    this.active = assessment.id; this.controller = new AbortController();
    try { await this.save(assessment); }
    catch (error) { this.active = undefined; this.controller = undefined; this.changed(); throw error; }
    this.assessments.set(assessment.id, assessment);
    this.changed();
    const controller = this.controller!;
    this.task = this.run(assessment, policy, controller).catch(() => {
      this.storageFailed(); assessment.status = 'interrupted'; assessment.finishedAt = new Date().toISOString(); controller.abort();
      for (const target of assessment.targets) if (['running', 'queued'].includes(target.status)) { target.status = 'interrupted'; target.finishedAt = assessment.finishedAt; }
    }).finally(() => { this.active = undefined; this.controller = undefined; this.changed(); });
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
      target.status = 'running'; target.startedAt = new Date().toISOString(); await this.save(assessment);
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
          target.status = observation.truncated ? 'completed_with_gaps' : 'completed';
          target.httpStatus = parse(z.number().int().min(100).max(599), observation.status);
          if (observation.truncated) target.error = 'response_capture_truncated';
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
      target.finishedAt = new Date().toISOString(); await this.save(assessment);
      if (!assessment.demo && index < assessment.targets.length - 1 && !signal.aborted) {
        try { await sleep(this.delayMs, undefined, { signal }); } catch { break; }
      }
    }
    for (const target of assessment.targets) if (['queued', 'running'].includes(target.status)) { target.status = 'cancelled'; target.finishedAt = new Date().toISOString(); }
    assessment.status = signal.aborted ? 'cancelled' : assessment.targets.every(target => target.status === 'failed') ? 'failed'
      : assessment.targets.some(target => ['failed', 'completed_with_gaps'].includes(target.status)) ? 'completed_with_gaps' : 'completed';
    assessment.finishedAt = new Date().toISOString(); await this.save(assessment);
  }
  private async save(assessment: Assessment) {
    assessment.updatedAt = new Date().toISOString();
    const validated = AssessmentSchema.parse(assessment);
    const path = join(this.directory, assessment.id + '.json');
    const temporary = path + '.tmp';
    try {
      await writeFile(temporary, JSON.stringify(validated, null, 2), { mode: 0o600 });
      await rename(temporary, path);
    } catch (error) { this.storageFailed(); throw error; }
    this.changed();
  }
  private async saveWorkspace(value: Workspace) {
    const parsed = WorkspaceSchema.parse(value);
    const path = join(this.directory, 'workspace.json'), temporary = path + '.tmp';
    try {
      await writeFile(temporary, JSON.stringify(parsed, null, 2), { mode: 0o600 }); await rename(temporary, path);
    } catch (error) { this.storageFailed(); throw error; }
    this.workspace = parsed; this.changed();
  }
}
