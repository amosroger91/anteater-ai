import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { listHackerOneCompanies, type DirectoryCompany } from '../../packages/program-intake/directory.js';
import { fetchProgram, type RawProgram, type FetchLike } from '../../packages/program-intake/hackerone.js';
import { autoApproval } from '../../packages/program-intake/auto.js';
import { compileIntake, intakeApprovalSource } from '../../packages/program-intake/compile.js';
import { sha256Hex } from '../../packages/provenance/index.js';
import { connect, migrate } from '../../packages/research-state/db.js';
import { saveProgram } from '../../packages/research-state/workspace.js';
import { applyProfile, type SetupProfile } from '../../packages/setup/profile.js';
import { loadConfig } from '../../packages/shared/config.js';

const selections = z.object({ id: z.string().uuid(), handles: z.array(z.string().max(80)).min(1).max(10000), approver: z.string().trim().min(2).max(200) }).strict();
const consent = z.object({ id: z.string().uuid(), approved: z.literal(true) }).strict();
type Phase = 'fetching' | 'select' | 'preparing' | 'review' | 'saving' | 'done' | 'failed' | 'cancelled';
interface ScopeReview { handle: string; name: string; url: string; allowed: string[]; excluded: string[]; assets: string[]; paths: string[]; actions: string[]; rate: number; policy: string; instructions: string[] }
interface ImportState {
  id: string; phase: Phase; progress: number; total: number; approver: string; expiresAt: string;
  companies: DirectoryCompany[]; scopes: ScopeReview[]; skipped: Array<{ handle: string; reason: string }>;
  imported: string[]; error?: string;
}
export interface CompanyImportDeps {
  fetchLike?: FetchLike;
  env?: NodeJS.ProcessEnv;
  persist?: (raws: RawProgram[], approver: string, signal: AbortSignal, done: (handle: string, reason?: string) => void) => Promise<void>;
}
function code(error: unknown): string {
  return error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : 'company_import_failed';
}
function approvalFor(raw: RawProgram, approver: string, id: string) {
  const approval = { ...autoApproval(raw, approver), revision: `ui-${id}` };
  return { ...approval, sourceSha256: sha256Hex(intakeApprovalSource(raw, approval)) };
}

// The server owns every scope snapshot. The browser may select handles, never supply policy.
export class CompanyImportService {
  private state?: ImportState;
  private raws: RawProgram[] = [];
  private controller?: AbortController;
  constructor(private profile: () => SetupProfile, private deps: CompanyImportDeps = {}) {}
  private environment() { return applyProfile(this.deps.env ?? process.env, this.profile()); }
  private authorization() {
    const env = this.environment();
    if (!env.HACKERONE_USERNAME || !env.HACKERONE_API_TOKEN) throw new Error('hackerone_credentials_required');
    return 'Basic ' + Buffer.from(`${env.HACKERONE_USERNAME}:${env.HACKERONE_API_TOKEN}`).toString('base64');
  }
  private current(id: string) {
    if (!this.state || this.state.id !== id) throw new Error('import_not_found');
    return this.state;
  }
  status(id: string) {
    const state = this.current(id);
    // Progress polling must not repeatedly copy every private policy document.
    return structuredClone({ ...state,
      companies: ['select', 'review'].includes(state.phase) ? state.companies : [],
      scopes: state.phase === 'review' ? state.scopes : [],
    });
  }
  private fresh(state: ImportState) {
    if (Date.now() >= Date.parse(state.expiresAt)) throw new Error('import_expired');
  }
  private launch(task: (state: ImportState, signal: AbortSignal) => Promise<void>) {
    const state = this.state!;
    this.controller = new AbortController();
    const signal = AbortSignal.any([this.controller.signal, AbortSignal.timeout(15 * 60_000)]);
    void task(state, signal).catch(error => {
      state.phase = signal.aborted ? 'cancelled' : 'failed'; state.error = signal.aborted ? 'import_cancelled_or_timed_out' : code(error);
    });
  }
  fetch() {
    const authorization = this.authorization();
    if (this.state && ['fetching', 'preparing', 'saving'].includes(this.state.phase)) throw new Error('import_busy');
    this.raws = [];
    this.state = { id: randomUUID(), phase: 'fetching', progress: 0, total: 0, approver: '',
      expiresAt: new Date(Date.now() + 30 * 60_000).toISOString(), companies: [], scopes: [], skipped: [], imported: [] };
    this.launch(async (state, signal) => {
      state.companies = await listHackerOneCompanies(authorization, signal, this.deps.fetchLike, count => { state.progress = count; });
      state.total = state.companies.length; state.phase = 'select';
    });
    return { id: this.state.id };
  }
  preview(input: unknown) {
    const request = selections.parse(input);
    const state = this.current(request.id); this.fresh(state);
    if (!['select', 'review'].includes(state.phase)) throw new Error('import_not_ready');
    const available = new Set(state.companies.map(company => company.handle));
    const handles = [...new Set(request.handles)];
    if (handles.some(handle => !available.has(handle))) throw new Error('company_not_in_snapshot');
    const authorization = this.authorization();
    this.raws = []; state.scopes = []; state.skipped = []; state.progress = 0; state.total = handles.length;
    state.approver = request.approver; state.phase = 'preparing';
    this.launch(async (state, signal) => {
      let size = 0;
      const programIds = new Set<string>();
      for (const handle of handles) {
        signal.throwIfAborted();
        try {
          const raw = await fetchProgram(handle, this.deps.fetchLike, { authorization, signal });
          signal.throwIfAborted();
          const compiled = compileIntake(raw, approvalFor(raw, state.approver, state.id));
          const program = compiled.programs[0];
          // Ambiguous/manual-only programs remain visible, but cannot enter an automated queue here.
          if (compiled.automation !== 'permitted' || !program) {
            state.skipped.push({ handle, reason: compiled.refused ?? compiled.automation });
          } else {
            if (programIds.has(program.id)) throw new Error('program_identity_collision');
            programIds.add(program.id);
            size += Buffer.byteLength(JSON.stringify(raw));
            if (size > 67_108_864) throw new Error('scope_snapshot_too_large');
            this.raws.push(raw);
            state.scopes.push({ handle, name: raw.name, url: raw.programUrl, allowed: program.policy.allowed,
              excluded: program.policy.excluded, assets: program.assets.map(asset => asset.url),
              paths: program.policy.allowedPaths, actions: program.policy.allowedActions, rate: program.policy.requestsPerSecond,
              policy: raw.policyText, instructions: raw.scopes.map(scope => scope.instruction).filter((text): text is string => Boolean(text)) });
          }
        } catch (error) {
          signal.throwIfAborted();
          // Stop the batch on account/rate failures instead of hammering every remaining handle.
          if (['scope_snapshot_too_large', 'program_http_401', 'program_http_429'].includes(code(error))) throw error;
          state.skipped.push({ handle, reason: code(error) });
        }
        state.progress++;
      }
      signal.throwIfAborted();
      state.expiresAt = new Date(Date.now() + 15 * 60_000).toISOString();
      state.phase = 'review';
    });
    return { id: state.id };
  }
  confirm(input: unknown) {
    const request = consent.parse(input);
    const state = this.current(request.id); this.fresh(state);
    if (state.phase === 'done') return { id: state.id };
    if (state.phase !== 'review' || !this.raws.length) throw new Error('no_approved_scope');
    const raws = [...this.raws]; state.phase = 'saving'; state.progress = 0; state.total = raws.length;
    this.launch(async (state, signal) => {
      const done = (handle: string, reason?: string) => {
        if (reason) state.skipped.push({ handle, reason }); else state.imported.push(handle);
        state.progress++;
      };
      if (this.deps.persist) await this.deps.persist(raws, state.approver, signal, done);
      else {
        const pool = connect(loadConfig(this.environment()).DATABASE_URL);
        try {
          await migrate(pool);
          for (const raw of raws) {
            signal.throwIfAborted();
            try {
              const approval = approvalFor(raw, state.approver, state.id);
              const compiled = compileIntake(raw, approval);
              const program = compiled.programs[0];
              if (!program || compiled.automation !== 'permitted') throw new Error('scope_no_longer_importable');
              await saveProgram(pool, program, { automationPolicy: compiled.automation, platformHandle: raw.handle,
                approver: state.approver, sourceSha256: approval.sourceSha256, approvedAt: approval.approvedAt, revision: approval.revision });
              done(raw.handle);
            } catch (error) { done(raw.handle, code(error)); }
          }
        } finally { await pool.end(); }
      }
      this.raws = []; state.phase = 'done';
    });
    return { id: state.id };
  }
  cancel(id: string) {
    const state = this.current(id);
    if (state.phase === 'saving') throw new Error('import_already_saving');
    this.controller?.abort(new Error('import_cancelled')); state.phase = 'cancelled'; this.raws = [];
    return { id };
  }
  async savedScope() {
    const pool = connect(loadConfig(this.environment()).DATABASE_URL);
    try {
      const result = await pool.query(`SELECT p.name,p.platform_handle AS handle,s.policy->'allowed' AS allowed,
        s.policy->>'expiresAt' AS expires_at FROM programs p JOIN scope_rules s ON s.program_id=p.id
        WHERE p.platform='hackerone' ORDER BY p.name LIMIT 10000`);
      return result.rows;
    } finally { await pool.end(); }
  }
}
