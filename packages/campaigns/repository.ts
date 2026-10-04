import { copyFile, mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { AssessmentSchema, WorkspaceSchema, type Assessment, type Workspace } from './contracts.js';

export interface CampaignSnapshot { assessments: Assessment[]; workspace: Workspace }

/** Snapshot persistence for the existing single-process service. A future PostgreSQL
 * scheduler must add transactional start/claim operations, not use this as a queue. */
export interface CampaignRepository {
  initialize(): Promise<CampaignSnapshot>;
  saveAssessment(assessment: Assessment): Promise<void>;
  saveWorkspace(workspace: Workspace): Promise<void>;
}

export class FileCampaignRepository implements CampaignRepository {
  constructor(readonly directory: string) {}
  async initialize(): Promise<CampaignSnapshot> {
    await mkdir(this.directory, { recursive:true, mode:0o700 });
    let workspace: Workspace = { schemaVersion:1, projects:[], drafts:[] };
    try { workspace = WorkspaceSchema.parse(JSON.parse(await readFile(join(this.directory, 'workspace.json'), 'utf8'))); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error('invalid_workspace_file'); }
    const names = (await readdir(this.directory)).filter(name => /^[a-f0-9-]{36}\.json$/.test(name));
    if (names.length > 100) throw new Error('assessment_history_limit');
    const assessments: Assessment[] = [];
    for (const name of names) {
      const raw = JSON.parse(await readFile(join(this.directory, name), 'utf8'));
      const assessment = AssessmentSchema.parse(raw);
      if (assessment.id + '.json' !== name) throw new Error('invalid_assessment_file');
      if (raw.schemaVersion === undefined) {
        await copyFile(join(this.directory, name), join(this.directory, `${assessment.id}.legacy-backup.json`), 1)
          .catch(error => { if (error.code !== 'EEXIST') throw error; });
        await this.saveAssessment(assessment);
      }
      assessments.push(assessment);
    }
    return { workspace, assessments };
  }
  async saveAssessment(assessment: Assessment) {
    const parsed = AssessmentSchema.parse(assessment);
    await this.atomicWrite(parsed.id + '.json', parsed);
  }
  async saveWorkspace(workspace: Workspace) { await this.atomicWrite('workspace.json', WorkspaceSchema.parse(workspace)); }
  private async atomicWrite(name: string, value: unknown) {
    const path = join(this.directory, name), temporary = path + '.tmp';
    await writeFile(temporary, JSON.stringify(value, null, 2), { mode:0o600 });
    await rename(temporary, path);
  }
}
