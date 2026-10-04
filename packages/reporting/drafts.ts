import { mkdir, readdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import { CampaignError, parse } from '../campaigns/contracts.js';
import { ReportEdits, ReportProfile, redactReportText } from './index.js';

const Selection = z.object({ assessmentId:z.uuid(), targetIndex:z.number().int().min(0).max(24), findingIndex:z.number().int().min(0).max(19), profile:ReportProfile }).strict();
export type ReportSelection = z.infer<typeof Selection>;
const Version = z.object({ revision:z.number().int().positive(), savedAt:z.iso.datetime(), sourceSnapshotSha256:z.string().regex(/^[a-f0-9]{64}$/), edits:ReportEdits }).strict();
const Record = z.object({ schemaVersion:z.literal(1), selection:Selection, versions:z.array(Version).min(1).max(20) }).strict()
  .refine(value => value.versions.every((version, index) => version.revision === index + 1), 'Report revisions must be consecutive.');
export const SaveDraftInput = z.object({ expectedRevision:z.number().int().min(0), sourceSnapshotSha256:z.string().regex(/^[a-f0-9]{64}$/), edits:ReportEdits }).strict();
const key = (selection: ReportSelection) => `${selection.assessmentId}-${selection.targetIndex}-${selection.findingIndex}-${selection.profile}`;

/** Local draft revisions during the file-to-PostgreSQL transition. This is report
 * metadata, never an execution queue. Import these revisions with B14.4/B02. */
export class ReportDraftStore {
  private records = new Map<string, z.infer<typeof Record>>();
  private mutations: Promise<unknown> = Promise.resolve();
  constructor(readonly directory: string) {}
  async init() {
    await mkdir(this.directory, { recursive:true, mode:0o700 });
    const names = (await readdir(this.directory)).filter(name => name.endsWith('.json'));
    if (names.length > 100) throw new CampaignError('report_draft_limit');
    for (const name of names) {
      const record = Record.parse(JSON.parse(await readFile(join(this.directory, name), 'utf8')));
      if (name !== key(record.selection) + '.json') throw new CampaignError('invalid_report_draft_file');
      this.records.set(key(record.selection), record);
    }
  }
  get(selection: ReportSelection) {
    Selection.parse(selection);
    const record = this.records.get(key(selection));
    return record ? structuredClone(record) : undefined;
  }
  save(selection: ReportSelection, raw: unknown, currentSourceSha256: string) {
    Selection.parse(selection); const input = SaveDraftInput.parse(raw);
    const action = this.mutations.then(async () => {
      if (input.sourceSnapshotSha256 !== currentSourceSha256) throw new CampaignError('report_source_changed_reload_before_saving');
      const id = key(selection), previous = this.records.get(id), revision = previous?.versions.length ?? 0;
      if (input.expectedRevision !== revision) throw new CampaignError('report_draft_changed_reload_before_saving');
      if (revision >= 20) throw new CampaignError('report_revision_limit');
      if (!previous && this.records.size >= 100) throw new CampaignError('report_draft_limit');
      const edits = parse(ReportEdits, { ...input.edits,
        title:redactReportText(input.edits.title), summary:redactReportText(input.edits.summary), steps:redactReportText(input.edits.steps),
        expected:redactReportText(input.edits.expected), impact:redactReportText(input.edits.impact),
        customFields:input.edits.customFields.map(field => ({ name:redactReportText(field.name), value:redactReportText(field.value) })),
      });
      const version = { revision:revision + 1, savedAt:new Date().toISOString(), sourceSnapshotSha256:currentSourceSha256, edits };
      const record = Record.parse({ schemaVersion:1, selection, versions:[...(previous?.versions ?? []), version] });
      const path = join(this.directory, id + '.json');
      await writeFile(path + '.tmp', JSON.stringify(record, null, 2), { mode:0o600 }); await rename(path + '.tmp', path);
      this.records.set(id, record);
      return structuredClone(version);
    });
    this.mutations = action.catch(() => {}); return action;
  }
  async close() { await this.mutations; }
}
