import { createHash } from 'node:crypto';
import { z } from 'zod';
import { AssessmentSchema, CampaignError, type Assessment } from '../campaigns/contracts.js';

export const ReportProfile = z.enum(['hackerone', 'bugcrowd', 'generic']);
export const ReportFormat = z.enum(['markdown', 'text', 'html', 'json']);
export type ReportProfile = z.infer<typeof ReportProfile>;
export type ReportFormat = z.infer<typeof ReportFormat>;
export const ReportEdits = z.object({
  title:z.string().trim().max(240).default(''), summary:z.string().trim().max(4000).default(''),
  steps:z.string().trim().max(8000).default(''), expected:z.string().trim().max(4000).default(''),
  impact:z.string().trim().max(4000).default(''),
  customFields:z.array(z.object({ name:z.string().trim().min(1).max(80), value:z.string().trim().max(2000) }).strict()).max(10).default([]),
}).strict().refine(value => new Set(value.customFields.map(field => field.name.toLowerCase())).size === value.customFields.length, 'Custom field names must be unique.');
export type ReportEdits = z.infer<typeof ReportEdits>;
const digest = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const humanize = (text: string) => text.replaceAll('_', ' ');

// Best-effort export redaction, not a claim that arbitrary text is secret-free.
// Reports remain drafts requiring human redaction review. Raw bodies are excluded.
export function redactReportText(value: string): string {
  return value.replace(/[\u0000-\u0008\u000b-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/https?:\/\/[^\s<>"'`]+/gi, raw => {
      try { const url = new URL(raw); return `${url.protocol}//${url.host}${url.pathname}${url.search ? '?REDACTED' : ''}`; }
      catch { return '[REDACTED URL]'; }
    })
    .replace(/\b(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*[^\r\n]+/gi, '[REDACTED HEADER]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, 'Bearer [REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED TOKEN]')
    .replace(/\b(password|passwd|secret|access_token|refresh_token|api_key|token)\s*[=:]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)/gi, '$1=[REDACTED]')
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[REDACTED EMAIL]');
}
const safe = (value: string) => redactReportText(value).slice(0, 12000);
const escapeHtml = (value: string) => value.replace(/[&<>"']/g, char => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[char]!));
const escapeMarkdown = (value: string) => value.replace(/[\\`*_{}\[\]()#+|>~]/g, '\\$&').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/(^|\n)(\s*)([-+*]|\d+\.)(?=\s)/g, '$1$2\\$3');

const PROFILES = {
  hackerone: {
    label: 'HackerOne', bodyLabel: 'Vulnerability information',
    guidance: 'Paste the reviewed Markdown into the program report form. Select the asset, weakness and required severity there; complete any custom fields. Upload evidence privately and use real attachment IDs only after upload.',
    source: 'https://docs.hackerone.com/en/articles/8473994-submitting-reports',
  },
  bugcrowd: {
    label: 'Bugcrowd', bodyLabel: 'Description',
    guidance: 'Paste the reviewed Markdown into the submission description. Select the target and applicable VRT classification in the form, complete program-specific fields, and attach the reviewed evidence privately.',
    source: 'https://docs.bugcrowd.com/researchers/reporting-managing-submissions/reporting-a-bug/',
  },
  generic: {
    label: 'Coordinated disclosure', bodyLabel: 'Technical description',
    guidance: 'Use the reviewed Markdown or text in the program’s specified private reporting channel. Check its required fields, eligible issue categories and evidence rules.',
    source: 'https://docs.hackerone.com/en/articles/8475116-quality-reports',
  },
} as const;

export function generateReport(raw: Assessment, targetIndex: number, findingIndex: number, profile: ReportProfile = 'generic', edits?: ReportEdits) {
  const run = AssessmentSchema.parse(raw);
  profile = ReportProfile.parse(profile);
  if (['queued', 'running', 'stopping'].includes(run.status)) throw new CampaignError('wait_for_assessment_completion');
  if (!Number.isSafeInteger(targetIndex) || targetIndex < 0 || !Number.isSafeInteger(findingIndex) || findingIndex < 0) throw new CampaignError('invalid_report_selection');
  const target = run.targets[targetIndex], finding = target?.findings[findingIndex];
  if (!target || !finding) throw new CampaignError('report_observation_not_found');
  const artifactId = `${run.id}:target:${targetIndex}:observation:${findingIndex}`;
  const sourceSnapshotSha256 = digest({ id:run.id, status:run.status, demo:run.demo, createdAt:run.createdAt, finishedAt:run.finishedAt,
    policyRevision:run.policyRevision, sourceUrl:run.sourceUrl, expiresAt:run.expiresAt, target, findingIndex });
  const profileInfo = PROFILES[profile];
  const evidence = {
    id: artifactId, kind:'stored_passive_observation', asset:safe(target.url),
    observedAt:target.finishedAt ?? run.finishedAt ?? run.createdAt,
    httpStatus:target.httpStatus ?? null, targetStatus:target.status,
    observationCode:safe(finding.code), detail:safe(finding.detail),
    detectorSuggestedSeverity:finding.severity,
    capturedBodySha256:target.bodySha256 ?? null,
    captureNote:'A body hash identifies captured bytes; the original response transcript is not included in this report.',
    coverage:target.coverage ? { executed:target.coverage.executed, gaps:target.coverage.gaps } : null,
  };
  const blockers = [
    ...(run.demo ? ['Synthetic demo: no target was contacted. Do not submit this sample.'] : []),
    'Confirm current program eligibility and complete its required fields.',
    'Independently reproduce this observation and attach relevant redacted request/response evidence.',
    'Establish a specific security consequence; passive observations alone do not demonstrate exploitability.',
    'Review all text and attachments for secrets and unrelated personal data before sharing.',
  ];
  const sections = [
    { heading:'Summary', paragraphs:[safe(`${humanize(finding.code)} was recorded for ${target.url}.`),
      'This is an automatically generated draft from a passive observation. It is not a verified vulnerability or an eligibility decision.'] },
    { heading:profileInfo.bodyLabel, paragraphs:[evidence.detail, `Evidence reference: ${artifactId}. Recorded HTTP status: ${evidence.httpStatus ?? 'unavailable'}.`] },
    { heading:'Prerequisites and scope', paragraphs:[`Authorization source: ${safe(run.sourceUrl)}`, `Recorded authorization expiry: ${run.expiresAt}. Recheck current permission before reproducing.`,
      'The assessment performs bounded HTTPS response inspection without login or resource creation.'] },
    { heading:'Suggested reproduction steps — not yet independently replayed', paragraphs:[
      '1. Confirm that the selected asset and this testing method are currently permitted by the program.',
      `2. Inspect the HTTPS response for ${safe(target.url)} within the program’s limits. Do not follow unapproved redirects.`,
      `3. Check whether the recorded observation (${safe(humanize(finding.code))}) still occurs; preserve a relevant redacted transcript.`,
      '4. Document expected versus observed behavior, a meaningful security consequence and any controls needed to rule out intentional behavior.',
    ] },
    { heading:'Expected behavior / remediation to review', paragraphs:[safe(finding.fix), 'Confirm that this recommendation applies to the specific response type and program; it is not proof of a violated security boundary.'] },
    { heading:'Impact', paragraphs:['NOT ESTABLISHED. Add only demonstrated impact supported by reproducible evidence. Do not infer account takeover, data exposure or bounty severity from this passive signal alone.'] },
    { heading:'Evidence and limitations', paragraphs:[
      `Observation recorded: ${evidence.observedAt}. Target outcome: ${target.status}.`,
      `Captured-response SHA-256: ${target.bodySha256 ?? 'not available'}. Original transcript: not included.`,
      `Coverage: ${target.coverage?.executed ?? 0} recorded checks, ${target.coverage?.gaps ?? 8} gaps.`,
      'Authentication, business logic and a full TLS audit were not assessed. Failed, truncated or skipped work is not a pass.',
      'No new requests were made while generating this report. No screenshots or platform attachment IDs have been invented.',
    ] },
    { heading:'Cleanup', paragraphs:['This passive assessment does not intentionally create application resources. No resource-deletion verification is claimed.'] },
    { heading:'Before submission', paragraphs:blockers },
    { heading:'Submission profile', paragraphs:[profileInfo.guidance, `Reference: ${profileInfo.source}`, 'Formatting compatibility does not guarantee program acceptance or a reward.'] },
  ];
  const checkedEdits = edits ? ReportEdits.parse(edits) : undefined;
  const editedFields: string[] = [];
  if (checkedEdits) {
    const replacements = [
      ['summary', 'Summary'], ['steps', 'Suggested reproduction steps — not yet independently replayed'],
      ['expected', 'Expected behavior / remediation to review'], ['impact', 'Impact'],
    ] as const;
    for (const [field, heading] of replacements) if (checkedEdits[field]) {
      const section = sections.find(item => item.heading === heading)!;
      section.paragraphs = ['Researcher-provided text — not independently verified by Anteater.', safe(checkedEdits[field])];
      editedFields.push(field);
    }
    if (checkedEdits.title) editedFields.push('title');
    if (checkedEdits.customFields.length) {
      sections.push(...checkedEdits.customFields.map(field => ({ heading:`Program field: ${safe(field.name)}`, paragraphs:[safe(field.value) || 'Not supplied.'] })));
      editedFields.push('customFields');
    }
  }
  const report = {
    schemaVersion:1, generatorVersion:'anteater-report/1', profile, profileLabel:profileInfo.label,
    id:`${run.id}-${targetIndex}-${findingIndex}`, assessmentId:run.id,
    title:safe(`${run.demo ? '[DEMO] ' : ''}[Draft] ${checkedEdits?.title || `${humanize(finding.code)} on ${new URL(target.url).hostname}`}`),
    status:'draft_needs_review', submissionReady:false, demo:run.demo,
    sourceSnapshotSha256, evidence:[evidence], evidenceSha256:digest(evidence),
    redaction:{ version:1, mode:'best_effort', humanReviewRequired:true },
    editedFields, blockers, sections,
  };
  return report;
}
export type GeneratedReport = ReturnType<typeof generateReport>;

export function renderReport(report: GeneratedReport, format: ReportFormat) {
  ReportFormat.parse(format);
  const notice = report.demo ? 'SYNTHETIC DEMO — DO NOT SUBMIT' : 'DRAFT — HUMAN REVIEW AND IMPACT VALIDATION REQUIRED';
  let content: string;
  if (format === 'json') content = JSON.stringify(report, null, 2) + '\n';
  else if (format === 'html') {
    content = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>${escapeHtml(report.title)}</title><style>body{font:16px/1.6 system-ui;max-width:880px;margin:40px auto;padding:0 24px;color:#183b36}h1{line-height:1.2}h2{margin-top:32px}p{white-space:pre-wrap;overflow-wrap:anywhere}.notice{padding:16px;background:#fff1cf;border:1px solid #dbc58c}footer{border-top:1px solid #ccc;padding-top:20px;font-size:12px}</style></head><body><p class="notice">${notice}</p><h1>${escapeHtml(report.title)}</h1>${report.sections.map(section => `<section><h2>${escapeHtml(section.heading)}</h2>${section.paragraphs.map(p => `<p>${escapeHtml(p)}</p>`).join('')}</section>`).join('')}<footer>Source snapshot SHA-256: ${report.sourceSnapshotSha256}<br>Evidence SHA-256: ${report.evidenceSha256}</footer></body></html>`;
  } else if (format === 'markdown') {
    content = `# ${escapeMarkdown(report.title)}\n\n**${notice}**\n\n` + report.sections.map(section => `## ${escapeMarkdown(section.heading)}\n\n${section.paragraphs.map(escapeMarkdown).join('\n\n')}`).join('\n\n')
      + `\n\nSource snapshot SHA-256: ${report.sourceSnapshotSha256}\n\nEvidence SHA-256: ${report.evidenceSha256}\n`;
  } else {
    content = `${report.title}\n\n${notice}\n\n` + report.sections.map(section => `${section.heading}\n${'='.repeat(section.heading.length)}\n${section.paragraphs.join('\n\n')}`).join('\n\n')
      + `\n\nSource snapshot SHA-256: ${report.sourceSnapshotSha256}\nEvidence SHA-256: ${report.evidenceSha256}\n`;
  }
  const extension = { markdown:'md', text:'txt', html:'html', json:'json' }[format];
  const mimeType = { markdown:'text/markdown', text:'text/plain', html:'text/html', json:'application/json' }[format];
  return { content, mimeType, filename:`anteater-${report.id}-${report.profile}.${extension}`, sha256:createHash('sha256').update(content).digest('hex') };
}
