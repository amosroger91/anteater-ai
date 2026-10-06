import type { Remediation } from '../remediation/index.js';

const REPORTABLE = new Set(['VERIFIED', 'HUMAN_REVIEW']);

export interface ReportFinding {
  id: string;
  type: string;
  location: string;
  severity: string;
  status: string;
  title?: string;
  impact?: string;
  asset?: string;
}
export interface ReportEvidence { steps: Array<{ step: string; iteration?: number; status: number }> }

function oneLine(value: string): string {
  return value.replace(/[\r\n]+/g, ' ').trim();
}

function titleOf(finding: ReportFinding): string {
  const title = finding.title?.trim() ? finding.title : finding.type.replaceAll('_', ' ');
  return oneLine(title) || 'Finding';
}

function affectedAsset(finding: ReportFinding): string {
  if (finding.asset?.trim()) return oneLine(finding.asset);
  try {
    const url = new URL(finding.location);
    if (url.protocol !== 'https:') return oneLine(finding.location);
    return `${url.protocol}//${url.host}`;
  } catch {
    return oneLine(finding.location);
  }
}

// Reviewer-editable Markdown. Only a verified or human-review finding produces a draft.
// Steps are statuses only, so a response body cannot leak into the draft.
export function renderReport(finding: ReportFinding, evidence: ReportEvidence, remediation: Remediation): string | null {
  if (!REPORTABLE.has(finding.status)) return null;
  const steps = evidence.steps.map((step, index) => `${index + 1}. \`${oneLine(step.step)}\` returned HTTP ${step.status}.`);
  const severity = oneLine(finding.severity) || 'unspecified';
  const location = oneLine(finding.location);
  return [
    `# ${titleOf(finding)}`,
    '',
    `Reviewer: edit this draft before submission. Finding \`${oneLine(finding.id)}\`.`,
    '',
    '## Severity',
    severity,
    '',
    '## Affected asset',
    affectedAsset(finding),
    '',
    '## Reproduction',
    location,
    '',
    ...(steps.length ? steps : ['No replay steps were stored.']),
    '',
    '## Impact',
    finding.impact ? oneLine(finding.impact) : `A ${severity} issue was replayed at ${location}.`,
    '',
    '## Remediation',
    remediation.summary,
    '',
    remediation.fix,
    '',
    `Reference: ${remediation.reference}`,
    '',
  ].join('\n');
}
