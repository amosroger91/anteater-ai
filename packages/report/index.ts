import type { Remediation } from '../remediation/index.js';

export interface ReportFinding { id: string; type: string; location: string; severity: string; impact?: string }
export interface ReportEvidence { steps: Array<{ step: string; iteration?: number; status: number }> }

// Reviewer-editable Markdown. Steps are statuses only, so a response body cannot leak into the draft.
export function renderReport(finding: ReportFinding, evidence: ReportEvidence, remediation: Remediation): string {
  const steps = evidence.steps.map((step, index) => `${index + 1}. \`${step.step}\` returned HTTP ${step.status}.`);
  return [
    `# ${finding.type}`,
    '',
    `Reviewer: edit this draft before submission. Finding \`${finding.id}\`. Severity \`${finding.severity}\`.`,
    '',
    '## Impact',
    finding.impact ?? `A ${finding.severity} issue was replayed at ${finding.location}.`,
    '',
    '## Reproduction',
    finding.location,
    '',
    ...(steps.length ? steps : ['No replay steps were stored.']),
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
