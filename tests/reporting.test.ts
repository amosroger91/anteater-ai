import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { generateReport, redactReportText, renderReport, ReportFormat, ReportProfile } from '../packages/reporting/index.js';
import { ReportDraftStore } from '../packages/reporting/drafts.js';
import { type Assessment } from '../packages/campaigns/contracts.js';
import { CampaignService } from '../packages/campaigns/service.js';
import { createDashboard } from '../apps/dashboard/server.js';

const assessment: Assessment = {
  id:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', name:'Owned app', demo:false, status:'completed',
  createdAt:'2026-10-03T00:00:00Z', finishedAt:'2026-10-03T00:00:01Z', sourceUrl:'https://example.test/policy?token=hidden', expiresAt:'2099-01-01T00:00:00Z',
  targets:[{ url:'https://app.example.test/', status:'completed', httpStatus:200, bodySha256:'a'.repeat(64),
    findings:[{ code:'missing_hsts', severity:'medium', detail:'Strict-Transport-Security was not present.', fix:'Review the HTTPS transport policy.' }] }],
};

test('each report profile exports four deterministic formats with honest readiness and source provenance', () => {
  for (const profile of ReportProfile.options) {
    const report = generateReport(assessment, 0, 0, profile);
    assert.equal(report.submissionReady, false); assert.equal(report.status, 'draft_needs_review');
    assert.match(report.sourceSnapshotSha256, /^[a-f0-9]{64}$/);
    assert.equal(report.evidence[0]?.httpStatus, 200);
    assert.match(report.sections.find(section => section.heading === 'Impact')!.paragraphs[0]!, /NOT ESTABLISHED/);
    assert.equal(report.evidenceSha256, createHash('sha256').update(JSON.stringify(report.evidence[0])).digest('hex'));
    for (const format of ReportFormat.options) {
      const artifact = renderReport(report, format);
      assert.equal(artifact.content, renderReport(generateReport(assessment, 0, 0, profile), format).content);
      assert.equal(artifact.sha256, createHash('sha256').update(artifact.content).digest('hex'));
      assert.ok(!artifact.content.includes('token=hidden')); assert.match(artifact.content, /REDACTED/);
    }
  }
  assert.ok(generateReport(assessment, 0, 0, 'hackerone').sections.some(section => section.heading === 'Vulnerability information'));
  assert.ok(generateReport(assessment, 0, 0, 'bugcrowd').sections.some(section => section.heading === 'Description'));
  const changed = structuredClone(assessment); changed.targets[0]!.findings[0]!.detail = 'Changed';
  assert.notEqual(generateReport(changed, 0, 0).sourceSnapshotSha256, generateReport(assessment, 0, 0).sourceSnapshotSha256);
});

test('report export rejects unfinished runs and nonexistent selections; demos cannot look submission-ready', () => {
  for (const status of ['running','queued','stopping'] as const) assert.throws(() => generateReport({ ...assessment, status }, 0, 0), /wait_for_assessment/);
  for (const index of [-1, 0.5, Infinity]) assert.throws(() => generateReport(assessment, index, 0), /invalid_report_selection/);
  assert.throws(() => generateReport(assessment, 1, 0), /observation_not_found/);
  assert.throws(() => generateReport(assessment, 0, 2), /observation_not_found/);
  const demo = generateReport({ ...assessment, demo:true }, 0, 0);
  assert.ok(demo.blockers.some(message => message.includes('Synthetic demo')));
  for (const format of ['markdown','text','html'] as const) assert.match(renderReport(demo, format).content, /DO NOT SUBMIT/);
});

test('untrusted observation text is redacted and escaped for Markdown and offline HTML', () => {
  const hostile = structuredClone(assessment);
  hostile.targets[0]!.findings[0]!.detail = '<script>alert(1)</script> ![image](https://outside.test/pixel)\nAuthorization: Bearer secret-auth\npassword="secret-password" token=secret-token\nhttps://user:secret-password@app.example.test/?key=secret-query#secret-fragment\ncontact=private@example.test';
  const report = generateReport(hostile, 0, 0);
  for (const format of ReportFormat.options) {
    const content = renderReport(report, format).content;
    for (const secret of ['secret-auth','secret-password','secret-token','secret-query','secret-fragment','private@example.test']) assert.ok(!content.includes(secret), `${format}: ${secret}`);
  }
  const html = renderReport(report, 'html').content;
  assert.ok(!html.includes('<script>')); assert.ok(!html.includes('<img')); assert.match(html, /&lt;script&gt;/);
  const markdown = renderReport(report, 'markdown').content;
  assert.ok(!markdown.includes('![image]')); assert.ok(!markdown.includes('<script>'));
  assert.equal(redactReportText('Cookie: sid=secret\nSet-Cookie: sid=secret'), '[REDACTED HEADER]\n[REDACTED HEADER]');
});

test('report drafts persist reviewed edits as optimistic immutable revisions and reject stale or changed sources', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anteater-report-drafts-'));
  const selection = { assessmentId:assessment.id, targetIndex:0, findingIndex:0, profile:'hackerone' as const };
  const source = generateReport(assessment, 0, 0, 'hackerone').sourceSnapshotSha256;
  const store = new ReportDraftStore(directory);
  try {
    await store.init(); const edits = { impact:'Controlled impact claim.', steps:'1. Use the operator-controlled test identity.', customFields:[{ name:'Test account', value:'hunter@example.test' }] };
    const first = await store.save(selection, { expectedRevision:0, sourceSnapshotSha256:source, edits }, source);
    assert.equal(first.revision, 1); assert.equal(first.edits.customFields[0]?.value, '[REDACTED EMAIL]');
    await assert.rejects(store.save(selection, { expectedRevision:0, sourceSnapshotSha256:source, edits }, source), /report_draft_changed/);
    await assert.rejects(store.save(selection, { expectedRevision:1, sourceSnapshotSha256:'0'.repeat(64), edits }, source), /report_source_changed/);
    const concurrent = await Promise.allSettled([1,2].map(() => store.save(selection, { expectedRevision:1, sourceSnapshotSha256:source, edits }, source)));
    assert.equal(concurrent.filter(result => result.status==='fulfilled').length, 1);
    const restored = new ReportDraftStore(directory); await restored.init();
    assert.equal(restored.get(selection)?.versions.length, 2); assert.equal(restored.get(selection)?.versions[0]?.revision, 1);
    assert.equal(restored.get(selection)?.versions[1]?.edits.impact, edits.impact);
    assert.throws(() => restored.save(selection, { expectedRevision:2, sourceSnapshotSha256:source, edits:{ ...edits, customFields:[{ name:'Test',value:'' }, { name:'test',value:'' }] } }, source));
  } finally { await store.close(); await rm(directory, { recursive:true, force:true }); }
});

test('report HTTP preview and downloads require a session, validate format, and preserve the raw history route', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anteater-reports-'));
  const service = new CampaignService(directory, undefined, 1); const app = await createDashboard(service, 0);
  try {
    const id = await service.demo(); for (let i = 0; service.state().active && i < 100; i++) await sleep(10);
    const path = `/api/assessments/${id}/reports/0/0`;
    assert.equal((await fetch(app.origin + path)).status, 401);
    const cookie = (await fetch(app.origin)).headers.get('set-cookie')!.split(';')[0]!;
    const headers = { cookie };
    const preview = await (await fetch(app.origin + path + '?profile=bugcrowd', { headers })).json();
    assert.equal(preview.report.profile, 'bugcrowd'); assert.match(preview.markdown, /DO NOT SUBMIT/);
    const edits = { summary:'Researcher-provided summary.', impact:'No impact is established.', steps:'1. Reproduce in an owned lab.', customFields:[{ name:'Environment',value:'private@example.test' }] };
    const saved = await fetch(app.origin + path + '?profile=bugcrowd', { method:'POST', headers:{ ...headers, origin:app.origin, 'content-type':'application/json' }, body:JSON.stringify({ expectedRevision:0, sourceSnapshotSha256:preview.report.sourceSnapshotSha256, edits }) });
    assert.equal(saved.status, 200); assert.equal((await saved.json()).revision, 1);
    const edited = await (await fetch(app.origin + path + '?profile=bugcrowd', { headers })).json();
    assert.match(edited.markdown, /Researcher-provided text/); assert.match(edited.markdown, /No impact is established/);
    assert.doesNotMatch(edited.markdown, /private@example\.test/); assert.equal(edited.report.draftRevision.revision, 1);
    const stale = await fetch(app.origin + path + '?profile=bugcrowd', { method:'POST', headers:{ ...headers, origin:app.origin, 'content-type':'application/json' }, body:JSON.stringify({ expectedRevision:0, sourceSnapshotSha256:preview.report.sourceSnapshotSha256, edits }) });
    assert.equal(stale.status, 400); assert.match((await stale.json()).error, /changed_reload/);
    for (const format of ReportFormat.options) {
      const response = await fetch(app.origin + path + `?profile=hackerone&format=${format}`, { headers });
      assert.equal(response.status, 200); assert.match(response.headers.get('content-disposition')!, /attachment; filename="anteater-/);
      const content = await response.text();
      assert.equal(response.headers.get('x-content-sha256'), createHash('sha256').update(content).digest('hex'));
    }
    assert.equal((await fetch(app.origin + path + '?format=exe', { headers })).status, 400);
    assert.equal((await fetch(app.origin + `/api/assessments/${id}/reports/99/0`, { headers })).status, 400);
    assert.equal((await fetch(app.origin + `/api/assessments/${id}/report`, { headers })).status, 200);
    assert.equal(service.enabled, false);
  } finally { await app.close(); await rm(directory, { recursive:true, force:true }); }
});
