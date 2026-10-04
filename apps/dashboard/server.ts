import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { join, resolve } from 'node:path';
import { DashboardService } from './service.js';
import { CampaignError } from '../../packages/campaigns/contracts.js';
import { generateReport, renderReport, ReportFormat, ReportProfile } from '../../packages/reporting/index.js';
import { ReportDraftStore } from '../../packages/reporting/drafts.js';

export async function createDashboard(service: DashboardService, port = 4317) {
  await service.init();
  const reportDrafts = new ReportDraftStore(join(service.directory, 'report-drafts')); await reportDrafts.init();
  const token = randomBytes(32).toString('hex');
  const streams = new Set<http.ServerResponse>();
  const streamEpoch = randomBytes(8).toString('hex');
  let origin = '';
  const server = http.createServer(async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    const json = (status: number, body: unknown) => { response.writeHead(status, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(body)); };
    try {
      if (request.headers.host !== new URL(origin).host) { json(403, { error: 'invalid_host' }); return; }
      if (request.headers['sec-fetch-site'] === 'cross-site') { json(403, { error: 'cross_site_request' }); return; }
      const requestUrl = new URL(request.url ?? '/', origin);
      const path = requestUrl.pathname;
      const assets: Record<string, [string, string]> = { '/': ['index.html', 'text/html'], '/app.js': ['app.js', 'text/javascript'], '/styles.css': ['styles.css', 'text/css'] };
      if (request.method === 'GET' && assets[path]) {
        const [name, type] = assets[path];
        if (path === '/') response.setHeader('Set-Cookie', `anteater_session=${token}; HttpOnly; SameSite=Strict; Path=/`);
        response.writeHead(200, { 'Content-Type': `${type}; charset=utf-8` });
        response.end(await readFile(new URL(`./public/${name}`, import.meta.url))); return;
      }
      const cookie = /(?:^|;\s*)anteater_session=([a-f0-9]{64})(?:;|$)/.exec(request.headers.cookie ?? '')?.[1];
      if (!cookie || !timingSafeEqual(Buffer.from(cookie), Buffer.from(token))) { json(401, { error: 'open_dashboard_to_start_session' }); return; }
      if (request.method === 'GET' && path === '/api/state') { json(200, service.state()); return; }
      if (request.method === 'GET' && path === '/api/events') {
        response.writeHead(200, { 'Content-Type': 'text/event-stream', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
        streams.add(response); response.write('retry: 2000\n\n');
        let pending: ReturnType<typeof setTimeout> | undefined;
        const snapshot = () => {
          pending = undefined;
          if (response.destroyed) return;
          if (response.writableLength > 1048576) { response.end(); return; }
          const state = service.state();
          response.write(`id: ${streamEpoch}:${state.revision}\nevent: state\ndata: ${JSON.stringify(state)}\n\n`);
        };
        const unsubscribe = service.subscribe(() => { pending ??= setTimeout(snapshot, 40); });
        const heartbeat = setInterval(() => { if (!response.destroyed) response.write(': heartbeat\n\n'); }, 15000);
        response.on('close', () => { unsubscribe(); clearInterval(heartbeat); clearTimeout(pending); streams.delete(response); });
        // A complete snapshot also handles reconnects with a cursor from an earlier process.
        snapshot(); return;
      }
      const reportMatch = /^\/api\/assessments\/([a-f0-9-]{36})\/reports\/(\d{1,2})\/(\d{1,2})$/.exec(path);
      if (request.method === 'GET' && reportMatch) {
        const assessment = service.assessments.get(reportMatch[1]!);
        if (!assessment) { json(404, { error:'assessment_not_found' }); return; }
        const profile = ReportProfile.parse(requestUrl.searchParams.get('profile') ?? 'generic');
        const selection = { assessmentId:assessment.id, targetIndex:Number(reportMatch[2]), findingIndex:Number(reportMatch[3]), profile };
        const base = generateReport(assessment, selection.targetIndex, selection.findingIndex, profile);
        const draft = reportDrafts.get(selection), latest = draft?.versions.at(-1);
        const revision = requestUrl.searchParams.get('revision');
        if (revision !== null && !/^[1-9]\d?$/.test(revision)) throw new CampaignError('invalid_report_revision');
        const version = revision ? draft?.versions.find(item => item.revision === Number(revision)) : latest;
        if (revision && !version) throw new CampaignError('report_revision_not_found');
        const stale = Boolean(version && version.sourceSnapshotSha256 !== base.sourceSnapshotSha256);
        const report = { ...(version && !stale ? generateReport(assessment, selection.targetIndex, selection.findingIndex, profile, version.edits) : base),
          draftRevision:version ? { revision:version.revision, savedAt:version.savedAt, applied:!stale } : null };
        if (stale) report.blockers.unshift('Saved edits refer to an older source snapshot. Review and save a new revision before exporting those edits.');
        const requestedFormat = requestUrl.searchParams.get('format');
        if (!requestedFormat) {
          json(200, { report, markdown:renderReport(report, 'markdown').content, draft:version ?? null, stale,
            latestRevision:latest?.revision ?? 0, versions:draft?.versions.map(item => ({ revision:item.revision, savedAt:item.savedAt })) ?? [] }); return;
        }
        const artifact = renderReport(report, ReportFormat.parse(requestedFormat));
        response.setHeader('Content-Disposition', `attachment; filename="${artifact.filename}"`);
        response.setHeader('X-Content-SHA256', artifact.sha256);
        response.setHeader('Content-Security-Policy', "sandbox; default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'");
        response.writeHead(200, { 'Content-Type':`${artifact.mimeType}; charset=utf-8` }); response.end(artifact.content); return;
      }
      const exportId = /^\/api\/assessments\/([a-f0-9-]{36})\/report$/.exec(path)?.[1];
      if (request.method === 'GET' && exportId) {
        const assessment = service.assessments.get(exportId);
        if (!assessment) { json(404, { error: 'assessment_not_found' }); return; }
        response.setHeader('Content-Disposition', `attachment; filename="anteater-${exportId}.json"`);
        json(200, assessment); return;
      }
      if (request.method !== 'POST') { json(404, { error: 'not_found' }); return; }
      if (request.headers.origin !== origin || request.headers['content-type'] !== 'application/json') { json(403, { error: 'same_origin_json_required' }); return; }
      let body = ''; for await (const chunk of request) { body += chunk.toString(); if (Buffer.byteLength(body) > 32768) { json(413, { error: 'request_too_large' }); return; } }
      const input = JSON.parse(body || '{}');
      if (reportMatch) {
        const assessment = service.assessments.get(reportMatch[1]!);
        if (!assessment) { json(404, { error:'assessment_not_found' }); return; }
        const profile = ReportProfile.parse(requestUrl.searchParams.get('profile') ?? 'generic');
        const selection = { assessmentId:assessment.id, targetIndex:Number(reportMatch[2]), findingIndex:Number(reportMatch[3]), profile };
        const report = generateReport(assessment, selection.targetIndex, selection.findingIndex, profile);
        json(200, await reportDrafts.save(selection, input, report.sourceSnapshotSha256)); return;
      }
      if (path === '/api/controls') {
        if (typeof input.enabled !== 'boolean') throw new Error('invalid_control');
        service.setEnabled(input.enabled); json(200, service.state()); return;
      }
      if (path === '/api/preview') { json(200, service.preview(input)); return; }
      if (path === '/api/projects') { json(200, await service.saveProject(input)); return; }
      if (path === '/api/drafts') { json(200, await service.saveDraft(input)); return; }
      if (path === '/api/assessments') { json(201, { id: await service.start(input, false, typeof request.headers['idempotency-key'] === 'string' ? request.headers['idempotency-key'] : undefined) }); return; }
      if (path === '/api/demo') { json(201, { id: await service.demo() }); return; }
      const cancelId = /^\/api\/assessments\/([a-f0-9-]{36})\/cancel$/.exec(path)?.[1];
      if (cancelId) { service.cancel(cancelId); json(200, { ok: true }); return; }
      const archiveId = /^\/api\/assessments\/([a-f0-9-]{36})\/archive$/.exec(path)?.[1];
      if (archiveId) {
        if (typeof input.archived !== 'boolean') throw new CampaignError('invalid_archive_request');
        await service.archive(archiveId, input.archived); json(200, { ok: true }); return;
      }
      json(404, { error: 'not_found' });
    } catch (error) {
      const code = error instanceof Error && /^[a-z_]+$/.test(error.message) ? error.message : 'invalid_input_or_storage_error';
      if (!response.headersSent) json(400, { error: code, issues: error instanceof CampaignError ? error.issues : [] }); else response.end();
    }
  });
  server.requestTimeout = 15000;
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  const address = server.address() as { port: number }; origin = `http://127.0.0.1:${address.port}`;
  return { server, origin, close: async () => {
    await service.close();
    await reportDrafts.close();
    for (const stream of streams) stream.end();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  } };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const app = await createDashboard(new DashboardService(resolve(process.env.DASHBOARD_DATA_DIR ?? 'dashboard-data')), Number(process.env.DASHBOARD_PORT ?? 4317));
  console.log(`Anteater dashboard: ${app.origin} (live requests start disabled)`);
  for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => { void app.close().catch(() => { process.exitCode = 1; }); });
}
