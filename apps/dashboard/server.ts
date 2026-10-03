import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { DashboardService } from './service.js';

export async function createDashboard(service: DashboardService, port = 4317) {
  await service.init();
  const token = randomBytes(32).toString('hex');
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
      const path = new URL(request.url ?? '/', origin).pathname;
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
      if (path === '/api/controls') {
        if (typeof input.enabled !== 'boolean') throw new Error('invalid_control');
        service.setEnabled(input.enabled); json(200, service.state()); return;
      }
      if (path === '/api/assessments') { json(201, { id: await service.start(input) }); return; }
      if (path === '/api/demo') { json(201, { id: await service.demo() }); return; }
      const cancelId = /^\/api\/assessments\/([a-f0-9-]{36})\/cancel$/.exec(path)?.[1];
      if (cancelId) { service.cancel(cancelId); json(200, { ok: true }); return; }
      json(404, { error: 'not_found' });
    } catch (error) {
      const code = error instanceof Error && /^[a-z_]+$/.test(error.message) ? error.message : 'invalid_input_or_storage_error';
      if (!response.headersSent) json(400, { error: code }); else response.end();
    }
  });
  server.requestTimeout = 15000;
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  const address = server.address() as { port: number }; origin = `http://127.0.0.1:${address.port}`;
  return { server, origin, close: async () => {
    await service.close();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  } };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const app = await createDashboard(new DashboardService(resolve(process.env.DASHBOARD_DATA_DIR ?? 'dashboard-data')), Number(process.env.DASHBOARD_PORT ?? 4317));
  console.log(`Anteater dashboard: ${app.origin} (live requests start disabled)`);
  for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => { void app.close().catch(() => { process.exitCode = 1; }); });
}
