import http from 'node:http';
import { readFile } from 'node:fs/promises';
import type pg from 'pg';
import { dashboardState } from './service.js';

// Loopback-only read-only dashboard. It never mutates state and never contacts a target; it only
// reports what the worker has already recorded in the database.
export function createDashboardServer(pool: Pick<pg.Pool, 'query'>): http.Server {
  return http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? '/', 'http://127.0.0.1');
      if (request.method === 'GET' && url.pathname === '/api/state') {
        const body = JSON.stringify(await dashboardState(pool));
        response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        response.end(body);
        return;
      }
      if (request.method === 'GET' && url.pathname === '/') {
        const page = await readFile(new URL('./public/index.html', import.meta.url), 'utf8');
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        response.end(page);
        return;
      }
      response.writeHead(404, { 'content-type': 'text/plain' });
      response.end('not found');
    } catch {
      response.writeHead(500, { 'content-type': 'text/plain' });
      response.end('error');
    }
  });
}
