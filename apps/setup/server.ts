import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { blankProfile, mergeProfile, profileStatus, SetupRequestSchema } from '../../packages/setup/profile.js';
import type { FileSetupStore } from '../../packages/setup/store.js';
import { publicFixtureScan, runLocalFixtureScan } from '../orchestrator/fixture-campaign.js';
import { scanSavedLab } from './lab-scan.js';
import type { PassiveDeps } from '../../packages/web-executor/index.js';

const page = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
const scanner = readFileSync(new URL('./run.html', import.meta.url), 'utf8');
const MAX_BODY = 32_768;

export interface SetupStore {
  read(): ReturnType<FileSetupStore['read']>;
  write(profile: ReturnType<typeof blankProfile>): void;
}

function loopback(request: IncomingMessage): boolean {
  const address = request.socket.remoteAddress;
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1';
}

function send(response: ServerResponse, status: number, body: unknown, type = 'application/json'): void {
  const payload = type === 'application/json' ? JSON.stringify(body) : String(body);
  response.writeHead(status, {
    'content-type': `${type}; charset=utf-8`,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  response.end(payload);
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > MAX_BODY) throw new Error('setup_too_large');
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export function createSetupServer(store: SetupStore, options: { labDeps?: PassiveDeps } = {}) {
  return createServer(async (request, response) => {
    try {
      if (!loopback(request)) { send(response, 403, { error: 'loopback_only' }); return; }
      const url = new URL(request.url ?? '/', 'http://127.0.0.1');
      if (request.method === 'GET' && url.pathname === '/') { send(response, 200, page, 'text/html'); return; }
      if (request.method === 'GET' && url.pathname === '/run') { send(response, 200, scanner, 'text/html'); return; }
      if (request.method === 'POST' && url.pathname === '/api/scan/lab') {
        const origin = request.headers.origin;
        if (origin && !/^http:\/\/127\.0\.0\.1:\d+$/.test(origin)) { send(response, 403, { error: 'origin_rejected' }); return; }
        if (!request.headers['content-type']?.includes('application/json')) { send(response, 415, { error: 'json_required' }); return; }
        const body = JSON.parse(await readBody(request)) as { host?: unknown };
        try {
          send(response, 200, await scanSavedLab(store.read() ?? blankProfile(), typeof body.host === 'string' ? body.host : '', options.labDeps));
        } catch (error) {
          const code = error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : 'scan_failed';
          send(response, 400, { error: code });
        }
        return;
      }
      if (request.method === 'POST' && url.pathname === '/api/scan/fixture') {
        const origin = request.headers.origin;
        if (origin && !/^http:\/\/127\.0\.0\.1:\d+$/.test(origin)) { send(response, 403, { error: 'origin_rejected' }); return; }
        send(response, 200, publicFixtureScan(await runLocalFixtureScan()));
        return;
      }
      if (request.method === 'GET' && url.pathname === '/api/status') {
        send(response, 200, profileStatus(store.read()));
        return;
      }
      if (request.method === 'POST' && url.pathname === '/api/keys') {
        send(response, 200, { accountKey: randomBytes(32).toString('hex'), evidenceKey: randomBytes(32).toString('hex') });
        return;
      }
      if (request.method === 'POST' && url.pathname === '/api/setup') {
        const origin = request.headers.origin;
        if (origin && !/^http:\/\/127\.0\.0\.1:\d+$/.test(origin)) { send(response, 403, { error: 'origin_rejected' }); return; }
        if (!request.headers['content-type']?.includes('application/json')) { send(response, 415, { error: 'json_required' }); return; }
        const parsed = SetupRequestSchema.safeParse(JSON.parse(await readBody(request)));
        if (!parsed.success) { send(response, 400, { error: 'invalid_setup' }); return; }
        let stored;
        try { stored = mergeProfile(store.read() ?? blankProfile(), parsed.data); }
        catch (error) {
          const code = error instanceof Error ? error.message : 'invalid_setup';
          send(response, 400, { error: /^[a-z0-9_]+$/.test(code) ? code : 'invalid_setup' });
          return;
        }
        store.write(stored);
        send(response, 200, profileStatus(stored));
        return;
      }
      send(response, 404, { error: 'not_found' });
    } catch (error) {
      const code = error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : 'setup_failed';
      send(response, 400, { error: code });
    }
  });
}
