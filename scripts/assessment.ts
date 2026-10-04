import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

// A client of the same local API used by the browser; it never starts a second scanner.
const [command = 'list', argument, ...options] = process.argv.slice(2);
const base = new URL(process.env.ANTEATER_DASHBOARD_URL ?? 'http://127.0.0.1:4317');
if (base.protocol !== 'http:' || base.hostname !== '127.0.0.1' || base.pathname !== '/' || base.search || base.hash || base.username || base.password) throw new Error('local_dashboard_url_required');
const home = await fetch(base, { redirect: 'error', signal: AbortSignal.timeout(5000) });
if (!home.ok) throw new Error('dashboard_unavailable');
const cookie = home.headers.get('set-cookie')?.split(';')[0];
if (!cookie) throw new Error('dashboard_session_required');
let path = '/api/state'; let body: unknown;
if (command === 'preview' || command === 'start') {
  if (!argument) throw new Error('assessment_json_file_required');
  const content = await readFile(argument, 'utf8');
  if (Buffer.byteLength(content) > 32768) throw new Error('assessment_file_too_large');
  body = JSON.parse(content); path = command === 'preview' ? '/api/preview' : '/api/assessments';
} else if (command === 'cancel') {
  if (!argument || !/^[a-f0-9-]{36}$/.test(argument)) throw new Error('assessment_id_required');
  path = `/api/assessments/${argument}/cancel`; body = {};
} else if (command !== 'list') throw new Error('use_list_preview_start_or_cancel');
const key = options.find(option => option.startsWith('--key='))?.slice(6) ?? randomUUID();
if (command === 'start') console.error(`Submission key: ${key}. Reuse --key=${key} if retrying an uncertain response.`);
const response = await fetch(new URL(path, base), { method: body === undefined ? 'GET' : 'POST', redirect: 'error', signal: AbortSignal.timeout(15000),
  headers: { cookie, origin: base.origin, 'content-type': 'application/json', 'idempotency-key': key }, body: body === undefined ? undefined : JSON.stringify(body) });
const result = await response.json(); console.log(JSON.stringify(result, null, 2));
if (!response.ok) process.exitCode = 1;
