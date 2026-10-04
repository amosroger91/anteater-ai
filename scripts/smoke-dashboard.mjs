import assert from 'node:assert/strict';
import { access, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { createDashboard } from '../dist/apps/dashboard/server.js';
import { CampaignService } from '../dist/packages/campaigns/service.js';

const directory = await mkdtemp(join(tmpdir(), 'anteater-build-smoke-'));
let app;
try {
  app = await createDashboard(new CampaignService(directory, async () => { throw new Error('unexpected_live_request'); }, 1), 0);
  const home = await fetch(app.origin);
  assert.equal(home.status, 200); assert.match(await home.text(), /scope-preview/);
  const cookie = home.headers.get('set-cookie').split(';')[0];
  for (const asset of ['app.js', 'styles.css']) {
    const response = await fetch(`${app.origin}/${asset}`); assert.equal(response.status, 200); assert.ok((await response.text()).length > 100);
  }
  await access(new URL('../dist/infrastructure/postgres/006_cleanup.sql', import.meta.url));
  const response = await fetch(app.origin + '/api/demo', { method: 'POST', headers: { cookie, origin: app.origin, 'content-type': 'application/json' }, body: '{}' });
  assert.equal(response.status, 201);
  let state;
  for (let i = 0; i < 100; i++) {
    state = await (await fetch(app.origin + '/api/state', { headers: { cookie } })).json();
    if (!state.active) break;
    await sleep(20);
  }
  assert.equal(state.active, null); assert.equal(state.enabled, false);
  assert.equal(state.assessments[0].status, 'completed_with_gaps');
  assert.equal(state.assessments[0].demo, true);
  console.log('Compiled dashboard: static assets, migrations, session and synthetic demo passed.');
} finally {
  await app?.close(); await rm(directory, { recursive: true, force: true });
}
