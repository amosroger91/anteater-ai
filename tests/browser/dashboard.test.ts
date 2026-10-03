import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright';
import { createDashboard } from '../../apps/dashboard/server.js';
import { DashboardService } from '../../apps/dashboard/service.js';

test('dashboard demo, scope form, report and mobile layout work in Chromium', { timeout: 60000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anteater-dashboard-ui-'));
  const requests: string[] = [];
  const service = new DashboardService(directory, async (target, options) => {
    await options.beforeRequest?.(); requests.push(target);
    return { status: 200, contentType: 'text/html', signals: [{ code: 'missing_hsts', severity: 'medium', detail: '<script>untrusted text</script>' }] };
  }, 10);
  const app = await createDashboard(service, 0); const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1050 } });
    const errors: string[] = []; page.on('pageerror', error => errors.push(error.message));
    await page.goto(app.origin);
    await page.getByRole('button', { name: 'Explore a demo' }).click();
    await page.waitForFunction(() => document.getElementById('run-status')?.textContent === 'completed');
    assert.equal(requests.length, 0, 'demo never invokes real transport');
    assert.equal(await page.locator('#metric-findings').textContent(), '2');
    assert.ok(await page.locator('#demo-notice').isVisible());
    const download = page.waitForEvent('download'); await page.getByRole('link', { name: /Download report/ }).click();
    assert.match((await download).suggestedFilename(), /^anteater-.*\.json$/);
    if (process.env.DASHBOARD_SCREENSHOT_DIR) await page.screenshot({ path: join(process.env.DASHBOARD_SCREENSHOT_DIR, 'anteater-dashboard-desktop.png'), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'mobile has no horizontal overflow');
    if (process.env.DASHBOARD_SCREENSHOT_DIR) await page.screenshot({ path: join(process.env.DASHBOARD_SCREENSHOT_DIR, 'anteater-dashboard-mobile.png'), fullPage: true });
    await page.getByRole('button', { name: 'Enable passive requests' }).click();
    await page.getByRole('button', { name: 'New assessment', exact: true }).click();
    await page.getByLabel('Assessment name').fill('Owned portal');
    await page.getByLabel('Authorized hosts').fill('app.example.test\napi.example.test');
    await page.getByLabel('Policy or authorization URL').fill('https://example.test/policy');
    await page.getByLabel('I reviewed the authorization', { exact: false }).check();
    await page.getByRole('button', { name: 'Start assessment' }).click();
    await page.waitForFunction(() => document.getElementById('page-title')?.textContent === 'Owned portal' && document.getElementById('run-status')?.textContent === 'completed');
    assert.deepEqual(requests, ['https://app.example.test/', 'https://api.example.test/']);
    assert.equal(await page.locator('#findings-list script').count(), 0, 'remote findings are rendered as text');
    await page.reload(); await page.waitForFunction(() => document.getElementById('page-title')?.textContent === 'Owned portal');
    assert.deepEqual(errors, []);
  } finally { await browser.close(); await app.close(); await rm(directory, { recursive: true, force: true }); }
});
