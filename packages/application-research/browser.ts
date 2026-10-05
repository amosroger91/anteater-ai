import { chromium, type Browser, type BrowserContext, type Page } from 'playwright';
import { RequestGate, publicUrl, type Purpose, type ExchangeResponse } from './transport.js';
import { jsonPointer, type Application } from './profile.js';
import type { Account } from './accounts.js';

export interface PageInventory { url: string; title: string; links: string[]; forms: Array<{ action: string; method: string; fields: string[] }>; login?: string; signup?: string }
export class BrowserSession {
  purpose: Purpose = 'discover';
  readonly visited = new Set<string>();
  readonly inventory: PageInventory[] = [];
  readonly errors: string[] = [];
  fatal?: string;
  private authorization?: string;
  private pending = new Set<Promise<unknown>>();
  private constructor(readonly id: string, readonly context: BrowserContext, readonly page: Page, readonly gate: RequestGate) {}
  static async create(browser: Browser, id: string, gate: RequestGate) {
    const context = await browser.newContext({ serviceWorkers: 'block', acceptDownloads: false, permissions: [], viewport: { width: 1280, height: 800 } });
    context.setDefaultTimeout(4000); context.setDefaultNavigationTimeout(15000);
    const page = await context.newPage();
    const session = new BrowserSession(id, context, page, gate);
    context.on('page', extra => { if (extra !== page) void extra.close(); });
    page.on('dialog', dialog => { void dialog.dismiss(); });
    await context.routeWebSocket('**/*', socket => { gate.deny('websocket'); socket.close(); });
    await context.route('**/*', async route => {
      const task = (async () => {
        try {
          const request = route.request();
          if (['image', 'media', 'font'].includes(request.resourceType())) { await route.abort(); return; }
          const headers = await request.allHeaders();
          if (new URL(request.url()).origin === gate.origin && headers.authorization) session.authorization = headers.authorization;
          const result = await gate.send(id, session.purpose, request.url(), request.method(), headers, request.postDataBuffer() ?? undefined);
          if (result.truncated || (result.headers['content-encoding'] && result.headers['content-encoding'] !== 'identity')) {
            gate.deny(result.truncated ? 'response_truncated' : 'unsupported_encoding'); await route.abort(); return;
          }
          const responseHeaders: Record<string, string> = {};
          for (const [key, value] of Object.entries(result.headers)) {
            if (value === undefined || ['content-length', 'transfer-encoding', 'connection', 'content-encoding'].includes(key)) continue;
            responseHeaders[key] = Array.isArray(value) ? value.join('\n') : String(value);
          }
          await route.fulfill({ status: result.status, headers: responseHeaders, body: result.body });
        } catch (error) {
          const code = error instanceof Error && /^[a-z_]+$/.test(error.message) ? error.message : 'request_failed';
          if (code === 'kill_switch') session.fatal = code;
          if (session.errors.length < 50) session.errors.push(code);
          await route.abort().catch(() => {});
        }
      })();
      session.pending.add(task); try { await task; } finally { session.pending.delete(task); }
    });
    return session;
  }
  async settle() { await this.page.waitForTimeout(100); await Promise.allSettled([...this.pending]); }
  async visit(url: string): Promise<PageInventory | undefined> {
    this.gate.signal.throwIfAborted();
    try {
      await this.page.goto(url, { waitUntil: 'domcontentloaded' }); await this.settle();
      const raw = await this.page.evaluate(() => {
        const links = [...document.querySelectorAll('a[href]')].slice(0, 200).map(a => ({ url: (a as HTMLAnchorElement).href, label: a.textContent?.trim().slice(0, 100) ?? '' }));
        return { title: document.title.slice(0, 150), links,
          forms: [...document.forms].slice(0, 20).map(form => ({ action: form.action, method: form.method.toUpperCase(), fields: [...form.querySelectorAll('input,textarea,select')].map(e => (e as HTMLInputElement).name || (e as HTMLInputElement).type).slice(0, 30) })),
          hasPassword: !!document.querySelector('input[type=password]') };
      });
      const urlNow = this.page.url();
      if (new URL(urlNow).origin !== this.gate.origin) return undefined;
      const links = raw.links.filter(link => { try { return new URL(link.url).origin === this.gate.origin; } catch { return false; } });
      const result: PageInventory = { url: publicUrl(urlNow), title: raw.title, links: links.map(link => publicUrl(link.url)), forms: raw.forms.map(form => ({ ...form, action: (() => { try { return publicUrl(form.action); } catch { return '[invalid]'; } })() })),
        login: links.find(link => /log.?in|sign.?in/i.test(link.label + ' ' + new URL(link.url).pathname))?.url,
        signup: links.find(link => /sign.?up|register|create.account/i.test(link.label + ' ' + new URL(link.url).pathname))?.url };
      if (raw.hasPassword && /login|signin|sign-in/i.test(new URL(urlNow).pathname)) result.login = urlNow;
      if (raw.hasPassword && /signup|register|sign-up/i.test(new URL(urlNow).pathname)) result.signup = urlNow;
      this.inventory.push(result); this.visited.add(urlNow);
      return result;
    } catch { this.errors.push('navigation_failed'); return undefined; }
  }
  async crawl(start: string, app: Application) {
    const queue = [{ url: start, depth: 0 }]; const queued = new Set([start]);
    while (queue.length && !this.fatal && this.visited.size < app.maxPages && !this.gate.signal.aborted && this.gate.count < app.maxRequests) {
      const next = queue.shift()!;
      const item = await this.visit(next.url); if (!item || next.depth >= app.maxDepth) continue;
      for (const value of item.links) {
        const url = new URL(value); url.hash = '';
        // Query variants are recorded as endpoints; navigation avoids token values and combinatorial loops.
        if (url.search || queued.has(url.href)) continue;
        queued.add(url.href); if (queue.length < app.maxPages * 4) queue.push({ url: url.href, depth: next.depth + 1 });
      }
    }
  }
  async challenge(): Promise<boolean> {
    return await this.page.locator('iframe[src*="captcha"], [data-sitekey], input[autocomplete="one-time-code"], input[name*="otp"], input[name*="captcha"]').count() > 0;
  }
  async fillAccount(account: Account, signup: boolean): Promise<string | undefined> {
    if (await this.challenge()) return 'interactive_challenge';
    const password = this.page.locator('input[type=password]:visible').first();
    if (!await password.count()) return 'unsupported_auth_form';
    const form = password.locator('xpath=ancestor::form[1]');
    if (!await form.count()) return 'unsupported_auth_form';
    const user = form.locator('input[type=email], input[autocomplete=username], input[name=username], input[name=email], input[type=text]').first();
    if (!await user.count()) return 'unsupported_auth_form';
    if (signup && await form.locator('input[type=checkbox][required]:not(:checked)').count()) return 'registration_requires_consent';
    await user.fill(account.username);
    for (const field of await form.locator('input[type=password]').all()) await field.fill(account.password);
    if (signup) for (const field of await form.locator('input[type=text][required]').all()) if (!await field.inputValue()) await field.fill('Anteater test account');
    return undefined;
  }
  async submitAccount() {
    const form = this.page.locator('input[type=password]:visible').first().locator('xpath=ancestor::form[1]');
    await form.evaluate((element: HTMLFormElement) => element.requestSubmit());
    await this.page.waitForTimeout(300); await this.settle();
  }
  async request(url: string, method = 'GET', body?: unknown): Promise<ExchangeResponse> {
    const headers: Record<string, string> = {};
    const cookies = await this.context.cookies(url); if (cookies.length) headers.cookie = cookies.map(cookie => `${cookie.name}=${cookie.value}`).join('; ');
    if (this.authorization) headers.authorization = this.authorization;
    if (body !== undefined) headers['content-type'] = 'application/json';
    return this.gate.send(this.id, this.purpose, url, method, headers, body === undefined ? undefined : Buffer.from(JSON.stringify(body)));
  }
  async authenticated(account: Account, app: Application): Promise<boolean> {
    if (await this.challenge()) return false;
    if (app.auth.sessionPath) {
      const response = await this.request(new URL(app.auth.sessionPath, this.gate.origin).href);
      try { return response.status === 200 && jsonPointer(JSON.parse(response.body.toString()), app.auth.identityPointer) === account.username; } catch { return false; }
    }
    return await this.page.locator('input[type=password]:visible').count() === 0 && await this.page.getByRole('link', { name: /log.?out|sign.?out/i }).count() > 0;
  }
  async close() { await this.context.close().catch(() => {}); }
}
export async function launchResearchBrowser() {
  return chromium.launch({ headless: true, chromiumSandbox: true, args: ['--disable-background-networking', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--disable-quic'] });
}
