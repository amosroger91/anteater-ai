// Request budgets and resource limits (PRODUCTION_ROADMAP.md §4/§7). Pure, injectable-clock
// primitives applied to browser, HTTP and every adapter: per-host rate, concurrency, body caps,
// timeouts. Deterministic and testable without wall-clock sleeps.

export class TokenBucket {
  private tokens: number;
  private last: number;
  constructor(private ratePerSec: number, private burst: number, now = 0) {
    if (ratePerSec <= 0 || burst <= 0) throw new Error('invalid_budget');
    this.tokens = burst; this.last = now;
  }
  tryTake(now: number): boolean {
    this.tokens = Math.min(this.burst, this.tokens + (now - this.last) / 1000 * this.ratePerSec);
    this.last = now;
    if (this.tokens >= 1) { this.tokens -= 1; return true; }
    return false;
  }
}

export class Concurrency {
  private active = 0;
  constructor(private max: number) { if (max < 1) throw new Error('invalid_concurrency'); }
  get inUse(): number { return this.active; }
  tryAcquire(): boolean { if (this.active >= this.max) return false; this.active++; return true; }
  release(): void { if (this.active > 0) this.active--; }
}

export function assertBodyWithinCap(byteLength: number, capBytes: number): void {
  if (byteLength > capBytes) throw new Error('body_cap_exceeded');
}

// A composed per-program budget: global + per-host rate, a concurrency ceiling, and caps.
export interface BudgetConfig { globalRatePerSec: number; perHostRatePerSec: number; concurrency: number; bodyCapBytes: number; timeoutMs: number }

export class ProgramBudget {
  private global: TokenBucket;
  private perHost = new Map<string, TokenBucket>();
  private concurrency: Concurrency;
  constructor(private cfg: BudgetConfig, private now = () => Date.now()) {
    this.global = new TokenBucket(cfg.globalRatePerSec, Math.max(1, Math.ceil(cfg.globalRatePerSec)), this.now());
    this.concurrency = new Concurrency(cfg.concurrency);
  }
  allow(host: string): { ok: boolean; reason: string } {
    const t = this.now();
    if (!this.concurrency.tryAcquire()) return { ok: false, reason: 'concurrency_exceeded' };
    if (!this.global.tryTake(t)) { this.concurrency.release(); return { ok: false, reason: 'global_rate_exceeded' }; }
    let bucket = this.perHost.get(host);
    if (!bucket) { bucket = new TokenBucket(this.cfg.perHostRatePerSec, Math.max(1, Math.ceil(this.cfg.perHostRatePerSec)), t); this.perHost.set(host, bucket); }
    if (!bucket.tryTake(t)) { this.concurrency.release(); return { ok: false, reason: 'host_rate_exceeded' }; }
    return { ok: true, reason: 'ok' };
  }
  done(): void { this.concurrency.release(); }
  get timeoutMs(): number { return this.cfg.timeoutMs; }
  get bodyCapBytes(): number { return this.cfg.bodyCapBytes; }
}
