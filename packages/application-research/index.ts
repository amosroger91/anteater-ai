import type { Browser } from 'playwright';
import type { Config } from '../shared/config.js';
import { AccountStore, type Account } from './accounts.js';
import { BrowserSession, launchResearchBrowser } from './browser.js';
import { RequestGate, type Exchange } from './transport.js';
import { ApplicationSchema, type Application } from './profile.js';
import { imapVerifier, type VerifyMailbox } from './mailbox.js';
import { recoverOwnershipCleanup, verifyOwnership } from './verification.js';
import type { CleanupJournal } from './cleanup.js';
import { guardModelContext } from '../inert/index.js';

export interface ResearchDeps { browser?: Browser; exchange?: Exchange; mailbox?: VerifyMailbox; env?: NodeJS.ProcessEnv; cleanupJournal?: CleanupJournal }
export interface SessionCoverage { id: string; status: string; reason?: string; identityValidated: boolean }
export async function researchApplication(origin: string, rawApp: Application, config: Config, beforeRequest: (signal: AbortSignal) => Promise<void>, parentSignal?: AbortSignal, deps: ResearchDeps = {}) {
  const app = ApplicationSchema.parse(rawApp);
  const deadline = AbortSignal.timeout(app.maxDurationSeconds * 1000);
  const signal = parentSignal ? AbortSignal.any([parentSignal, deadline]) : deadline;
  const gate = new RequestGate(origin, app, signal, beforeRequest, deps.exchange, config.ALLOW_ACTIVE_TESTING, parentSignal);
  const env = deps.env ?? process.env;
  const gaps: string[] = [];
  const coverage: SessionCoverage[] = [];
  const secrets = new Set<string>();
  const browser = deps.browser ?? await launchResearchBrowser();
  const sessions: BrowserSession[] = [];
  const close = () => { for (const session of sessions) void session.close(); };
  // Keep authenticated cookies available for bounded cleanup after the assessment deadline.
  // Fleet cancellation still closes every context immediately.
  parentSignal?.addEventListener('abort', close, { once: true });
  let findings: Awaited<ReturnType<typeof verifyOwnership>> = [];
  const auth = app.auth;
  const store = config.ACCOUNT_KEY ? new AccountStore(config.CREDENTIAL_STORE, config.ACCOUNT_KEY) : undefined;
  try {
    signal.throwIfAborted();
    const publicSession = await BrowserSession.create(browser, 'anonymous', gate); sessions.push(publicSession);
    await publicSession.crawl(origin + '/', app);
    coverage.push({ id: 'anonymous', status: publicSession.inventory.length ? 'explored' : 'unreachable', identityValidated: false });
    const login = auth.loginPath ? new URL(auth.loginPath, origin).href : publicSession.inventory.find(page => page.login)?.login;
    const signup = auth.signupPath ? new URL(auth.signupPath, origin).href : publicSession.inventory.find(page => page.signup)?.signup;
    const accounts: Account[] = [];
    for (const entry of auth.accounts) {
      const username = env[entry.usernameEnv]; const password = env[entry.passwordEnv];
      if (!username || !password) { coverage.push({ id: entry.id, status: 'unavailable', reason: 'credentials_missing', identityValidated: false }); continue; }
      accounts.push({ id: entry.id, username, password, createdAt: new Date().toISOString(), registration: 'verified', role: entry.role, tenant: entry.tenant });
    }
    if (!accounts.length && auth.signupEnabled) {
      if (!config.ALLOW_ACTIVE_TESTING) gaps.push('registration_active_testing_disabled');
      else if (!store || !auth.mailbox) gaps.push('registration_requires_account_key_and_mailbox');
      else if (!signup) gaps.push('signup_not_discovered');
      else for (const id of ['account-a', 'account-b']) accounts.push(await store.prepare(new URL(origin).hostname, id, auth.mailbox.emailDomain));
    }
    if (!accounts.length) gaps.push(login ? 'authenticated_coverage_unavailable' : 'no_authentication_discovered');
    for (const account of accounts) { secrets.add(account.username); secrets.add(account.password); }
    const authenticated: BrowserSession[] = [];
    for (const account of accounts) {
      if (signal.aborted || gate.count >= app.maxRequests) { gaps.push('authentication_budget_exhausted'); break; }
      if (!config.ALLOW_ACTIVE_TESTING) { coverage.push({ id: account.id, status: 'unavailable', reason: 'login_active_testing_disabled', identityValidated: false }); continue; }
      if (!login) { coverage.push({ id: account.id, status: 'unavailable', reason: 'login_not_discovered', identityValidated: false }); continue; }
      const session = await BrowserSession.create(browser, account.id, gate); sessions.push(session);
      let reason: string | undefined;
      try {
        if (account.registration !== 'verified' && store && signup) {
          session.purpose = 'signup';
          if (account.registration === 'prepared') {
            await session.visit(signup);
            reason = await session.fillAccount(account, true);
            if (!reason) {
              // Persist before submitting: a crash must not blindly register another account.
              account.registration = 'submitted'; await store.put(new URL(origin).hostname, account);
              await session.submitAccount();
            }
          }
          if (!reason && auth.mailbox) {
            const verifier = deps.mailbox ?? imapVerifier(auth.mailbox, env);
            const link = await verifier(account, origin, auth, signal);
            if (link) await session.visit(link);
            // Sites without email confirmation can still pass the identity check below.
          }
        }
        if (!reason) {
          session.purpose = 'login'; await session.visit(login);
          reason = await session.fillAccount(account, false);
          if (!reason) {
            await session.submitAccount();
            if (!await session.authenticated(account, app)) reason = await session.challenge() ? 'interactive_challenge' : 'session_not_validated';
          }
        }
        if (reason) coverage.push({ id: account.id, status: 'unavailable', reason, identityValidated: false });
        else {
          account.registration = 'verified';
          if (store && !auth.accounts.some(entry => entry.id === account.id)) await store.put(new URL(origin).hostname, account);
          coverage.push({ id: account.id, status: 'authenticated', identityValidated: Boolean(auth.sessionPath) });
          session.purpose = 'discover';
          if (auth.sessionPath) authenticated.push(session);
        }
      } catch { coverage.push({ id: account.id, status: 'unavailable', reason: 'authentication_failed', identityValidated: false }); }
    }
    const recovered = await recoverOwnershipCleanup(app, origin, authenticated, gaps, deps.cleanupJournal);
    if (recovered) findings = await verifyOwnership(app, authenticated, gaps, deps.cleanupJournal);
    for (const session of authenticated) await session.crawl(origin + '/', app);
    if (sessions.some(session => session.fatal === 'kill_switch')) throw new Error('kill_switch');
  } catch (error) {
    if (parentSignal?.aborted || (error instanceof Error && error.message === 'kill_switch')) throw error;
    gaps.push(deadline.aborted ? 'assessment_deadline' : 'assessment_interrupted');
  } finally {
    parentSignal?.removeEventListener('abort', close);
    await Promise.allSettled(sessions.map(session => session.close()));
    if (!deps.browser) await browser.close();
  }
  const redact = (value: string) => guardModelContext(value).redacted;
  const inventory = sessions.flatMap(session => session.inventory.map(page => ({ session: session.id, url: redact(page.url), title: redact(page.title), links: page.links.map(redact), forms: page.forms.map(form => ({ ...form, action: redact(form.action) })) })));
  const errors = [...new Set(sessions.flatMap(session => session.errors))];
  for (const entry of auth.accounts) {
    if (!coverage.some(row => row.id === entry.id && row.status === 'authenticated' && row.identityValidated)) gaps.push(`account_unavailable:${entry.id}`);
  }
  const report = { kind: 'OBSERVATION', executor: 'application-browser', target: origin,
    coverage: { sessions: coverage, pages: inventory.length, requests: gate.count, blocked: gate.blocked, gaps: [...new Set(gaps)], errors,
      complete: !gaps.length && !errors.length && !Object.keys(gate.blocked).length && !coverage.some(row => row.status === 'unavailable' || row.status === 'unreachable') }, inventory, endpoints: gate.endpoints, findings,
    signals: findings.map(finding => ({ code: finding.code, severity: finding.severity, detail: `Reproduced under rule ${finding.rule}; awaiting human review` })) };
  // Remove exact credential values even if the application echoes them in titles or URLs.
  let serialized = JSON.stringify(report);
  for (const secret of secrets) if (secret) for (const variant of [secret, encodeURIComponent(secret)]) serialized = serialized.replaceAll(JSON.stringify(variant).slice(1, -1), '[redacted]');
  return JSON.parse(serialized) as typeof report;
}
