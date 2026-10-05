# Earning real bug-bounty money with Anteater

A build-and-operate plan to take this codebase from a safe, fixture-validated prototype to a system
that produces **accepted, paid** bug-bounty submissions. Written against the code as it exists today,
and deliberately honest about where the money actually is and what it will take.

---

## 0. Honest starting point

What exists (per [READINESS.md](READINESS.md)) is a well-engineered, **passive, read-only research
framework** with the live paths off by default:

- `GLOBAL_KILL_SWITCH` defaults on; `ENABLE_PASSIVE_HTTP` and `ENABLE_APPLICATION_RESEARCH` are both
  opt-in and currently off.
- Scope is deliberately narrow: HTTPS/443 only, five read-only actions
  (`inspect_http_target|robots|sitemap|openapi`, `research_application`), exclusions and expiry
  enforced, DNS-pinned HTTPS with private-IP blocking.
- Durable Postgres job queue (leases, fencing, retries, dead-letter), DB-enforced finding lifecycle
  (`VERIFIED`/`SUBMITTED` require a transaction actor), human submission via `finding:submit`.
- Candidate discovery/admission, methodology registry, web/API checks, verification/replay, evidence
  utilities, auth/multi-role scaffolding — mostly **built and tested, but not yet wired into one live
  campaign**.

**It has never contacted a real target and has never submitted a finding.** Zero dollars earned. The
distance to money is not "more modules"; it is wiring + real-target proof + a human triage loop + the
right target selection.

---

## 1. The economic reality — read this before building anything

Most bug-bounty money does **not** come from what scanners find. It comes from:

1. **Business-logic flaws** (price/workflow/race abuse) — humans only.
2. **Access control / IDOR / BOLA** — the biggest automatable-ish category, but needs authenticated,
   multi-role, app-aware testing and human judgment of impact.
3. **Chained bugs** (info-leak + weak endpoint → account takeover) — human reasoning.
4. **First-finder on newly exposed assets** — subdomain takeover, exposed `.git`/`.env`, default creds,
   leaked secrets, exposed admin/dashboards. **This is the category automation genuinely wins**, because
   it is a *race* and a *monitoring* problem, not a cleverness problem.

What automated passive scanning earns on its own: **close to nothing.** Missing security headers, weak
TLS, cookie flags, version banners are triaged as *Informational* — $0 — and spamming them damages your
platform reputation and gets you throttled or removed. Every serious program is already scanned by
thousands of people and by the vendor's own tooling.

**Implication for Anteater's strategy:** its durable edge is **continuous monitoring + first-finder
speed + evidence-grade triage that feeds a human**, not "autonomous scanner." Build toward that, or it
loses money.

### The anti-automation trap (viability killer)

Many programs **explicitly forbid automated scanning / high request rates.** Violating that gets you
banned, which ends income. So the program-intake stage must classify each program as:

- **Automation-permitted** → Anteater's discovery + passive + rate-bounded checks may run.
- **Manual-only** → Anteater runs *recon/monitoring only* (usually allowed) and a human does the testing.
- **Out / no safe harbor / no web scope** → never touched.

This classification is a first-class, human-reviewed input, not a guess.

---

## 2. Non-negotiables (ethics = survival here)

These are both the right thing and the thing that keeps the income stream alive:

- Only enrolled programs with published scope and safe harbor. Honor scope, exclusions, rate limits,
  and testing restrictions exactly — the scope engine already fails closed; keep it that way.
- **A human reviews and submits every finding.** No autonomous submission, ever. The DB actor guard
  already enforces this; do not weaken it.
- Proof-of-concept only. No data exfiltration beyond the minimum to demonstrate impact; no pivoting,
  no lateral movement, no destructive payloads, no touching other users' real data.
- Deduplicate against the program's known issues and your own prior submissions before sending.
- Never bypass anti-automation controls (CAPTCHA/MFA/WAF). Report them as coverage gaps (the `session`
  module already classifies these) and move on.

---

## 3. Where to aim first (highest $ per unit of effort, in order)

1. **Continuous asset discovery + first-finder monitoring.** Subdomain takeover, dangling DNS/CNAME,
   newly exposed `.git`/`.env`/`.DS_Store`, exposed admin panels / `/actuator` / debug endpoints,
   default or leaked credentials, public cloud buckets, secrets in served JS. These pay (Low–High) and
   reward the machine that checks *first, continuously, across many assets*. Anteater's discovery +
   change-detection + candidate admission is purpose-built for this.
2. **High-signal passive/active-light checks mapped to paid severities.** CORS-with-credentials, open
   redirect that enables token theft, SSRF via known sinks, authz misconfig on discovered endpoints.
3. **Authenticated access-control (IDOR/BOLA).** Highest reliable $ per finding. Needs the
   `application-research` auth flows + `authz` matrix wired into a persistent, evidence-producing
   campaign with disposable test data.

Explicitly **de-prioritize** header/TLS/cookie "findings" as submissions — keep them only as internal
coverage signal, never as bounty reports.

---

## 4. Build plan — phases, each with an exit criterion and a safety gate

### Phase 0 — Prove the loop offline, then on one owned staging app
Close the open [READINESS.md](READINESS.md) gates that block *any* live use:
- Wire discovery → admission → passive executor → detectors → finding lifecycle → evidence into **one
  persistent campaign** (`apps/orchestrator/campaign.ts` is the seam; most detector packages are not
  yet live worker stages).
- Independently test outbound egress outside Playwright routing: DNS rebinding, redirects, subresources,
  frames, workers, WebSockets.
- Run end-to-end against an **owned vulnerable/patched staging app** + real test mailbox: prove identity,
  isolation, marker cleanup, cleanup after timeout/crash, safe behavior under mailbox/network failure.
- **Exit:** a seeded access-control bug on staging is discovered, verified by deterministic replay,
  evidence captured, a report drafted, and a human submits it through `finding:submit` — all green,
  including `verify:local`. No real program yet.
- **Gate:** both live flags stay off until this passes.

### Phase 1 — Real program intake + scope compiler
- Build adapters that import published program rules/scope from the platforms you join (start with one:
  HackerOne *or* Bugcrowd *or* Intigriti *or* YesWeHack). Capture scope, exclusions, rate rules, and the
  **automation-permitted** classification from §1.
- Human approves each compiled scope; store provenance (`packages/provenance` already verifies approver
  + source hash + expiry).
- **Exit:** three real programs compiled, human-approved, with correct automation classification, and
  out-of-scope/excluded names provably never queued.

### Phase 2 — Continuous discovery + change detection (the first-finder engine)
- Wire live CT-log + Subfinder + passive-DNS adapters (built, currently offline) behind per-program
  rate budgets and candidate-only admission.
- Persist assets with first-seen/last-seen; alert on *new* exposure between runs (this is the money
  signal).
- **Exit:** a newly exposed seeded asset on staging is detected within one scheduled cycle and raised as
  a candidate, never contacted if out of scope.

### Phase 3 — Paid-severity detectors with fixtures
- Implement the §3.1 detectors (takeover, exposed `.git`/`.env`, exposed admin, default creds, CORS,
  SSRF-sink, open-redirect-to-takeover), each with **vulnerable + patched fixtures** that pass the
  release gate (`npm run gate`) and a methodology mapping. False-positive rate is the KPI, not count.
- **Exit:** every enabled detector has fixtures, a policy-denial test, and a recorded coverage mapping.

### Phase 4 — Authenticated access-control testing
- Wire `application-research` (two ordinary users + a least-privileged admin, role-labeled) + `authz`
  cross-role probes + ownership-replay into the campaign, with disposable test data and guaranteed
  cleanup.
- **Exit:** seeded cross-user/cross-tenant reads are found on staging, patched variants rejected,
  sessions isolated, no test resources left behind.

### Phase 5 — Verification, evidence, report, human triage
- Deterministic replay promotes to `VERIFIED`; redacted/encrypted evidence persisted; auto-draft a
  reviewer-editable report with impact + remediation (`packages/remediation` exists); dedupe against
  prior submissions; queue for human.
- **Exit:** a finding flows candidate → verified → human-reviewed → submitted with a clean report and a
  dedupe check, end to end.

### Phase 6 — Scale, operate, and measure the money
- Schedule across many programs with global/per-program budgets; dead-letter + retention + kill/
  revocation are already wired; add metrics, alerts, backup/restore, crash drills (open in READINESS).
- Run the unit-economics loop in §6 and act on it.
- **Exit:** sustained operation across 10+ programs with positive net economics over a measured window,
  or a decision to pivot.

---

## 5. Human-in-the-loop operating model

Automation finds and evidences; a person decides and submits. Concretely:

- A **daily triage queue**: candidates ranked by estimated payout and confidence. Human spends ~30–60
  min/day confirming, de-duping, writing/finishing the report, and submitting.
- Submission hygiene: one high-quality report beats ten noisy ones. Platform reputation (signal, not
  spam) directly affects invites to private programs, which pay far better than public ones.
- Track and respect per-program dup rates; mute detectors that produce dups on a given program.

---

## 6. Unit economics — define "working" numerically

Instrument and review weekly:

- Assets monitored, candidates/day, auto-findings/day.
- Human-confirmed → submitted → **accepted** → **paid $**; and dup/informational/N-A rates.
- Human triage minutes per submission; infra/compute cost.
- **Net = paid $ − (human hours × your rate) − infra.**

Realistic expectations: **months, not days, to first paid bounty.** Early net is likely negative or low.
The leverage comes from monitoring many programs cheaply so the *first-finder* and *IDOR* hits
accumulate. If the only output is informational header findings, the system is not working — stop
submitting them.

---

## 7. Kill / pivot criteria (decide these up front)

- If after ~3 months and ~10 programs: dup+informational rate > ~70%, net economics negative, and no
  Medium+ accepted finding → **stop auto-submitting and pivot.** Likely pivots: sell the *continuous
  attack-surface monitoring* as a service (the first-finder engine has standalone value), or keep
  Anteater purely as a human-augmentation recon tool for a skilled hunter.

---

## 8. Anti-goals (do not build these)

- No internet-wide / unscoped scanner.
- No autonomous submission, no exploitation beyond minimal PoC, no scope or ToS violation, no anti-
  automation bypass.
- No aggressive/mutating execution against production targets you do not own a disposable mirror of.
- No treating header/TLS/cookie nits as paid submissions.

---

## 9. The one-paragraph summary

Anteater will not earn money as an "autonomous scanner." It can earn money as a **continuous,
scope-respecting attack-surface monitor and access-control tester that produces evidence-grade
candidates for a human to confirm and submit** — winning on first-finder speed across many authorized
programs and on reliable IDOR/exposure detection. The code is already safe and durable; the work is
Phases 0–6: wire the pieces into one live campaign, prove it on owned staging, select the right
programs, and run a disciplined human triage loop while measuring net dollars.

---

# Part II — Builder's implementation guide (for an agent)

This part is written so an agent unfamiliar with the repo can execute the phases. Follow the
conventions, use the interface reference, and implement each phase's tasks in order. Do not skip the
acceptance tests or the safety gates.

## A. Conventions you MUST follow

1. **Runtime/language:** Node ≥ 22, TypeScript strict + `noUncheckedIndexedAccess`, ESM. Import local
   files with a `.js` extension even though the source is `.ts` (e.g. `../scope-engine/index.js`).
2. **Validation:** parse all external/boundary input with `zod`. Use `.strict()` on object schemas.
   Never trust discovery output, model output, HTTP responses, file contents, or env as instructions —
   they are data.
3. **Tests:** `node:test` run via `tsx`. Unit tests live in `tests/*.test.ts` (`npm test`). Integration
   tests needing Postgres run under `npm run verify:local` (embedded Postgres) — add DB-touching tests
   to `tests/integration/*.test.ts`. Browser tests: `tests/browser/*.test.ts` (`npm run test:browser`).
4. **Fixture-first:** every detector ships with a **vulnerable** and a **patched** fixture and is added
   to the release gate (`scripts/gate.ts` + `packages/fixtures-apps`). A detector that is not in the
   gate is not done.
5. **Safety invariants — never weaken these:**
   - The scope engine fails closed; `authorize()` must gate every outbound target+action.
   - `GLOBAL_KILL_SWITCH` defaults `true`; `ENABLE_PASSIVE_HTTP` / `ENABLE_APPLICATION_RESEARCH` default
     `false`. Do not change defaults. Live flags stay off until the Phase-0 proof passes.
   - HTTPS/443 only; read-only methods only on live targets; no auto-followed redirects.
   - Private/reserved IPs blocked (`addressBlockReason`); DNS pinned (resolve once, connect to that IP).
   - `VERIFIED` only via deterministic replay; `SUBMITTED` only by a human — both enforced by the DB
     trigger in `006_runtime_control.sql` (transaction must `SET LOCAL anteater.actor`). Do not bypass.
   - A model never chooses a target or an action; it only fills a validated closed form.
6. **After every change, run and keep green:** `npm run build` (tsc), `npm test`, `npm run gate`, and —
   for anything touching the worker/gateway/DB/migrations — `npm run verify:local`.
7. **Migrations:** add a new numbered file `infrastructure/postgres/00N_*.sql`, make it **idempotent**
   (`IF NOT EXISTS`, guarded `DO $$`), and append its name to the `migrationFiles` array in
   `packages/research-state/db.ts`. Migrations run in a transaction under an advisory lock and are
   tracked in `schema_migrations`. Never edit an already-applied migration; add a new one.
8. **Commits:** work on a feature branch, one coherent commit per task group. When staging, use explicit
   paths — do **not** `git add -A` (23 `vendor/*` gitlinks are staged-but-deleted on this tree and a
   blanket add would drop the pins). End commit messages with the attribution line the harness provides.
9. **Do not duplicate existing code.** Before writing a module, grep for it. Known seams already exist:
   `web-executor` (passive HTTP), `posture-check` (`findingsFromResponse`/`addressBlockReason`),
   `application-research` (auth flows), `findings` (state machine/replay), `discovery` (admission),
   `operations` (kill/retention/dead-letter). Extend these; do not reinvent them.

## B. Interface quick-reference (real signatures — verified against the code)

```
// packages/scope-engine/index.ts
SAFE_ACTIONS = ['inspect_http_target','inspect_robots','inspect_sitemap','inspect_openapi','research_application']
authorize(rawPolicy, target, action, config /* needs GLOBAL_KILL_SWITCH */, now?) -> { allowed, reason }
targetForAction(assetUrl, action) -> string
PolicySchema fields: programId, revision, sourceUrl, reviewed:true, expiresAt, allowed[], excluded[],
  allowedActions[], allowedPaths[]=['/'], schemes:['https'], ports:[443], requestsPerSecond, application?

// packages/research-state/jobs.ts  (class Jobs(pool, concurrency, leaseSeconds))
enqueue(program, asset, action, key?)      claim(): Job|undefined      heartbeat(job)
complete(job, observation): Promise<observationId>   // inserts observation, OBSERVATION findings from
   // observation.signals, owner-boundary HUMAN_REVIEW rows, policy-authorized follow-ups, hypotheses
recordAnalysis(job, observationId, run)     recordAnalysisFailure(job, failure)
defer(job, seconds?)     fail(job, code?)
submitFinding(pool, findingId, reviewer)    // sets anteater.actor='human', requires reviewer

// packages/mcp/index.ts
new ToolGateway(pool, () => Config).invoke(job, tool, assetId, signal?) -> observation record

// packages/web-executor/index.ts
executePassiveHttp(target, { maxBytes, signal?, beforeRequest?, timeoutMs?, deps? }) -> observation
   // deps = { lookup, request } are injectable for tests

// packages/application-research/index.ts
researchApplication(origin, app /*ApplicationSchema*/, config, beforeRequest(signal), parentSignal?, deps?)
// profile.ts: ApplicationSchema has readPathPrefixes, excludedPaths, maxPages/Depth/Requests/Duration,
//   auth (AuthSchema), privateResources[] (name, createPath, readPath w/ {id}, cleanupPath w/ {marker}, ownerOnly)

// packages/discovery/index.ts + adapters.ts + more-adapters.ts + enqueue.ts
FixtureDiscovery; CertTransparencyDiscovery(fetchLike?); PassiveDnsDiscovery(resolver); SubfinderDiscovery(exec); GitleaksAdapter(exec)
toCandidates(raws, roots); partition(cands, policy, action); diffCandidates(prev, cur)
candidateJobs(admitted, policy, action, revision) -> JobSpec[]

// packages/findings/index.ts
transition(from, to, actor) ; ContractSchema ; replay(contract, responder) ; verifyCandidate(from, contract, responder)
Responder = (stepId, iteration) => { status, body, unavailable? }

// packages/coverage/index.ts : coverageReport(results) ; validateRegistry()
// packages/provenance/index.ts : verifyApproval(approval, sourceText, now?)
// packages/application-research/intake.ts : loadCampaign(domainsFile, profileFile) ; CampaignSchema
// packages/operations/index.ts : canProceed(state, programId, leaseEpoch) ; classifyFailure(...) ; retentionPlan(...)
```

## C. Phases

### Phase 0 — Prove the full loop on owned staging

**0.1 Build the staging lab.** DONE — `infrastructure/lab/` has a seeded vulnerable app + patched twin
(`app.mjs`) behind Caddy TLS (`docker-compose.yml`, `Caddyfile`) with the seeded-bug list in
`README.md` (IDOR, exposed `.git`, CORS-with-credentials, open redirect). This synthetic lab is the
**deterministic, known-answer** target for the detector gate and the loop proof.

**0.1b Live integration target — the dev box (192.168.60.26).** This owned Proxmox dev/test VM
(n8n/Postgres/Portainer) is the live integration target, not a CI target (its state is real/
non-deterministic). Wiring required before pointing Anteater at it:
- Add the `ALLOW_PRIVATE_LAB_TARGETS` + `LAB_TARGET_HOSTS` flags (already declared in `config.ts`) into
  the egress path: in `web-executor` pass `allowPrivate=true` to `addressBlockReason` **only** when the
  resolved host is in `LAB_TARGET_HOSTS` and `ALLOW_PRIVATE_LAB_TARGETS` is on; it must never relax the
  guard for any other host. Add `tests/lab-target.test.ts` proving a non-lab private host is still
  blocked even with the flag on.
- Target it by hostname (`lab.anteater.test` → 192.168.60.26 via hosts), TLS on 443.
- **Operational prep (document in the runbook and enforce in an aggressive preflight): Proxmox snapshot
  first; deactivate n8n workflows or confirm no live outbound credentials.** Aggressive/Nuclei runs are
  refused unless a `--snapshot-confirmed` flag is passed.

**0.2 Single live campaign orchestrator.** Create `apps/orchestrator/live-campaign.ts` that composes,
for one program: discovery → `partition` admission → `candidateJobs` → enqueue → worker runs the
gateway (passive HTTP + application research) → `complete()` persists → `findings` lifecycle →
`coverage`. Reuse `apps/orchestrator/campaign.ts` as the pure composition seam; this file adds the
persistence + queue wiring. Do **not** fork the worker — call into `Jobs`/`ToolGateway`.

**0.3 Egress hardening tests (independent of Playwright).** Add `tests/egress-safety.test.ts` proving,
against an injected transport, that: DNS rebinding (second resolution differs) cannot change the
connected IP; a redirect to another host is not followed; private/reserved IPs are refused
(`addressBlockReason`); body cap and timeout abort. For the browser, add `tests/browser/egress.test.ts`
asserting subresources/frames/workers/WebSocket requests to off-scope origins are blocked by the
same-origin routing.

**0.4 End-to-end proof.** Add `tests/integration/staging-loop.test.ts` (runs under `verify:local` with
the lab, or a synthetic transport if the lab is not present in CI) that: ingests a reviewed campaign for
the staging host, discovers+admits it, runs the campaign, finds the seeded IDOR, `verifyCandidate`
reproduces it and rejects the patched variant, evidence is stored, and `submitFinding` moves it to
`SUBMITTED` only with an actor+reviewer.

**Exit:** `npm test`, `npm run gate`, `npm run verify:local`, `npm run test:browser` all green, and the
staging loop test passes end-to-end. **Gate:** both live flags remain off in committed config.

### Phase 1 — Real program intake + scope compiler

**1.1 Provider adapter.** Create `packages/program-intake/<platform>.ts` (pick ONE platform first) with
`fetchProgram(handle, fetchLike?): Promise<RawProgram>` returning the published scope, exclusions, rate
rules, and the raw policy text. `fetchLike` injectable; real calls go only to the platform's documented
API/host, size-capped, timed out, zod-parsed.

**1.2 Automation classifier.** In `packages/program-intake/classify.ts` implement
`classifyAutomation(policyText): 'permitted'|'manual-only'|'prohibited'` using explicit phrase rules
(e.g. "no automated", "do not use scanners", "rate limit", "automated tools allowed"). Default to
`manual-only` when ambiguous. Add fixtures for each class.

**1.3 Compile to a reviewed campaign.** Extend `packages/application-research/intake.ts` consumption:
produce a `CampaignSchema` profile from the provider output, require the `ApprovalFields`
(approver/sourceSha256/approvedAt) and `verifyApproval` against the canonical profile, and set
`allowedActions` according to the automation class (manual-only → discovery/passive only; never
`research_application`). A human approves; store provenance.

**1.4 Migration `007_programs_intake.sql`:** add `programs.automation_policy text`,
`programs.platform_handle text`, and a `program_approvals` table (approver, source_sha256, approved_at,
revision). Idempotent; append to `migrationFiles`.

**Exit:** three real programs compiled + human-approved with correct automation class; a test proves a
`prohibited` program is never enqueued and a `manual-only` program never gets `research_application`.

### Phase 2 — Continuous discovery + change detection (first-finder engine)

**2.1 Wire live adapters** (`CertTransparencyDiscovery`, `SubfinderDiscovery`, `PassiveDnsDiscovery`)
behind per-program rate budgets. Keep them injectable; real external calls go only to the documented
sources. Admission stays `partition()` — discovered names are candidates until the signed allow-list
authorizes the exact host.

**2.2 Asset persistence + change detection.** Migration `008_assets_discovery.sql`: add `assets.first_seen`,
`assets.last_seen`, `assets.source`, `assets.confidence`, and a `discovery_runs` table. Implement
`packages/discovery/store.ts` with `recordObservedHosts(pool, programId, candidates)` (upsert
first/last seen) and `newlyExposed(pool, programId): Promise<string[]>` using `diffCandidates` semantics.

**2.3 Scheduler.** Create `scripts/monitor.ts` (`npm run monitor`) that, per automation-permitted
program, runs discovery on an interval, admits, records, and enqueues **only** newly-exposed in-scope
hosts for passive checks. Respect budgets and the kill switch each cycle (`runtime_control.global_kill`
+ `operations.canProceed`).

**Exit:** a newly-exposed seeded staging host is detected within one cycle and raised as a candidate;
an out-of-scope discovery is recorded but never enqueued/contacted (test-proven).

### Phase 3 — Paid-severity detectors (fixtures + gate)

For each detector below, add: a pure function in `packages/web-checks/` (or extend
`posture-check.findingsFromResponse` where it already captures headers), a vulnerable+patched fixture in
`packages/fixtures-apps`, a case in `scripts/gate.ts`, and a methodology mapping in
`packages/coverage/index.ts`. Severity must reflect **paid** reality (takeover/IDOR = high; header nits
= info and never submitted).

- `subdomain_takeover` (dangling CNAME → known-fingerprint body/404 signature).
- `exposed_vcs` (`/.git/config`, `/.env`, `/.DS_Store` reachable — read-only GET, match signature).
- `exposed_admin` (`/actuator`, `/admin`, debug endpoints returning privileged content).
- `cors_credentialed` (already partly present — ensure ACAO-reflect + credentials).
- `open_redirect_to_takeover` (redirect to attacker origin on an auth/token path).
- `secrets_in_js` (served JS contains live-looking keys — reuse `inert`/`modules` secret patterns;
  report rule+location only, never the secret value).

**Each detector's KPI is false-positive rate, not count.** The gate must pass (flags vulnerable, clean
on patched) before the detector is enabled.

**Exit:** every new detector in the gate with a methodology mapping and a policy-denial test.

### Phase 4 — Authenticated access-control (IDOR/BOLA)

**4.1 Role-aware credentials.** Extend `AuthSchema`/`ApplicationSchema` to label accounts with roles
(two ordinary users + one least-privileged admin). Store secrets via the encrypted
`CREDENTIAL_STORE`/`ACCOUNT_KEY` path already present; never put secrets in logs/prompts/reports.

**4.2 Ownership probes.** Use `packages/authz` to build the actor/resource/action matrix from
`privateResources` + observed routes, generate cross-role read probes, and produce an ownership
`Contract`. Drive it through `application-research` sessions as the `Responder` for `verifyCandidate`.
Every create must guarantee marker-based cleanup (the schema already enforces a `{marker}` cleanup path).

**4.3 Disposable data + cleanup proof.** Add a test proving create→read-as-other→delete always cleans
up, including when create returns a malformed id (delete by marker).

**Exit:** seeded cross-user and cross-tenant reads found on staging; patched variants rejected; sessions
isolated; zero residual test resources.

### Phase 4.5 — Aggressive testing against the dev box (snapshot-gated)

Run active/fuzzing checks against the owned dev box (192.168.60.26) — the "do its worst" tier — safely,
by making it recoverable and side-effect-free first.

- **Preflight (enforced in code, not just docs).** Create `scripts/aggressive.ts` (`npm run aggressive`)
  that refuses to run unless: the target host is in `LAB_TARGET_HOSTS`, `--snapshot-confirmed` is passed
  (operator attests a Proxmox snapshot exists), and an n8n-outbound attestation is given. Missing the
  snapshot attestation → exit non-zero, do nothing.
- **Execution.** Actually run the pinned Nuclei adapter (`packages/tool-adapters`, built but never
  executed) via `execFile` with its allowlisted argv — non-destructive tags only by default
  (`-exclude-tags dos,intrusive,fuzz,cve,vuln`), per-host rate budget, pinned `NUCLEI_BIN`. Parse JSONL
  into findings through the normal lifecycle.
- **Truly destructive tier (opt-in).** Dropping the exclude-tags (real fuzzing/DoS-class templates) is
  allowed ONLY against a host in `LAB_TARGET_HOSTS` and ONLY behind a second `--allow-destructive` flag
  plus the snapshot attestation. Record a loud audit event; the runbook recovery step is `qm rollback`.
- **Exit:** a Nuclei run against the dev box flows findings through the lifecycle; the preflight refuses
  to run without the snapshot attestation (test-proven with a stubbed exec).
- **Gate:** destructive tags are impossible against any host not in `LAB_TARGET_HOSTS`.

### Phase 5 — Verification, evidence, report, human triage

**5.1 Lifecycle driver.** In the campaign, promote verified candidates via the `findings` state machine
(the DB trigger enforces actor). Persist redacted+encrypted evidence (`packages/evidence`), the audit
hash-chain, and a coverage report per campaign.

**5.2 Report generation.** Create `packages/report/index.ts` `renderReport(finding, evidence, remediation)`
→ a reviewer-editable Markdown report (impact, reproduction steps, remediation from
`packages/remediation`). Use the `ks-report-design` skill style if producing a client/PDF artifact.

**5.3 Dedup + triage queue.** Migration `009_triage.sql`: a `triage_queue` view/table ranking
HUMAN_REVIEW/VERIFIED findings by estimated payout × confidence, with a dedupe key over
`(program, type, location)` that also checks prior `SUBMITTED` findings. `scripts/triage.ts`
(`npm run triage`) lists the queue; `npm run finding:submit --id= --reviewer=` submits one.

**5.4 Retest job.** On a program re-scan, re-run the stored contract via `findings/retest`; an outage or
failed control is "inconclusive", not "fixed".

**Exit:** a finding flows candidate → verified → human-reviewed → submitted with a clean report and a
passing dedupe check, end to end on staging.

### Phase 6 — Scale, operate, measure

**6.1 Multi-program scheduling** across automation-permitted programs with global + per-program budgets;
honor kill/revocation each iteration; dead-letter non-retryable failures.

**6.2 Metrics + alerts.** Feed `packages/metrics` a real snapshot (queue age, coverage gaps, rate-limit
hits, tool/mailbox failures, dead-lettered) and expose a `scripts/metrics.ts` dump or a `/healthz`/
`/metrics` endpoint. Add backup/restore scripts and a crash-recovery drill test.

**6.3 Economics ledger.** Migration `010_economics.sql`: a `submissions` table (program, finding, status
timeline: submitted/triaged/accepted/duplicate/informational/paid, amount, currency). `scripts/ledger.ts`
(`npm run ledger`) computes the §6 unit economics (net = paid − human-hours×rate − infra).

**Exit:** sustained operation across 10+ programs, the ledger produces the economics report, and the
kill/pivot decision in §7 can be made on real numbers.

## D. Definition of done for the whole build

- All phases' exit criteria met; `npm run build`, `npm test`, `npm run gate`, `npm run verify:local`,
  `npm run test:browser` green; `docs/READINESS.md` "Required before production operation" boxes checked
  with evidence; and at least one finding submitted through the human path against a real
  automation-permitted program with a recorded outcome in the economics ledger.
- No safety invariant in §A.5 weakened. No autonomous submission. No scope/ToS violation.
