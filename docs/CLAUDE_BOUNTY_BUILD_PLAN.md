# Anteater: the 10× bug-bounty research workspace

**Implementation handoff for Claude · October 3, 2026**

**Repository:** `amosroger91/anteater-ai`
**Inspected local baseline:** `4c74e3b` on `codex/review-hardening`
**Primary objective:** help the operator earn bug-bounty income by finding eligible, distinct, reproducible vulnerabilities and producing excellent private reports.
**Product objective:** make a skilled researcher substantially more effective per hour, without requiring CSV editing, terminal orchestration, or trust in unsupported AI conclusions.

This is an implementation specification, not a claim that the proposed features exist or that a payout is guaranteed. The existing passive-first UI remains the default. Authenticated research is a later, explicitly enabled workflow after its technical gates pass. This document takes priority over older product roadmaps for the proposed delivery order; existing code and tests remain the source of truth about implemented behavior.

## Contents

1. [Instructions for Claude](#1-instructions-for-claude)
2. [Commercial thesis and the meaning of 10×](#2-commercial-thesis-and-the-meaning-of-10)
3. [Current implementation and reuse map](#3-current-implementation-and-reuse-map)
4. [The product to build](#4-the-product-to-build)
5. [Architecture and persistence contracts](#5-architecture-and-persistence-contracts)
6. [Implementation backlog](#6-implementation-backlog)
7. [Research strategy and detector portfolio](#7-research-strategy-and-detector-portfolio)
8. [Interface specification](#8-interface-specification)
9. [Evidence, verification and reports](#9-evidence-verification-and-reports)
10. [AI assistance that earns its cost](#10-ai-assistance-that-earns-its-cost)
11. [Evaluation and release gates](#11-evaluation-and-release-gates)
12. [Revenue pilot and feedback loop](#12-revenue-pilot-and-feedback-loop)
13. [Delivery sequence and completion criteria](#13-delivery-sequence-and-completion-criteria)
14. [Operating and recovery procedures](#14-operating-and-recovery-procedures)
15. [Copyable Claude kickoff prompt](#15-copyable-claude-kickoff-prompt)
16. [References and decision provenance](#16-references-and-decision-provenance)

## 1. Instructions for Claude

### 1.1 Your mandate

Build a coherent research workflow, not a collection of disconnected scanners. Carry each selected milestone through implementation, migration, testing, documentation and a usable UI. The operator should be able to work entirely through the interface for normal research.

Start by reading this file, applicable `AGENTS.md` files, `docs/DASHBOARD.md`, `docs/VALIDATION.md`, and the implementation paths listed below. Inspect the current branch and uncommitted changes. Do not reset user work or assume the baseline hash still matches HEAD.

Create `docs/IMPLEMENTATION_STATUS.md` with one row per ticket in section 6. Record status, dependencies, commits, test evidence, remaining limitations and the next concrete action. Use `not_started`, `in_progress`, `blocked_external_input`, `implemented_unverified`, and `verified`. A checkmark requires evidence. Keep detailed architecture decisions in short ADR files under `docs/adr/`.

### 1.2 Work in vertical slices

For each ticket:

1. Inspect the existing implementation and state what will be reused.
2. Define the externally observable behavior and failure cases before editing.
3. Make additive schema changes and preserve existing data.
4. Implement the service, HTTP contract and minimum usable screen together where applicable.
5. Test the important success, negative and interruption paths.
6. Update documentation and the status ledger with commands and outcomes.
7. Commit a coherent change. Never mark a stub or a fixture-only integration production-ready.

Do not spend the first milestone rewriting the UI in a new framework. Extract modules as complexity grows. Prefer TypeScript, the existing Node server, PostgreSQL, Playwright, Zod and the current test runner. Add a dependency only when it removes a material problem and its maintenance/licensing tradeoff is recorded.

### 1.3 Scope of this handoff

The plan authorizes development and local/owned-fixture verification. It is not authorization to contact arbitrary bounty targets, create external accounts, spend money, submit reports, or publish private program information. Implement adapters and demo flows without those inputs. When a real program is needed, obtain the operator's selected program, current policy, approved assets, permitted actions and controlled accounts. Missing real-world inputs must not stop independent implementation and fixture work.

Preserve the operator's passive-first preference. New authenticated capabilities must have distinct controls, budgets, account setup and status. Do not enable them by upgrading an existing passive project.

### 1.4 Never silently weaken these invariants

- Discovery, page text, API schemas and model output cannot grant authorization.
- Every request must fit the current scope, action, path, method, expiry and remaining budget.
- A current session cookie is not proof that two sessions belong to different people.
- Test with operator-controlled accounts and synthetic resources. Do not use other users' records as test material.
- Models propose hypotheses and drafts; they cannot verify a vulnerability or submit a report.
- Keep evidence of what happened distinct from a hypothesis about what might happen.
- An incomplete, failed or skipped check is not a pass. An unexecuted retest cannot resolve a finding.
- A timeout after a write has an uncertain outcome. Never blindly repeat it.
- Pending cleanup survives process restarts. Scope revocation can block cleanup; expose that obligation rather than bypassing policy.
- Raw secrets do not enter logs, exports, model prompts or frontend state.
- No volume-driven mass submissions, unsolicited disclosure, evasion, account abuse, denial-of-service testing or arbitrary model-generated shell commands.

These are functional requirements for a trustworthy research product. They should be enforced in services and tests, not only in warning text.

## 2. Commercial thesis and the meaning of 10×

### 2.1 The strategic bet

Anteater should specialize first in **authorized web/API permission and workflow research**. It already has useful foundations for sessions, canonical principals, access matrices, controlled resources, deterministic replay and cleanup. Integrating these into a strong workflow is a better initial bet than adding dozens of shallow detector wrappers.

The first differentiating loop:

> Understand an application → build a role/resource map → identify an untested permission boundary → run a bounded experiment using controlled data → establish repeatable behavior and a negative control → draft an evidence-linked report → learn from the actual triage outcome.

Treat this specialization as a testable product hypothesis. It is not a claim that these bug classes always pay more. OWASP identifies object- and function-level authorization as important API risks, which supports their technical relevance; payout potential still depends on a particular program and demonstrated impact. [OWASP API1](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/), [OWASP API5](https://api-security.owasp.org/editions/2023/en/0xa5-broken-function-level-authorization/).

### 2.2 Optimize the real funnel

Track the following separately:

`reviewed program → mapped workflow → eligible hypothesis → executed experiment → reproducible candidate → human-approved report → submitted → accepted/nonduplicate → awarded → paid`

An observation is not a candidate. A locally verified candidate is not an accepted report. An award notification is not cash received. Do not collapse these into a single green success counter.

The primary product metric is **distinct, independently reviewable candidates per researcher-hour**. The commercial outcome is **realized net bounty income per total operator-hour**, measured over a long enough period to include triage and payment delays.

### 2.3 Define 10× as an experiment

Build a frozen benchmark of permission/workflow tasks before optimizing. Compare a documented manual workflow, the existing baseline, and the improved product on the same held-out tasks. Include account setup, triage, false positives, cleanup, report editing and recovery time.

Proposed targets, not existing results:

| Measure | Initial target | Guardrail |
| --- | --- | --- |
| Active operator time from known candidate to evidence-complete draft | ≤20% of manual baseline | Independent reviewer can reproduce it |
| Repeated program/account setup time | ≤10% after first setup | Scope and sessions still revalidated |
| Qualified hypothesis coverage per operator-hour | ≥5× on held-out workflows | Fixed request and spend budget |
| Whole-workflow verified candidate productivity | Stretch goal 10× | No loss in precision or evidence quality |
| Candidate precision in blind owned-lab review | ≥90%, report sample size | No tuned-only fixture claim |
| Scope/control violations in release tests | Zero observed | One violation blocks release |
| Paid income | Measure actual receipts | No invented revenue target or payout guarantee |

Report ratios with denominators, distributions and uncertainty. Do not multiply favorable microbenchmarks and call the product 10× better. Run counterbalanced task ordering where practical; record researcher familiarity and model versions. For small live samples, show raw outcomes instead of impressive percentages.

### 2.4 Revenue accounting

Store monetary amounts as integer minor units with an explicit currency. Keep award date, payment date, original amount, platform fees and documented expenses separate. Show original currencies; conversions need a recorded exchange rate and date.

Useful calculations:

```text
realized_net = payments_received - recorded_cash_expenses
realized_net_per_hour = realized_net / all_logged_operator_hours
acceptance_rate = accepted_nonduplicate / decided_submissions
report_preparation_minutes = review + evidence_editing + reproduction + drafting
cost_per_reviewable_candidate = attributable_compute_cost / reviewable_candidates
```

Track outstanding submissions by age. Do not count unresolved reports as rejections or assumed income. Expected-value estimates are optional later and must display their assumptions and sparse-data uncertainty. Initially use a transparent priority score rather than pretending to know a payout probability.

### 2.5 Features to defer

Defer broad internet scanning, automated account farming, public SaaS hosting, a scanner marketplace, mobile/native binary research, generalized exploit generation, automatic submission, a graph database, Kubernetes and multi-agent swarms. Also defer generalized race-condition, payment-abuse and resource-exhaustion tests from live mode. These have poor value for this first focused release relative to their operational complexity.

Keep passive posture checks as onboarding, baseline context and a source of leads. Missing headers and version banners do not become bounty-ready reports merely because the UI assigns them a severity.

## 3. Current implementation and reuse map

The following was inspected at the stated baseline. Recheck before editing; do not recreate completed work.

| Existing path | What it provides | Required evolution |
| --- | --- | --- |
| `apps/dashboard/public/{index.html,app.js,styles.css}` | Lightweight form, saved scope/drafts, preview, progress, history, archive | Research workspace, inventory, hypothesis board, evidence and report flows |
| `apps/dashboard/server.ts` | Local-only HTTP API, session/Host/origin checks, snapshot SSE | Versioned API, durable event cursors, pagination, typed errors |
| `packages/campaigns/{contracts,service}.ts` | Validated local JSON, migration backups, idempotency, sequential passive executor | Repository abstraction and PostgreSQL-backed live campaigns |
| `scripts/assessment.ts` | CLI client of the dashboard API | Preserve parity with future service operations |
| `apps/orchestrator/{worker,campaign}.ts` | Existing orchestration entry points | Consume common campaign/job contracts |
| `packages/research-state/{db,jobs,workspace}.ts` | PostgreSQL state, leases, transactional observations | Campaign linkage, scoped claims, events, epoch fencing |
| `packages/scope-engine/index.ts` | Policy and action admission | Program terms, immutable approvals, shared revocation |
| `packages/bounty-providers/index.ts` | Program intake foundations | Reviewed policy/version inbox, eligibility profiles |
| `packages/discovery/*` | Candidate discovery/admission foundations | Campaign UI, provenance, bounded change detection |
| `packages/api-inventory/index.ts` | API inventory parsing | Observed route schemas and actor/resource mapping |
| `packages/application-research/*` | Browser/account/mailbox flows, ownership verification, cleanup | Explicit UI setup, principal freshness, isolated worker deployment |
| `packages/authz/index.ts` | Role matrix and controlled ownership contracts | Rich actor/tenant/resource relationships and workflow expectations |
| `packages/research-state/cleanup.ts` | Durable PostgreSQL cleanup journal | Dedicated reconciliation jobs and operator resolution |
| `packages/findings/{index,retest}.ts` | Finding transitions, replay, dedup and retest primitives | Persisted triage/evidence revisions, nuanced outcome state |
| `packages/evidence/index.ts` | Evidence foundation | Redacted artifacts, integrity, retention, provenance |
| `packages/agent-runtime/index.ts`, `packages/llm/index.ts` | Model execution/analysis foundations | Bounded, evidence-linked research suggestions and evals |
| `packages/operations/{store,retention}.ts` | Operations and retention controls | One retention policy for campaigns, blobs and exports |
| `packages/{coverage,web-checks,web-executor}/*` | Passive checks, explicit coverage and bounded transport | Detector/check contracts and honest evidence summaries |
| `infrastructure/postgres/001_initial.sql` through `006_cleanup.sql` | Existing schema | Add migrations; never rewrite already applied migrations |
| `scripts/smoke-dashboard.mjs` | Compiled runtime smoke | Maintain install/build/demo compatibility |

Recorded validation: 145 unit tests, 10 browser tests, 15 reported PostgreSQL integration tests, a 5/5 detector fixture gate, and fresh-clone install/build/demo validation on Windows/Node 24. These are historical baseline results, not a new test run for this document. See [VALIDATION.md](VALIDATION.md).

Important existing limitations:

- Dashboard JSON execution and PostgreSQL workers are separate live systems.
- SSE sends current snapshots; it does not yet replay a durable event log.
- Live request enablement is process-local, not a distributed stop control.
- The local checkbox is not authenticated organizational approval.
- Browser/ownership fixtures do not establish independent egress isolation or real-program effectiveness.
- Coverage and source dependency counts are not a measured finding yield.
- Existing finding chain severity uses the maximum member severity. Do not silently replace it with model-invented impact escalation.

## 4. The product to build

### 4.1 One opinionated operator journey

1. **Choose a program.** Import or enter its current brief, reward eligibility and restrictions. Review changes before running anything.
2. **Define a research mission.** Pick an approved application and a specific question, such as whether one controlled user can access another controlled user's private draft.
3. **Map the workflow.** Browse deliberately using isolated controlled accounts; collect approved routes and resource relationships.
4. **Review suggestions.** Anteater proposes explainable hypotheses linked to observed routes and gaps in permission coverage.
5. **Inspect the experiment.** See actors, exact requests/actions, budgets, expected outcomes, evidence requirements and cleanup obligations.
6. **Run and observe.** Follow discrete stages and stop work across workers. Unknown or blocked states remain visible.
7. **Review evidence.** Compare owner, other-user and control responses; confirm the observed behavior and narrow its impact.
8. **Prepare a report.** Create a private, editable report from the evidence ledger. Redaction preview and reproduction checklist precede export.
9. **Record submission and outcome.** The operator submits, records the platform ID and tracks follow-up, award and payment.
10. **Learn.** Feed actual rejection, duplicate and acceptance reasons into future prioritization without deleting contrary evidence.

### 4.2 Three explicit modes

| Mode | Purpose | Network behavior |
| --- | --- | --- |
| Demo / lab | Onboarding, regression and training | Synthetic or explicitly owned lab only |
| Passive baseline | Current default posture workflow | Existing bounded authorized requests |
| Guided authenticated research | High-value permission/workflow experiments | Explicit reviewed plan, controlled accounts, constrained workers |

The product should work without AI. Model availability must never block viewing evidence, stopping a run, reviewing a finding or exporting a report. No internet dependency is needed for synthetic demo mode.

### 4.3 What makes it compelling

- A permission coverage map tells the researcher what has and has not been tested.
- Every candidate has a compact evidence comparison and a reproducibility badge backed by a run.
- A hypothesis queue explains why each experiment deserves time and what would falsify it.
- A report editor highlights unsupported claims and inserts evidence references.
- A program change inbox prevents stale scope and spotlights newly eligible surfaces.
- A private research notebook remembers failed ideas, expected behavior and previous triage decisions.
- An outcome dashboard measures research value and costs, not just scan counts.

## 5. Architecture and persistence contracts

### 5.1 Target architecture

```text
Browser workspace + API CLI
           |
Versioned application API / operator identity
           |
Campaign, policy, inventory, hypothesis, evidence, finding and report services
           |
PostgreSQL: authoritative state + transactional outbox + leased jobs
           |
Admission: scope revision + revocation epoch + budgets + principal preconditions
           |
Isolated passive/browser workers -- independently restricted egress --> approved assets
           |
Immutable observations -> redacted evidence -> deterministic verification -> human review
           |
Report export and manual submission -> outcome ledger -> prioritization feedback
```

One live scheduling authority. Use the existing leased jobs implementation; do not build a second queue. Keep a lightweight fixture repository for demo/testing. After migration, PostgreSQL live mode must fail closed when unavailable rather than silently reverting to file-backed execution.

### 5.2 Proposed entities

Names below are design proposals, not existing table/API claims. Inspect current migrations and reuse compatible tables rather than duplicating them.

| Entity | Key fields and constraints |
| --- | --- |
| `projects` | UUID, name, optional tags/owner, archive timestamp, optimistic version |
| `program_profiles` | Platform, external ID, policy URL, private/public flag, eligibility notes, reward currency/ranges, review timestamp |
| `policy_revisions` | Immutable source digest, normalized grants/exclusions, reviewer identity, expiry, terms version; project FK |
| `campaigns` | Project/policy FK, mode, state, budget snapshot, stop epoch, creator, version, start/end timestamps |
| `campaign_targets` | Campaign FK, exact origin, admission reason, target state; no inferred wildcard expansion |
| `campaign_events` | Campaign FK, monotonic sequence, event type/version, timestamp, redacted payload; unique campaign+sequence |
| `request_reservations` | Program/origin/campaign, cost, expiry, admission epoch, consumed/released state |
| `check_runs` | Job/campaign FK, detector ID/version, applicability, status/reason, evidence references, timestamps |
| `identities` | Project, secret reference, canonical principal fingerprint, tenant, role, last verified time; encrypted secrets elsewhere |
| `resources` | Project, controlled owner, synthetic marker reference, creation/reconciliation state, cleanup contract |
| `routes` | Exact origin, method, observed and normalized path, schema hash, provenance, context/role; never authority by itself |
| `hypotheses` | Boundary, provenance, rationale, predicted outcome, falsifier, approved plan hash, priority factors, state |
| `evidence_artifacts` | Project/campaign/job FKs, artifact kind, content hash, redaction version, bytes, encryption metadata, retention/hold |
| `finding_revisions` | Finding FK, immutable claims/evidence set, detector/verification version, reviewer decision and reason |
| `report_revisions` | Finding FK, structured report, evidence manifest, edits, export digest, reviewer identity |
| `submission_outcomes` | Platform report ID, dated status events, stated duplicate/rejection reason, award/payment facts |
| `time_cost_entries` | Campaign/project/report attribution, operator time, compute cost, currency, source and correction history |

Use foreign keys, uniqueness and check constraints for invariants the database can enforce. Scope idempotency to actor/project/operation/key, store a canonical input digest, and return the original result for an identical replay. Persist idempotency and the scheduled jobs in the same transaction. A reused key with different input returns a conflict.

### 5.3 State models

Campaign states: `draft → ready → queued → preparing → running → stopping → cancelled`; terminal execution outcomes also include `completed`, `completed_with_gaps`, `failed`, `interrupted`. Define allowed transitions in one package. Parent state is derived from durable child outcomes and explicit cancellation, not a frontend guess.

Check statuses: `planned`, `running`, `passed`, `candidate`, `failed`, `skipped`, `not_applicable`, `cancelled`, `blocked`. Require reason codes for skipped/blocked/failed states. Store attempted and completed counts separately. Candidate does not imply confirmed impact.

Keep the existing finding verification lifecycle. Add separate review and platform outcome dimensions instead of overloading `VERIFIED`: internal verification, human disposition, submitted status, platform decision and payment are different facts. Map migrations explicitly to existing database constraints and actors.

### 5.4 Proposed HTTP contracts

Introduce `/api/v1/` with a compatibility period for current endpoints. All mutation bodies use strict schemas; errors include `code`, `message`, `issues`, `retryable`, and `requestId`. Never return a stack trace or secret. Suggested routes:

```text
GET/POST   /api/v1/projects
GET/PATCH  /api/v1/projects/:id                  (expectedVersion)
POST       /api/v1/projects/:id/policies/preview
POST       /api/v1/projects/:id/policies/approve (immutable revision)
GET        /api/v1/projects/:id/policy-changes
POST       /api/v1/campaigns/preview
POST       /api/v1/campaigns                    (Idempotency-Key)
GET        /api/v1/campaigns/:id
POST       /api/v1/campaigns/:id/cancel
GET        /api/v1/campaigns/:id/events?after=SEQUENCE
GET        /api/v1/projects/:id/inventory?cursor=...
GET/POST   /api/v1/projects/:id/hypotheses
POST       /api/v1/hypotheses/:id/plan
POST       /api/v1/hypotheses/:id/execute        (approved plan digest)
GET        /api/v1/findings/:id/evidence
POST       /api/v1/findings/:id/review           (expectedVersion)
POST       /api/v1/findings/:id/retest
POST       /api/v1/findings/:id/report-drafts
POST       /api/v1/reports/:id/export
POST       /api/v1/reports/:id/submission-record (operator-entered facts)
GET        /api/v1/operations/health
GET        /api/v1/operations/cleanup
```

Use bounded cursor pagination with stable sort keys. Redacted metadata in lists; fetch artifacts separately. Keep export URLs authenticated and scoped to the operator/project. Server-side ownership checks apply even to IDs obtained from a legitimate list.

### 5.5 Concurrency, cancellation and events

- Claim jobs through existing lease fencing; extend the job contract with campaign and policy/stop epochs.
- Revalidate admission after dequeue and immediately before each network operation, including browser actions that produce requests.
- Persist cancellation and increment the epoch transactionally. Prevent new admissions after this boundary; attempt to abort already admitted/in-flight requests and record uncertainty honestly.
- Treat inability to contact the authoritative admission store as a denial for new target traffic.
- Do not claim exactly-once external side effects. Use at-least-once job delivery with fenced completion, operation IDs and reconciliation for uncertain writes.
- Store result, resulting state and outbox events in one transaction. Notifications may duplicate; consumer sequence handling must be idempotent.
- SSE event IDs identify the campaign and sequence. Reconnect replays missing durable events. If retention removed the cursor, return an explicit snapshot/reset event.
- A restarted worker cannot use an old lease to publish completion or schedule children.
- Enforce both per-origin and per-program budgets across workers. Model/tool calls have separate cost ceilings.

### 5.6 Data migration and rollback

Create an explicit import command with dry-run, validation report and import manifest. Preserve local UUIDs, timestamps, demo flags, evidence references and scope snapshots. Validate before writing. Import each assessment transactionally; reruns are harmless. Quarantine malformed records with actionable diagnostics. Do not start jobs from imported terminal history.

Back up the original data directory. Record file digests and source schema versions in an import ledger. Cut live writes over once; legacy files become read-only archival input. Verify record counts, relationships and sampled report hashes. On application rollback, stop workers and use the documented compatible schema version; never automatically execute a destructive down migration or resume the old live scheduler against the same campaigns.

## 6. Implementation backlog

Sizing is relative: **S** = narrow change, **M** = cross-layer feature, **L** = substantial integration. These are not promises about calendar time. New paths below are proposed. Each ticket ends in a working slice and recorded evidence, not just interfaces.

### B00 — Establish a trustworthy development baseline

**Priority:** P0 · **Size:** S · **Dependencies:** none

**Touch:** validation docs, CI, fixture manifest, new status ledger.

- Record branch/HEAD, working-tree changes, runtime, database version and supported operating systems.
- Run the existing build/unit/browser/database/compiled-smoke commands once and preserve failures honestly.
- Inventory actual runtime dependencies versus source-only tool dependencies; imported repositories do not count as executable adapters.
- Add ADRs for common campaign storage, operator identity and execution isolation.
- Create the task ledger, a fixture index and an upgrade/restore checklist.

**Acceptance:** another developer can install, build, run the demo and identify the next ticket. Baseline failures are either fixed or explicitly scoped; no test is deleted to manufacture a green run.

### B01 — Put live campaigns into PostgreSQL

**Priority:** P0 · **Size:** L · **Dependencies:** B00

**Touch:** `packages/campaigns/*`, `packages/research-state/*`, dashboard server, orchestrator, new additive migration(s).

- Extract storage and scheduling dependencies from `CampaignService` while preserving its public behavior.
- Add project, approval, campaign and target persistence linked to existing jobs/observations.
- Route API and CLI live starts through one transaction and one job scheduler.
- Preserve the no-database synthetic demo; require PostgreSQL explicitly for unified live mode.
- Implement scoped idempotency and optimistic revision checks in the database.
- Integrate the old worker path so it cannot bypass campaign controls or create invisible live work.

**Tests:** identical concurrent starts, changed-input key conflict, API timeout after commit, database outage, stale project version, competing worker claims, old-lease completion.

**Acceptance:** UI and CLI observe the same durable campaign. Restarting either loses no committed state. One submitted operation creates one logical campaign/job set.

### B02 — Import existing history and provide a migration screen

**Priority:** P0 · **Size:** M · **Dependencies:** B01

**Touch:** new `scripts/import-dashboard-history.ts`, repository adapters, UI startup/migration view.

- Preview how many projects, drafts and reports will import; show invalid files without uploading data.
- Record import manifest, source digests and preserved IDs; retain existing `.legacy-backup.json` files.
- Import in resumable transactions and verify counts/relations afterward.
- Mark imported incomplete work interrupted; restarting requires a new reviewed execution decision.
- Provide recovery instructions and make legacy execution read-only after cutover.

**Tests:** empty directory, old schema, already migrated schema, corrupt record, conflicting UUID, crash mid-import, repeat import, backup restore.

**Acceptance:** two imports produce the same database state and no network work; the UI shows original report dates and scope.

### B03 — Shared admission, stop control and fair budgets

**Priority:** P0 · **Size:** L · **Dependencies:** B01

**Touch:** jobs, scope engine, budget, executor, worker control, dashboard controls.

- Add program/campaign stop epochs and policy-revision fences.
- Reserve request/concurrency budgets transactionally across workers; release unused reservations with explicit expiry.
- Separate total request caps, host rates, program-wide rates, response bytes, duration, browser navigation and model spend.
- Implement cancellation before scheduling, while queued, during DNS/HTTP, during model work and during reconciliation.
- Define which jobs can retry and which require renewed review. Authorization failure is never a transient retry.
- Add operations telemetry for admission denials, old leases and spent budgets.

**Tests:** two workers sharing one origin, clock boundaries, policy expiry after dequeue, revocation during DNS, lost database connection, hung request, re-enabled program with stale jobs.

**Acceptance:** no new request is admitted after the authoritative stop boundary. Already admitted requests are aborted where possible and represented accurately. Budget exhaustion cannot be bypassed by restarting a worker.

### B04 — Durable live progress and complete local usability

**Priority:** P1 · **Size:** M · **Dependencies:** B01, B03

**Touch:** event/outbox storage, SSE endpoint, dashboard modules.

- Replace full-history polling as the primary feed with bounded durable event replay and targeted snapshots.
- Show campaign stage, planned/attempted/completed checks, blocked reason, elapsed time and last worker activity.
- Add pagination, persistent filters and URL-addressable campaign/finding views.
- Preserve focus, selected target and unsaved form content during updates.
- Implement reviewed deletion with an artifact/count preview and explicit hold checks; archive remains reversible.
- Add keyboard, screen-reader, reduced-motion and narrow-screen checks.

**Tests:** lost stream, duplicate events, missing cursor, server restart, stale tab, export in progress, deletion of held evidence, keyboard-only navigation.

**Acceptance:** reconnect reproduces current state without duplicate activity or missing committed outcomes; long history does not freeze the browser.

### B05 — Program brief and eligibility workspace

**Priority:** P1 · **Size:** M · **Dependencies:** B01

**Touch:** bounty providers, scope engine, proposed `packages/programs/`, program UI.

- Support manually supplied briefs/URLs and authorized provider integrations; keep private program data private.
- Store source content digest, retrieval/review times, explicit exclusions, automation limits, account requirements and reward eligibility.
- Distinguish paid bounty programs from disclosure-only programs.
- Display side-by-side policy changes. Unclear restrictions become unresolved review items, not permissive defaults.
- Require review of the exact relevant source revision before it can govern a live run.
- Apply program-specific issue exclusions during candidate triage without deleting underlying observations.

**Tests:** scope shrinks, source unavailable, ambiguous wildcard, new third-party exclusion, invitation/private brief, automation prohibited, program closes.

**Acceptance:** a researcher can explain why an asset/action is permitted and whether its category is reward-eligible from stored provenance. A policy parser cannot approve its own output.

### B06 — Operator identity, secret references and execution isolation

**Priority:** P0 before authenticated live mode · **Size:** L · **Dependencies:** B01, B03

**Touch:** session, accounts, browser transport, scope engine, deployment profiles, database roles.

- Keep loopback-only binding as the default. Add authenticated operator identity for approvals/review; do not add remote hosting implicitly.
- Implement secret reference storage with encrypted secrets and an OS-protected key strategy on supported local platforms.
- Separate database migration and runtime credentials; test effective privileges.
- Isolate browser profiles, download directories and temporary artifacts per run/account.
- Build an independently restricted egress deployment profile and an explicit unsupported-platform state if that boundary is unavailable.
- Exercise browser navigation, subresources, redirects, service workers, WebSockets and DNS changes through the boundary; disable unsupported channels.
- Model precise handling for required identity-provider origins. An authentication exception must not become permission to research the identity provider.

**Acceptance:** a malicious page cannot cause traffic to an unapproved destination or read another project's secret. Authenticated live mode stays unavailable on an unverified isolation profile; demo remains usable.

### B07 — Evidence ledger and artifact viewer

**Priority:** P0 for candidate verification · **Size:** L · **Dependencies:** B01, B06 for secret-bearing traffic

**Touch:** evidence, provenance, operations retention, proposed artifact service/viewer.

- Record bounded request/response metadata, controlled-data assertions, timestamps, actor references, content hashes, detector versions and approval revision.
- Apply redaction before persistence where possible; store restricted originals only when justified and encrypted.
- Version redaction rules and distinguish original-byte digest from redacted-artifact digest.
- Provide side-by-side response comparison, readable JSON diffs and optional scrubbed browser screenshots.
- Make evidence immutable; corrections are new revisions, with audit links to superseded material.
- Add legal/program retention settings, holds, expiry and deletion records without claiming backups vanish instantly.

**Tests:** authorization headers, cookie values, query tokens, emails, nested JSON secrets, logs on failure, oversized body, screenshot secrets, partial captures and corrupted blobs.

**Acceptance:** a reviewer can follow every material claim to a specific artifact and execution. Export and model contexts contain no seeded secrets.

### B08 — Controlled account and session workbench

**Priority:** P1 · **Size:** L · **Dependencies:** B05–B07

**Touch:** application-research accounts/profile/browser, session, account setup UI.

- Start with two operator-supplied disposable ordinary-user accounts; do not require signup automation.
- Store secret references, role expectations, tenant identity and a fresh canonical principal observation.
- Explain same-principal aliases, expired sessions, missing tenant context and interactive challenges.
- Keep login assistance separate from authorization experiments. Support operator completion of challenges; do not automate their defeat.
- Recheck identity immediately before role comparisons and after relevant session changes.
- Show account health without exposing credentials or raw session tokens.

**Tests:** aliases resolve to one user, session swapping, shared tenant versus distinct tenant, expired/partially authenticated login, changing principal, cached login screen, MFA pause.

**Acceptance:** duplicate principals cannot enter a cross-account experiment; session failure becomes blocked coverage, not a finding.

### B09 — Application map and permission coverage

**Priority:** P1 · **Size:** L · **Dependencies:** B05, B07, B08

**Touch:** API inventory, discovery, browser observations, proposed `packages/inventory/`, inventory screen.

- Ingest operator-supplied schemas, approved browser observations and bounded discovery sources.
- Normalize route templates while preserving raw evidence and avoiding over-merging different endpoints.
- Associate route/method with observed actor, tenant, resource type, object identifier location and workflow stage.
- Mark roles as observed, declared or researcher-expected; never infer expected access solely from a single response.
- Build a permission matrix with unknown/allowed/denied/untested/blocked states and evidence links.
- Maintain candidate admission inbox; external references and newly discovered hosts stay unapproved.

**Tests:** GraphQL operation distinctions, parameterized paths, same route/different methods, schema drift, remote references, third-party scripts, missing ownership metadata.

**Acceptance:** the researcher can identify one specific untested boundary and trace its route/resource provenance without reading raw traffic dumps.

### B10 — Hypothesis queue and constrained experiment planner

**Priority:** P1 · **Size:** L · **Dependencies:** B03, B07–B09

**Touch:** authz, findings, proposed `packages/hypotheses/`, hypothesis/plan screens.

- Define a strict hypothesis schema: question, actors/resources, expected boundary, evidence, assumptions, falsifier and permitted experiment template.
- Generate deterministic suggestions before adding models: missing actor/resource matrix cells, newly observed sensitive routes and changed workflow transitions.
- Rank using visible factors: policy eligibility, unresolved evidence, permission-boundary relevance, novelty to this project, cost and uncertainty.
- Compile a reviewed hypothesis into a bounded typed plan; validate the whole plan against current policy and budgets.
- Bind approval to plan digest and policy revision. Editing requests/actors/resources invalidates it.
- Limit live execution to registered action templates. No arbitrary URL/tool/shell strings from a model.

**Tests:** stale plan, changed account, guessed ownership, unavailable control, budget underestimation, prompt-injected route labels, plan with an unapproved action.

**Acceptance:** every queued experiment has an inspectable reason, falsifier, exact action bounds and deterministic admission outcome.

### B11 — First high-value verifier: controlled cross-account reads

**Priority:** P1 · **Size:** L · **Dependencies:** B03, B06–B10, B12

**Touch:** authz, application verification, findings replay, dedicated fixtures and evidence comparison UI.

- Reuse existing distinct-principal and controlled-marker logic; strengthen rather than replace it with status-code heuristics.
- Use resources supplied or created by controlled accounts. Record ownership and expected sharing semantics.
- Compare the owner access, the other controlled principal's access, and a known control chosen for that workflow.
- Require a meaningful controlled-data assertion. A 200 response or different response length alone is insufficient.
- Reproduce according to a bounded contract with independent session checks. Record partial consistency instead of silently retrying until success.
- Verify cleanup or expose a durable obligation before declaring the experiment operationally complete.

**Tests:** vulnerable/patched twins, intentional public sharing, same-user aliases, login-page 200, reflected marker, stale cache, cross-tenant expectations, redacted/partial response and nondeterministic behavior.

**Acceptance:** blind tests produce reviewable evidence for vulnerable cases and no verified candidate for patched or intentionally shared cases. Human review is still required for submission readiness.

### B12 — Dedicated cleanup and uncertain-write reconciliation

**Priority:** P0 before resource-creating experiments · **Size:** L · **Dependencies:** B01, B03, B06–B08

**Touch:** existing cleanup journal, jobs, application cleanup, operations UI.

- Persist intent before any permitted resource creation. Include owner, marker, operation ID, approved cleanup contract and budget.
- Schedule reconciliation independently from the next research run; use fenced leases and bounded retries.
- Model `prepared`, `creation_uncertain`, `resource_known`, `delete_requested`, `delete_pending`, `confirmed_absent`, `blocked_policy`, `requires_operator` explicitly.
- Handle timeout/missing ID/202 responses using application-specific observation contracts, not generic assumptions.
- Expose action, attempts, last evidence, current policy and manual resolution reason in the UI.
- Prevent new resource-creating work when unresolved obligations exceed the configured threshold.

**Tests:** crash before send, after send and before persistence; delayed creation; missing resource ID; asynchronous delete; revoked policy; renewed authorization; lost lease; permanent server error.

**Acceptance:** every possibly created resource is either confirmed absent or represented by a visible, durable obligation. Manual resolution is audited and cannot pretend network verification happened.

### B13 — Persistent triage and intelligent deduplication

**Priority:** P1 · **Size:** M · **Dependencies:** B07, B10, B11

**Touch:** findings, operations store, migrations, findings UI.

- Persist review state, rationale, owner, labels and evidence revision with optimistic concurrency.
- Fingerprint by program, vulnerability class, route/operation, violated boundary and root-cause evidence; preserve all occurrences.
- Separate same-root-cause grouping from platform duplicate status. The tool cannot see undisclosed third-party reports.
- Support accepted-for-reporting, needs-more-evidence, expected-behavior, duplicate-local, ineligible and rejected dispositions.
- Preserve reviewer disagreements and historical decisions. Scope or detector changes can reopen review with an explanation.

**Acceptance:** two tabs cannot silently overwrite decisions; recurring observations consolidate without erasing evidence; local dedup never claims a report is globally novel.

### B14 — Report studio and private submission ledger

**Priority:** P1 · **Size:** L · **Dependencies:** B05, B07, B13

**Touch:** proposed `packages/reporting/`, findings/report UI, structured export service.

- Generate the report structure in section 9 from selected immutable finding/evidence revisions.
- Provide editable title, summary, steps, observed/expected behavior, demonstrated impact, limitations and remediation notes.
- Highlight factual sentences missing evidence references. Keep model wording visibly proposed until reviewed.
- Produce Markdown and self-contained HTML plus a redacted evidence manifest. Add PDF only after the HTML model is stable.
- Add export redaction preview, evidence integrity validation and reproduction checklist.
- Record submission manually with platform ID/date/status; no automatic platform publishing in the first release.

**Tests:** missing attachment, unsupported impact, stale evidence, secret in title/body/screenshot, HTML injection, export interrupted, report revision after submission.

**Acceptance:** an independent reviewer reproduces the issue from the exported packet, and the operator can submit it without reconstructing evidence manually.

### B15 — Retests and change-aware research

**Priority:** P1 · **Size:** M · **Dependencies:** B05, B09, B13

**Touch:** findings retest, inventory snapshots, campaign comparison UI.

- Compare normalized routes, permission outcomes, policy revisions and relevant content/schema digests.
- Suppress volatility such as timestamps using documented normalization; preserve originals and hash provenance.
- Suggest a bounded retest for a meaningful change. A suggestion never grants permission or immediately launches work.
- Classify outcomes as reproduced, not reproduced with adequate coverage, inconclusive, blocked or not retested.
- Preserve the original finding while adding the new evidence; human closure is distinct from a clean retest.

**Acceptance:** a failed request cannot mark a bug fixed; unrelated content changes do not flood the research queue; an authorization change invalidates incompatible retest plans.

### B16 — Add two more focused research families

**Priority:** P2 · **Size:** L · **Dependencies:** first B11/B14 pilot evidence, B12

**Touch:** detector registry, typed experiment templates, fixture corpus, permission/workflow UI.

- Add function/role authorization checks limited to approved operations and controlled actors.
- Add selected invitation/sharing/ownership state-transition checks in owned labs first, then reviewed live templates only where a program permits them.
- Prefer reading controlled state. Any write needs explicit side-effect classification, supported cleanup and a specific budget.
- Require vulnerability-specific negative controls, intended behavior and eligibility context.
- Do not generalize a successful fixture into unlimited workflow exploration. Each adapter declares its supported actions and limitations.

**Acceptance:** each family has independent vulnerable/patched fixtures, realistic negative cases and at least one reproducible owned-staging demonstration. Enable live use per template, not through a global “aggressive” switch.

### B17 — Bounded AI research assistant

**Priority:** P2 · **Size:** M · **Dependencies:** B07, B09, B10, B14

**Touch:** LLM/runtime, hypothesis and report services, evaluation fixtures.

- Start with route labeling, evidence summaries, hypothesis suggestions and report editing.
- Send allowlisted redacted context with stable evidence IDs; use strict output schemas and response-size/time/cost bounds.
- Treat page text, reports, comments and retrieved content as untrusted data.
- Validate every cited evidence ID, principal, route and tool/template reference server-side.
- Add cached context digests, model/prompt version tracking and graceful unavailable-provider behavior.
- Make external providers an explicit project setting, respecting private program data constraints.

**Acceptance:** the assistant reduces measured review/drafting time on held-out cases, rejects injected instructions and unsupported claims, and cannot bypass admission or mark findings verified.

### B18 — Research economics and outcome-driven prioritization

**Priority:** P1 for logging, P2 for recommendations · **Size:** M · **Dependencies:** B05, B13, B14

**Touch:** proposed `packages/outcomes/`, cost/time ledger, dashboard analytics.

- Record research sessions, attributable tool/model costs, submission decisions, triage outcomes, awards and payments.
- Support manual correction with audit history and explicit unknown/missing data.
- Show funnels by program, research family and period; keep unresolved cohorts separate.
- Collect rejection reasons using program feedback, not a model's guess.
- Use results to recommend where to spend the next research block, with sample sizes and transparent factors.

**Acceptance:** the operator can distinguish cash received from awards/pending reports and identify a low-value research family without exporting CSV.

### B19 — Blind benchmark and controlled first-program pilot

**Priority:** P0 before effectiveness claims · **Size:** L · **Dependencies:** B11–B14; logging from B18

**Touch:** benchmark, fixtures, evaluation runner, results documentation.

- Build the benchmark and pilot defined in sections 11–12.
- Separate training/development fixtures from held-out cases; prevent retrieval of solution labels.
- Include an independent reviewer and manual baseline measurements.
- Conduct the first real-program pilot only with reviewed policy and controlled accounts.
- Record accepted, duplicate, informative, rejected and unresolved submissions; keep every cost and failed idea in the denominator.

**Acceptance:** a reproducible evaluation report supports or rejects the specialization hypothesis. No 10× or revenue claim appears without corresponding measurements.

### B20 — Package a dependable daily-use release

**Priority:** P1 · **Size:** M · **Dependencies:** B01–B15, B19 for live research release

**Touch:** launcher/readiness, CI, deployment documentation, health/backup tooling.

- Provide a one-command local startup with database readiness, migration status and a clear port-conflict message.
- Document the supported PostgreSQL installation path; do not silently ship a test-only embedded runtime as production infrastructure.
- Add health checks for worker heartbeat, queue age, storage, policy expiry and cleanup obligations.
- Test backup/restore, interrupted upgrades, browser crash and disk exhaustion.
- Produce a release manifest with code/model/detector/schema versions and known limitations.
- Confirm source dependency licenses and any redistributed executable licenses before bundling them.

**Acceptance:** a fresh supported machine can install and run the documented workflow; recovery preserves evidence and obligations; remote/team hosting remains a separate release.

## 7. Research strategy and detector portfolio

### 7.1 Choose depth before breadth

Start with one application and a small number of workflows that the operator can understand. The system should become excellent at finding gaps between intended permissions and observed behavior. Build a reusable project notebook containing the role model, ownership rules, tenant boundaries, sharing behavior and known intentional exceptions.

A proposed first investigation uses only synthetic records owned by the operator's accounts. The tool records what is known, what is assumed, what would demonstrate a violation and what would disprove it. This is a research contract, not an instruction to search through unrelated users' object IDs.

### 7.2 Portfolio and required proof

| Family | Product priority | Evidence required before candidate promotion | Common false-positive trap |
| --- | --- | --- | --- |
| Cross-account/tenant object reads | First | Distinct principals, controlled ownership, private-data assertion, intended boundary, control and repeatable replay | Public sharing, aliases, reflected markers, cached login page |
| Function/role authorization | Second | Verified actor role, approved operation, meaningful unauthorized result, documented expected denial | Hidden UI mistaken for a server-side restriction |
| Sharing/invitation state transitions | Third | Controlled workflow state, expected transition, observable boundary violation and cleanup | Intentional link sharing or stale session state |
| Session/logout invalidation | Later bounded template | Explicit policy expectations, controlled session lifecycle, meaningful continued capability | Grace periods or expected token lifetime misclassified |
| Browser-dependent injection/CORS behavior | Later, separate evidence contract | Actual controlled browser behavior and demonstrated impact within policy | Reflection or permissive headers alone |
| Disclosed configuration/metadata | Context and leads | Proven sensitive exposure and program eligibility | Banners, missing headers and public documentation |
| Public source/API specification review | Supporting workflow | Supplied/authorized source, exact code or schema references, live claim separately verified | Inferring reachable exploitation from static patterns |

Do not label the first release a comprehensive penetration tester. Publish a capability matrix with exactly supported contexts, permitted actions and known gaps.

### 7.3 Detector contract

Each detector/template must declare:

```typescript
// Proposed contract; refine types against existing packages before implementing.
interface ResearchTemplate {
  id: string;
  version: string;
  researchFamily: string;
  requiredCapabilities: string[];
  requiredPrincipalCount: number;
  requiresKnownOwnership: boolean;
  sideEffects: 'none' | 'controlled-resource-write';
  maxRequests: number;
  maxCreatedResources: number;
  timeoutMs: number;
  cleanupContractId?: string;
  inputSchemaVersion: number;
  evidenceRequirements: string[];
  negativeControlRequirements: string[];
  supportedApplicability: string[];
  unsupportedContexts: string[];
  fixtureManifest: string;
}
```

The planner resolves a template to exact approved targets and operations. The gateway must independently enforce the resolved plan's bounds; declaring a request count is not enforcement. Inputs must not allow arbitrary scripting. Version changes that alter behavior require new fixtures and must be visible in reports and comparisons.

### 7.4 Prioritization without invented certainty

Use a factor table rather than one unexplained AI score:

- **Eligible:** current program permits the asset, action and research family.
- **Boundary relevance:** the workflow actually contains ownership, tenant or role distinctions.
- **Evidence readiness:** controlled accounts/resources and a useful control exist.
- **New information:** newly observed behavior or an untested matrix cell, not a repeat of a rejected idea.
- **Cost:** estimated requests, setup, review time and model expense.
- **Uncertainty:** unclear intended behavior, insufficient identity evidence or missing observations.

Show “why now” and “what would change this recommendation.” Ineligible work cannot be rescued by a high score. A low-cost header observation does not outrank a well-supported permission hypothesis solely because it is easy to run.

### 7.5 Program selection assistant

The operator should be able to compare three to five candidate programs in a private table. Include current reward eligibility, permitted automation, available controlled-account setup, application complexity, policy clarity, researcher familiarity and recorded triage responsiveness. Leave unknown values unknown. Private participation and platform access remain operator-controlled.

The system may summarize a supplied brief and make a recommendation; it must display the source and review date. It must not rank programs using scraped private reports or assert that a target is “low competition” without defensible data. Avoid treating advertised maximum bounty as expected payout.

## 8. Interface specification

### 8.1 Navigation

Keep the existing restrained visual style and lightweight behavior. Proposed primary navigation:

```text
Today
Programs / Projects
Application map
Hypotheses
Campaigns
Findings
Reports & outcomes
Operations
```

Use a project selector to constrain data. Preserve a simple “New passive assessment” action for the current workflow. Do not force passive users through account setup or an AI configuration wizard.

### 8.2 Today screen

Present the next useful action, not a wall of metrics:

- Running work with stop action and worker freshness.
- Scope changes needing review.
- Evidence-ready candidates awaiting review.
- Blocked experiments and unresolved cleanup.
- Report follow-ups entered by the operator.
- Research time, expense and realized outcomes for the selected period.

Every card links to the exact record. Empty states offer a synthetic walkthrough or a concrete setup action. Do not show fabricated activity, earnings or vulnerability totals.

### 8.3 Project overview

Show approved scope and exclusions, source revision, expiry, mode, account health, request budget and recent outcomes. Separate “Edit draft” from “Approve revision.” Old runs link to their immutable historical revision. A policy change badge explains which pending plans it affects.

### 8.4 Application map

Default to a table and permission matrix, with an optional relationship diagram when it helps. Columns: workflow, route/operation, actor, resource type, ownership expectation, evidence freshness and coverage. Filters: unknown boundaries, changed routes, missing controls, tenant and actor.

Selecting a matrix cell opens observed evidence, expected behavior and suggested bounded experiments. Do not make a graph visualization the only accessible route to research.

### 8.5 Hypothesis details and execution preview

Use these sections in order:

1. Research question and why it matters.
2. Supporting evidence and assumptions.
3. Controlled actors/resources and expected permissions.
4. Plan steps, action classification and request/cost limits.
5. Positive assertion and negative control.
6. Cleanup plan and uncertainty handling.
7. Authorization revision and explicit launch action.

Offer “Reject idea,” “Needs context,” “Save plan,” and “Run reviewed plan.” Show actionable reasons for disabled controls. A changed plan clears launch approval without erasing the user's draft.

### 8.6 Campaign progress

Use stages such as `admitting → establishing sessions → checking preconditions → executing experiment → verifying → reconciling cleanup → ready for review`. Stages are durable states or derived from durable events, not decorative timers.

Display completed/attempted/planned counts, current activity, age of last heartbeat, remaining budget and blocked reasons. Do not show an estimated completion time until enough measured data exists; label it an estimate. The stop control explains whether in-flight work is still settling.

### 8.7 Finding review

Show the claim, scope eligibility, confidence rationale and verification outcome above the evidence. Default the evidence comparison to controlled owner / second principal / negative control. Make missing or contradictory evidence prominent. Keep proposed severity editable with rationale and taxonomy version.

Keyboard actions should support next/previous candidate, opening evidence, changing disposition and saving a note. Dangerous/destructive actions need a clear effect preview. Ordinary review should not require repeated confirmation dialogs.

### 8.8 Report studio

Use an outline and editor with an evidence sidebar. Flag missing prerequisites, unsupported factual claims, unspecified actor roles and attachments that no longer match the manifest. Preserve human edits when regenerating AI suggestions; offer a diff, never overwrite silently.

Export choices: Markdown, HTML and JSON manifest initially. The export preview identifies redactions and missing evidence. Recording a manual submission requires a report revision, platform identifier and timestamp; it does not contact the platform.

### 8.9 Interaction and performance targets

Proposed test targets on a declared development machine:

- Meaningful initial workspace content within two seconds on a local populated database.
- Filter/page responses under 300 ms p95 for a fixture dataset of 10,000 findings and 1,000 campaigns.
- No unbounded artifact/body loading in history lists.
- Live updates preserve focus and screen-reader context; throttle announcements to meaningful changes.
- Main flows work at 390 px width and with keyboard-only operation.
- Respect reduced-motion settings and test contrast; never encode outcome solely in color.
- Offline/unavailable backend visibly freezes stale data and disables execution; edits remain recoverable.

These are acceptance targets to measure, not current performance claims. Store dataset, machine and query plans with benchmark results.

## 9. Evidence, verification and reports

### 9.1 Evidence is the product's core asset

For each material observation, record campaign/job/check IDs; exact policy revision; actor and tenant references; request method and scoped URL; redacted input summary; timestamp; response metadata; bounded body evidence where allowed; capture/truncation status; artifact digest; detector version; and execution environment.

For a candidate, add the expected boundary, controlled ownership evidence, asserted fields, negative control, repetition results, known limitations, cleanup status and human review. Make evidence references stable across UI, JSON and report exports.

Store fact and interpretation separately. For example, “the controlled marker appeared in account B's response in two admitted runs” is an observation. “Any customer record can be read” is a broader claim requiring additional permitted evidence and must not be invented from that observation.

### 9.2 Verification gate

A candidate reaches verified technical behavior only when:

1. The current execution plan and policy were valid when requests were admitted.
2. Canonical principal and ownership preconditions were satisfied.
3. The vulnerability-specific positive assertion matched meaningful evidence.
4. The prescribed negative control behaved as expected.
5. The bounded repetition requirement passed without selectively omitting failures.
6. Evidence is intact, correctly attributed and sufficient for an independent reviewer.

Operational completeness also requires either confirmed cleanup or a disclosed unresolved obligation. Separate technical reproduction from operational completion and submission readiness. Program eligibility, novelty and bounty amount are not established by deterministic replay.

### 9.3 Report-ready gate

A human confirms: asset and research method were permitted; report category is eligible; expected behavior is understood; reproduction uses controlled data; impact is no broader than the evidence; secrets and unrelated data are removed; cleanup state is disclosed; and the report is coherent without internal tool access.

HackerOne's report guidance emphasizes clear reproduction and useful supporting information. Use that as a quality standard, while applying each program's own requirements. [HackerOne Quality Reports](https://docs.hackerone.com/en/articles/8475116-quality-reports).

### 9.4 Structured report template

```markdown
# [Specific boundary violation] in [affected workflow]

## Summary
What happened, who can do it, and the narrow demonstrated consequence.

## Affected asset and eligibility
Approved asset, program policy revision/date, relevant scope notes.

## Preconditions
Controlled accounts and roles, ownership, initial workflow state.
Secret values are referenced or redacted, not pasted.

## Steps to reproduce
Numbered, minimal steps tied to evidence IDs.
Each step names the actor and expected state.

## Expected behavior
The intended permission boundary and its basis.

## Observed behavior
Exact assertion, response evidence, repetition and control results.

## Demonstrated impact
What the evidence proves; explicitly separate untested extensions.

## Evidence
Redacted request/response excerpts, relevant screenshots, artifact manifest.

## Cleanup and remaining state
What was created, what was removed, any outstanding obligation.

## Suggested remediation
Optional, focused on the violated invariant rather than generic advice.

## Limitations
Untested roles, paths, conditions or uncertain outcomes.
```

The report editor may propose a severity and mapping. Pin the taxonomy version and expose the reasoning. Bugcrowd's VRT provides baseline classifications, not a promise of a program's final priority or reward. [Official VRT repository](https://github.com/bugcrowd/vulnerability-rating-taxonomy).

### 9.5 Automated program-compatible report generation

Implement automatic, deterministic report drafts from recorded findings and evidence. Support these profiles:

| Profile | Primary artifact | Fields / behavior |
| --- | --- | --- |
| HackerOne | Markdown for the report form | Title, vulnerability information, steps, impact; asset, weakness and severity remain explicit form selections; support custom program fields |
| Bugcrowd | Markdown for the submission form | Title, description with reproduction and impact, affected target/location, suggested taxonomy needing review; honor program-specific fields |
| Generic coordinated disclosure | Markdown and plain text | Portable summary, prerequisites, reproduction, evidence, impact, remediation, limitations |
| Reviewer packet | Self-contained HTML and JSON manifest | Offline review, stable evidence IDs, hashes, provenance, redaction metadata and readiness checklist |

Markdown is supported by [HackerOne](https://docs.hackerone.com/en/articles/8475125-using-markdown) and in [Bugcrowd submission content](https://docs.bugcrowd.com/researchers/reporting-managing-submissions/reporting-a-bug/embedded-images-for-submissions-and-comments/). Formatting compatibility does not guarantee acceptance, eligibility or reward. Recheck each program's current template and required fields. Use the platform form as the canonical submission path; HTML/JSON are supporting artifacts, not a claim that those files can replace the form.

Split B14 into independently tracked slices:

- [x] **B14.1 — verified locally (2026-10-04):** pure report model/generator, HackerOne/Bugcrowd/generic Markdown, text, HTML and JSON; per-observation generation from completed local assessments; demo labels and explicit missing-impact/reproduction checklist; preview/download UI and transport security tests. See [implementation status](IMPLEMENTATION_STATUS.md) and [validation history](VALIDATION.md).
- [ ] **B14.2 — in progress:** persistent editable report revisions, human-authored impact and reproduction steps, evidence selection and claim references; custom program fields; optimistic concurrency; no overwrite of human edits. Local file revisions, editable text/custom fields, source-snapshot binding, optimistic revision checks and browser version history are implemented and verified. Evidence selection and claim references remain open; file persistence does not provide cross-process or PostgreSQL concurrency.
- **B14.3:** evidence attachment manifest with content digests, redaction preview and integrity verification; uploaded platform attachment IDs entered by the operator, never invented; report-ready gates and unsupported-claim checks.
- **B14.4:** reviewed export bundle, manual submission/outcome record, follow-up draft generation and integration with the durable campaign/finding lifecycle.

B14.1 can ship ahead of the larger persistence milestone because it only formats existing terminal observations; B14 remains incomplete until its full dependencies and later slices pass. Automatic generation must never automatically submit or promote an observation to a verified finding. If impact, reproduction or program requirements are unknown, mark the draft incomplete and name what the operator must supply. Generate one focused report per selected observation initially; root-cause grouping comes later.

Deterministic templates are the default. AI can optionally edit wording after B17 passes its evaluation gate. Escape untrusted text in each renderer; do not render remote HTML or embed external media. Apply best-effort secret redaction, disclose its limits, and require human redaction review. Never put raw captured response bodies or secrets into a manifest merely to make it look complete. The first draft generator can cite a stored detector observation and a captured-body hash, but must not pretend it has a full raw transcript.

Tests must cover every profile/format, missing evidence, duplicate generation, selection bounds, terminal-state requirement, demo watermark, redaction, Markdown/HTML injection, authenticated export and browser preview/download. Include a report contract version and a source-snapshot digest for reproducibility.

### 9.6 Submission and follow-up

Initial release exports a reviewed packet and records what the operator submitted. Future platform integrations require a separately reviewed implementation and explicit operator submission action. Do not auto-submit on verification or run scheduled report spam.

Track triager questions, requested evidence, latest reply, disclosure restrictions, decision history and next manual follow-up. Generate draft replies with evidence links; sending remains a separate explicit action. Never fabricate platform status from a model summary or inferred email wording.

## 10. AI assistance that earns its cost

### 10.1 Allowed initial tasks

- Label observed routes and group related workflows.
- Explain what a permission matrix currently demonstrates and what remains unknown.
- Suggest hypotheses using approved template IDs and existing evidence.
- Summarize differences between controlled responses without changing their content.
- Draft or improve report prose with claim-level evidence references.
- Summarize operator-supplied triage feedback into suggested structured outcome labels.

Each task needs a non-AI fallback and a task-specific evaluation set. Do not choose models by branding or parameter count alone.

### 10.2 Proposed output contract

```json
{
  "schemaVersion": 1,
  "task": "suggest_hypothesis",
  "question": "Does the observed ownership boundary hold for the second controlled actor?",
  "templateId": "registered-template-id",
  "evidenceIds": ["existing-artifact-id"],
  "assumptions": ["Expected sharing behavior still needs operator confirmation"],
  "missingInputs": ["known negative control"],
  "confidenceRationale": "Observed route and ownership metadata support investigation; no violation is established."
}
```

Validate shape, identifiers and semantics. An existing evidence ID does not establish that the evidence supports the claim; evaluate and review entailment separately. Invalid outputs become rejected suggestions with diagnostics, not partial executable plans.

### 10.3 Prompt-injection and data boundaries

Retrieved pages, repository text, findings and program briefs can contain instructions; treat them as data. Give the model no direct permission to launch requests, alter policy, read arbitrary local files, retrieve secrets, submit reports or run commands. Its tool vocabulary, if any, should only retrieve bounded project data and create draft suggestions.

Separate project contexts and redact before model transport. Test attempts to request secrets, override scope, invent evidence IDs, widen URLs, conceal failures and change severity. Record context digest, prompt/model versions, token usage, duration and validation outcome. Avoid logging sensitive prompts verbatim.

### 10.4 Quality and cost gates

Use at least 50 held-out examples per initial AI task before default enablement, with an independently reviewed subset. Report supported-claim rate, hallucinated evidence IDs, missed contradictions, edit time and cost per usable output. Include adversarial examples and an unavailable-provider case.

Proposed gate: zero accepted nonexistent evidence references; at least 95% of factual draft claims supported in the reviewed evaluation set; no authority-changing action; and a measured reduction in editing/review time. A numeric confidence score alone cannot satisfy the gate. If assistance costs more time than it saves, keep the task disabled by default.

### 10.5 Platform constraints

HackerOne currently permits responsible AI assistance subject to its rules and individual program restrictions, and expects human investigation/validation before submission. Treat this as a reason to build an evidence-centered human review workflow, not as universal permission for autonomous scanning. Recheck the policy before a pilot. [HackerOne Code of Conduct](https://www.hackerone.com/policies/code-of-conduct).

## 11. Evaluation and release gates

### 11.1 Evaluation pyramid

1. **Pure unit tests:** normalization, policies, lifecycle transitions, fingerprints, report schemas and redaction rules.
2. **PostgreSQL integration:** real transactions, uniqueness, leases, fencing, outbox, migrations, import and retention.
3. **Transport contract tests:** bounded requests, DNS/address checks, deadlines, cancellation and capture limits.
4. **Browser workflows:** real browser against controlled applications, independent principals, login challenges and UI behavior.
5. **Deployment boundary tests:** actual isolated worker and restricted egress; injected transport success is insufficient.
6. **Owned-staging research:** complete vulnerable/patched experiments, evidence packet and independent reproduction.
7. **Authorized live pilot:** real policy, narrow reviewed scope and actual platform outcomes.

Results at one level do not substitute for another. Specifically, unit tests cannot prove program eligibility, fixtures cannot prove bounty yield, and a local browser test cannot prove distributed revocation.

### 11.2 Minimum research corpus

Build at least 30 distinct owned-lab workflow cases for the first verifier release:

- 10 vulnerable cases with deliberately different ownership/tenant/session shapes.
- 10 patched counterparts requiring the same application navigation and setup.
- 10 realistic confusing cases: intentionally public records, optional sharing, aliases, stale sessions, marker reflection, cached responses, error-page 200s, asynchronous deletion, partial captures and ambiguous expected behavior.

Ensure held-out cases include structural differences, not just renamed fixtures. Split by application/workflow family to prevent near-duplicate leakage. Keep the label manifest outside model context and evaluation worker access where practical. Add cases for each externally discovered failure without moving them into the held-out score retroactively.

Start with two independently implemented lab applications rather than one switch that changes every response from vulnerable to patched. At least one should exercise tenant and sharing semantics. All fixture data is synthetic.

### 11.3 Failure-injection matrix

| Failure | Required behavior | Ticket |
| --- | --- | --- |
| API times out after campaign commit | Same key returns original campaign | B01 |
| Two workers claim simultaneously | Respect shared concurrency; no conflicting ownership | B01/B03 |
| Lease expires before completion | Old owner cannot publish result or child work | B03 |
| Program policy changes mid-campaign | New admissions use current revision; incompatible work is blocked | B03/B05 |
| Stop occurs after admission | Abort where possible; record in-flight uncertainty | B03 |
| Browser issues unexpected third-party requests | Enforced boundary denies them; visible coverage gap | B06 |
| DNS returns a disallowed address | No target connection | B06 |
| Session aliases share a principal | Cross-account plan blocked | B08 |
| Account role changes during setup | Preconditions rechecked; plan invalidated as needed | B08/B10 |
| Create succeeds but response is lost | Durable uncertain obligation; no blind repeat | B12 |
| Delete returns asynchronous acceptance | Remain pending until absence contract passes | B12 |
| Cleanup authorization is revoked | No bypass; visible blocked obligation | B12 |
| Database is unavailable | No new admitted target traffic; preserve diagnostics | B03/B20 |
| Disk or artifact write fails | Stop affected work; no report-ready evidence state | B07 |
| SSE drops or duplicates events | Replay/reset converges without double application | B04 |
| Model invents evidence or emits instructions | Reject suggestion; no execution | B17 |
| A retest cannot authenticate | Inconclusive/blocked, never resolved | B15 |
| Retention encounters evidence under review | Respect hold and record deferred purge | B07 |
| Export contains a seeded token | Export gate fails; token not emitted | B14 |
| Restore uses older backup | Pending/incomplete state explicit; no automatic replay of writes | B20 |

### 11.4 Required commands and additions

Preserve these existing commands and run those relevant to each change:

```powershell
npm ci
npm run check
npm run test:browser
npm run verify:local
npm run test:dashboard-build
npm run gate
npm run deps:check
```

`verify:local` is the existing native local integration path; inspect its setup before using it on another platform. CI has its own PostgreSQL service setup. The dependency check verifies repository pins; it does not mean those upstream tools were executed or validated.

Proposed commands to implement where useful:

```text
npm run history:import -- --dry-run PATH
npm run history:import -- --manifest MANIFEST
npm run test:migrations
npm run test:egress
npm run benchmark:research -- --suite held-out --manifest VERSION
npm run evaluate:assistant -- --task report-draft --dataset VERSION
npm run evidence:verify -- REPORT_ID
npm run backup:verify -- SNAPSHOT_PATH
```

Do not document these as available until they exist. Record exact command, environment, fixture/dataset revision and result in the status ledger. Avoid rerunning slow suites without a change or unresolved concern that justifies it.

### 11.5 Release gates

**Gate A — Durable passive workspace**

- Common PostgreSQL scheduling path, idempotency and import complete.
- Existing passive form behavior preserved, including exclusions and review invalidation.
- Shared cancellation/budgets tested across processes.
- Durable progress reconnect and backup/restore tested.
- Fresh install and compiled demo work.

**Gate B — Guided research in owned labs**

- Accounts and principal checks work through the UI.
- Independent egress controls pass deployment tests.
- Evidence/redaction/cleanup are durable across injected failures.
- Controlled cross-account verifier passes blind vulnerable/patched/negative cases.
- Independent reviewer reproduces a finding from the report packet.

**Gate C — Narrow authorized live pilot**

- Operator supplies reviewed current program and permitted controlled accounts/actions.
- Program-specific budgets are configured and visible.
- Only released templates are available; the intended experiment is reviewed.
- Scope, secret handling and report confidentiality follow that program's terms.
- Outcomes and all research time/cost are recorded.

**Gate D — Daily-use research release**

- Pilot failures fed into regression tests.
- No unresolved critical scope, secret, cleanup or evidence-integrity defect.
- Recovery drills, upgrade compatibility and operator documentation pass.
- Effectiveness and remaining limitations are stated with measured evidence.

AI and additional detector families are optional for Gates A–C. Do not postpone the first useful owned-lab report while building a general agent platform.

## 12. Revenue pilot and feedback loop

### 12.1 Operator inputs needed for live work

Before the first real campaign, collect only the missing essentials:

- Chosen program and proof of participation/access where relevant.
- Current policy source, permitted assets/actions, excluded categories and automation restrictions.
- Two controlled accounts, their roles/tenant relationships and permitted synthetic data workflow.
- Operator research-time budget and spending cap.
- Preferred report format and private evidence retention needs.

Until these exist, continue on fixtures and owned staging. Do not invent a target, assume invitation access, import credentials from unrelated browser sessions or infer account-creation permission from a public signup page.

### 12.2 First 30 research sessions

This is an experimental cadence, not a promise of results or a rigid calendar.

**Sessions 1–5: understand and instrument.** Choose a small program set, review policy, establish accounts, manually map core workflows and record a manual baseline. Fix setup friction. Produce no speculative reports just to meet a quota.

**Sessions 6–15: focused permission research.** Work on one or two applications. Review a small number of strong hypotheses each session. Capture negative results and intended behavior. Prepare a report only when the evidence and eligibility gates pass.

**Sessions 16–25: deepen and compare.** Revisit changed or under-tested boundaries, improve control selection and test the next research family only if the first has useful precision. Compare assisted versus manual time on comparable tasks.

**Sessions 26–30: evaluate and decide.** Review submission outcomes, outstanding reports, costs, setup/review time and recurring rejection reasons. Decide whether to deepen the specialization, change program selection, improve the verifier or stop an ineffective research family.

Do not wait for every report to resolve before improving the tool, but do not assign unresolved work a fabricated monetary outcome.

### 12.3 Session worksheet

Each session records:

```text
Program/project and reviewed policy revision:
Research question and selected workflows:
Start/end and actual active researcher minutes:
Tool/model costs and request budget consumed:
Hypotheses considered / rejected / executed:
Verified technical candidates and evidence IDs:
Human report decisions and reasons:
Cleanup obligations:
Platform outcomes received this session:
What changed our understanding:
Best next experiment:
```

Auto-populate measured fields. Keep inferred estimates marked as estimates and make manual time correction easy. Include time spent on dead ends and triage; excluding them would misrepresent the product's economics.

### 12.4 Weekly decision review

Ask:

1. Which workflows generated useful evidence instead of noise?
2. Where did researchers spend the most time: setup, mapping, controls, verification or reports?
3. Which candidates were ineligible, duplicates or expected behavior, and why?
4. Did automation reduce total review time or merely increase the candidate pile?
5. Is a program's response cadence compatible with the operator's goals?
6. Which one product change would remove the largest demonstrated bottleneck?

Implement the highest-value observed bottleneck before adding a new scanner. If the main loss is duplicates, prioritize deeper application understanding and change detection. If it is invalid findings, improve controls. If it is report rejection for insufficient detail, improve evidence and reproduction before increasing research volume.

### 12.5 Stop and pivot criteria

- Any unauthorized request or secret leak suspends the affected live capability until investigated and regression-tested.
- Unreconciled side effects beyond the configured threshold stop new writes.
- Repeated failures of the same intended-behavior assumption require revising that template, not raising confidence.
- A research family producing no reviewable candidates after the agreed pilot budget gets an explicit continue/pivot decision with evidence.
- Do not increase request volume merely because earnings are low.
- Treat payout potential as conditional on program judgment, novelty and demonstrated impact. A high benchmark score does not establish income.

Bugcrowd's terms and code of conduct emphasize following each program's brief and disclosure conditions. The product must preserve those program-specific requirements rather than applying one universal scanning policy. [Standard Disclosure Terms](https://www.bugcrowd.com/resources/hacker-resources/standard-disclosure-terms/), [Code of Conduct](https://www.bugcrowd.com/resources/hacker-resources/code-of-conduct/).

## 13. Delivery sequence and completion criteria

### 13.1 Critical path

```text
B00 -> B01 -> B02 + B03 -> B04                         Durable passive product
          -> B05                                       Program context
                 B03 -> B06 -> B07 -> B08 -> B09       Safe research context
                                      -> B12          Cleanup readiness
                        B09 + B12 -> B10 -> B11        First useful verifier
                                      B11 -> B13 -> B14 -> B19
                                                        Report + live pilot
                        B13 -> B15                      Retest/change loop
                        B14 -> B18                      Economics/feedback
                        Pilot evidence -> B16 / B17     Expand only with evidence
                        Core + recovery -> B20          Daily-use release
```

The arrows summarize the path; the per-ticket dependency lists are authoritative. Logging from B18 should be introduced before pilot data collection, even though recommendations can wait. A developer may work on independent components concurrently, but contracts and migrations need a single coordinated owner. Parallelism is optional; do not make it a prerequisite for following this handoff.

### 13.2 Suggested delivery waves

| Wave | Deliverable | Indicative effort for one experienced developer with AI assistance | Exit evidence |
| --- | --- | --- | --- |
| 1 | Common durable passive service and migration | 1–2 weeks | Gate A plus import/restore tests |
| 2 | Program policy, isolation, accounts and evidence | 2–3 weeks | Principal, egress and secret/redaction tests |
| 3 | Inventory, hypotheses, cleanup and first verifier | 2–4 weeks | Blind owned-lab cases and interrupted-write recovery |
| 4 | Triage, report studio and pilot logging | 1–2 weeks | Independent report reproduction |
| 5 | Narrow live pilot and focused corrections | Several research sessions; triage duration external | Recorded outcomes and bottleneck review |
| 6 | Additional research families, useful AI and packaging | 2–4 weeks after pilot learning | Held-out improvement and daily-use recovery gates |

These are rough planning ranges, not a commitment. Isolation and application-specific authentication may dominate effort. Do not compress the schedule by dropping evidence, controls or cleanup. Platform response and payout timing are outside implementation control.

### 13.3 First three implementation changesets

**Changeset 1: persistence contracts and migration skeleton.** Define campaign repository interfaces against the actual service, add an additive schema migration, preserve existing file-backed demo behavior, and add repository contract tests. Do not change the UI's start semantics yet. Include an ADR explaining ID mappings and existing table reuse.

**Changeset 2: PostgreSQL live execution.** Implement campaign start/idempotency and job linkage, route dashboard/CLI through it, and make existing workers respect campaign context. Include restart, duplicate-start and stale-lease tests. Keep a feature flag during migration, with no silent fallback or simultaneous schedulers for one project.

**Changeset 3: shared controls and visible migration.** Implement stop epochs/request reservations, import preview/manifest and the UI's storage/worker mode display. Verify two-worker cancellation and repeat import. Only then cut over the operator's live workspace.

This sequence yields concrete improvements early while avoiding a half-rewritten UI attached to two competing execution engines.

### 13.4 Definition of done for a feature

- Works through its intended UI/API workflow with real persistent state.
- Has meaningful positive, negative and interruption tests appropriate to its risk.
- Preserves current authorization, evidence and cleanup invariants.
- Exposes partial, stale, failed and blocked states honestly.
- Has migration/rollback behavior and documentation where needed.
- Passes relevant checks on supported environments; untested environments are named.
- Contains no hidden mock behavior presented as real functionality.
- Includes a documented limitation rather than an unsupported capability claim.

### 13.5 Definition of done for this plan

**Engineering complete:** Gates A, B and D pass for the declared supported release, the first verifier/report workflow is fully integrated, documentation and recovery are usable, and open later-stage tickets are explicitly classified.

**Commercial hypothesis validated:** the operator has real, attributable, nonduplicate accepted bounty outcomes and enough recorded effort/cost data to decide whether continued investment makes sense. This cannot be guaranteed by code completion or synthetic benchmarks.

**Stretch 10× claim validated:** an independently reviewable whole-workflow benchmark meets the declared ratio with comparable effort and quality. Otherwise report the actual improvement; do not relabel the goal as a result.

## 14. Operating and recovery procedures

### 14.1 Before a live research session

Confirm current reviewed policy, selected mode, controlled identity health, available budgets, cleanup backlog and worker health. Show this as one concise readiness panel, not a series of repetitive modal approvals. Highlight changes since the last reviewed session. Preserve review validity only where inputs are unchanged and policy allows it.

For the first live release, use conservative default concurrency of one admitted experiment per program and respect the stricter of configured or published rates. Keep existing passive bounds unless the operator explicitly reviews a new plan. Browser background traffic counts toward actual limits; when it cannot be budgeted reliably, stop and expose the unsupported workflow rather than ignoring it.

### 14.2 Request to stop

Persist stop/epoch change, prevent new admissions, signal active workers, attempt cancellation and record remaining in-flight states. The UI must show when work has actually settled. Uncertain writes create reconciliation obligations. Whether cleanup can proceed depends on current authorization; stopping must not silently launch extra target actions outside its defined semantics.

### 14.3 Database outage

Deny new admissions, preserve local nonsecret diagnostics, stop scheduling and show stale-state age. Do not fall back to a separate live file queue. On recovery, reconcile leases and operation IDs before resuming. Revalidate scope and any explicit operator resume requirements.

### 14.4 Secret exposure suspicion

Stop the affected capability, identify impacted artifacts/logs/exports, invalidate affected sessions with the operator's authority, and rotate credentials through the appropriate workflow. Preserve a redacted audit trail. Do not send raw secrets to a model for incident explanation. Regenerate exports from corrected evidence and document what copies cannot be recalled.

### 14.5 Backup and restore

Use a consistent database snapshot and matching artifact manifest. Encrypt backups containing restricted evidence. Restore into an isolated instance, validate relations/hashes, verify cleanup obligations and keep execution disabled. Resolve incomplete operations and current policies before enabling requests. Demonstrate this procedure with fixtures before release.

### 14.6 Retention and deletion

Define retention per artifact class and project policy. Hold evidence tied to active review or unresolved cleanup. Deletion previews identify related artifacts and exported copies that are outside managed storage. Purging a database row must not leave recoverable secret payloads in another managed table, model log or generated report. Record deletions without retaining the deleted sensitive content in the audit log.

### 14.7 Upgrade

Stop live admissions, back up, verify schema compatibility, apply additive migrations, run smoke checks, reconcile unfinished work and restart with requests disabled. Document when rollback requires restoration rather than old-code execution. A release should never automatically repeat resource-creating operations solely because its schema changed.

## 15. Copyable Claude kickoff prompt

```text
You are implementing Anteater as a high-quality bug-bounty research workspace.
Read docs/CLAUDE_BOUNTY_BUILD_PLAN.md fully, then inspect the current repository,
applicable AGENTS.md instructions and docs/VALIDATION.md. The plan baseline is
the current branch HEAD; implementation checkpoint `c8fde77` adds the first
report studio and campaign-storage foundation. Read the latest status ledger
and validation history before relying on earlier plan assumptions.

The objective is to improve legitimate researcher productivity and evidence
quality so the operator can pursue paid, eligible, distinct bug-bounty findings.
Do not promise income or claim synthetic detections establish live effectiveness.

Create/update docs/IMPLEMENTATION_STATUS.md. B00 and B14.1 are verified locally;
B14.2 is in progress; B01 has a schema/repository foundation but is not integrated.
Continue B01 by implementing the PostgreSQL campaign repository/admission path,
and continue report evidence work without exposing campaign-linked jobs to the
legacy worker. Reuse the existing PostgreSQL jobs, leases, scope engine, campaign service, account research,
cleanup journal, finding verification and passive UI. Do not rewrite everything.

Work in tested vertical slices. For each slice, implement service/persistence/UI
behavior as appropriate, test negative and interruption paths, document migration
and recovery, update the ledger and commit coherent changes. Continue independent
implementation when real-program inputs are missing; use owned synthetic labs.

Keep passive mode the default. Authenticated research requires the plan's gates,
current reviewed program policy, controlled accounts and approved experiments.
Do not contact arbitrary targets, create external accounts, spend money, submit
reports, expose remote access or publish private data from this handoff alone.
Models cannot grant scope, execute arbitrary tools, verify findings or submit.

Preserve user changes and existing tests. Do not mark stubs, untested adapters,
unsupported platforms or fixture-only outcomes complete. Do not silently weaken
scope enforcement, principal checks, request budgets, redaction or cleanup.

After each milestone, state: what now works in the UI; migrations applied;
tests actually run and outcomes; known limitations; changed files/commits; and
the next unblocked ticket. Keep status factual and make the product usable.
```

### Suggested `IMPLEMENTATION_STATUS.md` entry

```markdown
| Ticket | Status | Commit(s) | Verification | Remaining limitation | Next action |
| --- | --- | --- | --- | --- | --- |
| B01 | in_progress | ... | PostgreSQL repository contract tests pass | UI not wired | Connect start endpoint |

## Current milestone
Concrete observable outcome:
Dependencies satisfied:
External inputs still required:

## Last verification
Command / environment / dataset revision / actual result:

## Decisions
ADR links and reason for scope changes:

## Next session
First file to inspect and next concrete task:
```

## 16. References and decision provenance

Sources checked October 3, 2026. Platform rules and program briefs can change; revalidate before live research. These sources inform the eligibility, report-quality and taxonomy choices. The architecture, targets, prioritization and delivery estimates in this document are design recommendations, not claims made by those sources.

1. [HackerOne Code of Conduct](https://www.hackerone.com/policies/code-of-conduct) — AI-assisted research, human validation and program restrictions.
2. [HackerOne Quality Reports](https://docs.hackerone.com/en/articles/8475116-quality-reports) — clear reproduction and useful supporting evidence.
3. [HackerOne Disclosure Guidelines](https://www.hackerone.com/terms/disclosure-guidelines) — program policy and coordinated disclosure context.
4. [Bugcrowd Standard Disclosure Terms](https://www.bugcrowd.com/resources/hacker-resources/standard-disclosure-terms/) — program-specific research and disclosure requirements.
5. [Bugcrowd Code of Conduct](https://www.bugcrowd.com/resources/hacker-resources/code-of-conduct/) — researcher conduct and bounty brief requirements.
6. [Bugcrowd VRT](https://github.com/bugcrowd/vulnerability-rating-taxonomy) — baseline vulnerability classification; pin a reviewed version when implementing.
7. [OWASP API1:2023](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/) — object-level authorization risk model.
8. [OWASP API5:2023](https://api-security.owasp.org/editions/2023/en/0xa5-broken-function-level-authorization/) — function-level authorization risk model.

Local context: [existing improvement plan](IMPROVEMENT_PLAN.md), [dashboard guide](DASHBOARD.md), [validation history](VALIDATION.md), [review-hardening notes](REVIEW_HARDENING.md). Older documents describe earlier implementation stages; use the latest code and validation evidence when they differ.

**The product's advantage should be better research decisions, stronger evidence and less wasted operator time. Build that loop first, measure it honestly, and expand only where the results justify the complexity.**
