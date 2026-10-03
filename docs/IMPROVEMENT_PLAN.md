# Anteater AI improvement plan

Planning baseline: October 2, 2026. This plan describes proposed work against the current local implementation, including the passive dashboard and review-hardening changes. It does not claim those changes have been published or production-validated.

## 1. Product direction

Build a lightweight, local-first workspace for authorized web and API assessments. A user should be able to define reviewed scope, understand what an assessment will do, follow its progress, examine evidence, assign a remediation owner, and verify a fix through the interface.

The product should answer five questions clearly:

1. What did I authorize?
2. What actually ran, and what could not run?
3. Which observations matter, and what evidence supports them?
4. What should be fixed next?
5. Did the fix work, and what changed since the previous assessment?

Keep the interface small and responsive. Improve the value of each assessment before adding more tools, parallelism, or model complexity. Continue with passive checks as the default product; authenticated testing is a later, separately enabled capability.

## 2. Starting point and principal gaps

| Area | Current implementation | Next gap to close |
| --- | --- | --- |
| Interface | Target/scope form, demo, progress, target details, severity filter, JSON download, local history | Reusable projects, drafts, clearer errors, review workflow, comparisons, accessible reporting |
| Dashboard execution | Single-process, sequential bounded HTTPS collection | Separate from PostgreSQL workers; controls and retention do not govern other processes |
| Dashboard storage | Atomic JSON files; capped history | Schema validation/versioning, migration, archive/delete controls, durable shared state |
| Worker execution | PostgreSQL jobs, leases, policy checks and atomic observations | Common campaign lifecycle and frontend integration |
| Coverage | Eight passive check definitions and explicit execution records | Context-sensitive applicability, richer check outcomes, verified methodology expansion |
| Findings | Passive signals and limited configured ownership verification | Persistent human decisions, deduplication, evidence views, report editing and retests |
| Cleanup | Persistent owner-bound intents and bounded reconciliation | Dedicated cleanup jobs, escalation, explicit handling of asynchronous or uncertain creation |
| Operations | Local switches, retention batches, tests and CI configuration | Shared revocation, external egress enforcement, recovery drills and deployable access controls |
| AI | Fixture/local-provider analysis interfaces | Verified model identity, task-specific evaluation and useful bounded assistance |

The recorded local baseline is a passing build, 137 unit tests, nine browser tests, and 15 reported database integration tests. Those counts demonstrate tested fixture behavior, not live detection effectiveness. [VALIDATION.md](VALIDATION.md) records the boundaries.

## 3. Architecture to work toward

```text
Lightweight browser UI
        |
Local API / authenticated team API when enabled
        |
Projects + immutable approvals + campaign service
        |
PostgreSQL jobs, events, findings, review decisions and cleanup intents
        |
Scope / expiry / budget / revocation admission
        |
Isolated workers -> independently restricted egress -> authorized targets
        |
Observations -> evidence -> deterministic checks -> human review -> retest
        |
Reports and optional bounded AI explanation
```

Implementation choices:

- Keep the current Node/TypeScript backend and lightweight browser frontend. Introduce a larger frontend framework only if interaction complexity justifies its maintenance cost.
- Extract a shared assessment service used by the dashboard and CLI. Scope, rate limits, state transitions and check outcomes must have one implementation.
- Make PostgreSQL the authoritative durable backend for the unified worker mode. Keep the no-database demo. Migrate existing dashboard JSON history through an explicit, idempotent import; do not create two permanent live job systems.
- Preserve easy local startup with a documented launcher and readiness checks. Evaluate a supported local database packaging path before bundling it; the existing development-only embedded database helper is not automatically a production runtime choice.
- Use server-sent events for one-way progress, with reconnect cursors and polling fallback. WebSockets are unnecessary unless a genuine two-way interaction appears.
- Version persisted records, API payloads, detector contracts and reports. Validate them at the boundaries.
- Keep raw browser rendering, model output, and external tool output outside authorization decisions.

A campaign records the exact approval revision, target set, check versions, request budgets and settings used. Later changes produce a new revision; they do not silently rewrite the historical assessment.

## 4. Phased delivery

### Phase 0 — Preserve and release the current baseline

**Priority:** P0. **Relative size:** small. **Dependency:** none.

Work:

- Review and commit the current local changes as coherent changesets; retain a reproducible base revision.
- Run the pipeline from a clean checkout, ensuring the replacement coverage module and static dashboard assets are included.
- Validate the supported Node version, the local Windows path and the Linux CI path.
- Document startup, port conflicts, data locations, dependency installation, shutdown and recovery.
- Add a release checklist that verifies migrations, static assets, test results and remaining limitations.
- Verify installation and startup without existing developer caches or an already running PostgreSQL instance.

**Exit gate:** a new checkout can install, build, open the dashboard and run the demo using documented commands; required CI checks pass; no known release-blocking defects remain.

### Phase 1 — Make the passive dashboard comfortable for daily use

**Priority:** P1. **Relative size:** medium. **Dependency:** Phase 0.

Work:

- Add named projects with saved, versioned scope profiles and optional owners/tags.
- Save assessment drafts. Support paste-and-review target entry with per-line errors, duplicate detection and visible canonicalization. Keep CSV import optional rather than the main workflow.
- Show a pre-run summary: exact hosts, permitted actions and paths, expiry, request budget and expected coverage. List exclusions beside the included targets.
- Improve progress states: queued, preparing, running, stopping, completed, completed with gaps, failed, cancelled and interrupted. Keep run completion separate from target success.
- Show elapsed time, current stage and last activity. Estimate remaining time only after enough timing data exists, and label it as an estimate.
- Add history search, pagination, archive and delete controls. Deletion requires a clear consequence preview; archive remains reversible.
- Make errors actionable: expired authorization, blocked address, DNS error, certificate rejection, timeout, storage failure or unavailable worker should each have a useful next step.
- For each check, show its purpose, evidence, execution time and why it passed, was skipped or was not applicable. Display planned, attempted and completed check counts separately.
- Add keyboard navigation, reliable focus return from dialogs, accessible contrast, descriptive status announcements and phone-width usability tests.
- Add a service-health panel: storage, worker, database when applicable, pending cleanup and request-enable state.

**Exit gate:** a user can save scope, create an assessment, understand a partial failure, locate an earlier run and inspect the relevant evidence without editing files or consulting the CLI. All main flows work by keyboard and at phone width.

### Phase 2 — Connect the interface to one durable campaign engine

**Priority:** P1. **Relative size:** large. **Dependency:** Phase 0; coordinate the UI contract with Phase 1.

Work:

- Introduce persisted project, approval, campaign and campaign-target records, linked to existing jobs, observations and findings.
- Route UI and CLI execution through the shared assessment service and the existing leased queue.
- Store per-check results with status, reason, detector version, evidence reference and start/finish timestamps.
- Add durable campaign events for progress, errors, cancellation and reviewer changes. Resume event delivery after reconnect without duplicating events.
- Use idempotency keys for assessment creation and job submission so retries or double clicks cannot launch duplicate work.
- Implement graceful cancellation that stops scheduling immediately, signals active work and records uncompleted checks honestly.
- Add structured retry categories and a dead-letter view; retry transient transport failures within budget, not expired scope or policy denials.
- Make restart behavior explicit. Revalidate scope before resuming any queued or interrupted work; do not automatically repeat uncertain writes.
- Import legacy dashboard JSON by original assessment ID. Validate the schema, preserve a backup, and make repeated imports harmless.
- Add shared concurrency and request reservations; start conservatively rather than raising throughput immediately.

**Exit gate:** UI and CLI show the same run, a restart preserves progress and evidence, duplicate submissions produce one assessment, and a stop request prevents further admitted target requests across the configured workers.

### Phase 3 — Make passive results more complete and more trustworthy

**Priority:** P1. **Relative size:** medium to large. **Dependency:** stable result contracts from Phase 2.

Work:

- Publish a detector contract: required input, applicability, permitted requests, output schema, evidence, limitations, version and fixtures.
- Review existing header checks by response type. An API response should not inherit every HTML-page expectation.
- Assess cookie attributes per cookie, including intentional differences between session cookies and script-readable application cookies.
- Add an explicitly scoped TLS/certificate inspection stage. Distinguish certificate trust/name/expiry signals from a full protocol/cipher audit.
- Treat redirects as observed navigation until controlled testing establishes an open redirect. Never follow a destination outside the approved host/path set.
- Add opt-in, policy-granted fixed-path checks for robots, sitemap and API descriptions; show their added request cost before running them.
- Deduplicate related observations across pages and responses without losing their original evidence or route context.
- Separate severity, confidence, exposure and verification status. Avoid a single unexplained numerical risk score.
- Review methodology mappings against pinned source versions. Show implemented subsets and unmapped checks; do not translate a few checks into a compliance claim.
- Broaden the negative fixture corpus: intentional external redirects, non-HTML content, error responses, partial captures, caching exceptions and browser-enforced CORS cases.

**Exit gate:** each enabled check has a documented evidence requirement, applicability rules, safe request contract and both positive and negative fixtures. Reports distinguish configuration observations from demonstrated impact.

### Phase 4 — Add finding review, useful reports and regression tracking

**Priority:** P1. **Relative size:** medium. **Dependency:** Phases 2–3.

Work:

- Add persistent triage decisions: needs review, accepted, rejected, duplicate, deferred and resolved, mapped to the existing finding state machine.
- Record who changed a finding, when, why and which evidence revision they reviewed. Keep analyst severity separate from detector-suggested severity.
- Add ownership, notes and due dates. Require reasons for dismissal, suppression or severity changes.
- Present redacted request/response metadata, timestamps, hashes, affected paths, detection rationale and specific remediation guidance.
- Add assessment comparison: new, recurring, changed, resolved and not retested. A failed or skipped retest must never mark a finding resolved.
- Generate an editable HTML report first, then a PDF export using the same report model. Retain machine-readable JSON and add CSV only as an optional export.
- Reports include reviewed scope, execution dates, versions, methodology subset, limitations, findings, evidence and remediation priorities.
- Allow bounded retests from a finding, using current approval and a matching detector/replay contract.

**Exit gate:** a reviewer can take a signal through an explained decision, create a shareable report, apply a fix and obtain a recorded retest outcome without manipulating database rows.

### Phase 5 — Establish operational controls before remote or active use

**Priority:** P0 for remote/team/active rollout; P1 for continued local work. **Relative size:** large. **Dependency:** Phase 2.

Work:

- Define the threat model and deployment boundaries for local operator, team server, isolated worker and hostile target content.
- Add real operator authentication before remote exposure. Define separate operator, reviewer, administrator and read-only permissions.
- Integrate authenticated policy approvals with approver identity, reviewed source hash, revision, expiry and explicit host/path/action grants.
- Add shared stop/revocation state with an epoch or equivalent fence. Check it immediately before each request; publish status to every worker.
- Independently constrain worker egress through host/container/proxy controls. Validate browser subresources, frames, workers, WebSockets, redirects and DNS changes against this boundary.
- Separate migration credentials from runtime database roles and verify effective privileges with integration tests.
- Centralize secret references, rotation and access logging. Never expose stored passwords through the frontend, reports or model context.
- Extend retention to imported/local reports, evidence blobs, export files and backups, with explicit holds and deletion audit records.
- Add structured metrics for queue age, rate limits, failed checks, worker heartbeat, pending cleanup, database/export failures and policy expiry.
- Exercise backup restoration, worker termination, database outage, browser crash, disk exhaustion and upgrade rollback.

**Exit gate:** authorization changes and stop requests are enforced across workers; independent egress tests pass; least-privilege access is demonstrated; restoration and interruption recovery are rehearsed. Remote access remains off until these checks pass.

### Phase 6 — Integrate discovery and API inventory

**Priority:** P2. **Relative size:** medium to large. **Dependency:** Phases 2, 3 and relevant Phase 5 controls.

Work:

- Connect approved discovery adapters to campaign stages with explicit source and request budgets.
- Persist each candidate's origin, timestamp, confidence, relationship to submitted roots and admission decision.
- Present a held-candidate inbox. A discovered host is never automatically treated as permission to assess it.
- Compare candidate history and flag additions, removals and policy changes.
- Integrate browser-observed routes and supplied OpenAPI inventories into a normalized route/method/role model.
- Reject unapproved remote references and cross-origin schema fetches. Distinguish a supplied API contract from an actually observed endpoint.
- Let users select and approve bounded coverage expansion before enqueueing extra jobs.

**Exit gate:** discovery adds reviewable candidates and inventory while making zero target requests to unapproved hosts, methods or paths, including names discovered through third-party infrastructure.

### Phase 7 — Add authenticated assessment as a separate capability

**Priority:** P2; deliberately deferred from the passive dashboard. **Relative size:** large. **Dependency:** Phases 2–5 plus owned-staging validation.

Work:

- Add a distinct authenticated-assessment setup flow with role labels, secret references, approved routes and session health checks.
- Require distinct canonical user identities for cross-account tests; support two ordinary users before introducing an explicitly supplied least-privilege administrator.
- Display incomplete authentication, MFA/CAPTCHA challenges and unsupported workflows as coverage gaps.
- Use isolated contexts and approved actor/resource/action matrices; distinguish reads from writes in both approval and budgets.
- Validate behavior against an independently controlled vulnerable/patched staging application and real test mailbox, not only the injected fixture transport.
- Implement dedicated cleanup/reconciliation jobs with durable ownership, idempotency, deadlines, retry classification and escalation. Avoid automatically closing obligations while creation could still finish later.
- Support application-specific confirmation contracts for asynchronous deletion. Preserve pending obligations when policy revocation prevents cleanup.
- Prefer supplied disposable accounts initially; add generated-account lifecycle management only after account creation, verification and retirement are proven.

**Exit gate:** cross-account results are reproducible against vulnerable staging and absent against patched staging; every created resource is either confirmed removed or represented by an actionable durable obligation; revoked authorization stops further testing.

### Phase 8 — Make AI assistance useful and measurable

**Priority:** P2/P3. **Relative size:** medium. **Dependency:** stable evidence and review workflow.

Work:

- Start with evidence-linked summaries, plain-language explanations, grouping of related signals and draft remediation text.
- Clearly label generated suggestions and require review before accepting them into a report.
- Treat page text, headers, documents and tool output as untrusted input. AI cannot grant scope, select arbitrary commands or declare a finding verified.
- Verify the actual installed model identity/digest and record model, prompt, schema and settings with each output.
- Build an evaluation set from reviewed cases: unsupported claims, grounding accuracy, secret leakage, useful grouping and reviewer time saved.
- Enforce context, time and concurrency budgets; handle model failure without repeating completed target requests.
- Keep local processing the initial path. Any external provider needs explicit configuration and a visible description of the data sent.

**Exit gate:** generated explanations cite available evidence, produce no unsupported verification claims in the release evaluation set, and demonstrate a measured improvement in reviewer effort. Preserve a complete non-AI workflow.

### Phase 9 — Scheduling, integrations and controlled expansion

**Priority:** P3. **Relative size:** medium to large. **Dependency:** Phases 2, 4 and 5.

Work:

- Add scheduled reassessments with approval-expiry checks, maintenance windows, shared budgets and visible pause controls.
- Notify on meaningful new findings, regressions, failed runs or required cleanup action, rather than every successful poll.
- Add reviewed issue-tracker export after report editing and identity controls are reliable. Prevent duplicate tickets and redact evidence before export.
- Introduce additional runtime tools one at a time with pinned binaries/templates, reviewed licenses, resource limits, output parsers and positive/negative fixtures.
- Add optional read-only owned-source/dependency analysis with separate input scope and secret handling.
- Treat cloud, infrastructure and cluster collection as separate modules requiring separate authorizations, roles and deployment validation.

**Exit gate:** scheduled work cannot outlive its authorization or bypass manual-run controls; each integration has a tested failure path and a measurable user benefit.

## 5. Data and API work needed

Core entities should include Project, Asset, ApprovalRevision, Campaign, CampaignTarget, CheckRun, Observation, Evidence, Finding, ReviewDecision, CleanupIntent, Retest and AuditEvent. Reuse existing tables where their semantics fit instead of duplicating them.

Required API capabilities:

- Project and reviewed-scope management with explicit revisions.
- Assessment preview, creation, listing, details and cancellation.
- Event stream with cursor-based reconnection.
- Per-target/per-check outcomes and evidence access.
- Finding review, comparison, suppression and retest requests.
- Report generation and download.
- Cleanup status, escalation and authorized reconciliation.
- Health, retention, archive and access-management endpoints appropriate to the deployment mode.

Mutation endpoints need validation, authorization, idempotency where applicable, audit records and stable error codes. Add pagination and response-size limits before increasing history or target caps. Preserve backwards-compatible report readers or provide explicit migrations.

## 6. Quality and measurement

| Measure | What to record | Release expectation |
| --- | --- | --- |
| Scope enforcement | Denied and admitted requests, approval revision | Zero requests to deliberately unapproved targets/actions in boundary tests |
| Coverage honesty | Planned, executed, failed, skipped and N/A checks | Every claimed pass has an execution record; every gap has a reason |
| Finding quality | Reviewed true/false positives by check and version | Establish a baseline before setting per-class precision targets; publish raw counts |
| Repeatability | Same evidence/configuration and replay outcomes | Stable deterministic results; flaky candidates remain unverified |
| Cleanup | Created, confirmed removed, pending and escalated resources | No resource creation without durable intent; no silent disappearance of obligations |
| Reliability | Duplicate jobs, restart recovery, queue age and export lag | Demonstrated crash recovery without duplicate unsafe work or lost findings |
| Operator experience | Setup time, time to useful report, review time | Measure on realistic tasks and improve against the baseline |
| Performance | Requests per assessment, memory, CPU, duration | Meet reviewed budgets; improve throughput only without weakening those limits |

Test layers should include pure detector tests, PostgreSQL integration, browser UI tests, transport fault injection, owned-staging vulnerable/patched cases and deployment-boundary tests. A release suite should cover empty input, partial results, cancellation, stale scope, clock/expiry boundaries, simultaneous users, duplicate submissions, malformed evidence and interrupted upgrades.

Do not use total test count, imported-tool count or model size as a product-success measure.

## 7. Initial implementation backlog

| Order | Deliverable | Definition of done |
| --- | --- | --- |
| 1 | Reproducible current release | Clean checkout installs, builds and opens the demo; required CI passes |
| 2 | Project/scope drafts | Saved scopes and drafts survive restart; targets have useful inline errors |
| 3 | Result/state contract | Partial success and per-check reasons are represented consistently in UI and storage |
| 4 | Shared campaign service | UI and CLI create and inspect the same persisted assessment |
| 5 | Event-driven progress | Reconnect shows correct progress without duplicate events |
| 6 | Stop/retry semantics | Cross-worker stop and bounded retries pass interruption tests |
| 7 | Finding review panel | Decisions, notes, owners and review history persist |
| 8 | Comparison and retest | New/recurring/resolved/not-retested states are correct on fixtures |
| 9 | HTML report | Export matches reviewed evidence and includes scope/coverage limitations |
| 10 | Owned-staging passive pilot | An independently controlled environment exercises actual DNS/TLS and failure behavior |

Each item should be delivered as a reviewable change with relevant tests and an operator-visible improvement. Phase 5's authentication and egress work becomes mandatory before team access or active tests, regardless of other backlog priorities.

## 8. Sequencing and effort

Use two-week planning cycles with working demonstrations at the end of each cycle. Sizes above indicate relative complexity, not fixed delivery promises. The availability of owned staging, test accounts, deployment infrastructure and independent review will substantially affect timing.

Suggested first six cycles, assuming one experienced implementer and timely product feedback:

1. Baseline release, setup improvements, UI errors and draft/scope design.
2. Projects, persisted campaign contract and legacy-history import.
3. Shared queue execution, progress events, cancellation and recovery.
4. Check applicability, evidence views and finding triage.
5. Comparison, retest, editable HTML reports and owned-staging passive validation.
6. Reliability hardening, operational metrics, retention/restore drills and pilot feedback.

This is a planning hypothesis for a stronger passive product, not a promise that production operations or authenticated testing will be complete in twelve weeks. Re-estimate after the shared-engine work. Schedule Phases 6–9 only when their prerequisites are demonstrated and their value is supported by operator feedback.

## 9. Decisions to make before expanding the pilot

- Is the next release for one local operator, a small internal team, or a hosted product? Default to one local operator until requirements change.
- Which owned staging application and mailbox will validate real transport, identity and cleanup behavior?
- Who owns scope approval and finding acceptance in team mode?
- How long should each evidence/report class be kept, and what must be held for review?
- Which two or three finding categories would save the most reviewer time? Use those to choose detector expansion.
- Which report audience matters first: developers fixing issues, managers prioritizing work, or external submission reviewers?

None of these decisions prevents the baseline, UI and shared-engine work from starting. They constrain later deployment and capability expansion.

## 10. Release milestones

**Milestone A — Dependable local passive workspace:** clear target entry, saved scope, truthful progress, usable history, actionable findings and reproducible setup.

**Milestone B — Durable assessment and review system:** one engine for UI/CLI, restart recovery, evidence-backed triage, comparison, reports and retests.

**Milestone C — Controlled operational pilot:** authenticated approvals where needed, shared revocation, independent egress, owned-staging proof, access controls and restore drills.

**Milestone D — Broader authorized assessment:** reviewed discovery, authenticated role checks, selected runtime integrations and evaluated AI assistance.

The next implementation priority is Milestone A moving into the shared-engine portion of Milestone B. Avoid expanding active testing or tool breadth before the workflow produces dependable, reviewable results.
