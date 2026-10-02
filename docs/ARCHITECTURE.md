# Architecture — initial milestone

## Implemented boundary

The first task is a fixture-only vertical slice. PostgreSQL is authoritative for normalized program metadata, reviewed versioned policies, assets, jobs, observations and export work. Agents receive bounded structured input. The model can produce analysis text; it cannot rewrite policy, call arbitrary tools or submit reports.

Discovery is an interface and a local fixture implementation. Classification is supplied by the fixture; real classification and policy ingestion are milestone 2. A production policy compiler must require explicit operator review and record the source document hash before accepting machine rules. A discovered hostname alone grants no permission.

## Authorization

Every gateway invocation resolves the asset identifier and current policy from the database and verifies the active job lease. It checks the kill switch, strict schema, policy expiry, action allowlist, exact or wildcard host scope and exclusions. Unsupported target forms fail closed. The only implementation returns constant synthetic data for `fixture-api`; it performs no network I/O.

HTTPS port 443 and whole origins are the only supported scope forms. This intentionally rejects legitimate path-scoped programs until that semantics is implemented. DNS answers, redirect destinations, public suffix validation, policy revocation during a network request and connection-time IP pinning are not implemented. No live backend exists to bypass these omissions.

## Durable jobs

Enqueue uses a unique deduplication key. Claim serializes a global concurrency decision with a PostgreSQL advisory transaction lock and selects work with `FOR UPDATE SKIP LOCKED`. A lease token fences stale workers. Expired jobs are reclaimable up to three attempts; exhausted leases become failed. Completion validates the token and atomically records the result, observation, tool run and export intent. Failures use bounded delayed retries.

This is at-least-once execution with deduplicated persistence, not exactly-once external side effects. Long-running tasks need heartbeat renewal, cancellation, resource budgets and an idempotent executor before release. The current demo is a single bounded iteration, not a scheduler service. The configured concurrency ceiling must be uniform across processes. Rate reservations use database time and a separate lock to apply both global and program limits atomically; blocked callers must retry later.

## Markdown persistence

Program files have schema/revision headers and JSON blocks under fixed Markdown headings. The database transaction queues an export revision. The exporter serializes per-program writers, writes each generated file to a temporary sibling then renames it, and acknowledges only the revision it read. A failed export remains pending and can be replayed. A crash between renames may leave a mixed revision set; rerunning reconciles it. This is eventual consistency, not a multi-file filesystem transaction.

`PROGRAM.md` holds metadata; `SCOPE.md` holds policy; `ASSETS.md` holds asset IDs and URLs; `RECON.md` holds observations; `FINDINGS.md` holds findings and states; `HISTORY.md` holds job status/attempts. `NOTES.md` belongs to the operator and is never overwritten. Exports remain readable with PostgreSQL offline. Export roots must be trusted, operator-owned directories; filesystem adversaries and arbitrary symlink parent trees are outside the MVP threat model.

## Workflow framework decision

Temporal was evaluated first: durable workflows and activity recovery suit future multi-stage research and long human-review waits. For one short bounded fixture task, another service and worker SDK add operational cost without simplifying the current slice. PostgreSQL leases keep the MVP small. Revisit Temporal when the graph includes cancellation trees, versioned multi-step workflows and durable human signals. Redis is likewise deferred; PostgreSQL already owns locks, jobs and rate reservations.

## Web-development dependency layer

The project prioritizes web application source review, API contracts, browser behavior, HTTP/TLS configuration, password-form policy and authorized web testing. The source-only dependency catalog tracks 29 upstream repositories using Git submodules. Dependabot proposes daily revision updates; reviewed gitlinks keep the source reproducible. Sparse import avoids entire password corpora and unrelated bulk data. No dependency is automatically registered as an agent tool. Offline source analysis and fixture adapters are the next integration step; every eventual network adapter must enforce scope and program policy independently.

## Planned roles

Program, recon, web, API, analysis, verification, documentation and scheduler roles are represented in the model registry type. Only observation analysis runs in this slice. Future roles communicate through typed persisted tasks, never an unbounded shared conversation. Each role gets a restricted tool set and a token/time budget. No host shell is exposed.

## Findings and operations

The schema reserves observations, hypotheses, findings, evidence, tool runs and agent runs. No finding promotion or submission API exists. A database constraint requires a reviewer for SUBMITTED, but production also needs identity-backed approval and audit trails. JSON events report bounded lifecycle metadata without raw prompts or response bodies. Backups, metrics, reconciliation daemon, scheduler health checks and 24/7 operation remain future work.
