# Validation history

## Automated bounty-report drafts and campaign foundation — 2026-10-04

- `npm run build` and `npm run test:dashboard-build` passed. The compiled dashboard smoke test confirmed copied assets, migrations, local session behavior and the synthetic demo.
- **152 unit tests passed** serially. New report coverage checks all three profiles and four export formats, completed-run and observation selection, source/evidence hashes, demo labeling, text/HTML injection handling, best-effort redaction, local revision persistence, source binding and stale-revision conflicts. Repository snapshot validation/restart recovery tests also passed.
- **10 Chromium end-to-end tests passed** serially: two dashboard/report workflows and eight isolated application-research browser flows covering account identity, interruption, cleanup, signup/email verification, and vulnerable-versus-patched replay. Screenshot artifacts in `docs/screenshots/` were captured from the dashboard tests using synthetic data only.
- **20 temporary PostgreSQL integration tests passed**, followed by idempotent fixture replay. Migration 007 and its project/policy/campaign/job relationship constraints passed. Jobs attached to a campaign are deliberately excluded from legacy worker claims until campaign-aware authorization and stop handling are integrated.
- Validation used Windows / Node 24.13.0 and synthetic fixtures. No real assessment target, external report platform or remote Linux CI was used. Report output stays a draft: the operator must establish current eligibility, independently reproduce, demonstrate impact and review/redact evidence. The local report revision store is not a multi-process/PostgreSQL persistence contract.

## Saved scopes and shared local service — 2026-10-03

- Build and **145 unit tests passed**. New coverage includes canonical scope/exclusions, line errors, project revision conflicts, incomplete draft recovery, immutable run snapshots, duplicate submissions across restart, migration backups, invalid schema rejection, completion states, SSE reconnect, CLI reuse and storage failure.
- **10 Chromium browser tests passed**, including saved projects/drafts, preview invalidation, exclusions, reversible archive, history search and mobile layout. Desktop and 390px screenshots inspected.
- **15 reported PostgreSQL integration tests passed**, followed by idempotent fixture replay; detector gate **5/5**, zero fixture false positives.
- `npm run test:dashboard-build` passed against compiled JavaScript, copied static assets and migrations, with the synthetic demo and live requests disabled. CI now includes this smoke check.
- Fresh local clone with a separate, initially empty npm cache: `npm ci`, build and compiled-dashboard smoke test passed. No pre-existing PostgreSQL or frontend build was needed.
- Legacy mixed-success reports are normalized to `completed with gaps` on load, with original unversioned report backups retained; targeted migration/service tests passed after this correction.
- Local Windows / Node 24.13.0 validation. Remote Linux / Node 22 CI has not been run for these changes. No real assessment targets were contacted.
- The new `assessment` CLI uses the same local dashboard API. The PostgreSQL worker queue, shared revocation and durable event log are not yet connected to that service.

## Dashboard and review hardening — 2026-10-02

- TypeScript build and **137 unit tests passed**.
- **9 Chromium browser tests passed**, including duplicate-principal rejection, alias-to-principal checks, interruption/reconciliation, asynchronous cleanup, dashboard scope entry, demo, report download, reload, safe text rendering and phone-width layout.
- **15 reported PostgreSQL integration tests passed**, followed by idempotent fixture worker/demo replay. Added a populated-data retention test covering foreign-key relationships, evidence holds, durable cleanup, late analysis writes and regenerated exports.
- Detector gate: **5/5 fixture pairs**, zero fixture false positives. This measures only the small synthetic corpus, not real-world effectiveness.
- All **29 source dependency pins verified**. No upstream tool execution.
- Dashboard screenshots inspected at desktop and 390px phone width. It runs locally at `http://127.0.0.1:4317`, with live requests disabled and a clearly labeled synthetic demo.
- Node 24.13.0 on Windows; native temporary PostgreSQL. CI remains configured for Node 22 and PostgreSQL 17 with browser checks added. Remote CI has not been run for these local edits.
- No real research target, login, external mailbox or model inference was used. Independent egress and owned-staging validation remain required.

The initial clone at `1bb53b4` failed to build because the documented coverage package was absent and ignored. Earlier passing counts below are historical claims; the counts above describe the current verified local implementation. See [DASHBOARD.md](DASHBOARD.md) for use and [REVIEW_HARDENING.md](REVIEW_HARDENING.md) for limitations.

## Initial milestone validation — 2026-10-02

- `npm run check`: TypeScript build and 59 unit tests passed.
- `npm run verify:local`: 9 reported integration tests (including the parent test) passed against native PostgreSQL 17; fixture demonstration and deduplicated replay passed.
- Verified lease fencing, expiry recovery, bounded retries, policy-revision invalidation, concurrent claims, rate reservation, invocation-time scope changes, kill switch, rejected arbitrary tools, tool-only observations, structured model grounding, Markdown export and operator-note preservation.
- `docker compose config --quiet`: passed.
- `npm install`: dependency audit reported zero known vulnerabilities at installation time.
- No requests were made to research targets. All observed responses are synthetic fixture data.

Docker Desktop failed during local Secrets Engine startup with a socket-access error. PostgreSQL container runtime and the inert Kali image could not be exercised locally. Temporary native PostgreSQL was used for real database integration tests instead; its process was stopped afterward. GitHub CI is configured to repeat the checks against PostgreSQL in a service container.

Ollama inference and real MCP execution were not exercised. The demo and continuous worker use the deterministic model fixture; the Ollama adapter is covered with a stubbed transport. Live MCP and target execution are intentionally not implemented. See READINESS.md for the release gate.

## Web dependency library — 2026-10-02

- Registered and downloaded sparse source/data checkouts for all 29 Git submodules at their pinned commits.
- Verified every selected source directory and wordlist file exists. Corrected an outdated SecLists filename during this check.
- TypeScript build and 39 unit tests passed; the dependency registry check validates all 29 paths, origins, branches and commit pins.
- A dirty-checkout probe was rejected without losing the local test file; a clean repeat sync succeeded at the same pin.
- GitHub PR CI passed unit tests, registry validation, PostgreSQL integration tests and the fixture demonstration.
- No upstream installer, security script, browser, password attack or research target was executed during import. Runtime adapter validation remains separate work.

## Execution-depth validation — 2026-10-02

- `npm run check`: TypeScript build and 71 unit tests passed.
- `npm run verify:local`: 14 reported PostgreSQL tests passed, then worker/demo fixture replay retained exactly one completed job and observation.
- `npm run deps:check`: all 29 pinned source-only dependencies verified.
- New tests exercise capped downloads (including socket destruction), total DNS/response deadlines, private address rejection, DNS-to-connect authorization order, strict TLS options, redirect non-following and query redaction, cancelled/revoked requests, manifest limits/scope/collisions, action/path admission, valid bounded model JSON and repair-metadata rejection.
- Database tests exercise atomic evidence/audit/follow-up persistence, duplicate-completion fencing, policy-revision invalidation and new work, asset-URL lease retirement, passive-adapter opt-in and three concurrent leases across competing claimers.
- Transport tests use injected synthetic streams. No live research target, remote model or upstream security tool was executed. An actual owned HTTPS endpoint and real Ollama inference still need separate validation.
- No 10x throughput or finding-yield claim has been measured. Request-rate limits remain authoritative.

The earlier fixture-only descriptions above describe the earlier milestone. The opt-in passive collector is now implemented; production limitations remain in READINESS.md.

## Current working-tree update — 2026-10-02

- After the marker-based cleanup change, `npm run check` passed the TypeScript build and 127 unit tests.
- Before that change, 3 Chromium browser tests passed against the injected synthetic application transport; 14 PostgreSQL integration tests, fixture replay, and the 29-pin dependency check also passed.
- The browser suite was not rerun after the cleanup change at the operator's direction. A regression test for a successful create response with a missing resource ID was added; it remains unverified.
- No live target, real login, or external mailbox was tested. No claim about production egress isolation or live cleanup is supported by these fixtures.
