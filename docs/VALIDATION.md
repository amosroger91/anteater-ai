# Initial milestone validation — 2026-10-02

## Review fixes and company importer — 2026-10-06

TypeScript `tsc --noEmit` is the allowed static check for this change. No unit/integration/browser tests, fixture runs, model inference, platform API calls using credentials, or research scans were run in this session, per the user's instruction. Added regression sources cover company pagination and confirmation, excluded selections, cleanup request reservation/deadline/owner behavior, accepted negative controls, and asset identity. Earlier results below describe earlier commits and are not a pass for the current changes.

The October 5 execution/setup/model work was preserved from the intervening commits. The remaining asset-planner wiring and application cleanup-recovery hooks were completed here alongside the scanner importer. Runtime recovery and real API behavior still need independent validation when tests are authorized.

## Initial milestone record

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

- After the marker-based cleanup change, `npm run check` passed the TypeScript build and 127 unit tests. The browser suite was not part of that run.
- The later production-gate edit passed `tsc --noEmit`. `tsx --test tests/*.test.ts` passed 129 tests and failed `tests/dependencies.test.ts` because git rejected the UNC checkout as dubious ownership. The same file passed 6 tests when that process set `safe.directory` and did not change git config.
- `tsx --test tests/browser/*.test.ts` passed 4 Chromium tests against the injected lab, including cleanup when create returns no resource id. `npm run verify:local` passed 15 PostgreSQL tests on a temporary loopback server, including the finding-actor guard, database kill switch, and dead-letter row, then stopped that server. Fixture replay still stored one completed job and one observation.
- No live target, real login, external mailbox, or live Ollama process was tested. No claim about production egress isolation is supported by these fixtures.
