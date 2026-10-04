# Fixture and validation map

All entries below concern synthetic/owned fixture behavior, not bounty effectiveness.

| Area | Inputs / checks | What this establishes |
| --- | --- | --- |
| Program/queue | `fixtures/program.ts`, `tests/integration/state.test.ts` | Leases, scope gates, rate limits and replay |
| Owned browser lab | `fixtures/research-lab.ts`, `tests/browser/research.test.ts` | Controlled login/ownership/cleanup flows |
| Passive assessment | `tests/dashboard.test.ts`, `tests/campaign-service.test.ts` | Scope, drafts, state, migration, idempotency and stop |
| Dashboard browser | `tests/browser/dashboard.test.ts` | Actual form, project, draft, report preview/download and phone layout |
| Passive transport | `tests/web-executor.test.ts` | Bounded capture, private-address denial, cancellation and scope checks |
| Report exports | `tests/reporting.test.ts` | Profiles/formats, provenance, redaction, escaping, readiness and API protection |
| Repository | `tests/campaign-repository.test.ts` | Validated snapshots and lifecycle persistence through the storage boundary |
| Campaign schema | `tests/integration/campaign-foundation.test.ts` | Immutable policies, scoped uniqueness, composite boundaries and event constraints |
| Retention | `tests/integration/retention.test.ts` | Managed payload purge, holds, cleanup persistence and late-write gates |
| Detector pairs | `npm run gate` | Five existing vulnerable/patched fixture pairs only |

The B19 independent held-out research corpus has not been built. Do not report these development fixtures as that benchmark. Source-only dependency pins are verified by `deps:check`; they are not running scanner integrations.
