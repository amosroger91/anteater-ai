# Execution improvement plan and outcome

The review identified six concrete bottlenecks: fixture-only intake, unused concurrency capacity, no deterministic follow-up work, unused evidence/findings tables, model input truncation that could break JSON, and stale documentation.

| Improvement | Implemented behavior | Evidence |
| --- | --- | --- |
| Multiple reviewed programs | Size-bounded manifest provider, schema and scope validation | Manifest collision, scope and input-size tests |
| Useful collection | Opt-in pinned HTTPS GET and four fixed read-only actions | TLS options, byte caps, deadlines, redirect and blocked-address tests |
| Crash-safe next steps | Completion and policy-authorized follow-ups share a transaction | PostgreSQL follow-up, revision and duplicate-completion tests |
| Effective concurrency | Bounded batches across programs with fleet lease cap | Parallel PostgreSQL claims and graceful cancellation paths |
| Reviewable evidence | Capture hashes, observation signals, audit and hypothesis exports | Persistence/export tests |
| Reliable small-model inputs | Valid bounded feature JSON, strict schema and original-input grounding | Oversized-input and repair-metadata tests |

Follow-ups inspect only fixed paths allowed by current policy; models cannot choose targets. Existing completed fixture work retains its original dedupe key. The runner does not periodically revisit completed targets or reload manifests while running; restart with a new reviewed revision to research changed scope.

No throughput or finding-yield multiplier is claimed. To measure effectiveness next, use an owned test corpus and compare completed jobs/hour under the same request budget, retained true-positive signals, duplicate requests, queued follow-ups lost after crashes, model acceptance/repair rate and operator triage time. Unfinished production capabilities are tracked in [READINESS.md](READINESS.md).
