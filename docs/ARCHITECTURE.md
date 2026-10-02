# Architecture

## Execution flow

```text
Fixture or reviewed JSON manifests
             |
Strict program/policy validation -> PostgreSQL assets and versioned jobs
             |
Global lease/concurrency gate -> current scope, action and exact-path authorization
             |
Synthetic fixture OR explicitly enabled DNS-pinned HTTPS GET
             |
Atomic observation + evidence metadata + posture signals + allowed follow-ups + audit
             |
Bounded feature projection -> fixture/Ollama classification -> accepted hypotheses
             |
Outbox sweep -> Markdown workspace and operator review
```

## Authorization and collection

The gateway resolves identifiers from the database and validates the job action, active lease, current asset/policy revision, expiry, exclusions and exact path. Asset inputs must be canonical HTTPS origins. Scope supports exact/wildcard DNS names, HTTPS port 443 and explicit paths; wildcard rules exclude their apex. Query strings, credentials, IP literals, IDNs and ambiguous path normalization are rejected.

Fixture operation is the default. The optional passive executor requires `ENABLE_PASSIVE_HTTP=true`, `GLOBAL_KILL_SWITCH=false` and a reviewed policy for every target/action/path. It resolves DNS once, rejects prohibited address classes, then rechecks authorization and reserves the request rate immediately before connecting to the selected address. TLS verifies the original hostname via SNI, certificates are required to validate, and redirects are recorded without being followed. Each GET has a total 10-second budget including DNS/gateway waits, a 16 KiB header cap and a configurable captured-body cap (64 KiB default). Oversized downloads are terminated. Headers exclude cookie values; redirect query/fragment data is removed. Response snippets can still contain sensitive application data and need operator-controlled storage.

There is no general crawler, shell, authenticated MCP transport or active attack executor. Upstream source dependencies do not register themselves as tools. The existing CSV posture interface is separate from the worker and retains its own documented controls.

## Scheduling and durability

The worker loads its manifest at startup, seeds root jobs for every asset and processes bounded concurrent batches. `--once` processes one batch; continuous mode drains follow-ups and retries and sweeps pending exports. Reloading a manifest requires restart. A new policy revision or target identity creates a new dedupe key; completed work is not periodically rescanned. The original fixture key remains stable across upgrades.

Claim serializes the fleet concurrency count with a PostgreSQL advisory lock and selects jobs with `FOR UPDATE SKIP LOCKED`. The concurrency setting must match across workers. Lease tokens fence stale owners; heartbeat failure aborts an in-flight request. SIGINT/SIGTERM stop new claims and abort collection. A force-killed worker leaves reclaimable work. Execution is at least once; persistence is deduplicated. Requests that reached a server before a crash can repeat.

Completion atomically records observations, tool runs, prefix-hash metadata, deterministic signals in OBSERVATION state, audit events, authorized fixed-path follow-up jobs and export intent. Follow-up admission requires both current action and path authorization. Stale policy/asset state is checked again before completion. Analysis occurs after commit and cannot trigger a tool retry.

## State and export

Ordered migrations create schema and constraints; `003_execution_depth.sql` extends actions and adds audit events. Application writes to the audit table are insert-only; it is not yet tamper-proof or protected by a dedicated database role. Hashes describe captured bytes, which may be truncated. Only bounded snippets and metadata are retained, not a complete replay archive.

The exporter serializes per-program writes, writes temporary siblings and renames them, then acknowledges only the outbox revision read. A crash may leave a mixed file set; another sweep reconciles it. `PROGRAM.md`, `SCOPE.md`, `ASSETS.md`, `RECON.md`, `FINDINGS.md`, `HYPOTHESES.md`, `AUDIT.md` and `HISTORY.md` are projections. `NOTES.md` remains operator-owned. Export directories must be trusted.

## Model and findings boundaries

Models receive valid bounded feature JSON, produce a strict classification and quote only observed evidence. Raw responses and accepted hypotheses remain separate from tool data. See [the model contract](DETERMINISTIC_MODEL.md). Deterministic posture signals are observations, not confirmed vulnerabilities. Finding verification/submission requires future authenticated review and transition services.

## Operational limits

The current runner is a development implementation, not a hardened 24/7 service. Environment switches are process-local; immediate fleet-wide revocation, independent egress enforcement, authenticated approvals, retention, periodic rescans, durable analysis recovery, backup/restore tests, metrics and dashboard work remain on [the readiness list](READINESS.md). PostgreSQL leases avoid adding an orchestration service now; revisit a workflow engine when cancellation graphs and durable human-review waits justify it.
