# Before real authorized research

- [x] Strict configuration with default kill switch and mandatory policy/scope.
- [x] Exact/wildcard scope and exclusion precedence, expiry and malformed-input tests.
- [x] Fixture-only typed tool gate; arbitrary commands and unknown assets rejected.
- [x] PostgreSQL leases, fencing, deduplication, bounded retries, policy revisions and rate reservations.
- [x] Versioned database migrations with analysis provenance and human-verification constraints.
- [x] Schema-constrained, grounded model analysis with deterministic sampling and failed-run recording.
- [x] Policy-bound passive posture checks, same-port redirect checks and fixed aggressive scanner controls.
- [x] Database-backed program state and replayable Markdown export.
- [x] Pinned web-focused upstream source catalog with daily Dependabot update configuration.
- [ ] Review licenses and package tested releases for each selected runtime adapter; importing source does not approve execution.
- [ ] Real source adapter with policy provenance, terms/access review and policy-change handling.
- [ ] Operator-reviewed policy compiler, source hashes and authenticated approval records.
- [ ] Complete scope semantics: public suffixes, paths, ports, IDNs and explicit exclusions.
- [ ] DNS/IP authorization for the live executor, rebinding defenses and per-hop certificate validation.
- [ ] Authenticated MCP transport, bounded structured tools, sandbox lifecycle and egress proxy.
- [ ] Independent executor authorization and immediate kill-switch/revocation/cancellation propagation.
- [ ] Distributed per-request rate enforcement inside multi-request tools.
- [ ] Scheduler, automatic lease renewal, graceful shutdown, retry jitter and dead-letter operations.
- [ ] Durable append-only audit events, evidence hashing/redaction/retention, authenticated human review.
- [ ] Findings transition service; no automatic report submission.
- [ ] Model registry loader, provider health checks, adversarial tool-output tests and local benchmarks.
- [ ] Crash/reboot and backup/restore tests, persistent outbox sweeper, metrics and operator dashboard.
- [ ] Independent isolation, authorization and adversarial QA before enabling any live executor.

Setting `ALLOW_ACTIVE_TESTING=true` cannot bypass this checklist: no live executor is implemented.
