# Readiness and remaining work

Anteater is a locally validated prototype. Its default kill switch remains on, and passive collection and application research are separately opt-in. Passing fixture tests establishes expected behavior in the test harness; it does not establish safety, coverage, or finding quality on a live service.

## Implemented and locally validated

- Strict configuration, reviewed host/action/path policy, exclusions, expiry, DNS-pinned HTTPS collection, request/response bounds, cancellation, and invocation-time scope checks.
- PostgreSQL jobs with leases, fencing, recovery, retries, rate reservations, atomic observations, and workspace exports.
- Domain-list intake for submitted roots and a `research` worker path gated by both policy and `ENABLE_APPLICATION_RESEARCH`.
- Playwright exploration with same-origin routing, isolated contexts, challenge reporting, up to two configured test accounts, optional encrypted generated accounts, and an IMAP adapter.
- Configured owner-resource access replay with owner/cross-account/repeat/negative controls. Every resource probe now requires a marker-based cleanup path and attempts deletion after every create attempt.
- Candidate discovery/admission libraries, Subfinder/CT/passive-DNS/Gitleaks adapters, methodology registry, web/API checks, finding/retest helpers, offline infrastructure analyzers, evidence utilities, and operations decision logic.
- 29 commit-pinned upstream source/data dependencies. Imported repositories are not executed just because they are pinned.

The review-hardening implementation adds the local passive dashboard, explicit coverage execution records, canonical-principal verification, durable cleanup intents, coordinated retention, and browser CI. See [VALIDATION.md](VALIDATION.md) and [REVIEW_HARDENING.md](REVIEW_HARDENING.md) for current verification and boundaries.

## Required before production operation

- [ ] Add authenticated policy approvals and verify approver, source hash, revision, and expiry in the live campaign loader. The current `reviewed: true` profile field is operator input, not proof of approval.
- [ ] Connect discovery adapters to the worker and persist candidate history. Keep discovered names held until the exact host and action pass the current policy.
- [ ] Enforce outbound restrictions outside Playwright routing. Independently test DNS rebinding, redirects, subresources, frames, workers, WebSockets, and browser escape paths in an isolated environment.
- [ ] Run against an owned vulnerable/patched staging app and real test mailbox; prove identity, isolation, marker cleanup, cleanup after timeout/crash, and safe behavior under mailbox and network failures.
- [ ] Add role-aware secrets and support at least two ordinary users plus an explicitly supplied least-privilege administrator. The current browser profile supports at most two accounts and does not label roles.
- [ ] Connect browser/API inventory, budgets, approved tool adapters, and methodology checks into one persistent campaign. The current worker processes submitted roots only; most detector packages are not live worker stages.
- [ ] Expand the explicit WSTG 4.2 subset, review licenses and source revisions, and add separately verified ASVS mappings; show every gap.
- [ ] Integrate complete finding states, encrypted/redacted evidence lifecycle, human reviewer identity, impact ranking, report editing, and retest jobs.
- [ ] Wire fleet-wide kill/revocation, operational metrics/alerts, dead-letter controls, least-privilege DB roles, retention jobs, backup/restore, and crash/reboot drills.
- [ ] Verify real model weights and inference if enabled; establish a task-specific evaluation set and bounded fleet concurrency.
- [ ] Review licenses and independently assess authorization, egress, sandboxing, secrets, data retention, and operational access.

The project has not measured a 10x improvement in throughput or finding yield. Its safe request budgets intentionally constrain speed. Read [PRODUCTION_ROADMAP.md](PRODUCTION_ROADMAP.md) for the ordered completion plan and [VALIDATION.md](VALIDATION.md) for test boundaries.
