# Readiness and remaining work

## Implemented and tested locally

- [x] Default kill switch, strict configuration, mandatory reviewed policy and scope.
- [x] Exact/wildcard hosts, exclusion precedence, expiry, exact-path allowlists and rejected ambiguous target forms.
- [x] Fixture provider plus bounded reviewed JSON manifests with identifier/scope validation.
- [x] Typed gateway actions: root, robots, sitemap and fixed OpenAPI path.
- [x] Separately enabled passive HTTPS executor: one pinned address, certificate validation, no redirects, total deadline, byte/header caps and cancellation.
- [x] PostgreSQL leases, fencing, retries, policy revisions, heartbeat and shared rate reservations.
- [x] Concurrent worker batches, signal handling and persistent outbox sweep.
- [x] Atomic observation persistence, hash metadata, observation-level findings, audit events and policy-filtered follow-ups.
- [x] Valid bounded model features, schema-constrained classification, grounded evidence and one repair attempt.
- [x] Replayable Markdown exports including hypotheses and audit events.
- [x] 29 pinned source dependencies and configured update PRs.

## Before production operation

- [ ] Source ingestion with terms/access review, authenticated policy approvals and source hashes.
- [ ] Public-suffix rules, broader path/port/IDN semantics and independently reviewed address/egress controls.
- [ ] Authenticated MCP transport, executor isolation and sandbox lifecycle.
- [ ] Immediate fleet-wide kill/revocation propagation; environment switches are process-local.
- [ ] Manifest hot reload, periodic revisit scheduling, retry jitter and dead-letter operator controls.
- [ ] Durable analysis recovery after a crash between observation completion and model persistence.
- [ ] Least-privilege audit roles, tamper resistance, evidence retention/redaction policy and full replay artifacts where needed.
- [ ] Finding transitions and identity-backed human verification/submission.
- [ ] Verify installed model digest, adversarial evaluation corpus, local benchmarks and fleet model concurrency limits.
- [ ] Production backup/restore and crash/reboot testing, monitoring, health checks and operator UI.
- [ ] Review upstream licenses and test each packaged runtime adapter.
- [ ] Independent live adapter/isolation QA on an owned test environment.

The fixture remains the default. `ENABLE_PASSIVE_HTTP=true` enables only the bounded read-only worker adapter after policy authorization. `ALLOW_ACTIVE_TESTING` does not enable that adapter or grant additional tools. No live research target was contacted during local verification. A 10x effectiveness improvement has not been measured; throughput is still constrained by reviewed request rates.
