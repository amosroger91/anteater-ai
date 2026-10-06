# Production roadmap

Anteater is a scope-first framework for repeatable web and API security checks. Its goal is to automate bounded, evidence-backed work so people can focus on business impact, novel attack paths, and remediation decisions. It must report coverage honestly; it cannot promise to find every vulnerability.

## Current state

The current working tree includes a domain-list worker, a reviewed per-campaign policy profile, a PostgreSQL job queue, a bounded passive HTTP worker, a persistent discovery monitor, and an opt-in Playwright application-research path. The browser path can explore same-origin pages, attempt up to three configured accounts with role and tenant labels, optionally create encrypted test accounts and verify them through IMAP, and replay a configured owner-only resource read across accounts. It requires `ENABLE_APPLICATION_RESEARCH=true`; non-read requests additionally require `ALLOW_ACTIVE_TESTING=true` and explicit paths in the application profile.

This is a prototype, not a production service. Browser fixtures use Chromium with an injected transport and a fake application/mailbox; earlier staging-loop checks use an owned local app through injected transport. These do not establish real egress isolation or mailbox behavior. The monitor can enqueue newly discovered, admitted hosts, and the ordinary worker runs explicitly authorized source-file checks. Scheduled revisits, broad authenticated methodology coverage, and a complete unattended discovery-to-report/retest workflow remain unfinished. Most additional detectors and infrastructure analyzers are libraries rather than live worker stages.

No tests were run for the October 5 review fixes, by explicit user instruction. Existing test counts are historical evidence for earlier commits. See [VALIDATION.md](VALIDATION.md) for recorded validation boundaries and [READINESS.md](READINESS.md) for production gates.

## Capability status

### 1. Input, authorization, and campaign flow

- [x] Parse and normalize a domain list and reject ambiguous entries.
- [x] Require a reviewed policy profile with source URL, expiry, revision, exact allowed hosts/actions, and request rate before enqueuing each submitted root.
- [x] Recheck scope and policy revision at job execution; retain a default-off kill switch.
- [~] Enforce approval source hash, revision, expiry, and a named approver in campaign intake. Authentication of that human identity remains open.
- [ ] Connect discovery, methodology checks, evidence, reporting, and scheduled revisits into one persistent campaign workflow. `apps/orchestrator/campaign.ts` is a fixture composition, not the live worker pipeline.

### 2. Authorized asset discovery

- [x] Candidate model, normalization, provenance, deduplication, scope admission, and candidate-to-job creation are implemented and fixture-tested.
- [x] Passive certificate-transparency, injected passive-DNS, Subfinder, and Gitleaks adapters exist. Subfinder/Gitleaks require an explicitly configured absolute binary and injected runner; Gitleaks returns redacted findings and never uses secrets.
- [x] Persist candidate snapshots and enqueue newly observed admitted hosts through the monitor. Candidates remain inactive until the exact host and action are admitted by current policy. Generated asset identities include the program and full-host hash; existing origins retain their database IDs.
- [ ] Add change handling, per-source budgets/retention, and egress controls for every live lookup and discovered host.

### 3. Authenticated and multi-role assessment

- [x] Isolated browser contexts, form inventory, same-origin navigation, bounded request/response sizes, and a DNS-pinned HTTPS transport are implemented.
- [x] Up to three operator-supplied accounts carry explicit user/admin roles and tenant labels. Local setup/environment secrets are resolved explicitly for research. Optional generated accounts are encrypted at rest; an IMAP verifier is available. MFA/CAPTCHA-style challenges are reported instead of bypassed.
- [x] A profile can define an owner-only resource: the worker creates a marked test object, checks owner access, cross-account access, a repeat, a missing-object control, and owner access again, then deletes the object through its owner-bound marker cleanup path.
- [~] Role labels and a supplied administrator exist. Finish a maintained secret service, session renewal/health checks, stronger signup lifecycle management, and worker-isolated secret access.
- [ ] Exercise login, signup, IMAP, session identity, and marker cleanup against an independently controlled vulnerable/patched staging app. The local fake transport does not validate real egress or real mailbox behavior.
- [ ] Extend beyond configured owner-resource probes to discovered actor/resource/action matrices. Business-logic inference and novel exploit development remain human-led.

### 4. Methodology coverage and web/API checks

- [x] A version-labelled registry maps 14 checks to 20 WSTG 4.2 and ASVS 4.0.3 references; status reports distinguish candidates, passed checks, skipped checks, and not-applicable checks. A detector with unobserved prerequisites remains a gap.
- [x] Registry validation and vulnerable/patched fixtures exist. Web-check, API inventory, tool-adapter, budget, and owned-source-analysis modules are present.
- [ ] Expand and review the methodology subset, retain source/license revisions, and reconcile the ASVS 4.0.3 references with the vendored ASVS 5.0 revision.
- [~] Source-file probes use the same gateway in worker and campaign execution, with exact-path policy, lease, rate, and runtime-control checks. Browser-discovered endpoints and API inventories are not yet fed through a complete methodology run; the Nuclei CLI remains an attested lab operation.
- [ ] Add independently reviewed budgets, safe-stop rules, response evidence contracts, and vulnerable/patched fixtures for each newly enabled live detector.

### 5. Verification, evidence, and reporting

- [x] Pure finding-state transitions, deterministic replay contracts, deduplication, rule-based signal chains, remediation text, and a retest helper exist.
- [x] Reproduced browser access-control candidates are saved as `HUMAN_REVIEW`; automated code does not submit a report on a person's behalf.
- [~] Observation and per-step response hashes are persisted. Redaction/encryption helpers exist, but the full evidence lifecycle, key management, and complete redacted evidence schema are not integrated across all workers.
- [~] Persisted triage, editable Markdown report drafts, submission deduplication, and inconclusive retest handling exist. Authenticated reviewer identity and automatic retest scheduling remain open.
- [ ] Measure false-positive rate, repeatability, cleanup success, reviewer time, and detection yield on a maintained benchmark before making effectiveness claims.

### 6. Other authorized asset classes

- [x] Offline analyzers exist for cloud/IAM, Kubernetes, secrets, network-service inventories, CI/CD configuration, and dependency/supply-chain data. Module authorization is separate from web-domain scope.
- [ ] Add read-only collectors only with separate credentials, scope, budgets, fixtures, and independent authorization. These modules currently analyze supplied data; they do not connect to live cloud accounts or clusters.

### 7. Production operations and security review

- [x] Pure decision logic exists for kill/revocation, retention planning, dead-letter classification, audit-chain validation, and threshold alerts.
- [~] Database kill/revocation/epoch checks are applied at execution boundaries, and worker/campaign share heartbeat handling. Metrics, retention execution, dead letters, and limited submission/dead-letter backup/restore commands exist. Full database/evidence backups, restore drills, production alerts, audit integrity under concurrency, least-privilege roles, and operator access review remain open.
- [ ] Enforce outbound network restrictions outside Playwright routing; test redirects, subresources, frames, workers, WebSockets, DNS changes, and browser escape paths in an isolated staging environment.
- [ ] Test crash/restart recovery, duplicate workers, database upgrades, credential/mail outages, policy revocation, and export reconciliation.
- [ ] Complete independent scope, browser-egress, sandbox, secret-handling, and data-retention reviews. Roll out only to owned staging first, then to individually approved targets.

## Production release gate

Do not call a campaign production-ready until a clean deployment can take a domain list plus authenticated reviewed policies, run discovery and all enabled checks under enforced egress controls, isolate account roles, recover after interruption, record truthful per-domain coverage, reproduce findings with secure controls, clean every test resource, and schedule only currently authorized revisits. A reviewer must control impact ranking and submission.

## Next implementation order

1. Keep the owner-resource probe fail-closed and prove marker-based cleanup for successful, malformed, timed-out, and interrupted create responses.
2. Run the browser pipeline against owned vulnerable and patched staging applications with a real test mailbox and enforced network egress controls.
3. Validate monitor-to-worker continuity and implement scheduled revisits without permanent deduplication suppressing rescans; keep held assets untouched.
4. Finish credential-service integration and identity/session health, then feed browser/API inventory into methodology coverage.
5. Integrate checks one at a time behind budgets, reviewable tool pins, and vulnerable/patched fixtures.
6. Finish evidence/report/retest workflows, fleet operations, recovery testing, and independent security review.
