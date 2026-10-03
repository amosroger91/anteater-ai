# Production roadmap

For the full product and engineering delivery sequence, see [IMPROVEMENT_PLAN.md](IMPROVEMENT_PLAN.md). This document retains the capability status and production release boundaries.

Anteater is a scope-first framework for repeatable web and API security checks. Its goal is to automate bounded, evidence-backed work so people can focus on business impact, novel attack paths, and remediation decisions. It must report coverage honestly; it cannot promise to find every vulnerability.

## Current state

The current working tree includes a domain-list worker, a reviewed per-campaign policy profile, a PostgreSQL job queue, a bounded passive HTTP worker, and an opt-in Playwright application-research path. The browser path can explore same-origin pages, attempt at most two configured accounts, optionally create encrypted test accounts and verify them through IMAP, and replay a configured owner-only resource read across accounts. It requires `ENABLE_APPLICATION_RESEARCH=true`; non-read requests additionally require `ALLOW_ACTIVE_TESTING=true` and explicit paths in the application profile.

This is a working prototype, not a production service. The automated tests use Chromium with an injected synthetic transport and a fake application/mailbox. They do not validate DNS, TLS, browser egress, a live login, a real mailbox, or cleanup behavior against an independently controlled staging application. The worker scans only submitted roots: discovery adapters and downstream checks are not yet joined into an unattended discovery-to-report campaign. Most additional detectors and infrastructure analyzers are libraries with fixture tests, not live worker stages.

The review-hardening implementation adds the local passive dashboard, explicit coverage execution records, canonical-principal verification, durable cleanup intents, coordinated retention, and browser CI. See [VALIDATION.md](VALIDATION.md) and [REVIEW_HARDENING.md](REVIEW_HARDENING.md) for current verification and boundaries.

## Capability status

### 1. Input, authorization, and campaign flow

- [x] Parse and normalize a domain list and reject ambiguous entries.
- [x] Require a reviewed policy profile with source URL, expiry, revision, exact allowed hosts/actions, and request rate before enqueuing each submitted root.
- [x] Recheck scope and policy revision at job execution; retain a default-off kill switch.
- [~] Record approval provenance as a pure verifier (`packages/provenance`), but do not yet require authenticated approver identity or a matching source hash in the live campaign loader.
- [ ] Connect discovery, methodology checks, evidence, reporting, and scheduled revisits into one persistent campaign workflow. `apps/orchestrator/campaign.ts` is a fixture composition, not the live worker pipeline.

### 2. Authorized asset discovery

- [x] Candidate model, normalization, provenance, deduplication, scope admission, and candidate-to-job creation are implemented and fixture-tested.
- [x] Passive certificate-transparency, injected passive-DNS, Subfinder, and Gitleaks adapters exist. Subfinder/Gitleaks require an explicitly configured absolute binary and injected runner; Gitleaks returns redacted findings and never uses secrets.
- [ ] Wire approved discovery adapters to the worker and persist candidate history. Candidates must remain held until the exact host and action are admitted by current policy.
- [ ] Add change handling, per-source budgets/retention, and egress controls for every live lookup and discovered host.

### 3. Authenticated and multi-role assessment

- [x] Isolated browser contexts, form inventory, same-origin navigation, bounded request/response sizes, and a DNS-pinned HTTPS transport are implemented.
- [x] Up to two operator-supplied accounts can be loaded from environment variables. Optional generated accounts are encrypted at rest; an IMAP verifier is available. MFA/CAPTCHA-style challenges are reported instead of bypassed.
- [x] A profile can define an owner-only resource: the worker creates a marked test object, checks owner access, cross-account access, a repeat, a missing-object control, and owner access again, then deletes the object through its owner-bound marker cleanup path.
- [ ] Support an explicit role model including a supplied least-privilege administrator, a maintained secret service, session renewal/health checks, stronger signup lifecycle management, and worker-isolated secret access.
- [ ] Exercise login, signup, IMAP, session identity, and marker cleanup against an independently controlled vulnerable/patched staging app. The local fake transport does not validate real egress or real mailbox behavior.
- [ ] Extend beyond configured owner-resource probes to discovered actor/resource/action matrices. Business-logic inference and novel exploit development remain human-led.

### 4. Methodology coverage and web/API checks

- [x] A version-labelled registry maps eight passive posture checks to four WSTG 4.2 references; ASVS coverage is not claimed; status reports distinguish candidates, passed checks, skipped checks, and not-applicable checks.
- [x] Registry validation and vulnerable/patched fixtures exist. Web-check, API inventory, tool-adapter, budget, and owned-source-analysis modules are present.
- [ ] Expand and review the methodology subset, retain source/license revisions, and add independently reviewed mappings for the vendored ASVS revision.
- [ ] Connect the APIs, checks, budgets, and reviewed tool adapters to the live egress worker. Browser-discovered endpoints and API inventories are not yet fed through a complete methodology run.
- [ ] Add independently reviewed budgets, safe-stop rules, response evidence contracts, and vulnerable/patched fixtures for each newly enabled live detector.

### 5. Verification, evidence, and reporting

- [x] Pure finding-state transitions, deterministic replay contracts, deduplication, rule-based signal chains, remediation text, and a retest helper exist.
- [x] Reproduced browser access-control candidates are saved as `HUMAN_REVIEW`; automated code does not submit a report on a person's behalf.
- [~] Observation and per-step response hashes are persisted. Redaction/encryption helpers exist, but the full evidence lifecycle, key management, and complete redacted evidence schema are not integrated across all workers.
- [ ] Wire general finding transitions, human identity, reviewer decisions, retest jobs, editable reports, and remediation evidence into persistent campaign state.
- [ ] Measure false-positive rate, repeatability, cleanup success, reviewer time, and detection yield on a maintained benchmark before making effectiveness claims.

### 6. Other authorized asset classes

- [x] Offline analyzers exist for cloud/IAM, Kubernetes, secrets, network-service inventories, CI/CD configuration, and dependency/supply-chain data. Module authorization is separate from web-domain scope.
- [ ] Add read-only collectors only with separate credentials, scope, budgets, fixtures, and independent authorization. These modules currently analyze supplied data; they do not connect to live cloud accounts or clusters.

### 7. Production operations and security review

- [x] Pure decision logic exists for kill/revocation, retention planning, dead-letter classification, audit-chain validation, and threshold alerts.
- [ ] Wire fleet-wide cancellation, revocation, audit integrity, least-privilege database roles, retention execution, metrics/alerts, dead-letter controls, backups, restore drills, and operator access review.
- [ ] Enforce outbound network restrictions outside Playwright routing; test redirects, subresources, frames, workers, WebSockets, DNS changes, and browser escape paths in an isolated staging environment.
- [ ] Test crash/restart recovery, duplicate workers, database upgrades, credential/mail outages, policy revocation, and export reconciliation.
- [ ] Complete independent scope, browser-egress, sandbox, secret-handling, and data-retention reviews. Roll out only to owned staging first, then to individually approved targets.

## Production release gate

Do not call a campaign production-ready until a clean deployment can take a domain list plus authenticated reviewed policies, run discovery and all enabled checks under enforced egress controls, isolate account roles, recover after interruption, record truthful per-domain coverage, reproduce findings with secure controls, clean every test resource, and schedule only currently authorized revisits. A reviewer must control impact ranking and submission.

## Next implementation order

1. Keep the owner-resource probe fail-closed and prove marker-based cleanup for successful, malformed, timed-out, and interrupted create responses.
2. Run the browser pipeline against owned vulnerable and patched staging applications with a real test mailbox and enforced network egress controls.
3. Wire candidate discovery through current-policy admission into persistent jobs; keep held assets untouched.
4. Add role-aware credentials and identity/session health, then feed browser/API inventory into methodology coverage.
5. Integrate checks one at a time behind budgets, reviewable tool pins, and vulnerable/patched fixtures.
6. Finish evidence/report/retest workflows, fleet operations, recovery testing, and independent security review.
