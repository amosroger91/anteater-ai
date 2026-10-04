# Implementation status

Plan: [CLAUDE_BOUNTY_BUILD_PLAN.md](CLAUDE_BOUNTY_BUILD_PLAN.md)
Baseline: `4c74e3b`. Current work is on `codex/review-hardening`; no remote release is implied.

## Current milestone

The dashboard can prepare a focused, editable report draft from one stored observation in a completed assessment. It renders HackerOne, Bugcrowd and generic profiles as Markdown, text, offline HTML or JSON, shows a human-review checklist, supports local saved revisions and provides download/copy actions. The first PostgreSQL campaign tables and a snapshot repository boundary are in place, but live campaigns are still file-backed.

No assessment targets were contacted to generate or validate these reports. Report formatting is not evidence of exploitability, program eligibility, acceptance or reward.

## Completion ledger

| Ticket | Status | Commit(s) | Verification | Remaining limitation / next action |
| --- | --- | --- | --- | --- |
| B00 | verified | `c8fde77` | Build; 152 unit tests; 10 Chromium end-to-end tests; 20 PostgreSQL integration tests; fixture replay; compiled-dashboard smoke test passed locally on Windows / Node 24.13.0. | Remote Linux CI not run for this working tree. |
| B01 | in_progress | `c8fde77` | Added a file snapshot repository boundary and migration 007; PostgreSQL tests validate idempotent migration, immutable policy rows, project/operator key scope, composite campaign/job links, and refusal to claim linked work with the legacy worker. | No PostgreSQL campaign repository or transactional start path is wired to UI/CLI; finish the durable repository/admission integration. |
| B02 | not_started | — | — | See plan. |
| B03 | not_started | — | — | See plan. |
| B04 | not_started | — | — | See plan. |
| B05 | not_started | — | — | See plan. |
| B06 | not_started | — | — | See plan. |
| B07 | not_started | — | — | See plan. |
| B08 | not_started | — | — | See plan. |
| B09 | not_started | — | — | See plan. |
| B10 | not_started | — | — | See plan. |
| B11 | not_started | — | — | See plan. |
| B12 | not_started | — | — | See plan. |
| B13 | not_started | — | — | See plan. |
| B14 | in_progress | `c8fde77` | B14.1 passes unit, API and Chromium UI checks; B14.2 local revision API and browser flow pass. | Evidence selection/attachment manifest, reviewed readiness gates and PostgreSQL report lifecycle are not complete. |
| B15 | not_started | — | — | See plan. |
| B16 | not_started | — | — | See plan. |
| B17 | not_started | — | — | See plan. |
| B18 | not_started | — | — | See plan. |
| B19 | not_started | — | — | See plan. |
| B20 | not_started | — | — | See plan. |

## Report slices

- [x] **B14.1 — Verified locally.** Deterministic profiles and four formats, completed-assessment observation selection, demo watermark, source/evidence hashes, explicit limitations, preview/download UI, same-origin session checks and redaction/escaping tests.
- [ ] **B14.2 — In progress.** Local immutable editable revisions, generic custom fields, optimistic revision checks, source-snapshot binding and browser editing/version history are implemented and tested. Remaining: evidence selection and claim references; file persistence is not a cross-process or PostgreSQL concurrency contract.
- [ ] **B14.3 — Not started.** Attachment manifest, redaction preview, integrity verification and explicit readiness gates.
- [ ] **B14.4 — Not started.** Durable campaign integration, reviewed export bundle and manual submission/outcome records.

## Last verification

All commands ran serially on Windows / Node 24.13.0 with synthetic fixtures. `npm run build`, `npm run test:dashboard-build`, `npx tsx --test --test-concurrency=1 tests/*.test.ts` (152 passed), `npx tsx --test --test-concurrency=1 tests/browser/*.test.ts` (10 passed), and `npm run verify:local` (20 PostgreSQL tests plus fixture replay) passed. Dashboard screenshots were captured under `docs/screenshots/`. No remote CI or real target assessment was run.

## Decisions

- Campaign storage boundary and migration: [ADR 0001](adr/0001-campaign-storage.md).
- Local operator/session identity versus reviewer identity: [ADR 0002](adr/0002-operator-identity.md).
- Application controls and independent egress boundary: [ADR 0003](adr/0003-execution-isolation.md).

## Next session

Read this status and `git status` first. Prioritize B01's PostgreSQL repository/admission integration before linking jobs to live campaigns. For report work, continue B14.2 with evidence selection and claim references, then B14.3. Keep campaign-linked jobs unclaimable by the legacy worker until its campaign-aware admission and stop controls are wired.
