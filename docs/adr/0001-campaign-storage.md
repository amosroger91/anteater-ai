# ADR 0001: one durable live scheduling authority

Status: accepted design; snapshot boundary and additive schema implemented, live scheduling not integrated.

Keep the current JSON adapter working during migration. Extract its load/save behavior into `packages/campaigns/repository.ts`; lifecycle recovery stays in CampaignService. This snapshot interface is intentionally insufficient for distributed scheduling. Do not implement PostgreSQL live execution by periodically saving the entire in-memory map.

Migration 007 adds projects, immutable policy revisions, campaigns, targets, job links, events and import provenance. Project/program and project/policy relationships are enforced with composite foreign keys. Existing research_jobs remains the only queue. No database jobs are created by this migration. Production entry points still use FileCampaignRepository.

Next add transactional campaign creation, scoped idempotency, target/job insertion, policy/epoch admission and durable outbox publication as one service path. Define stable mapping from saved local project UUIDs to existing program IDs during import. Create/update program mapping before campaign project insertion. Current scope_rules remains execution authority until immutable campaign policy admission replaces that dependency deliberately.

Never run file-backed and PostgreSQL schedulers for the same project. Database failure must not cause fallback live requests. Preserve the fixture/no-database demo. Do not enqueue linked live jobs before shared cancellation and policy admission are implemented; the existing worker is not yet campaign-aware.

Rollback: migration 007 is additive, but old workers must not be used with newly scheduled live campaign jobs. Stop admissions/workers before rollback; retain schema/data. No automatic destructive down migration.
