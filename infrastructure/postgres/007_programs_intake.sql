-- Program intake provenance (BOUNTY_EARNINGS_PLAN.md Phase 1.4).
-- automation_policy is the reviewed class. program_approvals records who approved
-- which source hash. A prohibited class is not an enqueue grant; the application
-- refuses to store one as a runnable program.

ALTER TABLE programs ADD COLUMN IF NOT EXISTS automation_policy text;
ALTER TABLE programs ADD COLUMN IF NOT EXISTS platform_handle text;

DO $$
BEGIN
  ALTER TABLE programs
    ADD CONSTRAINT programs_automation_policy_check
    CHECK (automation_policy IS NULL OR automation_policy IN ('permitted', 'manual-only', 'prohibited'));
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS program_approvals (
  program_id text NOT NULL REFERENCES programs(id),
  approver text NOT NULL,
  source_sha256 text NOT NULL,
  approved_at timestamptz NOT NULL,
  revision text NOT NULL,
  PRIMARY KEY (program_id, revision),
  CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
  CHECK (length(btrim(approver)) > 0),
  CHECK (length(btrim(revision)) > 0)
);
