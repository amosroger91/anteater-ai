-- Submission ledger (BOUNTY_EARNINGS_PLAN.md Phase 6.3).
-- One row per status change. Amounts are recorded outcomes, not estimates.

CREATE TABLE IF NOT EXISTS submissions (
  id uuid PRIMARY KEY,
  program_id text NOT NULL REFERENCES programs(id),
  finding_id uuid REFERENCES findings(id),
  status text NOT NULL CHECK (status IN ('submitted', 'triaged', 'accepted', 'duplicate', 'informational', 'paid')),
  amount numeric,
  currency text,
  recorded_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS submissions_program_recorded ON submissions(program_id, recorded_at DESC);
