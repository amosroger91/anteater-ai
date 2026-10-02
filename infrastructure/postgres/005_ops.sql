-- §7 operations schema: dead-letter queue, tamper-evident audit chain columns, retention index.
-- Schema-level and idempotent; safe to re-run. Cluster-level roles live in roles.sql (operator-applied).

CREATE TABLE IF NOT EXISTS dead_letter (
  id uuid PRIMARY KEY,
  job_id uuid REFERENCES research_jobs(id),
  reason text NOT NULL,
  error_code text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS dead_letter_created ON dead_letter(created_at);

-- Tamper-evident hash chain over the existing audit log.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS prev_hash text;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS hash text;

-- Retention sweeps scan observations/dead_letter by age.
CREATE INDEX IF NOT EXISTS observations_retention ON observations(created_at);
