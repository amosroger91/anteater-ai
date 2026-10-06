-- Persist cleanup before creating disposable application data. Debt survives crashed workers.
-- No credentials, session cookies, or response bodies belong in this table.
CREATE TABLE IF NOT EXISTS resource_cleanup (
  id uuid PRIMARY KEY,
  program_id text NOT NULL REFERENCES programs(id),
  policy_revision text NOT NULL,
  origin text NOT NULL,
  owner_id text NOT NULL,
  marker text NOT NULL,
  cleanup_url text NOT NULL,
  job_id uuid REFERENCES research_jobs(id) ON DELETE SET NULL,
  job_lease_token uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(program_id,origin,marker)
);
CREATE INDEX IF NOT EXISTS resource_cleanup_pending ON resource_cleanup(program_id,origin,created_at);
