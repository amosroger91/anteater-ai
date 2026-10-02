-- Expand the bounded read-only action set and retain an append-only execution trail.
ALTER TABLE research_jobs DROP CONSTRAINT IF EXISTS research_jobs_action_check;
ALTER TABLE research_jobs ADD CONSTRAINT research_jobs_action_check
  CHECK (action IN ('inspect_http_target','inspect_robots','inspect_sitemap','inspect_openapi'));

CREATE TABLE IF NOT EXISTS audit_events (
  id uuid PRIMARY KEY,
  event text NOT NULL,
  program_id text REFERENCES programs(id),
  job_id uuid REFERENCES research_jobs(id),
  asset_id text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_events_program_created ON audit_events(program_id, created_at, id);
CREATE INDEX IF NOT EXISTS evidence_sha256 ON evidence(sha256);
