BEGIN;
CREATE TABLE IF NOT EXISTS programs (
  id text PRIMARY KEY, name text NOT NULL, platform text NOT NULL,
  program_url text NOT NULL, categories jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS scope_rules (
  program_id text PRIMARY KEY REFERENCES programs(id), policy jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
  id text PRIMARY KEY, program_id text NOT NULL REFERENCES programs(id), url text NOT NULL,
  UNIQUE(program_id, url)
);
CREATE TABLE IF NOT EXISTS research_jobs (
  id uuid PRIMARY KEY, program_id text NOT NULL REFERENCES programs(id),
  asset_id text NOT NULL REFERENCES assets(id), action text NOT NULL,
  dedupe_key text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','completed','failed')),
  attempts integer NOT NULL DEFAULT 0, max_attempts integer NOT NULL DEFAULT 3,
  available_at timestamptz NOT NULL DEFAULT now(), lease_until timestamptz,
  lease_token uuid, result jsonb, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS research_jobs_claim ON research_jobs(status, available_at);
CREATE TABLE IF NOT EXISTS observations (
  id uuid PRIMARY KEY, program_id text NOT NULL REFERENCES programs(id),
  job_id uuid NOT NULL UNIQUE REFERENCES research_jobs(id), body jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS hypotheses (
  id uuid PRIMARY KEY, program_id text NOT NULL REFERENCES programs(id), body jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  id uuid PRIMARY KEY, program_id text NOT NULL REFERENCES programs(id),
  status text NOT NULL CHECK(status IN ('OBSERVATION','HYPOTHESIS','CANDIDATE','VERIFICATION','VERIFIED','REJECTED','HUMAN_REVIEW','SUBMITTED')),
  body jsonb NOT NULL, human_reviewer text,
  CHECK(status <> 'SUBMITTED' OR human_reviewer IS NOT NULL)
);
CREATE TABLE IF NOT EXISTS evidence (
  id uuid PRIMARY KEY, finding_id uuid REFERENCES findings(id), sha256 text NOT NULL, body jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS tool_runs (
  id uuid PRIMARY KEY, job_id uuid NOT NULL REFERENCES research_jobs(id), tool text NOT NULL,
  result jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS agent_runs (
  id uuid PRIMARY KEY, job_id uuid NOT NULL REFERENCES research_jobs(id), role text NOT NULL, model text, result jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_limits (key text PRIMARY KEY, next_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS workspace_outbox (program_id text PRIMARY KEY REFERENCES programs(id), revision bigint NOT NULL DEFAULT 1);
COMMIT;
