-- Additive foundation only. No work is enqueued by this migration. The dashboard
-- stays on its current adapter until transactional scheduling and admission land.
CREATE TABLE campaign_projects (
  id uuid PRIMARY KEY,
  program_id text NOT NULL REFERENCES programs(id),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  archived_at timestamptz,
  UNIQUE(id, program_id)
);

CREATE TABLE campaign_policy_revisions (
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL REFERENCES campaign_projects(id),
  revision text NOT NULL,
  source_sha256 text NOT NULL CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
  source_url text NOT NULL,
  policy jsonb NOT NULL CHECK (jsonb_typeof(policy) = 'object'),
  reviewed_by text NOT NULL CHECK (length(reviewed_by) > 0),
  approved_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  UNIQUE(project_id, revision),
  UNIQUE(id, project_id)
);
CREATE FUNCTION reject_campaign_policy_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'campaign policy revisions are immutable; create a new revision';
END;
$$;
CREATE TRIGGER campaign_policy_immutable BEFORE UPDATE ON campaign_policy_revisions
  FOR EACH ROW EXECUTE FUNCTION reject_campaign_policy_update();

CREATE TABLE campaign_runs (
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL,
  program_id text NOT NULL,
  policy_revision_id uuid NOT NULL,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  mode text NOT NULL CHECK (mode IN ('demo','passive','authenticated')),
  status text NOT NULL CHECK (status IN ('draft','ready','queued','preparing','running','stopping','completed','completed_with_gaps','failed','cancelled','interrupted')),
  created_by text NOT NULL CHECK (length(created_by) > 0),
  idempotency_key uuid NOT NULL,
  input_sha256 text NOT NULL CHECK (input_sha256 ~ '^[a-f0-9]{64}$'),
  budget jsonb NOT NULL CHECK (jsonb_typeof(budget) = 'object'),
  stop_epoch bigint NOT NULL DEFAULT 0 CHECK (stop_epoch >= 0),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz,
  FOREIGN KEY(project_id, program_id) REFERENCES campaign_projects(id, program_id),
  FOREIGN KEY(policy_revision_id, project_id) REFERENCES campaign_policy_revisions(id, project_id),
  UNIQUE(project_id, created_by, idempotency_key),
  UNIQUE(id, program_id)
);
CREATE INDEX campaign_runs_history ON campaign_runs(project_id, created_at DESC, id);

CREATE TABLE campaign_targets (
  id uuid PRIMARY KEY,
  campaign_id uuid NOT NULL REFERENCES campaign_runs(id),
  target_index integer NOT NULL CHECK (target_index >= 0 AND target_index < 25),
  url text NOT NULL,
  status text NOT NULL CHECK (status IN ('queued','running','stopping','completed','completed_with_gaps','failed','cancelled','interrupted','blocked')),
  reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  UNIQUE(campaign_id, target_index),
  UNIQUE(campaign_id, url),
  UNIQUE(id, campaign_id)
);

-- Link to the existing leased queue without creating another queue. A future
-- start transaction must create these links before workers can claim the jobs.
CREATE TABLE campaign_job_links (
  job_id uuid PRIMARY KEY REFERENCES research_jobs(id),
  campaign_id uuid NOT NULL,
  program_id text NOT NULL,
  target_id uuid NOT NULL,
  FOREIGN KEY(campaign_id, program_id) REFERENCES campaign_runs(id, program_id),
  FOREIGN KEY(target_id, campaign_id) REFERENCES campaign_targets(id, campaign_id)
);
ALTER TABLE research_jobs ADD CONSTRAINT research_jobs_program_id_id_unique UNIQUE(program_id, id);
ALTER TABLE campaign_job_links ADD CONSTRAINT campaign_job_program_fk
  FOREIGN KEY(program_id, job_id) REFERENCES research_jobs(program_id, id);

CREATE TABLE campaign_events (
  campaign_id uuid NOT NULL REFERENCES campaign_runs(id),
  sequence bigint NOT NULL CHECK (sequence > 0),
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  type text NOT NULL CHECK (length(type) BETWEEN 1 AND 80),
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(campaign_id, sequence)
);

CREATE TABLE campaign_imports (
  source_id uuid PRIMARY KEY,
  campaign_id uuid UNIQUE REFERENCES campaign_runs(id),
  source_sha256 text NOT NULL CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
  source_schema_version integer NOT NULL,
  imported_at timestamptz NOT NULL DEFAULT now(),
  manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest) = 'object')
);
