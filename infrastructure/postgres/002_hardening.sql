ALTER TABLE assets ADD COLUMN IF NOT EXISTS active boolean NOT NULL DEFAULT true;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS policy_revision text NOT NULL DEFAULT 'legacy';
ALTER TABLE research_jobs ADD COLUMN IF NOT EXISTS policy_revision text NOT NULL DEFAULT 'legacy';
ALTER TABLE research_jobs ADD COLUMN IF NOT EXISTS lease_heartbeat_at timestamptz;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS raw_text text;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'accepted';
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS sampling_options jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS model_digest text;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS prompt_hash text;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS schema_version text NOT NULL DEFAULT 'legacy';
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE hypotheses ADD COLUMN IF NOT EXISTS agent_run_id uuid REFERENCES agent_runs(id);
ALTER TABLE hypotheses ADD COLUMN IF NOT EXISTS observation_id uuid REFERENCES observations(id);
ALTER TABLE hypotheses ADD COLUMN IF NOT EXISTS dedupe_key text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS verified_by text;

UPDATE assets a
SET policy_revision = COALESCE((SELECT policy->>'revision' FROM scope_rules s WHERE s.program_id = a.program_id), 'legacy')
WHERE a.policy_revision = 'legacy';
UPDATE research_jobs j
SET policy_revision = COALESCE((SELECT policy->>'revision' FROM scope_rules s WHERE s.program_id = j.program_id), 'legacy')
WHERE j.policy_revision = 'legacy';

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'assets_program_id_id_unique') THEN
    ALTER TABLE assets ADD CONSTRAINT assets_program_id_id_unique UNIQUE (program_id, id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'research_jobs_asset_program_fk') THEN
    ALTER TABLE research_jobs ADD CONSTRAINT research_jobs_asset_program_fk FOREIGN KEY (program_id, asset_id) REFERENCES assets(program_id, id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'research_jobs_action_check') THEN
    ALTER TABLE research_jobs ADD CONSTRAINT research_jobs_action_check CHECK (action IN ('inspect_http_target'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_runs_status_check') THEN
    ALTER TABLE agent_runs ADD CONSTRAINT agent_runs_status_check CHECK (status IN ('accepted', 'parse_failed'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'findings_verified_check') THEN
    ALTER TABLE findings ADD CONSTRAINT findings_verified_check CHECK (status <> 'VERIFIED' OR verified_by IS NOT NULL);
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS hypotheses_dedupe_key ON hypotheses(dedupe_key) WHERE dedupe_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS research_jobs_policy_revision ON research_jobs(program_id, policy_revision, status);
CREATE INDEX IF NOT EXISTS assets_active_lookup ON assets(program_id, active);
