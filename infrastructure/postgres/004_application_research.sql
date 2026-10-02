ALTER TABLE research_jobs DROP CONSTRAINT IF EXISTS research_jobs_action_check;
ALTER TABLE research_jobs ADD CONSTRAINT research_jobs_action_check
  CHECK (action IN ('inspect_http_target','inspect_robots','inspect_sitemap','inspect_openapi','research_application'));
CREATE INDEX IF NOT EXISTS observations_application_reports ON observations(program_id, created_at);
