-- Active-probe actions (the injection suite). Widen the research_jobs action allow-list so a reviewed,
-- automation-permitted program can queue parameterized probes. Execution is still gated at runtime by
-- ALLOW_ACTIVE_TESTING and re-authorized per request by the scope engine (authorizeActive).
ALTER TABLE research_jobs DROP CONSTRAINT IF EXISTS research_jobs_action_check;
ALTER TABLE research_jobs ADD CONSTRAINT research_jobs_action_check
  CHECK (action IN ('inspect_http_target','inspect_robots','inspect_sitemap','inspect_openapi','research_application','probe_sqli','probe_xss','probe_ssrf','probe_redirect'));
