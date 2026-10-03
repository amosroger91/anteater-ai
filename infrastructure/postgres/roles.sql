-- Least-privilege database roles (PRODUCTION_ROADMAP.md §7). Operator-applied, NOT part of the
-- automatic migration list: roles are cluster-level and environment-specific, and must not be created
-- inside per-test schemas. Run once against the operator database by a superuser.
--
--   psql "$DATABASE_URL" -f infrastructure/postgres/roles.sql
--
-- The worker role may advance research state but may NOT mark findings VERIFIED or SUBMITTED — those
-- stay with the deterministic verifier and an authenticated human, mirroring packages/findings.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'anteater_worker') THEN
    CREATE ROLE anteater_worker NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'anteater_verifier') THEN
    CREATE ROLE anteater_verifier NOLOGIN;
  END IF;
END $$;

GRANT SELECT, INSERT, UPDATE ON research_jobs, observations, agent_runs, tool_runs, dead_letter TO anteater_worker;
GRANT SELECT, INSERT ON findings, evidence TO anteater_worker;
GRANT SELECT, INSERT, DELETE ON resource_cleanup TO anteater_worker;
-- The worker cannot UPDATE findings (so it cannot move a finding to VERIFIED/SUBMITTED).
REVOKE UPDATE ON findings FROM anteater_worker;

-- The verifier may transition findings into VERIFICATION/VERIFIED only.
GRANT SELECT, UPDATE ON findings TO anteater_verifier;
