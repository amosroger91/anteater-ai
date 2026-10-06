-- Bind each claimed lease to the fleet control epoch. In-flight leases from an older
-- process have no epoch and are retired; retries must be freshly claimed after upgrade.
ALTER TABLE research_jobs ADD COLUMN IF NOT EXISTS lease_epoch bigint;
UPDATE research_jobs SET status='queued', lease_token=NULL, lease_until=NULL, lease_heartbeat_at=NULL
  WHERE status='running' AND lease_epoch IS NULL;
