-- Triage queue (BOUNTY_EARNINGS_PLAN.md Phase 5.3).
-- Ranks HUMAN_REVIEW and VERIFIED findings by estimated payout times confidence.
-- A prior SUBMITTED row with the same program, type, and location hides the duplicate.

CREATE OR REPLACE VIEW triage_queue AS
WITH ranked AS (
  SELECT
    f.id,
    f.program_id,
    f.status,
    COALESCE(f.body->>'findingType', f.body->>'type', '') AS finding_type,
    COALESCE(f.body->>'location', '') AS location,
    CASE WHEN COALESCE(f.body->>'confidence', '') ~ '^[0-9]+([.][0-9]+)?$'
      THEN (f.body->>'confidence')::numeric ELSE 0.5 END AS confidence,
    CASE WHEN COALESCE(f.body->>'estimatedPayout', '') ~ '^[0-9]+([.][0-9]+)?$'
      THEN (f.body->>'estimatedPayout')::numeric
      WHEN COALESCE(f.body->>'severity', '') = 'critical' THEN 5000
      WHEN COALESCE(f.body->>'severity', '') = 'high' THEN 1000
      WHEN COALESCE(f.body->>'severity', '') = 'medium' THEN 250
      ELSE 0 END AS estimated_payout
  FROM findings f
  WHERE f.status IN ('HUMAN_REVIEW', 'VERIFIED')
    AND NOT EXISTS (
      SELECT 1 FROM findings prior
      WHERE prior.program_id = f.program_id
        AND prior.status = 'SUBMITTED'
        AND COALESCE(prior.body->>'findingType', prior.body->>'type', '') = COALESCE(f.body->>'findingType', f.body->>'type', '')
        AND COALESCE(prior.body->>'location', '') = COALESCE(f.body->>'location', '')
        AND prior.id <> f.id
    )
)
SELECT id, program_id, status, finding_type, location, confidence, estimated_payout,
  (estimated_payout * confidence) AS rank
FROM ranked;
