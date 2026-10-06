-- Submit-ready queue (extends 009_triage.sql and 010_economics.sql).
-- A HUMAN_REVIEW or VERIFIED finding stays out of triage_queue when the same
-- program, type, and location was already submitted or is on the known-issue list.
-- Rank is payout tier times confidence. Tier 0 (info) is not a submit-ready lead.
-- The tier CASE matches payoutTier() in packages/ledger/index.ts.

CREATE TABLE IF NOT EXISTS known_issues (
  id uuid PRIMARY KEY,
  program_id text NOT NULL REFERENCES programs(id),
  finding_type text NOT NULL,
  location text NOT NULL,
  note text,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (program_id, finding_type, location)
);

CREATE INDEX IF NOT EXISTS known_issues_lookup ON known_issues(program_id, finding_type, location);

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
      WHEN lower(COALESCE(f.body->>'severity', '')) = 'critical' THEN 5000
      WHEN lower(COALESCE(f.body->>'severity', '')) = 'high' THEN 1000
      WHEN lower(COALESCE(f.body->>'severity', '')) = 'medium' THEN 250
      ELSE 0 END AS estimated_payout,
    CASE lower(COALESCE(f.body->>'severity', ''))
      WHEN 'critical' THEN 4
      WHEN 'high' THEN 3
      WHEN 'medium' THEN 2
      WHEN 'low' THEN 1
      WHEN 'info' THEN 0
      WHEN 'informational' THEN 0
      ELSE CASE
        WHEN COALESCE(f.body->>'estimatedPayout', '') ~ '^[0-9]+([.][0-9]+)?$' AND (f.body->>'estimatedPayout')::numeric >= 5000 THEN 4
        WHEN COALESCE(f.body->>'estimatedPayout', '') ~ '^[0-9]+([.][0-9]+)?$' AND (f.body->>'estimatedPayout')::numeric >= 1000 THEN 3
        WHEN COALESCE(f.body->>'estimatedPayout', '') ~ '^[0-9]+([.][0-9]+)?$' AND (f.body->>'estimatedPayout')::numeric >= 250 THEN 2
        WHEN COALESCE(f.body->>'estimatedPayout', '') ~ '^[0-9]+([.][0-9]+)?$' AND (f.body->>'estimatedPayout')::numeric > 0 THEN 1
        ELSE 0
      END
    END AS payout_tier,
    (SELECT e.sha256 FROM evidence e WHERE e.finding_id = f.id ORDER BY e.sha256 LIMIT 1) AS evidence_sha,
    CASE WHEN jsonb_typeof(f.body->'replay'->'evidence') = 'array'
      THEN jsonb_array_length(f.body->'replay'->'evidence') ELSE 0 END AS evidence_steps
  FROM findings f
  WHERE f.status IN ('HUMAN_REVIEW', 'VERIFIED')
    AND NOT EXISTS (
      SELECT 1 FROM findings prior
      WHERE prior.program_id = f.program_id
        AND prior.status = 'SUBMITTED'
        AND prior.id <> f.id
        AND COALESCE(prior.body->>'findingType', prior.body->>'type', '') = COALESCE(f.body->>'findingType', f.body->>'type', '')
        AND COALESCE(prior.body->>'location', '') = COALESCE(f.body->>'location', '')
    )
    AND NOT EXISTS (
      SELECT 1 FROM submissions s
      JOIN findings sent ON sent.id = s.finding_id
      WHERE s.program_id = f.program_id
        AND s.status IN ('submitted', 'triaged', 'accepted', 'duplicate', 'informational', 'paid')
        AND sent.id <> f.id
        AND COALESCE(sent.body->>'findingType', sent.body->>'type', '') = COALESCE(f.body->>'findingType', f.body->>'type', '')
        AND COALESCE(sent.body->>'location', '') = COALESCE(f.body->>'location', '')
    )
    AND NOT EXISTS (
      SELECT 1 FROM known_issues k
      WHERE k.program_id = f.program_id
        AND k.finding_type = COALESCE(f.body->>'findingType', f.body->>'type', '')
        AND k.location = COALESCE(f.body->>'location', '')
    )
)
SELECT id, program_id, status, finding_type, location, confidence, estimated_payout,
  (payout_tier * confidence) AS rank,
  payout_tier, 'clear'::text AS dedupe_status, evidence_sha, evidence_steps
FROM ranked
WHERE payout_tier > 0;

CREATE OR REPLACE VIEW triage_suppressed AS
SELECT id, program_id, status, finding_type, location, dedupe_status
FROM (
  SELECT
    f.id,
    f.program_id,
    f.status,
    COALESCE(f.body->>'findingType', f.body->>'type', '') AS finding_type,
    COALESCE(f.body->>'location', '') AS location,
    CASE
      WHEN EXISTS (
        SELECT 1 FROM findings prior
        WHERE prior.program_id = f.program_id
          AND prior.status = 'SUBMITTED'
          AND prior.id <> f.id
          AND COALESCE(prior.body->>'findingType', prior.body->>'type', '') = COALESCE(f.body->>'findingType', f.body->>'type', '')
          AND COALESCE(prior.body->>'location', '') = COALESCE(f.body->>'location', '')
      ) OR EXISTS (
        SELECT 1 FROM submissions s
        JOIN findings sent ON sent.id = s.finding_id
        WHERE s.program_id = f.program_id
          AND s.status IN ('submitted', 'triaged', 'accepted', 'duplicate', 'informational', 'paid')
          AND sent.id <> f.id
          AND COALESCE(sent.body->>'findingType', sent.body->>'type', '') = COALESCE(f.body->>'findingType', f.body->>'type', '')
          AND COALESCE(sent.body->>'location', '') = COALESCE(f.body->>'location', '')
      ) THEN 'prior_submission'
      WHEN EXISTS (
        SELECT 1 FROM known_issues k
        WHERE k.program_id = f.program_id
          AND k.finding_type = COALESCE(f.body->>'findingType', f.body->>'type', '')
          AND k.location = COALESCE(f.body->>'location', '')
      ) THEN 'known_issue'
      ELSE NULL
    END AS dedupe_status
  FROM findings f
  WHERE f.status IN ('HUMAN_REVIEW', 'VERIFIED')
) flagged
WHERE dedupe_status IS NOT NULL;
