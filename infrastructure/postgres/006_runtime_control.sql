-- Fleet kill switch and a database guard on verified or submitted findings.
-- The application role can insert observations and human-review rows. VERIFIED and SUBMITTED
-- require a transaction-local actor set by the verifier or the human reviewer.

CREATE TABLE IF NOT EXISTS runtime_control (
  id integer PRIMARY KEY CHECK (id = 1),
  global_kill boolean NOT NULL DEFAULT false,
  epoch bigint NOT NULL DEFAULT 0
);
INSERT INTO runtime_control(id) VALUES (1) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS revoked_programs (
  program_id text PRIMARY KEY REFERENCES programs(id)
);

CREATE OR REPLACE FUNCTION findings_actor_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status = 'VERIFIED' AND current_setting('anteater.actor', true) IS DISTINCT FROM 'verifier' THEN
    RAISE EXCEPTION 'verifier_required';
  END IF;
  IF NEW.status = 'SUBMITTED' AND current_setting('anteater.actor', true) IS DISTINCT FROM 'human' THEN
    RAISE EXCEPTION 'human_required';
  END IF;
  IF NEW.status = 'SUBMITTED' AND (NEW.human_reviewer IS NULL OR length(btrim(NEW.human_reviewer)) = 0) THEN
    RAISE EXCEPTION 'human_reviewer_required';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS findings_actor_guard ON findings;
CREATE TRIGGER findings_actor_guard BEFORE INSERT OR UPDATE ON findings
  FOR EACH ROW EXECUTE FUNCTION findings_actor_guard();
