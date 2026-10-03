-- Survives job failures, process interruption, and observation retention.
CREATE TABLE resource_cleanup (
  id uuid PRIMARY KEY,
  program_id text NOT NULL REFERENCES programs(id),
  intent jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX resource_cleanup_program ON resource_cleanup(program_id, created_at);
