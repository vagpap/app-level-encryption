-- Adds per-row KEK version tracking for wrapped DEKs.

ALTER TABLE secured_entities
    ADD COLUMN IF NOT EXISTS secret_kek_version INTEGER;

UPDATE secured_entities
SET secret_kek_version = COALESCE((substring(secret_dek from '^vault:v([0-9]+):'))::INTEGER, 1)
WHERE secret_kek_version IS NULL;

ALTER TABLE secured_entities
    ALTER COLUMN secret_kek_version SET DEFAULT 1;

ALTER TABLE secured_entities
    ALTER COLUMN secret_kek_version SET NOT NULL;
