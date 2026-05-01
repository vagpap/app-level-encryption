-- Enables pgcrypto before UUID default usage and creates secured_entities schema.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS secured_entities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_info TEXT NOT NULL,
    secret_cipher TEXT NOT NULL,
    secret_dek TEXT NOT NULL,
    secret_bidx VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_secured_entities_secret_bidx
    ON secured_entities (secret_bidx);
