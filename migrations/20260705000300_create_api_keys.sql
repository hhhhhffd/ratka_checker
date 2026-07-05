CREATE TABLE api_keys (
    id uuid PRIMARY KEY,
    key_hash text NOT NULL UNIQUE,
    role text NOT NULL CHECK (role IN ('internal', 'public')),
    label text NOT NULL,
    rate_limit int NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz NULL
);

CREATE INDEX api_keys_active_hash_idx ON api_keys (key_hash) WHERE revoked_at IS NULL;
