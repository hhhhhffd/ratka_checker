CREATE TABLE scans (
    id uuid PRIMARY KEY,
    original_filename text NOT NULL,
    sha256 text NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'done', 'failed')),
    verdict text NULL CHECK (verdict IN ('clean', 'suspicious', 'malicious', 'unknown')),
    risk_score int NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    summary text NOT NULL DEFAULT '',
    error_code text NULL,
    error_message text NULL,
    storage_path text NOT NULL,
    file_deleted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz NULL
);

CREATE INDEX scans_sha256_idx ON scans (sha256);
CREATE INDEX scans_status_idx ON scans (status);
CREATE INDEX scans_retention_idx ON scans (created_at, file_deleted);
