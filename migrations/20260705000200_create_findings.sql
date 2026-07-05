CREATE TABLE findings (
    id bigserial PRIMARY KEY,
    scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id text NOT NULL,
    category text NOT NULL,
    severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    message text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX findings_scan_id_idx ON findings (scan_id);
