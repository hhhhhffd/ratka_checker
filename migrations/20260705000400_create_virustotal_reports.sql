CREATE TABLE virustotal_reports (
    sha256 text PRIMARY KEY,
    report_json jsonb NOT NULL,
    fetched_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX virustotal_reports_expires_at_idx ON virustotal_reports (expires_at);
