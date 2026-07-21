CREATE TABLE scan_decoded_strings (
    id bigserial PRIMARY KEY,
    scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    original_value text NOT NULL,
    decoder_method text NOT NULL,
    decoded_value text NOT NULL,
    confidence text NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    evidence jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX scan_decoded_strings_scan_id_idx ON scan_decoded_strings (scan_id);

CREATE TABLE scan_text_resources (
    id bigserial PRIMARY KEY,
    scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    archive_id text NOT NULL,
    archive_path text NOT NULL,
    resource_path text NOT NULL,
    detected_encoding text NOT NULL,
    confidence text NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX scan_text_resources_scan_id_idx ON scan_text_resources (scan_id);
