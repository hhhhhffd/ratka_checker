ALTER TABLE scans
    ADD COLUMN confidence text NOT NULL DEFAULT 'medium'
        CHECK (confidence IN ('low', 'medium', 'high')),
    ADD COLUMN obfuscation jsonb NOT NULL DEFAULT '{"level":"none","score":0,"signals":[]}'::jsonb;

ALTER TABLE findings
    ADD COLUMN finding_kind text NOT NULL DEFAULT 'finding'
        CHECK (finding_kind IN ('finding', 'heuristic', 'native', 'virustotal')),
    ADD COLUMN confidence text NOT NULL DEFAULT 'medium'
        CHECK (confidence IN ('low', 'medium', 'high')),
    ADD COLUMN score_contribution int NOT NULL DEFAULT 0
        CHECK (score_contribution >= 0 AND score_contribution <= 100),
    ADD COLUMN scope text NOT NULL DEFAULT 'unknown'
        CHECK (scope IN ('first_party', 'bundled_dependency', 'nested_mod', 'generated_code', 'metadata', 'resource', 'unknown')),
    ADD COLUMN evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN chain_id text NULL;

UPDATE findings
SET score_contribution = CASE severity
    WHEN 'low' THEN 5
    WHEN 'medium' THEN 15
    WHEN 'high' THEN 30
    WHEN 'critical' THEN 50
END
WHERE score_contribution = 0;

CREATE TABLE scan_capabilities (
    id bigserial PRIMARY KEY,
    scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id text NOT NULL,
    message text NOT NULL,
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX scan_capabilities_scan_id_idx ON scan_capabilities (scan_id);

CREATE TABLE confirmed_chains (
    id bigserial PRIMARY KEY,
    scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    chain_id text NOT NULL,
    rule_id text NOT NULL,
    severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence text NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    score_contribution int NOT NULL CHECK (score_contribution >= 0 AND score_contribution <= 100),
    operations jsonb NOT NULL,
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scan_id, chain_id)
);

CREATE INDEX confirmed_chains_scan_id_idx ON confirmed_chains (scan_id);

CREATE TABLE scan_limitations (
    id bigserial PRIMARY KEY,
    scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    code text NOT NULL,
    message text NOT NULL,
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX scan_limitations_scan_id_idx ON scan_limitations (scan_id);
