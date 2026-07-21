ALTER TABLE scans
    ADD COLUMN analysis_coverage jsonb NOT NULL
        DEFAULT '{"score":0,"total_classes":0,"parsed_classes":0,"total_resources":0,"analyzed_resources":0}'::jsonb;
