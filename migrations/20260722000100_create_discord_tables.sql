CREATE TABLE discord_guild_config (
    guild_id BIGINT PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    log_channel_id BIGINT NULL,
    error_channel_id BIGINT NULL,
    danger_role_id BIGINT NULL,
    report_virustotal BOOLEAN NOT NULL DEFAULT TRUE,
    report_behavior BOOLEAN NOT NULL DEFAULT TRUE,
    coverage_warning_threshold SMALLINT NOT NULL DEFAULT 80
        CHECK (coverage_warning_threshold >= 0 AND coverage_warning_threshold <= 100)
);

CREATE TABLE discord_allowed_channels (
    guild_id BIGINT NOT NULL REFERENCES discord_guild_config(guild_id) ON DELETE CASCADE,
    channel_id BIGINT NOT NULL,
    PRIMARY KEY (guild_id, channel_id)
);

CREATE TABLE discord_allowed_categories (
    guild_id BIGINT NOT NULL REFERENCES discord_guild_config(guild_id) ON DELETE CASCADE,
    category_id BIGINT NOT NULL,
    PRIMARY KEY (guild_id, category_id)
);

CREATE TABLE discord_danger_users (
    guild_id BIGINT NOT NULL REFERENCES discord_guild_config(guild_id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL,
    PRIMARY KEY (guild_id, user_id)
);

CREATE TABLE discord_scan_context (
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    guild_id BIGINT NOT NULL,
    channel_id BIGINT NOT NULL,
    message_id BIGINT NOT NULL,
    thread_id BIGINT NULL,
    author_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scan_id, message_id)
);

CREATE INDEX discord_scan_context_scan_id_idx ON discord_scan_context (scan_id);
CREATE INDEX discord_scan_context_guild_id_idx ON discord_scan_context (guild_id);
CREATE INDEX discord_scan_context_author_id_idx ON discord_scan_context (author_id);
CREATE INDEX discord_scan_context_created_at_idx ON discord_scan_context (created_at);
