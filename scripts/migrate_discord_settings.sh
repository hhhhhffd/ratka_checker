#!/usr/bin/env bash
set -euo pipefail

# Imports only the legacy Discord settings tables. Scan history is intentionally
# excluded: legacy `scans` rows cannot be reliably related to UUID scan records.
: "${DATABASE_URL:?DATABASE_URL is required}"

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;

WITH inserted AS (
    INSERT INTO discord_guild_config (
        guild_id, enabled, log_channel_id, error_channel_id, danger_role_id,
        report_virustotal, report_behavior
    )
    SELECT guild_id, enabled, log_channel_id, error_channel_id, danger_role_id,
           report_virustotal, report_behavior
    FROM guild_bot_config
    ON CONFLICT (guild_id) DO UPDATE SET
        enabled = EXCLUDED.enabled,
        log_channel_id = EXCLUDED.log_channel_id,
        error_channel_id = EXCLUDED.error_channel_id,
        danger_role_id = EXCLUDED.danger_role_id,
        report_virustotal = EXCLUDED.report_virustotal,
        report_behavior = EXCLUDED.report_behavior
    RETURNING 1
)
SELECT 'discord_guild_config: ' || count(*) FROM inserted;

WITH inserted AS (
    INSERT INTO discord_allowed_channels (guild_id, channel_id)
    SELECT guild_id, channel_id FROM guild_allowed_channels
    ON CONFLICT DO NOTHING
    RETURNING 1
)
SELECT 'discord_allowed_channels: ' || count(*) FROM inserted;

WITH inserted AS (
    INSERT INTO discord_allowed_categories (guild_id, category_id)
    SELECT guild_id, category_id FROM guild_allowed_categories
    ON CONFLICT DO NOTHING
    RETURNING 1
)
SELECT 'discord_allowed_categories: ' || count(*) FROM inserted;

WITH inserted AS (
    INSERT INTO discord_danger_users (guild_id, user_id)
    SELECT guild_id, user_id FROM guild_danger_users
    ON CONFLICT DO NOTHING
    RETURNING 1
)
SELECT 'discord_danger_users: ' || count(*) FROM inserted;

COMMIT;
SQL
