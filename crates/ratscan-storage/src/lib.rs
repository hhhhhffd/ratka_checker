//! PostgreSQL access used by RatScan service binaries.

use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordGuildConfig {
    pub enabled: bool,
    pub log_channel_id: Option<i64>,
    pub error_channel_id: Option<i64>,
    pub danger_role_id: Option<i64>,
    pub report_virustotal: bool,
    pub report_behavior: bool,
    pub coverage_warning_threshold: u8,
}

impl Default for DiscordGuildConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_channel_id: None,
            error_channel_id: None,
            danger_role_id: None,
            report_virustotal: true,
            report_behavior: true,
            coverage_warning_threshold: 80,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordScanContext {
    pub scan_id: Uuid,
    pub guild_id: i64,
    pub channel_id: i64,
    pub message_id: i64,
    pub thread_id: Option<i64>,
    pub author_id: i64,
}

/// Reusable Discord persistence facade. API migrations own schema creation; this type never does DDL.
#[derive(Clone)]
pub struct DiscordStorage {
    pool: PgPool,
}

impl DiscordStorage {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn guild_config(&self, guild_id: i64) -> anyhow::Result<DiscordGuildConfig> {
        sqlx::query(
            "INSERT INTO discord_guild_config (guild_id) VALUES ($1) ON CONFLICT DO NOTHING",
        )
        .bind(guild_id)
        .execute(&self.pool)
        .await?;
        let row = sqlx::query_as::<_, GuildConfigRow>(
            "SELECT enabled, log_channel_id, error_channel_id, danger_role_id, report_virustotal, report_behavior, coverage_warning_threshold FROM discord_guild_config WHERE guild_id = $1",
        )
        .bind(guild_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    pub async fn is_allowed(
        &self,
        guild_id: i64,
        channel_id: i64,
        category_id: Option<i64>,
    ) -> anyhow::Result<bool> {
        let allowed = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM discord_allowed_channels WHERE guild_id = $1 AND channel_id = $2) OR ($3::BIGINT IS NOT NULL AND EXISTS (SELECT 1 FROM discord_allowed_categories WHERE guild_id = $1 AND category_id = $3))",
        )
        .bind(guild_id)
        .bind(channel_id)
        .bind(category_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(allowed)
    }

    pub async fn insert_scan_context(&self, context: &DiscordScanContext) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "INSERT INTO discord_scan_context (scan_id, guild_id, channel_id, message_id, thread_id, author_id) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
        )
        .bind(context.scan_id)
        .bind(context.guild_id)
        .bind(context.channel_id)
        .bind(context.message_id)
        .bind(context.thread_id)
        .bind(context.author_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }
}

#[derive(sqlx::FromRow)]
struct GuildConfigRow {
    enabled: bool,
    log_channel_id: Option<i64>,
    error_channel_id: Option<i64>,
    danger_role_id: Option<i64>,
    report_virustotal: bool,
    report_behavior: bool,
    coverage_warning_threshold: i16,
}

impl From<GuildConfigRow> for DiscordGuildConfig {
    fn from(row: GuildConfigRow) -> Self {
        Self {
            enabled: row.enabled,
            log_channel_id: row.log_channel_id,
            error_channel_id: row.error_channel_id,
            danger_role_id: row.danger_role_id,
            report_virustotal: row.report_virustotal,
            report_behavior: row.report_behavior,
            coverage_warning_threshold: row.coverage_warning_threshold.try_into().unwrap_or(80),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DiscordGuildConfig;

    #[test]
    fn default_config_preserves_legacy_visibility_defaults() {
        let config = DiscordGuildConfig::default();
        assert!(config.enabled && config.report_virustotal && config.report_behavior);
        assert_eq!(config.coverage_warning_threshold, 80);
    }
}
