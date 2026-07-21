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

    pub async fn set_enabled(&self, guild_id: i64, enabled: bool) -> anyhow::Result<()> {
        self.ensure_guild_config(guild_id).await?;
        self.update_config(guild_id, "enabled", enabled).await
    }

    pub async fn set_log_channel(
        &self,
        guild_id: i64,
        channel_id: Option<i64>,
    ) -> anyhow::Result<()> {
        self.ensure_guild_config(guild_id).await?;
        sqlx::query("UPDATE discord_guild_config SET log_channel_id = $2 WHERE guild_id = $1")
            .bind(guild_id)
            .bind(channel_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_error_channel(
        &self,
        guild_id: i64,
        channel_id: Option<i64>,
    ) -> anyhow::Result<()> {
        self.ensure_guild_config(guild_id).await?;
        sqlx::query("UPDATE discord_guild_config SET error_channel_id = $2 WHERE guild_id = $1")
            .bind(guild_id)
            .bind(channel_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_danger_role(&self, guild_id: i64, role_id: Option<i64>) -> anyhow::Result<()> {
        self.ensure_guild_config(guild_id).await?;
        sqlx::query("UPDATE discord_guild_config SET danger_role_id = $2 WHERE guild_id = $1")
            .bind(guild_id)
            .bind(role_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_report_virustotal(&self, guild_id: i64, enabled: bool) -> anyhow::Result<()> {
        self.ensure_guild_config(guild_id).await?;
        self.update_config(guild_id, "report_virustotal", enabled)
            .await
    }

    pub async fn set_report_behavior(&self, guild_id: i64, enabled: bool) -> anyhow::Result<()> {
        self.ensure_guild_config(guild_id).await?;
        self.update_config(guild_id, "report_behavior", enabled)
            .await
    }

    pub async fn set_coverage_warning_threshold(
        &self,
        guild_id: i64,
        threshold: u8,
    ) -> anyhow::Result<()> {
        self.ensure_guild_config(guild_id).await?;
        sqlx::query(
            "UPDATE discord_guild_config SET coverage_warning_threshold = $2 WHERE guild_id = $1",
        )
        .bind(guild_id)
        .bind(i16::from(threshold))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_allowed_channels(&self, guild_id: i64) -> anyhow::Result<Vec<i64>> {
        self.list_ids("discord_allowed_channels", "channel_id", guild_id)
            .await
    }

    pub async fn add_allowed_channel(&self, guild_id: i64, channel_id: i64) -> anyhow::Result<()> {
        self.add_id(
            "discord_allowed_channels",
            "channel_id",
            guild_id,
            channel_id,
        )
        .await
    }

    pub async fn remove_allowed_channel(
        &self,
        guild_id: i64,
        channel_id: i64,
    ) -> anyhow::Result<()> {
        self.remove_id(
            "discord_allowed_channels",
            "channel_id",
            guild_id,
            channel_id,
        )
        .await
    }

    pub async fn list_allowed_categories(&self, guild_id: i64) -> anyhow::Result<Vec<i64>> {
        self.list_ids("discord_allowed_categories", "category_id", guild_id)
            .await
    }

    pub async fn add_allowed_category(
        &self,
        guild_id: i64,
        category_id: i64,
    ) -> anyhow::Result<()> {
        self.add_id(
            "discord_allowed_categories",
            "category_id",
            guild_id,
            category_id,
        )
        .await
    }

    pub async fn remove_allowed_category(
        &self,
        guild_id: i64,
        category_id: i64,
    ) -> anyhow::Result<()> {
        self.remove_id(
            "discord_allowed_categories",
            "category_id",
            guild_id,
            category_id,
        )
        .await
    }

    pub async fn list_danger_users(&self, guild_id: i64) -> anyhow::Result<Vec<i64>> {
        self.list_ids("discord_danger_users", "user_id", guild_id)
            .await
    }

    pub async fn add_danger_user(&self, guild_id: i64, user_id: i64) -> anyhow::Result<()> {
        self.add_id("discord_danger_users", "user_id", guild_id, user_id)
            .await
    }

    pub async fn remove_danger_user(&self, guild_id: i64, user_id: i64) -> anyhow::Result<()> {
        self.remove_id("discord_danger_users", "user_id", guild_id, user_id)
            .await
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

    async fn ensure_guild_config(&self, guild_id: i64) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO discord_guild_config (guild_id) VALUES ($1) ON CONFLICT DO NOTHING",
        )
        .bind(guild_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_config(&self, guild_id: i64, field: &str, value: bool) -> anyhow::Result<()> {
        let query = match field {
            "enabled" => "UPDATE discord_guild_config SET enabled = $2 WHERE guild_id = $1",
            "report_virustotal" => {
                "UPDATE discord_guild_config SET report_virustotal = $2 WHERE guild_id = $1"
            }
            "report_behavior" => {
                "UPDATE discord_guild_config SET report_behavior = $2 WHERE guild_id = $1"
            }
            _ => return Err(anyhow::anyhow!("unsupported Discord configuration field")),
        };
        sqlx::query(query)
            .bind(guild_id)
            .bind(value)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_ids(&self, table: &str, column: &str, guild_id: i64) -> anyhow::Result<Vec<i64>> {
        let query = relation_query(table, column, "SELECT", "");
        Ok(sqlx::query_scalar(&query)
            .bind(guild_id)
            .fetch_all(&self.pool)
            .await?)
    }

    async fn add_id(
        &self,
        table: &str,
        column: &str,
        guild_id: i64,
        value: i64,
    ) -> anyhow::Result<()> {
        self.ensure_guild_config(guild_id).await?;
        let query = relation_query(table, column, "INSERT", " ON CONFLICT DO NOTHING");
        sqlx::query(&query)
            .bind(guild_id)
            .bind(value)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn remove_id(
        &self,
        table: &str,
        column: &str,
        guild_id: i64,
        value: i64,
    ) -> anyhow::Result<()> {
        let query = relation_query(table, column, "DELETE", "");
        sqlx::query(&query)
            .bind(guild_id)
            .bind(value)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn relation_query(table: &str, column: &str, action: &str, suffix: &str) -> String {
    match (table, column, action) {
        ("discord_allowed_channels", "channel_id", "SELECT") => "SELECT channel_id FROM discord_allowed_channels WHERE guild_id = $1 ORDER BY channel_id".into(),
        ("discord_allowed_categories", "category_id", "SELECT") => "SELECT category_id FROM discord_allowed_categories WHERE guild_id = $1 ORDER BY category_id".into(),
        ("discord_danger_users", "user_id", "SELECT") => "SELECT user_id FROM discord_danger_users WHERE guild_id = $1 ORDER BY user_id".into(),
        ("discord_allowed_channels", "channel_id", "INSERT") => format!("INSERT INTO discord_allowed_channels (guild_id, channel_id) VALUES ($1, $2){suffix}"),
        ("discord_allowed_categories", "category_id", "INSERT") => format!("INSERT INTO discord_allowed_categories (guild_id, category_id) VALUES ($1, $2){suffix}"),
        ("discord_danger_users", "user_id", "INSERT") => format!("INSERT INTO discord_danger_users (guild_id, user_id) VALUES ($1, $2){suffix}"),
        ("discord_allowed_channels", "channel_id", "DELETE") => "DELETE FROM discord_allowed_channels WHERE guild_id = $1 AND channel_id = $2".into(),
        ("discord_allowed_categories", "category_id", "DELETE") => "DELETE FROM discord_allowed_categories WHERE guild_id = $1 AND category_id = $2".into(),
        ("discord_danger_users", "user_id", "DELETE") => "DELETE FROM discord_danger_users WHERE guild_id = $1 AND user_id = $2".into(),
        _ => unreachable!("all Discord storage relations are fixed by callers"),
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

    #[test]
    fn settings_crud_uses_fixed_relations_without_dynamic_sql_input() {
        assert_eq!(
            super::relation_query("discord_allowed_channels", "channel_id", "INSERT", " ON CONFLICT DO NOTHING"),
            "INSERT INTO discord_allowed_channels (guild_id, channel_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
        );
        assert_eq!(
            super::relation_query("discord_danger_users", "user_id", "DELETE", ""),
            "DELETE FROM discord_danger_users WHERE guild_id = $1 AND user_id = $2"
        );
    }
}
