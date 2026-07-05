use chrono::{Duration as ChronoDuration, Utc};
use sqlx::PgPool;
use tokio::time::{interval, MissedTickBehavior};

use crate::{
    config::AppConfig,
    storage::{db, files},
};

/// Starts the retention loop without blocking server startup.
pub fn spawn_cleanup_task(pool: PgPool, config: AppConfig) {
    tokio::spawn(async move {
        let mut ticker = interval(config.cleanup_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            if let Err(error) = cleanup_once(&pool, &config).await {
                tracing::error!(%error, "file retention cleanup failed");
            }
        }
    });
}

/// Deletes expired physical files in bounded batches and keeps DB metadata intact.
async fn cleanup_once(pool: &PgPool, config: &AppConfig) -> anyhow::Result<()> {
    let retention = ChronoDuration::from_std(config.file_retention)?;
    let cutoff = Utc::now() - retention;
    let expired_files = db::list_expired_files(pool, cutoff).await?;

    for expired_file in expired_files {
        let path = std::path::Path::new(&expired_file.storage_path);
        files::delete_jar(path).await?;
        db::mark_file_deleted(pool, expired_file.id).await?;
        tracing::info!(scan_id = %expired_file.id, path = %expired_file.storage_path, "deleted expired jar file");
    }
    Ok(())
}
