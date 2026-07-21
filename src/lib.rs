//! RatScan HTTP API service composition.

pub mod api;
pub mod config;
pub mod error;
pub mod models;
pub mod response;
pub mod storage;
pub mod virustotal;

pub use ratscan_core::{rules, scanner};

use config::AppConfig;
use sqlx::PgPool;

/// Initializes structured logging once before service startup.
pub fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Opens Postgres and applies the single shared migration history.
pub async fn connect_database(config: &AppConfig) -> anyhow::Result<PgPool> {
    let pool = PgPool::connect(&config.database_url).await?;
    storage::db::run_migrations(&pool).await?;
    Ok(pool)
}

/// Starts the API; Discord Gateway remains a distinct process.
pub async fn serve() -> anyhow::Result<()> {
    let config = AppConfig::from_env()?;
    let pool = connect_database(&config).await?;
    tokio::fs::create_dir_all(&config.storage_dir).await?;
    let rules_engine = rules::engine::RulesEngine::load_from_file(&config.rules_path)?;
    let app_state = api::AppState::new(pool.clone(), config.clone(), rules_engine);
    storage::cleanup::spawn_cleanup_task(pool, config.clone());
    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    tracing::info!(bind_addr = %config.bind_addr, "RatScan API listening");
    axum::serve(listener, api::router(app_state)).await?;
    Ok(())
}

/// Runs the API process after logging setup.
pub async fn run() -> anyhow::Result<()> {
    init_tracing();
    serve().await
}
