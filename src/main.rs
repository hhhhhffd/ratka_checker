mod api;
mod config;
mod error;
mod models;
mod response;
mod rules;
mod scanner;
mod storage;
mod virustotal;

use config::AppConfig;
use sqlx::PgPool;
use storage::db;
use tracing::info;

/// Initializes tracing before any command work so startup failures have structured context.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Opens the configured Postgres pool and applies embedded migrations before use.
async fn connect_database(config: &AppConfig) -> anyhow::Result<PgPool> {
    let pool = PgPool::connect(&config.database_url).await?;
    db::run_migrations(&pool).await?;
    Ok(pool)
}

/// Boots the API server, loads rules once, and starts retention cleanup alongside HTTP serving.
async fn serve() -> anyhow::Result<()> {
    let config = AppConfig::from_env()?;
    let pool = connect_database(&config).await?;
    tokio::fs::create_dir_all(&config.storage_dir).await?;

    let rules_engine = rules::engine::RulesEngine::load_from_file(&config.rules_path)?;
    let app_state = api::AppState::new(pool.clone(), config.clone(), rules_engine);
    storage::cleanup::spawn_cleanup_task(pool, config.clone());

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    info!(bind_addr = %config.bind_addr, "RatScan API listening");
    axum::serve(listener, api::router(app_state)).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    serve().await
}
