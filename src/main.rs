mod api;
mod auth;
mod config;
mod error;
mod models;
mod response;
mod rules;
mod scanner;
mod storage;

use base64::Engine;
use clap::{Parser, Subcommand};
use config::AppConfig;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use storage::db;
use tracing::{info, warn};

/// Command line entrypoint for serving the API or provisioning internal API keys.
#[derive(Debug, Parser)]
#[command(
    name = "ratscan",
    version,
    about = "Static scanner API for Minecraft jar mods"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Supported operational commands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Start the HTTP API and background cleanup worker.
    Serve,
    /// Generate one internal API key, store only its sha256 hash, and print the raw key once.
    SeedApiKey {
        #[arg(long)]
        label: String,
    },
}

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

/// Generates a high-entropy internal key and returns both the printable key and its sha256 hash.
fn generate_api_key() -> (String, String) {
    let mut random_bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut random_bytes);
    let raw_key = format!(
        "rscan_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes)
    );
    let key_hash = hex::encode(Sha256::digest(raw_key.as_bytes()));
    (raw_key, key_hash)
}

/// Creates one internal API key and prints the raw secret exactly once for operator storage.
async fn seed_api_key(label: String) -> anyhow::Result<()> {
    let config = AppConfig::from_env()?;
    let pool = connect_database(&config).await?;
    let (raw_key, key_hash) = generate_api_key();
    db::insert_api_key(&pool, &label, &key_hash, "internal", None).await?;
    println!("{raw_key}");
    warn!(
        label = %label,
        "raw API key was printed once; only its sha256 hash is stored"
    );
    Ok(())
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
    match Cli::parse().command {
        Command::Serve => serve().await,
        Command::SeedApiKey { label } => seed_api_key(label).await,
    }
}
