use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

use crate::scanner::archive::ScanLimits;

const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8080";
const DEFAULT_RULES_PATH: &str = "config/rules.yaml";
const DEFAULT_STORAGE_DIR: &str = "storage";
const DEFAULT_MAX_TOTAL_UNCOMPRESSED_MB: u64 = 200;
const DEFAULT_MAX_FILES_IN_ARCHIVE: usize = 5_000;
const DEFAULT_MAX_NESTING_DEPTH: usize = 3;
const DEFAULT_MAX_SINGLE_FILE_MB: u64 = 50;
const DEFAULT_FILE_RETENTION_DAYS: u64 = 7;
const DEFAULT_FILE_CLEANUP_INTERVAL_MINUTES: u64 = 60;

/// Runtime configuration loaded from environment variables with named defaults from the spec.
#[derive(Clone, Debug)]
pub struct AppConfig {
    pub database_url: String,
    pub bind_addr: SocketAddr,
    pub rules_path: PathBuf,
    pub storage_dir: PathBuf,
    pub scan_limits: ScanLimits,
    pub file_retention: Duration,
    pub cleanup_interval: Duration,
    pub upload_max_bytes: usize,
}

impl AppConfig {
    /// Loads all configuration at process start so invalid values fail fast before serving traffic.
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = env::var("DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("DATABASE_URL environment variable is required"))?;
        let bind_addr = env_string("RATSCAN_BIND_ADDR", DEFAULT_BIND_ADDR).parse()?;
        let rules_path = PathBuf::from(env_string("RATSCAN_RULES_PATH", DEFAULT_RULES_PATH));
        let storage_dir = PathBuf::from(env_string("RATSCAN_STORAGE_DIR", DEFAULT_STORAGE_DIR));

        let scan_limits = ScanLimits {
            max_total_uncompressed_bytes: mb_to_bytes(env_u64(
                "MAX_TOTAL_UNCOMPRESSED_MB",
                DEFAULT_MAX_TOTAL_UNCOMPRESSED_MB,
            )?),
            max_files_in_archive: env_usize("MAX_FILES_IN_ARCHIVE", DEFAULT_MAX_FILES_IN_ARCHIVE)?,
            max_nesting_depth: env_usize("MAX_NESTING_DEPTH", DEFAULT_MAX_NESTING_DEPTH)?,
            max_single_file_bytes: mb_to_bytes(env_u64(
                "MAX_SINGLE_FILE_MB",
                DEFAULT_MAX_SINGLE_FILE_MB,
            )?),
        };

        let file_retention = Duration::from_secs(
            env_u64("FILE_RETENTION_DAYS", DEFAULT_FILE_RETENTION_DAYS)? * 86_400,
        );
        let cleanup_interval = Duration::from_secs(
            env_u64(
                "FILE_CLEANUP_INTERVAL_MINUTES",
                DEFAULT_FILE_CLEANUP_INTERVAL_MINUTES,
            )? * 60,
        );

        Ok(Self {
            database_url,
            bind_addr,
            rules_path,
            storage_dir,
            upload_max_bytes: scan_limits.max_total_uncompressed_bytes as usize,
            scan_limits,
            file_retention,
            cleanup_interval,
        })
    }
}

/// Reads a string environment variable or falls back to the explicit default.
fn env_string(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

/// Reads a u64 environment variable with a named default and explicit parse errors.
fn env_u64(name: &str, default: u64) -> anyhow::Result<u64> {
    env::var(name)
        .map(|value| value.parse::<u64>())
        .unwrap_or(Ok(default))
        .map_err(|error| anyhow::anyhow!("{name} must be an unsigned integer: {error}"))
}

/// Reads a usize environment variable with a named default and explicit parse errors.
fn env_usize(name: &str, default: usize) -> anyhow::Result<usize> {
    env::var(name)
        .map(|value| value.parse::<usize>())
        .unwrap_or(Ok(default))
        .map_err(|error| anyhow::anyhow!("{name} must be an unsigned integer: {error}"))
}

/// Converts megabytes to bytes in one place to avoid anonymous numeric multipliers in scanners.
fn mb_to_bytes(megabytes: u64) -> u64 {
    megabytes * 1024 * 1024
}
