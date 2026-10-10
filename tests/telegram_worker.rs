use std::process::Command;

#[test]
fn telegram_worker_mode_validates_bot_config_without_starting_api() {
    let directory = tempfile::tempdir().expect("create worker test directory");
    let output = Command::new(env!("CARGO_BIN_EXE_ratscan"))
        .arg("--telegram-worker")
        .current_dir(directory.path())
        .env_clear()
        .env("TG_BOT_TOKEN", "")
        .env("ALLOWED_TG_ID", "")
        .output()
        .expect("run Telegram worker binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "worker accepted missing credentials"
    );
    assert!(stderr.contains("TG_BOT_TOKEN is required"), "{stderr}");
    assert!(
        !stderr.contains("DATABASE_URL"),
        "worker attempted to start API: {stderr}"
    );
}

#[test]
fn api_mode_requires_database_configuration_when_telegram_is_disabled() {
    let directory = tempfile::tempdir().expect("create API test directory");
    let output = Command::new(env!("CARGO_BIN_EXE_ratscan"))
        .current_dir(directory.path())
        .env_clear()
        .output()
        .expect("run API binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "API accepted missing database configuration"
    );
    assert!(
        stderr.contains("DATABASE_URL environment variable is required"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("TG_BOT_TOKEN is required"),
        "API attempted to start unconfigured worker: {stderr}"
    );
}
