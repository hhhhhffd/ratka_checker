//! Optional Telegram worker supervised by the RatScan API process.
//!
//! The Telegram implementation runs in Rust, but it is a child of
//! the API binary: systemd and Docker run one RatScan service only. A failed
//! Telegram worker is restarted without taking down the HTTP API.

use std::{env, time::Duration};

use tokio::{process::Command, task::JoinHandle, time::sleep};
use tracing::{info, warn};

mod bot;

pub(crate) const WORKER_ARGUMENT: &str = "--telegram-worker";

pub(crate) async fn run_worker() -> anyhow::Result<()> {
    bot::run().await
}

const RESTART_DELAY: Duration = Duration::from_secs(5);

pub fn spawn_if_configured() -> Option<JoinHandle<()>> {
    if !is_configured(
        env::var("TG_BOT_TOKEN").ok().as_deref(),
        env::var("ALLOWED_TG_ID").ok().as_deref(),
    ) {
        info!("Telegram worker is disabled: TG_BOT_TOKEN or ALLOWED_TG_ID is absent");
        return None;
    }

    Some(tokio::spawn(supervise()))
}

fn is_configured(token: Option<&str>, allowed_user_id: Option<&str>) -> bool {
    token.is_some_and(|value| !value.trim().is_empty())
        && allowed_user_id.is_some_and(|value| !value.trim().is_empty())
}

async fn supervise() {
    loop {
        let executable = match env::current_exe() {
            Ok(executable) => executable,
            Err(error) => {
                warn!(%error, "failed to locate Telegram worker executable");
                sleep(RESTART_DELAY).await;
                continue;
            }
        };
        let mut child = match Command::new(executable)
            .arg(WORKER_ARGUMENT)
            .kill_on_drop(true)
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                warn!(%error, "failed to start Telegram worker");
                sleep(RESTART_DELAY).await;
                continue;
            }
        };

        info!(pid = ?child.id(), "Telegram worker started");
        match child.wait().await {
            Ok(status) => warn!(%status, "Telegram worker exited; restarting it"),
            Err(error) => warn!(%error, "failed while waiting for Telegram worker; restarting it"),
        }
        sleep(RESTART_DELAY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::is_configured;

    #[test]
    fn telegram_requires_both_credentials() {
        assert!(is_configured(Some("token"), Some("123")));
        assert!(!is_configured(Some(""), Some("123")));
        assert!(!is_configured(Some("token"), None));
    }
}
