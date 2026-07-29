//! Optional Telegram worker supervised by the RatScan API process.
//!
//! The Telegram implementation remains a Python module, but it is a child of
//! the API binary: systemd and Docker run one RatScan service only. A failed
//! Telegram worker is restarted without taking down the HTTP API.

use std::{env, time::Duration};

use tokio::{process::Command, task::JoinHandle, time::sleep};
use tracing::{info, warn};

const RESTART_DELAY: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq)]
struct TelegramProcessConfig {
    python: String,
}

pub fn spawn_if_configured() -> Option<JoinHandle<()>> {
    if !is_configured(
        env::var("TG_BOT_TOKEN").ok().as_deref(),
        env::var("ALLOWED_TG_ID").ok().as_deref(),
    ) {
        info!("Telegram worker is disabled: TG_BOT_TOKEN or ALLOWED_TG_ID is absent");
        return None;
    }

    let config = TelegramProcessConfig {
        python: env::var("RATSCAN_TELEGRAM_PYTHON")
            .unwrap_or_else(|_| "telegram-venv/bin/python".to_owned()),
    };
    Some(tokio::spawn(supervise(config)))
}

fn is_configured(token: Option<&str>, allowed_user_id: Option<&str>) -> bool {
    token.is_some_and(|value| !value.trim().is_empty())
        && allowed_user_id.is_some_and(|value| !value.trim().is_empty())
}

async fn supervise(config: TelegramProcessConfig) {
    loop {
        let mut child = match Command::new(&config.python)
            .args(["-m", "telegram_bot.bot"])
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                warn!(%error, python = %config.python, "failed to start Telegram worker");
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
