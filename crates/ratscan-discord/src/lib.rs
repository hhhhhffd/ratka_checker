//! Discord-specific orchestration for RatScan. Scanner verdicts remain backend-owned.

pub mod api_client;
pub mod pipeline;
pub mod report;
pub mod routing;
pub mod settings;
pub mod throttling;

use std::str::FromStr;

use thiserror::Error;

pub const THREAD_SCAN: &str = "SCAN";
pub const THREAD_CLEAN: &str = "CLEAN";
pub const THREAD_SUSPICIOUS: &str = "SUSPICIOUS";
pub const THREAD_DANGER: &str = "DANGER";
pub const THREAD_ERROR: &str = "ERROR";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadName {
    Scan,
    Clean,
    Suspicious,
    Danger,
    Error,
}

/// Selects a name for the single thread created for all JARs on one message.
/// Failed attachments never hide a successful result, but an all-failure batch
/// must remain visibly actionable.
pub fn aggregate_thread_name<I>(verdicts: I) -> ThreadName
where
    I: IntoIterator<Item = Option<ratscan_models::scan::Verdict>>,
{
    let mut best = None;
    for verdict in verdicts.into_iter().flatten() {
        let rank = match verdict {
            ratscan_models::scan::Verdict::Malicious => 3,
            ratscan_models::scan::Verdict::Suspicious => 2,
            ratscan_models::scan::Verdict::Clean => 1,
            ratscan_models::scan::Verdict::Unknown => 0,
        };
        if best.is_none_or(|current| rank > current) {
            best = Some(rank);
        }
    }
    match best {
        Some(3) => ThreadName::Danger,
        Some(2) => ThreadName::Suspicious,
        Some(1) => ThreadName::Clean,
        _ => ThreadName::Error,
    }
}

impl ThreadName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scan => THREAD_SCAN,
            Self::Clean => THREAD_CLEAN,
            Self::Suspicious => THREAD_SUSPICIOUS,
            Self::Danger => THREAD_DANGER,
            Self::Error => THREAD_ERROR,
        }
    }
}

/// Maps only backend verdict values; the bot never derives a verdict from the risk score.
pub fn thread_name_for_verdict(verdict: Option<&ratscan_models::scan::Verdict>) -> ThreadName {
    match verdict {
        Some(ratscan_models::scan::Verdict::Clean) => ThreadName::Clean,
        Some(ratscan_models::scan::Verdict::Suspicious) => ThreadName::Suspicious,
        Some(ratscan_models::scan::Verdict::Malicious) => ThreadName::Danger,
        Some(ratscan_models::scan::Verdict::Unknown) | None => ThreadName::Error,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageReference {
    pub guild_id: Option<u64>,
    pub channel_id: Option<u64>,
    pub message_id: u64,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MessageReferenceError {
    #[error("message reference is empty or invalid")]
    Invalid,
}

/// Parses a bare message ID or a Discord message URL without accepting arbitrary URLs.
pub fn parse_message_reference(value: &str) -> Result<MessageReference, MessageReferenceError> {
    if let Ok(message_id) = u64::from_str(value.trim()) {
        return Ok(MessageReference {
            guild_id: None,
            channel_id: None,
            message_id,
        });
    }
    let url = url::Url::parse(value.trim()).map_err(|_| MessageReferenceError::Invalid)?;
    let host = url.host_str().ok_or(MessageReferenceError::Invalid)?;
    if !matches!(
        host,
        "discord.com" | "discordapp.com" | "canary.discord.com" | "ptb.discord.com"
    ) {
        return Err(MessageReferenceError::Invalid);
    }
    let parts = url
        .path_segments()
        .ok_or(MessageReferenceError::Invalid)?
        .collect::<Vec<_>>();
    if parts.len() != 4 || parts[0] != "channels" {
        return Err(MessageReferenceError::Invalid);
    }
    let guild_id = parts[1]
        .parse()
        .map_err(|_| MessageReferenceError::Invalid)?;
    let channel_id = parts[2]
        .parse()
        .map_err(|_| MessageReferenceError::Invalid)?;
    let message_id = parts[3]
        .parse()
        .map_err(|_| MessageReferenceError::Invalid)?;
    Ok(MessageReference {
        guild_id: Some(guild_id),
        channel_id: Some(channel_id),
        message_id,
    })
}

pub fn channel_is_allowed(
    allowed_channels: &[u64],
    allowed_categories: &[u64],
    channel_id: u64,
    category_id: Option<u64>,
) -> bool {
    allowed_channels.contains(&channel_id)
        || category_id.is_some_and(|id| allowed_categories.contains(&id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratscan_models::scan::Verdict;

    #[test]
    fn verdict_maps_to_thread_name_without_score_recalculation() {
        assert_eq!(
            thread_name_for_verdict(Some(&Verdict::Clean)),
            ThreadName::Clean
        );
        assert_eq!(
            thread_name_for_verdict(Some(&Verdict::Suspicious)),
            ThreadName::Suspicious
        );
        assert_eq!(
            thread_name_for_verdict(Some(&Verdict::Malicious)),
            ThreadName::Danger
        );
        assert_eq!(thread_name_for_verdict(None), ThreadName::Error);
    }

    #[test]
    fn message_url_parser_accepts_bare_id_and_discord_urls() {
        assert_eq!(parse_message_reference("42").unwrap().message_id, 42);
        let parsed = parse_message_reference("https://discord.com/channels/1/2/3").unwrap();
        assert_eq!(
            parsed,
            MessageReference {
                guild_id: Some(1),
                channel_id: Some(2),
                message_id: 3
            }
        );
        assert!(parse_message_reference("https://example.test/channels/1/2/3").is_err());
    }

    #[test]
    fn channel_or_parent_category_can_allow_scanning() {
        assert!(channel_is_allowed(&[10], &[], 10, None));
        assert!(channel_is_allowed(&[], &[20], 10, Some(20)));
        assert!(!channel_is_allowed(&[], &[20], 10, None));
    }

    #[test]
    fn aggregate_verdict_prefers_the_most_dangerous_successful_result() {
        assert_eq!(
            aggregate_thread_name([Some(Verdict::Clean), Some(Verdict::Malicious), None]),
            ThreadName::Danger
        );
        assert_eq!(
            aggregate_thread_name([None, Some(Verdict::Suspicious), Some(Verdict::Clean)]),
            ThreadName::Suspicious
        );
        assert_eq!(aggregate_thread_name([None, None]), ThreadName::Error);
    }
}
