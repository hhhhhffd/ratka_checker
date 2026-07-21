use std::collections::BTreeSet;

use serenity::{
    all::{RoleId, UserId},
    builder::CreateAllowedMentions,
};

use crate::api_client::ApiClientError;

pub fn public_error(error: &ApiClientError) -> &'static str {
    match error {
        ApiClientError::AttachmentTooLarge => "файл превышает лимит",
        ApiClientError::DiscordCdn(_) | ApiClientError::DiscordCdnHttp { .. } => {
            "Discord CDN недоступен"
        }
        ApiClientError::ApiUnavailable(_) | ApiClientError::HttpFailure { .. } => "API недоступен",
        ApiClientError::InvalidResponse(_) | ApiClientError::FailedScan => {
            "API вернул некорректный ответ"
        }
        ApiClientError::Timeout => "проверка превысила таймаут",
    }
}

pub fn alert_mentions(
    danger_role_id: Option<i64>,
    danger_users: &[i64],
) -> (String, CreateAllowedMentions) {
    let users = danger_users
        .iter()
        .copied()
        .filter_map(|id| u64::try_from(id).ok())
        .collect::<BTreeSet<_>>();
    let roles = danger_role_id
        .and_then(|id| u64::try_from(id).ok())
        .into_iter()
        .collect::<Vec<_>>();
    let content = users
        .iter()
        .map(|id| format!("<@{id}>"))
        .chain(roles.iter().map(|id| format!("<@&{id}>")))
        .collect::<Vec<_>>()
        .join(" ");
    let allowed = CreateAllowedMentions::new()
        .users(users.iter().copied().map(UserId::new))
        .roles(roles.iter().copied().map(RoleId::new))
        .everyone(false)
        .all_users(false)
        .all_roles(false);
    (content, allowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn danger_mentions_include_only_configured_recipients() {
        let (content, allowed) = alert_mentions(Some(7), &[2, 2, 3]);
        assert_eq!(content, "<@2> <@3> <@&7>");
        let json = serde_json::to_value(allowed).unwrap();
        assert_eq!(json["parse"], serde_json::json!([]));
        assert_eq!(json["users"], serde_json::json!(["2", "3"]));
        assert_eq!(json["roles"], serde_json::json!(["7"]));
    }
}
