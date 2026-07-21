use serenity::{
    all::{ButtonStyle, ChannelType},
    builder::{CreateActionRow, CreateButton, CreateSelectMenu, CreateSelectMenuKind},
};

use ratscan_storage::DiscordGuildConfig;

pub const SETTINGS_PREFIX: &str = "ratka_settings:";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingsView {
    Main,
    Channels,
    Logs,
    Danger,
}

pub fn is_settings_component(custom_id: &str) -> bool {
    custom_id.starts_with(SETTINGS_PREFIX)
}

pub fn panel(config: &DiscordGuildConfig, view: SettingsView) -> Vec<CreateActionRow> {
    match view {
        SettingsView::Main => vec![
            CreateActionRow::Buttons(vec![
                toggle_button("enabled", "Scanner", config.enabled),
                toggle_button("virustotal", "VirusTotal", config.report_virustotal),
                toggle_button("behavior", "Sandbox behavior", config.report_behavior),
            ]),
            CreateActionRow::Buttons(vec![
                nav_button("view_channels", "Allowed sources"),
                nav_button("view_logs", "Routing & health"),
                nav_button("view_danger", "Danger alerts"),
            ]),
        ],
        SettingsView::Channels => vec![
            select(
                "add_channel",
                "Add allowed channel",
                CreateSelectMenuKind::Channel {
                    channel_types: Some(vec![ChannelType::Text, ChannelType::News]),
                    default_channels: None,
                },
            ),
            select(
                "remove_channel",
                "Remove allowed channel",
                CreateSelectMenuKind::Channel {
                    channel_types: Some(vec![ChannelType::Text, ChannelType::News]),
                    default_channels: None,
                },
            ),
            select(
                "add_category",
                "Add allowed category",
                CreateSelectMenuKind::Channel {
                    channel_types: Some(vec![ChannelType::Category]),
                    default_channels: None,
                },
            ),
            select(
                "remove_category",
                "Remove allowed category",
                CreateSelectMenuKind::Channel {
                    channel_types: Some(vec![ChannelType::Category]),
                    default_channels: None,
                },
            ),
            back_row(),
        ],
        SettingsView::Logs => vec![
            select(
                "log_channel",
                "Set log channel",
                CreateSelectMenuKind::Channel {
                    channel_types: Some(vec![ChannelType::Text, ChannelType::News]),
                    default_channels: None,
                },
            ),
            select(
                "error_channel",
                "Set error channel",
                CreateSelectMenuKind::Channel {
                    channel_types: Some(vec![ChannelType::Text, ChannelType::News]),
                    default_channels: None,
                },
            ),
            CreateActionRow::SelectMenu(
                CreateSelectMenu::new(
                    id("coverage"),
                    CreateSelectMenuKind::String {
                        options: vec![
                            serenity::builder::CreateSelectMenuOption::new("50%", "50"),
                            serenity::builder::CreateSelectMenuOption::new("80%", "80"),
                            serenity::builder::CreateSelectMenuOption::new("90%", "90"),
                        ],
                    },
                )
                .placeholder("Coverage warning threshold"),
            ),
            CreateActionRow::Buttons(vec![
                nav_button("api_health", "API health"),
                nav_button("view_main", "Back"),
            ]),
        ],
        SettingsView::Danger => vec![
            select(
                "danger_role",
                "Set danger role",
                CreateSelectMenuKind::Role {
                    default_roles: None,
                },
            ),
            select(
                "add_danger_user",
                "Add danger user",
                CreateSelectMenuKind::User {
                    default_users: None,
                },
            ),
            select(
                "remove_danger_user",
                "Remove danger user",
                CreateSelectMenuKind::User {
                    default_users: None,
                },
            ),
            back_row(),
        ],
    }
}

fn select(action: &str, placeholder: &str, kind: CreateSelectMenuKind) -> CreateActionRow {
    CreateActionRow::SelectMenu(CreateSelectMenu::new(id(action), kind).placeholder(placeholder))
}

fn toggle_button(action: &str, label: &str, enabled: bool) -> CreateButton {
    CreateButton::new(id(action))
        .label(format!("{label}: {}", if enabled { "on" } else { "off" }))
        .style(if enabled {
            ButtonStyle::Success
        } else {
            ButtonStyle::Danger
        })
}

fn nav_button(action: &str, label: &str) -> CreateButton {
    CreateButton::new(id(action))
        .label(label)
        .style(ButtonStyle::Secondary)
}

fn id(action: &str) -> String {
    format!("{SETTINGS_PREFIX}{action}")
}

fn back_row() -> CreateActionRow {
    CreateActionRow::Buttons(vec![nav_button("view_main", "Back")])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panel_contains_all_required_setting_controls() {
        let encoded = [
            SettingsView::Main,
            SettingsView::Channels,
            SettingsView::Logs,
            SettingsView::Danger,
        ]
        .into_iter()
        .map(|view| serde_json::to_string(&panel(&DiscordGuildConfig::default(), view)).unwrap())
        .collect::<String>();
        for action in [
            "enabled",
            "add_channel",
            "remove_channel",
            "add_category",
            "remove_category",
            "log_channel",
            "error_channel",
            "danger_role",
            "add_danger_user",
            "remove_danger_user",
            "virustotal",
            "behavior",
            "coverage",
            "api_health",
        ] {
            assert!(encoded.contains(&format!("{SETTINGS_PREFIX}{action}")));
        }
    }
}
