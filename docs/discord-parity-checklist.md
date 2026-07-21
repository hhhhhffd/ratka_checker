# Discord Rust migration parity checklist

`ratscan-discord` owns Discord gateway processing. This list maps legacy
`ds-bot` behavior to a regression test or a deployment verification scenario.

| Legacy behavior | Rust verification |
| --- | --- |
| Detect every `.jar` in one message | `pipeline::permit_is_acquired_before_download_work_begins` |
| One SCAN thread for a multi-JAR message | Code review scenario: `Handler::start_scan` creates the thread once before `process_message_jobs`; staging: submit two JARs and observe one thread with two reports. |
| Final thread name uses worst successful verdict | `aggregate_verdict_prefers_the_most_dangerous_successful_result`, `partial_failure_does_not_hide_successful_verdict` |
| Per-file error stays visible and partial success is retained | `partial_failure_does_not_hide_successful_verdict`; staging: one oversized and one clean JAR. |
| Per-user, per-guild, queued-file limits | `throttling::*` |
| Bounded permit precedes download | `pipeline::permit_is_acquired_before_download_work_begins` |
| Manual ID and Discord URL scans, guild check, owner check | `manual_message_references_validate_guild_and_url`; staging owner/non-owner and cross-guild URL scenarios. |
| `/ratka_checker enable`, `settings`, `scan` schemas | `command_schema_has_required_subcommands_and_options` |
| Idempotent command create/update without deleting other commands | `command_schema_matches`; staging: seed an unrelated global command and reconnect the bot. |
| Allowed channels, categories, log/error channels, danger role/users | `settings::panel_contains_all_required_setting_controls`, `ratscan-storage::settings_crud_uses_fixed_relations_without_dynamic_sql_input`; staging component clicks. |
| Text, announcement, and thread category resolution | `category_resolution_handles_text_announcement_and_threads` |
| Safe danger mentions | `routing::danger_mentions_include_only_configured_recipients` |
| Clean log and unknown/suspicious/malicious log-or-thread fallback | staging: configure and remove `log_channel`; verify both routes. |
| Error technical routing and safe public reason | staging: configure/unconfigure `error_channel` and inject CDN/API errors. |
| Retry only transient HTTP conditions | `api_client::retries_only_temporary_http_statuses` |
| Download → POST → pending → GET done → report → context persistence handoff | `api_client::mock_http_scan_flow_downloads_uploads_polls_reports_and_persists_context` |
| Compact user summary | `report::user_report_contains_only_summary_fields` |
| Legacy settings migration is non-destructive and repeatable | Run `DATABASE_URL=... scripts/migrate_discord_settings.sh` twice in staging; the second run updates settings and reports zero relation inserts. |

Every legacy feature is mapped above. The marked staging scenarios remain the
recommended post-deploy verification; a real Discord login is deliberately not
part of automated CI.
