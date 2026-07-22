use std::{collections::HashSet, env, sync::Arc, time::Duration};

use ratscan_discord::{
    api_client::{ApiClientConfig, ApiClientError, ScanApiClient},
    parse_message_reference,
    pipeline::{process_message_jobs, AttachmentJob, AttachmentOutcome, JobQueue},
    report::{format_report, ReportContext},
    routing::{alert_mentions, public_error},
    settings::{is_settings_component, panel, SettingsView, SETTINGS_PREFIX},
    throttling::RateLimiter,
    THREAD_SCAN,
};
use ratscan_storage::{DiscordGuildConfig, DiscordScanContext, DiscordStorage};
use serenity::{
    all::{
        Channel, ChannelId, ChannelType, Command, CommandDataOptionValue, CommandOptionType,
        ComponentInteraction, ComponentInteractionDataKind, Context, CreateCommand,
        CreateCommandOption, CreateEmbed, CreateInteractionResponse,
        CreateInteractionResponseMessage, CreateMessage, EditInteractionResponse, EventHandler,
        GatewayIntents, Interaction, Message, MessageId, MessageReference, MessageType, Ready,
    },
    async_trait, Client,
};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

const DEFAULT_MAX_ATTACHMENT_BYTES: usize = 50 * 1024 * 1024;
const DEFAULT_MAX_CONCURRENT_SCANS: usize = 2;
const DEFAULT_MAX_QUEUED_SCANS: usize = 20;
const DEFAULT_PER_USER_PER_MINUTE: usize = 10;
const DEFAULT_PER_GUILD_PER_MINUTE: usize = 30;

#[derive(Clone)]
struct BotConfig {
    token: String,
    owner_ids: HashSet<u64>,
    api: ApiClientConfig,
    database_url: String,
    max_queued_scans: usize,
    per_user_scans_per_minute: usize,
    per_guild_scans_per_minute: usize,
}

impl BotConfig {
    fn from_env() -> anyhow::Result<Self> {
        let token = required_env("DISCORD_TOKEN")?;
        let owner_ids = required_env("OWNER_USER_IDS")?
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::parse)
            .collect::<Result<HashSet<_>, _>>()?;
        if owner_ids.is_empty() {
            anyhow::bail!("OWNER_USER_IDS must include at least one user id");
        }
        let api = ApiClientConfig {
            base_url: env_or("RATSCAN_API_BASE_URL", "http://api:8080"),
            max_attachment_bytes: env_usize("DISCORD_MAX_JAR_BYTES", DEFAULT_MAX_ATTACHMENT_BYTES)?,
            scan_timeout: Duration::from_secs(env_u64("DISCORD_SCAN_TIMEOUT_SECONDS", 120)?),
            poll_interval: Duration::from_secs(env_u64("DISCORD_SCAN_POLL_INTERVAL_SECONDS", 2)?),
            health_timeout: Duration::from_secs(5),
            max_concurrent_scans: env_usize(
                "DISCORD_MAX_CONCURRENT_SCANS",
                DEFAULT_MAX_CONCURRENT_SCANS,
            )?,
        };
        Ok(Self {
            token,
            owner_ids,
            api,
            database_url: required_env("DATABASE_URL")?,
            max_queued_scans: env_usize("DISCORD_MAX_QUEUED_SCANS", DEFAULT_MAX_QUEUED_SCANS)?,
            per_user_scans_per_minute: env_usize(
                "DISCORD_PER_USER_SCANS_PER_MINUTE",
                DEFAULT_PER_USER_PER_MINUTE,
            )?,
            per_guild_scans_per_minute: env_usize(
                "DISCORD_PER_GUILD_SCANS_PER_MINUTE",
                DEFAULT_PER_GUILD_PER_MINUTE,
            )?,
        })
    }
}

struct Handler {
    owners: HashSet<u64>,
    storage: DiscordStorage,
    api: ScanApiClient,
    limiter: Arc<Mutex<RateLimiter>>,
    jobs: JobQueue,
    thread_notice_ids: Arc<Mutex<HashSet<u64>>>,
}

struct ScanDeliveryContext<'a> {
    http: &'a serenity::http::Http,
    thread_id: ChannelId,
    storage: &'a DiscordStorage,
    config: &'a DiscordGuildConfig,
    guild_id: u64,
    author_id: u64,
    channel_id: u64,
    message_id: u64,
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        info!(user = %ready.user.name, "Discord gateway connected");
        if let Err(error) = register_ratka_command(&ctx).await {
            error!(%error, "failed to register slash command");
        }
    }

    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        match interaction {
            Interaction::Command(command) if command.data.name == "ratka_checker" => {
                self.handle_command(&ctx, command).await;
            }
            Interaction::Component(component)
                if is_settings_component(&component.data.custom_id) =>
            {
                self.handle_settings_component(&ctx, component).await;
            }
            _ => {}
        }
    }

    async fn message(&self, ctx: Context, message: Message) {
        if self.delete_created_thread_notice(&ctx, &message).await {
            return;
        }
        let Some(guild_id) = message.guild_id.map(|id| id.get()) else {
            return;
        };
        if message.author.bot || jar_jobs(&message).is_empty() {
            return;
        }
        if let Err(error) = self
            .start_scan(&ctx, message.clone(), guild_id, false)
            .await
        {
            match error {
                StartScanError::NotEligible => {}
                StartScanError::RateLimited => {
                    let _ = message
                        .reply(
                            &ctx.http,
                            "Проверка не поставлена в очередь: превышен лимит.",
                        )
                        .await;
                }
                other => {
                    error!(%other, message_id = message.id.get(), "failed to prepare automatic Discord scan");
                    let _ = message
                        .reply(&ctx.http, "Проверка не запущена: внутренняя ошибка.")
                        .await;
                }
            }
        }
    }
}

impl Handler {
    async fn delete_created_thread_notice(&self, ctx: &Context, message: &Message) -> bool {
        let Some(thread_id) =
            created_thread_notice_thread_id(message.kind, message.message_reference.as_ref())
        else {
            return false;
        };
        if !self.thread_notice_ids.lock().await.remove(&thread_id) {
            return false;
        }
        if let Err(error) = message.delete(&ctx.http).await {
            warn!(%error, message_id = message.id.get(), thread_id, "failed to delete created-thread notice");
        }
        true
    }

    async fn handle_command(&self, ctx: &Context, command: serenity::all::CommandInteraction) {
        if !self.owners.contains(&command.user.id.get()) {
            let _ = ephemeral_command(
                ctx,
                &command,
                "У тебя нет доступа к управлению Ratka Checker.",
            )
            .await;
            return;
        }
        let Some(guild_id) = command.guild_id else {
            let _ = ephemeral_command(ctx, &command, "Команда работает только на сервере.").await;
            return;
        };
        let Some(subcommand) = command.data.options.first().cloned() else {
            let _ = ephemeral_command(ctx, &command, "Неизвестная команда.").await;
            return;
        };
        match subcommand.name.as_str() {
            "enable" => {
                let enabled = nested_bool(&subcommand, "enabled");
                let message = match enabled {
                    Some(enabled) => match self
                        .storage
                        .set_enabled(guild_id.get() as i64, enabled)
                        .await
                    {
                        Ok(()) => format!(
                            "Ratka Checker {}.",
                            if enabled {
                                "включён"
                            } else {
                                "выключен"
                            }
                        ),
                        Err(error) => {
                            error!(%error, "failed to update enabled setting");
                            "Команда не выполнена из-за внутренней ошибки.".into()
                        }
                    },
                    None => "Параметр enabled обязателен.".into(),
                };
                let _ = ephemeral_command(ctx, &command, &message).await;
            }
            "settings" => match self.storage.guild_config(guild_id.get() as i64).await {
                Ok(config) => {
                    let response = CreateInteractionResponse::Message(
                        CreateInteractionResponseMessage::new()
                            .content(settings_summary(&config))
                            .components(panel(&config, SettingsView::Main))
                            .ephemeral(true),
                    );
                    if let Err(error) = command.create_response(&ctx.http, response).await {
                        warn!(%error, "failed to open settings panel");
                    }
                }
                Err(error) => {
                    error!(%error, "failed to read settings");
                    let _ = ephemeral_command(
                        ctx,
                        &command,
                        "Команда не выполнена из-за внутренней ошибки.",
                    )
                    .await;
                }
            },
            "scan" => {
                let Some(reference) = nested_string(&subcommand, "message") else {
                    let _ = ephemeral_command(ctx, &command, "Параметр message обязателен.").await;
                    return;
                };
                self.handle_manual_scan(ctx, command, guild_id.get(), reference.to_owned())
                    .await;
            }
            _ => {
                let _ = ephemeral_command(ctx, &command, "Неизвестная команда.").await;
            }
        }
    }

    async fn handle_manual_scan(
        &self,
        ctx: &Context,
        command: serenity::all::CommandInteraction,
        guild_id: u64,
        reference: String,
    ) {
        let _ = command
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Defer(
                    CreateInteractionResponseMessage::new().ephemeral(true),
                ),
            )
            .await;
        let reference = match parse_message_reference(&reference) {
            Ok(value) => value,
            Err(_) => {
                let _ = command
                    .edit_response(
                        &ctx.http,
                        EditInteractionResponse::new().content(
                            "Укажи ID сообщения из текущего канала или полную ссылку на сообщение.",
                        ),
                    )
                    .await;
                return;
            }
        };
        if reference.guild_id.is_some_and(|id| id != guild_id) {
            let _ = command
                .edit_response(
                    &ctx.http,
                    EditInteractionResponse::new()
                        .content("Сообщение должно быть из этого сервера."),
                )
                .await;
            return;
        }
        let channel_id = reference.channel_id.unwrap_or(command.channel_id.get());
        match ChannelId::new(channel_id).to_channel(&ctx.http).await {
            Ok(Channel::Guild(channel)) if channel.guild_id.get() == guild_id => {}
            Ok(_) => {
                let _ = command
                    .edit_response(
                        &ctx.http,
                        EditInteractionResponse::new()
                            .content("Сообщение должно быть из этого сервера."),
                    )
                    .await;
                return;
            }
            Err(error) => {
                warn!(%error, channel_id, "manual scan channel fetch failed");
                let _ = command
                    .edit_response(
                        &ctx.http,
                        EditInteractionResponse::new().content(
                            "Не удалось найти канал. Проверь ссылку и доступ бота к каналу.",
                        ),
                    )
                    .await;
                return;
            }
        };
        let message = match ChannelId::new(channel_id)
            .message(&ctx.http, MessageId::new(reference.message_id))
            .await
        {
            Ok(message) => message,
            Err(error) => {
                warn!(%error, "manual scan message fetch failed");
                let _ = command
                    .edit_response(
                        &ctx.http,
                        EditInteractionResponse::new().content(
                            "Не удалось найти сообщение. Проверь ID/ссылку и доступ бота к каналу.",
                        ),
                    )
                    .await;
                return;
            }
        };
        if jar_jobs(&message).is_empty() {
            let _ = command
                .edit_response(
                    &ctx.http,
                    EditInteractionResponse::new()
                        .content("В указанном сообщении нет `.jar` вложений."),
                )
                .await;
            return;
        }
        match self.start_scan(ctx, message, guild_id, true).await {
            Ok(thread_url) => {
                let _ = command
                    .edit_response(
                        &ctx.http,
                        EditInteractionResponse::new()
                            .content(format!("Проверка запущена: {thread_url}")),
                    )
                    .await;
            }
            Err(StartScanError::RateLimited) => {
                let _ = command
                    .edit_response(
                        &ctx.http,
                        EditInteractionResponse::new()
                            .content("Проверка не поставлена в очередь: превышен лимит."),
                    )
                    .await;
            }
            Err(error) => {
                warn!(%error, "manual scan could not start");
                let _ = command
                    .edit_response(
                        &ctx.http,
                        EditInteractionResponse::new()
                            .content("Не удалось создать ветку для отчёта."),
                    )
                    .await;
            }
        }
    }

    async fn start_scan(
        &self,
        ctx: &Context,
        message: Message,
        guild_id: u64,
        manual: bool,
    ) -> Result<String, StartScanError> {
        let channel_id = message.channel_id.get();
        let jobs = jar_jobs(&message);
        let config = self.storage.guild_config(guild_id as i64).await?;
        if !manual && !config.enabled {
            return Err(StartScanError::NotEligible);
        }
        if !manual {
            let category_id = resolve_category_id(&ctx.http, message.channel_id).await;
            if !self
                .storage
                .is_allowed(
                    guild_id as i64,
                    channel_id as i64,
                    category_id.map(|id| id as i64),
                )
                .await?
            {
                return Err(StartScanError::NotEligible);
            }
        }
        self.limiter
            .lock()
            .await
            .accept_batch(
                message.author.id.get(),
                guild_id,
                jobs.len(),
                std::time::Instant::now(),
            )
            .map_err(|_| StartScanError::RateLimited)?;
        let expected_thread_id = message.id.get();
        self.thread_notice_ids
            .lock()
            .await
            .insert(expected_thread_id);
        let thread = match message
            .channel_id
            .create_thread_from_message(
                &ctx.http,
                message.id,
                serenity::all::CreateThread::new(THREAD_SCAN),
            )
            .await
        {
            Ok(thread) => thread,
            Err(error) => {
                self.thread_notice_ids
                    .lock()
                    .await
                    .remove(&expected_thread_id);
                self.limiter.lock().await.complete_batch(jobs.len());
                return Err(StartScanError::Discord(error));
            }
        };
        let thread_id = thread.id.get();
        if thread_id != expected_thread_id {
            let mut thread_notice_ids = self.thread_notice_ids.lock().await;
            thread_notice_ids.remove(&expected_thread_id);
            thread_notice_ids.insert(thread_id);
        }
        let thread_notice_ids = Arc::clone(&self.thread_notice_ids);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            thread_notice_ids.lock().await.remove(&thread_id);
        });
        if let Err(error) = thread
            .id
            .edit_thread(&ctx.http, serenity::all::EditThread::new().locked(true))
            .await
        {
            warn!(%error, thread_id = thread.id.get(), "failed to lock scan thread");
        }
        let api = self.api.clone();
        let storage = self.storage.clone();
        let http = ctx.http.clone();
        let report_http = http.clone();
        let jobs_queue = self.jobs.clone();
        let limiter = Arc::clone(&self.limiter);
        let thread_id = thread.id;
        let author_id = message.author.id.get();
        let message_id = message.id.get();
        tokio::spawn(async move {
            let outcome = process_message_jobs(jobs.clone(), jobs_queue, move |job| {
                let api = api.clone();
                let storage = storage.clone();
                let http = report_http.clone();
                let config = config.clone();
                async move {
                    let filename = job.filename.clone();
                    let result: anyhow::Result<_> = async {
                        let bytes = api.download_attachment(&job.url, job.declared_size).await?;
                        let scan = api.scan_attachment(bytes, &job.filename).await?;
                        let inserted = storage.insert_scan_context(&DiscordScanContext {
                            scan_id: scan.scan_id, guild_id: guild_id as i64, channel_id: channel_id as i64,
                            message_id: message_id as i64, thread_id: Some(thread_id.get() as i64), author_id: author_id as i64,
                        }).await?;
                        if !inserted { warn!(scan_id = %scan.scan_id, "duplicate Discord scan context ignored"); }
                        let delivery = ScanDeliveryContext {
                            http: &http,
                            thread_id,
                            storage: &storage,
                            config: &config,
                            guild_id,
                            author_id,
                            channel_id,
                            message_id,
                        };
                        send_report(&delivery, &scan, &filename).await?;
                        route_success(&delivery, &scan, &filename).await?;
                        Ok(scan)
                    }.await;
                    match result {
                        Ok(scan) => AttachmentOutcome::Scanned { filename, result: Box::new(scan) },
                        Err(error) => {
                            let public = error.downcast_ref::<ApiClientError>().map_or("внутренняя ошибка", public_error);
                            route_error(&http, thread_id, &config, guild_id, &filename, public, &error).await;
                            AttachmentOutcome::Failed { filename, public_error: public.into() }
                        }
                    }
                }
            }).await;
            if let Err(error) = thread_id
                .edit_thread(
                    &http,
                    serenity::all::EditThread::new()
                        .name(outcome.thread_name.as_str())
                        .locked(true),
                )
                .await
            {
                warn!(%error, thread_id = thread_id.get(), "failed to rename scan thread");
            }
            limiter.lock().await.complete_batch(jobs.len());
        });
        Ok(format!(
            "https://discord.com/channels/{guild_id}/{}",
            thread.id.get()
        ))
    }

    async fn handle_settings_component(&self, ctx: &Context, component: ComponentInteraction) {
        if !self.owners.contains(&component.user.id.get()) {
            let _ = ephemeral_component(
                ctx,
                &component,
                "У тебя нет доступа к управлению Ratka Checker.",
            )
            .await;
            return;
        }
        let Some(guild_id) = component.guild_id else {
            let _ =
                ephemeral_component(ctx, &component, "Панель работает только на сервере.").await;
            return;
        };
        let action = component.data.custom_id.trim_start_matches(SETTINGS_PREFIX);
        let guild = guild_id.get() as i64;
        if let Some(view) = match action {
            "view_main" => Some(SettingsView::Main),
            "view_channels" => Some(SettingsView::Channels),
            "view_logs" => Some(SettingsView::Logs),
            "view_danger" => Some(SettingsView::Danger),
            _ => None,
        } {
            match self.storage.guild_config(guild).await {
                Ok(config) => {
                    let response = CreateInteractionResponse::UpdateMessage(
                        CreateInteractionResponseMessage::new()
                            .content(settings_summary(&config))
                            .components(panel(&config, view)),
                    );
                    if let Err(error) = component.create_response(&ctx.http, response).await {
                        warn!(%error, "failed to update settings panel view");
                    }
                }
                Err(error) => {
                    warn!(%error, "failed to load settings panel view");
                    let _ = ephemeral_component(
                        ctx,
                        &component,
                        "Настройки не загружены из-за внутренней ошибки.",
                    )
                    .await;
                }
            }
            return;
        }
        let result = match action {
            "enabled" => self.toggle_enabled(guild).await,
            "api_health" => self
                .api
                .health()
                .await
                .map(|healthy| format!("API health: {}", if healthy { "ok" } else { "unhealthy" }))
                .map_err(anyhow::Error::from),
            "add_channel" => {
                self.channel_value(&component, |value| {
                    self.storage.add_allowed_channel(guild, value)
                })
                .await
            }
            "remove_channel" => {
                self.channel_value(&component, |value| {
                    self.storage.remove_allowed_channel(guild, value)
                })
                .await
            }
            "add_category" => {
                self.channel_value(&component, |value| {
                    self.storage.add_allowed_category(guild, value)
                })
                .await
            }
            "remove_category" => {
                self.channel_value(&component, |value| {
                    self.storage.remove_allowed_category(guild, value)
                })
                .await
            }
            "log_channel" => {
                self.channel_value(&component, |value| {
                    self.storage.set_log_channel(guild, Some(value))
                })
                .await
            }
            "error_channel" => {
                self.channel_value(&component, |value| {
                    self.storage.set_error_channel(guild, Some(value))
                })
                .await
            }
            "danger_role" => {
                self.role_value(&component, |value| {
                    self.storage.set_danger_role(guild, Some(value))
                })
                .await
            }
            "add_danger_user" => {
                self.user_value(&component, |value| {
                    self.storage.add_danger_user(guild, value)
                })
                .await
            }
            "remove_danger_user" => {
                self.user_value(&component, |value| {
                    self.storage.remove_danger_user(guild, value)
                })
                .await
            }
            _ => Err(anyhow::anyhow!("unknown settings component")),
        };
        let message = result.unwrap_or_else(|error| {
            warn!(%error, action, "settings component failed");
            "Настройка не сохранена из-за внутренней ошибки.".into()
        });
        let _ = ephemeral_component(ctx, &component, &message).await;
    }

    async fn toggle_enabled(&self, guild: i64) -> anyhow::Result<String> {
        let config = self.storage.guild_config(guild).await?;
        self.storage.set_enabled(guild, !config.enabled).await?;
        Ok("Настройка сохранена.".into())
    }
    async fn channel_value<F, Fut>(
        &self,
        component: &ComponentInteraction,
        apply: F,
    ) -> anyhow::Result<String>
    where
        F: FnOnce(i64) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<()>>,
    {
        let value =
            selected_channel(component).ok_or_else(|| anyhow::anyhow!("channel is required"))?;
        apply(value).await?;
        Ok("Настройка сохранена.".into())
    }
    async fn role_value<F, Fut>(
        &self,
        component: &ComponentInteraction,
        apply: F,
    ) -> anyhow::Result<String>
    where
        F: FnOnce(i64) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<()>>,
    {
        let value = selected_role(component).ok_or_else(|| anyhow::anyhow!("role is required"))?;
        apply(value).await?;
        Ok("Настройка сохранена.".into())
    }
    async fn user_value<F, Fut>(
        &self,
        component: &ComponentInteraction,
        apply: F,
    ) -> anyhow::Result<String>
    where
        F: FnOnce(i64) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<()>>,
    {
        let value = selected_user(component).ok_or_else(|| anyhow::anyhow!("user is required"))?;
        apply(value).await?;
        Ok("Настройка сохранена.".into())
    }
}

async fn send_report(
    delivery: &ScanDeliveryContext<'_>,
    scan: &ratscan_models::scan::ScanResponse,
    filename: &str,
) -> anyhow::Result<()> {
    let context = ReportContext {
        filename: filename.into(),
    };
    for embed in format_report(scan, &context) {
        let mut rendered = CreateEmbed::new()
            .title(embed.title)
            .description(embed.description);
        for field in embed.fields {
            rendered = rendered.field(field.name, field.value, false);
        }
        delivery
            .thread_id
            .send_message(delivery.http, CreateMessage::new().embed(rendered))
            .await?;
    }
    Ok(())
}

async fn route_success(
    delivery: &ScanDeliveryContext<'_>,
    scan: &ratscan_models::scan::ScanResponse,
    filename: &str,
) -> anyhow::Result<()> {
    let log = scan_log(delivery, scan, filename);
    let requires_attention = requires_attention(scan.verdict.as_ref());
    let (content, allowed_mentions) = if requires_attention {
        let users = delivery
            .storage
            .list_danger_users(delivery.guild_id as i64)
            .await?;
        let (mentions, allowed_mentions) = alert_mentions(delivery.config.danger_role_id, &users);
        (
            format!("{mentions}\n⚠️ {log}").trim().to_owned(),
            Some(allowed_mentions),
        )
    } else {
        (log, None)
    };
    let mut message = CreateMessage::new().content(content);
    if let Some(allowed_mentions) = allowed_mentions {
        message = message.allowed_mentions(allowed_mentions);
    }
    if !send_configured(delivery.http, delivery.config.log_channel_id, message).await
        && requires_attention
    {
        let users = delivery
            .storage
            .list_danger_users(delivery.guild_id as i64)
            .await?;
        let (mentions, allowed_mentions) = alert_mentions(delivery.config.danger_role_id, &users);
        let fallback = format!(
            "{mentions}\n⚠️ Scan requires review. Scan ID: `{}`.",
            scan.scan_id
        )
        .trim()
        .to_owned();
        delivery
            .thread_id
            .send_message(
                delivery.http,
                CreateMessage::new()
                    .content(fallback)
                    .allowed_mentions(allowed_mentions),
            )
            .await?;
    }
    Ok(())
}

fn requires_attention(verdict: Option<&ratscan_models::scan::Verdict>) -> bool {
    matches!(
        verdict,
        Some(
            ratscan_models::scan::Verdict::Unknown
                | ratscan_models::scan::Verdict::Suspicious
                | ratscan_models::scan::Verdict::Malicious
        )
    )
}

fn scan_log(
    delivery: &ScanDeliveryContext<'_>,
    scan: &ratscan_models::scan::ScanResponse,
    filename: &str,
) -> String {
    let verdict = scan
        .verdict
        .as_ref()
        .map_or("unknown", ratscan_models::scan::Verdict::as_str);
    let thread_url = format!(
        "https://discord.com/channels/{}/{}",
        delivery.guild_id,
        delivery.thread_id.get()
    );
    let message_url = format!(
        "https://discord.com/channels/{}/{}/{}",
        delivery.guild_id, delivery.channel_id, delivery.message_id
    );
    let safe_filename = filename.replace('`', "'");
    format!(
        "## Scan log\n\n**File:** `{filename}`\n**Author:** <@{author_id}>\n**Channel:** <#{channel_id}>\n**Thread:** {thread_url}\n**Message:** {message_url}\n**Verdict:** `{verdict}`\n**Risk:** `{risk_score}/100`\n**SHA-256:** `{sha256}`\n**Scan ID:** `{scan_id}`",
        filename = safe_filename,
        author_id = delivery.author_id,
        channel_id = delivery.channel_id,
        risk_score = scan.risk_score,
        sha256 = scan.sha256,
        scan_id = scan.scan_id,
    )
}

async fn route_error(
    http: &serenity::http::Http,
    thread_id: ChannelId,
    config: &DiscordGuildConfig,
    guild_id: u64,
    filename: &str,
    public: &str,
    technical: &anyhow::Error,
) {
    let detailed = format!(
        "RatScan technical error\nguild={guild_id}; thread={}; file=`{filename}`\n{technical:#}",
        thread_id.get()
    );
    let sent = send_configured(
        http,
        config.error_channel_id,
        CreateMessage::new().content(detailed),
    )
    .await;
    if !sent {
        warn!(
            thread_id = thread_id.get(),
            "error channel is absent or rejected technical scan error"
        );
    }
    if let Err(error) = thread_id
        .send_message(
            http,
            CreateMessage::new().content(format!("`{filename}`: {public}")),
        )
        .await
    {
        warn!(%error, "failed to publish safe scan error");
    }
}

async fn send_configured(
    http: &serenity::http::Http,
    channel_id: Option<i64>,
    message: CreateMessage,
) -> bool {
    let Some(channel_id) = channel_id.and_then(|id| u64::try_from(id).ok()) else {
        return false;
    };
    ChannelId::new(channel_id)
        .send_message(http, message)
        .await
        .is_ok()
}

async fn resolve_category_id(http: &serenity::http::Http, channel_id: ChannelId) -> Option<u64> {
    let channel = channel_id.to_channel(http).await.ok()?.guild()?;
    let parent_id = channel.parent_id?;
    category_from_channel(http, channel.kind, parent_id).await
}

async fn category_from_channel(
    http: &serenity::http::Http,
    kind: ChannelType,
    parent_id: ChannelId,
) -> Option<u64> {
    if is_thread(kind) {
        let parent_category = parent_id.to_channel(http).await.ok()?.guild()?.parent_id;
        return category_id_for_parent_channel(
            kind,
            Some(parent_id.get()),
            parent_category.map(|id| id.get()),
        );
    }
    category_id_for_parent_channel(kind, Some(parent_id.get()), None)
}

fn is_thread(kind: ChannelType) -> bool {
    matches!(
        kind,
        ChannelType::NewsThread | ChannelType::PublicThread | ChannelType::PrivateThread
    )
}
fn category_id_for_parent_channel(
    kind: ChannelType,
    direct_parent: Option<u64>,
    parent_category: Option<u64>,
) -> Option<u64> {
    if is_thread(kind) {
        parent_category
    } else {
        direct_parent
    }
}

fn jar_jobs(message: &Message) -> Vec<AttachmentJob> {
    message
        .attachments
        .iter()
        .filter(|attachment| attachment.filename.to_ascii_lowercase().ends_with(".jar"))
        .map(|attachment| AttachmentJob {
            filename: attachment.filename.clone(),
            url: attachment.url.clone(),
            declared_size: Some(attachment.size as u64),
        })
        .collect()
}

fn nested_bool(option: &serenity::all::CommandDataOption, name: &str) -> Option<bool> {
    let CommandDataOptionValue::SubCommand(values) = &option.value else {
        return None;
    };
    values
        .iter()
        .find(|value| value.name == name)
        .and_then(|value| value.value.as_bool())
}
fn nested_string<'a>(option: &'a serenity::all::CommandDataOption, name: &str) -> Option<&'a str> {
    let CommandDataOptionValue::SubCommand(values) = &option.value else {
        return None;
    };
    values
        .iter()
        .find(|value| value.name == name)
        .and_then(|value| value.value.as_str())
}
fn selected_channel(component: &ComponentInteraction) -> Option<i64> {
    match &component.data.kind {
        ComponentInteractionDataKind::ChannelSelect { values } => {
            values.first().and_then(|id| i64::try_from(id.get()).ok())
        }
        _ => None,
    }
}
fn selected_role(component: &ComponentInteraction) -> Option<i64> {
    match &component.data.kind {
        ComponentInteractionDataKind::RoleSelect { values } => {
            values.first().and_then(|id| i64::try_from(id.get()).ok())
        }
        _ => None,
    }
}
fn selected_user(component: &ComponentInteraction) -> Option<i64> {
    match &component.data.kind {
        ComponentInteractionDataKind::UserSelect { values } => {
            values.first().and_then(|id| i64::try_from(id.get()).ok())
        }
        _ => None,
    }
}

async fn ephemeral_command(
    ctx: &Context,
    command: &serenity::all::CommandInteraction,
    content: &str,
) -> serenity::Result<()> {
    command
        .create_response(
            &ctx.http,
            CreateInteractionResponse::Message(
                CreateInteractionResponseMessage::new()
                    .content(content)
                    .ephemeral(true),
            ),
        )
        .await
}
async fn ephemeral_component(
    ctx: &Context,
    component: &ComponentInteraction,
    content: &str,
) -> serenity::Result<()> {
    component
        .create_response(
            &ctx.http,
            CreateInteractionResponse::Message(
                CreateInteractionResponseMessage::new()
                    .content(content)
                    .ephemeral(true),
            ),
        )
        .await
}

fn settings_summary(config: &DiscordGuildConfig) -> String {
    format!("Настройки: scanner={}", config.enabled)
}

#[derive(Debug, thiserror::Error)]
enum StartScanError {
    #[error("not eligible")]
    NotEligible,
    #[error("rate limited")]
    RateLimited,
    #[error(transparent)]
    Storage(#[from] anyhow::Error),
    #[error(transparent)]
    Discord(#[from] serenity::Error),
}

async fn register_ratka_command(ctx: &Context) -> serenity::Result<()> {
    let desired = rata_command();
    let existing = Command::get_global_commands(&ctx.http).await?;
    match existing
        .iter()
        .find(|command| command.name == "ratka_checker")
    {
        Some(command) if command_schema_matches(command) => Ok(()),
        Some(command) => Command::edit_global_command(&ctx.http, command.id, desired)
            .await
            .map(|_| ()),
        None => Command::create_global_command(&ctx.http, desired)
            .await
            .map(|_| ()),
    }
}

fn created_thread_notice_thread_id(
    kind: MessageType,
    message_reference: Option<&MessageReference>,
) -> Option<u64> {
    (kind == MessageType::ThreadCreated)
        .then(|| message_reference.map(|reference| reference.channel_id.get()))
        .flatten()
}

fn rata_command() -> CreateCommand {
    CreateCommand::new("ratka_checker")
        .description("Управление Ratka Checker")
        .add_option(
            CreateCommandOption::new(
                CommandOptionType::SubCommand,
                "enable",
                "Включить или выключить сканер",
            )
            .add_sub_option(
                CreateCommandOption::new(
                    CommandOptionType::Boolean,
                    "enabled",
                    "true - включить, false - выключить",
                )
                .required(true),
            ),
        )
        .add_option(CreateCommandOption::new(
            CommandOptionType::SubCommand,
            "settings",
            "Открыть настройки Ratka Checker",
        ))
        .add_option(
            CreateCommandOption::new(
                CommandOptionType::SubCommand,
                "scan",
                "Сформировать отчёт по сообщению",
            )
            .add_sub_option(
                CreateCommandOption::new(
                    CommandOptionType::String,
                    "message",
                    "ID сообщения в текущем канале или ссылка на сообщение",
                )
                .required(true),
            ),
        )
}

fn command_schema_matches(command: &Command) -> bool {
    let expected = serde_json::to_value(rata_command()).expect("command schema serializes");
    let actual = serde_json::to_value(command).expect("Discord command serializes");
    ["name", "description", "options"]
        .into_iter()
        .all(|key| expected.get(key) == actual.get(key))
}

fn required_env(name: &str) -> anyhow::Result<String> {
    env::var(name).map_err(|_| anyhow::anyhow!("{name} is required"))
}
fn env_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}
fn env_u64(name: &str, default: u64) -> anyhow::Result<u64> {
    env::var(name).map_or(Ok(default), |value| value.parse().map_err(Into::into))
}
fn env_usize(name: &str, default: usize) -> anyhow::Result<usize> {
    env::var(name).map_or(Ok(default), |value| value.parse().map_err(Into::into))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = BotConfig::from_env()?;
    let pool = sqlx::PgPool::connect(&config.database_url).await?;
    let limiter = RateLimiter::new(
        config.per_user_scans_per_minute,
        config.per_guild_scans_per_minute,
        config.max_queued_scans,
        Duration::from_secs(60),
    );
    let handler = Handler {
        owners: config.owner_ids,
        storage: DiscordStorage::new(pool),
        api: ScanApiClient::new(config.api.clone())?,
        limiter: Arc::new(Mutex::new(limiter)),
        jobs: JobQueue::new(config.api.max_concurrent_scans),
        thread_notice_ids: Arc::new(Mutex::new(HashSet::new())),
    };
    let intents =
        GatewayIntents::GUILDS | GatewayIntents::GUILD_MESSAGES | GatewayIntents::MESSAGE_CONTENT;
    let mut client = Client::builder(config.token, intents)
        .event_handler(handler)
        .await?;
    tokio::select! { result = client.start() => result?, _ = tokio::signal::ctrl_c() => { info!("graceful shutdown requested"); client.shard_manager.shutdown_all().await; } }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_resolution_handles_text_announcement_and_threads() {
        assert_eq!(
            category_id_for_parent_channel(ChannelType::Text, Some(10), None),
            Some(10)
        );
        assert_eq!(
            category_id_for_parent_channel(ChannelType::News, Some(11), None),
            Some(11)
        );
        assert_eq!(
            category_id_for_parent_channel(ChannelType::PublicThread, Some(20), Some(30)),
            Some(30)
        );
        assert_eq!(
            category_id_for_parent_channel(ChannelType::NewsThread, Some(21), Some(31)),
            Some(31)
        );
    }

    #[test]
    fn manual_message_references_validate_guild_and_url() {
        assert_eq!(parse_message_reference("123").unwrap().channel_id, None);
        let parsed = parse_message_reference("https://discord.com/channels/1/2/3").unwrap();
        assert_eq!(
            (parsed.guild_id, parsed.channel_id, parsed.message_id),
            (Some(1), Some(2), 3)
        );
    }

    #[test]
    fn created_thread_notice_uses_referenced_thread_id() {
        let reference = MessageReference::new(Default::default(), ChannelId::new(456));
        assert_eq!(
            created_thread_notice_thread_id(MessageType::ThreadCreated, Some(&reference)),
            Some(456)
        );
        assert_eq!(
            created_thread_notice_thread_id(MessageType::Regular, Some(&reference)),
            None
        );
    }

    #[test]
    fn command_schema_has_required_subcommands_and_options() {
        let value = serde_json::to_value(rata_command()).unwrap();
        assert_eq!(value["name"], "ratka_checker");
        assert_eq!(value["options"].as_array().unwrap().len(), 3);
        assert_eq!(value["options"][0]["options"][0]["name"], "enabled");
        assert_eq!(value["options"][2]["options"][0]["name"], "message");
    }

    #[test]
    fn unknown_requires_danger_alert() {
        assert!(requires_attention(Some(
            &ratscan_models::scan::Verdict::Unknown
        )));
        assert!(requires_attention(Some(
            &ratscan_models::scan::Verdict::Suspicious
        )));
        assert!(requires_attention(Some(
            &ratscan_models::scan::Verdict::Malicious
        )));
        assert!(!requires_attention(Some(
            &ratscan_models::scan::Verdict::Clean
        )));
    }
}
