use std::{collections::HashSet, env, sync::Arc, time::Duration};

use ratscan_discord::{
    api_client::{ApiClientConfig, ScanApiClient},
    report::{format_report, ReportContext},
    thread_name_for_verdict,
    throttling::RateLimiter,
    THREAD_ERROR, THREAD_SCAN,
};
use ratscan_storage::{DiscordScanContext, DiscordStorage};
use serenity::{
    all::{
        Command, Context, CreateCommand, CreateCommandOption, CreateEmbed,
        CreateInteractionResponse, CreateInteractionResponseMessage, CreateMessage, EventHandler,
        GatewayIntents, Interaction, Message, Ready,
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
        let Interaction::Command(command) = interaction else {
            return;
        };
        if command.data.name != "ratka_checker" {
            return;
        }
        if !self.owners.contains(&command.user.id.get()) {
            let _ = command
                .create_response(
                    &ctx.http,
                    CreateInteractionResponse::Message(
                        CreateInteractionResponseMessage::new()
                            .content("У тебя нет доступа к управлению Ratka Checker.")
                            .ephemeral(true),
                    ),
                )
                .await;
            return;
        }
        let response = match command.data.options.first().map(|option| option.name.as_str()) {
            Some("enable") => "Настройка enable доступна только владельцам; состояние хранится в discord_guild_config.",
            Some("settings") => "Панель настроек: allowed channels/categories, log/error channel, danger role/users, VirusTotal и sandbox behavior. Компоненты настроек будут обработаны без удаления чужих команд.",
            Some("scan") => "Ручная проверка поддерживает ID сообщения или Discord URL; бот проверит вложения указанного сообщения.",
            _ => "Неизвестная команда.",
        };
        if let Err(error) = command
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new()
                        .content(response)
                        .ephemeral(true),
                ),
            )
            .await
        {
            warn!(%error, "failed to reply to command");
        }
    }

    async fn message(&self, ctx: Context, message: Message) {
        if message.author.bot || message.guild_id.is_none() {
            return;
        }
        let jars = message
            .attachments
            .iter()
            .filter(|attachment| attachment.filename.to_ascii_lowercase().ends_with(".jar"))
            .collect::<Vec<_>>();
        if jars.is_empty() {
            return;
        }
        let guild_id = message.guild_id.expect("checked").get();
        let channel_id = message.channel_id.get();
        let config = match self.storage.guild_config(guild_id as i64).await {
            Ok(value) => value,
            Err(error) => {
                error!(%error, "failed to read Discord guild config");
                return;
            }
        };
        if !config.enabled {
            return;
        }
        if !self
            .storage
            .is_allowed(guild_id as i64, channel_id as i64, None)
            .await
            .unwrap_or(false)
        {
            return;
        }
        for attachment in jars {
            let accepted = self.limiter.lock().await.accept(
                message.author.id.get(),
                guild_id,
                std::time::Instant::now(),
            );
            if let Err(reason) = accepted {
                let _ = message
                    .reply(
                        &ctx.http,
                        format!("Проверка не поставлена в очередь: {reason:?} limit."),
                    )
                    .await;
                continue;
            }
            let api = self.api.clone();
            let storage = self.storage.clone();
            let http = ctx.http.clone();
            let filename = attachment.filename.clone();
            let url = attachment.url.clone();
            let declared_size = Some(attachment.size as u64);
            let author_id = message.author.id.get();
            let message_id = message.id.get();
            let limiter = Arc::clone(&self.limiter);
            tokio::spawn(async move {
                let thread = match message
                    .channel_id
                    .create_thread_from_message(
                        &http,
                        message.id,
                        serenity::all::CreateThread::new(THREAD_SCAN),
                    )
                    .await
                {
                    Ok(thread) => thread,
                    Err(error) => {
                        error!(%error, "failed to create Discord scan thread");
                        limiter.lock().await.complete();
                        return;
                    }
                };
                if let Err(error) = thread
                    .id
                    .edit_thread(&http, serenity::all::EditThread::new().locked(true))
                    .await
                {
                    warn!(%error, thread_id = thread.id.get(), "failed to lock scan thread");
                }
                let result = async {
                    let bytes = api.download_attachment(&url, declared_size).await.map_err(anyhow::Error::from)?;
                    let scan = api.scan_attachment(bytes, &filename).await.map_err(anyhow::Error::from)?;
                    let inserted = storage.insert_scan_context(&DiscordScanContext { scan_id: scan.scan_id, guild_id: guild_id as i64, channel_id: channel_id as i64, message_id: message_id as i64, thread_id: Some(thread.id.get() as i64), author_id: author_id as i64 }).await?;
                    if !inserted { warn!(scan_id = %scan.scan_id, message_id, "duplicate Discord scan context ignored"); }
                    let report = format_report(&scan, &ReportContext { filename: filename.clone(), author_id, channel_id, thread_url: format!("https://discord.com/channels/{guild_id}/{}", thread.id.get()), coverage_warning_threshold: config.coverage_warning_threshold, report_virustotal: config.report_virustotal, report_behavior: config.report_behavior });
                    for embed in report { let mut rendered = CreateEmbed::new().title(embed.title).description(embed.description); for field in embed.fields { rendered = rendered.field(field.name, field.value, false); } thread.send_message(&http, CreateMessage::new().embed(rendered)).await?; }
                    thread.id.edit_thread(&http, serenity::all::EditThread::new().name(thread_name_for_verdict(scan.verdict.as_ref()).as_str()).locked(true)).await?;
                    anyhow::Ok(())
                }.await;
                if let Err(error) = result {
                    error!(%error, filename = %filename, "Discord scan failed");
                    let _ = thread.send_message(&http, CreateMessage::new().content("Проверка завершилась ошибкой. Подробности отправлены в error channel.")).await;
                    let _ = thread
                        .id
                        .edit_thread(
                            &http,
                            serenity::all::EditThread::new()
                                .name(THREAD_ERROR)
                                .locked(true),
                        )
                        .await;
                }
                limiter.lock().await.complete();
            });
        }
    }
}

async fn register_ratka_command(ctx: &Context) -> serenity::Result<()> {
    let existing = Command::get_global_commands(&ctx.http).await?;
    if existing
        .iter()
        .any(|command| command.name == "ratka_checker")
    {
        return Ok(());
    }
    let command = CreateCommand::new("ratka_checker")
        .description("Управление Ratka Checker")
        .add_option(CreateCommandOption::new(
            serenity::all::CommandOptionType::SubCommand,
            "enable",
            "Включить или выключить scanner",
        ))
        .add_option(CreateCommandOption::new(
            serenity::all::CommandOptionType::SubCommand,
            "settings",
            "Открыть настройки",
        ))
        .add_option(CreateCommandOption::new(
            serenity::all::CommandOptionType::SubCommand,
            "scan",
            "Проверить сообщение",
        ));
    Command::create_global_command(&ctx.http, command).await?;
    Ok(())
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
        api: ScanApiClient::new(config.api)?,
        limiter: Arc::new(Mutex::new(limiter)),
    };
    let intents =
        GatewayIntents::GUILDS | GatewayIntents::GUILD_MESSAGES | GatewayIntents::MESSAGE_CONTENT;
    let mut client = Client::builder(config.token, intents)
        .event_handler(handler)
        .await?;
    tokio::select! { result = client.start() => result?, _ = tokio::signal::ctrl_c() => { info!("graceful shutdown requested"); client.shard_manager.shutdown_all().await; } }
    Ok(())
}
