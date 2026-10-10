use std::{env, path::Path, sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context};
use reqwest::{multipart, Client, Response};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::{io::AsyncWriteExt, task::JoinSet, time::sleep};
use tracing::warn;

const MAX_MESSAGE_LENGTH: usize = 3900;

struct BotConfig {
    token: String,
    allowed_tg_id: i64,
    api_base_url: String,
    request_timeout: Duration,
    poll_attempts: usize,
    poll_interval: Duration,
}

impl BotConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            token: env::var("TG_BOT_TOKEN")
                .ok()
                .filter(|value| !value.is_empty())
                .context("TG_BOT_TOKEN is required")?,
            allowed_tg_id: env::var("ALLOWED_TG_ID")
                .context("ALLOWED_TG_ID is required")?
                .trim()
                .parse()
                .context("ALLOWED_TG_ID must be an integer")?,
            api_base_url: env::var("RATSCAN_API_BASE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8080".into())
                .trim_end_matches('/')
                .to_owned(),
            request_timeout: duration_env("TG_BOT_REQUEST_TIMEOUT_SECONDS", 30.0)?,
            poll_attempts: env::var("TG_BOT_POLL_ATTEMPTS")
                .map(|value| value.trim().parse())
                .unwrap_or(Ok(24))
                .context("TG_BOT_POLL_ATTEMPTS must be a non-negative integer")?,
            poll_interval: duration_env("TG_BOT_POLL_INTERVAL_SECONDS", 5.0)?,
        })
    }
}

fn duration_env(name: &str, default: f64) -> anyhow::Result<Duration> {
    let seconds = env::var(name)
        .map(|value| value.trim().parse::<f64>())
        .unwrap_or(Ok(default))
        .with_context(|| format!("{name} must be a number"))?;
    Duration::try_from_secs_f64(seconds)
        .with_context(|| format!("{name} must be a finite non-negative duration"))
}

#[derive(Deserialize)]
struct Update {
    update_id: i64,
    message: Option<Message>,
}

#[derive(Deserialize)]
struct Message {
    chat: Chat,
    from: Option<User>,
    text: Option<String>,
    caption: Option<String>,
    document: Option<Document>,
    message_thread_id: Option<i64>,
    is_topic_message: Option<bool>,
}

#[derive(Deserialize)]
struct Chat {
    id: i64,
}

#[derive(Deserialize)]
struct User {
    id: i64,
}

#[derive(Deserialize)]
struct Document {
    file_id: String,
    file_name: Option<String>,
}

struct Bot {
    config: BotConfig,
    telegram: Client,
    api: Client,
    telegram_base_url: String,
    download_base_url: String,
    username: String,
}

impl Bot {
    async fn call(&self, method: &str, payload: Value) -> anyhow::Result<Value> {
        let response = self
            .telegram
            .post(format!("{}/{method}", self.telegram_base_url))
            .json(&payload)
            .send()
            .await
            // reqwest errors include the URL, which contains the bot token.
            .map_err(reqwest::Error::without_url)?;
        telegram_response(response).await
    }

    async fn answer(&self, message: &Message, text: &str) -> anyhow::Result<i64> {
        let mut payload = json!({"chat_id": message.chat.id, "text": text, "parse_mode": "HTML"});
        if message.is_topic_message == Some(true) {
            if let Some(thread_id) = message.message_thread_id {
                payload["message_thread_id"] = json!(thread_id);
            }
        }
        self.call("sendMessage", payload).await?["message_id"]
            .as_i64()
            .context("Telegram returned no message_id")
    }

    async fn edit(&self, chat_id: i64, message_id: i64, text: &str) -> anyhow::Result<()> {
        self.call(
            "editMessageText",
            json!({"chat_id": chat_id, "message_id": message_id,
                "text": text, "parse_mode": "HTML"}),
        )
        .await?;
        Ok(())
    }

    async fn get_report(&self, resource: &str, id: &str) -> anyhow::Result<Value> {
        let mut url = reqwest::Url::parse(&self.config.api_base_url)?;
        url.path_segments_mut()
            .map_err(|_| anyhow!("RATSCAN_API_BASE_URL cannot be a base URL"))?
            .pop_if_empty()
            .extend(["v1", resource, id]);
        read_api_response(self.api.get(url).send().await?).await
    }

    async fn submit(&self, document: &Document, filename: &str) -> anyhow::Result<Value> {
        let file = self
            .call("getFile", json!({"file_id": document.file_id}))
            .await?;
        let path = file["file_path"]
            .as_str()
            .context("Telegram returned no file_path")?;
        let response = self
            .telegram
            .get(format!("{}/{path}", self.download_base_url))
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let mut response = response
            .error_for_status()
            .map_err(reqwest::Error::without_url)?;
        let tmp_dir = tempfile::Builder::new().prefix("ratscan_tg_").tempdir()?;
        let file_path = tmp_dir.path().join("upload.jar");
        let mut destination = tokio::fs::File::create(&file_path).await?;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(reqwest::Error::without_url)?
        {
            destination.write_all(&chunk).await?;
        }
        destination.flush().await?;
        drop(destination);
        let part = multipart::Part::file(&file_path)
            .await?
            .file_name(filename.to_owned())
            .mime_str("application/java-archive")?;
        let response = self
            .api
            .post(format!("{}/v1/scans", self.config.api_base_url))
            .multipart(multipart::Form::new().part("file", part))
            .send()
            .await?;
        read_api_response(response).await
    }

    async fn wait_for_final_report(&self, scan_id: &str) -> anyhow::Result<Value> {
        let mut last_report = None;
        for _ in 0..self.config.poll_attempts {
            let report = self.get_report("scans", scan_id).await?;
            if matches!(report["status"].as_str(), Some("done" | "failed")) {
                return Ok(report);
            }
            last_report = Some(report);
            sleep(self.config.poll_interval).await;
        }
        match last_report {
            Some(report) => Ok(report),
            None => self.get_report("scans", scan_id).await,
        }
    }

    async fn send_report(
        &self,
        message: &Message,
        report: &Value,
        title: &str,
    ) -> anyhow::Result<()> {
        let mut summary = format_summary(report, title, true);
        if summary.chars().count() > MAX_MESSAGE_LENGTH {
            summary = format_summary(report, title, false);
        }
        self.answer(message, &summary).await?;
        let part = multipart::Part::bytes(serde_json::to_vec_pretty(report)?).file_name(format!(
            "ratscan-{}.json",
            field(report, "scan_id", "report")
        ));
        let mut form = multipart::Form::new()
            .text("chat_id", message.chat.id.to_string())
            .text("caption", "Полный JSON отчет.")
            .part("document", part);
        if message.is_topic_message == Some(true) {
            if let Some(thread_id) = message.message_thread_id {
                form = form.text("message_thread_id", thread_id.to_string());
            }
        }
        let response = self
            .telegram
            .post(format!("{}/sendDocument", self.telegram_base_url))
            .multipart(form)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        telegram_response(response).await?;
        Ok(())
    }

    async fn handle(&self, message: Message) -> anyhow::Result<()> {
        if message.from.as_ref().map(|user| user.id) != Some(self.config.allowed_tg_id) {
            return Ok(());
        }
        let chat_id = message.chat.id;
        let (command, argument) = parse_command(
            message
                .text
                .as_deref()
                .or(message.caption.as_deref())
                .unwrap_or(""),
            &self.username,
        );
        match command {
            "start" => {
                self.answer(&message, "Скинь .jar файлом для проверки, используй /id &lt;scan_id&gt; или /sha256 &lt;hash&gt; для поиска отчета.").await?;
            }
            "id" | "sha256" | "hash" => {
                let is_hash = command != "id";
                if argument.is_empty() {
                    self.answer(
                        &message,
                        if is_hash {
                            "Формат: /sha256 &lt;64 hex-символа&gt;"
                        } else {
                            "Формат: /id &lt;scan_id&gt;"
                        },
                    )
                    .await?;
                    return Ok(());
                }
                let id = if is_hash {
                    argument.to_lowercase()
                } else {
                    argument.to_owned()
                };
                if is_hash && (id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit())) {
                    self.answer(&message, "SHA-256 должен содержать ровно 64 hex-символа.")
                        .await?;
                    return Ok(());
                }
                match self
                    .get_report(if is_hash { "hashes" } else { "scans" }, &id)
                    .await
                {
                    Ok(report) => {
                        self.send_report(
                            &message,
                            &report,
                            if is_hash {
                                "Отчет по SHA-256"
                            } else {
                                "Полный отчет"
                            },
                        )
                        .await?
                    }
                    Err(error) => {
                        warn!(%error, "failed to fetch report");
                        self.answer(
                            &message,
                            &format!("Не удалось получить отчет: {}", escape(&error.to_string())),
                        )
                        .await?;
                    }
                }
            }
            _ => {
                if let Some(document) = message.document.as_ref() {
                    let filename = Path::new(document.file_name.as_deref().unwrap_or("upload.jar"))
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("upload.jar");
                    if !filename.to_lowercase().ends_with(".jar") {
                        self.answer(&message, "API принимает только .jar файлы.")
                            .await?;
                        return Ok(());
                    }
                    let status_id = self
                        .answer(&message, "Файл получен, запускаю проверку.")
                        .await?;
                    let report = match self.submit(document, filename).await {
                        Ok(report) => report,
                        Err(error) => {
                            warn!(%error, "failed to submit document");
                            self.edit(
                                chat_id,
                                status_id,
                                &format!(
                                    "Не удалось запустить проверку: {}",
                                    escape(&error.to_string())
                                ),
                            )
                            .await?;
                            return Ok(());
                        }
                    };
                    let Some(scan_id) = report["scan_id"].as_str() else {
                        self.edit(chat_id, status_id, "API не вернул scan_id.")
                            .await?;
                        return Ok(());
                    };
                    self.edit(
                        chat_id,
                        status_id,
                        &format!("Проверка запущена: <code>{}</code>", escape(scan_id)),
                    )
                    .await?;
                    let final_report = self.wait_for_final_report(scan_id).await?;
                    self.send_report(&message, &final_report, "Отчет по файлу")
                        .await?;
                } else {
                    self.answer(
                        &message,
                        "Скинь .jar файлом, используй /id &lt;scan_id&gt; или /sha256 &lt;hash&gt;.",
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }
}

async fn telegram_response(response: Response) -> anyhow::Result<Value> {
    let payload: Value = response.json().await.map_err(reqwest::Error::without_url)?;
    if payload["ok"] != true {
        bail!(
            "Telegram API: {}",
            payload["description"]
                .as_str()
                .unwrap_or("unexpected response")
        );
    }
    payload
        .get("result")
        .cloned()
        .context("Telegram returned no result")
}

async fn read_api_response(response: Response) -> anyhow::Result<Value> {
    let status = response.status();
    let text = response.text().await?;
    if status.as_u16() >= 400 {
        bail!(
            "RatScan API returned HTTP {}: {}",
            status.as_u16(),
            text.chars().take(500).collect::<String>()
        );
    }
    let payload: Value =
        serde_json::from_str(&text).context("RatScan API returned invalid JSON")?;
    if !payload.is_object() {
        bail!("RatScan API returned unexpected JSON shape");
    }
    Ok(payload)
}

fn parse_command<'a>(text: &'a str, username: &str) -> (&'a str, &'a str) {
    if !text.starts_with('/') {
        return ("", "");
    }
    let (command, argument) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
    let (command, mention) = command[1..].split_once('@').unwrap_or((&command[1..], ""));
    if !mention.is_empty() && !mention.eq_ignore_ascii_case(username) {
        return ("", "");
    }
    (command, argument.trim())
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn field(value: &Value, name: &str, default: &str) -> String {
    value
        .get(name)
        .map(value_text)
        .unwrap_or_else(|| default.to_owned())
}

fn value_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        value => value.to_string(),
    }
}

fn format_summary(report: &Value, title: &str, include_findings: bool) -> String {
    let mut lines = vec![
        format!("<b>{}</b>", escape(title)),
        format!(
            "ID: <code>{}</code>",
            escape(&field(report, "scan_id", "unknown"))
        ),
        format!(
            "Статус: <b>{}</b>",
            escape(&field(report, "status", "unknown"))
        ),
        format!(
            "SHA-256: <code>{}</code>",
            escape(&field(report, "sha256", "unknown"))
        ),
        format!(
            "Вердикт: <b>{}</b>",
            escape(&field(report, "verdict", "unknown"))
        ),
        format!(
            "Риск: <b>{}</b>",
            escape(&field(report, "risk_score", "unknown"))
        ),
    ];
    if let Some(findings) = report["findings"].as_array() {
        lines.push(format!("Findings: <b>{}</b>", findings.len()));
        if include_findings && !findings.is_empty() {
            lines.extend([String::new(), "<b>Findings</b>".into()]);
            for (index, item) in findings.iter().take(20).enumerate() {
                if item.is_object() {
                    lines.push(format!(
                        "{}. <b>{}</b> <code>{}</code> - {}",
                        index + 1,
                        escape(&field(item, "severity", "unknown")),
                        escape(&field(item, "rule_id", "unknown")),
                        escape(&field(item, "message", ""))
                    ));
                }
            }
            if findings.len() > 20 {
                lines.push(format!(
                    "...и еще {}; полный список в JSON.",
                    findings.len() - 20
                ));
            }
        }
    }
    if let Some(vt) = report["virustotal"].as_object() {
        lines.extend([String::new(), "<b>VirusTotal</b>".into()]);
        if let Some(status) = vt.get("status").filter(|value| !value.is_null()) {
            lines.push(format!("Статус: <b>{}</b>", escape(&value_text(status))));
        }
        if let Some(stats) = vt.get("stats").and_then(Value::as_object) {
            lines.push(format!(
                "Stats: {}",
                stats
                    .iter()
                    .map(|(key, value)| format!("{}={}", escape(key), escape(&value_text(value))))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if let Some(flagged) = vt.get("flagged_engines").and_then(Value::as_array) {
            lines.push(format!("Flagged engines: <b>{}</b>", flagged.len()));
        }
        if let Some(error) = vt
            .get("error")
            .filter(|value| !value.is_null() && **value != "")
        {
            lines.push(format!("Ошибка: {}", escape(&value_text(error))));
        }
    }
    lines.join("\n")
}

pub(super) async fn run() -> anyhow::Result<()> {
    match dotenvy::dotenv() {
        Ok(_) => {}
        Err(dotenvy::Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(dotenvy::Error::Io(error)) => {
            return Err(error).context("failed to load Telegram .env file")
        }
        Err(_) => bail!("invalid Telegram .env file"),
    }
    let config = BotConfig::from_env()?;
    let telegram_base_url = format!("https://api.telegram.org/bot{}", config.token);
    let download_base_url = format!("https://api.telegram.org/file/bot{}", config.token);
    let mut api = Client::builder();
    // aiohttp treated a zero total timeout as unlimited.
    if !config.request_timeout.is_zero() {
        api = api.timeout(config.request_timeout);
    }
    let api = api.build()?;
    let mut bot = Bot {
        config,
        api,
        telegram: Client::builder().timeout(Duration::from_secs(60)).build()?,
        telegram_base_url,
        download_base_url,
        username: String::new(),
    };
    bot.username = bot.call("getMe", json!({})).await?["username"]
        .as_str()
        .context("Telegram returned no username")?
        .to_owned();
    let bot = Arc::new(bot);
    let mut offset = 0_i64;
    let mut handlers = JoinSet::new();
    loop {
        while let Some(result) = handlers.try_join_next() {
            if let Err(error) = result {
                warn!(%error, "Telegram message handler failed");
            }
        }
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal?;
                return Ok(());
            }
            result = bot.call("getUpdates", json!({"offset": offset, "timeout": 30, "allowed_updates": ["message"]})) => {
                let payload = match result {
                    Ok(payload) => payload,
                    Err(error) => {
                        warn!(%error, "Telegram polling failed; retrying");
                        sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                };
                let updates: Vec<Update> = serde_json::from_value(payload)?;
                for update in updates {
                    offset = update.update_id + 1;
                    if let Some(message) = update.message {
                        let bot = Arc::clone(&bot);
                        handlers.spawn(async move {
                            if let Err(error) = bot.handle(message).await {
                                warn!(%error, "failed to handle Telegram message");
                            }
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{DefaultBodyLimit, Multipart, Path as RoutePath, State},
        http::StatusCode,
        response::{IntoResponse, Response as ServerResponse},
        routing::{get, post},
        Json, Router,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    #[derive(Default)]
    struct MockState {
        calls: Mutex<Vec<(String, Value)>>,
        uploads: Mutex<Vec<(String, Vec<u8>)>>,
        documents: Mutex<Vec<(String, Value)>>,
        document_threads: Mutex<Vec<Option<i64>>>,
        download_body: Mutex<Vec<u8>>,
        scan_requests: AtomicUsize,
    }

    async fn telegram_method(
        State(state): State<Arc<MockState>>,
        RoutePath(method): RoutePath<String>,
        Json(payload): Json<Value>,
    ) -> Json<Value> {
        state.calls.lock().unwrap().push((method.clone(), payload));
        let result = match method.as_str() {
            "getFile" => json!({"file_path": "archive.jar"}),
            "sendMessage" => json!({"message_id": 10}),
            "editMessageText" => json!({"message_id": 10}),
            _ => panic!("unexpected Telegram method {method}"),
        };
        Json(json!({"ok": true, "result": result}))
    }

    async fn upload(State(state): State<Arc<MockState>>, mut form: Multipart) -> Json<Value> {
        let field = form.next_field().await.unwrap().unwrap();
        assert_eq!(field.name(), Some("file"));
        assert_eq!(field.content_type(), Some("application/java-archive"));
        let filename = field.file_name().unwrap().to_owned();
        let bytes = field.bytes().await.unwrap().to_vec();
        state.uploads.lock().unwrap().push((filename, bytes));
        Json(json!({"scan_id": "scan-1"}))
    }

    async fn send_document(
        State(state): State<Arc<MockState>>,
        mut form: Multipart,
    ) -> Json<Value> {
        let mut found_document = false;
        let mut thread_id = None;
        while let Some(field) = form.next_field().await.unwrap() {
            match field.name().unwrap() {
                "chat_id" => assert_eq!(field.text().await.unwrap(), "42"),
                "caption" => assert_eq!(field.text().await.unwrap(), "Полный JSON отчет."),
                "message_thread_id" => {
                    thread_id = Some(field.text().await.unwrap().parse::<i64>().unwrap())
                }
                "document" => {
                    let filename = field.file_name().unwrap().to_owned();
                    let report = serde_json::from_slice(&field.bytes().await.unwrap()).unwrap();
                    state.documents.lock().unwrap().push((filename, report));
                    found_document = true;
                }
                name => panic!("unexpected multipart field {name}"),
            }
        }
        assert!(found_document);
        state.document_threads.lock().unwrap().push(thread_id);
        Json(json!({"ok": true, "result": {"message_id": 11}}))
    }

    async fn scan(
        State(state): State<Arc<MockState>>,
        RoutePath(id): RoutePath<String>,
    ) -> ServerResponse {
        let count = state.scan_requests.fetch_add(1, Ordering::SeqCst);
        match id.as_str() {
            "error" => (StatusCode::NOT_FOUND, "<missing>").into_response(),
            "invalid" => Json(json!([])).into_response(),
            "bad-json" => "not JSON".into_response(),
            _ => Json(
                json!({"scan_id": id, "status": if count == 0 { "queued" } else { "done" },
                "sha256": "abc", "verdict": "clean", "risk_score": 0, "findings": []}),
            )
            .into_response(),
        }
    }

    async fn hash_report(RoutePath(hash): RoutePath<String>) -> Json<Value> {
        Json(json!({"scan_id": "hash-scan", "status": "done", "sha256": hash}))
    }

    struct Fixture {
        bot: Bot,
        state: Arc<MockState>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    async fn fixture() -> Fixture {
        let state = Arc::new(MockState::default());
        *state.download_body.lock().unwrap() = b"jar contents".to_vec();
        let router = Router::new()
            .route("/telegram/sendDocument", post(send_document))
            .route("/telegram/{method}", post(telegram_method))
            .route(
                "/files/archive.jar",
                get(|State(state): State<Arc<MockState>>| async move {
                    state.download_body.lock().unwrap().clone()
                }),
            )
            .route("/v1/scans", post(upload))
            .route("/v1/scans/{id}", get(scan))
            .route("/v1/hashes/{hash}", get(hash_report))
            .layer(DefaultBodyLimit::max(8 * 1024 * 1024))
            .with_state(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Fixture {
            bot: Bot {
                config: BotConfig {
                    token: String::new(),
                    allowed_tg_id: 7,
                    api_base_url: base_url.clone(),
                    request_timeout: Duration::from_secs(2),
                    poll_attempts: 3,
                    poll_interval: Duration::ZERO,
                },
                telegram: Client::new(),
                api: Client::new(),
                telegram_base_url: format!("{base_url}/telegram"),
                download_base_url: format!("{base_url}/files"),
                username: "ratscan_bot".into(),
            },
            state,
            server,
        }
    }

    fn message(text: &str) -> Message {
        Message {
            chat: Chat { id: 42 },
            from: Some(User { id: 7 }),
            text: Some(text.into()),
            caption: None,
            document: None,
            message_thread_id: None,
            is_topic_message: None,
        }
    }

    #[tokio::test]
    async fn ignores_unauthorized_and_anonymous_messages() {
        let fixture = fixture().await;
        for user in [Some(User { id: 8 }), None] {
            let mut message = message("/id scan-1");
            message.from = user;
            fixture.bot.handle(message).await.unwrap();
        }
        assert!(fixture.state.calls.lock().unwrap().is_empty());
        assert_eq!(fixture.state.scan_requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn commands_validate_arguments_and_return_reports() {
        let fixture = fixture().await;
        for text in ["/start", "/id", "/sha256", "/hash nope"] {
            fixture.bot.handle(message(text)).await.unwrap();
        }
        assert_eq!(fixture.state.calls.lock().unwrap().len(), 4);
        assert!(fixture.state.calls.lock().unwrap()[0].1["text"]
            .as_str()
            .unwrap()
            .contains("&lt;scan_id&gt;"));
        fixture
            .bot
            .handle(message("/id@ratscan_bot scan-1"))
            .await
            .unwrap();
        fixture
            .bot
            .handle(message(&format!("/hash {}", "AB".repeat(32))))
            .await
            .unwrap();
        let mut caption_command = message("");
        caption_command.text = None;
        caption_command.caption = Some("/id scan-caption".into());
        caption_command.document = Some(Document {
            file_id: "file-1".into(),
            file_name: Some("mod.jar".into()),
        });
        fixture.bot.handle(caption_command).await.unwrap();
        let documents = fixture.state.documents.lock().unwrap();
        assert_eq!(documents[0].0, "ratscan-scan-1.json");
        assert_eq!(documents[1].1["sha256"], "ab".repeat(32));
        assert_eq!(documents[2].1["scan_id"], "scan-caption");
        assert!(fixture.state.uploads.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn document_is_downloaded_uploaded_polled_and_reported() {
        let fixture = fixture().await;
        let mut message = message("");
        message.document = Some(Document {
            file_id: "file-1".into(),
            file_name: Some("../../MOD.JAR".into()),
        });
        fixture.bot.handle(message).await.unwrap();
        assert_eq!(
            *fixture.state.uploads.lock().unwrap(),
            vec![("MOD.JAR".into(), b"jar contents".to_vec())]
        );
        assert_eq!(fixture.state.scan_requests.load(Ordering::SeqCst), 2);
        let documents = fixture.state.documents.lock().unwrap();
        assert_eq!(documents.len(), 1);
        assert_eq!(documents[0].1["status"], "done");
        let calls = fixture.state.calls.lock().unwrap();
        assert_eq!(calls[2].0, "editMessageText");
        assert!(calls[2].1["text"].as_str().unwrap().contains("scan-1"));
    }

    #[tokio::test]
    async fn document_status_summary_and_json_stay_in_forum_topic() {
        let fixture = fixture().await;
        let incoming: Message = serde_json::from_value(json!({
            "chat": {"id": 42}, "from": {"id": 7},
            "document": {"file_id": "file-1", "file_name": "mod.jar"},
            "message_thread_id": 77, "is_topic_message": true,
        }))
        .unwrap();
        fixture.bot.handle(incoming).await.unwrap();
        let calls = fixture.state.calls.lock().unwrap();
        let messages: Vec<_> = calls
            .iter()
            .filter(|(method, _)| method == "sendMessage")
            .collect();
        assert_eq!(messages.len(), 2);
        for (_, payload) in messages {
            assert_eq!(payload["message_thread_id"], 77);
        }
        assert_eq!(
            *fixture.state.document_threads.lock().unwrap(),
            vec![Some(77)]
        );
    }

    #[tokio::test]
    async fn large_document_is_streamed_without_corrupting_bytes() {
        let fixture = fixture().await;
        let expected: Vec<u8> = (0..4 * 1024 * 1024)
            .map(|index| (index % 251) as u8)
            .collect();
        *fixture.state.download_body.lock().unwrap() = expected.clone();
        let document = Document {
            file_id: "file-1".into(),
            file_name: Some("large.jar".into()),
        };
        fixture.bot.submit(&document, "large.jar").await.unwrap();
        assert_eq!(
            *fixture.state.uploads.lock().unwrap(),
            vec![("large.jar".into(), expected)]
        );
    }

    #[tokio::test]
    async fn rejects_non_jar_without_downloading() {
        let fixture = fixture().await;
        let mut message = message("");
        message.document = Some(Document {
            file_id: "file-1".into(),
            file_name: Some("mod.zip".into()),
        });
        fixture.bot.handle(message).await.unwrap();
        let calls = fixture.state.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1["text"], "API принимает только .jar файлы.");
        assert!(fixture.state.uploads.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn polling_returns_last_report_and_fetches_once_with_zero_attempts() {
        let mut fixture = fixture().await;
        fixture.bot.config.poll_attempts = 1;
        assert_eq!(
            fixture.bot.wait_for_final_report("scan-1").await.unwrap()["status"],
            "queued"
        );
        fixture.bot.config.poll_attempts = 0;
        assert_eq!(
            fixture.bot.wait_for_final_report("scan-1").await.unwrap()["status"],
            "done"
        );
        assert_eq!(fixture.state.scan_requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn api_errors_are_reported_and_invalid_responses_rejected() {
        let fixture = fixture().await;
        fixture.bot.handle(message("/id error")).await.unwrap();
        let text = fixture.state.calls.lock().unwrap()[0].1["text"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(text.contains("HTTP 404"));
        assert!(text.contains("&lt;missing&gt;"));
        assert!(fixture
            .bot
            .get_report("scans", "invalid")
            .await
            .unwrap_err()
            .to_string()
            .contains("unexpected JSON shape"));
        assert!(fixture
            .bot
            .get_report("scans", "bad-json")
            .await
            .unwrap_err()
            .to_string()
            .contains("invalid JSON"));
    }

    #[tokio::test]
    async fn long_summary_omits_findings_but_json_preserves_them() {
        let fixture = fixture().await;
        let report = json!({"scan_id": "long", "findings": [{"rule_id": "test", "severity": "high", "message": "x".repeat(4000)}]});
        fixture
            .bot
            .send_report(&message(""), &report, "Полный отчет")
            .await
            .unwrap();
        let calls = fixture.state.calls.lock().unwrap();
        let summary = calls[0].1["text"].as_str().unwrap();
        assert!(summary.chars().count() < MAX_MESSAGE_LENGTH);
        assert!(summary.contains("Findings: <b>1</b>"));
        assert!(!summary.contains("<b>Findings</b>"));
        assert_eq!(fixture.state.documents.lock().unwrap()[0].1, report);
    }

    #[test]
    fn summary_preserves_html_escaping_findings_and_virustotal() {
        let findings: Vec<_> = (0..22)
            .map(|_| json!({"rule_id": "<rule>", "severity": "high", "message": "a&b"}))
            .collect();
        let report = json!({"scan_id": "<id>", "risk_score": null, "findings": findings,
            "virustotal": {"status": "done", "stats": {"malicious": 2}, "flagged_engines": ["engine"], "error": "<error>"}});
        let summary = format_summary(&report, "Отчет", true);
        for expected in [
            "&lt;id&gt;",
            "&lt;rule&gt;",
            "a&amp;b",
            "...и еще 2;",
            "malicious=2",
            "Flagged engines: <b>1</b>",
            "&lt;error&gt;",
            "Риск: <b>None</b>",
        ] {
            assert!(summary.contains(expected), "missing {expected}");
        }
        assert!(!summary.contains("21. <b>"));
    }

    #[test]
    fn commands_respect_mentions_and_whitespace() {
        assert_eq!(
            parse_command("/id@RatScan_Bot   scan-id \n", "ratscan_bot"),
            ("id", "scan-id")
        );
        assert_eq!(parse_command("/id@other_bot x", "ratscan_bot"), ("", ""));
        assert_eq!(parse_command("hello /id x", "ratscan_bot"), ("", ""));
    }
}
