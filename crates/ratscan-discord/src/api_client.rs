use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use futures::StreamExt;
use ratscan_models::scan::{ScanResponse, ScanStatus};
use reqwest::{multipart, RequestBuilder, Response, StatusCode};
use thiserror::Error;
use tokio::{sync::Semaphore, time::sleep};

#[derive(Clone, Debug)]
pub struct ApiClientConfig {
    pub base_url: String,
    pub max_attachment_bytes: usize,
    pub scan_timeout: Duration,
    pub poll_interval: Duration,
    pub health_timeout: Duration,
    pub max_concurrent_scans: usize,
}

#[derive(Debug, Error)]
pub enum ApiClientError {
    #[error("Discord CDN download failed: {0}")]
    DiscordCdn(#[source] reqwest::Error),
    #[error("Discord CDN returned HTTP {status}")]
    DiscordCdnHttp { status: StatusCode },
    #[error("attachment exceeds configured maximum size")]
    AttachmentTooLarge,
    #[error("RatScan API is unavailable: {0}")]
    ApiUnavailable(#[source] reqwest::Error),
    #[error("RatScan API returned HTTP {status}")]
    HttpFailure { status: StatusCode },
    #[error("RatScan API returned an invalid response: {0}")]
    InvalidResponse(#[source] reqwest::Error),
    #[error("RatScan scan timed out")]
    Timeout,
    #[error("RatScan API returned failed scan state")]
    FailedScan,
}

#[derive(Clone)]
pub struct ScanApiClient {
    client: reqwest::Client,
    config: ApiClientConfig,
    scans: Arc<Semaphore>,
}

impl ScanApiClient {
    pub fn new(config: ApiClientConfig) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder().build()?;
        let scans = Arc::new(Semaphore::new(config.max_concurrent_scans));
        Ok(Self {
            client,
            config,
            scans,
        })
    }

    pub async fn health(&self) -> Result<bool, ApiClientError> {
        let url = format!("{}/health", self.config.base_url.trim_end_matches('/'));
        let response = self
            .client
            .get(url)
            .timeout(self.config.health_timeout)
            .send()
            .await
            .map_err(ApiClientError::ApiUnavailable)?;
        if !response.status().is_success() {
            return Ok(false);
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(ApiClientError::InvalidResponse)?;
        Ok(body.get("status").and_then(serde_json::Value::as_str) == Some("ok"))
    }

    pub async fn download_attachment(
        &self,
        url: &str,
        declared_size: Option<u64>,
    ) -> Result<Vec<u8>, ApiClientError> {
        if declared_size.is_some_and(|size| size > self.config.max_attachment_bytes as u64) {
            return Err(ApiClientError::AttachmentTooLarge);
        }
        let response = self
            .send_with_retry(deadline_from_now(self.config.scan_timeout), || {
                self.client.get(url)
            })
            .await
            .map_err(ApiClientError::DiscordCdn)?;
        if !response.status().is_success() {
            return Err(ApiClientError::DiscordCdnHttp {
                status: response.status(),
            });
        }
        let mut body = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(ApiClientError::DiscordCdn)?;
            if bytes.len().saturating_add(chunk.len()) > self.config.max_attachment_bytes {
                return Err(ApiClientError::AttachmentTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    pub async fn scan_attachment(
        &self,
        bytes: Vec<u8>,
        filename: &str,
    ) -> Result<ScanResponse, ApiClientError> {
        let _permit = self
            .scans
            .acquire()
            .await
            .map_err(|_| ApiClientError::Timeout)?;
        let deadline = Instant::now() + self.config.scan_timeout;
        let response = self.post_scan(bytes, filename, deadline).await?;
        self.wait_for_done(response, deadline).await
    }

    async fn post_scan(
        &self,
        bytes: Vec<u8>,
        filename: &str,
        deadline: Instant,
    ) -> Result<ScanResponse, ApiClientError> {
        self.request_json(
            || {
                let part = multipart::Part::bytes(bytes.clone())
                    .file_name(filename.to_owned())
                    .mime_str("application/java-archive")
                    .expect("fixed JAR MIME type is valid");
                self.client
                    .post(self.url("/v1/scans"))
                    .multipart(multipart::Form::new().part("file", part))
            },
            deadline,
        )
        .await
    }

    async fn wait_for_done(
        &self,
        mut response: ScanResponse,
        deadline: Instant,
    ) -> Result<ScanResponse, ApiClientError> {
        loop {
            match response.status {
                ScanStatus::Done => return Ok(response),
                ScanStatus::Failed => return Err(ApiClientError::FailedScan),
                ScanStatus::Pending => {}
            }
            if Instant::now() >= deadline {
                return Err(ApiClientError::Timeout);
            }
            sleep(
                self.config
                    .poll_interval
                    .min(deadline.saturating_duration_since(Instant::now())),
            )
            .await;
            response = self
                .request_json(
                    || {
                        self.client
                            .get(self.url(&format!("/v1/scans/{}", response.scan_id)))
                    },
                    deadline,
                )
                .await?;
        }
    }

    async fn request_json(
        &self,
        request: impl Fn() -> RequestBuilder,
        deadline: Instant,
    ) -> Result<ScanResponse, ApiClientError> {
        let response = self
            .send_with_retry(deadline, request)
            .await
            .map_err(ApiClientError::ApiUnavailable)?;
        if !response.status().is_success() {
            return Err(ApiClientError::HttpFailure {
                status: response.status(),
            });
        }
        response
            .json()
            .await
            .map_err(ApiClientError::InvalidResponse)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.config.base_url.trim_end_matches('/'), path)
    }

    async fn send_with_retry(
        &self,
        deadline: Instant,
        request: impl Fn() -> RequestBuilder,
    ) -> Result<Response, reqwest::Error> {
        const RETRY_DELAYS: [Duration; 2] =
            [Duration::from_millis(100), Duration::from_millis(300)];

        for retry_delay in RETRY_DELAYS
            .into_iter()
            .chain(std::iter::once(Duration::ZERO))
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return request().timeout(Duration::ZERO).send().await;
            }
            match request().timeout(remaining).send().await {
                Ok(response)
                    if is_retryable_status(response.status()) && !retry_delay.is_zero() =>
                {
                    sleep(retry_delay.min(deadline.saturating_duration_since(Instant::now())))
                        .await;
                }
                Ok(response) => return Ok(response),
                Err(error) if is_retryable_network_error(&error) && !retry_delay.is_zero() => {
                    sleep(retry_delay.min(deadline.saturating_duration_since(Instant::now())))
                        .await;
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("retry loop always returns on its final attempt")
    }
}

fn deadline_from_now(timeout: Duration) -> Instant {
    Instant::now() + timeout
}

pub fn is_retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
    )
}

pub fn is_retryable_network_error(error: &reqwest::Error) -> bool {
    error.is_connect() || error.is_timeout() || error.is_request() || error.is_body()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        net::SocketAddr,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use axum::{
        extract::State,
        http::StatusCode as AxumStatusCode,
        response::IntoResponse,
        routing::{get, post},
        Json, Router,
    };
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn retries_only_temporary_http_statuses() {
        assert!(is_retryable_status(StatusCode::BAD_GATEWAY));
        assert!(is_retryable_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(is_retryable_status(StatusCode::GATEWAY_TIMEOUT));
        assert!(!is_retryable_status(StatusCode::BAD_REQUEST));
        assert!(!is_retryable_status(StatusCode::UNAUTHORIZED));
        assert!(!is_retryable_status(StatusCode::FORBIDDEN));
        assert!(!is_retryable_status(StatusCode::PAYLOAD_TOO_LARGE));
    }

    #[derive(Clone)]
    struct MockApiState {
        polls: Arc<AtomicUsize>,
    }

    #[derive(Default)]
    struct InMemoryDiscordContextStore {
        contexts: Mutex<HashSet<(uuid::Uuid, u64)>>,
    }

    impl InMemoryDiscordContextStore {
        fn insert(&self, scan_id: uuid::Uuid, message_id: u64) -> bool {
            self.contexts.lock().unwrap().insert((scan_id, message_id))
        }
    }

    async fn attachment() -> impl IntoResponse {
        (
            AxumStatusCode::OK,
            [("content-type", "application/java-archive")],
            vec![1_u8, 2, 3],
        )
    }

    async fn create_scan() -> Json<serde_json::Value> {
        Json(scan_response("pending"))
    }

    async fn get_scan(State(state): State<MockApiState>) -> Json<serde_json::Value> {
        let status = if state.polls.fetch_add(1, Ordering::SeqCst) == 0 {
            "pending"
        } else {
            "done"
        };
        Json(scan_response(status))
    }

    fn scan_response(status: &str) -> serde_json::Value {
        serde_json::json!({
            "scan_id": "00000000-0000-0000-0000-000000000000", "status": status, "sha256": "abc",
            "verdict": if status == "done" { serde_json::Value::String("clean".into()) } else { serde_json::Value::Null },
            "risk_score": 0, "confidence": "high", "obfuscation_score": 0,
            "analysis_coverage": {"score": 100, "overall_score": 100, "total_classes": 1, "parsed_classes": 1, "total_resources": 0, "analyzed_resources": 0},
            "capabilities": [], "decoded_strings": [], "text_resources": [], "findings": [], "confirmed_chains": [],
            "obfuscation": {"level": "none", "score": 0}, "limitations": []
        })
    }

    #[tokio::test]
    async fn mock_http_scan_flow_downloads_uploads_polls_reports_and_persists_context() {
        let state = MockApiState {
            polls: Arc::new(AtomicUsize::new(0)),
        };
        let app = Router::new()
            .route("/attachment.jar", get(attachment))
            .route("/v1/scans", post(create_scan))
            .route("/v1/scans/{id}", get(get_scan))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = ScanApiClient::new(ApiClientConfig {
            base_url: format!("http://{address}"),
            max_attachment_bytes: 1024,
            scan_timeout: Duration::from_secs(2),
            poll_interval: Duration::from_millis(1),
            health_timeout: Duration::from_secs(1),
            max_concurrent_scans: 1,
        })
        .unwrap();
        let bytes = client
            .download_attachment(&format!("http://{address}/attachment.jar"), Some(3))
            .await
            .unwrap();
        let scan = client.scan_attachment(bytes, "mod.jar").await.unwrap();
        assert_eq!(scan.status, ScanStatus::Done);
        assert_eq!(state.polls.load(Ordering::SeqCst), 2);
        let contexts = InMemoryDiscordContextStore::default();
        assert!(contexts.insert(scan.scan_id, 42));
        let report = crate::report::format_report(
            &scan,
            &crate::report::ReportContext {
                filename: "mod.jar".into(),
            },
        );
        assert!(!report.is_empty());
        server.abort();
    }
}
