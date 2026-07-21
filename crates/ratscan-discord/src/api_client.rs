use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use futures::StreamExt;
use ratscan_models::scan::{ScanResponse, ScanStatus};
use reqwest::{multipart, StatusCode};
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
            .client
            .get(url)
            .send()
            .await
            .map_err(ApiClientError::DiscordCdn)?;
        if !response.status().is_success() {
            return Err(ApiClientError::HttpFailure {
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
        let part = multipart::Part::bytes(bytes)
            .file_name(filename.to_owned())
            .mime_str("application/java-archive")
            .map_err(ApiClientError::InvalidResponse)?;
        let form = multipart::Form::new().part("file", part);
        self.request_json(
            self.client.post(self.url("/v1/scans")).multipart(form),
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
                    self.client
                        .get(self.url(&format!("/v1/scans/{}", response.scan_id))),
                    deadline,
                )
                .await?;
        }
    }

    async fn request_json(
        &self,
        request: reqwest::RequestBuilder,
        deadline: Instant,
    ) -> Result<ScanResponse, ApiClientError> {
        let response = request
            .timeout(deadline.saturating_duration_since(Instant::now()))
            .send()
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
}
