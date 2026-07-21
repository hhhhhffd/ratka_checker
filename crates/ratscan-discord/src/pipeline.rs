use std::{future::Future, sync::Arc};

use futures::{stream, StreamExt};
use ratscan_models::scan::{ScanResponse, Verdict};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{aggregate_thread_name, ThreadName};

/// A JAR that belongs to one Discord message. The pipeline deliberately owns
/// metadata only; bytes are obtained after the bounded job permit is granted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentJob {
    pub filename: String,
    pub url: String,
    pub declared_size: Option<u64>,
}

#[derive(Clone, Debug)]
pub enum AttachmentOutcome {
    Scanned {
        filename: String,
        result: Box<ScanResponse>,
    },
    Failed {
        filename: String,
        public_error: String,
    },
}

impl AttachmentOutcome {
    pub fn verdict(&self) -> Option<Verdict> {
        match self {
            Self::Scanned { result, .. } => result.verdict.clone(),
            Self::Failed { .. } => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MessageScanOutcome {
    pub attachments: Vec<AttachmentOutcome>,
    pub thread_name: ThreadName,
}

impl MessageScanOutcome {
    pub fn from_attachments(attachments: Vec<AttachmentOutcome>) -> Self {
        let thread_name = aggregate_thread_name(attachments.iter().map(AttachmentOutcome::verdict));
        Self {
            attachments,
            thread_name,
        }
    }
}

/// Limits active jobs, including download, API upload, polling, reporting and
/// persistence. Keeping this permit across the complete lifecycle prevents a
/// large queued message batch from retaining every JAR in memory.
#[derive(Clone, Debug)]
pub struct JobQueue {
    permits: Arc<Semaphore>,
}

impl JobQueue {
    pub fn new(max_concurrent_jobs: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(max_concurrent_jobs)),
        }
    }

    pub async fn acquire(&self) -> Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        Arc::clone(&self.permits).acquire_owned().await
    }
}

/// Runs one message's jobs with bounded concurrency. `scan` is invoked only
/// after a job permit has been acquired, which is the ordering required before
/// attachment download.
pub async fn process_message_jobs<F, Fut>(
    jobs: Vec<AttachmentJob>,
    queue: JobQueue,
    scan: F,
) -> MessageScanOutcome
where
    F: Fn(AttachmentJob) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = AttachmentOutcome> + Send,
{
    let outcomes = stream::iter(jobs)
        .map(|job| {
            let queue = queue.clone();
            let scan = scan.clone();
            async move {
                match queue.acquire().await {
                    Ok(_permit) => scan(job).await,
                    Err(_) => AttachmentOutcome::Failed {
                        filename: job.filename,
                        public_error: "внутренняя ошибка".into(),
                    },
                }
            }
        })
        .buffer_unordered(usize::MAX)
        .collect()
        .await;
    MessageScanOutcome::from_attachments(outcomes)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn job(name: &str) -> AttachmentJob {
        AttachmentJob {
            filename: name.into(),
            url: "https://cdn.example/test.jar".into(),
            declared_size: None,
        }
    }

    #[tokio::test]
    async fn permit_is_acquired_before_download_work_begins() {
        let queue = JobQueue::new(1);
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let active_for_scan = Arc::clone(&active);
        let maximum_for_scan = Arc::clone(&maximum);
        let outcome =
            process_message_jobs(vec![job("one.jar"), job("two.jar")], queue, move |job| {
                let active = Arc::clone(&active_for_scan);
                let maximum = Arc::clone(&maximum_for_scan);
                async move {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(current, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    AttachmentOutcome::Failed {
                        filename: job.filename,
                        public_error: "x".into(),
                    }
                }
            })
            .await;
        assert_eq!(outcome.attachments.len(), 2);
        assert_eq!(maximum.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn partial_failure_does_not_hide_successful_verdict() {
        let outcome = process_message_jobs(vec![job("bad.jar"), job("clean.jar")], JobQueue::new(2), |job| async move {
            if job.filename == "bad.jar" {
                AttachmentOutcome::Failed { filename: job.filename, public_error: "API недоступен".into() }
            } else {
                let mut value: ScanResponse = serde_json::from_value(serde_json::json!({
                    "scan_id": "00000000-0000-0000-0000-000000000000", "status": "done", "sha256": "a",
                    "verdict": "clean", "risk_score": 0, "confidence": "high", "obfuscation_score": 0,
                    "analysis_coverage": {"score": 100, "total_classes": 1, "parsed_classes": 1, "total_resources": 0, "analyzed_resources": 0}, "capabilities": [], "decoded_strings": [], "text_resources": [],
                    "findings": [], "confirmed_chains": [], "obfuscation": {"score": 0}, "limitations": []
                })).unwrap();
                value.verdict = Some(Verdict::Clean);
                AttachmentOutcome::Scanned { filename: job.filename, result: Box::new(value) }
            }
        }).await;
        assert_eq!(outcome.thread_name, ThreadName::Clean);
        assert!(outcome
            .attachments
            .iter()
            .any(|item| matches!(item, AttachmentOutcome::Failed { .. })));
    }
}
