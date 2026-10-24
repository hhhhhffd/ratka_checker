use std::{path::PathBuf, time::Duration};

use axum::extract::{Multipart, Path, State};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    api::AppState,
    error::AppError,
    models::scan::{Finding, ScanReport, VirusTotalStatus},
    response::PrettyJson,
    scanner::archive,
    storage::{db, files},
    virustotal,
};

/// A pending scan newer than this is shared by duplicate uploads; an older one is presumed stuck
/// and a fresh scan is started. It comfortably exceeds a static scan plus the VirusTotal
/// upload/poll phase, so healthy in-flight scans are not duplicated.
const PENDING_SCAN_REUSE_WINDOW: Duration = Duration::from_secs(30 * 60);

/// Accepts a multipart jar upload, persists it by sha256, and enqueues a background scan.
pub async fn create_scan(
    State(state): State<AppState>,
    multipart: Multipart,
) -> Result<PrettyJson<crate::models::scan::ScanResponse>, AppError> {
    let upload = extract_upload(multipart).await?;
    validate_filename(&upload.filename)?;

    let sha256 = hex::encode(Sha256::digest(&upload.bytes));
    let storage_path = files::save_jar(&state.config.storage_dir, &sha256, &upload.bytes).await?;
    let storage_path_string = storage_path.to_string_lossy().to_string();

    if let Some(existing) =
        db::find_reusable_scan_by_sha256(&state.db, &sha256, PENDING_SCAN_REUSE_WINDOW)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
    {
        db::mark_file_available(&state.db, existing.scan_id, &storage_path_string).await?;
        return Ok(PrettyJson(existing));
    }

    let scan_id = Uuid::new_v4();
    db::create_pending_scan(
        &state.db,
        scan_id,
        &upload.filename,
        &sha256,
        &storage_path_string,
    )
    .await?;

    spawn_scan_worker(
        scan_id,
        storage_path,
        upload.filename.clone(),
        state.clone(),
    );

    let response = db::find_scan_by_id(&state.db, scan_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("created scan was not found"))?;
    Ok(PrettyJson(response))
}

/// Returns current scan state and result by id for polling clients.
pub async fn get_scan(
    State(state): State<AppState>,
    Path(scan_id): Path<Uuid>,
) -> Result<PrettyJson<crate::models::scan::ScanResponse>, AppError> {
    let response = db::find_scan_by_id(&state.db, scan_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("scan not found"))?;
    Ok(PrettyJson(response))
}

/// Starts one detached worker for a scan; the worker owns all state it needs to finish DB updates.
fn spawn_scan_worker(scan_id: Uuid, storage_path: PathBuf, filename: String, state: AppState) {
    tokio::spawn(async move {
        if let Err(error) = run_scan_worker(scan_id, storage_path, filename, state.clone()).await {
            tracing::error!(scan_id = %scan_id, %error, "scan worker failed");
            if let Err(update_error) =
                db::fail_scan(&state.db, scan_id, "scan_worker_failed", &error.to_string()).await
            {
                tracing::error!(scan_id = %scan_id, %update_error, "failed to persist worker failure");
            }
        }
    });
}

/// Runs blocking archive/class parsing off the async runtime and persists the final scan state.
async fn run_scan_worker(
    scan_id: Uuid,
    storage_path: PathBuf,
    filename: String,
    state: AppState,
) -> anyhow::Result<()> {
    let limits = state.config.scan_limits;
    let rules_engine = state.rules_engine.clone();
    let scan_path = storage_path.clone();
    let mut outcome =
        tokio::task::spawn_blocking(move || archive::scan_file(&scan_path, limits, &rules_engine))
            .await?;
    if let Some(report) = run_virustotal(scan_id, &storage_path, &filename, &state).await? {
        let findings = virustotal::findings_for_report(&report);
        if !findings.is_empty() {
            outcome.summary = merge_virustotal_findings(&mut outcome.report, findings);
        }
    }

    db::complete_scan_report(&state.db, scan_id, &outcome.report, &outcome.summary).await
}

/// Adds VirusTotal evidence to the structured report without discarding static-analysis context.
fn merge_virustotal_findings(
    report: &mut ScanReport,
    findings: impl IntoIterator<Item = Finding>,
) -> String {
    let previous_verdict = report.verdict.clone();
    report.findings.extend(findings);
    let (verdict, risk_score, summary) = archive::finalize_report_with_analysis_limits(
        &report.findings,
        &report.confirmed_chains,
        &report.obfuscation,
        &report.analysis_coverage,
    );
    report.verdict = stricter_verdict(previous_verdict, verdict);
    report.risk_score = risk_score;
    summary
}

/// A post-processing source such as VirusTotal may add evidence, but it must not
/// erase a stricter verdict already established by static analysis.
fn stricter_verdict(
    previous: crate::models::scan::Verdict,
    recalculated: crate::models::scan::Verdict,
) -> crate::models::scan::Verdict {
    if verdict_rank(&previous) >= verdict_rank(&recalculated) {
        previous
    } else {
        recalculated
    }
}

fn verdict_rank(verdict: &crate::models::scan::Verdict) -> u8 {
    match verdict {
        crate::models::scan::Verdict::Clean => 0,
        crate::models::scan::Verdict::Unknown => 1,
        crate::models::scan::Verdict::Suspicious => 2,
        crate::models::scan::Verdict::Malicious => 3,
    }
}

/// Runs the optional VirusTotal phase and persists its own report without failing static analysis.
async fn run_virustotal(
    scan_id: Uuid,
    storage_path: &std::path::Path,
    filename: &str,
    state: &AppState,
) -> anyhow::Result<Option<crate::models::scan::VirusTotalReport>> {
    if !state.config.virustotal.enabled {
        return Ok(None);
    }

    let sha256 = storage_path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("stored jar path does not contain sha256 filename"))?;

    if let Some(report) = db::find_fresh_virustotal_report(&state.db, sha256).await? {
        return Ok(Some(report));
    }

    let report =
        match virustotal::analyze_file(&state.config.virustotal, sha256, storage_path, filename)
            .await
        {
            Ok(report) => report,
            Err(error) => {
                tracing::warn!(scan_id = %scan_id, %error, "VirusTotal analysis failed");
                virustotal::error_report(error.to_string())
            }
        };

    if is_cacheable_virustotal_report(&report) {
        db::upsert_virustotal_report(
            &state.db,
            sha256,
            &report,
            state.config.virustotal.cache_ttl,
        )
        .await?;
    }
    Ok(Some(report))
}

/// Errors are transient and a queued analysis is still in progress, so caching either for the
/// full TTL would pin an unusable result; the next scan of the same jar should ask VirusTotal again.
fn is_cacheable_virustotal_report(report: &crate::models::scan::VirusTotalReport) -> bool {
    !matches!(
        report.status,
        VirusTotalStatus::Error | VirusTotalStatus::Queued
    )
}

/// Parsed upload payload from the expected `multipart/form-data` field named `file`.
struct Upload {
    filename: String,
    bytes: Bytes,
}

/// Extracts exactly the `file` part and rejects missing or empty uploads explicitly.
async fn extract_upload(mut multipart: Multipart) -> Result<Upload, AppError> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| AppError::invalid_file(format!("invalid multipart upload: {error}")))?
    {
        if field.name() != Some("file") {
            continue;
        }

        let filename = field
            .file_name()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| "upload.jar".to_owned());
        let bytes = field.bytes().await.map_err(|error| {
            AppError::invalid_file(format!("failed to read uploaded file: {error}"))
        })?;
        if bytes.is_empty() {
            return Err(AppError::invalid_file("uploaded file is empty"));
        }
        return Ok(Upload { filename, bytes });
    }

    Err(AppError::invalid_file("multipart field 'file' is required"))
}

/// Enforces the MVP contract that only `.jar` uploads are accepted.
fn validate_filename(filename: &str) -> Result<(), AppError> {
    if filename.to_ascii_lowercase().ends_with(".jar") {
        Ok(())
    } else {
        Err(AppError::invalid_file(
            "uploaded file must have a .jar filename",
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::models::scan::{
        AnalysisCoverage, Capability, Confidence, Finding, Obfuscation, ScanReport, Severity,
        Verdict, VirusTotalStatus,
    };

    use super::{is_cacheable_virustotal_report, merge_virustotal_findings};

    #[test]
    fn only_settled_virustotal_reports_are_cached() {
        let mut report = crate::virustotal::error_report("boom".to_owned());
        assert!(!is_cacheable_virustotal_report(&report));
        report.status = VirusTotalStatus::Queued;
        assert!(!is_cacheable_virustotal_report(&report));
        for status in [
            VirusTotalStatus::Completed,
            VirusTotalStatus::NotFound,
            VirusTotalStatus::TooLargeToUpload,
        ] {
            report.status = status;
            assert!(is_cacheable_virustotal_report(&report));
        }
    }

    #[test]
    fn virustotal_merge_preserves_non_finding_report_sections() {
        let capability = Capability {
            rule_id: "CONFIG_FILE_WRITE".to_owned(),
            message: "Writes a JSON configuration file".to_owned(),
            evidence: Vec::new(),
        };
        let mut report = ScanReport {
            verdict: Verdict::Clean,
            risk_score: 0,
            confidence: Confidence::High,
            obfuscation_score: 0,
            analysis_coverage: AnalysisCoverage::default(),
            capabilities: vec![capability.clone()],
            decoded_strings: Vec::new(),
            text_resources: Vec::new(),
            findings: Vec::new(),
            confirmed_chains: Vec::new(),
            obfuscation: Obfuscation::default(),
            limitations: Vec::new(),
        };

        let summary = merge_virustotal_findings(
            &mut report,
            vec![Finding::legacy(
                "VT_TRUSTED_MALICIOUS_ENGINE",
                "virustotal",
                Severity::Critical,
                "Trusted engine detected malware",
            )],
        );

        assert_eq!(report.capabilities, vec![capability]);
        assert_eq!(report.confidence, Confidence::High);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.risk_score, 70);
        assert_eq!(report.verdict, Verdict::Malicious);
        assert!(!summary.is_empty());
    }

    #[test]
    fn virustotal_merge_does_not_downgrade_an_unknown_static_verdict() {
        let mut report = ScanReport {
            verdict: Verdict::Unknown,
            risk_score: 0,
            confidence: Confidence::Medium,
            obfuscation_score: 25,
            analysis_coverage: AnalysisCoverage {
                method_flow_coverage: 0,
                ..Default::default()
            },
            capabilities: Vec::new(),
            decoded_strings: Vec::new(),
            text_resources: Vec::new(),
            findings: Vec::new(),
            confirmed_chains: Vec::new(),
            obfuscation: Obfuscation::default(),
            limitations: Vec::new(),
        };

        merge_virustotal_findings(&mut report, Vec::new());

        assert_eq!(report.verdict, Verdict::Unknown);
    }
}
