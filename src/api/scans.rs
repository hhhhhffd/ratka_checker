use std::path::PathBuf;

use axum::extract::{Multipart, Path, State};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    api::AppState,
    error::AppError,
    models::scan::{Finding, ScanReport},
    response::PrettyJson,
    scanner::archive,
    storage::{db, files},
    virustotal,
};

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

    if let Some(existing) = db::find_latest_scan_by_sha256(&state.db, &sha256)
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
        outcome.summary = merge_virustotal_findings(
            &mut outcome.report,
            virustotal::findings_for_report(&report),
        );
    }

    db::complete_scan_report(&state.db, scan_id, &outcome.report, &outcome.summary).await
}

/// Adds VirusTotal evidence to the structured report without discarding static-analysis context.
fn merge_virustotal_findings(
    report: &mut ScanReport,
    findings: impl IntoIterator<Item = Finding>,
) -> String {
    report.findings.extend(findings);
    let (verdict, risk_score, summary) = archive::finalize_findings(&report.findings);
    report.verdict = verdict;
    report.risk_score = risk_score;
    summary
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

    db::upsert_virustotal_report(
        &state.db,
        sha256,
        &report,
        state.config.virustotal.cache_ttl,
    )
    .await?;
    Ok(Some(report))
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
        Capability, Confidence, Finding, Obfuscation, ScanReport, Severity, Verdict,
    };

    use super::merge_virustotal_findings;

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
            capabilities: vec![capability.clone()],
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
        assert_eq!(report.risk_score, Severity::Critical.score_weight());
        assert_eq!(report.verdict, Verdict::Suspicious);
        assert!(!summary.is_empty());
    }
}
