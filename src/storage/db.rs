use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::models::scan::{
    Finding, ScanResponse, ScanStatus, Severity, Verdict, VirusTotalReport, VirusTotalSource,
};

/// Database row for scans before conversion into the public API response.
#[derive(Debug, sqlx::FromRow)]
pub struct ScanRow {
    pub id: Uuid,
    pub sha256: String,
    pub status: String,
    pub verdict: Option<String>,
    pub risk_score: i32,
    pub summary: String,
}

/// Database row for findings before conversion into typed API/domain objects.
#[derive(Debug, sqlx::FromRow)]
struct FindingRow {
    rule_id: String,
    category: String,
    severity: String,
    message: String,
}

/// Database row for cached VirusTotal reports.
#[derive(Debug, sqlx::FromRow)]
struct VirusTotalReportRow {
    report_json: serde_json::Value,
}

/// Candidate file selected for retention cleanup.
#[derive(Debug, sqlx::FromRow)]
pub struct ExpiredFileRow {
    pub id: Uuid,
    pub storage_path: String,
}

/// Applies sqlx migrations embedded at compile time before the service uses the schema.
pub async fn run_migrations(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

/// Creates the pending scan row before the worker starts so clients can poll immediately.
pub async fn create_pending_scan(
    pool: &PgPool,
    scan_id: Uuid,
    original_filename: &str,
    sha256: &str,
    storage_path: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO scans (id, original_filename, sha256, status, storage_path)
        VALUES ($1, $2, $3, 'pending', $4)
        "#,
    )
    .bind(scan_id)
    .bind(original_filename)
    .bind(sha256)
    .bind(storage_path)
    .execute(pool)
    .await?;
    Ok(())
}

/// Returns the newest scan for a hash so duplicate uploads can reuse existing verdicts.
pub async fn find_latest_scan_by_sha256(
    pool: &PgPool,
    sha256: &str,
) -> anyhow::Result<Option<ScanResponse>> {
    let row = sqlx::query_as::<_, ScanRow>(
        r#"
        SELECT id, sha256, status, verdict, risk_score, summary
        FROM scans
        WHERE sha256 = $1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(sha256)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(scan) => Ok(Some(scan_response_from_row(pool, scan).await?)),
        None => Ok(None),
    }
}

/// Returns a scan by id with findings for polling clients.
pub async fn find_scan_by_id(pool: &PgPool, scan_id: Uuid) -> anyhow::Result<Option<ScanResponse>> {
    let row = sqlx::query_as::<_, ScanRow>(
        r#"
        SELECT id, sha256, status, verdict, risk_score, summary
        FROM scans
        WHERE id = $1
        LIMIT 1
        "#,
    )
    .bind(scan_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(scan) => Ok(Some(scan_response_from_row(pool, scan).await?)),
        None => Ok(None),
    }
}

/// Marks a scan complete and replaces findings in one transaction to keep responses consistent.
pub async fn complete_scan(
    pool: &PgPool,
    scan_id: Uuid,
    verdict: Verdict,
    risk_score: u8,
    summary: &str,
    findings: &[Finding],
) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE scans
        SET status = 'done',
            verdict = $2,
            risk_score = $3,
            summary = $4,
            error_code = NULL,
            error_message = NULL,
            updated_at = now(),
            completed_at = now()
        WHERE id = $1
        "#,
    )
    .bind(scan_id)
    .bind(verdict.as_str())
    .bind(i32::from(risk_score))
    .bind(summary)
    .execute(&mut *tx)
    .await?;
    replace_findings(&mut tx, scan_id, findings).await?;
    tx.commit().await?;
    Ok(())
}

/// Marks infrastructure failures separately from scanner `unknown` verdicts.
pub async fn fail_scan(
    pool: &PgPool,
    scan_id: Uuid,
    error_code: &str,
    error_message: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        UPDATE scans
        SET status = 'failed',
            verdict = NULL,
            risk_score = 0,
            summary = '',
            error_code = $2,
            error_message = $3,
            updated_at = now(),
            completed_at = now()
        WHERE id = $1
        "#,
    )
    .bind(scan_id)
    .bind(error_code)
    .bind(error_message)
    .execute(pool)
    .await?;
    Ok(())
}

/// Marks a restored duplicate upload as physically present again after retention deletion.
pub async fn mark_file_available(
    pool: &PgPool,
    scan_id: Uuid,
    storage_path: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        UPDATE scans
        SET storage_path = $2, file_deleted = false, updated_at = now()
        WHERE id = $1
        "#,
    )
    .bind(scan_id)
    .bind(storage_path)
    .execute(pool)
    .await?;
    Ok(())
}

/// Lists file paths past retention without deleting DB scan metadata.
pub async fn list_expired_files(
    pool: &PgPool,
    cutoff: DateTime<Utc>,
) -> sqlx::Result<Vec<ExpiredFileRow>> {
    sqlx::query_as::<_, ExpiredFileRow>(
        r#"
        SELECT id, storage_path
        FROM scans
        WHERE file_deleted = false AND created_at < $1
        LIMIT 100
        "#,
    )
    .bind(cutoff)
    .fetch_all(pool)
    .await
}

/// Records that cleanup removed the physical jar while preserving the scan row forever.
pub async fn mark_file_deleted(pool: &PgPool, scan_id: Uuid) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        UPDATE scans
        SET file_deleted = true, updated_at = now()
        WHERE id = $1
        "#,
    )
    .bind(scan_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Returns a fresh VirusTotal cache entry that can be reused without another external request.
pub async fn find_fresh_virustotal_report(
    pool: &PgPool,
    sha256: &str,
) -> anyhow::Result<Option<VirusTotalReport>> {
    let row = sqlx::query_as::<_, VirusTotalReportRow>(
        r#"
        SELECT report_json
        FROM virustotal_reports
        WHERE sha256 = $1 AND expires_at > now()
        LIMIT 1
        "#,
    )
    .bind(sha256)
    .fetch_optional(pool)
    .await?;

    row.map(report_from_row).transpose()
}

/// Upserts a VirusTotal report with a TTL so duplicate scans do not spend quota.
pub async fn upsert_virustotal_report(
    pool: &PgPool,
    sha256: &str,
    report: &VirusTotalReport,
    ttl: Duration,
) -> anyhow::Result<()> {
    let chrono_ttl = chrono::Duration::from_std(ttl)?;
    let expires_at = Utc::now() + chrono_ttl;
    let report_json = serde_json::to_value(report)?;

    sqlx::query(
        r#"
        INSERT INTO virustotal_reports (sha256, report_json, fetched_at, expires_at)
        VALUES ($1, $2, now(), $3)
        ON CONFLICT (sha256) DO UPDATE
        SET report_json = EXCLUDED.report_json,
            fetched_at = now(),
            expires_at = EXCLUDED.expires_at
        "#,
    )
    .bind(sha256)
    .bind(report_json)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Replaces findings inside an existing transaction so scan completion is atomic.
async fn replace_findings(
    tx: &mut Transaction<'_, Postgres>,
    scan_id: Uuid,
    findings: &[Finding],
) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM findings WHERE scan_id = $1")
        .bind(scan_id)
        .execute(&mut **tx)
        .await?;

    for finding in findings {
        sqlx::query(
            r#"
            INSERT INTO findings (scan_id, rule_id, category, severity, message)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(scan_id)
        .bind(&finding.rule_id)
        .bind(&finding.category)
        .bind(finding.severity.as_str())
        .bind(&finding.message)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Converts database rows to the public response and validates enum strings at the boundary.
async fn scan_response_from_row(pool: &PgPool, scan: ScanRow) -> anyhow::Result<ScanResponse> {
    let findings = scan_findings(pool, scan.id).await?;
    let virustotal = find_virustotal_report_for_response(pool, &scan.sha256).await?;
    Ok(ScanResponse {
        scan_id: scan.id,
        status: ScanStatus::from_db(&scan.status)?,
        sha256: scan.sha256,
        verdict: scan.verdict.as_deref().map(Verdict::from_db).transpose()?,
        risk_score: scan.risk_score.clamp(0, 100) as u8,
        summary: scan.summary,
        findings: findings.iter().map(Finding::to_response).collect(),
        virustotal,
    })
}

/// Loads findings for one scan in insertion order for stable API output.
async fn scan_findings(pool: &PgPool, scan_id: Uuid) -> anyhow::Result<Vec<Finding>> {
    let rows = sqlx::query_as::<_, FindingRow>(
        r#"
        SELECT rule_id, category, severity, message
        FROM findings
        WHERE scan_id = $1
        ORDER BY id ASC
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok(Finding {
                rule_id: row.rule_id,
                category: row.category,
                severity: Severity::from_db(&row.severity)?,
                message: row.message,
            })
        })
        .collect()
}

/// Returns the last VirusTotal report for API responses, even when too old for quota caching.
async fn find_virustotal_report_for_response(
    pool: &PgPool,
    sha256: &str,
) -> anyhow::Result<Option<VirusTotalReport>> {
    let row = sqlx::query_as::<_, VirusTotalReportRow>(
        r#"
        SELECT report_json
        FROM virustotal_reports
        WHERE sha256 = $1
        LIMIT 1
        "#,
    )
    .bind(sha256)
    .fetch_optional(pool)
    .await?;

    row.map(report_from_row).transpose()
}

/// Deserializes a cached report and marks it as cache-sourced for callers.
fn report_from_row(row: VirusTotalReportRow) -> anyhow::Result<VirusTotalReport> {
    let mut report = serde_json::from_value::<VirusTotalReport>(row.report_json)?;
    report.source = VirusTotalSource::Cache;
    Ok(report)
}
