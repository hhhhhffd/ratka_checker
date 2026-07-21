use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::models::scan::{
    AnalysisCoverage, Capability, CodeScope, Confidence, ConfirmedChain, DecodedString, Finding,
    FindingKind, Limitation, Obfuscation, ScanReport, ScanResponse, ScanStatus, Severity,
    TextResource, Verdict, VirusTotalReport, VirusTotalSource,
};
use crate::virustotal;

/// Database row for scans before conversion into the public API response.
#[derive(Debug, sqlx::FromRow)]
pub struct ScanRow {
    pub id: Uuid,
    pub sha256: String,
    pub status: String,
    pub verdict: Option<String>,
    pub risk_score: i32,
    pub confidence: String,
    pub obfuscation: serde_json::Value,
    pub analysis_coverage: serde_json::Value,
}

/// Database row for findings before conversion into typed API/domain objects.
#[derive(Debug, sqlx::FromRow)]
struct FindingRow {
    rule_id: String,
    category: String,
    severity: String,
    finding_kind: String,
    confidence: String,
    score_contribution: i32,
    scope: String,
    evidence: serde_json::Value,
    chain_id: Option<String>,
    message: String,
}

#[derive(Debug, sqlx::FromRow)]
struct CapabilityRow {
    rule_id: String,
    message: String,
    evidence: serde_json::Value,
}

#[derive(Debug, sqlx::FromRow)]
struct ConfirmedChainRow {
    chain_id: String,
    rule_id: String,
    severity: String,
    confidence: String,
    score_contribution: i32,
    operations: serde_json::Value,
    evidence: serde_json::Value,
}

#[derive(Debug, sqlx::FromRow)]
struct LimitationRow {
    code: String,
    message: String,
    evidence: serde_json::Value,
}

#[derive(Debug, sqlx::FromRow)]
struct DecodedStringRow {
    original_value: String,
    decoder_method: String,
    decoded_value: String,
    confidence: String,
    evidence: serde_json::Value,
}

#[derive(Debug, sqlx::FromRow)]
struct TextResourceRow {
    archive_id: String,
    archive_path: String,
    resource_path: String,
    detected_encoding: String,
    confidence: String,
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
        SELECT id, sha256, status, verdict, risk_score, confidence, obfuscation, analysis_coverage
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
        SELECT id, sha256, status, verdict, risk_score, confidence, obfuscation, analysis_coverage
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
#[allow(dead_code)]
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

/// Persists the full structured scan report atomically for the new API response model.
pub async fn complete_scan_report(
    pool: &PgPool,
    scan_id: Uuid,
    report: &ScanReport,
    summary: &str,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let obfuscation = serde_json::to_value(&report.obfuscation)?;
    let analysis_coverage = serde_json::to_value(&report.analysis_coverage)?;
    sqlx::query(
        r#"
        UPDATE scans SET status = 'done', verdict = $2, risk_score = $3, summary = $4,
            confidence = $5, obfuscation = $6, analysis_coverage = $7,
            error_code = NULL, error_message = NULL,
            updated_at = now(), completed_at = now()
        WHERE id = $1
        "#,
    )
    .bind(scan_id)
    .bind(report.verdict.as_str())
    .bind(i32::from(report.risk_score))
    .bind(summary)
    .bind(report.confidence.as_str())
    .bind(obfuscation)
    .bind(analysis_coverage)
    .execute(&mut *tx)
    .await?;
    replace_findings(&mut tx, scan_id, &report.findings).await?;
    replace_capabilities(&mut tx, scan_id, &report.capabilities).await?;
    replace_confirmed_chains(&mut tx, scan_id, &report.confirmed_chains).await?;
    replace_limitations(&mut tx, scan_id, &report.limitations).await?;
    replace_decoded_strings(&mut tx, scan_id, &report.decoded_strings).await?;
    replace_text_resources(&mut tx, scan_id, &report.text_resources).await?;
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
        let evidence = serde_json::to_value(&finding.evidence)
            .map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
        sqlx::query(
            r#"
            INSERT INTO findings
                (scan_id, rule_id, category, severity, finding_kind, confidence,
                 score_contribution, scope, evidence, chain_id, message)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(scan_id)
        .bind(&finding.rule_id)
        .bind(&finding.category)
        .bind(finding.severity.as_str())
        .bind(finding.kind.as_str())
        .bind(finding.confidence.as_str())
        .bind(i32::from(finding.score_contribution))
        .bind(finding.scope.as_str())
        .bind(evidence)
        .bind(&finding.related_chain_id)
        .bind(&finding.message)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn replace_capabilities(
    tx: &mut Transaction<'_, Postgres>,
    scan_id: Uuid,
    capabilities: &[Capability],
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM scan_capabilities WHERE scan_id = $1")
        .bind(scan_id)
        .execute(&mut **tx)
        .await?;
    for capability in capabilities {
        sqlx::query("INSERT INTO scan_capabilities (scan_id, rule_id, message, evidence) VALUES ($1, $2, $3, $4)")
            .bind(scan_id).bind(&capability.rule_id).bind(&capability.message)
            .bind(serde_json::to_value(&capability.evidence)?).execute(&mut **tx).await?;
    }
    Ok(())
}

async fn replace_confirmed_chains(
    tx: &mut Transaction<'_, Postgres>,
    scan_id: Uuid,
    chains: &[ConfirmedChain],
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM confirmed_chains WHERE scan_id = $1")
        .bind(scan_id)
        .execute(&mut **tx)
        .await?;
    for chain in chains {
        sqlx::query(r#"INSERT INTO confirmed_chains
            (scan_id, chain_id, rule_id, severity, confidence, score_contribution, operations, evidence)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#)
            .bind(scan_id).bind(&chain.chain_id).bind(&chain.rule_id).bind(chain.severity.as_str())
            .bind(chain.confidence.as_str()).bind(i32::from(chain.score_contribution))
            .bind(serde_json::to_value(&chain.operations)?).bind(serde_json::to_value(&chain.evidence)?)
            .execute(&mut **tx).await?;
    }
    Ok(())
}

async fn replace_limitations(
    tx: &mut Transaction<'_, Postgres>,
    scan_id: Uuid,
    limitations: &[Limitation],
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM scan_limitations WHERE scan_id = $1")
        .bind(scan_id)
        .execute(&mut **tx)
        .await?;
    for limitation in limitations {
        sqlx::query("INSERT INTO scan_limitations (scan_id, code, message, evidence) VALUES ($1, $2, $3, $4)")
            .bind(scan_id).bind(&limitation.code).bind(&limitation.message)
            .bind(serde_json::to_value(&limitation.evidence)?).execute(&mut **tx).await?;
    }
    Ok(())
}

async fn replace_decoded_strings(
    tx: &mut Transaction<'_, Postgres>,
    scan_id: Uuid,
    values: &[DecodedString],
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM scan_decoded_strings WHERE scan_id = $1")
        .bind(scan_id)
        .execute(&mut **tx)
        .await?;
    for value in values {
        sqlx::query(
            r#"INSERT INTO scan_decoded_strings
                (scan_id, original_value, decoder_method, decoded_value, confidence, evidence)
                VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(scan_id)
        .bind(&value.original_value)
        .bind(&value.decoder_method)
        .bind(&value.decoded_value)
        .bind(value.confidence.as_str())
        .bind(serde_json::to_value(&value.evidence)?)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn replace_text_resources(
    tx: &mut Transaction<'_, Postgres>,
    scan_id: Uuid,
    resources: &[TextResource],
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM scan_text_resources WHERE scan_id = $1")
        .bind(scan_id)
        .execute(&mut **tx)
        .await?;
    for resource in resources {
        sqlx::query(
            r#"INSERT INTO scan_text_resources
                (scan_id, archive_id, archive_path, resource_path, detected_encoding, confidence)
                VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(scan_id)
        .bind(&resource.archive_id)
        .bind(&resource.archive_path)
        .bind(&resource.resource_path)
        .bind(&resource.detected_encoding)
        .bind(resource.confidence.as_str())
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Converts database rows to the public response and validates enum strings at the boundary.
async fn scan_response_from_row(pool: &PgPool, scan: ScanRow) -> anyhow::Result<ScanResponse> {
    let findings = scan_findings(pool, scan.id).await?;
    let capabilities = scan_capabilities(pool, scan.id).await?;
    let confirmed_chains = scan_confirmed_chains(pool, scan.id).await?;
    let limitations = scan_limitations(pool, scan.id).await?;
    let decoded_strings = scan_decoded_strings(pool, scan.id).await?;
    let text_resources = scan_text_resources(pool, scan.id).await?;
    let virustotal = find_virustotal_report_for_response(pool, &scan.sha256).await?;
    Ok(ScanResponse {
        scan_id: scan.id,
        status: ScanStatus::from_db(&scan.status)?,
        sha256: scan.sha256,
        verdict: scan.verdict.as_deref().map(Verdict::from_db).transpose()?,
        risk_score: scan.risk_score.clamp(0, 100) as u8,
        confidence: Confidence::from_db(&scan.confidence)?,
        obfuscation_score: serde_json::from_value::<Obfuscation>(scan.obfuscation.clone())?.score,
        analysis_coverage: serde_json::from_value::<AnalysisCoverage>(scan.analysis_coverage)?,
        capabilities,
        decoded_strings,
        text_resources,
        findings,
        confirmed_chains,
        obfuscation: serde_json::from_value::<Obfuscation>(scan.obfuscation)?,
        limitations,
        virustotal,
    })
}

/// Loads findings for one scan in insertion order for stable API output.
async fn scan_findings(pool: &PgPool, scan_id: Uuid) -> anyhow::Result<Vec<Finding>> {
    let rows = sqlx::query_as::<_, FindingRow>(
        r#"
        SELECT rule_id, category, severity, finding_kind, confidence, score_contribution,
               scope, evidence, chain_id, message
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
                kind: FindingKind::from_db(&row.finding_kind)?,
                severity: Severity::from_db(&row.severity)?,
                confidence: Confidence::from_db(&row.confidence)?,
                score_contribution: row.score_contribution.clamp(0, 100) as u8,
                scope: CodeScope::from_db(&row.scope)?,
                message: row.message,
                evidence: serde_json::from_value(row.evidence)?,
                related_chain_id: row.chain_id,
            })
        })
        .collect()
}

async fn scan_capabilities(pool: &PgPool, scan_id: Uuid) -> anyhow::Result<Vec<Capability>> {
    let rows = sqlx::query_as::<_, CapabilityRow>(
        "SELECT rule_id, message, evidence FROM scan_capabilities WHERE scan_id = $1 ORDER BY id ASC",
    ).bind(scan_id).fetch_all(pool).await?;
    rows.into_iter()
        .map(|row| {
            Ok(Capability {
                rule_id: row.rule_id,
                message: row.message,
                evidence: serde_json::from_value(row.evidence)?,
            })
        })
        .collect()
}

async fn scan_confirmed_chains(
    pool: &PgPool,
    scan_id: Uuid,
) -> anyhow::Result<Vec<ConfirmedChain>> {
    let rows = sqlx::query_as::<_, ConfirmedChainRow>(r#"SELECT chain_id, rule_id, severity, confidence,
        score_contribution, operations, evidence FROM confirmed_chains WHERE scan_id = $1 ORDER BY id ASC"#)
        .bind(scan_id).fetch_all(pool).await?;
    rows.into_iter()
        .map(|row| {
            Ok(ConfirmedChain {
                chain_id: row.chain_id,
                rule_id: row.rule_id,
                severity: Severity::from_db(&row.severity)?,
                confidence: Confidence::from_db(&row.confidence)?,
                score_contribution: row.score_contribution.clamp(0, 100) as u8,
                operations: serde_json::from_value(row.operations)?,
                evidence: serde_json::from_value(row.evidence)?,
            })
        })
        .collect()
}

async fn scan_limitations(pool: &PgPool, scan_id: Uuid) -> anyhow::Result<Vec<Limitation>> {
    let rows = sqlx::query_as::<_, LimitationRow>(
        "SELECT code, message, evidence FROM scan_limitations WHERE scan_id = $1 ORDER BY id ASC",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(Limitation {
                code: row.code,
                message: row.message,
                evidence: serde_json::from_value(row.evidence)?,
            })
        })
        .collect()
}

async fn scan_decoded_strings(pool: &PgPool, scan_id: Uuid) -> anyhow::Result<Vec<DecodedString>> {
    let rows = sqlx::query_as::<_, DecodedStringRow>(
        r#"SELECT original_value, decoder_method, decoded_value, confidence, evidence
           FROM scan_decoded_strings WHERE scan_id = $1 ORDER BY id ASC"#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(DecodedString {
                original_value: row.original_value,
                decoder_method: row.decoder_method,
                decoded_value: row.decoded_value,
                confidence: Confidence::from_db(&row.confidence)?,
                evidence: serde_json::from_value(row.evidence)?,
            })
        })
        .collect()
}

async fn scan_text_resources(pool: &PgPool, scan_id: Uuid) -> anyhow::Result<Vec<TextResource>> {
    let rows = sqlx::query_as::<_, TextResourceRow>(
        r#"SELECT archive_id, archive_path, resource_path, detected_encoding, confidence
           FROM scan_text_resources WHERE scan_id = $1 ORDER BY id ASC"#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(TextResource {
                archive_id: row.archive_id,
                archive_path: row.archive_path,
                resource_path: row.resource_path,
                detected_encoding: row.detected_encoding,
                confidence: Confidence::from_db(&row.confidence)?,
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
    report.ensure_behavior_shape();
    virustotal::sanitize_report(&mut report);
    Ok(report)
}
