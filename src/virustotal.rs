use std::{collections::HashMap, path::Path};

use reqwest::{multipart, StatusCode};
use serde::Deserialize;

use crate::{
    config::VirusTotalConfig,
    models::scan::{
        VirusTotalEngineResult, VirusTotalReport, VirusTotalSource, VirusTotalStats,
        VirusTotalStatus,
    },
};

const API_BASE_URL: &str = "https://www.virustotal.com/api/v3";
const FLAGGED_CATEGORIES: &[&str] = &["malicious", "suspicious"];

/// Looks up a file by sha256 and uploads it only when VirusTotal has no existing report.
pub async fn analyze_file(
    config: &VirusTotalConfig,
    sha256: &str,
    file_path: &Path,
    filename: &str,
) -> anyhow::Result<VirusTotalReport> {
    let api_key = config
        .api_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("VIRUSTOTAL_API_KEY is required when enabled"))?;
    let client = reqwest::Client::builder().timeout(config.timeout).build()?;

    match lookup_file(&client, api_key, sha256).await? {
        LookupResult::Found(report) => return Ok(report),
        LookupResult::NotFound => {}
    }

    let metadata = tokio::fs::metadata(file_path).await?;
    if metadata.len() > config.upload_limit_bytes {
        return Ok(VirusTotalReport {
            status: VirusTotalStatus::TooLargeToUpload,
            source: VirusTotalSource::Lookup,
            stats: None,
            flagged_engines: Vec::new(),
            names: Vec::new(),
            first_submission_date: None,
            permalink: None,
            error: Some(
                "file is unknown to VirusTotal and exceeds the 32MB upload limit".to_owned(),
            ),
        });
    }

    let analysis_id = upload_file(&client, api_key, file_path, filename).await?;
    poll_analysis(&client, api_key, &analysis_id, config).await
}

/// Builds a public error report without exposing credentials or internal request details.
pub fn error_report(message: String) -> VirusTotalReport {
    VirusTotalReport {
        status: VirusTotalStatus::Error,
        source: VirusTotalSource::Lookup,
        stats: None,
        flagged_engines: Vec::new(),
        names: Vec::new(),
        first_submission_date: None,
        permalink: None,
        error: Some(message),
    }
}

enum LookupResult {
    Found(VirusTotalReport),
    NotFound,
}

async fn lookup_file(
    client: &reqwest::Client,
    api_key: &str,
    sha256: &str,
) -> anyhow::Result<LookupResult> {
    let response = client
        .get(format!("{API_BASE_URL}/files/{sha256}"))
        .header("x-apikey", api_key)
        .send()
        .await?;

    if response.status() == StatusCode::NOT_FOUND {
        return Ok(LookupResult::NotFound);
    }
    let response = response.error_for_status()?;
    let payload = response.json::<VirusTotalData<FileObject>>().await?;
    Ok(LookupResult::Found(file_report(
        payload.data,
        VirusTotalSource::Lookup,
    )))
}

async fn upload_file(
    client: &reqwest::Client,
    api_key: &str,
    file_path: &Path,
    filename: &str,
) -> anyhow::Result<String> {
    let bytes = tokio::fs::read(file_path).await?;
    let file_part = multipart::Part::bytes(bytes).file_name(filename.to_owned());
    let form = multipart::Form::new().part("file", file_part);

    let payload = client
        .post(format!("{API_BASE_URL}/files"))
        .header("x-apikey", api_key)
        .multipart(form)
        .send()
        .await?
        .error_for_status()?
        .json::<VirusTotalData<AnalysisRef>>()
        .await?;
    Ok(payload.data.id)
}

async fn poll_analysis(
    client: &reqwest::Client,
    api_key: &str,
    analysis_id: &str,
    config: &VirusTotalConfig,
) -> anyhow::Result<VirusTotalReport> {
    for attempt in 0..config.poll_attempts {
        let response = client
            .get(format!("{API_BASE_URL}/analyses/{analysis_id}"))
            .header("x-apikey", api_key)
            .send()
            .await?
            .error_for_status()?
            .json::<VirusTotalData<AnalysisObject>>()
            .await?;

        if response.data.attributes.status == "completed" {
            return Ok(analysis_report(response.data));
        }
        if attempt + 1 < config.poll_attempts {
            tokio::time::sleep(config.poll_interval).await;
        }
    }

    Ok(VirusTotalReport {
        status: VirusTotalStatus::Queued,
        source: VirusTotalSource::Upload,
        stats: None,
        flagged_engines: Vec::new(),
        names: Vec::new(),
        first_submission_date: None,
        permalink: None,
        error: None,
    })
}

fn file_report(file: FileObject, source: VirusTotalSource) -> VirusTotalReport {
    let permalink = file.links.and_then(|links| links.self_url);
    VirusTotalReport {
        status: VirusTotalStatus::Completed,
        source,
        stats: file.attributes.last_analysis_stats,
        flagged_engines: flagged_engines(file.attributes.last_analysis_results),
        names: file.attributes.names,
        first_submission_date: file.attributes.first_submission_date,
        permalink,
        error: None,
    }
}

fn analysis_report(analysis: AnalysisObject) -> VirusTotalReport {
    VirusTotalReport {
        status: VirusTotalStatus::Completed,
        source: VirusTotalSource::Upload,
        stats: analysis.attributes.stats,
        flagged_engines: flagged_engines(analysis.attributes.results),
        names: Vec::new(),
        first_submission_date: None,
        permalink: None,
        error: None,
    }
}

fn flagged_engines(
    results: HashMap<String, VirusTotalRawEngineResult>,
) -> Vec<VirusTotalEngineResult> {
    let mut engines = results
        .into_values()
        .filter(|result| FLAGGED_CATEGORIES.contains(&result.category.as_str()))
        .map(|result| VirusTotalEngineResult {
            engine_name: result.engine_name,
            category: result.category,
            result: result.result,
        })
        .collect::<Vec<_>>();
    engines.sort_by(|left, right| left.engine_name.cmp(&right.engine_name));
    engines
}

#[derive(Debug, Deserialize)]
struct VirusTotalData<T> {
    data: T,
}

#[derive(Debug, Deserialize)]
struct FileObject {
    attributes: FileAttributes,
    links: Option<FileLinks>,
}

#[derive(Debug, Default, Deserialize)]
struct FileAttributes {
    #[serde(default)]
    last_analysis_stats: Option<VirusTotalStats>,
    #[serde(default)]
    last_analysis_results: HashMap<String, VirusTotalRawEngineResult>,
    #[serde(default)]
    names: Vec<String>,
    first_submission_date: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct FileLinks {
    #[serde(rename = "self")]
    self_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnalysisRef {
    id: String,
}

#[derive(Debug, Deserialize)]
struct AnalysisObject {
    attributes: AnalysisAttributes,
}

#[derive(Debug, Default, Deserialize)]
struct AnalysisAttributes {
    status: String,
    #[serde(default)]
    stats: Option<VirusTotalStats>,
    #[serde(default)]
    results: HashMap<String, VirusTotalRawEngineResult>,
}

#[derive(Debug, Default, Deserialize)]
struct VirusTotalRawEngineResult {
    #[serde(default)]
    engine_name: String,
    #[serde(default)]
    category: String,
    result: Option<String>,
}
