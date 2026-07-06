use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use reqwest::{multipart, StatusCode};
use serde::Deserialize;

use crate::{
    config::VirusTotalConfig,
    models::scan::{
        Finding, Severity, VirusTotalBehaviorInfo, VirusTotalBehaviorReport,
        VirusTotalEngineResult, VirusTotalReport, VirusTotalSource, VirusTotalStats,
        VirusTotalStatus,
    },
};

const API_BASE_URL: &str = "https://www.virustotal.com/api/v3";
const BEHAVIOR_VALUE_LIMIT: usize = 50;
const BEHAVIOR_STRING_LIMIT: usize = 300;
const FLAGGED_CATEGORIES: &[&str] = &["malicious", "suspicious"];
const TRUSTED_ENGINES: &[&str] = &[
    "BitDefender",
    "ESET-NOD32",
    "Emsisoft",
    "F-Secure",
    "Fortinet",
    "Kaspersky",
    "Malwarebytes",
    "Microsoft",
    "Sophos",
    "Symantec",
    "TrendMicro",
    "TrendMicro-HouseCall",
    "Webroot",
    "Windows Defender",
];

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
            behavior: behavior_info(None),
            error: Some(
                "file is unknown to VirusTotal and exceeds the 32MB upload limit".to_owned(),
            ),
        });
    }

    let analysis_id = upload_file(&client, api_key, file_path, filename).await?;
    poll_analysis(&client, api_key, &analysis_id, sha256, config).await
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
        behavior: behavior_info(None),
        error: Some(message),
    }
}

/// Converts a completed VirusTotal report into weighted findings for the main risk score.
pub fn findings_for_report(report: &VirusTotalReport) -> Vec<Finding> {
    if report.status != VirusTotalStatus::Completed {
        return Vec::new();
    }

    let malicious_engines = report
        .flagged_engines
        .iter()
        .filter(|engine| engine.category == "malicious")
        .collect::<Vec<_>>();
    let trusted_malicious = malicious_engines
        .iter()
        .copied()
        .filter(|engine| is_trusted_engine(&engine.engine_name))
        .collect::<Vec<_>>();

    if !trusted_malicious.is_empty() {
        return vec![Finding {
            rule_id: "VT_TRUSTED_MALICIOUS_ENGINE".to_owned(),
            category: "virustotal".to_owned(),
            severity: Severity::Critical,
            message: format!(
                "VirusTotal: trusted engine detected malware: {}",
                engine_summary(&trusted_malicious)
            ),
        }];
    }

    if malicious_engines.len() >= 3 {
        return vec![Finding {
            rule_id: "VT_MULTIPLE_MALICIOUS_ENGINES".to_owned(),
            category: "virustotal".to_owned(),
            severity: Severity::High,
            message: format!(
                "VirusTotal: {} engines detected malware: {}",
                malicious_engines.len(),
                engine_summary(&malicious_engines)
            ),
        }];
    }

    if !malicious_engines.is_empty() {
        return vec![Finding {
            rule_id: "VT_SINGLE_MALICIOUS_ENGINE".to_owned(),
            category: "virustotal".to_owned(),
            severity: Severity::Medium,
            message: format!(
                "VirusTotal: single engine detected malware: {}",
                engine_summary(&malicious_engines)
            ),
        }];
    }

    let suspicious_count = report
        .flagged_engines
        .iter()
        .filter(|engine| engine.category == "suspicious")
        .count();
    if suspicious_count > 0 {
        return vec![Finding {
            rule_id: "VT_SUSPICIOUS_ENGINES".to_owned(),
            category: "virustotal".to_owned(),
            severity: Severity::Low,
            message: format!("VirusTotal: {suspicious_count} engines marked file suspicious"),
        }];
    }

    Vec::new()
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
    let mut report = file_report(payload.data, VirusTotalSource::Lookup);
    match lookup_file_behaviours(client, api_key, sha256).await {
        Ok(Some(behavior)) => {
            report.behavior = Some(behavior);
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(sha256, %error, "VirusTotal behaviour lookup failed");
        }
    }
    Ok(LookupResult::Found(report))
}

async fn lookup_file_behaviours(
    client: &reqwest::Client,
    api_key: &str,
    sha256: &str,
) -> anyhow::Result<Option<VirusTotalBehaviorInfo>> {
    let response = client
        .get(format!("{API_BASE_URL}/files/{sha256}/behaviours"))
        .header("x-apikey", api_key)
        .send()
        .await?;

    if matches!(
        response.status(),
        StatusCode::NOT_FOUND | StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
    ) {
        return Ok(None);
    }

    let response = response.error_for_status()?;
    let payload = response
        .json::<VirusTotalData<Vec<VirusTotalBehaviorObject>>>()
        .await?;
    if payload.data.is_empty() {
        return Ok(None);
    }
    Ok(Some(behavior_info_from_reports(payload.data)))
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
    sha256: &str,
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
            let mut report = analysis_report(response.data);
            if let Ok(Some(behavior)) = lookup_file_behaviours(client, api_key, sha256).await {
                report.behavior = Some(behavior);
            }
            return Ok(report);
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
        behavior: behavior_info(None),
        error: None,
    })
}

fn file_report(file: FileObject, source: VirusTotalSource) -> VirusTotalReport {
    let permalink = file.links.and_then(|links| links.self_url);
    let behavior_available = file.attributes.behavior_available();
    VirusTotalReport {
        status: VirusTotalStatus::Completed,
        source,
        stats: file.attributes.last_analysis_stats,
        flagged_engines: flagged_engines(file.attributes.last_analysis_results),
        names: file.attributes.names,
        first_submission_date: file.attributes.first_submission_date,
        permalink,
        behavior: behavior_info(behavior_available),
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
        behavior: behavior_info(None),
        error: None,
    }
}

fn behavior_info(available: Option<bool>) -> Option<VirusTotalBehaviorInfo> {
    Some(VirusTotalBehaviorInfo::empty(available))
}

fn behavior_info_from_reports(
    behavior_reports: Vec<VirusTotalBehaviorObject>,
) -> VirusTotalBehaviorInfo {
    let mut behavior = VirusTotalBehaviorInfo::empty(Some(true));
    for raw_report in behavior_reports {
        let report = behavior_report_from_attributes(raw_report.attributes);
        extend_unique(&mut behavior.contacted_ips, &report.contacted_ips);
        extend_unique(&mut behavior.contacted_domains, &report.contacted_domains);
        extend_unique(&mut behavior.contacted_urls, &report.contacted_urls);
        extend_unique(&mut behavior.dropped_files, &report.dropped_files);
        extend_unique(&mut behavior.files_written, &report.files_written);
        extend_unique(&mut behavior.processes_created, &report.processes_created);
        extend_unique(&mut behavior.command_executions, &report.command_executions);
        extend_unique(&mut behavior.dns_lookups, &report.dns_lookups);
        behavior.reports.push(report);
    }
    behavior
}

fn behavior_report_from_attributes(attributes: serde_json::Value) -> VirusTotalBehaviorReport {
    VirusTotalBehaviorReport {
        sandbox_name: string_field(&attributes, &["sandbox_name", "sandbox", "environment_id"]),
        analysis_date: integer_field(&attributes, &["analysis_date", "date"]),
        verdict: string_field(
            &attributes,
            &["verdict", "sandbox_verdict", "classification", "category"],
        ),
        contacted_ips: field_strings(
            &attributes,
            &["contacted_ips", "ip_traffic", "network", "hosts"],
        ),
        contacted_domains: field_strings(
            &attributes,
            &["contacted_domains", "domains", "dns_lookups", "hosts"],
        ),
        contacted_urls: field_strings(
            &attributes,
            &["contacted_urls", "http_conversations", "urls"],
        ),
        dropped_files: field_strings(&attributes, &["dropped_files", "files_dropped"]),
        files_written: field_strings(
            &attributes,
            &["files_written", "files_created", "files_deleted"],
        ),
        processes_created: field_strings(
            &attributes,
            &[
                "processes_created",
                "processes_terminated",
                "process_tree",
                "processes",
            ],
        ),
        command_executions: field_strings(
            &attributes,
            &[
                "command_executions",
                "commands_executed",
                "cmd",
                "command_line",
            ],
        ),
        dns_lookups: field_strings(&attributes, &["dns_lookups", "dns_requests"]),
    }
}

fn string_field(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .find_map(json_string)
        .map(truncate_behavior_string)
}

fn integer_field(value: &serde_json::Value, keys: &[&str]) -> Option<i64> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .find_map(serde_json::Value::as_i64)
}

fn field_strings(value: &serde_json::Value, keys: &[&str]) -> Vec<String> {
    let mut output = Vec::new();
    for key in keys {
        if let Some(field_value) = value.get(*key) {
            collect_json_strings(field_value, &mut output);
        }
    }
    unique_limited(output)
}

fn collect_json_strings(value: &serde_json::Value, output: &mut Vec<String>) {
    if output.len() >= BEHAVIOR_VALUE_LIMIT {
        return;
    }
    match value {
        serde_json::Value::String(text) => output.push(truncate_behavior_string(text)),
        serde_json::Value::Array(values) => {
            for value in values {
                collect_json_strings(value, output);
                if output.len() >= BEHAVIOR_VALUE_LIMIT {
                    break;
                }
            }
        }
        serde_json::Value::Object(object) => {
            for value in object.values() {
                collect_json_strings(value, output);
                if output.len() >= BEHAVIOR_VALUE_LIMIT {
                    break;
                }
            }
        }
        serde_json::Value::Number(number) => output.push(number.to_string()),
        _ => {}
    }
}

fn json_string(value: &serde_json::Value) -> Option<&str> {
    match value {
        serde_json::Value::String(text) => Some(text.as_str()),
        _ => None,
    }
}

fn extend_unique(target: &mut Vec<String>, values: &[String]) {
    let mut seen = target.iter().cloned().collect::<HashSet<_>>();
    for value in values {
        if target.len() >= BEHAVIOR_VALUE_LIMIT {
            break;
        }
        if seen.insert(value.clone()) {
            target.push(value.clone());
        }
    }
}

fn unique_limited(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for value in values {
        if output.len() >= BEHAVIOR_VALUE_LIMIT {
            break;
        }
        if seen.insert(value.clone()) {
            output.push(value);
        }
    }
    output
}

fn truncate_behavior_string(value: &str) -> String {
    value.chars().take(BEHAVIOR_STRING_LIMIT).collect()
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

fn is_trusted_engine(engine_name: &str) -> bool {
    TRUSTED_ENGINES
        .iter()
        .any(|trusted| engine_name.eq_ignore_ascii_case(trusted))
}

fn engine_summary(engines: &[&VirusTotalEngineResult]) -> String {
    engines
        .iter()
        .take(5)
        .map(|engine| match &engine.result {
            Some(result) => format!("{} ({result})", engine.engine_name),
            None => engine.engine_name.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
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

#[derive(Debug, Deserialize)]
struct VirusTotalBehaviorObject {
    attributes: serde_json::Value,
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
    #[serde(default)]
    sandbox_verdicts: HashMap<String, serde_json::Value>,
    #[serde(default)]
    threat_severity: Option<ThreatSeverity>,
}

impl FileAttributes {
    fn behavior_available(&self) -> Option<bool> {
        self.threat_severity
            .as_ref()
            .and_then(|severity| {
                severity
                    .threat_severity_data
                    .as_ref()
                    .and_then(|data| data.can_be_detonated)
            })
            .or_else(|| {
                if self.sandbox_verdicts.is_empty() {
                    None
                } else {
                    Some(true)
                }
            })
    }
}

#[derive(Debug, Default, Deserialize)]
struct ThreatSeverity {
    #[serde(default)]
    threat_severity_data: Option<ThreatSeverityData>,
}

#[derive(Debug, Default, Deserialize)]
struct ThreatSeverityData {
    can_be_detonated: Option<bool>,
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

#[cfg(test)]
mod tests {
    use crate::models::scan::{VirusTotalSource, VirusTotalStatus};

    use super::*;

    #[test]
    fn trusted_malicious_engine_becomes_critical_finding() {
        let report = VirusTotalReport {
            status: VirusTotalStatus::Completed,
            source: VirusTotalSource::Lookup,
            stats: None,
            flagged_engines: vec![VirusTotalEngineResult {
                engine_name: "Kaspersky".to_owned(),
                category: "malicious".to_owned(),
                result: Some("Trojan-PSW.Win32.Test".to_owned()),
            }],
            names: Vec::new(),
            first_submission_date: None,
            permalink: None,
            behavior: behavior_info(None),
            error: None,
        };

        let findings = findings_for_report(&report);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VT_TRUSTED_MALICIOUS_ENGINE");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn clean_virustotal_report_does_not_add_findings() {
        let report = VirusTotalReport {
            status: VirusTotalStatus::Completed,
            source: VirusTotalSource::Lookup,
            stats: None,
            flagged_engines: Vec::new(),
            names: Vec::new(),
            first_submission_date: None,
            permalink: None,
            behavior: behavior_info(None),
            error: None,
        };

        assert!(findings_for_report(&report).is_empty());
    }

    #[test]
    fn file_attributes_report_behavior_availability() {
        let attributes = FileAttributes {
            threat_severity: Some(ThreatSeverity {
                threat_severity_data: Some(ThreatSeverityData {
                    can_be_detonated: Some(true),
                }),
            }),
            ..Default::default()
        };

        assert_eq!(attributes.behavior_available(), Some(true));
    }

    #[test]
    fn behavior_reports_are_condensed_into_artifacts() {
        let behavior = behavior_info_from_reports(vec![VirusTotalBehaviorObject {
            attributes: serde_json::json!({
                "sandbox_name": "Zenbox",
                "verdict": "malicious",
                "contacted_ips": ["203.0.113.10"],
                "contacted_domains": ["example.invalid"],
                "contacted_urls": ["https://example.invalid/payload"],
                "dropped_files": [{"sha256": "abc123", "path": "C:\\\\Temp\\\\x.dll"}],
                "files_written": ["C:\\\\Temp\\\\x.dll"],
                "processes_created": [{"command_line": "java -jar sample.jar"}],
                "command_executions": ["cmd.exe /c whoami"],
                "dns_lookups": ["example.invalid"]
            }),
        }]);

        assert_eq!(behavior.available, Some(true));
        assert_eq!(behavior.reports.len(), 1);
        assert!(behavior.contacted_ips.contains(&"203.0.113.10".to_owned()));
        assert!(behavior
            .contacted_domains
            .contains(&"example.invalid".to_owned()));
        assert!(behavior
            .command_executions
            .contains(&"cmd.exe /c whoami".to_owned()));
    }
}
