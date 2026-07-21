#![allow(clippy::large_enum_variant, clippy::unnecessary_lazy_evaluations)]

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    path::Path,
};

use reqwest::{multipart, StatusCode};
use serde::Deserialize;

use crate::{
    config::VirusTotalConfig,
    models::scan::{
        Confidence, Finding, Severity, VirusTotalBehaviorInfo, VirusTotalBehaviorReport,
        VirusTotalEngineResult, VirusTotalFileArtifact, VirusTotalNetworkArtifact,
        VirusTotalProcess, VirusTotalReport, VirusTotalSource, VirusTotalStats, VirusTotalStatus,
    },
};

const API_BASE_URL: &str = "https://www.virustotal.com/api/v3";
const BEHAVIOR_VALUE_LIMIT: usize = 50;
const BEHAVIOR_STRING_LIMIT: usize = 300;
const VT_SANDBOX_JAVA_PROCESSES: &[&str] = &[
    "sample.jar",
    "jartracer.jar",
    "cmdlinestart.log",
    "/tmp/sample.jar",
];
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
        behavior: behavior_info(None),
        error: Some(message),
    }
}

/// Removes known VirusTotal sandbox/runtime artifacts from behavior data before API exposure.
pub fn sanitize_report(report: &mut VirusTotalReport) {
    let Some(behavior) = &mut report.behavior else {
        return;
    };

    for behavior_report in &mut behavior.reports {
        filter_sandbox_noise(behavior_report);
    }
    behavior.reports.retain(|behavior_report| {
        has_attributed_behavior_signal(behavior_report)
            || !behavior_report.environment_noise.is_empty()
    });
    rebuild_behavior_aggregates(behavior);
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
        return vec![Finding::legacy(
            "VT_TRUSTED_MALICIOUS_ENGINE",
            "virustotal",
            Severity::Critical,
            format!(
                "VirusTotal: trusted engine detected malware: {}",
                engine_summary(&trusted_malicious)
            ),
        )];
    }

    if malicious_engines.len() >= 3 {
        return vec![Finding::legacy(
            "VT_MULTIPLE_MALICIOUS_ENGINES",
            "virustotal",
            Severity::High,
            format!(
                "VirusTotal: {} engines detected malware: {}",
                malicious_engines.len(),
                engine_summary(&malicious_engines)
            ),
        )];
    }

    if !malicious_engines.is_empty() {
        return vec![Finding::legacy(
            "VT_SINGLE_MALICIOUS_ENGINE",
            "virustotal",
            Severity::Medium,
            format!(
                "VirusTotal: single engine detected malware: {}",
                engine_summary(&malicious_engines)
            ),
        )];
    }

    let suspicious_count = report
        .flagged_engines
        .iter()
        .filter(|engine| engine.category == "suspicious")
        .count();
    if suspicious_count > 0 {
        return vec![Finding::legacy(
            "VT_SUSPICIOUS_ENGINES",
            "virustotal",
            Severity::Low,
            format!("VirusTotal: {suspicious_count} engines marked file suspicious"),
        )];
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
        behavior: behavior_info(None),
        error: None,
    })
}

fn file_report(file: FileObject, source: VirusTotalSource) -> VirusTotalReport {
    let behavior_available = file.attributes.behavior_available();
    VirusTotalReport {
        status: VirusTotalStatus::Completed,
        source,
        stats: file.attributes.last_analysis_stats,
        flagged_engines: flagged_engines(file.attributes.last_analysis_results),
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
        merge_behavior_report(&mut behavior, &report);
        behavior.reports.push(report);
    }
    behavior.reports.retain(has_attributed_behavior_signal);
    if !behavior.sample_execution.is_empty() {
        behavior.behavior_confidence = Confidence::High;
    }
    behavior
}

fn behavior_report_from_attributes(attributes: serde_json::Value) -> VirusTotalBehaviorReport {
    let processes = process_records(&attributes);
    let sample_execution = processes
        .iter()
        .filter(|process| is_sample_process(process))
        .cloned()
        .collect::<Vec<_>>();
    let attributed_process_ids = attributed_process_ids(&sample_execution, &processes);
    let attributed_child_processes = processes
        .iter()
        .filter(|process| {
            process
                .pid
                .is_some_and(|pid| attributed_process_ids.contains(&pid))
                && !sample_execution.contains(process)
        })
        .cloned()
        .collect::<Vec<_>>();

    let mut environment_noise = Vec::new();
    for process in &processes {
        if !process
            .pid
            .is_some_and(|pid| attributed_process_ids.contains(&pid))
        {
            add_environment_noise(&mut environment_noise, "process", process_summary(process));
        }
    }
    let (attributed_files, file_noise) =
        classify_file_artifacts(&attributes, &attributed_process_ids);
    environment_noise.extend(file_noise);
    let (attributed_network, network_noise) =
        classify_network_artifacts(&attributes, &attributed_process_ids);
    environment_noise.extend(network_noise);

    let mut report = VirusTotalBehaviorReport {
        sandbox_name: string_field(&attributes, &["sandbox_name", "sandbox", "environment_id"]),
        analysis_date: integer_field(&attributes, &["analysis_date", "date"]),
        verdict: string_field(
            &attributes,
            &["verdict", "sandbox_verdict", "classification", "category"],
        ),
        behavior_confidence: if sample_execution.is_empty() {
            Confidence::Low
        } else {
            Confidence::High
        },
        sample_execution,
        attributed_child_processes,
        attributed_files,
        attributed_network,
        environment_noise: unique_limited(environment_noise),
        ..Default::default()
    };
    populate_legacy_behavior_fields(&mut report);
    report
}

fn filter_sandbox_noise(report: &mut VirusTotalBehaviorReport) {
    let legacy_values = [
        ("contacted_ip", &mut report.contacted_ips),
        ("contacted_domain", &mut report.contacted_domains),
        ("contacted_url", &mut report.contacted_urls),
        ("dropped_file", &mut report.dropped_files),
        ("file_write", &mut report.files_written),
        ("process", &mut report.processes_created),
        ("command", &mut report.command_executions),
        ("dns", &mut report.dns_lookups),
    ];
    for (kind, values) in legacy_values {
        for value in values.drain(..) {
            add_environment_noise(&mut report.environment_noise, kind, value);
        }
    }
    report.environment_noise = unique_limited(report.environment_noise.clone());
}

fn has_attributed_behavior_signal(report: &VirusTotalBehaviorReport) -> bool {
    report.verdict.is_some()
        || !report.sample_execution.is_empty()
        || !report.attributed_child_processes.is_empty()
        || !report.attributed_files.is_empty()
        || !report.attributed_network.is_empty()
}

fn rebuild_behavior_aggregates(behavior: &mut VirusTotalBehaviorInfo) {
    behavior.sample_execution.clear();
    behavior.attributed_child_processes.clear();
    behavior.attributed_files.clear();
    behavior.attributed_network.clear();
    behavior.environment_noise.clear();
    behavior.contacted_ips.clear();
    behavior.contacted_domains.clear();
    behavior.contacted_urls.clear();
    behavior.dropped_files.clear();
    behavior.files_written.clear();
    behavior.processes_created.clear();
    behavior.command_executions.clear();
    behavior.dns_lookups.clear();

    for report in &mut behavior.reports {
        filter_sandbox_noise(report);
    }
    for report in behavior.reports.clone() {
        merge_behavior_report(behavior, &report);
    }

    behavior.behavior_confidence = if behavior.sample_execution.is_empty() {
        Confidence::Low
    } else {
        Confidence::High
    };
}

fn merge_behavior_report(behavior: &mut VirusTotalBehaviorInfo, report: &VirusTotalBehaviorReport) {
    extend_unique_processes(&mut behavior.sample_execution, &report.sample_execution);
    extend_unique_processes(
        &mut behavior.attributed_child_processes,
        &report.attributed_child_processes,
    );
    extend_unique_file_artifacts(&mut behavior.attributed_files, &report.attributed_files);
    extend_unique_network_artifacts(&mut behavior.attributed_network, &report.attributed_network);
    extend_unique(&mut behavior.environment_noise, &report.environment_noise);
    extend_unique(&mut behavior.contacted_ips, &report.contacted_ips);
    extend_unique(&mut behavior.contacted_domains, &report.contacted_domains);
    extend_unique(&mut behavior.contacted_urls, &report.contacted_urls);
    extend_unique(&mut behavior.dropped_files, &report.dropped_files);
    extend_unique(&mut behavior.files_written, &report.files_written);
    extend_unique(&mut behavior.processes_created, &report.processes_created);
    extend_unique(&mut behavior.command_executions, &report.command_executions);
    extend_unique(&mut behavior.dns_lookups, &report.dns_lookups);
}

fn populate_legacy_behavior_fields(report: &mut VirusTotalBehaviorReport) {
    report.contacted_ips = unique_limited(
        report
            .attributed_network
            .iter()
            .filter_map(|artifact| artifact.ip.clone())
            .collect(),
    );
    report.contacted_domains = unique_limited(
        report
            .attributed_network
            .iter()
            .filter_map(|artifact| artifact.domain.clone())
            .collect(),
    );
    report.contacted_urls = unique_limited(
        report
            .attributed_network
            .iter()
            .filter_map(|artifact| artifact.url.clone())
            .collect(),
    );
    report.dropped_files = unique_limited(
        report
            .attributed_files
            .iter()
            .filter(|artifact| artifact.operation == "dropped")
            .map(|artifact| artifact.path.clone())
            .collect(),
    );
    report.files_written = unique_limited(
        report
            .attributed_files
            .iter()
            .filter(|artifact| artifact.operation != "dropped")
            .map(|artifact| artifact.path.clone())
            .collect(),
    );
    report.processes_created = unique_limited(
        report
            .attributed_child_processes
            .iter()
            .map(process_summary)
            .collect(),
    );
}

fn process_records(attributes: &serde_json::Value) -> Vec<VirusTotalProcess> {
    let mut records = Vec::new();
    for key in ["process_tree", "processes_created", "processes"] {
        let Some(value) = attributes.get(key) else {
            continue;
        };
        collect_process_records(value, &mut records);
    }
    records.truncate(BEHAVIOR_VALUE_LIMIT);
    records
}

fn collect_process_records(value: &serde_json::Value, records: &mut Vec<VirusTotalProcess>) {
    if records.len() >= BEHAVIOR_VALUE_LIMIT {
        return;
    }
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_process_records(value, records);
            }
        }
        serde_json::Value::Object(object) => {
            let process = VirusTotalProcess {
                pid: object_u64(object, &["pid", "process_id"]),
                parent_pid: object_u64(object, &["ppid", "parent_pid", "parent_process_id"]),
                image: object_string(object, &["image", "path", "name", "process_name"]),
                command_line: object_string(object, &["command_line", "command", "cmd"]),
            };
            if process.pid.is_some() || process.image.is_some() || process.command_line.is_some() {
                records.push(process);
            }
            for key in ["children", "child_processes", "processes"] {
                if let Some(children) = object.get(key) {
                    collect_process_records(children, records);
                }
            }
        }
        serde_json::Value::String(command_line) => records.push(VirusTotalProcess {
            command_line: Some(truncate_behavior_string(command_line)),
            ..Default::default()
        }),
        _ => {}
    }
}

fn attributed_process_ids(
    sample_execution: &[VirusTotalProcess],
    processes: &[VirusTotalProcess],
) -> HashSet<u64> {
    let mut attributed = sample_execution
        .iter()
        .filter_map(|process| process.pid)
        .collect::<HashSet<_>>();
    let mut changed = true;
    while changed {
        changed = false;
        for process in processes {
            if let (Some(pid), Some(parent_pid)) = (process.pid, process.parent_pid) {
                if attributed.contains(&parent_pid) && attributed.insert(pid) {
                    changed = true;
                }
            }
        }
    }
    attributed
}

fn is_sample_process(process: &VirusTotalProcess) -> bool {
    [process.image.as_deref(), process.command_line.as_deref()]
        .into_iter()
        .flatten()
        .any(|value| normalize_behavior_value(value).contains("sample.jar"))
}

fn process_summary(process: &VirusTotalProcess) -> String {
    process
        .command_line
        .clone()
        .or_else(|| process.image.clone())
        .unwrap_or_else(|| format!("pid={}", process.pid.unwrap_or_default()))
}

fn classify_file_artifacts(
    attributes: &serde_json::Value,
    attributed_process_ids: &HashSet<u64>,
) -> (Vec<VirusTotalFileArtifact>, Vec<String>) {
    let mut attributed = Vec::new();
    let mut noise = Vec::new();
    for (key, operation) in [
        ("dropped_files", "dropped"),
        ("files_dropped", "dropped"),
        ("files_written", "written"),
        ("files_created", "written"),
        ("files_deleted", "deleted"),
    ] {
        let Some(value) = attributes.get(key) else {
            continue;
        };
        for artifact in file_artifacts(value, operation) {
            if artifact
                .process_id
                .is_some_and(|pid| attributed_process_ids.contains(&pid))
            {
                attributed.push(artifact);
            } else {
                add_environment_noise(&mut noise, key, artifact.path);
            }
        }
    }
    (limited_artifacts(attributed), unique_limited(noise))
}

fn file_artifacts(value: &serde_json::Value, operation: &str) -> Vec<VirusTotalFileArtifact> {
    match value {
        serde_json::Value::Array(values) => values
            .iter()
            .flat_map(|value| file_artifacts(value, operation))
            .collect(),
        serde_json::Value::Object(object) => object_string(object, &["path", "file_path", "name"])
            .map(|path| {
                vec![VirusTotalFileArtifact {
                    path,
                    operation: operation.to_owned(),
                    process_id: object_u64(object, &["pid", "process_id"]),
                }]
            })
            .unwrap_or_default(),
        serde_json::Value::String(path) => vec![VirusTotalFileArtifact {
            path: truncate_behavior_string(path),
            operation: operation.to_owned(),
            process_id: None,
        }],
        _ => Vec::new(),
    }
}

fn classify_network_artifacts(
    attributes: &serde_json::Value,
    attributed_process_ids: &HashSet<u64>,
) -> (Vec<VirusTotalNetworkArtifact>, Vec<String>) {
    let mut attributed = Vec::new();
    let mut noise = Vec::new();
    for key in [
        "ip_traffic",
        "network",
        "contacted_ips",
        "contacted_domains",
        "domains",
        "dns_lookups",
        "contacted_urls",
        "http_conversations",
        "urls",
    ] {
        let Some(value) = attributes.get(key) else {
            continue;
        };
        for artifact in network_artifacts(value, key) {
            if artifact
                .process_id
                .is_some_and(|pid| attributed_process_ids.contains(&pid))
            {
                attributed.push(artifact);
            } else {
                add_environment_noise(&mut noise, key, network_summary(&artifact));
            }
        }
    }
    (limited_artifacts(attributed), unique_limited(noise))
}

fn network_artifacts(value: &serde_json::Value, source: &str) -> Vec<VirusTotalNetworkArtifact> {
    match value {
        serde_json::Value::Array(values) => values
            .iter()
            .flat_map(|value| network_artifacts(value, source))
            .collect(),
        serde_json::Value::Object(object) => {
            let ip = object_string(object, &["ip", "destination_ip", "host"])
                .and_then(|value| value.parse::<IpAddr>().ok().map(|ip| ip.to_string()));
            let artifact = VirusTotalNetworkArtifact {
                ip,
                domain: object_string(object, &["domain", "hostname"]),
                url: object_string(object, &["url", "request_url"]),
                port: object_u16(object, &["port", "destination_port"]),
                protocol: object_string(object, &["protocol", "transport_protocol"]),
                process_id: object_u64(object, &["pid", "process_id"]),
            };
            if artifact.ip.is_some() || artifact.domain.is_some() || artifact.url.is_some() {
                vec![artifact]
            } else {
                Vec::new()
            }
        }
        serde_json::Value::String(value) => {
            let mut artifact = VirusTotalNetworkArtifact::default();
            if let Ok(ip) = value.parse::<IpAddr>() {
                artifact.ip = Some(ip.to_string());
            } else if matches!(source, "contacted_urls" | "http_conversations" | "urls") {
                artifact.url = Some(truncate_behavior_string(value));
            } else {
                artifact.domain = Some(truncate_behavior_string(value));
            }
            vec![artifact]
        }
        _ => Vec::new(),
    }
}

fn network_summary(artifact: &VirusTotalNetworkArtifact) -> String {
    artifact
        .url
        .clone()
        .or_else(|| artifact.domain.clone())
        .or_else(|| artifact.ip.clone())
        .unwrap_or_else(|| "unparsed network artifact".to_owned())
}

fn add_environment_noise(target: &mut Vec<String>, kind: &str, value: String) {
    if !is_noisy_virustotal_behavior_value(&value) && !is_noisy_domain_or_dns_value(&value) {
        target.push(format!("{kind}: {}", truncate_behavior_string(&value)));
    }
}

fn object_string(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter()
        .filter_map(|key| object.get(*key))
        .find_map(json_string)
        .map(truncate_behavior_string)
}

fn object_u64(object: &serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .filter_map(|key| object.get(*key))
        .find_map(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
}

fn object_u16(object: &serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> Option<u16> {
    object_u64(object, keys).and_then(|port| u16::try_from(port).ok())
}

fn extend_unique_processes(target: &mut Vec<VirusTotalProcess>, values: &[VirusTotalProcess]) {
    for value in values {
        if target.len() >= BEHAVIOR_VALUE_LIMIT || target.contains(value) {
            continue;
        }
        target.push(value.clone());
    }
}

fn extend_unique_file_artifacts(
    target: &mut Vec<VirusTotalFileArtifact>,
    values: &[VirusTotalFileArtifact],
) {
    for value in values {
        if target.len() >= BEHAVIOR_VALUE_LIMIT || target.contains(value) {
            continue;
        }
        target.push(value.clone());
    }
}

fn extend_unique_network_artifacts(
    target: &mut Vec<VirusTotalNetworkArtifact>,
    values: &[VirusTotalNetworkArtifact],
) {
    for value in values {
        if target.len() >= BEHAVIOR_VALUE_LIMIT || target.contains(value) {
            continue;
        }
        target.push(value.clone());
    }
}

fn limited_artifacts<T>(mut artifacts: Vec<T>) -> Vec<T> {
    artifacts.truncate(BEHAVIOR_VALUE_LIMIT);
    artifacts
}

fn is_noisy_virustotal_behavior_value(value: &str) -> bool {
    let normalized = normalize_behavior_value(value);

    is_noisy_windows_java_artifact(&normalized)
        || is_noisy_linux_java_artifact(&normalized)
        || is_noisy_sandbox_java_command(&normalized)
        || is_noisy_rsyslog_artifact(&normalized)
        || is_flattened_sandbox_artifact_marker(&normalized)
}

fn is_noisy_domain_or_dns_value(value: &str) -> bool {
    let normalized = normalize_behavior_value(value);

    is_ip_literal(&normalized) || normalized.ends_with(".dscr.akamai.net")
}

fn is_ip_literal(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

fn is_noisy_windows_java_artifact(value: &str) -> bool {
    value.contains("appdata/local/temp/hsperfdata_")
        || (contains_oracle_jre_usage_path(value) && value.ends_with(".timestamp"))
        || value.ends_with("/cmdlinestart.log")
        || value.contains("/device/condrv/connect")
        || (value.contains("/program files/java/") && value.contains("/bin/java.exe"))
        || value.ends_with("/windows/system32/conhost.exe")
        || (value.contains("/windows/system32/conhost.exe") && value.contains("-forcev1"))
        || value.ends_with("/windows/syswow64/cmd.exe")
        || (value.contains("icacls.exe")
            && contains_oracle_jre_usage_path(value)
            && value.contains("/grant"))
}

fn contains_oracle_jre_usage_path(value: &str) -> bool {
    value.contains("programdata/oracle/java.oracle_jre_usage")
        || value.contains("programdata/oracle/java/.oracle_jre_usage")
}

fn is_noisy_linux_java_artifact(value: &str) -> bool {
    value.starts_with("/proc/") && value.ends_with("/coredump_filter")
        || value.starts_with("/proc/") && value.ends_with("/coredumpfilter")
        || value.starts_with("/tmp/hsperfdata")
        || value == "/usr/bin/java"
        || value == "/bin/gzip"
}

fn is_noisy_sandbox_java_command(value: &str) -> bool {
    let runs_known_sandbox_sample = value.contains("java")
        && VT_SANDBOX_JAVA_PROCESSES
            .iter()
            .any(|artifact| value.contains(artifact));

    runs_known_sandbox_sample
        || (value.contains("cmd.exe")
            && value.contains("java.exe")
            && value.contains("sample.jar")
            && value.contains("cmdlinestart.log"))
}

fn is_noisy_rsyslog_artifact(value: &str) -> bool {
    value == "/usr/lib/rsyslog/rsyslog-rotate"
        || value == "/usr/bin/systemctl systemctl kill -s hup rsyslog.service"
        || value == "systemctl kill -s hup rsyslog.service"
        || value.contains("rsyslog-rotate logrotate_script /var/log/")
}

fn is_flattened_sandbox_artifact_marker(value: &str) -> bool {
    value == "text"
        || value.chars().all(|character| character.is_ascii_digit())
        || (value.len() >= 16
            && value.ends_with(".timestamp")
            && value
                .trim_end_matches(".timestamp")
                .chars()
                .all(|character| character.is_ascii_hexdigit()))
        || (value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit()))
}

fn normalize_behavior_value(value: &str) -> String {
    value
        .trim()
        .replace('\\', "/")
        .replace("//", "/")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
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
                "process_tree": [
                    {"pid": 10, "command_line": "java -jar sample.jar"},
                    {"pid": 11, "ppid": 10, "command_line": "powershell.exe -enc AAAA"}
                ],
                "dropped_files": [{"path": "C:\\\\Temp\\\\x.dll", "process_id": 11}],
                "ip_traffic": [{
                    "destination_ip": "203.0.113.10",
                    "domain": "example.invalid",
                    "url": "https://example.invalid/payload",
                    "destination_port": 443,
                    "protocol": "tcp",
                    "process_id": 11
                }]
            }),
        }]);

        assert_eq!(behavior.available, Some(true));
        assert_eq!(behavior.behavior_confidence, Confidence::High);
        assert_eq!(behavior.reports.len(), 1);
        assert_eq!(behavior.sample_execution.len(), 1);
        assert_eq!(behavior.attributed_child_processes.len(), 1);
        assert_eq!(behavior.attributed_files.len(), 1);
        assert_eq!(behavior.attributed_network[0].port, Some(443));
        assert_eq!(
            behavior.attributed_network[0].protocol.as_deref(),
            Some("tcp")
        );
        assert!(behavior.contacted_ips.contains(&"203.0.113.10".to_owned()));
        assert!(behavior
            .contacted_domains
            .contains(&"example.invalid".to_owned()));
        assert!(behavior
            .processes_created
            .contains(&"powershell.exe -enc AAAA".to_owned()));
    }

    #[test]
    fn behavior_reports_filter_known_virustotal_sandbox_noise() {
        let behavior = behavior_info_from_reports(vec![VirusTotalBehaviorObject {
            attributes: serde_json::json!({
                "files_written": [
                    "C:\\Users\\user\\AppData\\Local\\Temp\\hsperfdata_user\\1234",
                    "C:\\ProgramData\\Oracle\\Java.oracle_jre_usage123ABC.timestamp",
                    "C:\\cmdlinestart.log",
                    "C:\\Temp\\payload.dll"
                ],
                "processes_created": [
                    "C:\\Program Files\\Java\\jre1.8.0_441\\bin\\java.exe",
                    "C:\\Windows\\System32\\conhost.exe",
                    "/usr/bin/java",
                    "/bin/gzip",
                    "powershell.exe -enc AAAA"
                ],
                "command_executions": [
                    "java.exe -jar C:\\Temp\\sample.jar",
                    "java.exe -javaagent:C:\\Temp\\jartracer.jar -jar C:\\Temp\\sample.jar",
                    "cmd.exe /c java.exe -javaagent:jartracer.jar -jar sample.jar > cmdlinestart.log",
                    "icacls.exe C:\\ProgramData\\Oracle\\Java.oracle_jre_usage /grant \"everyone\":(OI)(CI)M",
                    "systemctl kill -s HUP rsyslog.service",
                    "java.exe -jar C:\\Users\\user\\Downloads\\unknown.jar"
                ],
                "dropped_files": [
                    "/proc/1234/coredumpfilter",
                    "/tmp/hsperfdata_user/1234",
                    "/usr/lib/rsyslog/rsyslog-rotate",
                    "/tmp/payload.bin"
                ]
            }),
        }]);

        assert_eq!(behavior.behavior_confidence, Confidence::Low);
        assert!(behavior.sample_execution.is_empty());
        assert!(behavior.attributed_child_processes.is_empty());
        assert!(behavior.attributed_files.is_empty());
        assert!(behavior.processes_created.is_empty());
        assert!(behavior.files_written.is_empty());
        assert!(behavior
            .environment_noise
            .iter()
            .any(|value| value.contains("payload.dll")));
    }

    #[test]
    fn sanitize_report_filters_cached_behavior_aggregates() {
        let mut report = VirusTotalReport {
            status: VirusTotalStatus::Completed,
            source: VirusTotalSource::Cache,
            stats: None,
            flagged_engines: Vec::new(),
            behavior: Some(VirusTotalBehaviorInfo {
                available: Some(true),
                behavior_confidence: Confidence::Low,
                sample_execution: Vec::new(),
                attributed_child_processes: Vec::new(),
                attributed_files: Vec::new(),
                attributed_network: Vec::new(),
                environment_noise: Vec::new(),
                reports: vec![
                    VirusTotalBehaviorReport {
                        sandbox_name: Some("CAPE Sandbox".to_owned()),
                        analysis_date: Some(1),
                        dropped_files: vec![
                            "1824".to_owned(),
                            "TEXT".to_owned(),
                            "f17b4034f5593ee4f170eccc12d34a6de25dd00a00bf19c1015c00a40aff1130"
                                .to_owned(),
                        ],
                        files_written: vec![
                            "C:\\ProgramData\\Oracle\\Java\\.oracle_jre_usage\\3903daac9bc4a3b7.timestamp"
                                .to_owned(),
                        ],
                        processes_created: vec![
                            "\"C:\\Program Files\\Java\\jre-1.8\\bin\\java.exe\" -jar \"C:\\Users\\<USER>\\Desktop\\sample.jar\""
                                .to_owned(),
                        ],
                        command_executions: vec![
                            "C:\\Windows\\system32\\icacls.exe C:\\ProgramData\\Oracle\\Java\\.oracle_jre_usage /grant \"everyone\":(OI)(CI)M"
                                .to_owned(),
                        ],
                        ..Default::default()
                    },
                    VirusTotalBehaviorReport {
                        sandbox_name: Some("Zenbox".to_owned()),
                        analysis_date: Some(2),
                        contacted_domains: vec![
                            "a1672.dscr.akamai.net".to_owned(),
                            "23.195.81.9".to_owned(),
                        ],
                        dns_lookups: vec![
                            "a1672.dscr.akamai.net".to_owned(),
                            "23.195.81.25".to_owned(),
                        ],
                        files_written: vec![
                            "/proc/4965/coredump_filter".to_owned(),
                            "/tmp/hsperfdata_root/4965".to_owned(),
                            "C:\\Users\\user\\AppData\\Local\\Temp\\hsperfdata_user".to_owned(),
                            "\\Device\\ConDrv\\\\Connect".to_owned(),
                        ],
                        processes_created: vec![
                            "/bin/sh sh -c /usr/lib/rsyslog/rsyslog-rotate logrotate_script /var/log/syslog"
                                .to_owned(),
                            "C:\\Windows\\System32\\conhost.exe C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1"
                                .to_owned(),
                        ],
                        ..Default::default()
                    },
                ],
                contacted_domains: vec![
                    "a1672.dscr.akamai.net".to_owned(),
                    "23.195.81.9".to_owned(),
                ],
                dropped_files: vec!["3903daac9bc4a3b7.timestamp".to_owned(), "1824".to_owned()],
                files_written: vec!["/proc/4965/coredump_filter".to_owned()],
                processes_created: vec!["/usr/bin/java -jar /tmp/sample.jar".to_owned()],
                command_executions: vec!["/bin/gzip".to_owned()],
                dns_lookups: vec![
                    "a1672.dscr.akamai.net".to_owned(),
                    "23.195.81.25".to_owned(),
                ],
                contacted_ips: Vec::new(),
                contacted_urls: Vec::new(),
            }),
            error: None,
        };

        sanitize_report(&mut report);

        let behavior = report.behavior.expect("behavior is present");
        assert!(behavior.reports.is_empty());
        assert!(behavior.contacted_domains.is_empty());
        assert!(behavior.dns_lookups.is_empty());
        assert!(behavior.dropped_files.is_empty());
        assert!(behavior.files_written.is_empty());
        assert!(behavior.processes_created.is_empty());
        assert!(behavior.command_executions.is_empty());
    }

    #[test]
    fn behavior_noise_filter_keeps_network_artifacts() {
        let behavior = behavior_info_from_reports(vec![VirusTotalBehaviorObject {
            attributes: serde_json::json!({
                "contacted_domains": ["pastebin.com", "198.51.100.10"],
                "contacted_urls": [
                    "https://raw.githubusercontent.com/example/payload.jar",
                    "https://discord.com/api/webhooks/1/token"
                ],
                "dns_lookups": ["pastebin.com", "198.51.100.10"]
            }),
        }]);

        assert_eq!(behavior.behavior_confidence, Confidence::Low);
        assert!(behavior.attributed_network.is_empty());
        assert!(behavior.contacted_domains.is_empty());
        assert!(behavior.contacted_urls.is_empty());
        assert!(behavior
            .environment_noise
            .iter()
            .any(|value| value.contains("pastebin.com")));
    }
}
