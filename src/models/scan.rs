use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Persistent scan lifecycle state exposed by API responses.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Pending,
    Done,
    Failed,
}

impl ScanStatus {
    /// Converts database text into the typed API model and fails closed on unknown values.
    pub fn from_db(value: &str) -> anyhow::Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "done" => Ok(Self::Done),
            "failed" => Ok(Self::Failed),
            other => Err(anyhow::anyhow!("unknown scan status: {other}")),
        }
    }
}

/// Risk verdict emitted after a scan completes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
    Unknown,
}

impl Verdict {
    /// Converts risk score into the required clean/suspicious/malicious bands.
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=19 => Self::Clean,
            20..=59 => Self::Suspicious,
            _ => Self::Malicious,
        }
    }

    /// Converts nullable database text into the typed API model.
    pub fn from_db(value: &str) -> anyhow::Result<Self> {
        match value {
            "clean" => Ok(Self::Clean),
            "suspicious" => Ok(Self::Suspicious),
            "malicious" => Ok(Self::Malicious),
            "unknown" => Ok(Self::Unknown),
            other => Err(anyhow::anyhow!("unknown verdict: {other}")),
        }
    }

    /// Returns the database representation used by check constraints and API serialization.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
            Self::Unknown => "unknown",
        }
    }
}

/// Finding severity with fixed scoring weights from the specification.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Converts YAML/database text into the typed model and rejects misspelled severities.
    pub fn from_db(value: &str) -> anyhow::Result<Self> {
        match value {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(anyhow::anyhow!("unknown severity: {other}")),
        }
    }

    /// Returns the score contribution required for this severity.
    pub fn score_weight(&self) -> u8 {
        match self {
            Self::Low => 5,
            Self::Medium => 15,
            Self::High => 30,
            Self::Critical => 50,
        }
    }

    /// Returns the database representation used by check constraints and API serialization.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// How confidently the scanner classified a behaviour or archive component.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    #[default]
    Medium,
    High,
}

impl Confidence {
    pub fn from_db(value: &str) -> anyhow::Result<Self> {
        match value {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            other => Err(anyhow::anyhow!("unknown confidence: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Origin of code or data that produced a scan result.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeScope {
    FirstParty,
    BundledDependency,
    NestedMod,
    GeneratedCode,
    Metadata,
    Resource,
    #[default]
    Unknown,
}

impl CodeScope {
    pub fn from_db(value: &str) -> anyhow::Result<Self> {
        match value {
            "first_party" => Ok(Self::FirstParty),
            "bundled_dependency" => Ok(Self::BundledDependency),
            "nested_mod" => Ok(Self::NestedMod),
            "generated_code" => Ok(Self::GeneratedCode),
            "metadata" => Ok(Self::Metadata),
            "resource" => Ok(Self::Resource),
            "unknown" => Ok(Self::Unknown),
            other => Err(anyhow::anyhow!("unknown code scope: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FirstParty => "first_party",
            Self::BundledDependency => "bundled_dependency",
            Self::NestedMod => "nested_mod",
            Self::GeneratedCode => "generated_code",
            Self::Metadata => "metadata",
            Self::Resource => "resource",
            Self::Unknown => "unknown",
        }
    }
}

/// Classification of a result. Capabilities are intentionally not risk-bearing findings.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    #[default]
    Finding,
    Heuristic,
    Native,
    Virustotal,
}

impl FindingKind {
    pub fn from_db(value: &str) -> anyhow::Result<Self> {
        match value {
            "finding" => Ok(Self::Finding),
            "heuristic" => Ok(Self::Heuristic),
            "native" => Ok(Self::Native),
            "virustotal" => Ok(Self::Virustotal),
            other => Err(anyhow::anyhow!("unknown finding kind: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Finding => "finding",
            Self::Heuristic => "heuristic",
            Self::Native => "native",
            Self::Virustotal => "virustotal",
        }
    }
}

/// Exact source location and value origin used to support a result.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Evidence {
    pub archive_id: String,
    pub archive_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_descriptor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytecode_offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_path: Option<String>,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_preview: Option<String>,
    #[serde(default)]
    pub scope: CodeScope,
}

/// A neutral observable behaviour that does not contribute to risk by itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Capability {
    pub rule_id: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

/// A sequence of operations connected by data-flow evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfirmedChain {
    pub chain_id: String,
    pub rule_id: String,
    pub severity: Severity,
    #[serde(default)]
    pub confidence: Confidence,
    pub score_contribution: u8,
    pub operations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

/// Degree to which obfuscation limits static-analysis confidence.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Obfuscation {
    #[serde(default)]
    pub level: ObfuscationLevel,
    pub score: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ObfuscationLevel {
    #[default]
    None,
    Low,
    Medium,
    High,
}

/// A reason why the scan may not be complete.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Limitation {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

/// Structured result emitted by the scanner before persistence or API enrichment.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanReport {
    pub verdict: Verdict,
    pub risk_score: u8,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confirmed_chains: Vec<ConfirmedChain>,
    #[serde(default)]
    pub obfuscation: Obfuscation,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<Limitation>,
}

/// Suspicious signal with its contribution and the evidence supporting it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub category: String,
    #[serde(default)]
    pub kind: FindingKind,
    pub severity: Severity,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub score_contribution: u8,
    #[serde(default)]
    pub scope: CodeScope,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_chain_id: Option<String>,
}

impl Finding {
    /// Creates a legacy rule result while callers are migrated to supply structured evidence.
    pub fn legacy(
        rule_id: impl Into<String>,
        category: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        let score_contribution = severity.score_weight();
        Self {
            rule_id: rule_id.into(),
            category: category.into(),
            kind: FindingKind::Finding,
            severity,
            confidence: Confidence::Medium,
            score_contribution,
            scope: CodeScope::Unknown,
            message: message.into(),
            evidence: Vec::new(),
            related_chain_id: None,
        }
    }
}

/// Summary of the latest VirusTotal report cached for the scanned file hash.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VirusTotalReport {
    #[serde(
        default = "default_virustotal_status",
        skip_serializing_if = "is_completed_virustotal_status"
    )]
    pub status: VirusTotalStatus,
    #[serde(default = "default_virustotal_source", skip_serializing)]
    pub source: VirusTotalSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<VirusTotalStats>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flagged_engines: Vec<VirusTotalEngineResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<VirusTotalBehaviorInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl VirusTotalReport {
    /// Ensures cached legacy VirusTotal API responses have the current behavior shape.
    pub fn ensure_behavior_shape(&mut self) {
        if self.behavior.is_none() {
            self.behavior = Some(VirusTotalBehaviorInfo::empty(None));
        }
    }
}

/// Advisory dynamic-analysis context from VirusTotal sandbox/behaviour data.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VirusTotalBehaviorInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reports: Vec<VirusTotalBehaviorReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacted_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacted_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacted_urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dropped_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files_written: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processes_created: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command_executions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_lookups: Vec<String>,
}

/// One VirusTotal sandbox/behaviour report condensed for API consumers.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VirusTotalBehaviorReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacted_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacted_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacted_urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dropped_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files_written: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processes_created: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command_executions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_lookups: Vec<String>,
}

impl VirusTotalBehaviorInfo {
    pub fn empty(available: Option<bool>) -> Self {
        Self {
            available,
            reports: Vec::new(),
            contacted_ips: Vec::new(),
            contacted_domains: Vec::new(),
            contacted_urls: Vec::new(),
            dropped_files: Vec::new(),
            files_written: Vec::new(),
            processes_created: Vec::new(),
            command_executions: Vec::new(),
            dns_lookups: Vec::new(),
        }
    }
}

/// Coarse VirusTotal lifecycle state exposed without leaking raw API response shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VirusTotalStatus {
    Completed,
    Queued,
    NotFound,
    TooLargeToUpload,
    Error,
}

fn is_completed_virustotal_status(status: &VirusTotalStatus) -> bool {
    *status == VirusTotalStatus::Completed
}

fn default_virustotal_status() -> VirusTotalStatus {
    VirusTotalStatus::Completed
}

fn default_virustotal_source() -> VirusTotalSource {
    VirusTotalSource::Lookup
}

/// Where the VirusTotal value came from inside the service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VirusTotalSource {
    Cache,
    Lookup,
    Upload,
}

/// VirusTotal aggregate engine counters.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VirusTotalStats {
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub timeout: u32,
}

/// One flagged VirusTotal engine result, limited to non-harmless categories.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VirusTotalEngineResult {
    pub engine_name: String,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
}

/// Response shared by POST /v1/scans, GET /v1/scans/{id}, and hash lookups.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanResponse {
    pub scan_id: Uuid,
    pub status: ScanStatus,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    pub risk_score: u8,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub confirmed_chains: Vec<ConfirmedChain>,
    #[serde(default)]
    pub obfuscation: Obfuscation,
    #[serde(default)]
    pub limitations: Vec<Limitation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virustotal: Option<VirusTotalReport>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn virustotal_report(status: VirusTotalStatus) -> VirusTotalReport {
        VirusTotalReport {
            status,
            source: VirusTotalSource::Cache,
            stats: None,
            flagged_engines: Vec::new(),
            behavior: None,
            error: None,
        }
    }

    #[test]
    fn completed_virustotal_response_omits_internal_fields() {
        let value = serde_json::to_value(virustotal_report(VirusTotalStatus::Completed))
            .expect("report serializes");

        assert!(value.get("status").is_none());
        assert!(value.get("source").is_none());
        assert!(value.get("names").is_none());
    }

    #[test]
    fn non_completed_virustotal_response_keeps_status() {
        let value = serde_json::to_value(virustotal_report(VirusTotalStatus::Error))
            .expect("report serializes");

        assert_eq!(
            value.get("status").and_then(serde_json::Value::as_str),
            Some("error")
        );
        assert!(value.get("source").is_none());
        assert!(value.get("names").is_none());
    }

    #[test]
    fn virustotal_report_deserializes_trimmed_completed_cache_shape() {
        let report = serde_json::from_value::<VirusTotalReport>(serde_json::json!({
            "stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 1,
                "timeout": 0
            }
        }))
        .expect("trimmed report deserializes");

        assert_eq!(report.status, VirusTotalStatus::Completed);
        assert_eq!(report.source, VirusTotalSource::Lookup);
    }

    #[test]
    fn scan_response_omits_summary() {
        let response = ScanResponse {
            scan_id: Uuid::nil(),
            status: ScanStatus::Done,
            sha256: "abc".to_owned(),
            verdict: Some(Verdict::Clean),
            risk_score: 0,
            confidence: Confidence::High,
            capabilities: Vec::new(),
            findings: Vec::new(),
            confirmed_chains: Vec::new(),
            obfuscation: Obfuscation::default(),
            limitations: Vec::new(),
            virustotal: None,
        };

        let value = serde_json::to_value(response).expect("response serializes");

        assert!(value.get("summary").is_none());
    }

    #[test]
    fn legacy_finding_uses_safe_structured_defaults() {
        let finding = Finding::legacy("RULE", "archive", Severity::Low, "legacy result");

        assert_eq!(finding.kind, FindingKind::Finding);
        assert_eq!(finding.confidence, Confidence::Medium);
        assert_eq!(finding.scope, CodeScope::Unknown);
        assert_eq!(finding.score_contribution, 5);
        assert!(finding.evidence.is_empty());
    }

    #[test]
    fn legacy_scan_response_deserializes_with_structured_defaults() {
        let response = serde_json::from_value::<ScanResponse>(serde_json::json!({
            "scan_id": Uuid::nil(),
            "status": "done",
            "sha256": "abc",
            "verdict": "clean",
            "risk_score": 0,
            "findings": [{
                "rule_id": "OLD_RULE",
                "category": "archive",
                "severity": "low",
                "message": "old response"
            }]
        }))
        .expect("legacy response deserializes");

        assert_eq!(response.confidence, Confidence::Medium);
        assert!(response.capabilities.is_empty());
        assert_eq!(response.findings[0].scope, CodeScope::Unknown);
        assert_eq!(response.obfuscation, Obfuscation::default());
    }
}
