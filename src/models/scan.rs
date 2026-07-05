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

/// Public finding object returned in scan responses.
#[derive(Clone, Debug, Serialize)]
pub struct FindingResponse {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
}

/// Internal finding object carries category for DB storage and summary generation.
#[derive(Clone, Debug)]
pub struct Finding {
    pub rule_id: String,
    pub category: String,
    pub severity: Severity,
    pub message: String,
}

impl Finding {
    /// Drops internal category data for the public API response shape.
    pub fn to_response(&self) -> FindingResponse {
        FindingResponse {
            rule_id: self.rule_id.clone(),
            severity: self.severity.clone(),
            message: self.message.clone(),
        }
    }
}

/// Response shared by POST /v1/scans, GET /v1/scans/{id}, and hash lookups.
#[derive(Clone, Debug, Serialize)]
pub struct ScanResponse {
    pub scan_id: Uuid,
    pub status: ScanStatus,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    pub risk_score: u8,
    pub summary: String,
    pub findings: Vec<FindingResponse>,
}
