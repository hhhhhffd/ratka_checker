use serde::Deserialize;

use crate::models::scan::Severity;

/// Configurable rule loaded from YAML at process startup.
#[derive(Clone, Debug, Deserialize)]
pub struct Rule {
    pub rule_id: String,
    pub category: String,
    pub severity: Severity,
    pub match_type: MatchType,
    pub pattern: String,
    pub message: String,
}

/// Supported rule match sources produced by the scanner.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchType {
    StringContains,
    Regex,
    BytecodeRef,
    ManifestField,
    ArchiveStructure,
}
