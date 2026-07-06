use std::{collections::HashSet, fs, path::Path};

use regex::Regex;

use crate::{
    models::scan::Finding,
    rules::model::{MatchType, Rule},
    scanner::archive::ScanData,
};

/// Rule engine with precompiled regexes so scans do not repeatedly parse rule patterns.
#[derive(Debug)]
pub struct RulesEngine {
    rules: Vec<CompiledRule>,
}

#[derive(Debug)]
struct CompiledRule {
    rule: Rule,
    regex: Option<Regex>,
}

impl RulesEngine {
    /// Loads and validates YAML rules once at startup to fail fast on bad config.
    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let yaml = fs::read_to_string(path)?;
        let rules: Vec<Rule> = serde_yaml::from_str(&yaml)?;
        let compiled = rules
            .into_iter()
            .map(|rule| {
                let regex = if matches!(rule.match_type, MatchType::Regex) {
                    Some(Regex::new(&format!("(?i){}", rule.pattern))?)
                } else {
                    None
                };
                Ok(CompiledRule { rule, regex })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(Self { rules: compiled })
    }

    /// Applies every configured rule to extracted scan data and emits each rule at most once.
    pub fn evaluate(&self, data: &ScanData) -> Vec<Finding> {
        let mut emitted_rule_ids = HashSet::new();
        let mut findings = Vec::new();

        for compiled in &self.rules {
            if !emitted_rule_ids.contains(&compiled.rule.rule_id)
                && self.rule_matches(compiled, data)
            {
                emitted_rule_ids.insert(compiled.rule.rule_id.clone());
                findings.push(Finding {
                    rule_id: compiled.rule.rule_id.clone(),
                    category: compiled.rule.category.clone(),
                    severity: compiled.rule.severity.clone(),
                    message: compiled.rule.message.clone(),
                });
            }
        }

        findings
    }

    /// Dispatches a rule to the data source selected by `match_type`.
    fn rule_matches(&self, compiled: &CompiledRule, data: &ScanData) -> bool {
        match compiled.rule.match_type {
            MatchType::StringContains => {
                contains_case_insensitive(&data.strings, &compiled.rule.pattern)
            }
            MatchType::Regex => compiled.regex.as_ref().is_some_and(|regex| {
                data.first_party_strings
                    .iter()
                    .any(|candidate| regex.is_match(candidate))
                    || data
                        .metadata_strings
                        .iter()
                        .any(|candidate| regex.is_match(candidate))
                    || data
                        .first_party_bytecode_refs
                        .iter()
                        .any(|candidate| regex.is_match(candidate))
                    || data
                        .manifest_fields
                        .iter()
                        .any(|candidate| regex.is_match(candidate))
            }),
            MatchType::BytecodeRef => {
                contains_case_insensitive(&data.first_party_bytecode_refs, &compiled.rule.pattern)
            }
            MatchType::ManifestField => {
                contains_case_insensitive(&data.manifest_fields, &compiled.rule.pattern)
            }
            MatchType::ArchiveStructure => data
                .archive_signals
                .iter()
                .any(|signal| signal.eq_ignore_ascii_case(&compiled.rule.pattern)),
        }
    }
}

/// Performs case-insensitive substring matching for string-like rule sources.
fn contains_case_insensitive(candidates: &[String], pattern: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    candidates
        .iter()
        .any(|candidate| candidate.to_ascii_lowercase().contains(&pattern))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{
        models::scan::Severity,
        rules::{
            engine::RulesEngine,
            model::{MatchType, Rule},
        },
        scanner::archive::ScanData,
    };

    /// Verifies that duplicate matching data does not duplicate a finding for one rule.
    #[test]
    fn evaluate_emits_each_rule_once() {
        let engine = RulesEngine {
            rules: vec![super::CompiledRule {
                rule: Rule {
                    rule_id: "TEST".to_owned(),
                    category: "test".to_owned(),
                    severity: Severity::High,
                    match_type: MatchType::StringContains,
                    pattern: "secret".to_owned(),
                    message: "found".to_owned(),
                },
                regex: None,
            }],
        };
        let data = ScanData {
            strings: vec!["secret one".to_owned(), "secret two".to_owned()],
            metadata_strings: Vec::new(),
            first_party_strings: Vec::new(),
            bytecode_refs: Vec::new(),
            first_party_bytecode_refs: Vec::new(),
            manifest_fields: Vec::new(),
            archive_signals: Vec::new(),
            class_major_versions: Vec::new(),
            class_names: Vec::new(),
            class_files: Vec::new(),
            mod_ids: Vec::new(),
            mod_aliases: Vec::new(),
            entrypoint_classes: Vec::new(),
            entry_timestamps: Vec::new(),
        };
        assert_eq!(engine.evaluate(&data).len(), 1);
    }

    /// Verifies bytecode API rules use scoped first-party references, not vendored deps.
    #[test]
    fn bytecode_rules_ignore_unscoped_dependency_refs() {
        let engine = RulesEngine {
            rules: vec![super::CompiledRule {
                rule: Rule {
                    rule_id: "PROCESS_BUILDER".to_owned(),
                    category: "dangerous_api".to_owned(),
                    severity: Severity::Low,
                    match_type: MatchType::BytecodeRef,
                    pattern: "java/lang/ProcessBuilder".to_owned(),
                    message: "found".to_owned(),
                },
                regex: None,
            }],
        };
        let data = ScanData {
            bytecode_refs: vec!["java/lang/ProcessBuilder".to_owned()],
            first_party_bytecode_refs: Vec::new(),
            ..Default::default()
        };

        assert!(engine.evaluate(&data).is_empty());
    }

    /// Verifies regex rules still inspect mod metadata after dependency scoping.
    #[test]
    fn regex_rules_still_match_metadata_strings() {
        let engine = RulesEngine {
            rules: vec![super::CompiledRule {
                rule: Rule {
                    rule_id: "TYPO".to_owned(),
                    category: "supply_chain".to_owned(),
                    severity: Severity::High,
                    match_type: MatchType::Regex,
                    pattern: "OptiFinee".to_owned(),
                    message: "found".to_owned(),
                },
                regex: Some(regex::Regex::new("(?i)OptiFinee").expect("valid regex")),
            }],
        };
        let data = ScanData {
            metadata_strings: vec![r#"{"id":"OptiFinee"}"#.to_owned()],
            ..Default::default()
        };

        assert_eq!(engine.evaluate(&data).len(), 1);
    }

    /// Verifies that the default production rules file remains loadable.
    #[test]
    fn default_rules_file_loads() {
        let engine = RulesEngine::load_from_file(Path::new("config/rules.yaml"));

        assert!(engine.is_ok());
    }
}
