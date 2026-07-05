use std::{
    collections::HashSet,
    fs::File,
    io::{Cursor, Read},
    path::Path,
};

use zip::ZipArchive;

use crate::{
    models::scan::{Finding, Severity, Verdict},
    rules::engine::RulesEngine,
    scanner::{class_file, metadata, strings},
};

const NESTED_JAR_SIGNAL: &str = "nested_jar";
const NATIVE_BINARY_SIGNAL: &str = "native_binary";
const LARGE_ASSET_SIGNAL: &str = "large_asset";
const INVALID_CLASS_CONSTANT_POOL_SIGNAL: &str = "invalid_class_constant_pool";
const BYTECODE_VERSION_MISMATCH_SIGNAL: &str = "bytecode_version_mismatch";
const LARGE_ASSET_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024;
const BYTECODE_VERSION_SPREAD_THRESHOLD: u16 = 4;

/// Named zip-bomb limits loaded from environment through AppConfig.
#[derive(Clone, Copy, Debug)]
pub struct ScanLimits {
    pub max_total_uncompressed_bytes: u64,
    pub max_files_in_archive: usize,
    pub max_nesting_depth: usize,
    pub max_single_file_bytes: u64,
}

/// Data extracted from archive/class parsing and consumed by configurable rules.
#[derive(Clone, Debug, Default)]
pub struct ScanData {
    pub strings: Vec<String>,
    pub bytecode_refs: Vec<String>,
    pub manifest_fields: Vec<String>,
    pub archive_signals: Vec<String>,
    pub class_major_versions: Vec<u16>,
}

/// Complete scanner result ready to persist after risk scoring.
#[derive(Clone, Debug)]
pub struct ScanOutcome {
    pub verdict: Verdict,
    pub risk_score: u8,
    pub summary: String,
    pub findings: Vec<Finding>,
}

/// Scans a stored jar from disk; intended to run inside `spawn_blocking`.
pub fn scan_file(path: &Path, limits: ScanLimits, rules_engine: &RulesEngine) -> ScanOutcome {
    match read_file(path).and_then(|bytes| scan_bytes(&bytes, limits, rules_engine)) {
        Ok(outcome) => outcome,
        Err(error) => unknown_outcome(
            "SCAN_TECHNICAL_FAILURE",
            "static_scan",
            format!("Скан не выполнен технически: {error}"),
        ),
    }
}

/// Parses and evaluates in-memory jar bytes, stopping immediately on safety-limit violations.
fn scan_bytes(
    bytes: &[u8],
    limits: ScanLimits,
    rules_engine: &RulesEngine,
) -> anyhow::Result<ScanOutcome> {
    let mut context = ArchiveContext {
        limits,
        total_uncompressed_bytes: 0,
        file_count: 0,
        data: ScanData::default(),
    };

    if let Err(error) = parse_zip_bytes(bytes, 0, &mut context) {
        return Ok(unknown_outcome(
            error.rule_id(),
            "archive_structure",
            error.to_string(),
        ));
    }

    context.add_derived_signals();
    let findings = rules_engine.evaluate(&context.data);
    let risk_score = risk_score(&findings);
    let verdict = Verdict::from_score(risk_score);
    let summary = summarize(&findings, verdict.clone());

    Ok(ScanOutcome {
        verdict,
        risk_score,
        summary,
        findings,
    })
}

/// Reads the jar once before zip parsing to keep the blocking scanner self-contained.
fn read_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Parses a zip archive recursively while enforcing global limits before reading file contents.
fn parse_zip_bytes(
    bytes: &[u8],
    depth: usize,
    context: &mut ArchiveContext,
) -> Result<(), ScanAbort> {
    if depth > context.limits.max_nesting_depth {
        return Err(ScanAbort::NestingDepth {
            limit: context.limits.max_nesting_depth,
        });
    }

    let cursor = Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor).map_err(|error| ScanAbort::InvalidZip {
        message: error.to_string(),
    })?;

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| ScanAbort::InvalidZip {
                message: error.to_string(),
            })?;
        if entry.is_dir() {
            continue;
        }

        let name = entry.name().replace('\\', "/");
        let uncompressed_size = entry.size();
        context.observe_file(&name, uncompressed_size)?;

        let mut entry_bytes = Vec::new();
        entry
            .read_to_end(&mut entry_bytes)
            .map_err(|error| ScanAbort::InvalidZip {
                message: error.to_string(),
            })?;
        context.extract_entry(&name, &entry_bytes, depth)?;
    }

    Ok(())
}

/// Mutable scanner state shared across nested archives so limits are global, not per-jar.
struct ArchiveContext {
    limits: ScanLimits,
    total_uncompressed_bytes: u64,
    file_count: usize,
    data: ScanData,
}

impl ArchiveContext {
    /// Records file metadata and enforces zip-bomb limits before any content processing.
    fn observe_file(&mut self, name: &str, uncompressed_size: u64) -> Result<(), ScanAbort> {
        self.file_count += 1;
        if self.file_count > self.limits.max_files_in_archive {
            return Err(ScanAbort::FileCount {
                limit: self.limits.max_files_in_archive,
            });
        }

        if uncompressed_size > self.limits.max_single_file_bytes {
            return Err(ScanAbort::SingleFileSize {
                path: name.to_owned(),
                limit: self.limits.max_single_file_bytes,
                actual: uncompressed_size,
            });
        }

        self.total_uncompressed_bytes = self
            .total_uncompressed_bytes
            .checked_add(uncompressed_size)
            .ok_or(ScanAbort::TotalSize {
                limit: self.limits.max_total_uncompressed_bytes,
            })?;
        if self.total_uncompressed_bytes > self.limits.max_total_uncompressed_bytes {
            return Err(ScanAbort::TotalSize {
                limit: self.limits.max_total_uncompressed_bytes,
            });
        }

        self.observe_archive_structure(name, uncompressed_size);
        Ok(())
    }

    /// Adds archive-structure signals based on path and size metadata.
    fn observe_archive_structure(&mut self, name: &str, uncompressed_size: u64) {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".jar") {
            self.data.archive_signals.push(NESTED_JAR_SIGNAL.to_owned());
        }
        if [".exe", ".dll", ".so", ".bat", ".cmd", ".ps1"]
            .iter()
            .any(|extension| lower.ends_with(extension))
        {
            self.data
                .archive_signals
                .push(NATIVE_BINARY_SIGNAL.to_owned());
        }
        if lower.starts_with("assets/") && uncompressed_size >= LARGE_ASSET_THRESHOLD_BYTES {
            self.data
                .archive_signals
                .push(LARGE_ASSET_SIGNAL.to_owned());
        }
        self.data.strings.push(name.to_owned());
    }

    /// Extracts content signals from metadata, class files, generic resources, and nested jars.
    fn extract_entry(&mut self, name: &str, bytes: &[u8], depth: usize) -> Result<(), ScanAbort> {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".jar") {
            return parse_zip_bytes(bytes, depth + 1, self);
        }

        if metadata::is_metadata_file(name) {
            let (fields, strings) = metadata::extract_metadata(name, bytes);
            self.data.manifest_fields.extend(fields);
            self.data.strings.extend(strings);
        }

        if lower.ends_with(".class") {
            match class_file::parse_class_file(bytes) {
                Ok(class_data) => {
                    self.data.strings.extend(class_data.strings);
                    self.data.bytecode_refs.extend(class_data.bytecode_refs);
                    self.data
                        .class_major_versions
                        .push(class_data.major_version);
                }
                Err(error) => {
                    tracing::warn!(path = %name, %error, "class file constant pool parse failed");
                    self.data
                        .archive_signals
                        .push(INVALID_CLASS_CONSTANT_POOL_SIGNAL.to_owned());
                }
            }
        } else {
            self.data
                .strings
                .extend(strings::extract_printable_strings(bytes));
        }

        Ok(())
    }

    /// Adds aggregate signals that require seeing multiple files before deciding.
    fn add_derived_signals(&mut self) {
        let unique_versions = self
            .data
            .class_major_versions
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        if unique_versions.len() > 1 {
            let min_version = unique_versions.iter().min().copied().unwrap_or_default();
            let max_version = unique_versions.iter().max().copied().unwrap_or_default();
            if max_version.saturating_sub(min_version) > BYTECODE_VERSION_SPREAD_THRESHOLD {
                self.data
                    .archive_signals
                    .push(BYTECODE_VERSION_MISMATCH_SIGNAL.to_owned());
            }
        }
    }
}

/// Scanner aborts that should produce `verdict: unknown` instead of a malicious score.
#[derive(Debug, thiserror::Error)]
enum ScanAbort {
    #[error("Файл не является валидным zip/jar архивом: {message}")]
    InvalidZip { message: String },
    #[error("Превышен лимит количества файлов в архиве: максимум {limit}")]
    FileCount { limit: usize },
    #[error("Превышен лимит общего распакованного размера: максимум {limit} байт")]
    TotalSize { limit: u64 },
    #[error("Превышен лимит размера файла {path}: {actual} байт при лимите {limit} байт")]
    SingleFileSize {
        path: String,
        limit: u64,
        actual: u64,
    },
    #[error("Превышен лимит вложенности jar: максимум {limit}")]
    NestingDepth { limit: usize },
}

impl ScanAbort {
    /// Returns a stable technical finding id for the API response.
    fn rule_id(&self) -> &'static str {
        match self {
            Self::InvalidZip { .. } => "INVALID_ZIP",
            Self::FileCount { .. } => "ZIP_FILE_COUNT_LIMIT",
            Self::TotalSize { .. } => "ZIP_TOTAL_SIZE_LIMIT",
            Self::SingleFileSize { .. } => "ZIP_SINGLE_FILE_LIMIT",
            Self::NestingDepth { .. } => "ZIP_NESTING_DEPTH_LIMIT",
        }
    }
}

/// Scores findings with the fixed severity weights and caps the total at 100.
fn risk_score(findings: &[Finding]) -> u8 {
    findings
        .iter()
        .map(|finding| u16::from(finding.severity.score_weight()))
        .sum::<u16>()
        .min(100) as u8
}

/// Builds a concise user-facing Russian summary without ever claiming complete safety.
fn summarize(findings: &[Finding], verdict: Verdict) -> String {
    if findings.is_empty() && verdict == Verdict::Clean {
        return "Явных угроз не найдено, но это не гарантия полной безопасности.".to_owned();
    }

    let mut categories = findings
        .iter()
        .map(|finding| finding.category.as_str())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    categories.sort_unstable();

    format!(
        "Найдены сработавшие правила в категориях: {}.",
        categories.join(", ")
    )
}

/// Creates a technical `unknown` outcome with one explanatory finding.
fn unknown_outcome(rule_id: &str, category: &str, message: String) -> ScanOutcome {
    ScanOutcome {
        verdict: Verdict::Unknown,
        risk_score: 0,
        summary: message.clone(),
        findings: vec![Finding {
            rule_id: rule_id.to_owned(),
            category: category.to_owned(),
            severity: Severity::High,
            message,
        }],
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        models::scan::{Finding, Severity, Verdict},
        scanner::archive::{risk_score, summarize},
    };

    /// Verifies the fixed severity weights are capped at 100.
    #[test]
    fn risk_score_caps_at_100() {
        let findings = vec![
            Finding {
                rule_id: "A".to_owned(),
                category: "x".to_owned(),
                severity: Severity::Critical,
                message: "a".to_owned(),
            },
            Finding {
                rule_id: "B".to_owned(),
                category: "x".to_owned(),
                severity: Severity::Critical,
                message: "b".to_owned(),
            },
            Finding {
                rule_id: "C".to_owned(),
                category: "x".to_owned(),
                severity: Severity::High,
                message: "c".to_owned(),
            },
        ];
        assert_eq!(risk_score(&findings), 100);
    }

    /// Verifies clean summaries avoid saying that a jar is guaranteed safe.
    #[test]
    fn clean_summary_is_not_absolute() {
        let summary = summarize(&[], Verdict::Clean);
        assert!(summary.contains("не гарантия"));
    }
}
