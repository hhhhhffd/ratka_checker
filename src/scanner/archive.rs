use std::{
    collections::{HashMap, HashSet},
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
const NESTED_ZIP_SIGNAL: &str = "nested_zip";
const NATIVE_BINARY_SIGNAL: &str = "native_binary";
const SCRIPT_FILE_SIGNAL: &str = "script_file";
const LARGE_ASSET_SIGNAL: &str = "large_asset";
const INVALID_CLASS_CONSTANT_POOL_SIGNAL: &str = "invalid_class_constant_pool";
const BYTECODE_VERSION_MISMATCH_SIGNAL: &str = "bytecode_version_mismatch";
const TIMESTAMP_OUTLIER_SIGNAL: &str = "timestamp_outlier";
const MODID_PACKAGE_MISMATCH_SIGNAL: &str = "modid_package_mismatch";
const SHORT_NAMES_WITHOUT_MIXIN_SIGNAL: &str = "short_class_names_without_mixin";
const DOWNLOAD_WRITE_EXEC_SIGNAL: &str = "download_write_exec";
const CREDENTIAL_HTTP_EXFIL_SIGNAL: &str = "credential_path_with_http";
const BASE64_DYNAMIC_CLASS_SIGNAL: &str = "base64_dynamic_class_loading";
const ROBOT_HTTP_SIGNAL: &str = "robot_with_http";
const CLIPBOARD_CRYPTO_SIGNAL: &str = "clipboard_crypto_address";
const MIXIN_METADATA_SIGNAL: &str = "mixin_metadata_present";
const HTTP_DYNAMIC_CLASSLOAD_SIGNAL: &str = "http_dynamic_class_loading";
const REMOTE_CLASS_LOADING_SIGNAL: &str = "remote_class_loading";
const NATIVE_LIB_REMOTE_LOAD_SIGNAL: &str = "native_lib_remote_load";
const SCRIPT_DOWNLOAD_EXEC_SIGNAL: &str = "script_download_exec";
const EXTERNAL_URLCLASSLOADER_SIGNAL: &str = "urlclassloader_external_target";
const LARGE_ASSET_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024;
const BYTECODE_VERSION_SPREAD_THRESHOLD: u16 = 4;
const TIMESTAMP_OUTLIER_MIN_FILES: usize = 20;
const TIMESTAMP_DOMINANT_PERCENT: usize = 90;
const SHORT_CLASS_NAME_MIN_CLASSES: usize = 8;
const SHORT_CLASS_NAME_PERCENT: usize = 70;
const NETWORK_APIS: &[&str] = &[
    "java/net/Socket",
    "java/net/URL",
    "java/net/HttpURLConnection",
    "javax/net/ssl/HttpsURLConnection",
    "java/net/http/HttpClient",
    "java/net/http/HttpRequest",
];
const DYNAMIC_CLASS_APIS: &[&str] =
    &["java/lang/ClassLoader.defineClass", "java/net/URLClassLoader"];
const NATIVE_LOAD_APIS: &[&str] = &[
    "java/lang/Runtime.load",
    "java/lang/Runtime.loadLibrary",
    "java/lang/System.load",
    "java/lang/System.loadLibrary",
];
const EXEC_APIS: &[&str] = &["java/lang/Runtime.exec", "java/lang/ProcessBuilder"];

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
    pub class_names: Vec<String>,
    pub class_files: Vec<ClassScanData>,
    pub mod_ids: Vec<String>,
    pub mod_aliases: Vec<String>,
    pub entry_timestamps: Vec<(String, String)>,
}

/// Per-class data used for lower-noise correlation signals.
#[derive(Clone, Debug, Default)]
pub struct ClassScanData {
    pub strings: Vec<String>,
    pub bytecode_refs: Vec<String>,
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
    let (verdict, risk_score, summary) = finalize_findings(&findings);

    Ok(ScanOutcome {
        verdict,
        risk_score,
        summary,
        findings,
    })
}

/// Recomputes verdict fields after callers add non-static findings such as VirusTotal signals.
pub fn finalize_findings(findings: &[Finding]) -> (Verdict, u8, String) {
    let risk_score = risk_score(findings);
    let verdict = Verdict::from_score(risk_score);
    let summary = summarize(findings, verdict.clone());
    (verdict, risk_score, summary)
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
        if let Some(last_modified) = entry.last_modified() {
            context
                .data
                .entry_timestamps
                .push((name.clone(), format!("{last_modified:?}")));
        }
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
            if !is_fabric_declared_nested_jar(&lower) {
                self.data.archive_signals.push(NESTED_JAR_SIGNAL.to_owned());
            }
        }
        if lower.ends_with(".zip") {
            self.data.archive_signals.push(NESTED_ZIP_SIGNAL.to_owned());
        }
        if [".bat", ".cmd", ".ps1", ".vbs", ".scr"]
            .iter()
            .any(|extension| lower.ends_with(extension))
        {
            self.data
                .archive_signals
                .push(SCRIPT_FILE_SIGNAL.to_owned());
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
        self.observe_magic_bytes(&lower, bytes);

        if lower.ends_with(".jar") || lower.ends_with(".zip") {
            return parse_zip_bytes(bytes, depth + 1, self);
        }

        if metadata::is_metadata_file(name) {
            let metadata = metadata::extract_metadata(name, bytes);
            self.data.manifest_fields.extend(metadata.manifest_fields);
            self.data.strings.extend(metadata.strings);
            self.data.mod_ids.extend(metadata.mod_ids);
            self.data.mod_aliases.extend(metadata.mod_aliases);
            self.data.archive_signals.extend(metadata.archive_signals);
        }

        if lower.ends_with(".class") {
            match class_file::parse_class_file(bytes) {
                Ok(class_data) => {
                    self.data.class_files.push(ClassScanData {
                        strings: class_data.strings.clone(),
                        bytecode_refs: class_data.bytecode_refs.clone(),
                    });
                    self.data.strings.extend(class_data.strings);
                    self.data.bytecode_refs.extend(class_data.bytecode_refs);
                    self.data.archive_signals.extend(class_data.archive_signals);
                    if let Some(class_name) = class_data.class_name {
                        self.data.class_names.push(class_name);
                    }
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

    fn observe_magic_bytes(&mut self, lower_name: &str, bytes: &[u8]) {
        if is_native_binary(bytes) {
            self.data
                .archive_signals
                .push(NATIVE_BINARY_SIGNAL.to_owned());
        }
        if bytes.starts_with(b"PK\x03\x04") && !is_fabric_declared_nested_jar(lower_name) {
            self.data.archive_signals.push(NESTED_ZIP_SIGNAL.to_owned());
        }
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
        self.add_timestamp_outlier_signal();
        self.add_modid_package_signal();
        self.add_short_name_signal();
        self.add_correlation_signals();
    }

    fn add_timestamp_outlier_signal(&mut self) {
        if self.data.entry_timestamps.len() < TIMESTAMP_OUTLIER_MIN_FILES {
            return;
        }
        let mut counts = HashMap::<&str, usize>::new();
        for (_, timestamp) in self.timestamp_candidates() {
            *counts.entry(timestamp.as_str()).or_default() += 1;
        }
        let dominant = counts.values().copied().max().unwrap_or_default();
        let total = self.timestamp_candidates().len();
        if dominant * 100 / total >= TIMESTAMP_DOMINANT_PERCENT && total > dominant {
            self.data
                .archive_signals
                .push(TIMESTAMP_OUTLIER_SIGNAL.to_owned());
        }
    }

    fn timestamp_candidates(&self) -> Vec<&(String, String)> {
        self.data
            .entry_timestamps
            .iter()
            .filter(|(path, _)| !is_signature_or_manifest_path(path))
            .collect()
    }

    fn add_modid_package_signal(&mut self) {
        if self.data.mod_ids.is_empty() || self.data.class_names.is_empty() {
            return;
        }
        let packages = self
            .data
            .class_names
            .iter()
            .filter_map(|class_name| class_name.rsplit_once('/').map(|(package, _)| package))
            .map(normalize_identifier)
            .collect::<Vec<_>>();
        let declared_ids = self
            .data
            .mod_ids
            .iter()
            .chain(self.data.mod_aliases.iter())
            .map(|mod_id| normalize_identifier(mod_id))
            .filter(|mod_id| mod_id.len() >= 4)
            .collect::<Vec<_>>();
        if declared_ids.is_empty() {
            return;
        }

        let has_matching_namespace = declared_ids.iter().any(|mod_id| {
            packages
                .iter()
                .any(|package| package.contains(mod_id) || mod_id.contains(package))
        });
        if !has_matching_namespace {
            self.data
                .archive_signals
                .push(MODID_PACKAGE_MISMATCH_SIGNAL.to_owned());
        }
    }

    fn add_short_name_signal(&mut self) {
        if self
            .data
            .archive_signals
            .iter()
            .any(|signal| signal == MIXIN_METADATA_SIGNAL)
        {
            return;
        }
        if self.data.class_names.len() < SHORT_CLASS_NAME_MIN_CLASSES {
            return;
        }
        let short_names = self
            .data
            .class_names
            .iter()
            .filter(|class_name| {
                class_name
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| name.chars().count() <= 2)
            })
            .count();
        if short_names * 100 / self.data.class_names.len() >= SHORT_CLASS_NAME_PERCENT {
            self.data
                .archive_signals
                .push(SHORT_NAMES_WITHOUT_MIXIN_SIGNAL.to_owned());
        }
    }

    fn add_correlation_signals(&mut self) {
        self.add_class_correlation_signals();

        let has_http = self.has_ref_any(&[
            "java/net/HttpURLConnection",
            "javax/net/ssl/HttpsURLConnection",
            "java/net/http/HttpClient",
            "java/net/http/HttpRequest",
        ]);
        let has_write =
            self.has_ref_any(&["java/nio/file/Files.write", "java/io/FileOutputStream"]);
        let has_exec = self.has_ref_any(&["java/lang/Runtime.exec", "java/lang/ProcessBuilder"]);
        if has_http && has_write && has_exec {
            self.data
                .archive_signals
                .push(DOWNLOAD_WRITE_EXEC_SIGNAL.to_owned());
        }

        if has_http
            && self.has_string_any(&["discord/Local Storage/leveldb", "Local State", "Login Data"])
        {
            self.data
                .archive_signals
                .push(CREDENTIAL_HTTP_EXFIL_SIGNAL.to_owned());
        }

        if self.has_ref_any(&["java/util/Base64", "Base64.getDecoder"])
            && self.has_ref_any(&[
                "java/lang/ClassLoader.defineClass",
                "java/net/URLClassLoader",
            ])
        {
            self.data
                .archive_signals
                .push(BASE64_DYNAMIC_CLASS_SIGNAL.to_owned());
        }

        if has_http
            && self.has_ref_any(&[
                "java/lang/ClassLoader.defineClass",
                "java/net/URLClassLoader",
            ])
        {
            self.data
                .archive_signals
                .push(HTTP_DYNAMIC_CLASSLOAD_SIGNAL.to_owned());
        }

        if has_http && self.has_ref_any(&["java/awt/Robot"]) {
            self.data.archive_signals.push(ROBOT_HTTP_SIGNAL.to_owned());
        }

        if self.has_ref_any(&["java/awt/datatransfer/Clipboard"])
            && self.has_crypto_address_string()
        {
            self.data
                .archive_signals
                .push(CLIPBOARD_CRYPTO_SIGNAL.to_owned());
        }
    }

    fn add_class_correlation_signals(&mut self) {
        for class_file in &self.data.class_files {
            let has_network = refs_contain_any(&class_file.bytecode_refs, NETWORK_APIS);
            if !has_network {
                continue;
            }

            if refs_contain_any(&class_file.bytecode_refs, DYNAMIC_CLASS_APIS) {
                self.data
                    .archive_signals
                    .push(REMOTE_CLASS_LOADING_SIGNAL.to_owned());
            }
            if refs_contain_any(&class_file.bytecode_refs, NATIVE_LOAD_APIS) {
                self.data
                    .archive_signals
                    .push(NATIVE_LIB_REMOTE_LOAD_SIGNAL.to_owned());
            }
            if refs_contain_any(&class_file.bytecode_refs, EXEC_APIS) {
                self.data
                    .archive_signals
                    .push(SCRIPT_DOWNLOAD_EXEC_SIGNAL.to_owned());
            }
            if refs_contain_any(&class_file.bytecode_refs, &["java/net/URLClassLoader"])
                && strings_contain_external_url(&class_file.strings)
            {
                self.data
                    .archive_signals
                    .push(EXTERNAL_URLCLASSLOADER_SIGNAL.to_owned());
            }
        }
    }

    fn has_ref_any(&self, patterns: &[&str]) -> bool {
        refs_contain_any(&self.data.bytecode_refs, patterns)
    }

    fn has_string_any(&self, patterns: &[&str]) -> bool {
        patterns.iter().any(|pattern| {
            let pattern = pattern.to_ascii_lowercase();
            self.data
                .strings
                .iter()
                .any(|candidate| candidate.to_ascii_lowercase().contains(&pattern))
        })
    }

    fn has_crypto_address_string(&self) -> bool {
        self.data.strings.iter().any(|candidate| {
            let lower = candidate.to_ascii_lowercase();
            lower.contains("bc1q") || lower.contains("bc1p") || lower.contains("0x")
        })
    }
}

fn refs_contain_any(refs: &[String], patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| {
        refs.iter().any(|candidate| {
            candidate.eq_ignore_ascii_case(pattern) || candidate.contains(pattern)
        })
    })
}

fn strings_contain_external_url(strings: &[String]) -> bool {
    strings.iter().any(|candidate| {
        let lower = candidate.to_ascii_lowercase();
        lower.contains("http://") || lower.contains("https://")
    })
}

fn is_native_binary(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MZ")
        || bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
}

fn is_fabric_declared_nested_jar(lower_name: &str) -> bool {
    lower_name.starts_with("meta-inf/jars/") && lower_name.ends_with(".jar")
}

fn is_signature_or_manifest_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower == "meta-inf/manifest.mf"
        || lower.ends_with(".sf")
        || lower.ends_with(".rsa")
        || lower.ends_with(".dsa")
        || lower.ends_with(".ec")
}

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(|character| character.to_lowercase())
        .collect()
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
    use super::{
        risk_score, summarize, ArchiveContext, ClassScanData, ScanData, ScanLimits,
        EXTERNAL_URLCLASSLOADER_SIGNAL, REMOTE_CLASS_LOADING_SIGNAL,
    };

    use crate::models::scan::{Finding, Severity, Verdict};

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

    /// Verifies remote class loading requires network and loader APIs in one class file.
    #[test]
    fn class_correlation_detects_remote_class_loading_in_one_class() {
        let mut context = test_context(vec![ClassScanData {
            strings: Vec::new(),
            bytecode_refs: vec![
                "java/net/http/HttpClient".to_owned(),
                "java/lang/ClassLoader.defineClass".to_owned(),
            ],
        }]);

        context.add_correlation_signals();

        assert!(context
            .data
            .archive_signals
            .contains(&REMOTE_CLASS_LOADING_SIGNAL.to_owned()));
    }

    /// Verifies unrelated classes do not produce the lower-noise class correlation.
    #[test]
    fn class_correlation_ignores_refs_split_across_classes() {
        let mut context = test_context(vec![
            ClassScanData {
                strings: Vec::new(),
                bytecode_refs: vec!["java/net/http/HttpClient".to_owned()],
            },
            ClassScanData {
                strings: Vec::new(),
                bytecode_refs: vec!["java/lang/ClassLoader.defineClass".to_owned()],
            },
        ]);

        context.add_class_correlation_signals();

        assert!(!context
            .data
            .archive_signals
            .contains(&REMOTE_CLASS_LOADING_SIGNAL.to_owned()));
    }

    /// Verifies URLClassLoader with an external URL is emitted as a separate high signal.
    #[test]
    fn class_correlation_detects_external_urlclassloader_target() {
        let mut context = test_context(vec![ClassScanData {
            strings: vec!["https://example.invalid/payload.jar".to_owned()],
            bytecode_refs: vec!["java/net/URL".to_owned(), "java/net/URLClassLoader".to_owned()],
        }]);

        context.add_class_correlation_signals();

        assert!(context
            .data
            .archive_signals
            .contains(&EXTERNAL_URLCLASSLOADER_SIGNAL.to_owned()));
    }

    fn test_context(class_files: Vec<ClassScanData>) -> ArchiveContext {
        ArchiveContext {
            limits: ScanLimits {
                max_total_uncompressed_bytes: 1,
                max_files_in_archive: 1,
                max_nesting_depth: 1,
                max_single_file_bytes: 1,
            },
            total_uncompressed_bytes: 0,
            file_count: 0,
            data: ScanData {
                class_files,
                ..Default::default()
            },
        }
    }
}
