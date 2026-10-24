use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::File,
    io::{Cursor, Read},
    path::Path,
};

use zip::ZipArchive;

use crate::{
    models::scan::{
        AnalysisCoverage, Capability, CodeScope, Confidence, ConfirmedChain, DecodedString,
        Evidence, Finding, Limitation, Obfuscation, ObfuscationLevel, ScanReport, Severity,
        TextResource, Verdict,
    },
    rules::engine::RulesEngine,
    scanner::{
        asset,
        class_file::{
            self, BootstrapMethodRef, CallSite, ConstantValue, ControlFlowEdgeKind, MethodScanData,
            ValueOrigin,
        },
        context_recognizers,
        dataflow::{
            analyze_method_flows_from_roots, dangerous_flow_roots, ConfirmedChainCandidate,
            ConfirmedChainKind, DataFlowConfig, FileTarget, FlowEvidence, FlowLimitation,
            MethodFlow, MethodId, Operation, SourceKind, TransformKind,
        },
        metadata, native, obfuscation, paths,
        scope::{
            classify_classes, ArchiveScopeInput, ClassScopeInput, DependencyMetadata,
            ScopeClassificationInput,
        },
        strings,
    },
};

const NESTED_JAR_SIGNAL: &str = "nested_jar";
const NESTED_ZIP_SIGNAL: &str = "nested_zip";
const SCRIPT_FILE_SIGNAL: &str = "script_file";
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
const PRIVACY_NETWORK_SYNC_RULE_ID: &str = "PRIVACY_NETWORK_SYNC";
const CUSTOM_INVOKEDYNAMIC_BOOTSTRAP_RULE_ID: &str = "CUSTOM_INVOKEDYNAMIC_BOOTSTRAP";
const MAX_CUSTOM_BOOTSTRAP_EVIDENCE: usize = 5;
const CONFIRMED_REMOTE_MEMORY_LOAD_RULE_ID: &str = "CONFIRMED_REMOTE_MEMORY_LOAD";
const CONFIRMED_EMBEDDED_NATIVE_DOWNLOADER_RULE_ID: &str = "CONFIRMED_EMBEDDED_NATIVE_DOWNLOADER";
const CONFIRMED_ENCODED_NATIVE_PAYLOAD_LOAD_RULE_ID: &str = "CONFIRMED_ENCODED_NATIVE_PAYLOAD_LOAD";
const CONFIRMED_WEBHOOK_EXFIL_RULE_ID: &str = "CONFIRMED_WEBHOOK_EXFIL";
const CREDENTIAL_WEBHOOK_CO_LOCATION_RULE_ID: &str = "CREDENTIAL_WEBHOOK_CO_LOCATION";
const SESSION_CHAT_EXFIL_CO_LOCATION_RULE_ID: &str = "SESSION_CHAT_EXFIL_CO_LOCATION";
const EXECUTABLE_DOWNLOAD_EXEC_CO_LOCATION_RULE_ID: &str = "EXECUTABLE_DOWNLOAD_EXEC_CO_LOCATION";
const OVERSIZED_ARCHIVE_ENTRY_RULE_ID: &str = "OVERSIZED_ARCHIVE_ENTRY";
const LARGE_ASSET_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024;
/// Hard ceiling on all entries, including plain resources that `max_files_in_archive` ignores.
/// Resource bytes are already bounded by the total size limit; this bounds per-entry work.
const MAX_ARCHIVE_ENTRIES: usize = 100_000;
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
const DYNAMIC_CLASS_APIS: &[&str] = &[
    "java/lang/ClassLoader.defineClass",
    "java/net/URLClassLoader",
];
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
    pub metadata_strings: Vec<String>,
    pub first_party_strings: Vec<String>,
    pub bytecode_refs: Vec<String>,
    pub first_party_bytecode_refs: Vec<String>,
    pub manifest_fields: Vec<String>,
    pub archive_signals: Vec<String>,
    pub class_major_versions: Vec<u16>,
    pub class_names: Vec<String>,
    pub class_files: Vec<ClassScanData>,
    pub mod_ids: Vec<String>,
    pub mod_aliases: Vec<String>,
    pub entrypoint_classes: Vec<String>,
    /// Archive-specific contexts. Nested archives must never share timestamps or paths with
    /// their parent archive.
    pub archive_layers: Vec<ArchiveLayer>,
    pub resource_files: Vec<ResourceScanData>,
    /// Decoding failures are retained as limitations, never transformed into strings.
    pub normalization_limitations: Vec<Limitation>,
    /// Neutral archive facts such as bundled native libraries and large assets.
    pub archive_capabilities: Vec<Capability>,
    pub embedded_native_capabilities: Vec<Capability>,
}

/// A single JAR or ZIP encountered while recursively parsing the submitted archive.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArchiveLayer {
    pub id: String,
    pub parent_id: Option<String>,
    pub path: String,
    pub depth: usize,
    pub declared_dependency: bool,
    pub mod_metadata: Vec<String>,
    pub entrypoint_classes: Vec<String>,
    pub entries: Vec<ArchiveEntryData>,
    pub timestamp_baseline: Option<String>,
}

/// Metadata retained for an entry without retaining or executing its contents.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArchiveEntryData {
    pub path: String,
    pub timestamp: Option<String>,
    pub normalized_timestamp: bool,
    pub uncompressed_size: u64,
}

/// A non-class resource and the archive layer it came from.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResourceScanData {
    pub archive_id: String,
    pub archive_path: String,
    pub path: String,
    pub uncompressed_size: u64,
    /// Shannon entropy in thousandths of a bit per byte. Keeping an integer
    /// makes resource metadata comparable without retaining resource bytes.
    pub entropy_milli_bits: u16,
    pub detected_encoding: Option<String>,
    pub decoding_confidence: Confidence,
}

/// Per-class data used for lower-noise correlation signals.
#[derive(Clone, Debug, Default)]
pub struct ClassScanData {
    pub archive_id: String,
    pub archive_path: String,
    pub path: String,
    pub class_name: Option<String>,
    pub major_version: u16,
    pub strings: Vec<String>,
    pub bytecode_refs: Vec<String>,
    pub methods: Vec<MethodScanData>,
    pub scope: CodeScope,
    pub dependency_name: Option<String>,
    pub dependency_version: Option<String>,
    pub reachable_from_entrypoint: bool,
    pub classification_confidence: Confidence,
    pub custom_bootstrap_methods: Vec<BootstrapMethodRef>,
}

/// Complete scanner result ready to persist after risk scoring.
#[derive(Clone, Debug)]
pub struct ScanOutcome {
    pub report: ScanReport,
    pub verdict: Verdict,
    pub risk_score: u8,
    pub summary: String,
    pub findings: Vec<Finding>,
}

/// Scans a stored jar from disk; intended to run inside `spawn_blocking`.
pub fn scan_file(path: &Path, limits: ScanLimits, rules_engine: &RulesEngine) -> ScanOutcome {
    match read_file(path) {
        Ok(bytes) => scan_jar_bytes(&bytes, limits, rules_engine),
        Err(error) => technical_failure_outcome(error),
    }
}

/// Scans jar bytes already held in memory, e.g. a file a browser user selected.
pub fn scan_jar_bytes(bytes: &[u8], limits: ScanLimits, rules_engine: &RulesEngine) -> ScanOutcome {
    scan_bytes(bytes, limits, rules_engine).unwrap_or_else(technical_failure_outcome)
}

fn technical_failure_outcome(error: anyhow::Error) -> ScanOutcome {
    unknown_outcome(
        "SCAN_TECHNICAL_FAILURE",
        "static_scan",
        format!("Скан не выполнен технически: {error}"),
    )
}

/// Parses and evaluates in-memory jar bytes without extracting unbounded entries.
fn scan_bytes(
    bytes: &[u8],
    limits: ScanLimits,
    rules_engine: &RulesEngine,
) -> anyhow::Result<ScanOutcome> {
    let mut context = ArchiveContext {
        limits,
        total_uncompressed_bytes: 0,
        code_file_count: 0,
        entry_count: 0,
        data: ScanData::default(),
        structural_findings: Vec::new(),
        next_archive_id: 0,
    };
    let root_archive_id = context.create_archive_layer(None, "<root>".to_owned(), 0, false);

    if let Err(error) = parse_zip_bytes(bytes, &root_archive_id, &mut context) {
        return Ok(unknown_outcome(
            error.rule_id(),
            "archive_structure",
            error.to_string(),
        ));
    }

    context.add_derived_signals();
    let obfuscation = obfuscation::enrich_and_analyze(&mut context.data);
    let data_flow = analyze_scan_data_flow(&context.data);
    let contextual_results = context_recognizers::recognize(&context.data);
    let mut findings = rules_engine.evaluate(&context.data);
    findings.extend(context.structural_findings.clone());
    findings.retain(|finding| !contextual_results.suppresses(&finding.rule_id));
    findings.retain(|finding| finding.category != "obfuscation");
    findings.extend(contextual_results.findings);
    add_contextual_findings(&mut findings, &context.data);
    findings.extend(custom_invokedynamic_bootstrap_finding(&context.data));
    findings.extend(credential_webhook_co_location_finding(&context.data));
    findings.extend(session_chat_exfil_co_location_finding(&context.data));
    findings.extend(executable_download_exec_co_location_finding(&context.data));
    let mut confirmed_chains = data_flow
        .confirmed_chains
        .iter()
        .map(confirmed_chain_from_candidate)
        .collect::<Vec<_>>();
    if let Some(chain) = confirmed_remote_memory_load(&context.data) {
        confirmed_chains.push(chain);
    }
    if let Some(chain) = confirmed_embedded_native_downloader(&context.data) {
        confirmed_chains.push(chain);
    }
    if let Some(chain) = confirmed_encoded_native_payload_load(&context.data) {
        confirmed_chains.push(chain);
    }
    if let Some(chain) = confirmed_webhook_exfil(&context.data, &obfuscation.decoded_values) {
        confirmed_chains.push(chain);
    }
    if let Some(safe_context) = confirmed_safe_updater_context(&confirmed_chains) {
        confirmed_chains.push(safe_context);
    }
    let chain_capabilities = updater_capabilities(&confirmed_chains);
    let analysis_coverage = analysis_coverage(&context.data, &data_flow);
    let has_first_party_network_calls = has_first_party_network_calls(&context.data);
    let mut limitations = data_flow
        .limitations
        .iter()
        .map(flow_limitation)
        .collect::<Vec<_>>();
    limitations.extend(context.data.normalization_limitations.clone());
    if !matches!(obfuscation.obfuscation.level, ObfuscationLevel::None) {
        limitations.push(Limitation {
            code: "OBFUSCATED_CODE".to_owned(),
            message: "Обфускация ограничивает полноту статического анализа; для важных решений нужна ручная проверка.".to_owned(),
            evidence: Vec::new(),
        });
    }
    if analysis_coverage.parsed_classes < analysis_coverage.total_classes {
        limitations.push(Limitation {
            code: "CLASS_PARSE_LIMITATION".to_owned(),
            message:
                "Часть class-файлов не удалось разобрать; покрытие статического анализа снижено."
                    .to_owned(),
            evidence: Vec::new(),
        });
    }
    if has_first_party_network_calls
        && analysis_coverage.method_flow_coverage == 0
        && !matches!(obfuscation.obfuscation.level, ObfuscationLevel::None)
    {
        limitations.push(Limitation {
            code: "NETWORK_FLOW_ANALYSIS_INCOMPLETE".to_owned(),
            message: "Сетевой код в обфусцированном моде не был покрыт анализом потока; вердикт clean недостоверен."
                .to_owned(),
            evidence: Vec::new(),
        });
    }
    let limitations = aggregate_limitations(limitations);
    let (verdict, risk_score, summary) = finalize_report_with_network_analysis_limits(
        &findings,
        &confirmed_chains,
        &obfuscation.obfuscation,
        &analysis_coverage,
        has_first_party_network_calls,
    );

    let report = ScanReport {
        verdict: verdict.clone(),
        risk_score,
        confidence: obfuscation.confidence,
        obfuscation_score: obfuscation.obfuscation.score,
        analysis_coverage,
        capabilities: context
            .data
            .archive_capabilities
            .into_iter()
            .chain(context.data.embedded_native_capabilities)
            .chain(contextual_results.capabilities)
            .chain(chain_capabilities)
            .collect(),
        decoded_strings: decoded_strings(&obfuscation.decoded_values, &context.data.class_files),
        text_resources: text_resources(&context.data.resource_files),
        findings: findings.clone(),
        confirmed_chains,
        obfuscation: obfuscation.obfuscation,
        limitations,
    };

    Ok(ScanOutcome {
        report,
        verdict,
        risk_score,
        summary,
        findings,
    })
}

fn flow_limitation(limitation: &FlowLimitation) -> Limitation {
    let (code, message, method, offset) = match limitation {
        FlowLimitation::MissingMethod { caller, callee } => (
            "UNRESOLVED_CALL",
            format!("Не удалось разрешить вызов {}.{}{}", callee.class_name, callee.method_name, callee.descriptor),
            caller,
            None,
        ),
        FlowLimitation::InterproceduralDepthReached { method } => (
            "INTERPROCEDURAL_DEPTH_LIMIT",
            "Достигнут лимит глубины межметодного анализа.".to_owned(),
            method,
            None,
        ),
        FlowLimitation::RecursiveCallSkipped { method } => (
            "RECURSIVE_CALL_SKIPPED",
            "Рекурсивный вызов не анализировался повторно.".to_owned(),
            method,
            None,
        ),
        FlowLimitation::UnknownFileTarget { method, offset } => (
            "UNKNOWN_FILE_TARGET",
            "Не удалось статически установить целевой путь операции с файлом.".to_owned(),
            method,
            Some(*offset),
        ),
        FlowLimitation::UnsupportedInstruction { method, offset, opcode } => (
            "UNSUPPORTED_INSTRUCTION",
            format!("Инструкция JVM 0x{opcode:02x} не поддержана flow-adapter."),
            method,
            Some(*offset),
        ),
        FlowLimitation::ObjectTrackingUnavailable { method, offset, object_type } => (
            "OBJECT_TRACKING_LIMITATION",
            format!("Невозможно отследить состояние объекта {object_type}."),
            method,
            Some(*offset),
        ),
        FlowLimitation::LinearControlFlow { method } => (
            "LINEAR_CFG_ANALYSIS",
            "Метод содержит ветвления и проанализирован линейно; значения на CFG-join не объединялись."
                .to_owned(),
            method,
            None,
        ),
    };
    Limitation {
        code: code.to_owned(),
        message,
        evidence: vec![Evidence {
            archive_id: method.archive_id.clone(),
            archive_path: method.archive_id.clone(),
            class_name: Some(method.class_name.clone()),
            method_name: Some(method.method_name.clone()),
            method_descriptor: Some(method.descriptor.clone()),
            bytecode_offset: offset,
            resource_path: None,
            operation: "flow_limitation".to_owned(),
            value_preview: None,
            source_value: None,
            target_value: None,
            confidence: Confidence::Low,
            scope: CodeScope::Unknown,
        }],
    }
}

const MAX_LIMITATION_EXAMPLES: usize = 3;

/// Keeps scan reports bounded: limitations describe analyzer coverage, not one
/// user-facing finding per bytecode location.
fn aggregate_limitations(limitations: Vec<Limitation>) -> Vec<Limitation> {
    let mut grouped = BTreeMap::<String, Vec<Limitation>>::new();
    for limitation in limitations {
        grouped
            .entry(limitation.code.clone())
            .or_default()
            .push(limitation);
    }
    grouped
        .into_values()
        .map(|values| {
            let count = values.len();
            let first = &values[0];
            let evidence = values
                .iter()
                .flat_map(|limitation| limitation.evidence.iter().cloned())
                .take(MAX_LIMITATION_EXAMPLES)
                .collect::<Vec<_>>();
            let message = if count == 1 {
                first.message.clone()
            } else {
                format!(
                    "{} Всего: {count}; показаны первые {} примера.",
                    first.message,
                    evidence.len()
                )
            };
            Limitation {
                code: first.code.clone(),
                message,
                evidence,
            }
        })
        .collect()
}

/// Recomputes verdict fields after callers add non-static findings such as VirusTotal signals.
pub fn finalize_findings(findings: &[Finding]) -> (Verdict, u8, String) {
    finalize_report(findings, &[], &Obfuscation::default())
}

/// Applies score caps and evidence gates. Weak findings alone can never produce `malicious`.
pub fn finalize_report(
    findings: &[Finding],
    confirmed_chains: &[ConfirmedChain],
    obfuscation: &Obfuscation,
) -> (Verdict, u8, String) {
    let mut risk_score = risk_score(findings, confirmed_chains, obfuscation);
    let verdict = verdict_from_evidence(findings, confirmed_chains, obfuscation, risk_score);
    if verdict == Verdict::Malicious {
        risk_score = risk_score.max(70);
    }
    let summary = summarize(findings, verdict.clone());
    (verdict, risk_score, summary)
}

/// Recomputes a verdict while preserving analysis-completeness safeguards.
pub fn finalize_report_with_analysis_limits(
    findings: &[Finding],
    confirmed_chains: &[ConfirmedChain],
    obfuscation: &Obfuscation,
    analysis_coverage: &AnalysisCoverage,
) -> (Verdict, u8, String) {
    finalize_report_with_network_analysis_limits(
        findings,
        confirmed_chains,
        obfuscation,
        analysis_coverage,
        false,
    )
}

fn finalize_report_with_network_analysis_limits(
    findings: &[Finding],
    confirmed_chains: &[ConfirmedChain],
    obfuscation: &Obfuscation,
    analysis_coverage: &AnalysisCoverage,
    has_first_party_network_calls: bool,
) -> (Verdict, u8, String) {
    let (verdict, risk_score, _summary) = finalize_report(findings, confirmed_chains, obfuscation);
    let verdict = apply_analysis_limits(
        verdict,
        obfuscation,
        analysis_coverage,
        has_first_party_network_calls,
    );
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
    archive_id: &str,
    context: &mut ArchiveContext,
) -> Result<(), ScanAbort> {
    let depth = context.archive_depth(archive_id)?;
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
        let timestamp = entry.last_modified().map(format_zip_timestamp);
        let normalized_timestamp = entry
            .last_modified()
            .is_some_and(is_normalized_zip_timestamp);
        let disposition = context.observe_file(
            archive_id,
            &name,
            uncompressed_size,
            timestamp,
            normalized_timestamp,
        )?;
        if disposition == EntryDisposition::SkipOversized {
            continue;
        }

        let mut entry_bytes = Vec::new();
        entry
            .read_to_end(&mut entry_bytes)
            .map_err(|error| ScanAbort::InvalidZip {
                message: error.to_string(),
            })?;
        context.extract_entry(archive_id, &name, &entry_bytes)?;
    }

    context.calculate_timestamp_baseline(archive_id)?;

    Ok(())
}

/// Mutable scanner state shared across nested archives so limits are global, not per-jar.
struct ArchiveContext {
    limits: ScanLimits,
    total_uncompressed_bytes: u64,
    code_file_count: usize,
    entry_count: usize,
    data: ScanData,
    structural_findings: Vec<Finding>,
    next_archive_id: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryDisposition {
    Extract,
    SkipOversized,
}

impl ArchiveContext {
    fn create_archive_layer(
        &mut self,
        parent_id: Option<String>,
        path: String,
        depth: usize,
        declared_dependency: bool,
    ) -> String {
        let id = format!("archive-{}", self.next_archive_id);
        self.next_archive_id += 1;
        self.data.archive_layers.push(ArchiveLayer {
            id: id.clone(),
            parent_id,
            path,
            depth,
            declared_dependency,
            mod_metadata: Vec::new(),
            entrypoint_classes: Vec::new(),
            entries: Vec::new(),
            timestamp_baseline: None,
        });
        id
    }

    fn archive_layer(&self, archive_id: &str) -> Result<&ArchiveLayer, ScanAbort> {
        self.data
            .archive_layers
            .iter()
            .find(|layer| layer.id == archive_id)
            .ok_or_else(|| ScanAbort::InvalidZip {
                message: format!("missing archive layer {archive_id}"),
            })
    }

    fn archive_layer_mut(&mut self, archive_id: &str) -> Result<&mut ArchiveLayer, ScanAbort> {
        self.data
            .archive_layers
            .iter_mut()
            .find(|layer| layer.id == archive_id)
            .ok_or_else(|| ScanAbort::InvalidZip {
                message: format!("missing archive layer {archive_id}"),
            })
    }

    fn archive_depth(&self, archive_id: &str) -> Result<usize, ScanAbort> {
        Ok(self.archive_layer(archive_id)?.depth)
    }

    fn archive_path(&self, archive_id: &str) -> Result<String, ScanAbort> {
        Ok(self.archive_layer(archive_id)?.path.clone())
    }

    /// Records file metadata and avoids extracting oversized archive entries.
    fn observe_file(
        &mut self,
        archive_id: &str,
        name: &str,
        uncompressed_size: u64,
        timestamp: Option<String>,
        normalized_timestamp: bool,
    ) -> Result<EntryDisposition, ScanAbort> {
        self.entry_count += 1;
        if self.entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(ScanAbort::EntryCount {
                limit: MAX_ARCHIVE_ENTRIES,
            });
        }
        // Only parsed code counts toward the configured limit: asset-heavy mods such as
        // cosmetics packs ship thousands of textures and models that need no class analysis.
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".class") || lower.ends_with(".jar") || lower.ends_with(".zip") {
            self.code_file_count += 1;
            if self.code_file_count > self.limits.max_files_in_archive {
                return Err(ScanAbort::FileCount {
                    limit: self.limits.max_files_in_archive,
                });
            }
        }

        self.archive_layer_mut(archive_id)?
            .entries
            .push(ArchiveEntryData {
                path: name.to_owned(),
                timestamp,
                normalized_timestamp,
                uncompressed_size,
            });
        self.observe_archive_structure(name, uncompressed_size);

        if uncompressed_size > self.limits.max_single_file_bytes {
            self.record_oversized_entry(archive_id, name, uncompressed_size)?;
            return Ok(EntryDisposition::SkipOversized);
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

        Ok(EntryDisposition::Extract)
    }

    /// Records a zip-bomb indicator while keeping other bounded entries analyzable.
    fn record_oversized_entry(
        &mut self,
        archive_id: &str,
        name: &str,
        uncompressed_size: u64,
    ) -> Result<(), ScanAbort> {
        let archive_path = self.archive_path(archive_id)?;
        let evidence = Evidence {
            archive_id: archive_id.to_owned(),
            archive_path,
            class_name: None,
            method_name: None,
            method_descriptor: None,
            bytecode_offset: None,
            resource_path: Some(name.to_owned()),
            operation: "oversized_archive_entry".to_owned(),
            value_preview: Some(format!("{uncompressed_size} bytes")),
            source_value: None,
            target_value: None,
            confidence: Confidence::High,
            scope: CodeScope::Resource,
        };
        self.structural_findings.push(Finding {
            rule_id: OVERSIZED_ARCHIVE_ENTRY_RULE_ID.to_owned(),
            category: "archive_structure".to_owned(),
            kind: crate::models::scan::FindingKind::Finding,
            severity: Severity::High,
            confidence: Confidence::High,
            score_contribution: Severity::High.score_weight(),
            scope: CodeScope::Resource,
            message: "Обнаружен oversized-ресурс, характерный для zip-bomb; его содержимое безопасно не извлекалось.".to_owned(),
            evidence: vec![evidence.clone()],
            related_chain_id: None,
        });
        self.data.normalization_limitations.push(Limitation {
            code: "ARCHIVE_ENTRY_SKIPPED_SIZE_LIMIT".to_owned(),
            message: format!(
                "Файл {name} имеет распакованный размер {uncompressed_size} байт и не был извлечён: лимит {} байт.",
                self.limits.max_single_file_bytes,
            ),
            evidence: vec![evidence],
        });
        Ok(())
    }

    /// Adds archive-structure signals based on path and size metadata.
    fn observe_archive_structure(&mut self, name: &str, _uncompressed_size: u64) {
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
        self.data.strings.push(name.to_owned());
    }

    /// Extracts content signals from metadata, class files, generic resources, and nested jars.
    fn extract_entry(
        &mut self,
        archive_id: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), ScanAbort> {
        let lower = name.to_ascii_lowercase();
        self.observe_magic_bytes(archive_id, name, &lower, bytes)?;

        self.observe_asset(archive_id, name, bytes)?;

        if lower.ends_with(".jar") || lower.ends_with(".zip") {
            let parent = self.archive_layer(archive_id)?;
            let child_path = archive_entry_path(&parent.path, name);
            let child_archive_id = self.create_archive_layer(
                Some(archive_id.to_owned()),
                child_path,
                parent.depth + 1,
                is_fabric_declared_nested_jar(&lower),
            );
            return parse_zip_bytes(bytes, &child_archive_id, self);
        }

        let decoded_text = strings::decode_text_resource(name, bytes);
        if metadata::is_metadata_file(name) {
            let decoded = match &decoded_text {
                Ok(Some(decoded)) => decoded,
                Ok(None) => {
                    self.add_text_decoding_limitation(
                        archive_id,
                        name,
                        "ресурс metadata не распознан как текст",
                    )?;
                    return Ok(());
                }
                Err(_) => {
                    self.add_text_decoding_limitation(
                        archive_id,
                        name,
                        "не удалось определить корректную кодировку metadata",
                    )?;
                    return Ok(());
                }
            };
            self.archive_layer_mut(archive_id)?
                .mod_metadata
                .push(name.to_owned());
            let metadata = metadata::extract_metadata(name, &decoded.text);
            self.archive_layer_mut(archive_id)?
                .entrypoint_classes
                .extend(metadata.entrypoint_classes.clone());
            self.data.manifest_fields.extend(metadata.manifest_fields);
            self.data.metadata_strings.extend(metadata.strings.clone());
            self.data.strings.extend(metadata.strings);
            self.data.mod_ids.extend(metadata.mod_ids);
            self.data.mod_aliases.extend(metadata.mod_aliases);
            self.data
                .entrypoint_classes
                .extend(metadata.entrypoint_classes);
            self.data.archive_signals.extend(metadata.archive_signals);
        }

        if lower.ends_with(".class") {
            match class_file::parse_class_file(bytes) {
                Ok(class_data) => {
                    self.data.class_files.push(ClassScanData {
                        archive_id: archive_id.to_owned(),
                        archive_path: self.archive_path(archive_id)?,
                        path: name.to_owned(),
                        class_name: class_data.class_name.clone(),
                        major_version: class_data.major_version,
                        strings: class_data.strings.clone(),
                        bytecode_refs: class_data.bytecode_refs.clone(),
                        methods: class_data.methods,
                        scope: CodeScope::Unknown,
                        dependency_name: None,
                        dependency_version: None,
                        reachable_from_entrypoint: false,
                        classification_confidence: Confidence::Low,
                        custom_bootstrap_methods: class_data.custom_bootstrap_methods,
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
            self.data.resource_files.push(ResourceScanData {
                archive_id: archive_id.to_owned(),
                archive_path: self.archive_path(archive_id)?,
                path: name.to_owned(),
                uncompressed_size: bytes.len() as u64,
                entropy_milli_bits: shannon_entropy_milli_bits(bytes),
                detected_encoding: decoded_text
                    .as_ref()
                    .ok()
                    .and_then(|decoded| decoded.as_ref())
                    .map(|decoded| decoded.encoding.as_str().to_owned()),
                decoding_confidence: decoded_text
                    .as_ref()
                    .ok()
                    .and_then(|decoded| decoded.as_ref())
                    .map(|decoded| decoded.confidence.clone())
                    .unwrap_or(Confidence::Low),
            });
            match decoded_text {
                Ok(Some(decoded)) => self.data.strings.push(decoded.text),
                Ok(None) => self
                    .data
                    .strings
                    .extend(strings::extract_printable_strings(bytes)),
                Err(_) => self.add_text_decoding_limitation(
                    archive_id,
                    name,
                    "не удалось определить корректную кодировку текстового ресурса",
                )?,
            }
        }

        Ok(())
    }

    fn add_text_decoding_limitation(
        &mut self,
        archive_id: &str,
        path: &str,
        message: &str,
    ) -> Result<(), ScanAbort> {
        self.data.normalization_limitations.push(Limitation {
            code: "TEXT_DECODING_LIMITATION".to_owned(),
            message: format!("{message}: {path}"),
            evidence: vec![Evidence {
                archive_id: archive_id.to_owned(),
                archive_path: self.archive_path(archive_id)?,
                class_name: None,
                method_name: None,
                method_descriptor: None,
                bytecode_offset: None,
                resource_path: Some(path.to_owned()),
                operation: "text_decoding".to_owned(),
                value_preview: None,
                source_value: None,
                target_value: None,
                confidence: Confidence::Low,
                scope: CodeScope::Resource,
            }],
        });
        Ok(())
    }

    fn observe_magic_bytes(
        &mut self,
        archive_id: &str,
        name: &str,
        lower_name: &str,
        bytes: &[u8],
    ) -> Result<(), ScanAbort> {
        if let Some(analysis) = native::inspect_native_file(name, bytes) {
            let archive_path = self.archive_path(archive_id)?;
            let (rule_id, message, value_preview) = if analysis.known_library.is_none()
                && analysis.has_downloader_imports
            {
                (
                    "EMBEDDED_NATIVE_DOWNLOADER",
                    "Встроенная DLL импортирует URLDownloadToFile и ShellExecute; это признак native-загрузчика.".to_owned(),
                    Some("URLDownloadToFile + ShellExecute".to_owned()),
                )
            } else {
                match analysis.known_library {
                    Some(known_library) => (
                        "EMBEDDED_NATIVE_LIBRARY",
                        format!("Встроенная native-библиотека {known_library:?} распознана по штатному пути загрузчика."),
                        Some(format!("{known_library:?}")),
                    ),
                    None => (
                        "EMBEDDED_NATIVE_BINARY",
                        "В архиве есть native-бинарный ресурс; его загрузка или выполнение не подтверждены.".to_owned(),
                        None,
                    ),
                }
            };
            let capability = Capability {
                rule_id: rule_id.to_owned(),
                message,
                evidence: vec![Evidence {
                    archive_id: archive_id.to_owned(),
                    archive_path,
                    class_name: None,
                    method_name: None,
                    method_descriptor: None,
                    bytecode_offset: None,
                    resource_path: Some(name.to_owned()),
                    operation: "embedded_native_binary".to_owned(),
                    value_preview,
                    source_value: None,
                    target_value: None,
                    confidence: Confidence::High,
                    scope: CodeScope::Resource,
                }],
            };
            if analysis.known_library.is_some() {
                self.data.embedded_native_capabilities.push(capability);
            } else {
                self.data.archive_capabilities.push(capability);
            }
        }
        if bytes.starts_with(b"PK\x03\x04") && !is_fabric_declared_nested_jar(lower_name) {
            self.data.archive_signals.push(NESTED_ZIP_SIGNAL.to_owned());
        }
        Ok(())
    }

    fn observe_asset(
        &mut self,
        archive_id: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), ScanAbort> {
        if !name.to_ascii_lowercase().starts_with("assets/")
            || (bytes.len() as u64) < LARGE_ASSET_THRESHOLD_BYTES
        {
            return Ok(());
        }
        let analysis = asset::inspect_asset(name, bytes);
        let valid_image = analysis.detected_format.is_some()
            && analysis.extension_matches_magic
            && analysis.trailing_payload.is_none();
        if !valid_image {
            self.data.archive_capabilities.push(Capability {
                rule_id: "LARGE_ASSET_RESOURCE".to_owned(),
                message: "Архив содержит большой ресурс в assets/; скрытая нагрузка или выполнение не подтверждены.".to_owned(),
                evidence: vec![Evidence {
                    archive_id: archive_id.to_owned(),
                    archive_path: self.archive_path(archive_id)?,
                    class_name: None,
                    method_name: None,
                    method_descriptor: None,
                    bytecode_offset: None,
                    resource_path: Some(name.to_owned()),
                    operation: "large_asset".to_owned(),
                    value_preview: Some(format!("{} bytes", bytes.len())),
                    source_value: None,
                    target_value: None,
                    confidence: Confidence::High,
                    scope: CodeScope::Resource,
                }],
            });
        }
        Ok(())
    }

    /// Adds aggregate signals that require seeing multiple files before deciding.
    fn add_derived_signals(&mut self) {
        self.classify_code_scope();
        self.add_first_party_scope();
        let scoped_versions = self.first_party_class_versions();
        let version_source = if scoped_versions.is_empty() {
            self.data.class_major_versions.as_slice()
        } else {
            scoped_versions.as_slice()
        };
        let unique_versions = version_source.iter().copied().collect::<HashSet<_>>();
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
    }

    fn add_first_party_scope(&mut self) {
        for class_file in &self.data.class_files {
            if class_file.scope == CodeScope::FirstParty {
                self.data
                    .first_party_strings
                    .extend(class_file.strings.clone());
                self.data
                    .first_party_bytecode_refs
                    .extend(class_file.bytecode_refs.clone());
            }
        }
    }

    fn first_party_class_versions(&self) -> Vec<u16> {
        self.data
            .class_files
            .iter()
            .filter(|class_file| class_file.scope == CodeScope::FirstParty)
            .map(|class_file| class_file.major_version)
            .collect()
    }

    /// Attributes every class to the archive it came from before first-party rules run.
    fn classify_code_scope(&mut self) {
        let archives = self
            .data
            .archive_layers
            .iter()
            .map(|layer| ArchiveScopeInput {
                archive_id: layer.id.clone(),
                archive_path: layer.path.clone(),
                depth: layer.depth,
                declared_dependency: layer
                    .declared_dependency
                    .then(|| dependency_metadata_from_archive_path(&layer.path)),
                has_mod_metadata: !layer.mod_metadata.is_empty(),
                entrypoint_classes: layer.entrypoint_classes.clone(),
                mixin_package_roots: Vec::new(),
                maven_package_roots: Vec::new(),
            })
            .collect();
        let classes = self
            .data
            .class_files
            .iter()
            .filter_map(|class| {
                class.class_name.as_ref().map(|class_name| ClassScopeInput {
                    archive_id: class.archive_id.clone(),
                    class_name: class_name.clone(),
                })
            })
            .collect();
        let classifications = classify_classes(&ScopeClassificationInput {
            archives,
            classes,
            dominant_package_roots: dominant_package_roots(&self.data.class_files),
        });
        let classifications = classifications
            .into_iter()
            .map(|classification| {
                (
                    (
                        classification.archive_id.clone(),
                        classification.class_name.clone(),
                    ),
                    classification,
                )
            })
            .collect::<HashMap<_, _>>();

        for class in &mut self.data.class_files {
            let Some(class_name) = &class.class_name else {
                continue;
            };
            let key = (class.archive_id.clone(), class_name.clone());
            let Some(classification) = classifications.get(&key) else {
                continue;
            };
            class.scope = classification.scope.clone();
            class.dependency_name = classification
                .dependency
                .as_ref()
                .map(|dependency| dependency.name.clone());
            class.dependency_version = classification
                .dependency
                .as_ref()
                .and_then(|dependency| dependency.version.clone());
            class.reachable_from_entrypoint = classification.reachable_from_entrypoint;
            class.classification_confidence = classification.classification_confidence.clone();
        }
    }

    fn add_timestamp_outlier_signal(&mut self) {
        if self
            .data
            .archive_layers
            .iter()
            .any(archive_layer_has_timestamp_outlier)
        {
            self.data
                .archive_signals
                .push(TIMESTAMP_OUTLIER_SIGNAL.to_owned());
        }
    }

    fn calculate_timestamp_baseline(&mut self, archive_id: &str) -> Result<(), ScanAbort> {
        let layer = self.archive_layer_mut(archive_id)?;
        let mut counts = HashMap::<&str, usize>::new();
        for entry in layer.entries.iter().filter(|entry| {
            !entry.normalized_timestamp && is_timestamp_outlier_candidate(&entry.path)
        }) {
            if let Some(timestamp) = entry.timestamp.as_deref() {
                *counts.entry(timestamp).or_default() += 1;
            }
        }
        layer.timestamp_baseline = counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(timestamp, _)| timestamp.to_owned());
        Ok(())
    }

    fn add_modid_package_signal(&mut self) {
        if self.data.mod_ids.is_empty() || self.data.class_names.is_empty() {
            return;
        }
        let packages = self
            .data
            .class_files
            .iter()
            .filter(|class_file| class_file.scope == CodeScope::FirstParty)
            .filter_map(|class_file| class_file.class_name.as_deref())
            .filter_map(|class_name| class_name.rsplit_once('/').map(|(package, _)| package))
            .map(normalize_identifier)
            .collect::<Vec<_>>();
        if packages.is_empty() {
            return;
        }
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
            packages.iter().any(|package| {
                package.contains(mod_id)
                    || mod_id.contains(package)
                    || has_significant_identifier_overlap(mod_id, package)
            })
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
            if class_file.scope != CodeScope::FirstParty {
                continue;
            }
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
        refs.iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(pattern) || candidate.contains(pattern))
    })
}

fn strings_contain_external_url(strings: &[String]) -> bool {
    strings.iter().any(|candidate| {
        let lower = candidate.to_ascii_lowercase();
        lower.contains("http://") || lower.contains("https://")
    })
}

/// Returns Shannon entropy in thousandths of a bit per byte without retaining
/// resource content after archive parsing.
fn shannon_entropy_milli_bits(bytes: &[u8]) -> u16 {
    if bytes.is_empty() {
        return 0;
    }
    let mut counts = [0_usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let length = bytes.len() as f64;
    let entropy = counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum::<f64>();
    (entropy * 1_000.0).round().clamp(0.0, f64::from(u16::MAX)) as u16
}

fn is_fabric_declared_nested_jar(lower_name: &str) -> bool {
    lower_name.starts_with("meta-inf/jars/") && lower_name.ends_with(".jar")
}

fn dependency_metadata_from_archive_path(path: &str) -> DependencyMetadata {
    let name = path
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .trim_end_matches(".jar")
        .to_owned();
    DependencyMetadata {
        name,
        version: None,
        package_roots: Vec::new(),
    }
}

fn dominant_package_roots(class_files: &[ClassScanData]) -> Vec<String> {
    let mut roots = HashMap::<String, usize>::new();
    for class_file in class_files {
        let Some(class_name) = class_file.class_name.as_deref() else {
            continue;
        };
        let package = class_name
            .rsplit_once('/')
            .map_or(class_name, |(package, _)| package);
        let segments = package
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        if segments.is_empty() {
            continue;
        }
        let root = segments[..segments.len().min(3)].join("/");
        *roots.entry(root).or_default() += 1;
    }
    roots
        .into_iter()
        .filter_map(|(root, count)| (count >= 2).then_some(root))
        .collect()
}

fn is_signature_or_manifest_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower == "meta-inf/manifest.mf"
        || lower.ends_with(".sf")
        || lower.ends_with(".rsa")
        || lower.ends_with(".dsa")
        || lower.ends_with(".ec")
}

fn is_timestamp_outlier_candidate(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    !is_signature_or_manifest_path(path)
        && !metadata::is_metadata_file(path)
        && !lower.ends_with(".jar")
        && !lower.ends_with(".zip")
        && !lower.starts_with("assets/")
        && !lower.contains("/lang/")
        && !lower.ends_with("readme")
        && !lower.ends_with("readme.txt")
        && !lower.ends_with("readme.md")
}

fn archive_layer_has_timestamp_outlier(layer: &ArchiveLayer) -> bool {
    let candidates = layer
        .entries
        .iter()
        .filter(|entry| !entry.normalized_timestamp && is_timestamp_outlier_candidate(&entry.path))
        .collect::<Vec<_>>();
    if candidates.len() < TIMESTAMP_OUTLIER_MIN_FILES {
        return false;
    }

    let mut counts = HashMap::<&str, usize>::new();
    for entry in &candidates {
        if let Some(timestamp) = entry.timestamp.as_deref() {
            *counts.entry(timestamp).or_default() += 1;
        }
    }
    let dominant = counts.values().copied().max().unwrap_or_default();
    dominant * 100 / candidates.len() >= TIMESTAMP_DOMINANT_PERCENT && candidates.len() > dominant
}

fn archive_entry_path(archive_path: &str, entry_path: &str) -> String {
    if archive_path == "<root>" {
        entry_path.to_owned()
    } else {
        format!("{archive_path}!/{entry_path}")
    }
}

fn format_zip_timestamp(timestamp: zip::DateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        timestamp.year(),
        timestamp.month(),
        timestamp.day(),
        timestamp.hour(),
        timestamp.minute(),
        timestamp.second()
    )
}

fn is_normalized_zip_timestamp(timestamp: zip::DateTime) -> bool {
    timestamp.year() == 1980 && timestamp.month() == 1 && timestamp.day() == 1
}

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(|character| character.to_lowercase())
        .collect()
}

fn has_significant_identifier_overlap(left: &str, right: &str) -> bool {
    const MIN_OVERLAP: usize = 6;

    if left.len() < MIN_OVERLAP || right.len() < MIN_OVERLAP {
        return false;
    }

    let (shorter, longer) = if left.len() <= right.len() {
        (left, right)
    } else {
        (right, left)
    };

    (0..=shorter.len() - MIN_OVERLAP)
        .map(|start| &shorter[start..start + MIN_OVERLAP])
        .any(|part| longer.contains(part))
}

fn add_contextual_findings(findings: &mut Vec<Finding>, data: &ScanData) {
    if findings
        .iter()
        .any(|finding| finding.rule_id == PRIVACY_NETWORK_SYNC_RULE_ID)
    {
        return;
    }

    if has_privacy_network_sync(data) {
        findings.push(Finding {
            rule_id: PRIVACY_NETWORK_SYNC_RULE_ID.to_owned(),
            category: "privacy".to_owned(),
            kind: crate::models::scan::FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::Low,
            score_contribution: 0,
            scope: CodeScope::FirstParty,
            message: "Обнаружена связка сеть/WebSocket + идентификаторы игрока/сервера + Authorization/Bearer; без доказанного потока данных это требует ручной проверки.".to_owned(),
            evidence: Vec::new(),
            related_chain_id: None,
        });
    }
}

/// javac, Kotlin, Scala, and Groovy link `invokedynamic` only through their
/// runtime factories. A bootstrap defined by the mod resolves call targets at
/// runtime, so network, session, and loader calls disappear from static call
/// sites; that alone makes a clean verdict unreliable.
fn custom_invokedynamic_bootstrap_finding(data: &ScanData) -> Option<Finding> {
    let evidence = data
        .class_files
        .iter()
        .filter(|class_file| {
            matches!(
                class_file.scope,
                CodeScope::FirstParty | CodeScope::NestedMod | CodeScope::Unknown
            )
        })
        .flat_map(|class_file| {
            class_file
                .custom_bootstrap_methods
                .iter()
                .map(move |bootstrap| Evidence {
                    archive_id: class_file.archive_id.clone(),
                    archive_path: class_file.archive_path.clone(),
                    class_name: class_file.class_name.clone(),
                    method_name: Some(bootstrap.name.clone()),
                    method_descriptor: Some(bootstrap.descriptor.clone()),
                    bytecode_offset: None,
                    resource_path: Some(class_file.path.clone()),
                    operation: "custom_invokedynamic_bootstrap".to_owned(),
                    value_preview: Some(format!("{}.{}", bootstrap.owner, bootstrap.name)),
                    source_value: None,
                    target_value: None,
                    confidence: Confidence::High,
                    scope: class_file.scope.clone(),
                })
        })
        .take(MAX_CUSTOM_BOOTSTRAP_EVIDENCE)
        .collect::<Vec<_>>();
    let scope = evidence.first()?.scope.clone();
    Some(Finding {
        rule_id: CUSTOM_INVOKEDYNAMIC_BOOTSTRAP_RULE_ID.to_owned(),
        category: "evasion".to_owned(),
        kind: crate::models::scan::FindingKind::Finding,
        severity: Severity::High,
        confidence: Confidence::High,
        score_contribution: 40,
        scope,
        message: "Код мода связывает invokedynamic через собственный bootstrap-метод: реальные вызовы определяются только во время выполнения и скрыты от статического анализа. Так работают обфускаторы, маскирующие сетевые и загрузочные вызовы.".to_owned(),
        evidence,
        related_chain_id: None,
    })
}

/// Lowercase markers of browser, Discord, and launcher credential stores.
const CREDENTIAL_STORE_MARKERS: &[&str] = &[
    "login data",
    "local state",
    "local storage\\leveldb",
    "local storage/leveldb",
];

/// Lowercase prefixes of webhook endpoints that accept arbitrary POST bodies.
const WEBHOOK_MARKERS: &[&str] = &[
    "discord.com/api/webhooks/",
    "discordapp.com/api/webhooks/",
    "hooks.slack.com/services/",
];

/// Flags a single class that holds both a credential store path and a webhook endpoint.
/// The exfiltration call is often guarded or flow-dependent, so the static flow chain cannot
/// confirm it; the co-location itself is the stealer signature and must carry risk. Scope is
/// not filtered because stealers are often hidden in declared nested jars, which classify as
/// bundled dependencies; the evidence keeps the scope visible.
fn credential_webhook_co_location_finding(data: &ScanData) -> Option<Finding> {
    data.class_files
        .iter()
        .find_map(|class_file| {
            let lowered = class_file
                .strings
                .iter()
                .map(|value| value.to_ascii_lowercase())
                .collect::<Vec<_>>();
            let store = first_marker_in(&lowered, CREDENTIAL_STORE_MARKERS)?;
            let webhook = first_marker_in(&lowered, WEBHOOK_MARKERS)?;
            Some(Finding {
                rule_id: CREDENTIAL_WEBHOOK_CO_LOCATION_RULE_ID.to_owned(),
                category: "credential_theft".to_owned(),
                kind: crate::models::scan::FindingKind::Finding,
                severity: Severity::Critical,
                confidence: Confidence::Medium,
                score_contribution: 80,
                scope: class_file.scope.clone(),
                message: "Класс содержит путь к хранилищу учётных данных и webhook-адрес для отправки данных. Статически не доказано, что отправка выполняется, но такая связка типична для стилера.".to_owned(),
                evidence: vec![Evidence {
                    archive_id: class_file.archive_id.clone(),
                    archive_path: class_file.archive_path.clone(),
                    class_name: class_file.class_name.clone(),
                    method_name: None,
                    method_descriptor: None,
                    bytecode_offset: None,
                    resource_path: Some(class_file.path.clone()),
                    operation: "credential_store_and_webhook_strings".to_owned(),
                    value_preview: Some(format!("{store}; {webhook}")),
                    source_value: None,
                    target_value: None,
                    confidence: Confidence::Medium,
                    scope: class_file.scope.clone(),
                }],
                related_chain_id: None,
            })
        })
}

/// Lowercase extensions of files that a process launcher can run directly.
const EXECUTABLE_URL_SUFFIXES: &[&str] = &[
    ".jar", ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".sh",
];

const PROCESS_LAUNCH_MARKERS: &[&str] = &["java/lang/ProcessBuilder", "java/lang/Runtime.exec"];

/// Flags a single class that holds an http(s) URL of an executable file, an HTTP client, and a
/// process launcher. The flow analysis confirms only download-write-exec chains, so a guarded
/// or write-less updater would otherwise score nothing; the co-location alone is not proof of
/// execution, hence suspicious rather than malicious.
fn executable_download_exec_co_location_finding(data: &ScanData) -> Option<Finding> {
    data.class_files.iter().find_map(|class_file| {
        let url = class_file
            .strings
            .iter()
            .find(|value| is_executable_url(value))?;
        let sink = first_class_marker_in_refs(&class_file.bytecode_refs, HTTP_SINK_MARKERS)?;
        let launcher = first_class_marker_in_refs(&class_file.bytecode_refs, PROCESS_LAUNCH_MARKERS)?;
        Some(Finding {
            rule_id: EXECUTABLE_DOWNLOAD_EXEC_CO_LOCATION_RULE_ID.to_owned(),
            category: "correlation".to_owned(),
            kind: crate::models::scan::FindingKind::Finding,
            severity: Severity::High,
            confidence: Confidence::Medium,
            score_contribution: 60,
            scope: class_file.scope.clone(),
            message: "Класс содержит адрес исполняемого файла, HTTP-клиент и запуск процесса. Статически не доказано, что скачанный файл запускается, но такая связка типична для загрузчика.".to_owned(),
            evidence: vec![Evidence {
                archive_id: class_file.archive_id.clone(),
                archive_path: class_file.archive_path.clone(),
                class_name: class_file.class_name.clone(),
                method_name: None,
                method_descriptor: None,
                bytecode_offset: None,
                resource_path: Some(class_file.path.clone()),
                operation: "executable_url_http_and_process_refs".to_owned(),
                value_preview: Some(format!("{url}; {sink}; {launcher}")),
                source_value: None,
                target_value: None,
                confidence: Confidence::Medium,
                scope: class_file.scope.clone(),
            }],
            related_chain_id: None,
        })
    })
}

fn is_executable_url(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    if !lowered.starts_with("http://") && !lowered.starts_with("https://") {
        return false;
    }
    let path = lowered.split(['?', '#']).next().unwrap_or_default();
    EXECUTABLE_URL_SUFFIXES
        .iter()
        .any(|suffix| path.ends_with(suffix))
}

/// Minecraft session (account token) or chat-event access that shares a class with an outbound
/// HTTP client is account theft: the transport is only reachable from the stolen data path.
/// Obfuscated call sites are invisible to direct call matching, so the class constant pool is used.
/// Session classes are listed for each mapping a production jar can carry: MCP (Forge <= 1.16),
/// Mojang (Forge/NeoForge 1.17+), and Fabric intermediary.
const SESSION_CHAT_SOURCE_MARKERS: &[&str] = &[
    "net/minecraft/util/Session",
    "net/minecraft/client/User",
    "net/minecraft/class_320",
    "net/minecraftforge/client/event/ClientChatEvent",
    "net/neoforged/neoforge/client/event/ClientChatEvent",
    "net/fabricmc/fabric/api/client/message/v1/ClientSendMessageEvents",
];

const HTTP_SINK_MARKERS: &[&str] = &[
    "java/net/URL",
    "java/net/HttpURLConnection",
    "javax/net/ssl/HttpsURLConnection",
    "java/net/http/HttpClient",
];

fn session_chat_exfil_co_location_finding(data: &ScanData) -> Option<Finding> {
    data.class_files.iter().find_map(|class_file| {
        let source =
            first_class_marker_in_refs(&class_file.bytecode_refs, SESSION_CHAT_SOURCE_MARKERS)?;
        let sink = first_class_marker_in_refs(&class_file.bytecode_refs, HTTP_SINK_MARKERS)?;
        Some(Finding {
            rule_id: SESSION_CHAT_EXFIL_CO_LOCATION_RULE_ID.to_owned(),
            category: "credential_theft".to_owned(),
            kind: crate::models::scan::FindingKind::Finding,
            severity: Severity::Critical,
            confidence: Confidence::Medium,
            score_contribution: 90,
            scope: class_file.scope.clone(),
            message: "Класс обращается к сессии аккаунта или к чату игры и к HTTP-клиенту. Это кража сессии/чата с отправкой по сети.".to_owned(),
            evidence: vec![Evidence {
                archive_id: class_file.archive_id.clone(),
                archive_path: class_file.archive_path.clone(),
                class_name: class_file.class_name.clone(),
                method_name: None,
                method_descriptor: None,
                bytecode_offset: None,
                resource_path: Some(class_file.path.clone()),
                operation: "session_or_chat_and_http_refs".to_owned(),
                value_preview: Some(format!("{source}; {sink}")),
                source_value: None,
                target_value: None,
                confidence: Confidence::Medium,
                scope: class_file.scope.clone(),
            }],
            related_chain_id: None,
        })
    })
}

/// Matches whole class names only: a bare class or member reference, or a type descriptor.
/// Plain substring matching would let `java/net/URL` match `java/net/URLEncoder`.
fn first_class_marker_in_refs(refs: &[String], markers: &[&'static str]) -> Option<&'static str> {
    markers.iter().copied().find(|marker| {
        let member_prefix = format!("{marker}.");
        let descriptor = format!("L{marker};");
        refs.iter().any(|value| {
            value == marker || value.starts_with(&member_prefix) || value.contains(&descriptor)
        })
    })
}

fn first_marker_in(values: &[String], markers: &[&'static str]) -> Option<&'static str> {
    markers
        .iter()
        .copied()
        .find(|marker| values.iter().any(|value| value.contains(marker)))
}

fn has_privacy_network_sync(data: &ScanData) -> bool {
    let has_xor_decode = data
        .archive_signals
        .iter()
        .any(|signal| signal == "xor_loop_string_decode");
    if !has_xor_decode {
        return false;
    }

    let has_auth_header = scoped_text_contains_any(data, &["authorization", "bearer"]);
    let has_network = refs_contain_any(&data.first_party_bytecode_refs, NETWORK_APIS)
        || scoped_text_contains_any(data, &["wss://", "ws://", "https://", "http://"]);
    let identifier_hits = ["uuid", "username", "server_address", "channel", "minecraft"]
        .iter()
        .filter(|pattern| scoped_text_contains(data, pattern))
        .count();

    has_auth_header && has_network && identifier_hits >= 2
}

fn scoped_text_contains_any(data: &ScanData, patterns: &[&str]) -> bool {
    patterns
        .iter()
        .any(|pattern| scoped_text_contains(data, pattern))
}

fn scoped_text_contains(data: &ScanData, pattern: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    data.first_party_strings
        .iter()
        .chain(data.first_party_bytecode_refs.iter())
        .any(|candidate| candidate.to_ascii_lowercase().contains(&pattern))
}

/// Translates first-party method summaries into the bounded, parser-independent data-flow model.
fn analyze_scan_data_flow(data: &ScanData) -> crate::scanner::dataflow::DataFlowResult {
    let flows = data
        .class_files
        .iter()
        .flat_map(|class_file| {
            class_file
                .methods
                .iter()
                .map(|method| method_flow_from_scan_data(class_file, method))
        })
        .collect::<Vec<_>>();
    let config = DataFlowConfig::default();
    let roots = dangerous_flow_roots(&flows, config.max_interprocedural_depth);
    let mut result = analyze_method_flows_from_roots(&flows, &roots, &config);
    for class_file in &data.class_files {
        if !matches!(
            class_file.scope,
            CodeScope::FirstParty | CodeScope::NestedMod | CodeScope::Unknown
        ) {
            continue;
        }
        for method in &class_file.methods {
            let method_id = MethodId {
                archive_id: class_file.archive_id.clone(),
                class_name: method.class_name.clone(),
                method_name: method.method_name.clone(),
                descriptor: method.descriptor.clone(),
            };
            if !result.analyzed_method_ids.contains(&method_id) {
                continue;
            }
            for instruction in &method.instructions {
                if !is_flow_supported_instruction(instruction.opcode) {
                    result
                        .limitations
                        .push(FlowLimitation::UnsupportedInstruction {
                            method: method_id.clone(),
                            offset: instruction.offset,
                            opcode: instruction.opcode,
                        });
                }
            }
            if !method.control_flow_edges.is_empty() {
                result
                    .limitations
                    .push(FlowLimitation::LinearControlFlow { method: method_id });
            }
        }
    }
    result
}

fn method_flow_from_scan_data(class_file: &ClassScanData, method: &MethodScanData) -> MethodFlow {
    let id = MethodId {
        archive_id: class_file.archive_id.clone(),
        class_name: method.class_name.clone(),
        method_name: method.method_name.clone(),
        descriptor: method.descriptor.clone(),
    };
    let mut events = Vec::new();
    let mut object_targets = HashMap::<String, FileTarget>::new();
    let mut process_builders = HashMap::<String, Vec<FileTarget>>::new();
    let mut list_commands = HashMap::<String, Vec<FileTarget>>::new();
    let mut http_output_streams = HashSet::<String>::new();

    for record in &method.local_origins {
        if let Some(input) = local_for_origin(method, &record.origin) {
            if input != record.local_index {
                events.push((
                    record.offset,
                    Operation::Copy {
                        input,
                        output: record.local_index,
                    },
                ));
            }
        }
    }
    for call in &method.calls {
        let Some(owner) = call.owner.as_deref() else {
            continue;
        };
        let evidence = flow_evidence(class_file, &id, call.offset, owner, &call.name);
        let output = call
            .result_origin
            .as_ref()
            .and_then(|origin| local_for_origin(method, origin));
        let arguments = call
            .argument_origins
            .iter()
            .filter_map(|origin| local_for_origin(method, origin))
            .collect::<Vec<_>>();

        if is_path_factory(owner, &call.name) {
            if let (Some(result), Some(target)) = (
                &call.result_origin,
                path_factory_target(call, &object_targets),
            ) {
                object_targets.insert(object_key(result), target);
            }
            continue;
        }
        if is_path_resolution(owner, &call.name) {
            if let (Some(result), Some(receiver), Some(child)) = (
                &call.result_origin,
                &call.receiver_origin,
                call.argument_origins
                    .first()
                    .and_then(|origin| target_from_origin(origin, &object_targets)),
            ) {
                if let Some(parent) = target_from_origin(receiver, &object_targets) {
                    object_targets.insert(
                        object_key(result),
                        resolve_path_target(parent, child, call.name.as_str()),
                    );
                }
            }
            continue;
        }
        if is_path_conversion(owner, &call.name) {
            if let (Some(result), Some(receiver)) = (&call.result_origin, &call.receiver_origin) {
                if let Some(target) = target_from_origin(receiver, &object_targets) {
                    object_targets.insert(object_key(result), target);
                }
            }
            continue;
        }
        if is_list_factory(owner, &call.name) {
            if let Some(result) = &call.result_origin {
                if let Some(command) = command_from_origins(
                    &call.argument_origins,
                    method,
                    &object_targets,
                    &list_commands,
                ) {
                    list_commands.insert(object_key(result), command);
                }
            }
            continue;
        }
        if is_mutable_list_constructor(owner, &call.name) {
            if let Some(receiver) = &call.receiver_origin {
                list_commands.entry(object_key(receiver)).or_default();
            }
            continue;
        }
        if is_list_append(owner, &call.name) {
            if let Some(receiver) = &call.receiver_origin {
                if let Some(command) = command_from_origins(
                    &call.argument_origins,
                    method,
                    &object_targets,
                    &list_commands,
                ) {
                    list_commands
                        .entry(object_key(receiver))
                        .or_default()
                        .extend(command);
                }
            }
            continue;
        }
        if owner == "java/lang/ProcessBuilder" && call.name == "<init>" {
            if let Some(receiver) = &call.receiver_origin {
                if let Some(command) = command_from_origins(
                    &call.argument_origins,
                    method,
                    &object_targets,
                    &list_commands,
                ) {
                    process_builders.insert(object_key(receiver), command);
                }
            }
            continue;
        }
        if owner == "java/lang/ProcessBuilder" && call.name == "command" {
            if let Some(receiver) = &call.receiver_origin {
                if let Some(command) = command_from_origins(
                    &call.argument_origins,
                    method,
                    &object_targets,
                    &list_commands,
                ) {
                    process_builders.insert(object_key(receiver), command);
                }
            }
            continue;
        }
        if owner == "java/lang/ProcessBuilder" && call.name == "start" {
            let target = call
                .receiver_origin
                .as_ref()
                .and_then(|origin| process_builders.get(&object_key(origin)))
                .and_then(|command| executable_target(command))
                .unwrap_or(FileTarget::Unknown);
            let mut evidence = evidence;
            evidence.target_value = known_target_value(&target);
            events.push((call.offset, Operation::ExecuteFile { target, evidence }));
            continue;
        }

        if is_authentication_chat_message(owner, &call.name)
            && class_handles_authentication_commands(class_file)
        {
            if let Some(output) = output {
                let mut evidence = evidence;
                evidence.source_value = Some("Minecraft authentication chat command".to_owned());
                events.push((
                    call.offset,
                    Operation::Source {
                        output,
                        kind: SourceKind::ChatCredential,
                        evidence,
                    },
                ));
            }
            continue;
        }
        if is_java_http_client_send(owner, &call.name) {
            if let Some(body) = arguments.first().copied() {
                events.push((
                    call.offset,
                    Operation::NetworkSend {
                        body,
                        evidence: evidence.clone(),
                    },
                ));
            }
            if let Some(output) = output {
                events.push((
                    call.offset,
                    Operation::Source {
                        output,
                        kind: SourceKind::HttpResponse,
                        evidence,
                    },
                ));
            }
            continue;
        }
        if let Some(kind) = remote_response_kind(owner, &call.name) {
            if let Some(output) = output {
                events.push((
                    call.offset,
                    Operation::Source {
                        output,
                        kind,
                        evidence,
                    },
                ));
            }
            continue;
        }
        if is_file_read(owner, &call.name) {
            if let Some(output) = output {
                let mut evidence = evidence;
                let source = call
                    .argument_origins
                    .first()
                    .and_then(|origin| target_from_origin(origin, &object_targets));
                evidence.source_value = source.as_ref().and_then(known_target_value);
                let kind = source
                    .as_ref()
                    .is_some_and(is_credential_target)
                    .then_some(SourceKind::CredentialFile)
                    .unwrap_or(SourceKind::FileRead);
                events.push((
                    call.offset,
                    Operation::Source {
                        output,
                        kind,
                        evidence,
                    },
                ));
            }
            continue;
        }
        if is_http_output_stream(owner, &call.name) {
            if let Some(result) = &call.result_origin {
                http_output_streams.insert(object_key(result));
                if let Some(local) = output {
                    http_output_streams.insert(object_key(&ValueOrigin::Local(local)));
                }
            }
            continue;
        }
        if is_http_output_write(
            owner,
            &call.name,
            call.receiver_origin.as_ref(),
            &http_output_streams,
        ) {
            if let Some(body) = arguments.first().copied() {
                events.push((call.offset, Operation::NetworkSend { body, evidence }));
            }
            continue;
        }
        if is_base64_decode(owner, &call.name) {
            if let (Some(input), Some(output)) = (arguments.last().copied(), output) {
                events.push((
                    call.offset,
                    Operation::Transform {
                        input,
                        output,
                        kind: TransformKind::Base64Decode,
                        evidence,
                    },
                ));
            }
            continue;
        }
        if is_secret_extraction(owner, &call.name, &call.argument_origins) {
            if let (Some(input), Some(output)) = (arguments.last().copied(), output) {
                events.push((
                    call.offset,
                    Operation::Transform {
                        input,
                        output,
                        kind: TransformKind::SecretExtract,
                        evidence,
                    },
                ));
            }
            continue;
        }
        if is_file_write(owner, &call.name) {
            if let Some(input) = arguments.last().copied() {
                let destination = call
                    .argument_origins
                    .first()
                    .and_then(|origin| target_from_origin(origin, &object_targets))
                    .unwrap_or(FileTarget::Unknown);
                let mut evidence = evidence;
                evidence.target_value = match &destination {
                    FileTarget::Known(value) => Some(value.clone()),
                    FileTarget::Unknown => None,
                };
                events.push((
                    call.offset,
                    Operation::WriteFile {
                        input,
                        destination,
                        evidence,
                    },
                ));
            }
            continue;
        }
        if is_process_execution(owner, &call.name) {
            let target = call
                .argument_origins
                .first()
                .and_then(|origin| {
                    command_from_origins(
                        std::slice::from_ref(origin),
                        method,
                        &object_targets,
                        &list_commands,
                    )
                    .and_then(|command| executable_target(&command))
                    .or_else(|| target_from_origin(origin, &object_targets))
                })
                .unwrap_or(FileTarget::Unknown);
            let mut evidence = evidence;
            evidence.target_value = match &target {
                FileTarget::Known(value) => Some(value.clone()),
                FileTarget::Unknown => None,
            };
            events.push((call.offset, Operation::ExecuteFile { target, evidence }));
            continue;
        }
        if is_http_send(owner, &call.name) {
            if let Some(body) = arguments.last().copied() {
                events.push((call.offset, Operation::NetworkSend { body, evidence }));
            }
            continue;
        }
        if is_dynamic_load(owner, &call.name) {
            if let Some(input) = arguments.first().copied() {
                let target = call
                    .argument_origins
                    .first()
                    .and_then(|origin| target_from_origin(origin, &object_targets));
                let mut evidence = evidence;
                evidence.target_value = target.as_ref().and_then(known_target_value);
                events.push((
                    call.offset,
                    Operation::DynamicLoad {
                        input,
                        kind: crate::scanner::dataflow::DynamicLoadKind::ClassDefinition,
                        evidence,
                    },
                ));
            }
            continue;
        }
        if !owner.starts_with("java/") && !owner.starts_with("javax/") {
            let callee = MethodId {
                archive_id: class_file.archive_id.clone(),
                class_name: owner.to_owned(),
                method_name: call.name.clone(),
                descriptor: call.descriptor.clone(),
            };
            events.push((
                call.offset,
                Operation::Call {
                    callee,
                    arguments,
                    return_to: output,
                    evidence,
                },
            ));
        }
    }
    for verification in integrity_verifications(class_file, method, &id) {
        events.push((
            verification.offset,
            Operation::IntegrityVerify {
                input: verification.input,
                evidence: verification.evidence,
            },
        ));
    }
    for returned in &method.return_origins {
        events.push((
            returned.offset,
            Operation::Return {
                value: returned
                    .value_origin
                    .as_ref()
                    .and_then(|origin| local_for_origin(method, origin)),
            },
        ));
    }
    events.sort_by_key(|(offset, _)| *offset);
    let operations = events.into_iter().map(|(_, operation)| operation).collect();
    MethodFlow {
        id,
        parameter_count: class_file::descriptor_shape(&method.descriptor)
            .map(|(count, _)| count as u16)
            .unwrap_or(0),
        parameter_slots: parameter_slots(method),
        scope: class_file.scope.clone(),
        operations,
    }
}

fn parameter_slots(method: &MethodScanData) -> Vec<u16> {
    let bytes = method.descriptor.as_bytes();
    if bytes.first() != Some(&b'(') {
        return Vec::new();
    }
    let mut slots = Vec::new();
    let mut index = 1;
    let mut slot = u16::from(!method.is_static);
    while bytes.get(index) != Some(&b')') {
        slots.push(slot);
        let start = index;
        while bytes.get(index) == Some(&b'[') {
            index += 1;
        }
        let width = match bytes.get(index) {
            Some(b'L') => {
                while bytes.get(index) != Some(&b';') {
                    index += 1;
                }
                index += 1;
                1
            }
            Some(b'J' | b'D') => {
                index += 1;
                2
            }
            Some(_) => {
                index += 1;
                1
            }
            None => return Vec::new(),
        };
        if start == index {
            return Vec::new();
        }
        slot = slot.saturating_add(width);
    }
    slots
}

fn local_for_origin(method: &MethodScanData, origin: &ValueOrigin) -> Option<u16> {
    if let ValueOrigin::Local(local) = origin {
        return Some(*local);
    }
    method
        .local_origins
        .iter()
        .rev()
        .find(|record| &record.origin == origin)
        .map(|record| record.local_index)
}

fn file_target_from_origin(origin: &ValueOrigin) -> Option<FileTarget> {
    match origin {
        ValueOrigin::Constant(ConstantValue::String(value)) => {
            let normalized = paths::normalize_symbolic_path(value)
                .map(|path| path.canonical)
                .unwrap_or_else(|| value.replace('\\', "/"));
            Some(FileTarget::Known(normalized))
        }
        _ => None,
    }
}

fn target_from_origin(
    origin: &ValueOrigin,
    object_targets: &HashMap<String, FileTarget>,
) -> Option<FileTarget> {
    file_target_from_origin(origin).or_else(|| object_targets.get(&object_key(origin)).cloned())
}

fn object_key(origin: &ValueOrigin) -> String {
    match origin {
        ValueOrigin::Instruction(offset) => format!("instruction:{offset}"),
        ValueOrigin::Local(index) => format!("local:{index}"),
        ValueOrigin::Field { owner, name, .. } => format!("field:{owner}.{name}"),
        ValueOrigin::Constant(value) => format!("constant:{value:?}"),
        ValueOrigin::Unknown => "unknown".to_owned(),
    }
}

fn known_target_value(target: &FileTarget) -> Option<String> {
    match target {
        FileTarget::Known(value) => Some(value.clone()),
        FileTarget::Unknown => None,
    }
}

fn is_path_factory(owner: &str, name: &str) -> bool {
    (owner == "java/nio/file/Paths" && name == "get")
        || (owner == "java/nio/file/Path" && name == "of")
        || (owner == "java/io/File" && name == "<init>")
}

fn path_factory_target(
    call: &class_file::CallSite,
    object_targets: &HashMap<String, FileTarget>,
) -> Option<FileTarget> {
    let mut arguments = call
        .argument_origins
        .iter()
        .filter_map(|origin| target_from_origin(origin, object_targets));
    let first = arguments.next()?;
    let second = arguments.next();
    Some(match second {
        Some(child) if call.owner.as_deref() == Some("java/io/File") => {
            resolve_path_target(first, child, "resolve")
        }
        _ => first,
    })
}

fn is_path_resolution(owner: &str, name: &str) -> bool {
    owner == "java/nio/file/Path" && matches!(name, "resolve" | "resolveSibling")
}

fn resolve_path_target(parent: FileTarget, child: FileTarget, operation: &str) -> FileTarget {
    let (FileTarget::Known(parent), FileTarget::Known(child)) = (parent, child) else {
        return FileTarget::Unknown;
    };
    let value = if operation == "resolveSibling" {
        parent
            .rsplit_once('/')
            .map(|(base, _)| format!("{base}/{child}"))
            .unwrap_or(child)
    } else {
        format!(
            "{}/{}",
            parent.trim_end_matches('/'),
            child.trim_start_matches('/')
        )
    };
    FileTarget::Known(
        paths::normalize_symbolic_path(&value)
            .map(|path| path.canonical)
            .unwrap_or(value),
    )
}

fn is_path_conversion(owner: &str, name: &str) -> bool {
    (owner == "java/nio/file/Path" && matches!(name, "toString" | "toFile"))
        || (owner == "java/io/File" && matches!(name, "toString" | "toPath"))
}

fn is_list_factory(owner: &str, name: &str) -> bool {
    (owner == "java/util/List" && matches!(name, "of" | "copyOf"))
        || (owner == "java/util/Arrays" && name == "asList")
}

fn is_mutable_list_constructor(owner: &str, name: &str) -> bool {
    owner == "java/util/ArrayList" && name == "<init>"
}

fn is_list_append(owner: &str, name: &str) -> bool {
    matches!(owner, "java/util/List" | "java/util/ArrayList") && name == "add"
}

fn command_from_origins(
    origins: &[ValueOrigin],
    method: &MethodScanData,
    object_targets: &HashMap<String, FileTarget>,
    list_commands: &HashMap<String, Vec<FileTarget>>,
) -> Option<Vec<FileTarget>> {
    let mut command = Vec::new();
    for origin in origins {
        let parts = command_from_origin(origin, method, object_targets, list_commands)?;
        command.extend(parts);
    }
    (!command.is_empty()).then_some(command)
}

fn command_from_origin(
    origin: &ValueOrigin,
    method: &MethodScanData,
    object_targets: &HashMap<String, FileTarget>,
    list_commands: &HashMap<String, Vec<FileTarget>>,
) -> Option<Vec<FileTarget>> {
    if let Some(command) = list_commands.get(&object_key(origin)) {
        return Some(command.clone());
    }
    let elements = method
        .array_elements
        .iter()
        .filter(|element| element.array_origin == *origin)
        .collect::<Vec<_>>();
    if !elements.is_empty() {
        let mut ordered = elements;
        ordered.sort_by_key(|element| element.index);
        return ordered
            .into_iter()
            .map(|element| target_from_origin(&element.value_origin, object_targets))
            .collect();
    }
    target_from_origin(origin, object_targets).map(|target| match &target {
        FileTarget::Known(value) if value.split_ascii_whitespace().count() > 1 => value
            .split_ascii_whitespace()
            .map(|part| FileTarget::Known(part.to_owned()))
            .collect(),
        _ => vec![target],
    })
}

fn executable_target(command: &[FileTarget]) -> Option<FileTarget> {
    let values = command
        .iter()
        .map(known_target_value)
        .collect::<Option<Vec<_>>>()?;
    let executable = values.first()?.to_ascii_lowercase();
    let target_index = match executable.as_str() {
        "java" | "java.exe" if values.get(1).is_some_and(|value| value == "-jar") => 2,
        "cmd" | "cmd.exe"
            if values
                .get(1)
                .is_some_and(|value| value.eq_ignore_ascii_case("/c")) =>
        {
            2
        }
        "sh" | "bash" => 1,
        "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe" => values.len().checked_sub(1)?,
        _ => return None,
    };
    command.get(target_index).cloned()
}

fn flow_evidence(
    class_file: &ClassScanData,
    method: &MethodId,
    offset: u32,
    owner: &str,
    name: &str,
) -> FlowEvidence {
    FlowEvidence {
        archive_id: class_file.archive_id.clone(),
        archive_path: class_file.archive_path.clone(),
        class_name: method.class_name.clone(),
        method_name: method.method_name.clone(),
        method_descriptor: method.descriptor.clone(),
        bytecode_offset: offset,
        operation: format!("{owner}.{name}"),
        value_preview: None,
        source_value: None,
        target_value: None,
        scope: class_file.scope.clone(),
    }
}

fn remote_response_kind(owner: &str, name: &str) -> Option<SourceKind> {
    if owner.contains("HttpClient") && matches!(name, "send" | "execute" | "get") {
        return Some(SourceKind::HttpResponse);
    }
    ((owner.contains("WebSocket") || owner.contains("Websocket"))
        && matches!(name, "receive" | "readMessage" | "sendAndWaitForResponse"))
    .then_some(SourceKind::SocketInput)
}

const AUTHENTICATION_COMMAND_PREFIXES: &[&str] = &[
    "/l",
    "/login",
    "/log",
    "/reg",
    "/register",
    "/registration",
    "/changepass",
    "/changepassword",
    "/change-password",
    "/pass",
    "/password",
    "/auth",
    "/authorize",
    "/signin",
    "/sign-in",
];

fn is_authentication_chat_message(owner: &str, name: &str) -> bool {
    owner == "net/minecraftforge/client/event/ClientChatEvent"
        && matches!(name, "getMessage" | "getMessageString")
}

fn class_handles_authentication_commands(class_file: &ClassScanData) -> bool {
    class_file
        .strings
        .iter()
        .chain(class_file.methods.iter().flat_map(|method| {
            method
                .constants
                .iter()
                .filter_map(|constant| match &constant.value {
                    ConstantValue::String(value) => Some(value),
                    _ => None,
                })
        }))
        .any(|value| is_authentication_command_prefix(value))
}

fn is_authentication_command_prefix(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    AUTHENTICATION_COMMAND_PREFIXES.iter().any(|prefix| {
        normalized == *prefix
            || normalized
                .strip_prefix(prefix)
                .and_then(|suffix| suffix.chars().next())
                .is_some_and(char::is_whitespace)
    })
}

fn is_http_output_stream(owner: &str, name: &str) -> bool {
    matches!(
        owner,
        "java/net/HttpURLConnection" | "javax/net/ssl/HttpsURLConnection"
    ) && name == "getOutputStream"
}

fn is_http_output_write(
    owner: &str,
    name: &str,
    receiver: Option<&ValueOrigin>,
    http_output_streams: &HashSet<String>,
) -> bool {
    owner == "java/io/OutputStream"
        && name == "write"
        && receiver.is_some_and(|origin| http_output_streams.contains(&object_key(origin)))
}

fn is_file_read(owner: &str, name: &str) -> bool {
    (owner == "java/nio/file/Files" && matches!(name, "readAllBytes" | "readString"))
        || (owner.contains("InputStream") && name == "read")
}

fn is_credential_target(target: &FileTarget) -> bool {
    let FileTarget::Known(value) = target else {
        return false;
    };
    let value = value.to_ascii_lowercase().replace('\\', "/");
    let discord = value.contains("discord/local storage/leveldb")
        || value.contains("discordcanary/local storage/leveldb")
        || value.contains("discordptb/local storage/leveldb");
    let chromium = value.contains("/user data/")
        && [
            "/login data",
            "/network/cookies",
            "/cookies",
            "/local state",
            "/local storage/leveldb",
        ]
        .iter()
        .any(|suffix| value.ends_with(suffix) || value.contains(&format!("{suffix}/")));
    let firefox = value.contains("mozilla/firefox/")
        && ["/logins.json", "/key4.db", "/cookies.sqlite"]
            .iter()
            .any(|suffix| value.ends_with(suffix));
    let minecraft = value.ends_with("minecraft/launcher_accounts.json")
        || value.ends_with(".minecraft/launcher_accounts.json");
    let telegram = value.contains("telegram desktop/tdata/") || value.ends_with("telegram/tdata");
    let wallet = [
        "/exodus/exodus.wallet",
        "/electrum/wallets/",
        "/atomic/wallets/",
        "/metamask/local extension settings/",
    ]
    .iter()
    .any(|needle| value.contains(needle));
    discord || chromium || firefox || minecraft || telegram || wallet
}

fn is_secret_extraction(owner: &str, name: &str, arguments: &[ValueOrigin]) -> bool {
    if !matches!(
        name,
        "getString" | "get" | "group" | "decrypt" | "unprotect"
    ) {
        return false;
    }
    let structured_parser = owner.contains("json")
        || owner.contains("gson")
        || owner.contains("jackson")
        || owner.contains("sql")
        || owner.contains("crypt");
    if !structured_parser {
        return false;
    }
    arguments.iter().any(|origin| {
        matches!(
            origin,
            ValueOrigin::Constant(ConstantValue::String(value))
                if matches!(value.to_ascii_lowercase().as_str(), "token" | "password" | "cookie" | "encrypted_key" | "authorization")
        )
    })
}

fn is_base64_decode(owner: &str, name: &str) -> bool {
    (owner.contains("Base64") || owner.contains("Decoder")) && name == "decode"
}

fn is_file_write(owner: &str, name: &str) -> bool {
    (owner == "java/nio/file/Files" && matches!(name, "write" | "writeString"))
        || owner == "java/io/FileOutputStream" && name == "write"
}

fn is_process_execution(owner: &str, name: &str) -> bool {
    (owner == "java/lang/Runtime" && name == "exec")
        || (owner == "java/lang/ProcessBuilder" && name == "start")
}

fn is_http_send(owner: &str, name: &str) -> bool {
    owner.contains("HttpClient") && matches!(name, "post" | "send" | "sendAsync" | "execute")
}

fn is_java_http_client_send(owner: &str, name: &str) -> bool {
    owner == "java/net/http/HttpClient" && matches!(name, "send" | "sendAsync")
}

fn is_dynamic_load(owner: &str, name: &str) -> bool {
    (name == "defineClass" && (owner.contains("ClassLoader") || !owner.starts_with("java/")))
        || (owner == "java/lang/System" && matches!(name, "load" | "loadLibrary"))
}

struct IntegrityVerificationFlow {
    offset: u32,
    input: u16,
    evidence: Vec<FlowEvidence>,
}

fn integrity_verifications(
    class_file: &ClassScanData,
    method: &MethodScanData,
    method_id: &MethodId,
) -> Vec<IntegrityVerificationFlow> {
    let mut verifications = Vec::new();
    for comparison in &method.calls {
        let Some(result) = comparison.result_origin.as_ref() else {
            continue;
        };
        let Some(branch) = method.branch_conditions.iter().find(|branch| {
            branch.value_origin == *result && branch_rejects_one_side(method, branch.offset)
        }) else {
            continue;
        };
        let Some((input_origin, mut evidence)) =
            integrity_input_for_comparison(class_file, method, method_id, comparison)
        else {
            continue;
        };
        let Some(input) = local_for_origin(method, &input_origin) else {
            continue;
        };
        evidence.push(FlowEvidence::for_method(
            method_id,
            branch.offset,
            "integrity_success_branch",
        ));
        verifications.push(IntegrityVerificationFlow {
            offset: branch.offset,
            input,
            evidence,
        });
    }
    verifications
}

fn integrity_input_for_comparison(
    class_file: &ClassScanData,
    method: &MethodScanData,
    method_id: &MethodId,
    comparison: &class_file::CallSite,
) -> Option<(ValueOrigin, Vec<FlowEvidence>)> {
    let owner = comparison.owner.as_deref()?;
    if owner == "java/security/Signature" && comparison.name == "verify" {
        let receiver = comparison.receiver_origin.as_ref()?;
        let input = method.calls.iter().rev().find_map(|call| {
            (call.offset < comparison.offset
                && call.owner.as_deref() == Some("java/security/Signature")
                && call.name == "update"
                && call.receiver_origin.as_ref() == Some(receiver))
            .then(|| call.argument_origins.first().cloned())
            .flatten()
        })?;
        let has_trusted_key = method.calls.iter().any(|call| {
            call.offset < comparison.offset
                && call.owner.as_deref() == Some("java/security/Signature")
                && call.name == "initVerify"
                && call.receiver_origin.as_ref() == Some(receiver)
        });
        if has_trusted_key {
            return Some((
                input,
                vec![flow_evidence(
                    class_file,
                    method_id,
                    comparison.offset,
                    "java/security/Signature",
                    "verify",
                )],
            ));
        }
    }
    let actual = if owner == "java/util/Arrays" && comparison.name == "equals" {
        comparison.argument_origins.iter().find_map(|origin| {
            digest_input_from_origin(method, origin).map(|value| (origin, value))
        })?
    } else if owner == "java/lang/String" && comparison.name == "equals" {
        let mut values = comparison
            .receiver_origin
            .iter()
            .chain(comparison.argument_origins.iter());
        values.find_map(|origin| {
            digest_input_from_origin(method, origin).map(|value| (origin, value))
        })?
    } else {
        return None;
    };
    let expected_is_separate = comparison
        .argument_origins
        .iter()
        .chain(comparison.receiver_origin.iter())
        .any(|origin| origin != actual.0 && !origin_depends_on(method, origin, &actual.1));
    expected_is_separate.then(|| {
        let mut evidence = method
            .calls
            .iter()
            .filter(|call| {
                call.owner.as_deref() == Some("java/security/MessageDigest")
                    && call.name == "digest"
                    && call.argument_origins.first() == Some(&actual.1)
            })
            .map(|call| {
                flow_evidence(
                    class_file,
                    method_id,
                    call.offset,
                    "java/security/MessageDigest",
                    "digest",
                )
            })
            .collect::<Vec<_>>();
        evidence.push(flow_evidence(
            class_file,
            method_id,
            comparison.offset,
            owner,
            &comparison.name,
        ));
        (actual.1, evidence)
    })
}

fn digest_input_from_origin(method: &MethodScanData, origin: &ValueOrigin) -> Option<ValueOrigin> {
    let call = method
        .calls
        .iter()
        .find(|call| call.result_origin.as_ref() == Some(origin))?;
    let owner = call.owner.as_deref()?;
    if owner == "java/security/MessageDigest" && call.name == "digest" {
        let receiver = call.receiver_origin.as_ref()?;
        let sha256 = method.calls.iter().any(|candidate| {
            candidate.owner.as_deref() == Some("java/security/MessageDigest")
                && candidate.name == "getInstance"
                && candidate.result_origin.as_ref() == Some(receiver)
                && candidate.argument_origins.iter().any(|argument| {
                    matches!(argument, ValueOrigin::Constant(ConstantValue::String(value)) if value.eq_ignore_ascii_case("SHA-256"))
                })
        });
        return sha256
            .then(|| call.argument_origins.first().cloned())
            .flatten();
    }
    if (owner == "java/util/HexFormat" && call.name == "formatHex")
        || ((owner.contains("Base64") || owner.contains("Encoder"))
            && matches!(call.name.as_str(), "encodeToString" | "encode"))
    {
        return call
            .argument_origins
            .first()
            .and_then(|argument| digest_input_from_origin(method, argument));
    }
    None
}

fn origin_depends_on(method: &MethodScanData, origin: &ValueOrigin, source: &ValueOrigin) -> bool {
    if origin == source {
        return true;
    }
    method
        .calls
        .iter()
        .find(|call| call.result_origin.as_ref() == Some(origin))
        .is_some_and(|call| {
            call.argument_origins
                .iter()
                .any(|argument| origin_depends_on(method, argument, source))
        })
}

fn branch_rejects_one_side(method: &MethodScanData, branch_offset: u32) -> bool {
    let Some(index) = method
        .instructions
        .iter()
        .position(|instruction| instruction.offset == branch_offset)
    else {
        return false;
    };
    let instruction = &method.instructions[index];
    let target = match instruction.operands.as_slice() {
        [high, low, ..] => branch_offset as i64 + i64::from(i16::from_be_bytes([*high, *low])),
        _ => return false,
    };
    immediately_rejects(method, index + 1)
        || method
            .instructions
            .iter()
            .position(|candidate| candidate.offset == target as u32)
            .is_some_and(|target_index| immediately_rejects(method, target_index))
}

fn immediately_rejects(method: &MethodScanData, start: usize) -> bool {
    method
        .instructions
        .iter()
        .skip(start)
        .take(12)
        .any(|instruction| matches!(instruction.opcode, 0xac..=0xb1 | 0xbf))
}

fn confirmed_chain_from_candidate(candidate: &ConfirmedChainCandidate) -> ConfirmedChain {
    let (rule_id, severity, score_contribution) = match candidate.kind {
        ConfirmedChainKind::DownloadWriteExecute => (
            "CONFIRMED_DOWNLOAD_WRITE_EXEC".to_owned(),
            Severity::Critical,
            70,
        ),
        ConfirmedChainKind::CredentialExfiltration => (
            "CONFIRMED_CREDENTIAL_EXFILTRATION".to_owned(),
            Severity::Critical,
            90,
        ),
        ConfirmedChainKind::DecodedDynamicLoad => (
            "CONFIRMED_DECODED_DYNAMIC_LOAD".to_owned(),
            Severity::High,
            60,
        ),
        ConfirmedChainKind::RemoteDynamicLoad => (
            "CONFIRMED_REMOTE_DYNAMIC_LOAD".to_owned(),
            Severity::Critical,
            80,
        ),
        ConfirmedChainKind::IntegrityVerifiedDownloadWriteExecute => (
            "CONFIRMED_INTEGRITY_VERIFIED_UPDATER".to_owned(),
            Severity::Low,
            0,
        ),
    };
    let evidence = std::iter::once(&candidate.source)
        .chain(candidate.transformations.iter())
        .chain(candidate.operations.iter())
        .map(|flow| Evidence {
            archive_id: flow.archive_id.clone(),
            archive_path: flow.archive_path.clone(),
            class_name: Some(flow.class_name.clone()),
            method_name: Some(flow.method_name.clone()),
            method_descriptor: Some(flow.method_descriptor.clone()),
            bytecode_offset: Some(flow.bytecode_offset),
            resource_path: None,
            operation: flow.operation.clone(),
            value_preview: flow.value_preview.clone(),
            source_value: flow.source_value.clone(),
            target_value: flow.target_value.clone(),
            confidence: Confidence::High,
            scope: flow.scope.clone(),
        })
        .collect();
    ConfirmedChain {
        chain_id: candidate.chain_id.clone(),
        rule_id,
        severity,
        confidence: Confidence::High,
        score_contribution,
        operations: candidate
            .operations
            .iter()
            .map(|operation| operation.operation.clone())
            .collect(),
        evidence,
    }
}

/// Confirms a staged in-memory loader only when one first-party component links
/// a network client, `JarInputStream`, and a custom `loadClass` implementation.
/// This avoids treating a bundled class loader or a network client alone as malware.
fn confirmed_remote_memory_load(data: &ScanData) -> Option<ConfirmedChain> {
    let first_party = data
        .class_files
        .iter()
        .filter(|class_file| class_file.scope == CodeScope::FirstParty)
        .collect::<Vec<_>>();
    let network_classes = first_party
        .iter()
        .filter(|class_file| refs_contain_any(&class_file.bytecode_refs, NETWORK_APIS))
        .filter_map(|class_file| class_file.class_name.as_deref())
        .collect::<HashSet<_>>();
    let loader_classes = first_party
        .iter()
        .filter(|class_file| {
            class_file
                .methods
                .iter()
                .any(|method| method.calls.iter().any(|call| call.name == "defineClass"))
        })
        .filter_map(|class_file| class_file.class_name.as_deref())
        .collect::<HashSet<_>>();

    for staging_class in &first_party {
        let has_jar_input = refs_contain_any(
            &staging_class.bytecode_refs,
            &["java/util/jar/JarInputStream"],
        );
        if !has_jar_input {
            continue;
        }
        let network_call = staging_class.methods.iter().find_map(|method| {
            method.calls.iter().find_map(|call| {
                call.owner
                    .as_deref()
                    .filter(|owner| network_classes.contains(owner))
                    .map(|_| (method, call))
            })
        })?;
        let loader_call = staging_class.methods.iter().find_map(|method| {
            method.calls.iter().find_map(|call| {
                call.owner
                    .as_deref()
                    .filter(|owner| loader_classes.contains(owner) && call.name == "loadClass")
                    .map(|_| (method, call))
            })
        })?;
        let jar_call = staging_class
            .methods
            .iter()
            .flat_map(|method| {
                method.calls.iter().filter_map(move |call| {
                    (call.owner.as_deref() == Some("java/util/jar/JarInputStream"))
                        .then_some((method, call))
                })
            })
            .next()?;
        let loader_class_name = loader_call.1.owner.as_deref()?;
        let loader_class = first_party
            .iter()
            .copied()
            .find(|class_file| class_file.class_name.as_deref() == Some(loader_class_name))?;
        let define_call = loader_class
            .methods
            .iter()
            .flat_map(|method| {
                method
                    .calls
                    .iter()
                    .filter_map(move |call| (call.name == "defineClass").then_some((method, call)))
            })
            .next()?;

        let network_evidence = flow_evidence(
            staging_class,
            &MethodId {
                archive_id: staging_class.archive_id.clone(),
                class_name: network_call.0.class_name.clone(),
                method_name: network_call.0.method_name.clone(),
                descriptor: network_call.0.descriptor.clone(),
            },
            network_call.1.offset,
            network_call.1.owner.as_deref()?,
            &network_call.1.name,
        );
        let jar_evidence = flow_evidence(
            staging_class,
            &MethodId {
                archive_id: staging_class.archive_id.clone(),
                class_name: jar_call.0.class_name.clone(),
                method_name: jar_call.0.method_name.clone(),
                descriptor: jar_call.0.descriptor.clone(),
            },
            jar_call.1.offset,
            "java/util/jar/JarInputStream",
            &jar_call.1.name,
        );
        let load_evidence = flow_evidence(
            loader_class,
            &MethodId {
                archive_id: loader_class.archive_id.clone(),
                class_name: define_call.0.class_name.clone(),
                method_name: define_call.0.method_name.clone(),
                descriptor: define_call.0.descriptor.clone(),
            },
            define_call.1.offset,
            define_call.1.owner.as_deref()?,
            "defineClass",
        );
        return Some(ConfirmedChain {
            chain_id: format!("remote-memory-load-{}", staging_class.archive_id),
            rule_id: CONFIRMED_REMOTE_MEMORY_LOAD_RULE_ID.to_owned(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            score_contribution: 80,
            operations: vec![
                network_evidence.operation.clone(),
                jar_evidence.operation.clone(),
                load_evidence.operation.clone(),
            ],
            evidence: [network_evidence, jar_evidence, load_evidence]
                .into_iter()
                .map(flow_evidence_to_evidence)
                .collect(),
        });
    }
    None
}

fn flow_evidence_to_evidence(flow: FlowEvidence) -> Evidence {
    Evidence {
        archive_id: flow.archive_id,
        archive_path: flow.archive_path,
        class_name: Some(flow.class_name),
        method_name: Some(flow.method_name),
        method_descriptor: Some(flow.method_descriptor),
        bytecode_offset: Some(flow.bytecode_offset),
        resource_path: None,
        operation: flow.operation,
        value_preview: flow.value_preview,
        source_value: flow.source_value,
        target_value: flow.target_value,
        confidence: Confidence::High,
        scope: flow.scope,
    }
}

/// Confirms a bundled native downloader only when Java code also loads it.
fn confirmed_embedded_native_downloader(data: &ScanData) -> Option<ConfirmedChain> {
    let native_evidence = data
        .archive_capabilities
        .iter()
        .find(|capability| capability.rule_id == "EMBEDDED_NATIVE_DOWNLOADER")?
        .evidence
        .first()?
        .clone();
    let (class_file, method, call) = data
        .class_files
        .iter()
        .filter(|class_file| class_file.scope == CodeScope::FirstParty)
        .find_map(|class_file| {
            class_file.methods.iter().find_map(|method| {
                method.calls.iter().find_map(|call| {
                    (call.owner.as_deref() == Some("java/lang/System")
                        && matches!(call.name.as_str(), "load" | "loadLibrary"))
                    .then_some((class_file, method, call))
                })
            })
        })?;
    let load_evidence = flow_evidence(
        class_file,
        &MethodId {
            archive_id: class_file.archive_id.clone(),
            class_name: method.class_name.clone(),
            method_name: method.method_name.clone(),
            descriptor: method.descriptor.clone(),
        },
        call.offset,
        "java/lang/System",
        &call.name,
    );
    Some(ConfirmedChain {
        chain_id: format!("embedded-native-downloader-{}", class_file.archive_id),
        rule_id: CONFIRMED_EMBEDDED_NATIVE_DOWNLOADER_RULE_ID.to_owned(),
        severity: Severity::Critical,
        confidence: Confidence::High,
        score_contribution: 80,
        operations: vec![
            native_evidence.operation.clone(),
            load_evidence.operation.clone(),
        ],
        evidence: vec![native_evidence, flow_evidence_to_evidence(load_evidence)],
    })
}

const MIN_ENCODED_NATIVE_PAYLOAD_STRING_LENGTH: usize = 256;

/// Confirms an embedded native payload loader when the same first-party class
/// decodes a sizeable XOR-obfuscated string, writes its bytes to a temporary
/// file, and passes that file to `System.load`.
fn confirmed_encoded_native_payload_load(data: &ScanData) -> Option<ConfirmedChain> {
    for class_file in data.class_files.iter().filter(|class_file| {
        matches!(
            class_file.scope,
            CodeScope::FirstParty | CodeScope::NestedMod
        )
    }) {
        let Some(class_name) = class_file.class_name.as_deref() else {
            continue;
        };
        let Some((loader_method, payload_bytes_call, temp_file_call, write_call, load_call)) =
            class_file.methods.iter().find_map(|method| {
                let payload_bytes_call = method.calls.iter().find(|call| {
                    call.owner.as_deref() == Some("java/lang/String")
                        && call.name == "getBytes"
                        && matches!(
                            call.receiver_origin.as_ref(),
                            Some(ValueOrigin::Field { owner, descriptor, .. })
                                if owner == class_name && descriptor == "Ljava/lang/String;"
                        )
                })?;
                let temp_file_call = method.calls.iter().find(|call| {
                    call.owner.as_deref() == Some("java/nio/file/Files")
                        && call.name == "createTempFile"
                })?;
                let write_call = method.calls.iter().find(|call| {
                    call.owner.as_deref() == Some("java/nio/file/Files") && call.name == "write"
                })?;
                let load_call = method.calls.iter().find(|call| {
                    call.owner.as_deref() == Some("java/lang/System") && call.name == "load"
                })?;
                let temp_file_origin = temp_file_call.result_origin.as_ref()?;
                let payload_bytes_origin = payload_bytes_call.result_origin.as_ref()?;
                let write_path = write_call.argument_origins.first()?;
                let write_bytes = write_call.argument_origins.get(1)?;
                if !origin_depends_on(method, write_path, temp_file_origin)
                    || !origin_depends_on(method, write_bytes, payload_bytes_origin)
                {
                    return None;
                }
                let path_to_string_call = method.calls.iter().find(|call| {
                    call.owner.as_deref() == Some("java/nio/file/Path")
                        && call.name == "toString"
                        && call.receiver_origin.as_ref().is_some_and(|origin| {
                            origin_depends_on(method, origin, temp_file_origin)
                        })
                })?;
                let path_string_origin = path_to_string_call.result_origin.as_ref()?;
                let load_path = load_call.argument_origins.first()?;
                if !origin_depends_on(method, load_path, path_string_origin) {
                    return None;
                }
                Some((
                    method,
                    payload_bytes_call,
                    temp_file_call,
                    write_call,
                    load_call,
                ))
            })
        else {
            continue;
        };

        let payload_field = match payload_bytes_call.receiver_origin.as_ref()? {
            ValueOrigin::Field { owner, name, .. } if owner == class_name => name,
            _ => continue,
        };
        let Some((decode_method, encoded_length, decode_call)) =
            class_file.methods.iter().find_map(|method| {
                if !is_encoded_native_payload_decoder(method) {
                    return None;
                }
                let field_written = method.field_writes.iter().any(|field| {
                    field.owner == class_name
                        && field.name.as_str() == payload_field
                        && field.descriptor == "Ljava/lang/String;"
                });
                if !field_written {
                    return None;
                }
                let encoded_length = method
                    .constants
                    .iter()
                    .filter_map(|constant| match &constant.value {
                        ConstantValue::String(value) => Some(value.len()),
                        _ => None,
                    })
                    .max()?;
                let decode_call = method.calls.iter().find(|call| {
                    call.owner.as_deref() == Some("java/lang/String")
                        && call.name == "<init>"
                        && call.descriptor.starts_with("([")
                })?;
                Some((method, encoded_length, decode_call))
            })
        else {
            continue;
        };

        let loader_id = MethodId {
            archive_id: class_file.archive_id.clone(),
            class_name: loader_method.class_name.clone(),
            method_name: loader_method.method_name.clone(),
            descriptor: loader_method.descriptor.clone(),
        };
        let decode_id = MethodId {
            archive_id: class_file.archive_id.clone(),
            class_name: decode_method.class_name.clone(),
            method_name: decode_method.method_name.clone(),
            descriptor: decode_method.descriptor.clone(),
        };
        let mut decode_evidence = flow_evidence(
            class_file,
            &decode_id,
            decode_call.offset,
            "java/lang/String",
            "<init>",
        );
        decode_evidence.operation = "encoded_native_payload".to_owned();
        decode_evidence.value_preview = Some(format!(
            "XOR-obfuscated String constant ({encoded_length} characters)"
        ));
        let evidence = vec![
            flow_evidence_to_evidence(decode_evidence),
            flow_evidence_to_evidence(flow_evidence(
                class_file,
                &loader_id,
                payload_bytes_call.offset,
                "java/lang/String",
                "getBytes",
            )),
            flow_evidence_to_evidence(flow_evidence(
                class_file,
                &loader_id,
                temp_file_call.offset,
                "java/nio/file/Files",
                "createTempFile",
            )),
            flow_evidence_to_evidence(flow_evidence(
                class_file,
                &loader_id,
                write_call.offset,
                "java/nio/file/Files",
                "write",
            )),
            flow_evidence_to_evidence(flow_evidence(
                class_file,
                &loader_id,
                load_call.offset,
                "java/lang/System",
                "load",
            )),
        ];
        return Some(ConfirmedChain {
            chain_id: format!("encoded-native-payload-load-{}", class_file.archive_id),
            rule_id: CONFIRMED_ENCODED_NATIVE_PAYLOAD_LOAD_RULE_ID.to_owned(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            score_contribution: 85,
            operations: vec![
                "encoded_native_payload".to_owned(),
                "java/lang/String.getBytes".to_owned(),
                "java/nio/file/Files.createTempFile".to_owned(),
                "java/nio/file/Files.write".to_owned(),
                "java/lang/System.load".to_owned(),
            ],
            evidence,
        });
    }
    None
}

fn is_encoded_native_payload_decoder(method: &MethodScanData) -> bool {
    let has_encoded_constant = method.constants.iter().any(|constant| {
        matches!(
            &constant.value,
            ConstantValue::String(value)
                if value.len() >= MIN_ENCODED_NATIVE_PAYLOAD_STRING_LENGTH
        )
    });
    let has_xor_loop = method
        .instructions
        .iter()
        .any(|instruction| instruction.opcode == 0x82)
        && method.control_flow_edges.iter().any(|edge| {
            edge.kind == ControlFlowEdgeKind::Branch && edge.to_offset < edge.from_offset
        });
    let has_char_array_input = method.calls.iter().any(|call| {
        call.owner.as_deref() == Some("java/lang/String") && call.name == "toCharArray"
    });
    let has_string_constructor = method.calls.iter().any(|call| {
        call.owner.as_deref() == Some("java/lang/String")
            && call.name == "<init>"
            && call.descriptor.starts_with("([")
    });

    has_encoded_constant && has_xor_loop && has_char_array_input && has_string_constructor
}

/// Confirms hidden player telemetry only when a statically recovered webhook is
/// used to send Minecraft client data. The config, collection, and network
/// transport may be split between first-party classes.
fn confirmed_webhook_exfil(
    data: &ScanData,
    decoded_values: &[obfuscation::DecodedValue],
) -> Option<ConfirmedChain> {
    let webhook = webhook_origin(data, decoded_values)?;
    let (transport_class, transport_method, post_call) = data
        .class_files
        .iter()
        .filter(|class_file| {
            class_file.scope == CodeScope::FirstParty && class_file.archive_id == webhook.archive_id
        })
        .find_map(|class_file| {
            class_file.methods.iter().find_map(|method| {
                let uses_webhook_config = class_file.class_name.as_deref()
                    == Some(webhook.class_name.as_str())
                    || method
                        .field_reads
                        .iter()
                        .any(|field| field.owner == webhook.class_name);
                uses_webhook_config
                    .then(|| webhook_post_call(method).map(|call| (class_file, method, call)))
                    .flatten()
            })
        })?;
    let transport_class_name = transport_class.class_name.as_deref()?;
    let (collector_class, collector_method, player_call, forwarding_call) = data
        .class_files
        .iter()
        .filter(|candidate| {
            candidate.scope == CodeScope::FirstParty && candidate.archive_id == webhook.archive_id
        })
        .find_map(|candidate| {
            candidate.methods.iter().find_map(|method| {
                let player_call = minecraft_client_call(method)?;
                let forwarding_call = method
                    .calls
                    .iter()
                    .find(|call| call.owner.as_deref() == Some(transport_class_name))?;
                Some((candidate, method, player_call, forwarding_call))
            })
        })
        .or_else(|| {
            minecraft_client_call(transport_method)
                .map(|player_call| (transport_class, transport_method, player_call, post_call))
        })?;
    let transport_method_id = MethodId {
        archive_id: transport_class.archive_id.clone(),
        class_name: transport_method.class_name.clone(),
        method_name: transport_method.method_name.clone(),
        descriptor: transport_method.descriptor.clone(),
    };
    let post_evidence = flow_evidence(
        transport_class,
        &transport_method_id,
        post_call.offset,
        post_call.owner.as_deref()?,
        &post_call.name,
    );
    let collector_method_id = MethodId {
        archive_id: collector_class.archive_id.clone(),
        class_name: collector_method.class_name.clone(),
        method_name: collector_method.method_name.clone(),
        descriptor: collector_method.descriptor.clone(),
    };
    let player_evidence = flow_evidence(
        collector_class,
        &collector_method_id,
        player_call.offset,
        player_call.owner.as_deref()?,
        &player_call.name,
    );
    let forwarding_evidence = flow_evidence(
        collector_class,
        &collector_method_id,
        forwarding_call.offset,
        forwarding_call.owner.as_deref()?,
        &forwarding_call.name,
    );
    let webhook_evidence = Evidence {
        archive_id: webhook.archive_id.clone(),
        archive_path: webhook.archive_path.clone(),
        class_name: Some(webhook.class_name.clone()),
        method_name: Some(webhook.method_name.clone()),
        method_descriptor: Some(webhook.method_descriptor.clone()),
        bytecode_offset: Some(webhook.bytecode_offset),
        resource_path: None,
        operation: webhook.operation.to_owned(),
        value_preview: Some("Webhook URL (redacted)".to_owned()),
        source_value: None,
        target_value: None,
        confidence: Confidence::High,
        scope: CodeScope::FirstParty,
    };

    Some(ConfirmedChain {
        chain_id: format!("webhook-exfil-{}", transport_class.archive_id),
        rule_id: CONFIRMED_WEBHOOK_EXFIL_RULE_ID.to_owned(),
        severity: Severity::Critical,
        confidence: Confidence::High,
        score_contribution: 80,
        operations: vec![
            webhook_evidence.operation.clone(),
            post_evidence.operation.clone(),
            player_evidence.operation.clone(),
            forwarding_evidence.operation.clone(),
        ],
        evidence: vec![
            webhook_evidence,
            flow_evidence_to_evidence(post_evidence),
            flow_evidence_to_evidence(player_evidence),
            flow_evidence_to_evidence(forwarding_evidence),
        ],
    })
}

struct WebhookOrigin {
    archive_id: String,
    archive_path: String,
    class_name: String,
    method_name: String,
    method_descriptor: String,
    bytecode_offset: u32,
    operation: &'static str,
}

fn webhook_origin(
    data: &ScanData,
    decoded_values: &[obfuscation::DecodedValue],
) -> Option<WebhookOrigin> {
    decoded_values
        .iter()
        .find(|value| obfuscation::is_webhook_url(&value.value))
        .map(|value| WebhookOrigin {
            archive_id: value.archive_id.clone(),
            archive_path: value.archive_path.clone(),
            class_name: value.class_name.clone(),
            method_name: value.method_name.clone(),
            method_descriptor: value.method_descriptor.clone(),
            bytecode_offset: value.bytecode_offset,
            operation: "decoded_webhook",
        })
        .or_else(|| {
            data.class_files
                .iter()
                .filter(|class_file| class_file.scope == CodeScope::FirstParty)
                .find_map(|class_file| {
                    class_file.methods.iter().find_map(|method| {
                        method.constants.iter().find_map(|constant| {
                            let ConstantValue::String(value) = &constant.value else {
                                return None;
                            };
                            obfuscation::is_webhook_url(value).then(|| WebhookOrigin {
                                archive_id: class_file.archive_id.clone(),
                                archive_path: class_file.archive_path.clone(),
                                class_name: method.class_name.clone(),
                                method_name: method.method_name.clone(),
                                method_descriptor: method.descriptor.clone(),
                                bytecode_offset: constant.offset,
                                operation: "hard_coded_webhook",
                            })
                        })
                    })
                })
        })
}

fn webhook_post_call(method: &MethodScanData) -> Option<&CallSite> {
    let legacy_post_call = method.calls.iter().find(|call| {
        call.owner.as_deref() == Some("java/net/HttpURLConnection") && call.name == "setDoOutput"
    });
    let has_body_stream = method.calls.iter().any(|call| {
        call.owner.as_deref() == Some("java/net/HttpURLConnection")
            && call.name == "getOutputStream"
    });
    let has_body_write = method
        .calls
        .iter()
        .any(|call| call.owner.as_deref() == Some("java/io/OutputStream") && call.name == "write");

    if legacy_post_call.is_some() && has_body_stream && has_body_write {
        return legacy_post_call;
    }

    method.calls.iter().find(|call| {
        call.owner.as_deref() == Some("java/net/http/HttpClient")
            && matches!(call.name.as_str(), "send" | "sendAsync")
    })
}

fn minecraft_client_call(method: &MethodScanData) -> Option<&CallSite> {
    method.calls.iter().find(|call| {
        call.owner
            .as_deref()
            .is_some_and(|owner| owner.starts_with("net/minecraft/"))
    })
}

/// Recognizes a safe updater only when flow analysis has proven that the
/// downloaded value was cryptographically verified before it was written and
/// launched. Text such as "sha256" is intentionally irrelevant here.
fn confirmed_safe_updater_context(chains: &[ConfirmedChain]) -> Option<ConfirmedChain> {
    let verified = chains
        .iter()
        .find(|chain| chain.rule_id == "CONFIRMED_INTEGRITY_VERIFIED_UPDATER")?;
    let has_credential_or_dynamic_risk = chains.iter().any(|chain| {
        matches!(
            chain.rule_id.as_str(),
            "CONFIRMED_CREDENTIAL_EXFILTRATION"
                | "CONFIRMED_REMOTE_DYNAMIC_LOAD"
                | "CONFIRMED_DECODED_DYNAMIC_LOAD"
                | CONFIRMED_REMOTE_MEMORY_LOAD_RULE_ID
                | CONFIRMED_EMBEDDED_NATIVE_DOWNLOADER_RULE_ID
                | CONFIRMED_ENCODED_NATIVE_PAYLOAD_LOAD_RULE_ID
        )
    });
    if has_credential_or_dynamic_risk {
        return None;
    }
    Some(ConfirmedChain {
        chain_id: format!("safe-updater-{}", verified.chain_id),
        rule_id: "CONFIRMED_SAFE_UPDATER_CONTEXT".to_owned(),
        severity: Severity::Low,
        confidence: Confidence::Medium,
        score_contribution: 0,
        operations: vec!["integrity_verified_updater_context".to_owned()],
        evidence: verified.evidence.clone(),
    })
}

fn updater_capabilities(chains: &[ConfirmedChain]) -> Vec<Capability> {
    let Some(chain) = chains
        .iter()
        .find(|chain| chain.rule_id == "CONFIRMED_DOWNLOAD_WRITE_EXEC")
    else {
        return Vec::new();
    };
    [
        (
            "AUTO_UPDATER_DOWNLOAD",
            "Автообновлятор получает обновление по сети.",
        ),
        (
            "AUTO_UPDATER_WRITE_JAR",
            "Автообновлятор записывает JAR обновления.",
        ),
        (
            "AUTO_UPDATER_LAUNCH",
            "Автообновлятор запускает обновление.",
        ),
    ]
    .into_iter()
    .map(|(rule_id, message)| Capability {
        rule_id: rule_id.to_owned(),
        message: message.to_owned(),
        evidence: chain.evidence.clone(),
    })
    .collect()
}

/// Scanner aborts that should produce `verdict: unknown` instead of a malicious score.
#[derive(Debug, thiserror::Error)]
enum ScanAbort {
    #[error("Файл не является валидным zip/jar архивом: {message}")]
    InvalidZip { message: String },
    #[error("Превышен лимит количества class-файлов и вложенных архивов: максимум {limit}")]
    FileCount { limit: usize },
    #[error("Превышен лимит общего количества записей в архиве: максимум {limit}")]
    EntryCount { limit: usize },
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
            Self::EntryCount { .. } => "ZIP_ENTRY_COUNT_LIMIT",
            Self::TotalSize { .. } => "ZIP_TOTAL_SIZE_LIMIT",
            Self::SingleFileSize { .. } => "ZIP_SINGLE_FILE_LIMIT",
            Self::NestingDepth { .. } => "ZIP_NESTING_DEPTH_LIMIT",
        }
    }
}

/// Scores findings with the fixed severity weights and caps the total at 100.
fn risk_score(
    findings: &[Finding],
    confirmed_chains: &[ConfirmedChain],
    _obfuscation: &Obfuscation,
) -> u8 {
    let mut category_scores = HashMap::<&str, u16>::new();
    for finding in findings {
        if !finding_is_risk_bearing(finding) {
            continue;
        }
        let cap = category_score_cap(&finding.category);
        let score = u16::from(finding_score_weight(finding)).min(cap);
        let total = category_scores.entry(&finding.category).or_default();
        *total = (*total + score).min(cap);
    }
    let has_safe_updater_context = confirmed_chains
        .iter()
        .any(|chain| chain.rule_id == "CONFIRMED_SAFE_UPDATER_CONTEXT");
    let chain_score = confirmed_chains
        .iter()
        .map(|chain| {
            if has_safe_updater_context && chain.rule_id == "CONFIRMED_DOWNLOAD_WRITE_EXEC" {
                30
            } else {
                u16::from(chain.score_contribution)
            }
        })
        .sum::<u16>();
    category_scores
        .values()
        .copied()
        .sum::<u16>()
        .saturating_add(chain_score)
        .min(100) as u8
}

/// Facts from broad rules are intentionally non-scoring until an analyzer can
/// attach contextual source-level evidence to them.
fn finding_is_risk_bearing(finding: &Finding) -> bool {
    finding.kind != crate::models::scan::FindingKind::Heuristic
        && (!finding.evidence.is_empty() || finding.category == "virustotal")
}

/// Reports how much archive content reached the bounded static analyzers.
fn analysis_coverage(
    data: &ScanData,
    data_flow: &crate::scanner::dataflow::DataFlowResult,
) -> AnalysisCoverage {
    let total_classes = data
        .archive_layers
        .iter()
        .flat_map(|layer| &layer.entries)
        .filter(|entry| entry.path.to_ascii_lowercase().ends_with(".class"))
        .count() as u32;
    let total_resources = data
        .archive_layers
        .iter()
        .flat_map(|layer| &layer.entries)
        .filter(|entry| {
            let path = entry.path.to_ascii_lowercase();
            !path.ends_with(".class") && !path.ends_with(".jar") && !path.ends_with(".zip")
        })
        .count() as u32;
    let parsed_classes = data.class_files.len().min(total_classes as usize) as u32;
    let analyzed_resources = data.resource_files.len().min(total_resources as usize) as u32;
    let class_parse_coverage = percent(parsed_classes, total_classes);
    let flow_eligible = data
        .class_files
        .iter()
        .filter(|class| {
            matches!(
                class.scope,
                CodeScope::FirstParty | CodeScope::NestedMod | CodeScope::Unknown
            )
        })
        .flat_map(|class| &class.methods)
        .count() as u32;
    let method_flow_coverage =
        percent(data_flow.analyzed_methods.min(flow_eligible), flow_eligible)
            .max(u8::from(data_flow.analyzed_methods > 0));
    let instruction_total = data
        .class_files
        .iter()
        .filter(|class| class.scope != CodeScope::BundledDependency)
        .flat_map(|class| &class.methods)
        .map(|method| method.instructions.len() as u32)
        .sum();
    let supported_instructions = data
        .class_files
        .iter()
        .filter(|class| class.scope != CodeScope::BundledDependency)
        .flat_map(|class| &class.methods)
        .flat_map(|method| &method.instructions)
        .filter(|instruction| is_flow_supported_instruction(instruction.opcode))
        .count() as u32;
    let supported_instruction_coverage = percent(supported_instructions, instruction_total);
    let resolved_call_coverage = percent(
        data_flow.resolved_calls,
        data_flow.resolved_calls + data_flow.unresolved_calls,
    );
    let resolved_value_target_coverage = percent(
        data_flow.resolved_value_targets,
        data_flow.resolved_value_targets + data_flow.unknown_file_targets,
    );
    let classified_classes = data
        .class_files
        .iter()
        .filter(|class| class.scope != CodeScope::Unknown)
        .count() as u32;
    let archive_scope_coverage = percent(classified_classes, parsed_classes);
    let overall_score = [
        class_parse_coverage,
        method_flow_coverage,
        supported_instruction_coverage,
        resolved_call_coverage,
        resolved_value_target_coverage,
        archive_scope_coverage,
    ]
    .into_iter()
    .map(u16::from)
    .sum::<u16>()
        / 6;

    AnalysisCoverage {
        score: overall_score as u8,
        overall_score: overall_score as u8,
        class_parse_coverage,
        method_flow_coverage,
        supported_instruction_coverage,
        resolved_call_coverage,
        resolved_value_target_coverage,
        archive_scope_coverage,
        total_classes,
        parsed_classes,
        total_resources,
        analyzed_resources,
    }
}

fn percent(numerator: u32, denominator: u32) -> u8 {
    if denominator == 0 {
        100
    } else {
        (u64::from(numerator.min(denominator)) * 100 / u64::from(denominator)) as u8
    }
}

fn is_flow_supported_instruction(opcode: u8) -> bool {
    matches!(
        opcode,
        0x01..=0x19
            | 0x1a..=0x2d
            | 0x36..=0x3a
            | 0x3b..=0x4e
            | 0x57..=0x5f
            | 0x60..=0x98
            | 0x99..=0xa6
            | 0xac..=0xb1
            | 0x4f..=0x56
            | 0xb2..=0xb9
            | 0xbb..=0xbe
            | 0xc5
    )
}

fn decoded_strings(
    values: &[obfuscation::DecodedValue],
    class_files: &[ClassScanData],
) -> Vec<DecodedString> {
    values
        .iter()
        .map(|value| DecodedString {
            original_value: value.original_value.clone(),
            decoder_method: value.transform.to_owned(),
            decoded_value: value.value.clone(),
            confidence: value.confidence.clone(),
            evidence: Evidence {
                archive_id: value.archive_id.clone(),
                archive_path: value.archive_path.clone(),
                class_name: Some(value.class_name.clone()),
                method_name: Some(value.method_name.clone()),
                method_descriptor: Some(value.method_descriptor.clone()),
                bytecode_offset: Some(value.bytecode_offset),
                resource_path: None,
                operation: "decoded_string".to_owned(),
                value_preview: Some(value.value.clone()),
                source_value: Some(value.original_value.clone()),
                target_value: Some(value.value.clone()),
                confidence: value.confidence.clone(),
                scope: class_files
                    .iter()
                    .find(|class| {
                        class.archive_id == value.archive_id
                            && class.class_name.as_deref() == Some(value.class_name.as_str())
                    })
                    .map(|class| class.scope.clone())
                    .unwrap_or(CodeScope::Unknown),
            },
        })
        .collect()
}

fn text_resources(resources: &[ResourceScanData]) -> Vec<TextResource> {
    resources
        .iter()
        .filter_map(|resource| {
            resource
                .detected_encoding
                .as_ref()
                .map(|encoding| TextResource {
                    archive_id: resource.archive_id.clone(),
                    archive_path: resource.archive_path.clone(),
                    resource_path: resource.path.clone(),
                    detected_encoding: encoding.clone(),
                    confidence: resource.decoding_confidence.clone(),
                })
        })
        .collect()
}

fn category_score_cap(category: &str) -> u16 {
    match category {
        "network" | "dangerous_api" | "obfuscation" => 5,
        "archive_structure" | "supply_chain" => 15,
        _ => 100,
    }
}

fn verdict_from_evidence(
    findings: &[Finding],
    confirmed_chains: &[ConfirmedChain],
    _obfuscation: &Obfuscation,
    risk_score: u8,
) -> Verdict {
    let has_safe_updater_context = confirmed_chains
        .iter()
        .any(|chain| chain.rule_id == "CONFIRMED_SAFE_UPDATER_CONTEXT");
    let has_malicious_chain = confirmed_chains.iter().any(|chain| {
        matches!(
            chain.rule_id.as_str(),
            "CONFIRMED_CREDENTIAL_EXFILTRATION"
                | "CONFIRMED_DECODED_DYNAMIC_LOAD"
                | "CONFIRMED_REMOTE_DYNAMIC_LOAD"
                | CONFIRMED_REMOTE_MEMORY_LOAD_RULE_ID
                | CONFIRMED_EMBEDDED_NATIVE_DOWNLOADER_RULE_ID
                | CONFIRMED_ENCODED_NATIVE_PAYLOAD_LOAD_RULE_ID
                | CONFIRMED_WEBHOOK_EXFIL_RULE_ID
        ) || (chain.rule_id == "CONFIRMED_DOWNLOAD_WRITE_EXEC" && !has_safe_updater_context)
    });
    let trusted_vt_detection = findings
        .iter()
        .any(|finding| finding.rule_id == "VT_TRUSTED_MALICIOUS_ENGINE");
    // Only the mod's own code is decisive; in bundled libraries the co-location is left to scoring.
    let session_exfiltration = findings.iter().any(|finding| {
        finding.rule_id == SESSION_CHAT_EXFIL_CO_LOCATION_RULE_ID
            && matches!(
                finding.scope,
                CodeScope::FirstParty | CodeScope::NestedMod | CodeScope::Unknown
            )
    });
    if has_malicious_chain || trusted_vt_detection || session_exfiltration {
        return Verdict::Malicious;
    }
    if !confirmed_chains.is_empty() || risk_score > 5 {
        Verdict::Suspicious
    } else {
        Verdict::Clean
    }
}

/// Prevents a clean verdict when obfuscation or missing flow coverage makes a negative result
/// unreliable.
fn apply_analysis_limits(
    verdict: Verdict,
    obfuscation: &Obfuscation,
    analysis_coverage: &AnalysisCoverage,
    has_first_party_network_calls: bool,
) -> Verdict {
    let incomplete_obfuscated_network_flow = has_first_party_network_calls
        && analysis_coverage.method_flow_coverage == 0
        && !matches!(obfuscation.level, ObfuscationLevel::None);
    // Obfuscation hides what the code does, so an absence of findings is not proof of safety.
    if verdict == Verdict::Clean
        && (matches!(
            obfuscation.level,
            ObfuscationLevel::Medium | ObfuscationLevel::High
        ) || incomplete_obfuscated_network_flow)
    {
        Verdict::Unknown
    } else {
        verdict
    }
}

fn has_first_party_network_calls(data: &ScanData) -> bool {
    data.class_files
        .iter()
        .filter(|class_file| {
            matches!(
                class_file.scope,
                CodeScope::FirstParty | CodeScope::NestedMod | CodeScope::Unknown
            )
        })
        .flat_map(|class_file| class_file.methods.iter())
        .flat_map(|method| method.calls.iter())
        .filter_map(|call| call.owner.as_deref())
        .any(|owner| {
            matches!(
                owner,
                "java/net/URL"
                    | "java/net/HttpURLConnection"
                    | "javax/net/ssl/HttpsURLConnection"
                    | "java/net/http/HttpClient"
                    | "java/net/Socket"
            )
        })
}

fn finding_score_weight(finding: &Finding) -> u8 {
    match finding.rule_id.as_str() {
        "TIMESTAMP_OUTLIER" => Severity::Low.score_weight(),
        "RAW_GITHUB_URL" => 0,
        _ => finding.score_contribution,
    }
}

/// Builds a concise user-facing Russian summary without ever claiming complete safety.
fn summarize(findings: &[Finding], verdict: Verdict) -> String {
    if findings.is_empty() && verdict == Verdict::Clean {
        return "Явных угроз не найдено, но это не гарантия полной безопасности.".to_owned();
    }
    if findings.is_empty() {
        return match verdict {
            Verdict::Malicious => "Обнаружена подтверждённая опасная цепочка поведения.".to_owned(),
            Verdict::Suspicious => {
                "Обнаружена подтверждённая подозрительная цепочка поведения.".to_owned()
            }
            Verdict::Unknown => "Результат сканирования неизвестен: анализ неполный.".to_owned(),
            Verdict::Clean => unreachable!("clean with empty findings handled above"),
        };
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
    let finding = Finding::legacy(rule_id, category, Severity::High, message.clone());
    let report = ScanReport {
        verdict: Verdict::Unknown,
        risk_score: 0,
        confidence: Confidence::Low,
        obfuscation_score: 0,
        analysis_coverage: AnalysisCoverage::default(),
        capabilities: Vec::new(),
        decoded_strings: Vec::new(),
        text_resources: Vec::new(),
        findings: vec![finding.clone()],
        confirmed_chains: Vec::new(),
        obfuscation: Obfuscation::default(),
        limitations: Vec::new(),
    };
    ScanOutcome {
        report,
        verdict: Verdict::Unknown,
        risk_score: 0,
        summary: message.clone(),
        findings: vec![finding],
    }
}

#[cfg(test)]
mod tests {
    use super::{
        add_contextual_findings, confirmed_remote_memory_load,
        credential_webhook_co_location_finding, custom_invokedynamic_bootstrap_finding,
        executable_download_exec_co_location_finding, file_target_from_origin, finalize_report,
        has_significant_identifier_overlap, is_credential_target, parse_zip_bytes, risk_score,
        scan_file, session_chat_exfil_co_location_finding, summarize, verdict_from_evidence,
        ArchiveContext, ClassScanData, ScanData, ScanLimits,
        CREDENTIAL_WEBHOOK_CO_LOCATION_RULE_ID, CUSTOM_INVOKEDYNAMIC_BOOTSTRAP_RULE_ID,
        EXECUTABLE_DOWNLOAD_EXEC_CO_LOCATION_RULE_ID, EXTERNAL_URLCLASSLOADER_SIGNAL,
        PRIVACY_NETWORK_SYNC_RULE_ID, REMOTE_CLASS_LOADING_SIGNAL,
        SESSION_CHAT_EXFIL_CO_LOCATION_RULE_ID, TIMESTAMP_OUTLIER_SIGNAL,
    };

    use crate::models::scan::{
        AnalysisCoverage, CodeScope, Confidence, Evidence, Finding, FindingKind, Limitation,
        Obfuscation, ObfuscationLevel, Severity, Verdict,
    };
    use crate::rules::engine::RulesEngine;
    use crate::scanner::{
        class_file::{
            BootstrapMethodRef, CallSite, ConstantValue, ControlFlowEdge, ControlFlowEdgeKind,
            FieldAccess, Instruction, InvokeKind, LoadedConstant, MethodScanData, ValueOrigin,
        },
        dataflow::FileTarget,
        obfuscation::DecodedValue,
    };
    use std::{
        io::{Cursor, Write},
        path::Path,
    };
    use zip::{write::SimpleFileOptions, DateTime, ZipWriter};

    /// Verifies the fixed severity weights are capped at 100.
    #[test]
    fn risk_score_caps_at_100() {
        let findings = vec![
            evidenced_finding("A", "x", Severity::Critical),
            evidenced_finding("B", "x", Severity::Critical),
            evidenced_finding("C", "x", Severity::High),
        ];
        assert_eq!(risk_score(&findings, &[], &Obfuscation::default()), 100);
    }

    /// Verifies noisy standalone rules stay below the malicious threshold.
    #[test]
    fn risk_score_ignores_legacy_matches_without_evidence() {
        let findings = vec![
            Finding::legacy(
                "TIMESTAMP_OUTLIER",
                "supply_chain",
                Severity::High,
                "timestamp",
            ),
            Finding::legacy("RAW_GITHUB_URL", "exfiltration", Severity::Low, "github"),
            Finding::legacy("MODS_SELF_COPY", "persistence", Severity::Low, "mods"),
            Finding::legacy("XOR_LOOP_HINT", "obfuscation", Severity::Low, "xor"),
        ];

        assert_eq!(risk_score(&findings, &[], &Obfuscation::default()), 0);
    }

    /// An anti-analysis marker is an observation and must not change the verdict
    /// without source-level evidence or a confirmed chain.
    #[test]
    fn anti_analysis_heuristic_does_not_change_verdict() {
        let findings = vec![Finding {
            rule_id: "VMWARE_CHECK".to_owned(),
            category: "evasion".to_owned(),
            kind: FindingKind::Heuristic,
            severity: Severity::High,
            confidence: Confidence::Low,
            score_contribution: 0,
            scope: CodeScope::Unknown,
            message: "vmware".to_owned(),
            evidence: Vec::new(),
            related_chain_id: None,
        }];

        let score = risk_score(&findings, &[], &Obfuscation::default());
        assert_eq!(score, 0);
        assert_eq!(
            verdict_from_evidence(&findings, &[], &Obfuscation::default(), score),
            Verdict::Clean
        );
    }

    #[test]
    fn repeated_limitations_are_aggregated_by_code() {
        let limitations = (0..10)
            .map(|_| Limitation {
                code: "INTERPROCEDURAL_DEPTH_LIMIT".into(),
                message: "Depth limit reached.".into(),
                evidence: Vec::new(),
            })
            .chain(std::iter::once(Limitation {
                code: "UNRESOLVED_CALL".into(),
                message: "Call could not be resolved.".into(),
                evidence: Vec::new(),
            }))
            .collect();

        let aggregated = super::aggregate_limitations(limitations);

        assert_eq!(aggregated.len(), 2);
        assert_eq!(aggregated[0].code, "INTERPROCEDURAL_DEPTH_LIMIT");
        assert!(aggregated[0].message.contains("Всего: 10"));
        assert_eq!(aggregated[1].code, "UNRESOLVED_CALL");
    }

    #[test]
    fn high_obfuscation_and_low_coverage_downgrade_clean_to_unknown() {
        let obfuscation = Obfuscation {
            level: ObfuscationLevel::High,
            score: 80,
            signals: Vec::new(),
        };
        let low_coverage = AnalysisCoverage {
            overall_score: 69,
            ..Default::default()
        };

        assert_eq!(
            super::apply_analysis_limits(Verdict::Clean, &obfuscation, &low_coverage, false),
            Verdict::Unknown
        );
        assert_eq!(
            super::apply_analysis_limits(Verdict::Malicious, &obfuscation, &low_coverage, false),
            Verdict::Malicious
        );
    }

    #[test]
    fn file_targets_use_symbolic_paths_for_data_flow_comparison() {
        let windows_path = ValueOrigin::Constant(ConstantValue::String(
            r"C:\Users\User\AppData\Roaming\ratka\loader.jar".to_owned(),
        ));
        let variable_path = ValueOrigin::Constant(ConstantValue::String(
            "%APPDATA%/Roaming/ratka/loader.jar".to_owned(),
        ));

        assert_eq!(
            file_target_from_origin(&windows_path),
            Some(FileTarget::Known(
                "AppData/Roaming/ratka/loader.jar".to_owned()
            ))
        );
        assert_eq!(
            file_target_from_origin(&windows_path),
            file_target_from_origin(&variable_path)
        );
    }

    #[test]
    fn credential_paths_require_a_structured_storage_location() {
        assert!(!is_credential_target(&FileTarget::Known(
            "config/account-session.json".to_owned(),
        )));
        assert!(is_credential_target(&FileTarget::Known(
            "Discord/Local Storage/leveldb/000005.ldb".to_owned(),
        )));
        assert!(is_credential_target(&FileTarget::Known(
            "Google/Chrome/User Data/Default/Login Data".to_owned(),
        )));
    }

    #[test]
    fn authentication_command_aliases_are_recognized_exactly() {
        for command in ["/l", "/login password", "/reg password", "/registration p"] {
            assert!(super::is_authentication_command_prefix(command));
        }
        assert!(!super::is_authentication_command_prefix("/locate village"));
        assert!(!super::is_authentication_command_prefix("/registering"));
    }

    #[test]
    fn incomplete_obfuscated_network_flow_downgrades_clean_to_unknown() {
        let obfuscation = Obfuscation {
            level: ObfuscationLevel::Medium,
            score: 25,
            signals: vec!["reflection_density".to_owned()],
        };
        let coverage = AnalysisCoverage {
            overall_score: 83,
            method_flow_coverage: 0,
            ..Default::default()
        };

        assert_eq!(
            super::apply_analysis_limits(Verdict::Clean, &obfuscation, &coverage, true),
            Verdict::Unknown
        );
        // Medium or high obfuscation keeps a clean verdict from being trusted; low does not.
        assert_eq!(
            super::apply_analysis_limits(Verdict::Clean, &obfuscation, &coverage, false),
            Verdict::Unknown
        );
        let low = Obfuscation {
            level: ObfuscationLevel::Low,
            score: 10,
            signals: Vec::new(),
        };
        assert_eq!(
            super::apply_analysis_limits(Verdict::Clean, &low, &coverage, false),
            Verdict::Clean
        );
    }

    /// Verifies privacy/network sync is suspicious but not malicious by itself.
    #[test]
    fn privacy_network_sync_requires_flow_evidence_before_scoring() {
        let mut findings = vec![
            Finding::legacy(
                "TIMESTAMP_OUTLIER",
                "supply_chain",
                Severity::High,
                "timestamp",
            ),
            Finding::legacy("XOR_LOOP_HINT", "obfuscation", Severity::Low, "xor"),
            Finding::legacy("URL_API", "network", Severity::Low, "url"),
            Finding::legacy("HTTPS_URL_CONNECTION", "network", Severity::Low, "https"),
        ];
        let data = ScanData {
            archive_signals: vec!["xor_loop_string_decode".to_owned()],
            first_party_strings: vec![
                "wss://ws.example.invalid".to_owned(),
                "Authorization".to_owned(),
                "Bearer".to_owned(),
                "uuid".to_owned(),
                "username".to_owned(),
                "server_address".to_owned(),
            ],
            first_party_bytecode_refs: vec!["java/net/Socket".to_owned()],
            ..Default::default()
        };

        add_contextual_findings(&mut findings, &data);

        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == PRIVACY_NETWORK_SYNC_RULE_ID));
        assert_eq!(risk_score(&findings, &[], &Obfuscation::default()), 0);
    }

    #[test]
    fn confirms_encoded_native_payload_temp_write_and_system_load() {
        const CLASS_NAME: &str = "mod/NativeLoader";
        let payload_field = FieldAccess {
            offset: 38,
            owner: CLASS_NAME.to_owned(),
            name: "payload".to_owned(),
            descriptor: "Ljava/lang/String;".to_owned(),
            value_origin: Some(ValueOrigin::Instruction(30)),
        };
        let decoder = MethodScanData {
            class_name: CLASS_NAME.to_owned(),
            method_name: "<clinit>".to_owned(),
            descriptor: "()V".to_owned(),
            instructions: vec![Instruction {
                offset: 14,
                opcode: 0x82,
                operands: Vec::new(),
            }],
            constants: vec![LoadedConstant {
                offset: 0,
                value: ConstantValue::String(
                    "X".repeat(super::MIN_ENCODED_NATIVE_PAYLOAD_STRING_LENGTH),
                ),
            }],
            calls: vec![
                call_with_origins(
                    7,
                    "java/lang/String",
                    "toCharArray",
                    Some(ValueOrigin::Constant(ConstantValue::String(
                        "payload".to_owned(),
                    ))),
                    Vec::new(),
                    Some(ValueOrigin::Instruction(8)),
                ),
                call_with_origins(
                    30,
                    "java/lang/String",
                    "<init>",
                    Some(ValueOrigin::Instruction(29)),
                    vec![ValueOrigin::Instruction(8)],
                    None,
                ),
            ],
            field_writes: vec![payload_field],
            control_flow_edges: vec![ControlFlowEdge {
                from_offset: 20,
                to_offset: 10,
                kind: ControlFlowEdgeKind::Branch,
            }],
            ..MethodScanData::default()
        };
        let temp_path = ValueOrigin::Instruction(1);
        let payload_bytes = ValueOrigin::Instruction(2);
        let path_string = ValueOrigin::Instruction(4);
        let loader = MethodScanData {
            class_name: CLASS_NAME.to_owned(),
            method_name: "load".to_owned(),
            descriptor: "()V".to_owned(),
            calls: vec![
                call_with_origins(
                    1,
                    "java/nio/file/Files",
                    "createTempFile",
                    None,
                    Vec::new(),
                    Some(temp_path.clone()),
                ),
                call_with_origins(
                    2,
                    "java/lang/String",
                    "getBytes",
                    Some(ValueOrigin::Field {
                        owner: CLASS_NAME.to_owned(),
                        name: "payload".to_owned(),
                        descriptor: "Ljava/lang/String;".to_owned(),
                    }),
                    Vec::new(),
                    Some(payload_bytes.clone()),
                ),
                call_with_origins(
                    3,
                    "java/nio/file/Files",
                    "write",
                    None,
                    vec![temp_path, payload_bytes, ValueOrigin::Unknown],
                    Some(ValueOrigin::Instruction(3)),
                ),
                call_with_origins(
                    4,
                    "java/nio/file/Path",
                    "toString",
                    Some(ValueOrigin::Instruction(1)),
                    Vec::new(),
                    Some(path_string.clone()),
                ),
                call_with_origins(5, "java/lang/System", "load", None, vec![path_string], None),
            ],
            ..MethodScanData::default()
        };
        let data = ScanData {
            class_files: vec![class_scan_data(CLASS_NAME, vec![], vec![decoder, loader])],
            ..Default::default()
        };

        let chain = super::confirmed_encoded_native_payload_load(&data)
            .expect("encoded native payload chain");
        assert_eq!(
            chain.rule_id,
            super::CONFIRMED_ENCODED_NATIVE_PAYLOAD_LOAD_RULE_ID
        );
        assert_eq!(chain.evidence.len(), 5);
        assert_eq!(
            verdict_from_evidence(&[], &[chain], &Obfuscation::default(), 85),
            Verdict::Malicious
        );

        let mut dependency_data = data;
        dependency_data.class_files[0].scope = CodeScope::BundledDependency;
        assert!(super::confirmed_encoded_native_payload_load(&dependency_data).is_none());
    }

    #[test]
    fn confirms_hard_coded_slack_webhook_player_exfiltration() {
        let method = MethodScanData {
            class_name: "mod/Webhook".to_owned(),
            method_name: "send".to_owned(),
            descriptor: "()V".to_owned(),
            calls: vec![
                test_call("java/net/HttpURLConnection", "setDoOutput"),
                test_call("java/net/HttpURLConnection", "getOutputStream"),
                test_call("java/io/OutputStream", "write"),
                test_call("net/minecraft/client/MinecraftClient", "getInstance"),
            ],
            ..MethodScanData::default()
        };
        let data = ScanData {
            class_files: vec![ClassScanData {
                archive_id: "archive-0".to_owned(),
                archive_path: "<root>".to_owned(),
                class_name: Some("mod/Webhook".to_owned()),
                scope: CodeScope::FirstParty,
                methods: vec![method],
                ..ClassScanData::default()
            }],
            ..ScanData::default()
        };
        let decoded_values = vec![DecodedValue {
            archive_id: "archive-0".to_owned(),
            archive_path: "<root>".to_owned(),
            class_name: "mod/Webhook".to_owned(),
            method_name: "<init>".to_owned(),
            method_descriptor: "()V".to_owned(),
            bytecode_offset: 12,
            transform: "base64-xor-known-webhook",
            original_value: "encrypted".to_owned(),
            value: "https://hooks.slack.com/services/T01234567/B01234567/abcdefghijklmnopqrstuvwxyz012345".to_owned(),
            confidence: Confidence::High,
        }];

        let chain = super::confirmed_webhook_exfil(&data, &decoded_values)
            .expect("confirmed webhook exfiltration");

        assert_eq!(chain.rule_id, super::CONFIRMED_WEBHOOK_EXFIL_RULE_ID);
        assert_eq!(
            verdict_from_evidence(&[], &[chain], &Obfuscation::default(), 80),
            Verdict::Malicious
        );
    }

    #[test]
    fn confirms_http_client_webhook_exfiltration_across_first_party_classes() {
        let webhook_literal = MethodScanData {
            class_name: "mod/DiscordWebhook".to_owned(),
            method_name: "<clinit>".to_owned(),
            descriptor: "()V".to_owned(),
            constants: vec![LoadedConstant {
                offset: 12,
                value: ConstantValue::String(
                    "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-".to_owned(),
                ),
            }],
            ..MethodScanData::default()
        };
        let transport = MethodScanData {
            class_name: "mod/DiscordWebhook".to_owned(),
            method_name: "sendScreenshot".to_owned(),
            descriptor: "([B)V".to_owned(),
            calls: vec![test_call("java/net/http/HttpClient", "sendAsync")],
            ..MethodScanData::default()
        };
        let collector = MethodScanData {
            class_name: "mod/ChatLogger".to_owned(),
            method_name: "takeScreenshot".to_owned(),
            descriptor: "()V".to_owned(),
            calls: vec![
                test_call("net/minecraft/client/MinecraftClient", "getInstance"),
                test_call("mod/DiscordWebhook", "sendScreenshot"),
            ],
            ..MethodScanData::default()
        };
        let data = ScanData {
            class_files: vec![
                class_scan_data(
                    "mod/DiscordWebhook",
                    vec![],
                    vec![webhook_literal, transport],
                ),
                class_scan_data("mod/ChatLogger", vec![], vec![collector]),
            ],
            ..Default::default()
        };

        let chain = super::confirmed_webhook_exfil(&data, &[])
            .expect("confirmed HttpClient webhook exfiltration");

        assert_eq!(chain.rule_id, super::CONFIRMED_WEBHOOK_EXFIL_RULE_ID);
        assert_eq!(chain.evidence.len(), 4);
        assert_eq!(
            verdict_from_evidence(&[], &[chain], &Obfuscation::default(), 80),
            Verdict::Malicious
        );
    }

    #[test]
    fn confirms_webhook_config_separate_from_transport_class() {
        let transport = MethodScanData {
            class_name: "mod/DiscordWebhook".to_owned(),
            method_name: "send".to_owned(),
            descriptor: "(Ljava/lang/String;)V".to_owned(),
            calls: vec![
                test_call("java/net/HttpURLConnection", "setDoOutput"),
                test_call("java/net/HttpURLConnection", "getOutputStream"),
                test_call("java/io/OutputStream", "write"),
            ],
            field_reads: vec![crate::scanner::class_file::FieldAccess {
                offset: 2,
                owner: "mod/Config".to_owned(),
                name: "webhookUrl".to_owned(),
                descriptor: "Ljava/lang/String;".to_owned(),
                value_origin: None,
            }],
            ..MethodScanData::default()
        };
        let collector = MethodScanData {
            class_name: "mod/ChatLogger".to_owned(),
            method_name: "logMessage".to_owned(),
            descriptor: "(Ljava/lang/String;)V".to_owned(),
            calls: vec![
                test_call("net/minecraft/client/MinecraftClient", "getInstance"),
                test_call("mod/DiscordWebhook", "send"),
            ],
            ..MethodScanData::default()
        };
        let data = ScanData {
            class_files: vec![
                class_scan_data("mod/Config", vec![], vec![]),
                class_scan_data("mod/DiscordWebhook", vec![], vec![transport]),
                class_scan_data("mod/ChatLogger", vec![], vec![collector]),
            ],
            ..ScanData::default()
        };
        let decoded_values = vec![DecodedValue {
            archive_id: "archive-0".to_owned(),
            archive_path: "<root>".to_owned(),
            class_name: "mod/Config".to_owned(),
            method_name: "<init>".to_owned(),
            method_descriptor: "()V".to_owned(),
            bytecode_offset: 40,
            transform: "base64-xor-known-webhook",
            original_value: "encrypted".to_owned(),
            value: "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789_-".to_owned(),
            confidence: Confidence::High,
        }];

        let chain = super::confirmed_webhook_exfil(&data, &decoded_values)
            .expect("confirmed webhook exfiltration with separate config");

        assert_eq!(chain.rule_id, super::CONFIRMED_WEBHOOK_EXFIL_RULE_ID);
        assert_eq!(chain.evidence.len(), 4);
        assert_eq!(
            verdict_from_evidence(&[], &[chain], &Obfuscation::default(), 80),
            Verdict::Malicious
        );
    }

    #[test]
    fn java_http_client_send_async_is_a_network_flow_terminal() {
        let method = MethodScanData {
            class_name: "mod/Telemetry".to_owned(),
            method_name: "sendHeartbeat".to_owned(),
            descriptor: "()V".to_owned(),
            calls: vec![CallSite {
                offset: 12,
                kind: InvokeKind::Virtual,
                owner: Some("java/net/http/HttpClient".to_owned()),
                name: "sendAsync".to_owned(),
                descriptor: "(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;)Ljava/util/concurrent/CompletableFuture;".to_owned(),
                receiver_origin: Some(ValueOrigin::Local(2)),
                argument_origins: vec![ValueOrigin::Local(0), ValueOrigin::Local(1)],
                result_origin: Some(ValueOrigin::Instruction(12)),
            }],
            ..MethodScanData::default()
        };
        let class = class_scan_data(
            "mod/Telemetry",
            vec!["java/net/http/HttpClient", "java/net/http/HttpRequest"],
            vec![method],
        );
        let data = ScanData {
            class_files: vec![class],
            ..Default::default()
        };

        let flow = super::method_flow_from_scan_data(
            &data.class_files[0],
            &data.class_files[0].methods[0],
        );
        assert!(flow
            .operations
            .iter()
            .any(|operation| matches!(operation, super::Operation::NetworkSend { body: 0, .. })));

        let result = super::analyze_scan_data_flow(&data);
        assert_eq!(result.analyzed_methods, 1);
        assert_eq!(result.unresolved_calls, 0);
    }

    /// Verifies related reversed/rotated identifiers do not produce namespace mismatch noise.
    #[test]
    fn identifier_overlap_accepts_related_modid_and_package() {
        assert!(has_significant_identifier_overlap("ogulniega", "gaogulnie"));
    }

    /// Verifies clean summaries avoid saying that a jar is guaranteed safe.
    #[test]
    fn clean_summary_is_not_absolute() {
        let summary = summarize(&[], Verdict::Clean);
        assert!(summary.contains("не гарантия"));
        let malicious_summary = summarize(&[], Verdict::Malicious);
        assert!(malicious_summary.contains("подтверждённая опасная цепочка"));
    }

    /// Verifies remote class loading requires network and loader APIs in one class file.
    #[test]
    fn class_correlation_detects_remote_class_loading_in_one_class() {
        let mut context = test_context(vec![ClassScanData {
            archive_id: "archive-0".to_owned(),
            archive_path: "<root>".to_owned(),
            path: "com/example/mod/Loader.class".to_owned(),
            class_name: Some("com/example/mod/Loader".to_owned()),
            major_version: 65,
            strings: Vec::new(),
            bytecode_refs: vec![
                "java/net/http/HttpClient".to_owned(),
                "java/lang/ClassLoader.defineClass".to_owned(),
            ],
            methods: Vec::new(),
            scope: CodeScope::FirstParty,
            dependency_name: None,
            dependency_version: None,
            reachable_from_entrypoint: false,
            classification_confidence: Confidence::High,
            custom_bootstrap_methods: Vec::new(),
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
                archive_id: "archive-0".to_owned(),
                archive_path: "<root>".to_owned(),
                path: "com/example/mod/Net.class".to_owned(),
                class_name: Some("com/example/mod/Net".to_owned()),
                major_version: 65,
                strings: Vec::new(),
                bytecode_refs: vec!["java/net/http/HttpClient".to_owned()],
                methods: Vec::new(),
                scope: CodeScope::FirstParty,
                dependency_name: None,
                dependency_version: None,
                reachable_from_entrypoint: false,
                classification_confidence: Confidence::High,
                custom_bootstrap_methods: Vec::new(),
            },
            ClassScanData {
                archive_id: "archive-0".to_owned(),
                archive_path: "<root>".to_owned(),
                path: "com/example/mod/Loader.class".to_owned(),
                class_name: Some("com/example/mod/Loader".to_owned()),
                major_version: 65,
                strings: Vec::new(),
                bytecode_refs: vec!["java/lang/ClassLoader.defineClass".to_owned()],
                methods: Vec::new(),
                scope: CodeScope::FirstParty,
                dependency_name: None,
                dependency_version: None,
                reachable_from_entrypoint: false,
                classification_confidence: Confidence::High,
                custom_bootstrap_methods: Vec::new(),
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
            archive_id: "archive-0".to_owned(),
            archive_path: "<root>".to_owned(),
            path: "com/example/mod/Loader.class".to_owned(),
            class_name: Some("com/example/mod/Loader".to_owned()),
            major_version: 65,
            strings: vec!["https://example.invalid/payload.jar".to_owned()],
            bytecode_refs: vec![
                "java/net/URL".to_owned(),
                "java/net/URLClassLoader".to_owned(),
            ],
            methods: Vec::new(),
            scope: CodeScope::FirstParty,
            dependency_name: None,
            dependency_version: None,
            reachable_from_entrypoint: false,
            classification_confidence: Confidence::High,
            custom_bootstrap_methods: Vec::new(),
        }]);

        context.add_class_correlation_signals();

        assert!(context
            .data
            .archive_signals
            .contains(&EXTERNAL_URLCLASSLOADER_SIGNAL.to_owned()));
    }

    /// Verifies vendored runtime libraries do not trigger remote-loader correlations.
    #[test]
    fn class_correlation_ignores_known_dependency_classes() {
        let mut context = test_context(vec![ClassScanData {
            archive_id: "archive-0".to_owned(),
            archive_path: "<root>".to_owned(),
            path: "jnr/ffi/provider/jffi/AsmLibraryLoader.class".to_owned(),
            class_name: Some("jnr/ffi/provider/jffi/AsmLibraryLoader".to_owned()),
            major_version: 52,
            strings: Vec::new(),
            bytecode_refs: vec![
                "java/net/URL".to_owned(),
                "java/net/URLClassLoader".to_owned(),
                "java/lang/ClassLoader.defineClass".to_owned(),
            ],
            methods: Vec::new(),
            scope: CodeScope::BundledDependency,
            dependency_name: Some("JNR".to_owned()),
            dependency_version: None,
            reachable_from_entrypoint: false,
            classification_confidence: Confidence::High,
            custom_bootstrap_methods: Vec::new(),
        }]);

        context.add_class_correlation_signals();

        assert!(!context
            .data
            .archive_signals
            .contains(&REMOTE_CLASS_LOADING_SIGNAL.to_owned()));
    }

    #[test]
    fn timestamp_baseline_is_calculated_per_nested_archive() {
        let root_timestamp = zip_timestamp(2024, 1, 1);
        let nested_timestamp = zip_timestamp(2023, 1, 1);
        let nested = zip_bytes(
            (0..20)
                .map(|index| {
                    (
                        format!("dependency-{index}.txt"),
                        nested_timestamp,
                        b"nested".to_vec(),
                    )
                })
                .collect(),
        );
        let mut root_entries = (0..19)
            .map(|index| {
                (
                    format!("root-{index}.txt"),
                    root_timestamp,
                    b"root".to_vec(),
                )
            })
            .collect::<Vec<_>>();
        root_entries.push((
            "META-INF/jars/dependency.jar".to_owned(),
            nested_timestamp,
            nested,
        ));

        let mut context = archive_test_context();
        let root_id = context.create_archive_layer(None, "<root>".to_owned(), 0, false);
        parse_zip_bytes(&zip_bytes(root_entries), &root_id, &mut context).expect("archive parses");
        context.add_timestamp_outlier_signal();

        let root = context
            .data
            .archive_layers
            .iter()
            .find(|layer| layer.id == root_id)
            .expect("root layer exists");
        let nested = context
            .data
            .archive_layers
            .iter()
            .find(|layer| layer.parent_id.as_deref() == Some(root_id.as_str()))
            .expect("nested layer exists");
        assert_eq!(
            root.timestamp_baseline.as_deref(),
            Some("2024-01-01T00:00:00")
        );
        assert_eq!(
            nested.timestamp_baseline.as_deref(),
            Some("2023-01-01T00:00:00")
        );
        assert!(!context
            .data
            .archive_signals
            .contains(&TIMESTAMP_OUTLIER_SIGNAL.to_owned()));
    }

    #[test]
    fn normalized_1980_zip_timestamp_does_not_trigger_outlier() {
        let normalized = zip_timestamp(1980, 1, 1);
        let regular = zip_timestamp(2024, 1, 1);
        let mut entries = (0..20)
            .map(|index| (format!("file-{index}.txt"), normalized, b"content".to_vec()))
            .collect::<Vec<_>>();
        entries.push(("different.txt".to_owned(), regular, b"different".to_vec()));

        let mut context = archive_test_context();
        let root_id = context.create_archive_layer(None, "<root>".to_owned(), 0, false);
        parse_zip_bytes(&zip_bytes(entries), &root_id, &mut context).expect("archive parses");
        context.add_timestamp_outlier_signal();

        assert!(!context
            .data
            .archive_signals
            .contains(&TIMESTAMP_OUTLIER_SIGNAL.to_owned()));
    }

    /// Cosmetics mods ship thousands of textures; only classes and nested archives use the
    /// configured file limit.
    #[test]
    fn file_count_limit_ignores_plain_resources() {
        let timestamp = zip_timestamp(2024, 1, 1);
        let mut context = archive_test_context();
        context.limits.max_total_uncompressed_bytes = 1024;
        context.limits.max_single_file_bytes = 64;
        context.limits.max_files_in_archive = 2;
        let root_id = context.create_archive_layer(None, "<root>".to_owned(), 0, false);
        let assets = (0..10)
            .map(|index| {
                (
                    format!("assets/mod/cosmetics/{index}.png"),
                    timestamp,
                    b"png".to_vec(),
                )
            })
            .collect::<Vec<_>>();

        parse_zip_bytes(&zip_bytes(assets), &root_id, &mut context)
            .expect("resources do not count toward the file limit");
        assert_eq!(context.data.resource_files.len(), 10);

        let mut context = archive_test_context();
        context.limits.max_total_uncompressed_bytes = 1024;
        context.limits.max_single_file_bytes = 64;
        context.limits.max_files_in_archive = 2;
        let root_id = context.create_archive_layer(None, "<root>".to_owned(), 0, false);
        let classes = (0..3)
            .map(|index| (format!("mod/C{index}.class"), timestamp, b"cafe".to_vec()))
            .collect::<Vec<_>>();
        let error = parse_zip_bytes(&zip_bytes(classes), &root_id, &mut context)
            .expect_err("class files count toward the file limit");
        assert_eq!(error.rule_id(), "ZIP_FILE_COUNT_LIMIT");
    }

    #[test]
    fn oversized_entry_is_skipped_without_discarding_other_archive_entries() {
        let timestamp = zip_timestamp(2024, 1, 1);
        let mut context = archive_test_context();
        context.limits.max_single_file_bytes = 4;
        context.limits.max_total_uncompressed_bytes = 64;
        context.limits.max_files_in_archive = 4;
        let root_id = context.create_archive_layer(None, "<root>".to_owned(), 0, false);
        let archive = zip_bytes(vec![
            ("payload.bin".to_owned(), timestamp, b"12345".to_vec()),
            ("safe.txt".to_owned(), timestamp, b"safe".to_vec()),
        ]);

        parse_zip_bytes(&archive, &root_id, &mut context).expect("archive parses safely");

        assert_eq!(context.structural_findings.len(), 1);
        assert_eq!(context.data.resource_files.len(), 1);
        assert_eq!(context.data.resource_files[0].path, "safe.txt");
        assert!(context
            .data
            .normalization_limitations
            .iter()
            .any(|limitation| { limitation.code == "ARCHIVE_ENTRY_SKIPPED_SIZE_LIMIT" }));
    }

    #[test]
    fn confirms_network_backed_in_memory_class_loader() {
        let network = class_scan_data(
            "example/Network",
            vec!["java/net/HttpURLConnection"],
            Vec::new(),
        );
        let loader = class_scan_data(
            "example/InMemoryLoader",
            vec!["java/lang/ClassLoader.defineClass"],
            vec![method_scan_data(
                "example/InMemoryLoader",
                vec![call_site("java/lang/ClassLoader", "defineClass")],
            )],
        );
        let staging = class_scan_data(
            "example/Staging",
            vec!["java/util/jar/JarInputStream"],
            vec![method_scan_data(
                "example/Staging",
                vec![
                    call_site("example/Network", "fetch"),
                    call_site("java/util/jar/JarInputStream", "<init>"),
                    call_site("example/InMemoryLoader", "loadClass"),
                ],
            )],
        );
        let data = ScanData {
            class_files: vec![network, loader, staging],
            ..Default::default()
        };

        let chain = confirmed_remote_memory_load(&data).expect("remote loader is confirmed");

        assert_eq!(chain.rule_id, "CONFIRMED_REMOTE_MEMORY_LOAD");
        assert_eq!(chain.evidence.len(), 3);
        assert_eq!(chain.score_contribution, 80);
        assert_eq!(
            verdict_from_evidence(&[], &[chain], &Obfuscation::default(), 80),
            Verdict::Malicious
        );
    }

    /// Mod-defined invokedynamic bootstraps hide call targets, so the result cannot be clean.
    #[test]
    fn custom_invokedynamic_bootstrap_is_suspicious_outside_dependencies() {
        let bootstrap = BootstrapMethodRef {
            owner: "example/Hidden".to_owned(),
            name: "bootstrap".to_owned(),
            descriptor: "()V".to_owned(),
        };
        let class_with_bootstrap = |scope| ClassScanData {
            class_name: Some("example/Hidden".to_owned()),
            scope,
            custom_bootstrap_methods: vec![bootstrap.clone()],
            ..Default::default()
        };
        let dependency_only = ScanData {
            class_files: vec![class_with_bootstrap(CodeScope::BundledDependency)],
            ..Default::default()
        };
        assert!(custom_invokedynamic_bootstrap_finding(&dependency_only).is_none());

        let first_party = ScanData {
            class_files: vec![class_with_bootstrap(CodeScope::FirstParty)],
            ..Default::default()
        };
        let finding = custom_invokedynamic_bootstrap_finding(&first_party)
            .expect("first-party custom bootstrap is reported");
        assert_eq!(finding.rule_id, CUSTOM_INVOKEDYNAMIC_BOOTSTRAP_RULE_ID);
        assert_eq!(
            finding.evidence[0].value_preview.as_deref(),
            Some("example/Hidden.bootstrap")
        );
        let (verdict, risk_score, _) = finalize_report(&[finding], &[], &Obfuscation::default());
        assert_eq!(verdict, Verdict::Suspicious);
        assert!(risk_score > 5);
    }

    /// A class with a browser credential path and a webhook URL is suspicious even when
    /// the POST is guarded and even when it sits in a declared nested jar; neither string
    /// alone may score.
    #[test]
    fn credential_store_and_webhook_in_one_class_is_suspicious() {
        let class = |strings: &[&str], scope| ClassScanData {
            class_name: Some("hubtest/FakeStealer".to_owned()),
            scope,
            strings: strings.iter().map(|value| (*value).to_owned()).collect(),
            ..Default::default()
        };
        let webhook = "https://discord.com/api/webhooks/123456789012345678/hubtest-not-a-real-hook";
        let store = "Google\\Chrome\\User Data\\Local State";

        let both = ScanData {
            class_files: vec![class(&[store, webhook], CodeScope::FirstParty)],
            ..Default::default()
        };
        let finding = credential_webhook_co_location_finding(&both)
            .expect("credential store and webhook in one class is reported");
        assert_eq!(finding.rule_id, CREDENTIAL_WEBHOOK_CO_LOCATION_RULE_ID);
        let (verdict, risk_score, _) = finalize_report(&[finding], &[], &Obfuscation::default());
        assert_eq!(verdict, Verdict::Suspicious);
        assert!(risk_score >= 80);

        let split_across_classes = ScanData {
            class_files: vec![
                class(&[store], CodeScope::FirstParty),
                class(&[webhook], CodeScope::FirstParty),
            ],
            ..Default::default()
        };
        assert!(credential_webhook_co_location_finding(&split_across_classes).is_none());

        let nested_in_declared_jar = ScanData {
            class_files: vec![class(&[store, webhook], CodeScope::BundledDependency)],
            ..Default::default()
        };
        let finding = credential_webhook_co_location_finding(&nested_in_declared_jar)
            .expect("a stealer hidden in a declared nested jar is reported");
        assert_eq!(finding.scope, CodeScope::BundledDependency);
    }

    /// Mirrors the HubLauncher "2-suspicious" test mod: a guarded updater that fetches a jar
    /// and launches `java -jar` without a confirmed file write.
    #[test]
    fn executable_url_http_client_and_process_launch_in_one_class_is_suspicious() {
        let class = |strings: &[&str], refs: &[&str]| ClassScanData {
            class_name: Some("hubtest/FakeUpdater".to_owned()),
            scope: CodeScope::FirstParty,
            strings: strings.iter().map(|value| (*value).to_owned()).collect(),
            bytecode_refs: refs.iter().map(|value| (*value).to_owned()).collect(),
            ..Default::default()
        };
        let refs = [
            "java/net/URL",
            "java/net/HttpURLConnection",
            "java/lang/ProcessBuilder.start",
        ];
        let updater = ScanData {
            class_files: vec![class(&["https://example.com/update.jar"], &refs)],
            ..Default::default()
        };
        let finding = executable_download_exec_co_location_finding(&updater)
            .expect("executable URL, HTTP client and process launch in one class are reported");
        assert_eq!(
            finding.rule_id,
            EXECUTABLE_DOWNLOAD_EXEC_CO_LOCATION_RULE_ID
        );
        let (verdict, _, _) = finalize_report(&[finding], &[], &Obfuscation::default());
        assert_eq!(verdict, Verdict::Suspicious);

        // A non-executable URL (version check) next to a browser launch is ordinary.
        let version_check = ScanData {
            class_files: vec![class(&["https://example.com/versions.json?jar=1"], &refs)],
            ..Default::default()
        };
        assert!(executable_download_exec_co_location_finding(&version_check).is_none());

        let no_launcher = ScanData {
            class_files: vec![class(
                &["https://example.com/update.jar"],
                &["java/net/URL", "java/net/HttpURLConnection"],
            )],
            ..Default::default()
        };
        assert!(executable_download_exec_co_location_finding(&no_launcher).is_none());
    }

    /// A class that reads the account session or chat events and also opens an HTTP
    /// client is a malicious exfiltration path, even when the call sites are obfuscated.
    #[test]
    fn session_or_chat_with_http_client_in_one_class_is_malicious() {
        let class = |refs: &[&str]| ClassScanData {
            class_name: Some("mezz/jei/ClientLifecycleHandler".to_owned()),
            scope: CodeScope::FirstParty,
            bytecode_refs: refs.iter().map(|value| (*value).to_owned()).collect(),
            ..Default::default()
        };
        let exfil = ScanData {
            class_files: vec![class(&[
                "Lnet/minecraft/util/Session;",
                "java/net/HttpURLConnection",
            ])],
            ..Default::default()
        };
        let finding = session_chat_exfil_co_location_finding(&exfil)
            .expect("session access and HTTP client in one class is reported");
        assert_eq!(finding.rule_id, SESSION_CHAT_EXFIL_CO_LOCATION_RULE_ID);
        let (verdict, _, _) = finalize_report(&[finding], &[], &Obfuscation::default());
        assert_eq!(verdict, Verdict::Malicious);

        let session_only = ScanData {
            class_files: vec![class(&["Lnet/minecraft/util/Session;"])],
            ..Default::default()
        };
        assert!(session_chat_exfil_co_location_finding(&session_only).is_none());

        // URL helpers share a prefix with `java/net/URL` but are not an HTTP client.
        let session_and_url_helper = ScanData {
            class_files: vec![class(&[
                "net/minecraft/client/User",
                "java/net/URLEncoder.encode",
            ])],
            ..Default::default()
        };
        assert!(session_chat_exfil_co_location_finding(&session_and_url_helper).is_none());

        // In a bundled library the co-location is scored, not decisive.
        let mut bundled = session_chat_exfil_co_location_finding(&exfil)
            .expect("session access and HTTP client in one class is reported");
        bundled.scope = CodeScope::BundledDependency;
        let (verdict, _, _) = finalize_report(&[bundled], &[], &Obfuscation::default());
        assert_eq!(verdict, Verdict::Suspicious);
    }

    /// A stealer that hides its webhook POST behind indy/condy bootstraps was
    /// previously reported as clean.
    #[test]
    fn real_custom_bootstrap_stealer_is_not_clean() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let sample = root.join("tests/realmods/jei-7.8.0.1011.jar");
        if !sample.is_file() {
            // The real-mod corpus is intentionally local.
            return;
        }
        let rules = RulesEngine::load_from_file(&root.join("config/rules.yaml"))
            .expect("production rules load");
        let limits = ScanLimits {
            max_total_uncompressed_bytes: 200 * 1024 * 1024,
            max_files_in_archive: 5_000,
            max_nesting_depth: 3,
            max_single_file_bytes: 50 * 1024 * 1024,
        };

        let outcome = scan_file(&sample, limits, &rules);

        assert_eq!(outcome.report.verdict, Verdict::Malicious);
        assert_eq!(outcome.report.obfuscation.level, ObfuscationLevel::High);
        assert!(outcome
            .report
            .findings
            .iter()
            .any(|finding| finding.rule_id == CUSTOM_INVOKEDYNAMIC_BOOTSTRAP_RULE_ID));
    }

    /// Real mods previously received false positives from isolated API, asset, and namespace facts.
    #[test]
    fn real_mods_are_clean_without_confirmed_dangerous_chains() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let corpus = root.join("tests/realmods/clean");
        if !corpus.is_dir() {
            // The real-mod corpus is intentionally local and is not required to
            // build the scanner from a source distribution.
            return;
        }
        let rules = RulesEngine::load_from_file(&root.join("config/rules.yaml"))
            .expect("production rules load");
        let limits = ScanLimits {
            max_total_uncompressed_bytes: 200 * 1024 * 1024,
            max_files_in_archive: 5_000,
            max_nesting_depth: 3,
            max_single_file_bytes: 50 * 1024 * 1024,
        };

        for filename in [
            "Apple Hands.jar",
            "Inv-Collector-v1.21.8-1.10.jar",
            "playerglow.jar",
            "shift tap.jar",
        ] {
            let outcome = scan_file(&corpus.join(filename), limits, &rules);
            assert_eq!(
                outcome.report.verdict,
                Verdict::Clean,
                "{filename}: {:?}",
                outcome.report.findings
            );
            assert!(
                outcome.report.findings.is_empty(),
                "{filename}: {:?}",
                outcome.report.findings
            );
            assert!(outcome.report.confirmed_chains.is_empty(), "{filename}");
        }
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
            code_file_count: 0,
            entry_count: 0,
            data: ScanData {
                class_files,
                entrypoint_classes: vec!["com.example.mod.Loader".to_owned()],
                ..Default::default()
            },
            structural_findings: Vec::new(),
            next_archive_id: 1,
        }
    }

    fn test_call(owner: &str, name: &str) -> CallSite {
        CallSite {
            offset: 8,
            kind: InvokeKind::Virtual,
            owner: Some(owner.to_owned()),
            name: name.to_owned(),
            descriptor: "()V".to_owned(),
            receiver_origin: None,
            argument_origins: Vec::new(),
            result_origin: None,
        }
    }

    fn call_with_origins(
        offset: u32,
        owner: &str,
        name: &str,
        receiver_origin: Option<ValueOrigin>,
        argument_origins: Vec<ValueOrigin>,
        result_origin: Option<ValueOrigin>,
    ) -> CallSite {
        CallSite {
            offset,
            kind: InvokeKind::Virtual,
            owner: Some(owner.to_owned()),
            name: name.to_owned(),
            descriptor: match (owner, name) {
                ("java/lang/String", "toCharArray") => "()[C",
                ("java/lang/String", "<init>") => "([C)V",
                _ => "()V",
            }
            .to_owned(),
            receiver_origin,
            argument_origins,
            result_origin,
        }
    }

    fn class_scan_data(
        class_name: &str,
        bytecode_refs: Vec<&str>,
        methods: Vec<MethodScanData>,
    ) -> ClassScanData {
        ClassScanData {
            archive_id: "archive-0".to_owned(),
            archive_path: "<root>".to_owned(),
            path: format!("{}.class", class_name),
            class_name: Some(class_name.to_owned()),
            major_version: 65,
            strings: Vec::new(),
            bytecode_refs: bytecode_refs.into_iter().map(ToOwned::to_owned).collect(),
            methods,
            scope: CodeScope::FirstParty,
            dependency_name: None,
            dependency_version: None,
            reachable_from_entrypoint: true,
            classification_confidence: Confidence::High,
            custom_bootstrap_methods: Vec::new(),
        }
    }

    fn method_scan_data(class_name: &str, calls: Vec<CallSite>) -> MethodScanData {
        MethodScanData {
            class_name: class_name.to_owned(),
            method_name: "run".to_owned(),
            descriptor: "()V".to_owned(),
            is_static: true,
            instructions: Vec::new(),
            constants: Vec::new(),
            calls,
            field_reads: Vec::new(),
            field_writes: Vec::new(),
            basic_blocks: Vec::new(),
            control_flow_edges: Vec::new(),
            local_origins: Vec::new(),
            stack_origins: Vec::new(),
            return_origins: Vec::new(),
            array_elements: Vec::new(),
            branch_conditions: Vec::new(),
        }
    }

    fn call_site(owner: &str, name: &str) -> CallSite {
        CallSite {
            offset: 0,
            kind: InvokeKind::Virtual,
            owner: Some(owner.to_owned()),
            name: name.to_owned(),
            descriptor: "()V".to_owned(),
            receiver_origin: None,
            argument_origins: Vec::new(),
            result_origin: None,
        }
    }

    fn evidenced_finding(rule_id: &str, category: &str, severity: Severity) -> Finding {
        let mut finding = Finding::legacy(rule_id, category, severity, "evidence-backed");
        finding.evidence.push(Evidence {
            archive_id: "archive-0".to_owned(),
            archive_path: "<root>".to_owned(),
            class_name: Some("example/Mod".to_owned()),
            method_name: Some("run".to_owned()),
            method_descriptor: Some("()V".to_owned()),
            bytecode_offset: Some(0),
            resource_path: None,
            operation: "test".to_owned(),
            value_preview: None,
            source_value: None,
            target_value: None,
            confidence: Confidence::High,
            scope: CodeScope::FirstParty,
        });
        finding
    }

    fn archive_test_context() -> ArchiveContext {
        ArchiveContext {
            limits: ScanLimits {
                max_total_uncompressed_bytes: 1024 * 1024,
                max_files_in_archive: 100,
                max_nesting_depth: 4,
                max_single_file_bytes: 1024 * 1024,
            },
            total_uncompressed_bytes: 0,
            code_file_count: 0,
            entry_count: 0,
            data: ScanData::default(),
            structural_findings: Vec::new(),
            next_archive_id: 0,
        }
    }

    fn zip_timestamp(year: u16, month: u8, day: u8) -> DateTime {
        DateTime::from_date_and_time(year, month, day, 0, 0, 0).expect("valid test timestamp")
    }

    fn zip_bytes(entries: Vec<(String, DateTime, Vec<u8>)>) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut archive = ZipWriter::new(cursor);
        for (path, timestamp, contents) in entries {
            let options = SimpleFileOptions::default().last_modified_time(timestamp);
            archive.start_file(path, options).expect("entry starts");
            archive.write_all(&contents).expect("entry writes");
        }
        archive.finish().expect("archive finishes").into_inner()
    }
}
