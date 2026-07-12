//! Recognizes benign contexts around broad Java API rules.
//!
//! The current parser exposes class-level constants and API references only. A broad rule is
//! therefore suppressed only when one first-party class contains an unambiguous safe value.

use std::collections::HashSet;

use crate::{
    models::scan::{Capability, CodeScope, Confidence, Evidence, Finding, FindingKind, Severity},
    scanner::archive::{ClassScanData, ScanData},
};

const CONFIG_FILE_WRITE_RULE_ID: &str = "CONFIG_FILE_WRITE";
const DESKTOP_BROWSE_STATIC_HTTPS_RULE_ID: &str = "DESKTOP_BROWSE_STATIC_HTTPS";
const DESKTOP_OPEN_CONFIG_DIRECTORY_RULE_ID: &str = "DESKTOP_OPEN_CONFIG_DIRECTORY";
const GENERIC_NAMESPACE_RULE_ID: &str = "GENERIC_OR_UNUSUAL_NAMESPACE";
const THREAD_SLEEP_RULE_ID: &str = "THREAD_SLEEP";
const LONG_SLEEP_RULE_ID: &str = "LONG_SLEEP";

const FILES_WRITE_RULE_ID: &str = "FILES_WRITE";
const DESKTOP_GET_DESKTOP_RULE_ID: &str = "DESKTOP_GET_DESKTOP";
const MODID_PACKAGE_MISMATCH_RULE_ID: &str = "MODID_PACKAGE_MISMATCH";
const SYSTEM_LOAD_RULE_ID: &str = "SYSTEM_LOAD";
const SYSTEM_LOAD_LIBRARY_RULE_ID: &str = "SYSTEM_LOAD_LIBRARY";
const REFLECTION_METHOD_INVOKE_RULE_ID: &str = "REFLECTION_METHOD_INVOKE";

const CONFIG_EXTENSIONS: &[&str] = &[
    ".json",
    ".toml",
    ".yml",
    ".yaml",
    ".properties",
    ".txt",
    ".log",
];

/// Contextual output applied after configurable rules have emitted broad signals.
#[derive(Debug, Default)]
pub struct ContextRecognition {
    pub capabilities: Vec<Capability>,
    pub findings: Vec<Finding>,
    suppressed_rule_ids: HashSet<&'static str>,
}

impl ContextRecognition {
    pub fn suppresses(&self, rule_id: &str) -> bool {
        self.suppressed_rule_ids.contains(rule_id)
    }
}

/// Classifies only safe local contexts. Unknown values intentionally remain rule findings.
pub fn recognize(data: &ScanData) -> ContextRecognition {
    let mut result = ContextRecognition::default();
    let mut emitted_capabilities = HashSet::new();

    // Creating Desktop performs no externally observable operation.
    result
        .suppressed_rule_ids
        .insert(DESKTOP_GET_DESKTOP_RULE_ID);

    // A native library carried in a recognized Java ecosystem path is a normal
    // loader pattern. The separate native analyzer supplies exact resource evidence.
    if !data.embedded_native_capabilities.is_empty() {
        result.suppressed_rule_ids.insert(SYSTEM_LOAD_RULE_ID);
        result
            .suppressed_rule_ids
            .insert(SYSTEM_LOAD_LIBRARY_RULE_ID);
    }

    recognize_config_writes(data, &mut result, &mut emitted_capabilities);
    for class_file in first_party_classes(data) {
        recognize_desktop_usage(class_file, &mut result, &mut emitted_capabilities);
        recognize_sleep(class_file, &mut result, &mut emitted_capabilities);
        recognize_neutral_java_capabilities(class_file, &mut result, &mut emitted_capabilities);
    }

    for layer in data
        .archive_layers
        .iter()
        .filter(|layer| layer.declared_dependency)
    {
        push_capability_once(
            &mut result.capabilities,
            &mut emitted_capabilities,
            "NESTED_DEPENDENCY",
            "Мод содержит явно объявленную вложенную зависимость.",
            vec![Evidence {
                archive_id: layer.id.clone(),
                archive_path: layer.path.clone(),
                class_name: None,
                method_name: None,
                method_descriptor: None,
                bytecode_offset: None,
                resource_path: None,
                operation: "nested_dependency".to_owned(),
                value_preview: None,
                scope: CodeScope::BundledDependency,
            }],
        );
    }

    if data
        .archive_signals
        .iter()
        .any(|signal| signal == "modid_package_mismatch")
    {
        result
            .suppressed_rule_ids
            .insert(MODID_PACKAGE_MISMATCH_RULE_ID);
        push_capability_once(
            &mut result.capabilities,
            &mut emitted_capabilities,
            GENERIC_NAMESPACE_RULE_ID,
            "Обнаружен необычный namespace классов; это признак качества кода, а не угрозы.",
            namespace_evidence(data),
        );
    }

    result
}

fn recognize_neutral_java_capabilities(
    class_file: &ClassScanData,
    result: &mut ContextRecognition,
    emitted_capabilities: &mut HashSet<String>,
) {
    if has_ref(class_file, "java/lang/reflect/Method.invoke") {
        result
            .suppressed_rule_ids
            .insert(REFLECTION_METHOD_INVOKE_RULE_ID);
        push_capability_once(
            &mut result.capabilities,
            emitted_capabilities,
            "REFLECTION",
            "Мод использует Java reflection.",
            vec![class_evidence(class_file, "reflection", None)],
        );
    }
    if has_ref(class_file, "java/util/Base64") || has_ref(class_file, "Base64.getDecoder") {
        push_capability_once(
            &mut result.capabilities,
            emitted_capabilities,
            "BASE64",
            "Мод использует Base64-преобразования.",
            vec![class_evidence(class_file, "base64", None)],
        );
    }
    if has_ref(class_file, "java/lang/ProcessBuilder") {
        push_capability_once(
            &mut result.capabilities,
            emitted_capabilities,
            "PROCESS_BUILDER",
            "Мод использует ProcessBuilder; запуск не подтверждён анализом потока данных.",
            vec![class_evidence(class_file, "process_builder", None)],
        );
    }
}

fn first_party_classes(data: &ScanData) -> impl Iterator<Item = &ClassScanData> {
    data.class_files
        .iter()
        .filter(|class_file| class_file.scope == CodeScope::FirstParty)
}

fn recognize_config_writes(
    data: &ScanData,
    result: &mut ContextRecognition,
    emitted_capabilities: &mut HashSet<String>,
) {
    let writes = first_party_classes(data)
        .filter(|class_file| has_ref(class_file, "java/nio/file/Files.write"))
        .collect::<Vec<_>>();
    if writes.is_empty() {
        return;
    }

    let mut all_writes_are_safe = true;
    for class_file in writes {
        let Some(path) = class_file
            .strings
            .iter()
            .find(|value| is_safe_config_path(value))
        else {
            all_writes_are_safe = false;
            continue;
        };

        push_capability_once(
            &mut result.capabilities,
            emitted_capabilities,
            CONFIG_FILE_WRITE_RULE_ID,
            "Мод сохраняет конфигурационный файл в config/.",
            vec![class_evidence(class_file, "files_write", Some(path))],
        );
    }

    if all_writes_are_safe {
        result.suppressed_rule_ids.insert(FILES_WRITE_RULE_ID);
    }
}

fn recognize_desktop_usage(
    class_file: &ClassScanData,
    result: &mut ContextRecognition,
    emitted_capabilities: &mut HashSet<String>,
) {
    if has_ref(class_file, "java/awt/Desktop.browse") {
        if let Some(url) = class_file
            .strings
            .iter()
            .find(|value| is_static_https_url(value))
        {
            push_capability_once(
                &mut result.capabilities,
                emitted_capabilities,
                DESKTOP_BROWSE_STATIC_HTTPS_RULE_ID,
                "Мод открывает статическую HTTPS-ссылку через Desktop API.",
                vec![class_evidence(class_file, "desktop_browse", Some(url))],
            );
        }
    }

    if has_ref(class_file, "java/awt/Desktop.open") {
        if let Some(path) = class_file
            .strings
            .iter()
            .find(|value| is_config_directory(value))
        {
            push_capability_once(
                &mut result.capabilities,
                emitted_capabilities,
                DESKTOP_OPEN_CONFIG_DIRECTORY_RULE_ID,
                "Мод открывает каталог конфигурации через Desktop API.",
                vec![class_evidence(class_file, "desktop_open", Some(path))],
            );
        }
    }
}

fn recognize_sleep(
    class_file: &ClassScanData,
    result: &mut ContextRecognition,
    emitted_capabilities: &mut HashSet<String>,
) {
    if !has_ref(class_file, "java/lang/Thread.sleep") {
        return;
    }

    result.suppressed_rule_ids.insert(LONG_SLEEP_RULE_ID);
    match sleep_tier(extract_sleep_duration(class_file)) {
        SleepTier::Ignore => {}
        SleepTier::Capability => push_capability_once(
            &mut result.capabilities,
            emitted_capabilities,
            THREAD_SLEEP_RULE_ID,
            "Мод использует короткую паузу Thread.sleep.",
            vec![class_evidence(class_file, "thread_sleep", None)],
        ),
        SleepTier::WeakFinding => result.findings.push(weak_sleep_finding(class_file)),
        SleepTier::ContextRequired => push_capability_once(
            &mut result.capabilities,
            emitted_capabilities,
            THREAD_SLEEP_RULE_ID,
            "Мод использует Thread.sleep; длительная или неразрешённая пауза без anti-sandbox контекста сама по себе не является угрозой.",
            vec![class_evidence(class_file, "thread_sleep", None)],
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SleepTier {
    Ignore,
    Capability,
    WeakFinding,
    ContextRequired,
}

fn sleep_tier(duration_millis: Option<u64>) -> SleepTier {
    match duration_millis {
        Some(0..=999) => SleepTier::Ignore,
        Some(1_000..=10_000) => SleepTier::Capability,
        Some(10_001..=30_000) => SleepTier::WeakFinding,
        Some(_) | None => SleepTier::ContextRequired,
    }
}

/// Supports fixture-compatible explicit constants until the method-level parser retains numeric
/// bytecode operands. Unknown durations remain an informational capability, never a risk score.
fn extract_sleep_duration(class_file: &ClassScanData) -> Option<u64> {
    class_file.strings.iter().find_map(|value| {
        let lower = value.to_ascii_lowercase();
        let digits = lower
            .strip_prefix("sleep_ms=")
            .or_else(|| lower.strip_prefix("sleep_millis="))?;
        digits.parse().ok()
    })
}

fn weak_sleep_finding(class_file: &ClassScanData) -> Finding {
    Finding {
        rule_id: LONG_SLEEP_RULE_ID.to_owned(),
        category: "evasion".to_owned(),
        kind: FindingKind::Heuristic,
        severity: Severity::Low,
        confidence: Confidence::Low,
        score_contribution: Severity::Low.score_weight(),
        scope: class_file.scope.clone(),
        message:
            "Обнаружена пауза Thread.sleep длительностью 10–30 секунд без достаточного контекста."
                .to_owned(),
        evidence: vec![class_evidence(class_file, "thread_sleep", None)],
        related_chain_id: None,
    }
}

fn has_ref(class_file: &ClassScanData, reference: &str) -> bool {
    class_file
        .bytecode_refs
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(reference))
}

fn is_safe_config_path(value: &str) -> bool {
    let normalized = value.replace('\\', "/").to_ascii_lowercase();
    let is_config_path = normalized.starts_with("config/")
        || normalized.contains("/config/")
        || normalized.starts_with("<fabric_config_dir>/");
    is_config_path
        && CONFIG_EXTENSIONS
            .iter()
            .any(|extension| normalized.ends_with(extension))
}

fn is_config_directory(value: &str) -> bool {
    let normalized = value.replace('\\', "/").to_ascii_lowercase();
    normalized == "config" || normalized.ends_with("/config") || normalized == "<fabric_config_dir>"
}

fn is_static_https_url(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("https://")
        && !trimmed.contains('{')
        && !trimmed.contains('}')
        && !trimmed.contains('+')
        && !trimmed.contains('$')
        && !trimmed.chars().any(char::is_whitespace)
}

fn push_capability_once(
    capabilities: &mut Vec<Capability>,
    emitted_capabilities: &mut HashSet<String>,
    rule_id: &'static str,
    message: &'static str,
    evidence: Vec<Evidence>,
) {
    if emitted_capabilities.insert(rule_id.to_owned()) {
        capabilities.push(Capability {
            rule_id: rule_id.to_owned(),
            message: message.to_owned(),
            evidence,
        });
    }
}

fn class_evidence(
    class_file: &ClassScanData,
    operation: &str,
    value_preview: Option<&str>,
) -> Evidence {
    Evidence {
        archive_id: class_file.archive_id.clone(),
        archive_path: class_file.archive_path.clone(),
        class_name: class_file.class_name.clone(),
        method_name: None,
        method_descriptor: None,
        bytecode_offset: None,
        resource_path: Some(class_file.path.clone()),
        operation: operation.to_owned(),
        value_preview: value_preview.map(ToOwned::to_owned),
        scope: class_file.scope.clone(),
    }
}

fn namespace_evidence(data: &ScanData) -> Vec<Evidence> {
    data.class_files
        .iter()
        .find(|class_file| class_file.scope == CodeScope::FirstParty)
        .map(|class_file| class_evidence(class_file, "namespace_classification", None))
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{recognize, sleep_tier, SleepTier};
    use crate::{
        models::scan::{CodeScope, Confidence},
        scanner::archive::{ClassScanData, ScanData},
    };

    fn class(refs: &[&str], strings: &[&str]) -> ClassScanData {
        ClassScanData {
            archive_id: "archive-0".to_owned(),
            archive_path: "<root>".to_owned(),
            path: "example/Mod.class".to_owned(),
            class_name: Some("example/Mod".to_owned()),
            major_version: 52,
            strings: strings.iter().map(|value| (*value).to_owned()).collect(),
            bytecode_refs: refs.iter().map(|value| (*value).to_owned()).collect(),
            methods: Vec::new(),
            scope: CodeScope::FirstParty,
            dependency_name: None,
            dependency_version: None,
            reachable_from_entrypoint: true,
            classification_confidence: Confidence::High,
        }
    }

    #[test]
    fn config_write_is_a_capability_and_suppresses_broad_rule() {
        let data = ScanData {
            class_files: vec![class(
                &["java/nio/file/Files.write"],
                &["config/example/settings.json"],
            )],
            ..Default::default()
        };

        let recognition = recognize(&data);

        assert!(recognition.suppresses("FILES_WRITE"));
        assert_eq!(recognition.capabilities[0].rule_id, "CONFIG_FILE_WRITE");
    }

    #[test]
    fn unsafe_write_keeps_the_broad_rule_even_when_another_write_is_config() {
        let data = ScanData {
            class_files: vec![
                class(
                    &["java/nio/file/Files.write"],
                    &["config/example/settings.json"],
                ),
                class(&["java/nio/file/Files.write"], &["payload.exe"]),
            ],
            ..Default::default()
        };

        let recognition = recognize(&data);

        assert!(!recognition.suppresses("FILES_WRITE"));
        assert!(recognition
            .capabilities
            .iter()
            .any(|capability| capability.rule_id == "CONFIG_FILE_WRITE"));
    }

    #[test]
    fn static_https_desktop_browse_is_a_capability() {
        let data = ScanData {
            class_files: vec![class(
                &["java/awt/Desktop.getDesktop", "java/awt/Desktop.browse"],
                &["https://wiki.example.invalid/mod"],
            )],
            ..Default::default()
        };

        let recognition = recognize(&data);

        assert!(recognition.suppresses("DESKTOP_GET_DESKTOP"));
        assert!(recognition
            .capabilities
            .iter()
            .any(|capability| capability.rule_id == "DESKTOP_BROWSE_STATIC_HTTPS"));
    }

    #[test]
    fn sleep_thresholds_follow_the_documented_tiers() {
        assert_eq!(sleep_tier(Some(999)), SleepTier::Ignore);
        assert_eq!(sleep_tier(Some(1_000)), SleepTier::Capability);
        assert_eq!(sleep_tier(Some(10_001)), SleepTier::WeakFinding);
        assert_eq!(sleep_tier(Some(30_001)), SleepTier::ContextRequired);
        assert_eq!(sleep_tier(None), SleepTier::ContextRequired);
    }

    #[test]
    fn intermediate_sleep_is_a_weak_finding() {
        let data = ScanData {
            class_files: vec![class(&["java/lang/Thread.sleep"], &["sleep_ms=15000"])],
            ..Default::default()
        };

        let recognition = recognize(&data);

        assert!(recognition.suppresses("LONG_SLEEP"));
        assert_eq!(recognition.findings.len(), 1);
    }

    #[test]
    fn namespace_mismatch_is_a_zero_score_capability() {
        let data = ScanData {
            archive_signals: vec!["modid_package_mismatch".to_owned()],
            class_files: vec![class(&[], &[])],
            ..Default::default()
        };

        let recognition = recognize(&data);

        assert!(recognition.suppresses("MODID_PACKAGE_MISMATCH"));
        assert_eq!(
            recognition.capabilities[0].rule_id,
            "GENERIC_OR_UNUSUAL_NAMESPACE"
        );
    }
}
