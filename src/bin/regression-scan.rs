//! Runs the static scanner against small, synthetic regression fixtures.
//!
//! The fixtures contain only metadata and deliberately inert class files. The
//! scanner never loads classes or native files; this binary only writes the
//! fixture archives into a temporary directory and scans their bytes.

// This standalone binary imports scanner modules directly until the application
// exposes a library crate; the API-only model types are intentionally unused.
#![allow(dead_code)]

#[path = "../models/mod.rs"]
mod models;
#[path = "../rules/mod.rs"]
mod rules;
#[path = "../scanner/mod.rs"]
mod scanner;

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

use serde::Deserialize;
use zip::{write::SimpleFileOptions, ZipWriter};

use crate::{
    models::scan::Verdict,
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
    scenario: Scenario,
    expected_verdict: ExpectedVerdict,
    risk_score: ScoreRange,
    #[serde(default)]
    required_findings: Vec<String>,
    #[serde(default)]
    forbidden_findings: Vec<String>,
    #[serde(default)]
    expected_capabilities: Vec<String>,
    expected_obfuscation_level: crate::models::scan::ObfuscationLevel,
}

#[derive(Clone, Copy, Debug, Deserialize)]
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
    let archive_path = temporary_directory.path().join(GENERATED_JAR_NAME);
    if let Err(error) = materialize_fixture(&archive_path, spec.scenario) {
        errors.push(format!(
            "could not generate safe fixture archive: {error:#}"
        ));
        return FixtureResult {
            name: spec.name.clone(),
            errors,
            limitations,
        };
    }

    let outcome = archive::scan_file(&archive_path, default_limits(), rules);
    errors.extend(assert_report(spec, &outcome));
    limitations.push(format!(
        "fixture source: {} (generated at scan time; no code was executed)",
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
        &minimal_class(
            FIXTURE_CLASS_NAME,
            &definition.references,
            &definition.strings,
        ),
        options,
    )?;
    for (path, bytes) in definition.resources {
        write_entry(&mut archive, path, bytes, options)?;
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
    references: Vec<&'static str>,
    strings: Vec<&'static str>,
    resources: Vec<(&'static str, &'static [u8])>,
}

impl From<Scenario> for ScenarioDefinition {
    fn from(scenario: Scenario) -> Self {
        match scenario {
            Scenario::ConfigWrite => Self {
                references: vec!["java/nio/file/Files.write"],
                strings: vec!["config/regressionfixture.json", "{}"],
                resources: Vec::new(),
            },
            Scenario::DesktopBrowse => Self {
                references: vec!["java/awt/Desktop.getDesktop", "java/awt/Desktop.browse"],
                strings: vec!["https://wiki.example.invalid/regression"],
                resources: Vec::new(),
            },
            Scenario::FatJarDependencies => Self {
                references: vec!["java/lang/reflect/Method.invoke", "java/util/Base64"],
                strings: Vec::new(),
                resources: vec![
                    ("META-INF/jars/jna-5.14.0.jar", empty_jar_bytes()),
                    ("META-INF/jars/zip4j-2.11.5.jar", empty_jar_bytes()),
                    ("jni/jffi/jnidispatch.dll", b"MZsafe-known-dependency"),
                ],
            },
            Scenario::DiscordRpc => Self {
                references: vec!["java/lang/System.loadLibrary", "java/lang/ProcessBuilder"],
                strings: vec!["discord-rpc", "media player integration"],
                resources: vec![(
                    "mediaplayerinfo/natives/discord-rpc.dll",
                    b"MZsafe-discord-fixture",
                )],
            },
            Scenario::AutoUpdater => Self {
                references: vec![
                    "java/net/http/HttpClient",
                    "java/nio/file/Files.write",
                    "java/lang/ProcessBuilder",
                ],
                strings: vec!["https://updates.example.invalid/mod.jar", "mod-update.jar"],
                resources: Vec::new(),
            },
            Scenario::ObfuscatedClean => Self {
                references: vec!["java/util/Base64"],
                strings: vec!["a", "b", "c", "configuration value"],
                resources: Vec::new(),
            },
            Scenario::ObfuscatedLoader => Self {
                references: vec![
                    "java/net/http/HttpClient",
                    "java/nio/file/Files.write",
                    "java/lang/Runtime.exec",
                ],
                strings: vec!["xor-decoded:https://updates.example.invalid/payload.jar"],
                resources: Vec::new(),
            },
            Scenario::CredentialStealer => Self {
                references: vec![
                    "java/net/http/HttpClient",
                    "java/nio/file/Files.readAllBytes",
                ],
                strings: vec![
                    "discord/Local Storage/leveldb",
                    "https://collector.example.invalid/upload",
                ],
                resources: Vec::new(),
            },
        }
    }
}

fn empty_jar_bytes() -> &'static [u8] {
    // A stored ZIP with no entries. It is data only and is never executed.
    b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
}

/// Builds an intentionally minimal class file with symbolic method references.
///
/// The class contains no method bodies, so it cannot execute. The symbolic
/// references are sufficient for the existing constant-pool scanner and make
/// the fixture format ready for a later method-level fixture upgrade.
fn minimal_class(class_name: &str, references: &[&str], strings: &[&str]) -> Vec<u8> {
    let mut pool = ConstantPoolBuilder::default();
    let this_name = pool.utf8(class_name);
    let this_class = pool.class(this_name);
    let object_name = pool.utf8("java/lang/Object");
    let object_class = pool.class(object_name);
    for value in strings {
        pool.utf8(value);
    }
    for reference in references {
        let (class_name, method_name) = reference
            .rsplit_once('.')
            .unwrap_or((*reference, "fixtureCall"));
        let owner_name = pool.utf8(class_name);
        let owner = pool.class(owner_name);
        let member_name = pool.utf8(method_name);
        let descriptor = pool.utf8("()V");
        let name_and_type = pool.name_and_type(member_name, descriptor);
        pool.method_ref(owner, name_and_type);
    }

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
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::scan::{
        Capability, Confidence, Finding, Obfuscation, ObfuscationLevel, ScanReport,
    };
    use tempfile::TempDir;

    #[test]
    fn every_fixture_spec_is_well_formed_and_materializes_to_a_safe_zip() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_FIXTURES_ROOT);
        let specs = load_fixture_specs(&root).expect("fixture specifications load");
        assert_eq!(specs.len(), 8, "the minimum planned corpus has eight cases");

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
            materialize_fixture(&archive_path, spec.scenario)
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
            scenario: Scenario::ConfigWrite,
            expected_verdict: ExpectedVerdict::One(Verdict::Clean),
            risk_score: ScoreRange { min: 0, max: 3 },
            required_findings: vec!["REQUIRED".to_owned()],
            forbidden_findings: vec!["FORBIDDEN".to_owned()],
            expected_capabilities: vec!["CONFIG_FILE_WRITE".to_owned()],
            expected_obfuscation_level: ObfuscationLevel::None,
        };
        let finding = Finding::legacy(
            "REQUIRED",
            "test",
            crate::models::scan::Severity::Low,
            String::new(),
        );
        let outcome = ScanOutcome {
            report: ScanReport {
                verdict: Verdict::Clean,
                risk_score: 0,
                confidence: Confidence::High,
                capabilities: vec![Capability {
                    rule_id: "CONFIG_FILE_WRITE".to_owned(),
                    message: String::new(),
                    evidence: Vec::new(),
                }],
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
}
