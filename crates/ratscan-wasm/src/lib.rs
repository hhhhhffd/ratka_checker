//! Browser build of the static scanner: the jar never leaves the user's machine.
//!
//! Rules are embedded at compile time from `config/rules.yaml`, so a wasm build
//! always matches the rule set of the commit it was built from.
//!
//! Build (wasm-bindgen-cli must match the `wasm-bindgen` version in Cargo.lock):
//! `cargo build -p ratscan-wasm --target wasm32-unknown-unknown --release`, then
//! `wasm-bindgen --target web --out-dir pkg target/wasm32-unknown-unknown/release/ratscan_wasm.wasm`.

use std::sync::OnceLock;

use ratscan_core::{
    rules::engine::RulesEngine,
    scanner::archive::{scan_jar_bytes, ScanLimits},
};
use ratscan_models::scan::ScanReport;
use serde::Serialize;
use wasm_bindgen::prelude::*;

const RULES_YAML: &str = include_str!("../../../config/rules.yaml");

/// Mirrors the API server defaults in `src/config.rs`.
const LIMITS: ScanLimits = ScanLimits {
    max_total_uncompressed_bytes: 200 * 1024 * 1024,
    max_files_in_archive: 5_000,
    max_nesting_depth: 3,
    max_single_file_bytes: 50 * 1024 * 1024,
};

static RULES: OnceLock<Result<RulesEngine, String>> = OnceLock::new();

#[derive(Serialize)]
struct BrowserScanResult {
    summary: String,
    report: ScanReport,
}

/// Scans jar bytes and returns the report as a JSON string.
#[wasm_bindgen]
pub fn scan(bytes: &[u8]) -> Result<String, JsError> {
    scan_to_json(bytes).map_err(|message| JsError::new(&message))
}

fn scan_to_json(bytes: &[u8]) -> Result<String, String> {
    let rules = RULES
        .get_or_init(|| {
            RulesEngine::from_yaml(RULES_YAML).map_err(|error| format!("invalid rules: {error}"))
        })
        .as_ref()?;
    let outcome = scan_jar_bytes(bytes, LIMITS, rules);
    serde_json::to_string(&BrowserScanResult {
        summary: outcome.summary,
        report: outcome.report,
    })
    .map_err(|error| format!("failed to serialize report: {error}"))
}

#[cfg(test)]
mod tests {
    use super::scan_to_json;

    #[test]
    fn embedded_rules_load_and_invalid_jar_yields_unknown_report() {
        let json = scan_to_json(b"not a zip").expect("scan must produce a report");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

        assert_eq!(value["report"]["verdict"], "unknown");
    }
}
