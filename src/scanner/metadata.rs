const METADATA_FILES: &[&str] = &[
    "META-INF/MANIFEST.MF",
    "fabric.mod.json",
    "META-INF/mods.toml",
    "mods.toml",
    "mcmod.info",
    "plugin.yml",
];

const MANIFEST_EXTERNAL_CLASS_PATH_SIGNAL: &str = "manifest_external_class_path";
const MIXIN_METADATA_SIGNAL: &str = "mixin_metadata_present";

/// Returns true for known Minecraft/plugin metadata files that are valuable to scan as text.
pub fn is_metadata_file(path: &str) -> bool {
    METADATA_FILES
        .iter()
        .any(|metadata_path| path.eq_ignore_ascii_case(metadata_path))
}

/// Metadata indicators extracted from manifest and mod descriptor files.
#[derive(Debug, Default)]
pub struct MetadataData {
    pub manifest_fields: Vec<String>,
    pub strings: Vec<String>,
    pub mod_ids: Vec<String>,
    pub mod_aliases: Vec<String>,
    pub entrypoint_classes: Vec<String>,
    pub archive_signals: Vec<String>,
}

/// Extracts manifest-style fields, raw text, mod ids, and contextual modloader hints.
pub fn extract_metadata(path: &str, text: &str) -> MetadataData {
    let mut data = MetadataData {
        manifest_fields: vec![path.to_owned()],
        strings: vec![text.to_owned()],
        mod_ids: Vec::new(),
        mod_aliases: Vec::new(),
        entrypoint_classes: Vec::new(),
        archive_signals: Vec::new(),
    };

    for line in text.lines() {
        if let Some((field_name, _)) = line.split_once(':') {
            let field_name = field_name.trim();
            data.manifest_fields.push(field_name.to_owned());
        }
    }

    if path.eq_ignore_ascii_case("META-INF/MANIFEST.MF") {
        extract_manifest_signals(&text, &mut data);
    }
    extract_mod_ids(path, &text, &mut data);
    if has_mixin_metadata(path, &text) {
        data.archive_signals.push(MIXIN_METADATA_SIGNAL.to_owned());
    }

    data
}

fn extract_manifest_signals(text: &str, data: &mut MetadataData) {
    for line in text.lines() {
        let Some((field_name, value)) = line.split_once(':') else {
            continue;
        };
        if field_name.eq_ignore_ascii_case("Class-Path") && contains_external_path(value.trim()) {
            data.archive_signals
                .push(MANIFEST_EXTERNAL_CLASS_PATH_SIGNAL.to_owned());
        }
    }
}

fn contains_external_path(value: &str) -> bool {
    value.split_whitespace().any(|path| {
        path.starts_with('/')
            || path.starts_with('\\')
            || path.contains("../")
            || path.contains("..\\")
            || path
                .as_bytes()
                .get(1)
                .is_some_and(|separator| *separator == b':')
    })
}

fn extract_mod_ids(path: &str, text: &str, data: &mut MetadataData) {
    let lower_path = path.to_ascii_lowercase();
    if lower_path.ends_with("fabric.mod.json") || lower_path.ends_with("mcmod.info") {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            collect_json_mod_ids(&value, data);
        }
        if lower_path.ends_with("fabric.mod.json") {
            return;
        }
    }

    for key in ["modId", "modid", "id"] {
        let pattern = format!("{key}=");
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(value) = trimmed.strip_prefix(&pattern) {
                data.mod_ids
                    .push(value.trim_matches(['"', '\'', ' ', '\t']).to_owned());
            }
        }
    }
}

fn collect_json_mod_ids(value: &serde_json::Value, data: &mut MetadataData) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                if matches!(key.as_str(), "id" | "modid" | "modId") {
                    if let Some(id) = value.as_str() {
                        data.mod_ids.push(id.to_owned());
                    }
                }
                if key == "provides" {
                    collect_string_array(value, &mut data.mod_aliases);
                }
                if key == "entrypoints" {
                    collect_json_strings(value, &mut data.entrypoint_classes);
                }
                collect_json_mod_ids(value, data);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_json_mod_ids(value, data);
            }
        }
        _ => {}
    }
}

fn collect_string_array(value: &serde_json::Value, output: &mut Vec<String>) {
    if let serde_json::Value::Array(values) = value {
        for value in values {
            if let Some(text) = value.as_str() {
                output.push(text.to_owned());
            }
        }
    }
}

fn collect_json_strings(value: &serde_json::Value, output: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => output.push(text.to_owned()),
        serde_json::Value::Array(values) => {
            for value in values {
                collect_json_strings(value, output);
            }
        }
        serde_json::Value::Object(object) => {
            for value in object.values() {
                collect_json_strings(value, output);
            }
        }
        _ => {}
    }
}

fn has_mixin_metadata(path: &str, text: &str) -> bool {
    let lower_path = path.to_ascii_lowercase();
    lower_path.contains("mixin")
        || text.contains("\"mixins\"")
        || text.contains("mixinConfigs")
        || text.contains("MixinConfigs")
}
