const METADATA_FILES: &[&str] = &[
    "META-INF/MANIFEST.MF",
    "fabric.mod.json",
    "META-INF/mods.toml",
    "mods.toml",
    "plugin.yml",
];

/// Returns true for known Minecraft/plugin metadata files that are valuable to scan as text.
pub fn is_metadata_file(path: &str) -> bool {
    METADATA_FILES
        .iter()
        .any(|metadata_path| path.eq_ignore_ascii_case(metadata_path))
}

/// Extracts manifest-style field names and raw metadata text for rules.
pub fn extract_metadata(path: &str, bytes: &[u8]) -> (Vec<String>, Vec<String>) {
    let text = String::from_utf8_lossy(bytes).to_string();
    let mut fields = vec![path.to_owned()];

    for line in text.lines() {
        if let Some((field_name, _)) = line.split_once(':') {
            fields.push(field_name.trim().to_owned());
        }
    }

    (fields, vec![text])
}
