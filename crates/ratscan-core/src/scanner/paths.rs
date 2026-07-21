//! Symbolic normalization for paths observed in static strings.
//!
//! The scanner deliberately represents environment-dependent roots symbolically
//! instead of inventing a host-specific absolute path.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymbolicPath {
    pub canonical: String,
}

/// Normalizes equivalent Java and Windows path spellings into a stable symbolic form.
pub fn normalize_symbolic_path(value: &str) -> Option<SymbolicPath> {
    let mut value = value.trim().replace('\\', "/");
    if value.is_empty() {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    if lower.contains("system.getenv(\"appdata\")") || lower.contains("system.getenv('appdata')") {
        value = value.replacen("System.getenv(\"APPDATA\")", "AppData", 1);
        value = value.replacen("System.getenv('APPDATA')", "AppData", 1);
    }
    let mut canonical = value
        .replace("%APPDATA%", "AppData")
        .replace("%appdata%", "AppData")
        .replace("${user.home}", "UserHome")
        .replace("${USER.HOME}", "UserHome")
        .replace("Paths.get(userHome, \".minecraft\")", "UserHome/.minecraft")
        .replace("Paths.get(userHome,'.minecraft')", "UserHome/.minecraft");
    let lower = canonical.to_ascii_lowercase();
    if let Some(index) = lower.find("/appdata/") {
        canonical = format!("AppData/{}", &canonical[index + "/appdata/".len()..]);
    } else if lower.starts_with("config/") {
        canonical = format!("Minecraft/{}", canonical);
    } else if lower.starts_with(".minecraft/") {
        canonical = format!("UserHome/{}", canonical);
    } else if lower.starts_with("%temp%/") || lower.starts_with("${java.io.tmpdir}/") {
        canonical = format!(
            "Temp/{}",
            canonical
                .split_once('/')
                .map(|(_, tail)| tail)
                .unwrap_or("")
        );
    }
    canonical = canonical
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/");
    (!canonical.is_empty()).then_some(SymbolicPath { canonical })
}

#[cfg(test)]
mod tests {
    use super::normalize_symbolic_path;

    #[test]
    fn normalizes_environment_and_separator_variants() {
        assert_eq!(
            normalize_symbolic_path(
                r"C:\\Users\\User\\AppData\\Roaming\\discord\\Local Storage\\leveldb"
            )
            .expect("path normalizes")
            .canonical,
            "AppData/Roaming/discord/Local Storage/leveldb"
        );
        assert_eq!(
            normalize_symbolic_path("%APPDATA%/discord/Local Storage/leveldb")
                .expect("path normalizes")
                .canonical,
            "AppData/discord/Local Storage/leveldb"
        );
        assert_eq!(
            normalize_symbolic_path("Paths.get(userHome, \".minecraft\")/config/example.json")
                .expect("path normalizes")
                .canonical,
            "UserHome/.minecraft/config/example.json"
        );
    }
}
