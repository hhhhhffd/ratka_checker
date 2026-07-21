//! Static native-library identification.
//!
//! This module only examines archive entry names and bytes. It never loads a
//! library, extracts it to disk, or invokes platform tooling.

/// Executable format recognized from a file signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFormat {
    Pe,
    Elf,
    MachO32,
    MachO64,
}

/// A well-known Java ecosystem native library family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownNativeLibrary {
    Jna,
    Lwjgl,
    DiscordRpc,
}

/// Static classification of a native archive entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeFileAnalysis {
    pub format: NativeFormat,
    /// A recognized dependency loader path is a capability candidate, not a
    /// security finding by itself.
    pub known_library: Option<KnownNativeLibrary>,
}

/// Inspects native magic bytes and classifies a known dependency path.
///
/// `None` means the byte slice does not begin with a supported native format.
pub fn inspect_native_file(path: &str, bytes: &[u8]) -> Option<NativeFileAnalysis> {
    Some(NativeFileAnalysis {
        format: native_format(bytes)?,
        known_library: classify_known_native_path(path),
    })
}

/// Returns the native format identified by the leading magic bytes.
pub fn native_format(bytes: &[u8]) -> Option<NativeFormat> {
    if bytes.starts_with(b"MZ") {
        Some(NativeFormat::Pe)
    } else if bytes.starts_with(b"\x7fELF") {
        Some(NativeFormat::Elf)
    } else if bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
    {
        Some(NativeFormat::MachO32)
    } else if bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
    {
        Some(NativeFormat::MachO64)
    } else {
        None
    }
}

/// Recognizes native files conventionally shipped by JNA, LWJGL, and Discord
/// RPC integrations. Paths are normalized locally so ZIP entry casing cannot
/// affect the result.
pub fn classify_known_native_path(path: &str) -> Option<KnownNativeLibrary> {
    let path = path.replace('\\', "/").to_ascii_lowercase();

    if is_discord_rpc_path(&path) {
        Some(KnownNativeLibrary::DiscordRpc)
    } else if is_jna_path(&path) {
        Some(KnownNativeLibrary::Jna)
    } else if is_lwjgl_path(&path) {
        Some(KnownNativeLibrary::Lwjgl)
    } else {
        None
    }
}

fn is_jna_path(path: &str) -> bool {
    path.contains("jnidispatch")
        || path.starts_with("com/sun/jna/")
        || path.starts_with("jna/")
        // jffi is the native FFI runtime commonly bundled alongside JNA-like
        // Java libraries. Retain compatibility with the scanner's old safe
        // path recognition while treating it as the same capability family.
        || (path.starts_with("jni/") && path.contains("jffi"))
}

fn is_lwjgl_path(path: &str) -> bool {
    path.starts_with("org/lwjgl/")
        || path.starts_with("lwjgl/")
        || path.contains("/lwjgl")
        || path.starts_with("natives/") && path.contains("lwjgl")
}

fn is_discord_rpc_path(path: &str) -> bool {
    path.contains("discord-rpc")
        || path.contains("discord_rpc")
        || path.contains("discord_game_sdk")
        || path.starts_with("mediaplayerinfo/natives/")
}

#[cfg(test)]
mod tests {
    use super::{
        classify_known_native_path, inspect_native_file, native_format, KnownNativeLibrary,
        NativeFormat,
    };

    #[test]
    fn identifies_supported_native_formats_without_executing_them() {
        assert_eq!(native_format(b"MZ\0\0"), Some(NativeFormat::Pe));
        assert_eq!(native_format(b"\x7fELF\x02"), Some(NativeFormat::Elf));
        assert_eq!(
            native_format(&[0xfe, 0xed, 0xfa, 0xce, 0]),
            Some(NativeFormat::MachO32)
        );
        assert_eq!(
            native_format(&[0xfe, 0xed, 0xfa, 0xcf, 0]),
            Some(NativeFormat::MachO64)
        );
        assert_eq!(native_format(b"not-native"), None);
    }

    #[test]
    fn recognizes_known_native_dependency_paths_case_insensitively() {
        assert_eq!(
            classify_known_native_path("COM\\SUN\\JNA\\win32-x86-64\\jnidispatch.dll"),
            Some(KnownNativeLibrary::Jna)
        );
        assert_eq!(
            classify_known_native_path("org/lwjgl/glfw/libglfw.so"),
            Some(KnownNativeLibrary::Lwjgl)
        );
        assert_eq!(
            classify_known_native_path("MediaPlayerInfo/natives/discord-rpc.dll"),
            Some(KnownNativeLibrary::DiscordRpc)
        );
    }

    #[test]
    fn keeps_unknown_native_files_distinct_from_known_capabilities() {
        assert_eq!(classify_known_native_path("assets/payload.dll"), None);

        let analysis = inspect_native_file("assets/payload.dll", b"MZpayload")
            .expect("PE magic should be recognized");
        assert_eq!(analysis.format, NativeFormat::Pe);
        assert_eq!(analysis.known_library, None);
    }
}
