use crate::models::scan::Confidence;

const MIN_PRINTABLE_STRING_LENGTH: usize = 4;

/// Encoding selected for a text resource without guessing from arbitrary bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextEncoding {
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
    Windows1251,
    Iso88591,
}

impl TextEncoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Utf8 => "utf-8",
            Self::Utf8Bom => "utf-8-bom",
            Self::Utf16Le => "utf-16le",
            Self::Utf16Be => "utf-16be",
            Self::Windows1251 => "windows-1251",
            Self::Iso88591 => "iso-8859-1",
        }
    }
}

/// A text resource decoded by a bounded, deterministic encoding detector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedTextResource {
    pub text: String,
    pub encoding: TextEncoding,
    pub confidence: Confidence,
}

/// Failure to decode a resource that was explicitly treated as text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextDecodingError {
    InvalidEncoding,
}

/// Extracts printable ASCII/UTF-8-ish strings from arbitrary binary data for signature matching.
pub fn extract_printable_strings(bytes: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for byte in bytes {
        if byte.is_ascii_graphic() || *byte == b' ' || *byte == b'\t' {
            current.push(*byte);
        } else {
            push_if_long_enough(&mut strings, &mut current);
        }
    }
    push_if_long_enough(&mut strings, &mut current);
    strings
}

/// Converts accumulated printable bytes into a string only when it is useful for matching.
fn push_if_long_enough(strings: &mut Vec<String>, current: &mut Vec<u8>) {
    if current.len() >= MIN_PRINTABLE_STRING_LENGTH {
        // `current` contains ASCII-only bytes by construction. Never use a
        // lossy conversion here: replacement characters could become rule input.
        if let Ok(value) = std::str::from_utf8(current) {
            strings.push(value.to_owned());
        }
    }
    current.clear();
}

/// Decodes only resource types expected to be text. Binary resources remain
/// outside encoding fallback logic, so random bytes cannot become rule input.
pub fn decode_text_resource(
    path: &str,
    bytes: &[u8],
) -> Result<Option<DecodedTextResource>, TextDecodingError> {
    if !is_text_resource_path(path) {
        return Ok(None);
    }
    decode_text(bytes).map(Some)
}

fn is_text_resource_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    [
        ".json",
        ".toml",
        ".properties",
        ".yml",
        ".yaml",
        ".txt",
        ".lang",
        ".mcmeta",
        ".mf",
    ]
    .iter()
    .any(|extension| path.ends_with(extension))
        || path.ends_with("plugin.yml")
}

fn decode_text(bytes: &[u8]) -> Result<DecodedTextResource, TextDecodingError> {
    if let Some(bytes) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return std::str::from_utf8(bytes)
            .map(|text| decoded(text, TextEncoding::Utf8Bom, Confidence::High))
            .map_err(|_| TextDecodingError::InvalidEncoding);
    }
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        return decode_utf16_bom(bytes).ok_or(TextDecodingError::InvalidEncoding);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Ok(decoded(text, TextEncoding::Utf8, Confidence::High));
    }
    if let Some(text) = decode_utf16_without_bom(bytes) {
        return Ok(text);
    }
    decode_legacy_text(bytes).ok_or(TextDecodingError::InvalidEncoding)
}

fn decode_utf16_bom(bytes: &[u8]) -> Option<DecodedTextResource> {
    let (encoding, bytes) = if let Some(bytes) = bytes.strip_prefix(&[0xff, 0xfe]) {
        (TextEncoding::Utf16Le, bytes)
    } else if let Some(bytes) = bytes.strip_prefix(&[0xfe, 0xff]) {
        (TextEncoding::Utf16Be, bytes)
    } else {
        return None;
    };
    decode_utf16(bytes, encoding).map(|text| decoded(&text, encoding, Confidence::High))
}

fn decode_utf16_without_bom(bytes: &[u8]) -> Option<DecodedTextResource> {
    if bytes.len() < 4 || bytes.len() % 2 != 0 {
        return None;
    }
    let even_zeros = bytes.iter().step_by(2).filter(|byte| **byte == 0).count();
    let odd_zeros = bytes
        .iter()
        .skip(1)
        .step_by(2)
        .filter(|byte| **byte == 0)
        .count();
    let unit_count = bytes.len() / 2;
    let encoding = if even_zeros * 3 >= unit_count {
        TextEncoding::Utf16Be
    } else if odd_zeros * 3 >= unit_count {
        TextEncoding::Utf16Le
    } else {
        return None;
    };
    decode_utf16(bytes, encoding).map(|text| decoded(&text, encoding, Confidence::Medium))
}

fn decode_utf16(bytes: &[u8], encoding: TextEncoding) -> Option<String> {
    let units = bytes
        .chunks_exact(2)
        .map(|pair| match encoding {
            TextEncoding::Utf16Le => u16::from_le_bytes([pair[0], pair[1]]),
            TextEncoding::Utf16Be => u16::from_be_bytes([pair[0], pair[1]]),
            _ => unreachable!("UTF-16 decoder received a non UTF-16 encoding"),
        })
        .collect::<Vec<_>>();
    String::from_utf16(&units)
        .ok()
        .filter(|text| is_plausible_text(text))
}

fn decode_legacy_text(bytes: &[u8]) -> Option<DecodedTextResource> {
    let cp1251 = bytes
        .iter()
        .map(|byte| cp1251_char(*byte))
        .collect::<String>();
    let iso88591 = bytes
        .iter()
        .map(|byte| char::from(*byte))
        .collect::<String>();
    if has_cyrillic_signal(&cp1251) && is_plausible_text(&cp1251) {
        Some(decoded(&cp1251, TextEncoding::Windows1251, Confidence::Low))
    } else if is_plausible_text(&iso88591) {
        Some(decoded(&iso88591, TextEncoding::Iso88591, Confidence::Low))
    } else {
        None
    }
}

fn decoded(text: &str, encoding: TextEncoding, confidence: Confidence) -> DecodedTextResource {
    DecodedTextResource {
        text: text.to_owned(),
        encoding,
        confidence,
    }
}

fn has_cyrillic_signal(text: &str) -> bool {
    text.chars()
        .filter(|character| matches!(character, '\u{0400}'..='\u{04ff}'))
        .count()
        >= 2
}

fn is_plausible_text(text: &str) -> bool {
    if text.is_empty() {
        return true;
    }
    let characters = text.chars().count();
    let printable = text
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .count();
    printable * 100 >= characters * 95
        && (text
            .chars()
            .any(|character| character.is_ascii_alphanumeric())
            || text.contains(['{', '}', '[', ']', '=', ':']))
}

fn cp1251_char(byte: u8) -> char {
    match byte {
        0x00..=0x7f => char::from(byte),
        0xc0..=0xdf => char::from_u32(0x0410 + u32::from(byte - 0xc0)).expect("Cyrillic range"),
        0xe0..=0xff => char::from_u32(0x0430 + u32::from(byte - 0xe0)).expect("Cyrillic range"),
        0xa8 => 'Ё',
        0xb8 => 'ё',
        _ => WINDOWS_1251_EXTENSIONS[(byte - 0x80) as usize],
    }
}

const WINDOWS_1251_EXTENSIONS: [char; 64] = [
    'Ђ', 'Ѓ', '‚', 'ѓ', '„', '…', '†', '‡', '€', '‰', 'Љ', '‹', 'Њ', 'Ќ', 'Ћ', 'Џ', 'ђ', '‘', '’',
    '“', '”', '•', '–', '—', '\u{0098}', '™', 'љ', '›', 'њ', 'ќ', 'ћ', 'џ', '\u{00a0}', 'Ў', 'ў',
    'Ј', '¤', 'Ґ', '¦', '§', 'Ё', '©', 'Є', '«', '¬', '\u{00ad}', '®', 'Ї', '°', '±', 'І', 'і',
    'ґ', 'µ', '¶', '·', 'ё', '№', 'є', '»', 'ј', 'Ѕ', 'ѕ', 'ї',
];

#[cfg(test)]
mod tests {
    use crate::models::scan::Confidence;

    use super::{decode_text_resource, TextDecodingError, TextEncoding};

    #[test]
    fn decodes_supported_resource_encodings_without_lossy_fallbacks() {
        let utf8 = decode_text_resource("config/mod.json", "{\"name\":\"тест\"}".as_bytes())
            .expect("valid UTF-8")
            .expect("text resource");
        assert_eq!(utf8.encoding, TextEncoding::Utf8);
        assert_eq!(utf8.confidence, Confidence::High);

        let utf16 = decode_text_resource("config/mod.json", &[0xff, 0xfe, b'{', 0, b'}', 0])
            .expect("valid UTF-16")
            .expect("text resource");
        assert_eq!(utf16.encoding, TextEncoding::Utf16Le);

        let cp1251 = decode_text_resource("config/mod.txt", &[0xd2, 0xe5, 0xf1, 0xf2, b'='])
            .expect("valid Windows-1251")
            .expect("text resource");
        assert_eq!(cp1251.encoding, TextEncoding::Windows1251);
    }

    #[test]
    fn rejects_binary_bytes_for_text_resources() {
        assert_eq!(
            decode_text_resource("config/mod.json", &[0xff, 0, 0x81, 0, 0x8d]),
            Err(TextDecodingError::InvalidEncoding)
        );
    }

    #[test]
    fn rejects_invalid_bom_instead_of_falling_back_to_a_legacy_encoding() {
        assert_eq!(
            decode_text_resource("config/mod.json", &[0xef, 0xbb, 0xbf, 0xff, b'x']),
            Err(TextDecodingError::InvalidEncoding)
        );
    }
}
