const MIN_PRINTABLE_STRING_LENGTH: usize = 4;

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
        strings.push(String::from_utf8_lossy(current).to_string());
    }
    current.clear();
}
