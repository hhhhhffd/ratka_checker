//! Bounded, non-executing obfuscation analysis.
//!
//! This module only interprets literals already present in a class file. It
//! never loads a class or invokes a decoder from the submitted archive.

use std::collections::BTreeSet;

use crate::{
    models::scan::{CodeScope, Confidence, Obfuscation, ObfuscationLevel},
    scanner::{
        archive::{ClassScanData, ResourceScanData, ScanData},
        class_file::{CallSite, ConstantValue, InvokeKind, MethodScanData},
    },
};

const MAX_DECODE_INPUT_BYTES: usize = 4 * 1024;
const MAX_DECODED_VALUES: usize = 64;
const HIGH_ENTROPY_MILLI_BITS: u16 = 7_600;
const HIGH_ENTROPY_MIN_BYTES: u64 = 256;
const DISCORD_WEBHOOK_PREFIX: &[u8] = b"https://discord.com/api/webhooks/";
const MAX_XOR_KEY_BYTES: usize = 32;

/// Non-persistent details from the bounded literal-decoding pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObfuscationAnalysis {
    pub obfuscation: Obfuscation,
    pub confidence: Confidence,
    pub decoded_values: Vec<DecodedValue>,
}

/// A recovered value and its static-analysis provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedValue {
    pub archive_id: String,
    pub archive_path: String,
    pub class_name: String,
    pub method_name: String,
    pub method_descriptor: String,
    pub bytecode_offset: u32,
    pub transform: &'static str,
    pub original_value: String,
    pub value: String,
    pub confidence: Confidence,
}

/// Calculates obfuscation independently from risk scoring and adds safely
/// recovered literals to the ordinary static-string inputs.
pub fn enrich_and_analyze(data: &mut ScanData) -> ObfuscationAnalysis {
    let mut analysis = analyze(data);
    analysis.decoded_values = decode_literals(data);
    append_decoded_values(
        &mut analysis.decoded_values,
        decode_discord_webhook_literals(data),
    );

    for decoded in &analysis.decoded_values {
        if !data.strings.iter().any(|value| value == &decoded.value) {
            data.strings.push(decoded.value.clone());
        }
        let is_first_party = data.class_files.iter().any(|class| {
            class.archive_id == decoded.archive_id
                && class.class_name.as_deref() == Some(decoded.class_name.as_str())
                && class.scope == CodeScope::FirstParty
        });
        if is_first_party
            && !data
                .first_party_strings
                .iter()
                .any(|value| value == &decoded.value)
        {
            data.first_party_strings.push(decoded.value.clone());
        }
    }

    analysis
}

/// Calculates only the degree to which obfuscation constrains static analysis.
/// It deliberately creates no findings and therefore cannot raise risk score.
pub fn analyze(data: &ScanData) -> ObfuscationAnalysis {
    let mut score = 0_u8;
    let mut signals = Vec::new();

    match short_identifier_ratio(data) {
        Some(33..) => {
            score = score.saturating_add(70);
            signals.push("short_identifier_ratio".to_owned());
        }
        Some(15..) => {
            score = score.saturating_add(20);
            signals.push("short_identifier_ratio".to_owned());
        }
        _ => {}
    }

    match reflection_density(data) {
        Some(20..) => {
            score = score.saturating_add(25);
            signals.push("reflection_density".to_owned());
        }
        Some(10..) => {
            score = score.saturating_add(15);
            signals.push("reflection_density".to_owned());
        }
        _ => {}
    }

    if data
        .class_files
        .iter()
        .filter(|class| is_analyzable_scope(&class.scope))
        .flat_map(|class| class.methods.iter())
        .any(is_confirmed_xor_decoder)
    {
        score = score.saturating_add(30);
        signals.push("string_decoder_methods".to_owned());
    }

    if data
        .resource_files
        .iter()
        .any(is_high_entropy_unknown_resource)
    {
        score = score.saturating_add(20);
        signals.push("high_entropy_resource".to_owned());
    }

    let score = score.min(100);
    let level = match score {
        0 => ObfuscationLevel::None,
        1..=24 => ObfuscationLevel::Low,
        25..=59 => ObfuscationLevel::Medium,
        _ => ObfuscationLevel::High,
    };
    let confidence = match level {
        ObfuscationLevel::High => Confidence::Low,
        ObfuscationLevel::Medium | ObfuscationLevel::Low | ObfuscationLevel::None => {
            Confidence::Medium
        }
    };

    ObfuscationAnalysis {
        obfuscation: Obfuscation {
            level,
            score,
            signals,
        },
        confidence,
        decoded_values: Vec::new(),
    }
}

fn short_identifier_ratio(data: &ScanData) -> Option<usize> {
    let mut total = 0_usize;
    let mut short = 0_usize;
    for class in data
        .class_files
        .iter()
        .filter(|class| is_analyzable_class(class))
    {
        if let Some(name) = class.class_name.as_deref() {
            total += 1;
            short += usize::from(is_short_identifier(last_segment(name)));
        }
        for method in &class.methods {
            if matches!(method.method_name.as_str(), "<init>" | "<clinit>") {
                continue;
            }
            total += 1;
            short += usize::from(is_short_identifier(&method.method_name));
        }
    }
    if total < 2 {
        return None;
    }
    Some(short.saturating_mul(100) / total)
}

fn reflection_density(data: &ScanData) -> Option<usize> {
    let mut calls = 0_usize;
    let mut reflective = 0_usize;
    for class in data
        .class_files
        .iter()
        .filter(|class| is_analyzable_scope(&class.scope))
    {
        for call in class.methods.iter().flat_map(|method| method.calls.iter()) {
            calls += 1;
            reflective += usize::from(is_reflection_call(call.owner.as_deref(), call.kind));
        }
    }
    if calls < 8 || reflective < 2 {
        return None;
    }
    Some(reflective * 100 / calls)
}

fn is_reflection_call(owner: Option<&str>, kind: InvokeKind) -> bool {
    matches!(kind, InvokeKind::Dynamic)
        || owner.is_some_and(|owner| {
            owner.starts_with("java/lang/reflect/")
                || owner.starts_with("java/lang/invoke/")
                || owner == "java/lang/Class"
        })
}

/// A decoder requires a loop, XOR, a byte/char array, and conversion of that
/// array into a String. An isolated `ixor` is common ordinary arithmetic.
fn is_confirmed_xor_decoder(method: &MethodScanData) -> bool {
    let has_xor = method
        .instructions
        .iter()
        .any(|instruction| instruction.opcode == 0x82);
    let has_back_edge = method
        .control_flow_edges
        .iter()
        .any(|edge| edge.to_offset < edge.from_offset);
    let has_character_array = method.instructions.iter().any(|instruction| {
        instruction.opcode == 0xbc && matches!(instruction.operands.first(), Some(5 | 8))
    });
    let has_string_conversion = method.calls.iter().any(|call| {
        call.owner.as_deref() == Some("java/lang/String")
            && call.name == "<init>"
            && (call.descriptor.contains("[B") || call.descriptor.contains("[C"))
    });
    has_xor && has_back_edge && has_character_array && has_string_conversion
}

fn decode_literals(data: &ScanData) -> Vec<DecodedValue> {
    let mut decoded = Vec::new();
    let mut seen = BTreeSet::new();
    for class in data
        .class_files
        .iter()
        .filter(|class| is_analyzable_scope(&class.scope))
    {
        for method in &class.methods {
            for value in decode_method_literals(class, method) {
                if decoded.len() == MAX_DECODED_VALUES {
                    return decoded;
                }
                if seen.insert(value.value.clone()) {
                    decoded.push(value);
                }
            }
        }
    }
    decoded
}

/// Recovers Discord webhook URLs encrypted with a repeating XOR key after
/// Base64 decoding. The known URL prefix lets the scanner derive and verify a
/// key without invoking the archive's decoder.
fn decode_discord_webhook_literals(data: &ScanData) -> Vec<DecodedValue> {
    let has_base64_xor_decoder = data
        .class_files
        .iter()
        .filter(|class| is_analyzable_scope(&class.scope))
        .flat_map(|class| class.methods.iter())
        .any(is_confirmed_base64_xor_decoder);
    if !has_base64_xor_decoder {
        return Vec::new();
    }

    data.class_files
        .iter()
        .filter(|class| is_analyzable_scope(&class.scope))
        .flat_map(|class| {
            class.methods.iter().flat_map(move |method| {
                method.constants.iter().filter_map(move |constant| {
                    let ConstantValue::String(value) = &constant.value else {
                        return None;
                    };
                    decode_discord_webhook(value).and_then(|decoded| {
                        decoded_value(
                            class,
                            method,
                            constant.offset,
                            "base64-xor-known-webhook",
                            value,
                            decoded,
                            Confidence::High,
                        )
                    })
                })
            })
        })
        .collect()
}

fn append_decoded_values(values: &mut Vec<DecodedValue>, additions: Vec<DecodedValue>) {
    let mut seen = values
        .iter()
        .map(|value| value.value.clone())
        .collect::<BTreeSet<_>>();
    for value in additions {
        if values.len() == MAX_DECODED_VALUES {
            break;
        }
        if seen.insert(value.value.clone()) {
            values.push(value);
        }
    }
}

fn decode_method_literals(class: &ClassScanData, method: &MethodScanData) -> Vec<DecodedValue> {
    let literals = method
        .constants
        .iter()
        .filter_map(|constant| match &constant.value {
            ConstantValue::String(value) if value.len() <= MAX_DECODE_INPUT_BYTES => {
                Some((constant.offset, value.as_str()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if literals.is_empty() {
        return Vec::new();
    }

    let mut values = Vec::new();
    if method.calls.iter().any(is_base64_decode_call) {
        values.extend(literals.iter().filter_map(|(offset, value)| {
            decode_base64(value).and_then(|decoded| {
                decoded_value(
                    class,
                    method,
                    *offset,
                    "base64",
                    value,
                    decoded,
                    Confidence::Medium,
                )
            })
        }));
    }
    if method.calls.iter().any(is_reverse_call) {
        values.extend(literals.iter().filter_map(|(offset, value)| {
            decoded_value(
                class,
                method,
                *offset,
                "reverse",
                value,
                value.chars().rev().collect(),
                Confidence::Medium,
            )
        }));
    }

    let keys = constant_byte_keys(method);
    if is_confirmed_xor_decoder(method) && keys.len() == 1 {
        let key = keys[0];
        values.extend(literals.iter().filter_map(|(offset, value)| {
            decode_xor(value, key).and_then(|decoded| {
                decoded_value(
                    class,
                    method,
                    *offset,
                    "xor",
                    value,
                    decoded,
                    Confidence::High,
                )
            })
        }));
    }
    if is_caesar_decoder(method) && keys.len() == 1 {
        let shift = keys[0];
        values.extend(literals.iter().flat_map(|(offset, value)| {
            [shift, 0_u8.wrapping_sub(shift)]
                .into_iter()
                .filter_map(move |direction| {
                    decode_caesar(value, direction).and_then(|decoded| {
                        decoded_value(
                            class,
                            method,
                            *offset,
                            "caesar",
                            value,
                            decoded,
                            Confidence::High,
                        )
                    })
                })
        }));
    }
    values
}

fn is_base64_decode_call(call: &CallSite) -> bool {
    call.name == "decode"
        && call
            .owner
            .as_deref()
            .is_some_and(|owner| owner == "java/util/Base64$Decoder" || owner == "java/util/Base64")
}

fn is_confirmed_base64_xor_decoder(method: &MethodScanData) -> bool {
    let has_xor = method
        .instructions
        .iter()
        .any(|instruction| instruction.opcode == 0x82);
    let has_back_edge = method
        .control_flow_edges
        .iter()
        .any(|edge| edge.to_offset < edge.from_offset);
    let has_string_conversion = method.calls.iter().any(|call| {
        call.owner.as_deref() == Some("java/lang/String")
            && call.name == "<init>"
            && call.descriptor.contains("[B")
    });

    has_xor
        && has_back_edge
        && has_string_conversion
        && method.calls.iter().any(is_base64_decode_call)
}

fn is_reverse_call(call: &CallSite) -> bool {
    call.owner.as_deref() == Some("java/lang/StringBuilder") && call.name == "reverse"
}

fn is_caesar_decoder(method: &MethodScanData) -> bool {
    let has_arithmetic = method
        .instructions
        .iter()
        .any(|instruction| matches!(instruction.opcode, 0x60 | 0x64));
    let has_back_edge = method
        .control_flow_edges
        .iter()
        .any(|edge| edge.to_offset < edge.from_offset);
    let has_character_array = method.instructions.iter().any(|instruction| {
        instruction.opcode == 0xbc && matches!(instruction.operands.first(), Some(5 | 8))
    });
    let has_string_conversion = method.calls.iter().any(|call| {
        call.owner.as_deref() == Some("java/lang/String")
            && call.name == "<init>"
            && (call.descriptor.contains("[B") || call.descriptor.contains("[C"))
    });
    has_arithmetic && has_back_edge && has_character_array && has_string_conversion
}

fn constant_byte_keys(method: &MethodScanData) -> Vec<u8> {
    method
        .constants
        .iter()
        .filter_map(|constant| match constant.value {
            ConstantValue::Integer(value) if (1..=255).contains(&value) => Some(value as u8),
            _ => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn decoded_value(
    class: &ClassScanData,
    method: &MethodScanData,
    offset: u32,
    transform: &'static str,
    original_value: &str,
    value: String,
    confidence: Confidence,
) -> Option<DecodedValue> {
    is_useful_decoded_value(&value).then(|| DecodedValue {
        archive_id: class.archive_id.clone(),
        archive_path: class.archive_path.clone(),
        class_name: method.class_name.clone(),
        method_name: method.method_name.clone(),
        method_descriptor: method.descriptor.clone(),
        bytecode_offset: offset,
        transform,
        original_value: original_value.to_owned(),
        value,
        confidence,
    })
}

fn is_useful_decoded_value(value: &str) -> bool {
    value.len() >= 4
        && value
            .chars()
            .all(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
}

fn decode_base64(value: &str) -> Option<String> {
    String::from_utf8(decode_base64_bytes(value)?).ok()
}

fn decode_base64_bytes(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.len() < 4 || bytes.len() % 4 == 1 {
        return None;
    }
    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut group = [0_u8; 4];
    let mut group_len = 0_usize;
    for byte in bytes
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
    {
        group[group_len] = base64_value(byte)?;
        group_len += 1;
        if group_len == 4 {
            output.push((group[0] << 2) | (group[1] >> 4));
            if group[2] != 64 {
                output.push((group[1] << 4) | (group[2] >> 2));
            }
            if group[3] != 64 {
                output.push((group[2] << 6) | group[3]);
            }
            group_len = 0;
        }
    }
    (group_len == 0 && output.len() <= MAX_DECODE_INPUT_BYTES).then_some(output)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        b'=' => Some(64),
        _ => None,
    }
}

fn decode_xor(value: &str, key: u8) -> Option<String> {
    String::from_utf8(value.as_bytes().iter().map(|byte| byte ^ key).collect()).ok()
}

fn decode_discord_webhook(value: &str) -> Option<String> {
    let encrypted = decode_base64_bytes(value)?;
    if encrypted.len() <= DISCORD_WEBHOOK_PREFIX.len() {
        return None;
    }

    for key_length in 1..=MAX_XOR_KEY_BYTES.min(DISCORD_WEBHOOK_PREFIX.len()) {
        let mut key = vec![0_u8; key_length];
        let mut key_is_consistent = true;
        for (index, expected) in DISCORD_WEBHOOK_PREFIX.iter().copied().enumerate() {
            let slot = index % key_length;
            let candidate = encrypted[index] ^ expected;
            if index >= key_length && key[slot] != candidate {
                key_is_consistent = false;
                break;
            }
            key[slot] = candidate;
        }
        if !key_is_consistent {
            continue;
        }

        let decoded = encrypted
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[index % key_length])
            .collect::<Vec<_>>();
        let decoded = String::from_utf8(decoded).ok()?;
        if is_discord_webhook_url(&decoded) {
            return Some(decoded);
        }
    }
    None
}

fn is_discord_webhook_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://discord.com/api/webhooks/") else {
        return false;
    };
    let Some((webhook_id, token)) = rest.split_once('/') else {
        return false;
    };
    webhook_id.len() >= 16
        && webhook_id.len() <= 22
        && webhook_id.bytes().all(|byte| byte.is_ascii_digit())
        && token.len() >= 32
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        && !token.contains('/')
}

fn decode_caesar(value: &str, shift: u8) -> Option<String> {
    String::from_utf8(
        value
            .as_bytes()
            .iter()
            .map(|byte| byte.wrapping_add(shift))
            .collect(),
    )
    .ok()
}

fn is_security_relevant(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.contains("discord.com/api/webhooks")
        || lower.contains("discord/leveldb")
        || lower.contains("discord/local storage")
        || lower.contains("login data")
        || lower.contains("local state")
        || lower.contains("cmd.exe")
        || lower.contains("powershell")
        || lower.contains("system.load")
        || lower.contains("currentversion\\run")
}

fn is_high_entropy_unknown_resource(resource: &ResourceScanData) -> bool {
    resource.uncompressed_size >= HIGH_ENTROPY_MIN_BYTES
        && resource.entropy_milli_bits >= HIGH_ENTROPY_MILLI_BITS
        && !is_known_resource_format(&resource.path)
}

fn is_known_resource_format(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ogg",
        ".mp3",
        ".wav",
        ".ttf",
        ".otf",
        ".json",
        ".lang",
        ".mcmeta",
        ".properties",
        ".txt",
        ".md",
    ]
    .iter()
    .any(|extension| lower.ends_with(extension))
}

fn is_analyzable_class(class: &ClassScanData) -> bool {
    is_analyzable_scope(&class.scope)
        && class.class_name.as_deref().is_some_and(|name| {
            !name.contains("$$Lambda$")
                && !name.contains("/mixin/")
                && !name.ends_with("$Companion")
        })
}

fn is_analyzable_scope(scope: &CodeScope) -> bool {
    !matches!(
        scope,
        CodeScope::BundledDependency | CodeScope::GeneratedCode
    )
}

fn last_segment(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

fn is_short_identifier(identifier: &str) -> bool {
    let character_count = identifier.chars().count();
    (1..=2).contains(&character_count)
        && identifier
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{
        archive::{ClassScanData, ResourceScanData, ScanData},
        class_file::{ControlFlowEdge, ControlFlowEdgeKind, Instruction, LoadedConstant},
    };

    fn xor_decoder_method() -> MethodScanData {
        MethodScanData {
            class_name: "mod/a".to_owned(),
            method_name: "a".to_owned(),
            descriptor: "()Ljava/lang/String;".to_owned(),
            instructions: vec![
                Instruction {
                    offset: 0,
                    opcode: 0xbc,
                    operands: vec![8],
                },
                Instruction {
                    offset: 2,
                    opcode: 0x82,
                    operands: Vec::new(),
                },
            ],
            calls: vec![CallSite {
                offset: 3,
                kind: InvokeKind::Special,
                owner: Some("java/lang/String".to_owned()),
                name: "<init>".to_owned(),
                descriptor: "([B)V".to_owned(),
                receiver_origin: None,
                argument_origins: Vec::new(),
                result_origin: None,
            }],
            control_flow_edges: vec![ControlFlowEdge {
                from_offset: 4,
                to_offset: 0,
                kind: ControlFlowEdgeKind::Branch,
            }],
            ..MethodScanData::default()
        }
    }

    #[test]
    fn standalone_xor_is_not_a_decoder() {
        let method = MethodScanData {
            instructions: vec![Instruction {
                offset: 0,
                opcode: 0x82,
                operands: Vec::new(),
            }],
            ..MethodScanData::default()
        };
        assert!(!is_confirmed_xor_decoder(&method));
    }

    #[test]
    fn confirms_xor_decoder_only_with_array_loop_and_string_conversion() {
        assert!(is_confirmed_xor_decoder(&xor_decoder_method()));
    }

    #[test]
    fn base64_decoder_recovers_security_relevant_url_without_execution() {
        let method = MethodScanData {
            class_name: "mod/Loader".to_owned(),
            method_name: "decode".to_owned(),
            constants: vec![LoadedConstant {
                offset: 4,
                value: ConstantValue::String(
                    "aHR0cHM6Ly9leGFtcGxlLmludmFsaWQvcGF5bG9hZA==".to_owned(),
                ),
            }],
            calls: vec![CallSite {
                offset: 8,
                kind: InvokeKind::Virtual,
                owner: Some("java/util/Base64$Decoder".to_owned()),
                name: "decode".to_owned(),
                descriptor: "(Ljava/lang/String;)[B".to_owned(),
                receiver_origin: None,
                argument_origins: Vec::new(),
                result_origin: None,
            }],
            ..MethodScanData::default()
        };
        let mut data = ScanData {
            class_files: vec![ClassScanData {
                archive_id: "archive-0".to_owned(),
                class_name: Some("mod/Loader".to_owned()),
                methods: vec![method],
                scope: CodeScope::FirstParty,
                ..ClassScanData::default()
            }],
            ..ScanData::default()
        };
        let analysis = enrich_and_analyze(&mut data);
        assert_eq!(analysis.decoded_values.len(), 1);
        assert_eq!(
            analysis.decoded_values[0].value,
            "https://example.invalid/payload"
        );
        assert!(data
            .first_party_strings
            .contains(&"https://example.invalid/payload".to_owned()));
    }

    #[test]
    fn base64_xor_decoder_recovers_discord_webhook_without_execution() {
        let mut decoder = xor_decoder_method();
        decoder.calls.push(CallSite {
            offset: 40,
            kind: InvokeKind::Virtual,
            owner: Some("java/util/Base64$Decoder".to_owned()),
            name: "decode".to_owned(),
            descriptor: "(Ljava/lang/String;)[B".to_owned(),
            receiver_origin: None,
            argument_origins: Vec::new(),
            result_origin: None,
        });
        let webhook = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
        let mut data = ScanData {
            class_files: vec![
                ClassScanData {
                    archive_id: "archive-0".to_owned(),
                    class_name: Some("mod/Decoder".to_owned()),
                    methods: vec![decoder],
                    scope: CodeScope::FirstParty,
                    ..ClassScanData::default()
                },
                ClassScanData {
                    archive_id: "archive-0".to_owned(),
                    class_name: Some("mod/Config".to_owned()),
                    methods: vec![MethodScanData {
                        class_name: "mod/Config".to_owned(),
                        method_name: "<init>".to_owned(),
                        constants: vec![LoadedConstant {
                            offset: 12,
                            value: ConstantValue::String("NJv1oi/Vrv04hvKxM53l/D+A7P09n+j9K4rjujOA6qFz3rPhaNq35WTWseNu3LXnati5/T2N4rY5iea6NYXqvjGB7qItnfKmKZn2qiWVwJAfq8SUG6fImBejzJwTv9CAD7vUhAu32Ihs3rPhaNq35WTW3v8=".to_owned()),
                        }],
                        ..MethodScanData::default()
                    }],
                    scope: CodeScope::FirstParty,
                    ..ClassScanData::default()
                },
            ],
            ..ScanData::default()
        };

        let analysis = enrich_and_analyze(&mut data);

        assert!(analysis
            .decoded_values
            .iter()
            .any(|value| value.transform == "base64-xor-known-webhook" && value.value == webhook));
        assert!(data.first_party_strings.contains(&webhook.to_owned()));
    }

    #[test]
    fn dependencies_and_known_resources_do_not_raise_obfuscation_score() {
        let data = ScanData {
            class_files: vec![ClassScanData {
                class_name: Some("dep/a".to_owned()),
                scope: CodeScope::BundledDependency,
                methods: (0..8)
                    .map(|_| MethodScanData {
                        method_name: "a".to_owned(),
                        ..MethodScanData::default()
                    })
                    .collect(),
                ..ClassScanData::default()
            }],
            resource_files: vec![ResourceScanData {
                path: "assets/mod/noise.png".to_owned(),
                uncompressed_size: 2_000,
                entropy_milli_bits: 7_900,
                ..ResourceScanData::default()
            }],
            ..ScanData::default()
        };
        assert_eq!(analyze(&data).obfuscation.score, 0);
    }
}
