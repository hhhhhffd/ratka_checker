/// Result of parsing a Java class file enough to extract strings and API references.
#[derive(Debug, Default)]
pub struct ClassFileData {
    pub strings: Vec<String>,
    pub bytecode_refs: Vec<String>,
    pub archive_signals: Vec<String>,
    pub class_name: Option<String>,
    pub major_version: u16,
}

const XOR_LOOP_SIGNAL: &str = "xor_loop_string_decode";
const MIN_DECODED_STRING_LENGTH: usize = 4;

#[derive(Clone, Debug)]
enum ConstantPoolEntry {
    Utf8(String),
    Integer(i32),
    Class {
        name_index: u16,
    },
    NameAndType {
        name_index: u16,
    },
    Ref {
        class_index: u16,
        name_and_type_index: u16,
    },
    Other,
}

/// Parses enough class structure to resolve constant-pool refs and inspect method bytecode.
pub fn parse_class_file(bytes: &[u8]) -> anyhow::Result<ClassFileData> {
    let mut cursor = ClassCursor::new(bytes);
    let magic = cursor.read_u32()?;
    if magic != 0xCAFEBABE {
        anyhow::bail!("invalid class magic");
    }

    let _minor_version = cursor.read_u16()?;
    let major_version = cursor.read_u16()?;
    let entries = parse_constant_pool(&mut cursor)?;

    let _access_flags = cursor.read_u16()?;
    let this_class = cursor.read_u16()?;
    let _super_class = cursor.read_u16()?;
    let class_name = resolve_class_name(&entries, this_class);

    skip_interfaces(&mut cursor)?;
    skip_members(&mut cursor)?;

    let mut method_strings = Vec::new();
    let mut archive_signals = Vec::new();
    let has_string_byte_constructor = has_string_byte_constructor(&entries);
    parse_methods(
        &mut cursor,
        &entries,
        has_string_byte_constructor,
        &mut method_strings,
        &mut archive_signals,
    )?;
    skip_attributes(&mut cursor)?;

    let mut strings = constant_pool_strings(&entries);
    strings.extend(integer_ip_strings(&entries));
    strings.extend(method_strings);

    let mut bytecode_refs = strings.clone();
    for entry in &entries {
        if let ConstantPoolEntry::Ref {
            class_index,
            name_and_type_index,
        } = entry
        {
            if let (Some(class_name), Some(member_name)) = (
                resolve_class_name(&entries, *class_index),
                resolve_member_name(&entries, *name_and_type_index),
            ) {
                bytecode_refs.push(class_name.clone());
                bytecode_refs.push(format!("{class_name}.{member_name}"));
            }
        }
    }

    Ok(ClassFileData {
        strings,
        bytecode_refs,
        archive_signals,
        class_name,
        major_version,
    })
}

fn parse_constant_pool(cursor: &mut ClassCursor<'_>) -> anyhow::Result<Vec<ConstantPoolEntry>> {
    let constant_pool_count = cursor.read_u16()? as usize;
    let mut entries = vec![ConstantPoolEntry::Other; constant_pool_count];
    let mut index = 1;

    while index < constant_pool_count {
        let tag = cursor.read_u8()?;
        match tag {
            1 => {
                let length = cursor.read_u16()? as usize;
                let bytes = cursor.read_bytes(length)?;
                entries[index] =
                    ConstantPoolEntry::Utf8(String::from_utf8_lossy(bytes).to_string());
            }
            3 => {
                entries[index] = ConstantPoolEntry::Integer(cursor.read_u32()? as i32);
            }
            7 => {
                entries[index] = ConstantPoolEntry::Class {
                    name_index: cursor.read_u16()?,
                };
            }
            8 => {
                let _string_index = cursor.read_u16()?;
            }
            9..=11 => {
                entries[index] = ConstantPoolEntry::Ref {
                    class_index: cursor.read_u16()?,
                    name_and_type_index: cursor.read_u16()?,
                };
            }
            12 => {
                entries[index] = ConstantPoolEntry::NameAndType {
                    name_index: cursor.read_u16()?,
                };
                let _descriptor_index = cursor.read_u16()?;
            }
            4 | 17 | 18 => {
                cursor.skip(4)?;
            }
            5 | 6 => {
                cursor.skip(8)?;
                index += 1;
            }
            15 => {
                cursor.skip(3)?;
            }
            16 | 19 | 20 => {
                cursor.skip(2)?;
            }
            unknown => anyhow::bail!("unknown constant pool tag {unknown}"),
        }
        index += 1;
    }
    Ok(entries)
}

fn constant_pool_strings(entries: &[ConstantPoolEntry]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|entry| match entry {
            ConstantPoolEntry::Utf8(value) => Some(value.clone()),
            _ => None,
        })
        .collect()
}

fn integer_ip_strings(entries: &[ConstantPoolEntry]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|entry| match entry {
            ConstantPoolEntry::Integer(value) => integer_to_ip(*value),
            _ => None,
        })
        .collect()
}

fn integer_to_ip(value: i32) -> Option<String> {
    let bytes = (value as u32).to_be_bytes();
    let private_or_noise = bytes[0] == 0
        || bytes[0] == 10
        || bytes[0] == 127
        || bytes[0] >= 224
        || (bytes[0] == 172 && (16..=31).contains(&bytes[1]))
        || (bytes[0] == 192 && bytes[1] == 168);
    if private_or_noise {
        return None;
    }
    Some(format!(
        "int_ip:{}.{}.{}.{}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    ))
}

fn skip_interfaces(cursor: &mut ClassCursor<'_>) -> anyhow::Result<()> {
    let interface_count = cursor.read_u16()? as usize;
    cursor.skip(interface_count * 2)
}

fn skip_members(cursor: &mut ClassCursor<'_>) -> anyhow::Result<()> {
    let member_count = cursor.read_u16()? as usize;
    for _ in 0..member_count {
        let _access_flags = cursor.read_u16()?;
        let _name_index = cursor.read_u16()?;
        let _descriptor_index = cursor.read_u16()?;
        skip_attributes(cursor)?;
    }
    Ok(())
}

fn parse_methods(
    cursor: &mut ClassCursor<'_>,
    entries: &[ConstantPoolEntry],
    has_string_byte_constructor: bool,
    strings: &mut Vec<String>,
    archive_signals: &mut Vec<String>,
) -> anyhow::Result<()> {
    let method_count = cursor.read_u16()? as usize;
    for _ in 0..method_count {
        let _access_flags = cursor.read_u16()?;
        let _name_index = cursor.read_u16()?;
        let _descriptor_index = cursor.read_u16()?;
        let attribute_count = cursor.read_u16()? as usize;
        for _ in 0..attribute_count {
            let attribute_name_index = cursor.read_u16()?;
            let attribute_length = cursor.read_u32()? as usize;
            let attribute_bytes = cursor.read_bytes(attribute_length)?;
            if utf8(entries, attribute_name_index).is_some_and(|name| name == "Code") {
                inspect_code_attribute(
                    attribute_bytes,
                    has_string_byte_constructor,
                    strings,
                    archive_signals,
                )?;
            }
        }
    }
    Ok(())
}

fn skip_attributes(cursor: &mut ClassCursor<'_>) -> anyhow::Result<()> {
    let attribute_count = cursor.read_u16()? as usize;
    for _ in 0..attribute_count {
        let _attribute_name_index = cursor.read_u16()?;
        let attribute_length = cursor.read_u32()? as usize;
        cursor.skip(attribute_length)?;
    }
    Ok(())
}

fn inspect_code_attribute(
    bytes: &[u8],
    has_string_byte_constructor: bool,
    strings: &mut Vec<String>,
    archive_signals: &mut Vec<String>,
) -> anyhow::Result<()> {
    let mut cursor = ClassCursor::new(bytes);
    let _max_stack = cursor.read_u16()?;
    let _max_locals = cursor.read_u16()?;
    let code_length = cursor.read_u32()? as usize;
    let code = cursor.read_bytes(code_length)?;

    strings.extend(recover_byte_array_strings(code));
    if has_string_byte_constructor && has_xor_loop(code) {
        archive_signals.push(XOR_LOOP_SIGNAL.to_owned());
    }
    Ok(())
}

fn recover_byte_array_strings(code: &[u8]) -> Vec<String> {
    if !code.windows(2).any(|window| window == [0xbc, 0x08]) {
        return Vec::new();
    }

    let mut constants = Vec::new();
    let mut decoded_bytes = Vec::new();
    let mut offset = 0;
    while offset < code.len() {
        match code[offset] {
            0x02 => {
                constants.push(-1);
                offset += 1;
            }
            opcode @ 0x03..=0x08 => {
                constants.push(i32::from(opcode - 0x03));
                offset += 1;
            }
            0x10 if offset + 1 < code.len() => {
                constants.push(i32::from(code[offset + 1] as i8));
                offset += 2;
            }
            0x11 if offset + 2 < code.len() => {
                constants.push(i32::from(i16::from_be_bytes([
                    code[offset + 1],
                    code[offset + 2],
                ])));
                offset += 3;
            }
            0x4f => {
                if let Some(value) = constants.pop() {
                    decoded_bytes.push(value as u8);
                }
                offset += 1;
            }
            opcode => {
                offset += opcode_length(opcode, code, offset).unwrap_or(1);
            }
        }
    }

    printable_runs(&decoded_bytes)
}

fn printable_runs(bytes: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    for byte in bytes {
        if byte.is_ascii_graphic() || *byte == b' ' {
            current.push(*byte);
        } else {
            push_decoded_string(&mut strings, &mut current);
        }
    }
    push_decoded_string(&mut strings, &mut current);
    strings
}

fn push_decoded_string(strings: &mut Vec<String>, current: &mut Vec<u8>) {
    if current.len() >= MIN_DECODED_STRING_LENGTH {
        strings.push(String::from_utf8_lossy(current).to_string());
    }
    current.clear();
}

fn has_xor_loop(code: &[u8]) -> bool {
    code.contains(&0x82) && (has_backward_goto(code, 0xa7, 2) || has_backward_goto(code, 0xc8, 4))
}

fn has_backward_goto(code: &[u8], opcode: u8, operand_len: usize) -> bool {
    let mut offset = 0;
    while offset + operand_len < code.len() {
        if code[offset] == opcode {
            let branch = if operand_len == 2 {
                i32::from(i16::from_be_bytes([code[offset + 1], code[offset + 2]]))
            } else {
                i32::from_be_bytes([
                    code[offset + 1],
                    code[offset + 2],
                    code[offset + 3],
                    code[offset + 4],
                ])
            };
            if branch < 0 {
                return true;
            }
        }
        offset += 1;
    }
    false
}

fn opcode_length(opcode: u8, code: &[u8], offset: usize) -> Option<usize> {
    match opcode {
        0x12 | 0x15..=0x19 | 0x36..=0x3a | 0xa9 | 0xbc => Some(2),
        0x13 | 0x14 | 0x84 | 0x99..=0xa8 | 0xbb..=0xbd | 0xc0 | 0xc1 | 0xc6 | 0xc7 => Some(3),
        0xb2..=0xb8 => Some(3),
        0xc5 => Some(4),
        0xb9 | 0xba | 0xc8 | 0xc9 => Some(5),
        0xaa => Some(table_switch_length(code, offset)?),
        0xab => Some(lookup_switch_length(code, offset)?),
        0xc4 => Some(wide_length(code, offset)?),
        _ => Some(1),
    }
}

fn table_switch_length(code: &[u8], offset: usize) -> Option<usize> {
    let padding = (4 - ((offset + 1) % 4)) % 4;
    let header = offset + 1 + padding;
    if header + 12 > code.len() {
        return None;
    }
    let low = read_i32(code, header + 4)?;
    let high = read_i32(code, header + 8)?;
    let entries = high.checked_sub(low)?.checked_add(1)? as usize;
    Some(1 + padding + 12 + entries * 4)
}

fn lookup_switch_length(code: &[u8], offset: usize) -> Option<usize> {
    let padding = (4 - ((offset + 1) % 4)) % 4;
    let header = offset + 1 + padding;
    if header + 8 > code.len() {
        return None;
    }
    let pairs = read_i32(code, header + 4)? as usize;
    Some(1 + padding + 8 + pairs * 8)
}

fn wide_length(code: &[u8], offset: usize) -> Option<usize> {
    let modified_opcode = *code.get(offset + 1)?;
    Some(if modified_opcode == 0x84 { 6 } else { 4 })
}

fn read_i32(code: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_be_bytes([
        *code.get(offset)?,
        *code.get(offset + 1)?,
        *code.get(offset + 2)?,
        *code.get(offset + 3)?,
    ]))
}

fn has_string_byte_constructor(entries: &[ConstantPoolEntry]) -> bool {
    entries.iter().any(|entry| {
        let ConstantPoolEntry::Ref {
            class_index,
            name_and_type_index,
        } = entry
        else {
            return false;
        };
        resolve_class_name(entries, *class_index)
            .is_some_and(|class_name| class_name == "java/lang/String")
            && resolve_member_name(entries, *name_and_type_index)
                .is_some_and(|member_name| member_name == "<init>")
    })
}

/// Resolves a class entry into its UTF-8 internal JVM class name.
fn resolve_class_name(entries: &[ConstantPoolEntry], index: u16) -> Option<String> {
    match entries.get(index as usize)? {
        ConstantPoolEntry::Class { name_index } => {
            utf8(entries, *name_index).map(ToOwned::to_owned)
        }
        _ => None,
    }
}

/// Resolves a name-and-type entry into only the method/field name for readable refs.
fn resolve_member_name(entries: &[ConstantPoolEntry], index: u16) -> Option<String> {
    match entries.get(index as usize)? {
        ConstantPoolEntry::NameAndType { name_index } => {
            utf8(entries, *name_index).map(ToOwned::to_owned)
        }
        _ => None,
    }
}

fn utf8(entries: &[ConstantPoolEntry], index: u16) -> Option<&str> {
    match entries.get(index as usize)? {
        ConstantPoolEntry::Utf8(value) => Some(value),
        _ => None,
    }
}

/// Small bounds-checked big-endian reader for Java class files.
struct ClassCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ClassCursor<'a> {
    /// Creates a cursor over immutable class bytes.
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// Reads one byte and advances the cursor.
    fn read_u8(&mut self) -> anyhow::Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    /// Reads a big-endian u16 and advances the cursor.
    fn read_u16(&mut self) -> anyhow::Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Reads a big-endian u32 and advances the cursor.
    fn read_u32(&mut self) -> anyhow::Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Skips fixed-width fields whose values are not needed for static signatures.
    fn skip(&mut self, length: usize) -> anyhow::Result<()> {
        self.read_bytes(length).map(|_| ())
    }

    /// Returns a checked byte slice and fails on truncated or intentionally malformed classes.
    fn read_bytes(&mut self, length: usize) -> anyhow::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("class cursor overflow"))?;
        if end > self.bytes.len() {
            anyhow::bail!("truncated class file");
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    /// Verifies the parser rejects non-class bytes instead of silently ignoring them.
    #[test]
    fn parse_class_file_rejects_invalid_magic() {
        let error = super::parse_class_file(b"not a class").expect_err("invalid class must fail");
        assert!(
            error.to_string().contains("invalid class magic")
                || error.to_string().contains("truncated")
        );
    }

    #[test]
    fn integer_to_ip_ignores_private_ranges() {
        assert_eq!(super::integer_to_ip(0x0a000001), None);
        assert_eq!(
            super::integer_to_ip(0x08080808),
            Some("int_ip:8.8.8.8".to_owned())
        );
    }
}
