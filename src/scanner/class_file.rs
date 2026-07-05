/// Result of parsing a Java class file enough to extract constant-pool strings and API references.
#[derive(Debug, Default)]
pub struct ClassFileData {
    pub strings: Vec<String>,
    pub bytecode_refs: Vec<String>,
    pub major_version: u16,
}

#[derive(Clone, Debug)]
enum ConstantPoolEntry {
    Utf8(String),
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

/// Parses the class constant pool and resolves method/field references for bytecode_ref rules.
pub fn parse_class_file(bytes: &[u8]) -> anyhow::Result<ClassFileData> {
    let mut cursor = ClassCursor::new(bytes);
    let magic = cursor.read_u32()?;
    if magic != 0xCAFEBABE {
        anyhow::bail!("invalid class magic");
    }

    let _minor_version = cursor.read_u16()?;
    let major_version = cursor.read_u16()?;
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
            3 | 4 | 17 | 18 => {
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

    let strings = entries
        .iter()
        .filter_map(|entry| match entry {
            ConstantPoolEntry::Utf8(value) => Some(value.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();

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
        major_version,
    })
}

/// Resolves a class entry into its UTF-8 internal JVM class name.
fn resolve_class_name(entries: &[ConstantPoolEntry], index: u16) -> Option<String> {
    match entries.get(index as usize)? {
        ConstantPoolEntry::Class { name_index } => match entries.get(*name_index as usize)? {
            ConstantPoolEntry::Utf8(value) => Some(value.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Resolves a name-and-type entry into only the method/field name for readable refs.
fn resolve_member_name(entries: &[ConstantPoolEntry], index: u16) -> Option<String> {
    match entries.get(index as usize)? {
        ConstantPoolEntry::NameAndType { name_index } => match entries.get(*name_index as usize)? {
            ConstantPoolEntry::Utf8(value) => Some(value.clone()),
            _ => None,
        },
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
}
