/// Result of parsing a Java class file enough to extract strings and API references.
#[derive(Debug, Default)]
pub struct ClassFileData {
    pub strings: Vec<String>,
    pub bytecode_refs: Vec<String>,
    pub archive_signals: Vec<String>,
    pub class_name: Option<String>,
    pub major_version: u16,
    /// Method-level data used by later correlation passes. Parsing this data is
    /// deliberately static: no class, resource, or native code is executed.
    pub methods: Vec<MethodScanData>,
}

/// Static representation of one JVM method body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MethodScanData {
    pub class_name: String,
    pub method_name: String,
    pub descriptor: String,
    pub instructions: Vec<Instruction>,
    pub constants: Vec<LoadedConstant>,
    pub calls: Vec<CallSite>,
    pub field_reads: Vec<FieldAccess>,
    pub field_writes: Vec<FieldAccess>,
    pub basic_blocks: Vec<BasicBlock>,
    pub control_flow_edges: Vec<ControlFlowEdge>,
    /// Origins assigned to locals by stores in the linear, conservative pass.
    pub local_origins: Vec<LocalValueOrigin>,
    /// Origins observed on the operand stack immediately before calls.
    pub stack_origins: Vec<StackOrigin>,
}

/// A decoded JVM instruction. `operands` retain their original bytecode form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub offset: u32,
    pub opcode: u8,
    pub operands: Vec<u8>,
}

/// Constant loaded by `ldc`, `ldc_w`, or `ldc2_w`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedConstant {
    pub offset: u32,
    pub value: ConstantValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConstantValue {
    String(String),
    Integer(i32),
    Class(String),
    Unknown,
}

/// Invocation resolved from an invoke instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallSite {
    pub offset: u32,
    pub kind: InvokeKind,
    pub owner: Option<String>,
    pub name: String,
    pub descriptor: String,
    pub receiver_origin: Option<ValueOrigin>,
    pub argument_origins: Vec<ValueOrigin>,
    pub result_origin: Option<ValueOrigin>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvokeKind {
    Virtual,
    Special,
    Static,
    Interface,
    Dynamic,
}

/// A resolved field read or write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldAccess {
    pub offset: u32,
    pub owner: String,
    pub name: String,
    pub descriptor: String,
    pub value_origin: Option<ValueOrigin>,
}

/// A basic block defined using bytecode instruction boundaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicBlock {
    pub id: u32,
    pub start_offset: u32,
    pub end_offset: u32,
    pub successors: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlFlowEdge {
    pub from_offset: u32,
    pub to_offset: u32,
    pub kind: ControlFlowEdgeKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlFlowEdgeKind {
    Fallthrough,
    Branch,
    Switch,
}

/// A conservative origin for a JVM stack value. Unknown is preferred to
/// guessing across unsupported instructions or control-flow joins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValueOrigin {
    Constant(ConstantValue),
    Local(u16),
    Field {
        owner: String,
        name: String,
        descriptor: String,
    },
    Instruction(u32),
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalValueOrigin {
    pub offset: u32,
    pub local_index: u16,
    pub origin: ValueOrigin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackOrigin {
    pub offset: u32,
    pub values: Vec<ValueOrigin>,
}

const XOR_LOOP_SIGNAL: &str = "xor_loop_string_decode";
const MIN_DECODED_STRING_LENGTH: usize = 4;

#[derive(Clone, Debug)]
enum ConstantPoolEntry {
    Utf8(String),
    Integer(i32),
    String {
        string_index: u16,
    },
    Class {
        name_index: u16,
    },
    NameAndType {
        name_index: u16,
        descriptor_index: u16,
    },
    Ref {
        tag: u8,
        class_index: u16,
        name_and_type_index: u16,
    },
    Dynamic {
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
    let mut methods = Vec::new();
    let has_string_byte_constructor = has_string_byte_constructor(&entries);
    parse_methods(
        &mut cursor,
        &entries,
        has_string_byte_constructor,
        &mut method_strings,
        &mut archive_signals,
        class_name.as_deref().unwrap_or_default(),
        &mut methods,
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
            ..
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
        methods,
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
                entries[index] = ConstantPoolEntry::String {
                    string_index: cursor.read_u16()?,
                }
            }
            9..=11 => {
                entries[index] = ConstantPoolEntry::Ref {
                    tag,
                    class_index: cursor.read_u16()?,
                    name_and_type_index: cursor.read_u16()?,
                };
            }
            12 => {
                entries[index] = ConstantPoolEntry::NameAndType {
                    name_index: cursor.read_u16()?,
                    descriptor_index: cursor.read_u16()?,
                };
            }
            17 | 18 => {
                cursor.skip(2)?;
                entries[index] = ConstantPoolEntry::Dynamic {
                    name_and_type_index: cursor.read_u16()?,
                };
            }
            4 => {
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
    class_name: &str,
    methods: &mut Vec<MethodScanData>,
) -> anyhow::Result<()> {
    let method_count = cursor.read_u16()? as usize;
    for _ in 0..method_count {
        let _access_flags = cursor.read_u16()?;
        let name_index = cursor.read_u16()?;
        let descriptor_index = cursor.read_u16()?;
        let method_name = utf8(entries, name_index)
            .ok_or_else(|| anyhow::anyhow!("method name is not UTF-8"))?
            .to_owned();
        let descriptor = utf8(entries, descriptor_index)
            .ok_or_else(|| anyhow::anyhow!("method descriptor is not UTF-8"))?
            .to_owned();
        let attribute_count = cursor.read_u16()? as usize;
        for _ in 0..attribute_count {
            let attribute_name_index = cursor.read_u16()?;
            let attribute_length = cursor.read_u32()? as usize;
            let attribute_bytes = cursor.read_bytes(attribute_length)?;
            if utf8(entries, attribute_name_index).is_some_and(|name| name == "Code") {
                let method = inspect_code_attribute(
                    attribute_bytes,
                    entries,
                    has_string_byte_constructor,
                    strings,
                    archive_signals,
                    class_name,
                    &method_name,
                    &descriptor,
                )?;
                methods.push(method);
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
    entries: &[ConstantPoolEntry],
    has_string_byte_constructor: bool,
    strings: &mut Vec<String>,
    archive_signals: &mut Vec<String>,
    class_name: &str,
    method_name: &str,
    descriptor: &str,
) -> anyhow::Result<MethodScanData> {
    let mut cursor = ClassCursor::new(bytes);
    let _max_stack = cursor.read_u16()?;
    let _max_locals = cursor.read_u16()?;
    let code_length = cursor.read_u32()? as usize;
    // The JVM class-file format limits a method body to 65,535 bytes. Enforce
    // that limit here rather than accepting a malformed blob indefinitely.
    if code_length > u16::MAX as usize {
        anyhow::bail!("method code exceeds JVM size limit");
    }
    let code = cursor.read_bytes(code_length)?;

    strings.extend(recover_byte_array_strings(code));
    if has_string_byte_constructor && has_xor_loop(code) {
        archive_signals.push(XOR_LOOP_SIGNAL.to_owned());
    }

    parse_method_code(entries, code, class_name, method_name, descriptor)
}

fn parse_method_code(
    entries: &[ConstantPoolEntry],
    code: &[u8],
    class_name: &str,
    method_name: &str,
    descriptor: &str,
) -> anyhow::Result<MethodScanData> {
    let instructions = decode_instructions(code)?;
    let (control_flow_edges, basic_blocks) = build_cfg(&instructions, code.len())?;
    let mut data = MethodScanData {
        class_name: class_name.to_owned(),
        method_name: method_name.to_owned(),
        descriptor: descriptor.to_owned(),
        instructions,
        basic_blocks,
        control_flow_edges,
        ..MethodScanData::default()
    };
    populate_value_origins(entries, &mut data)?;
    Ok(data)
}

fn decode_instructions(code: &[u8]) -> anyhow::Result<Vec<Instruction>> {
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < code.len() {
        let opcode = code[offset];
        let length = opcode_length(opcode, code, offset)
            .ok_or_else(|| anyhow::anyhow!("truncated instruction at bytecode offset {offset}"))?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("bytecode offset overflow"))?;
        if end > code.len() {
            anyhow::bail!("truncated instruction at bytecode offset {offset}");
        }
        instructions.push(Instruction {
            offset: offset as u32,
            opcode,
            operands: code[offset + 1..end].to_vec(),
        });
        offset = end;
    }
    Ok(instructions)
}

fn build_cfg(
    instructions: &[Instruction],
    code_length: usize,
) -> anyhow::Result<(Vec<ControlFlowEdge>, Vec<BasicBlock>)> {
    if instructions.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let offsets: std::collections::BTreeSet<u32> = instructions
        .iter()
        .map(|instruction| instruction.offset)
        .collect();
    let mut leaders = std::collections::BTreeSet::from([0_u32]);
    let mut edges = Vec::new();
    for (index, instruction) in instructions.iter().enumerate() {
        let next = instructions.get(index + 1).map(|value| value.offset);
        let targets = branch_targets(instruction)?;
        let is_unconditional = matches!(instruction.opcode, 0xa7 | 0xa8 | 0xc8 | 0xc9);
        let is_terminal = matches!(instruction.opcode, 0xac..=0xb1 | 0xbf);
        for (target, kind) in &targets {
            if *target < 0
                || *target as usize >= code_length
                || !offsets.contains(&(*target as u32))
            {
                anyhow::bail!(
                    "invalid branch target {target} at bytecode offset {}",
                    instruction.offset
                );
            }
            leaders.insert(*target as u32);
            edges.push(ControlFlowEdge {
                from_offset: instruction.offset,
                to_offset: *target as u32,
                kind: *kind,
            });
        }
        if let Some(next) = next.filter(|_| !is_unconditional && !is_terminal) {
            if !targets.is_empty() {
                leaders.insert(next);
            }
            edges.push(ControlFlowEdge {
                from_offset: instruction.offset,
                to_offset: next,
                kind: ControlFlowEdgeKind::Fallthrough,
            });
        }
    }

    let leader_offsets: Vec<u32> = leaders.into_iter().collect();
    let mut blocks = Vec::new();
    for (id, start_offset) in leader_offsets.iter().enumerate() {
        let end_offset = leader_offsets
            .get(id + 1)
            .copied()
            .unwrap_or(code_length as u32);
        let last_offset = instructions
            .iter()
            .filter(|instruction| {
                instruction.offset >= *start_offset && instruction.offset < end_offset
            })
            .map(|instruction| instruction.offset)
            .last()
            .unwrap_or(*start_offset);
        let successors = edges
            .iter()
            .filter(|edge| edge.from_offset == last_offset)
            .map(|edge| edge.to_offset)
            .collect();
        blocks.push(BasicBlock {
            id: id as u32,
            start_offset: *start_offset,
            end_offset,
            successors,
        });
    }
    Ok((edges, blocks))
}

fn branch_targets(instruction: &Instruction) -> anyhow::Result<Vec<(i64, ControlFlowEdgeKind)>> {
    let offset = i64::from(instruction.offset);
    match instruction.opcode {
        0x99..=0xa8 | 0xc6 | 0xc7 => {
            let branch = i16::from_be_bytes([instruction.operands[0], instruction.operands[1]]);
            Ok(vec![(
                offset + i64::from(branch),
                ControlFlowEdgeKind::Branch,
            )])
        }
        0xc8 | 0xc9 => {
            let branch = i32::from_be_bytes([
                instruction.operands[0],
                instruction.operands[1],
                instruction.operands[2],
                instruction.operands[3],
            ]);
            Ok(vec![(
                offset + i64::from(branch),
                ControlFlowEdgeKind::Branch,
            )])
        }
        0xaa => switch_targets(&instruction.operands, true, offset, instruction.offset),
        0xab => switch_targets(&instruction.operands, false, offset, instruction.offset),
        _ => Ok(Vec::new()),
    }
}

fn switch_targets(
    operands: &[u8],
    table: bool,
    offset: i64,
    instruction_offset: u32,
) -> anyhow::Result<Vec<(i64, ControlFlowEdgeKind)>> {
    let header = (4 - ((instruction_offset as usize + 1) % 4)) % 4;
    let minimum = if table { 12 } else { 8 };
    if operands.len() < header + minimum {
        anyhow::bail!("truncated switch instruction");
    }
    let default = read_i32(operands, header)
        .ok_or_else(|| anyhow::anyhow!("truncated switch instruction"))?;
    let mut targets = vec![(offset + i64::from(default), ControlFlowEdgeKind::Switch)];
    if table {
        let low = read_i32(operands, header + 4)
            .ok_or_else(|| anyhow::anyhow!("truncated switch instruction"))?;
        let high = read_i32(operands, header + 8)
            .ok_or_else(|| anyhow::anyhow!("truncated switch instruction"))?;
        let count =
            high.checked_sub(low)
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| anyhow::anyhow!("invalid tableswitch range"))? as usize;
        for index in 0..count {
            let branch = read_i32(operands, header + 12 + index * 4)
                .ok_or_else(|| anyhow::anyhow!("truncated switch instruction"))?;
            targets.push((offset + i64::from(branch), ControlFlowEdgeKind::Switch));
        }
    } else {
        let pairs = read_i32(operands, header + 4)
            .ok_or_else(|| anyhow::anyhow!("truncated switch instruction"))?
            as usize;
        for index in 0..pairs {
            let branch = read_i32(operands, header + 8 + index * 8 + 4)
                .ok_or_else(|| anyhow::anyhow!("truncated switch instruction"))?;
            targets.push((offset + i64::from(branch), ControlFlowEdgeKind::Switch));
        }
    }
    Ok(targets)
}

fn populate_value_origins(
    entries: &[ConstantPoolEntry],
    data: &mut MethodScanData,
) -> anyhow::Result<()> {
    let mut stack = Vec::new();
    let mut locals = std::collections::BTreeMap::<u16, ValueOrigin>::new();

    for instruction in data.instructions.clone() {
        let offset = instruction.offset;
        match instruction.opcode {
            0x01 => stack.push(ValueOrigin::Unknown),
            0x02..=0x08 => stack.push(ValueOrigin::Constant(ConstantValue::Integer(
                i32::from(instruction.opcode) - i32::from(0x03_u8),
            ))),
            0x10 => stack.push(ValueOrigin::Constant(ConstantValue::Integer(i32::from(
                instruction.operands[0] as i8,
            )))),
            0x11 => stack.push(ValueOrigin::Constant(ConstantValue::Integer(i32::from(
                i16::from_be_bytes([instruction.operands[0], instruction.operands[1]]),
            )))),
            0x12 | 0x13 | 0x14 => {
                let index = if instruction.opcode == 0x12 {
                    u16::from(instruction.operands[0])
                } else {
                    u16::from_be_bytes([instruction.operands[0], instruction.operands[1]])
                };
                let value = constant_value(entries, index);
                data.constants.push(LoadedConstant {
                    offset,
                    value: value.clone(),
                });
                stack.push(ValueOrigin::Constant(value));
            }
            0x15..=0x19 => {
                let index = u16::from(instruction.operands[0]);
                stack.push(
                    locals
                        .get(&index)
                        .cloned()
                        .unwrap_or(ValueOrigin::Local(index)),
                );
            }
            0x1a..=0x2d => {
                let index = u16::from((instruction.opcode - 0x1a) % 4);
                stack.push(
                    locals
                        .get(&index)
                        .cloned()
                        .unwrap_or(ValueOrigin::Local(index)),
                );
            }
            0x36..=0x3a => {
                let index = u16::from(instruction.operands[0]);
                store_local(
                    &mut stack,
                    &mut locals,
                    &mut data.local_origins,
                    offset,
                    index,
                );
            }
            0x3b..=0x4e => {
                let index = u16::from((instruction.opcode - 0x3b) % 4);
                store_local(
                    &mut stack,
                    &mut locals,
                    &mut data.local_origins,
                    offset,
                    index,
                );
            }
            0x57 => {
                let _ = stack.pop();
            }
            0x58 => {
                let _ = stack.pop();
                let _ = stack.pop();
            }
            0x59 => {
                if let Some(value) = stack.last().cloned() {
                    stack.push(value);
                }
            }
            0x5f => {
                let (Some(last), Some(previous)) = (stack.pop(), stack.pop()) else {
                    stack.clear();
                    continue;
                };
                stack.push(last);
                stack.push(previous);
            }
            0x60..=0x83 | 0x85..=0x98 => {
                let _ = stack.pop();
                let _ = stack.pop();
                stack.push(ValueOrigin::Instruction(offset));
            }
            0x84 => {}
            0xb2..=0xb5 => populate_field_access(entries, &instruction, &mut stack, data)?,
            0xb6..=0xb9 | 0xba => populate_call(entries, &instruction, &mut stack, data)?,
            0xbb | 0xbd | 0xc5 => stack.push(ValueOrigin::Instruction(offset)),
            0xbc => {
                let _ = stack.pop();
                stack.push(ValueOrigin::Instruction(offset));
            }
            0xbe => {
                let _ = stack.pop();
                stack.push(ValueOrigin::Instruction(offset));
            }
            0xbf | 0xac..=0xb1 => stack.clear(),
            _ => {}
        }

        if !branch_targets(&instruction)?.is_empty() {
            // A single linear state cannot soundly represent a join. Clear it
            // rather than fabricating a value relationship across branches.
            stack.clear();
        }
    }
    Ok(())
}

fn store_local(
    stack: &mut Vec<ValueOrigin>,
    locals: &mut std::collections::BTreeMap<u16, ValueOrigin>,
    records: &mut Vec<LocalValueOrigin>,
    offset: u32,
    local_index: u16,
) {
    let origin = stack.pop().unwrap_or(ValueOrigin::Unknown);
    locals.insert(local_index, origin.clone());
    records.push(LocalValueOrigin {
        offset,
        local_index,
        origin,
    });
}

fn populate_field_access(
    entries: &[ConstantPoolEntry],
    instruction: &Instruction,
    stack: &mut Vec<ValueOrigin>,
    data: &mut MethodScanData,
) -> anyhow::Result<()> {
    let index = u16::from_be_bytes([instruction.operands[0], instruction.operands[1]]);
    let (owner, name, descriptor) = resolve_field_ref(entries, index).ok_or_else(|| {
        anyhow::anyhow!(
            "unresolvable field reference at bytecode offset {}",
            instruction.offset
        )
    })?;
    match instruction.opcode {
        0xb2 => {
            data.field_reads.push(FieldAccess {
                offset: instruction.offset,
                owner: owner.clone(),
                name: name.clone(),
                descriptor: descriptor.clone(),
                value_origin: None,
            });
            stack.push(ValueOrigin::Field {
                owner,
                name,
                descriptor,
            });
        }
        0xb3 => {
            let value_origin = stack.pop().unwrap_or(ValueOrigin::Unknown);
            data.field_writes.push(FieldAccess {
                offset: instruction.offset,
                owner,
                name,
                descriptor,
                value_origin: Some(value_origin),
            });
        }
        0xb4 => {
            let _ = stack.pop();
            data.field_reads.push(FieldAccess {
                offset: instruction.offset,
                owner: owner.clone(),
                name: name.clone(),
                descriptor: descriptor.clone(),
                value_origin: None,
            });
            stack.push(ValueOrigin::Field {
                owner,
                name,
                descriptor,
            });
        }
        0xb5 => {
            let value_origin = stack.pop().unwrap_or(ValueOrigin::Unknown);
            let _ = stack.pop();
            data.field_writes.push(FieldAccess {
                offset: instruction.offset,
                owner,
                name,
                descriptor,
                value_origin: Some(value_origin),
            });
        }
        _ => unreachable!("only field access instructions are passed here"),
    }
    Ok(())
}

fn populate_call(
    entries: &[ConstantPoolEntry],
    instruction: &Instruction,
    stack: &mut Vec<ValueOrigin>,
    data: &mut MethodScanData,
) -> anyhow::Result<()> {
    let index = u16::from_be_bytes([instruction.operands[0], instruction.operands[1]]);
    let (kind, reference) = match instruction.opcode {
        0xb6 => (InvokeKind::Virtual, resolve_member_ref(entries, index)),
        0xb7 => (InvokeKind::Special, resolve_member_ref(entries, index)),
        0xb8 => (InvokeKind::Static, resolve_member_ref(entries, index)),
        0xb9 => (InvokeKind::Interface, resolve_member_ref(entries, index)),
        0xba => (InvokeKind::Dynamic, resolve_dynamic_ref(entries, index)),
        _ => unreachable!("only invoke instructions are passed here"),
    };
    let (owner, name, descriptor) =
        reference.unwrap_or_else(|| (String::new(), "<unresolved>".to_owned(), "()V".to_owned()));
    let (argument_count, has_result) = descriptor_shape(&descriptor).unwrap_or((0, false));
    let mut argument_origins = Vec::with_capacity(argument_count);
    for _ in 0..argument_count {
        argument_origins.push(stack.pop().unwrap_or(ValueOrigin::Unknown));
    }
    argument_origins.reverse();
    let receiver_origin = match kind {
        InvokeKind::Static | InvokeKind::Dynamic => None,
        _ => Some(stack.pop().unwrap_or(ValueOrigin::Unknown)),
    };
    data.stack_origins.push(StackOrigin {
        offset: instruction.offset,
        values: argument_origins.clone(),
    });
    let result_origin = has_result.then_some(ValueOrigin::Instruction(instruction.offset));
    data.calls.push(CallSite {
        offset: instruction.offset,
        kind,
        owner: (!owner.is_empty()).then_some(owner),
        name,
        descriptor,
        receiver_origin,
        argument_origins,
        result_origin: result_origin.clone(),
    });
    if let Some(origin) = result_origin {
        stack.push(origin);
    }
    Ok(())
}

fn constant_value(entries: &[ConstantPoolEntry], index: u16) -> ConstantValue {
    match entries.get(index as usize) {
        Some(ConstantPoolEntry::String { string_index }) => utf8(entries, *string_index)
            .map(|value| ConstantValue::String(value.to_owned()))
            .unwrap_or(ConstantValue::Unknown),
        Some(ConstantPoolEntry::Integer(value)) => ConstantValue::Integer(*value),
        Some(ConstantPoolEntry::Class { .. }) => resolve_class_name(entries, index)
            .map(ConstantValue::Class)
            .unwrap_or(ConstantValue::Unknown),
        _ => ConstantValue::Unknown,
    }
}

fn resolve_member_ref(
    entries: &[ConstantPoolEntry],
    index: u16,
) -> Option<(String, String, String)> {
    let ConstantPoolEntry::Ref {
        tag,
        class_index,
        name_and_type_index,
    } = entries.get(index as usize)?
    else {
        return None;
    };
    if !matches!(*tag, 10 | 11) {
        return None;
    }
    resolve_ref_parts(entries, *class_index, *name_and_type_index)
}

fn resolve_field_ref(
    entries: &[ConstantPoolEntry],
    index: u16,
) -> Option<(String, String, String)> {
    let ConstantPoolEntry::Ref {
        tag,
        class_index,
        name_and_type_index,
    } = entries.get(index as usize)?
    else {
        return None;
    };
    if *tag != 9 {
        return None;
    }
    resolve_ref_parts(entries, *class_index, *name_and_type_index)
}

fn resolve_ref_parts(
    entries: &[ConstantPoolEntry],
    class_index: u16,
    name_and_type_index: u16,
) -> Option<(String, String, String)> {
    let owner = resolve_class_name(entries, class_index)?;
    let (name, descriptor) = resolve_name_and_type(entries, name_and_type_index)?;
    Some((owner, name, descriptor))
}

fn resolve_dynamic_ref(
    entries: &[ConstantPoolEntry],
    index: u16,
) -> Option<(String, String, String)> {
    let ConstantPoolEntry::Dynamic {
        name_and_type_index,
    } = entries.get(index as usize)?
    else {
        return None;
    };
    let (name, descriptor) = resolve_name_and_type(entries, *name_and_type_index)?;
    Some((String::new(), name, descriptor))
}

fn resolve_name_and_type(entries: &[ConstantPoolEntry], index: u16) -> Option<(String, String)> {
    let ConstantPoolEntry::NameAndType {
        name_index,
        descriptor_index,
    } = entries.get(index as usize)?
    else {
        return None;
    };
    Some((
        utf8(entries, *name_index)?.to_owned(),
        utf8(entries, *descriptor_index)?.to_owned(),
    ))
}

fn descriptor_shape(descriptor: &str) -> Option<(usize, bool)> {
    let bytes = descriptor.as_bytes();
    if bytes.first().copied()? != b'(' {
        return None;
    }
    let mut index = 1;
    let mut arguments = 0;
    while *bytes.get(index)? != b')' {
        index = descriptor_type_end(bytes, index)?;
        arguments += 1;
    }
    let return_start = index + 1;
    Some((arguments, *bytes.get(return_start)? != b'V'))
}

fn descriptor_type_end(bytes: &[u8], mut index: usize) -> Option<usize> {
    while *bytes.get(index)? == b'[' {
        index += 1;
    }
    match *bytes.get(index)? {
        b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'Z' | b'V' => Some(index + 1),
        b'L' => bytes[index + 1..]
            .iter()
            .position(|value| *value == b';')
            .map(|position| index + 2 + position),
        _ => None,
    }
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
            ..
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
        ConstantPoolEntry::NameAndType { name_index, .. } => {
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

    #[test]
    fn parses_call_constants_and_stack_origins_without_execution() {
        let entries = vec![
            super::ConstantPoolEntry::Other,
            super::ConstantPoolEntry::Class { name_index: 2 },
            super::ConstantPoolEntry::Utf8("example/Target".to_owned()),
            super::ConstantPoolEntry::NameAndType {
                name_index: 4,
                descriptor_index: 5,
            },
            super::ConstantPoolEntry::Utf8("send".to_owned()),
            super::ConstantPoolEntry::Utf8("(Ljava/lang/String;)V".to_owned()),
            super::ConstantPoolEntry::Ref {
                tag: 10,
                class_index: 1,
                name_and_type_index: 3,
            },
            super::ConstantPoolEntry::String { string_index: 8 },
            super::ConstantPoolEntry::Utf8("https://example.invalid/payload".to_owned()),
        ];
        let code = [0x12, 0x07, 0xb8, 0x00, 0x06, 0xb1];

        let method = super::parse_method_code(&entries, &code, "example/Test", "run", "()V")
            .expect("bounded static parse must succeed");

        assert_eq!(method.instructions[0].offset, 0);
        assert_eq!(method.constants.len(), 1);
        assert_eq!(
            method.constants[0].value,
            super::ConstantValue::String("https://example.invalid/payload".to_owned())
        );
        assert_eq!(method.calls.len(), 1);
        assert_eq!(method.calls[0].owner.as_deref(), Some("example/Target"));
        assert_eq!(method.calls[0].name, "send");
        assert_eq!(
            method.calls[0].argument_origins,
            vec![super::ValueOrigin::Constant(super::ConstantValue::String(
                "https://example.invalid/payload".to_owned()
            ))]
        );
    }

    #[test]
    fn builds_cfg_using_valid_bytecode_offsets() {
        // iconst_0; ifeq +4; return; return
        let code = [0x03, 0x99, 0x00, 0x04, 0xb1, 0xb1];
        let method = super::parse_method_code(&[], &code, "example/Test", "branch", "()V")
            .expect("bounded static parse must succeed");

        assert!(method.control_flow_edges.iter().any(|edge| {
            edge.from_offset == 1
                && edge.to_offset == 5
                && edge.kind == super::ControlFlowEdgeKind::Branch
        }));
        assert!(method.control_flow_edges.iter().any(|edge| {
            edge.from_offset == 1
                && edge.to_offset == 4
                && edge.kind == super::ControlFlowEdgeKind::Fallthrough
        }));
        assert_eq!(method.basic_blocks.len(), 3);
    }
}
