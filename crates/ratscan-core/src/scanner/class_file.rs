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
    /// Distinct bootstrap methods referenced by `invokedynamic` and dynamic
    /// constants, excluding JDK and known language-runtime factories.
    pub custom_bootstrap_methods: Vec<BootstrapMethodRef>,
}

/// A bootstrap method that links an `invokedynamic` call site or a dynamic constant.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootstrapMethodRef {
    pub owner: String,
    pub name: String,
    pub descriptor: String,
}

/// Static representation of one JVM method body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MethodScanData {
    pub class_name: String,
    pub method_name: String,
    pub descriptor: String,
    pub is_static: bool,
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
    /// Values returned by explicit JVM return instructions.
    pub return_origins: Vec<ReturnOrigin>,
    /// Reference, byte, and char assignments observed in the linear pass.
    /// Used for varargs, constant binary signatures, and literal decoders.
    pub array_elements: Vec<ArrayElementOrigin>,
    /// Reference/byte reads retained for bootstrap tables and container headers.
    pub array_reads: Vec<ArrayReadOrigin>,
    /// Conditional values retained so security recognizers can prove that a
    /// rejecting branch guards a following sensitive operation.
    pub branch_conditions: Vec<BranchCondition>,
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
    /// The object read or written by instance field instructions; absent for statics.
    pub receiver_origin: Option<ValueOrigin>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReturnOrigin {
    pub offset: u32,
    pub value_origin: Option<ValueOrigin>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArrayElementOrigin {
    pub offset: u32,
    pub array_origin: ValueOrigin,
    pub index: Option<u16>,
    pub value_origin: ValueOrigin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArrayReadOrigin {
    pub offset: u32,
    pub array_origin: ValueOrigin,
    pub index_origin: ValueOrigin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchCondition {
    pub offset: u32,
    pub opcode: u8,
    pub value_origin: ValueOrigin,
    pub compared_origin: Option<ValueOrigin>,
}

const XOR_LOOP_SIGNAL: &str = "xor_loop_string_decode";
const MIN_DECODED_STRING_LENGTH: usize = 4;

#[derive(Clone, Debug)]
enum ConstantPoolEntry {
    Utf8(String),
    /// Modified UTF-8 may encode unpaired UTF-16 units in encrypted literals.
    Utf16(Vec<u16>),
    ResolvedString(String),
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
        bootstrap_method_attr_index: u16,
        name_and_type_index: u16,
    },
    MethodHandle {
        reference_index: u16,
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
    let mut entries = parse_constant_pool(&mut cursor)?;

    let _access_flags = cursor.read_u16()?;
    let this_class = cursor.read_u16()?;
    let _super_class = cursor.read_u16()?;
    let class_name = resolve_class_name(&entries, this_class);

    skip_interfaces(&mut cursor)?;
    let private_fields = private_static_fields(&mut cursor, &entries)?;

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
    let (bootstrap_method_handles, bootstrap_arguments) =
        parse_bootstrap_method_handles(&mut cursor, &entries)?;
    let custom_bootstrap_methods = custom_bootstrap_methods(&entries, &bootstrap_method_handles);

    normalize_hidden_literals(
        &mut entries,
        &mut methods,
        &bootstrap_method_handles,
        &bootstrap_arguments,
        class_name.as_deref().unwrap_or_default(),
        &private_fields,
    )?;

    let mut strings = constant_pool_strings(&entries);
    strings.extend(integer_ip_strings(&entries));
    strings.extend(method_strings);
    strings.extend(
        methods
            .iter()
            .flat_map(|method| method.constants.iter())
            .filter_map(|constant| {
                if let ConstantValue::String(value) = &constant.value {
                    Some(value.clone())
                } else {
                    None
                }
            }),
    );

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
        custom_bootstrap_methods,
    })
}

fn modified_utf16(bytes: &[u8]) -> anyhow::Result<Vec<u16>> {
    if let Ok(value) = std::str::from_utf8(bytes) {
        return Ok(value.encode_utf16().collect());
    }
    let mut units = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let first = bytes[index];
        let (width, mut value) = match first {
            0..=0x7f => (1, u16::from(first)),
            0xc0..=0xdf => (2, u16::from(first & 0x1f)),
            0xe0..=0xef => (3, u16::from(first & 0x0f)),
            _ => anyhow::bail!("invalid modified UTF-8 leading byte"),
        };
        for next in 1..width {
            let byte = *bytes
                .get(index + next)
                .ok_or_else(|| anyhow::anyhow!("truncated modified UTF-8"))?;
            if byte & 0xc0 != 0x80 {
                anyhow::bail!("invalid modified UTF-8 continuation")
            }
            value = (value << 6) | u16::from(byte & 0x3f);
        }
        units.push(value);
        index += width;
    }
    Ok(units)
}

/// Only two explicit, bounded literal-decoder templates are evaluated. This
/// never invokes a bootstrap, class initializer, reflection, or archive code.
fn normalize_hidden_literals(
    entries: &mut [ConstantPoolEntry],
    methods: &mut [MethodScanData],
    handles: &[u16],
    arguments: &[Vec<u16>],
    class_name: &str,
    private_fields: &[(String, String)],
) -> anyhow::Result<()> {
    let mut remaining_bytes = MAX_NORMALIZED_STRING_BYTES;
    let decoders = methods
        .iter()
        .filter(|method| char_array_decoder(method))
        .map(|method| method.method_name.clone())
        .collect::<Vec<_>>();
    let mut resolved = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let ConstantPoolEntry::Dynamic {
            bootstrap_method_attr_index,
            name_and_type_index,
        } = entry
        else {
            continue;
        };
        if resolve_name_and_type(entries, *name_and_type_index)
            .is_none_or(|(_, descriptor)| descriptor != "Ljava/lang/String;")
        {
            continue;
        }
        let bootstrap_index = usize::from(*bootstrap_method_attr_index);
        let Some(bootstrap) = handles
            .get(bootstrap_index)
            .and_then(|handle| resolve_method_handle(entries, *handle))
        else {
            continue;
        };
        if bootstrap.owner != class_name
            || !methods.iter().any(|method| {
                method.method_name == bootstrap.name
                    && method.descriptor == bootstrap.descriptor
                    && indexed_constant_decoder(method)
            })
        {
            continue;
        }
        let Some(args) = arguments.get(bootstrap_index) else {
            continue;
        };
        let [cipher, key, salt] = args.as_slice() else {
            continue;
        };
        let Some(ConstantPoolEntry::String { string_index }) = entries.get(usize::from(*cipher))
        else {
            continue;
        };
        let units = match entries.get(usize::from(*string_index)) {
            Some(ConstantPoolEntry::Utf8(value)) => value.encode_utf16().collect::<Vec<_>>(),
            Some(ConstantPoolEntry::Utf16(units)) => units.clone(),
            _ => continue,
        };
        if units.len() > 16 * 1024 {
            continue;
        }
        // Charge the maximum UTF-8 size before decoding, including repeated
        // CP references to the same cipher. Class-wide expansion is bounded.
        let cost = units.len().saturating_mul(3).max(1);
        if cost > remaining_bytes {
            break;
        }
        remaining_bytes -= cost;
        let (Some(ConstantPoolEntry::Integer(key)), Some(ConstantPoolEntry::Integer(salt))) = (
            entries.get(usize::from(*key)),
            entries.get(usize::from(*salt)),
        ) else {
            continue;
        };
        let decoded = units
            .iter()
            .enumerate()
            .map(|(i, unit)| unit ^ (*key as u16) ^ (salt.wrapping_add(i as i32) as u16))
            .collect::<Vec<_>>();
        if let Ok(value) = String::from_utf16(&decoded) {
            resolved.push((index, value));
        }
    }
    if resolved.is_empty() && decoders.is_empty() {
        return Ok(());
    }
    for (index, value) in resolved {
        entries[index] = ConstantPoolEntry::ResolvedString(value);
    }
    for method in methods.iter_mut() {
        method.constants.clear();
        method.calls.clear();
        method.field_reads.clear();
        method.field_writes.clear();
        method.local_origins.clear();
        method.stack_origins.clear();
        method.return_origins.clear();
        method.array_elements.clear();
        method.array_reads.clear();
        method.branch_conditions.clear();
        populate_value_origins_with_budget(entries, method, &decoders, &mut remaining_bytes)?;
    }
    resolve_table_calls(entries, methods, handles, class_name, private_fields);
    Ok(())
}

/// The supported loop computes `(char + shift) - key[index % key.length]`.
/// Operand slots, loop guards, updates and returned array must all agree.
fn char_array_decoder(method: &MethodScanData) -> bool {
    method.is_static
        && decoder_loop(method, 4, 0, true)
        && method.local_origins.len() == 5
        && method
            .local_origins
            .iter()
            .all(|record| (3..=7).contains(&record.local_index))
        && method
            .instructions
            .iter()
            .filter(|instruction| instruction.opcode == 0x84)
            .count()
            == 2
        && method.descriptor == "([CLjava/lang/String;I)Ljava/lang/String;"
        && method.calls.len() == 3
        && method.calls.iter().all(|call| {
            call.owner.as_deref() == Some("java/lang/String")
                && matches!(call.name.as_str(), "length" | "charAt" | "<init>")
        })
        && method.instructions.windows(4).any(|window| {
            window
                .iter()
                .map(|instruction| instruction.opcode)
                .eq([0x60, 0x15, 0x64, 0x92])
        })
        && method
            .instructions
            .iter()
            .filter(|instruction| instruction.opcode == 0x55)
            .count()
            == 1
        && [0x34, 0x60, 0x64, 0x70, 0x92].into_iter().all(|opcode| {
            method
                .instructions
                .iter()
                .filter(|instruction| instruction.opcode == opcode)
                .count()
                == 1
        })
        && [3, 4].into_iter().all(|slot| {
            method
                .local_origins
                .iter()
                .filter(|record| record.local_index == slot)
                .count()
                == 1
                && method.local_origins.iter().any(|record| {
                    record.local_index == slot
                        && record.origin == ValueOrigin::Constant(ConstantValue::Integer(0))
                })
                && method.instructions.iter().any(|instruction| {
                    instruction.opcode == 0x84 && instruction.operands == [slot as u8, 1]
                })
        })
        && method.field_writes.is_empty()
        && method.calls.iter().any(|call| {
            call.name == "charAt" && call.receiver_origin == Some(ValueOrigin::Local(1))
        })
        && method.calls.iter().any(|call| {
            call.name == "length" && call.receiver_origin == Some(ValueOrigin::Local(1))
        })
        && method.calls.iter().any(|call| {
            call.name == "<init>"
                && call.argument_origins == [ValueOrigin::Local(0)]
                && method.return_origins.len() == 1
                && method.return_origins[0].value_origin == call.receiver_origin
        })
        && method
            .control_flow_edges
            .iter()
            .any(|edge| edge.to_offset < edge.from_offset)
        && method
            .control_flow_edges
            .iter()
            .filter(|edge| edge.kind == ControlFlowEdgeKind::Branch)
            .count()
            == 2
        && method.instructions.windows(11).any(|w| {
            local_load(&w[0]) == Some(5)
                && local_load(&w[1]) == Some(2)
                && w[2].opcode == 0x60
                && local_load(&w[3]) == Some(6)
                && w[4].opcode == 0x64
                && w[5].opcode == 0x92
                && local_store(&w[6]) == Some(7)
                && local_load(&w[7]) == Some(0)
                && local_load(&w[8]) == Some(4)
                && local_load(&w[9]) == Some(7)
                && w[10].opcode == 0x55
        })
        && method.instructions.windows(6).any(|w| {
            local_load(&w[0]) == Some(1)
                && local_load(&w[1]) == Some(3)
                && local_load(&w[2]) == Some(1)
                && w[4].opcode == 0x70
                && method
                    .calls
                    .iter()
                    .any(|call| call.offset == w[3].offset && call.name == "length")
                && method
                    .calls
                    .iter()
                    .any(|call| call.offset == w[5].offset && call.name == "charAt")
        })
        && method.instructions.windows(3).any(|w| {
            local_load(&w[0]) == Some(0)
                && local_load(&w[1]) == Some(4)
                && w[2].opcode == 0x34
                && method.local_origins.iter().any(|record| {
                    record.local_index == 5
                        && record.origin == ValueOrigin::Instruction(w[2].offset)
                })
        })
        && method
            .calls
            .iter()
            .find(|call| call.name == "charAt")
            .is_some_and(|call| {
                method.local_origins.iter().any(|record| {
                    record.local_index == 6 && Some(&record.origin) == call.result_origin.as_ref()
                })
            })
}

fn local_load(instruction: &Instruction) -> Option<u16> {
    match instruction.opcode {
        0x15 | 0x19 => instruction.operands.first().copied().map(u16::from),
        0x1a..=0x1d => Some(u16::from(instruction.opcode - 0x1a)),
        0x2a..=0x2d => Some(u16::from(instruction.opcode - 0x2a)),
        _ => None,
    }
}

fn local_store(instruction: &Instruction) -> Option<u16> {
    match instruction.opcode {
        0x36 | 0x3a => instruction.operands.first().copied().map(u16::from),
        0x3b..=0x3e => Some(u16::from(instruction.opcode - 0x3b)),
        0x4b..=0x4e => Some(u16::from(instruction.opcode - 0x4b)),
        _ => None,
    }
}

fn indexed_constant_decoder(method: &MethodScanData) -> bool {
    method.is_static
        && decoder_loop(method, 7, 6, false)
        && method.local_origins.len() == 2
        && method.instructions.iter().filter(|instruction| instruction.opcode == 0x84).count() == 1
        && method.descriptor == "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/String;II)Ljava/lang/String;"
        && method.calls.len() == 2
        && method.calls.iter().any(|call| call.owner.as_deref() == Some("java/lang/String") && call.name == "toCharArray" && call.receiver_origin == Some(ValueOrigin::Local(3)))
        && method.calls.iter().any(|call| call.owner.as_deref() == Some("java/lang/String") && call.name == "<init>" && call.descriptor == "([C)V")
        && method.instructions.windows(9).any(|window| {
            window.iter().map(|instruction| instruction.opcode).eq([0x34, 0x15, 0x15, 0x15, 0x60, 0x82, 0x82, 0x92, 0x55])
                && window[1].operands == [4] && window[2].operands == [5] && window[3].operands == [7]
        })
        && method.instructions.iter().any(|instruction| instruction.opcode == 0x84 && instruction.operands == [7, 1])
        && method.local_origins.iter().filter(|record| record.local_index == 7).count() == 1
        && method.local_origins.iter().any(|record| record.local_index == 7 && record.origin == ValueOrigin::Constant(ConstantValue::Integer(0)))
        && [0x34, 0x55, 0x60].into_iter().all(|opcode| method.instructions.iter().filter(|instruction| instruction.opcode == opcode).count() == 1)
        && method.field_writes.is_empty()
        && method.control_flow_edges.iter().filter(|edge| edge.kind == ControlFlowEdgeKind::Branch).count() == 2
        && method.instructions.windows(13).any(|w| {
            local_load(&w[0]) == Some(6) && local_load(&w[1]) == Some(7)
                && local_load(&w[2]) == Some(6) && local_load(&w[3]) == Some(7)
                && w[4].opcode == 0x34 && local_load(&w[5]) == Some(4)
                && local_load(&w[6]) == Some(5) && local_load(&w[7]) == Some(7)
                && w[8].opcode == 0x60 && w[9].opcode == 0x82 && w[10].opcode == 0x82
                && w[11].opcode == 0x92 && w[12].opcode == 0x55
        })
        && method.calls.iter().find(|call| call.name == "toCharArray").is_some_and(|input| {
            method.local_origins.iter().any(|record| record.local_index == 6 && Some(&record.origin) == input.result_origin.as_ref())
                && method.calls.iter().any(|output| output.name == "<init>" && output.argument_origins.first() == input.result_origin.as_ref()
                && method.return_origins.len() == 1 && method.return_origins[0].value_origin == output.receiver_origin)
        })
}

fn decoder_loop(
    method: &MethodScanData,
    index_slot: u16,
    array_slot: u16,
    post_test: bool,
) -> bool {
    if method
        .instructions
        .iter()
        .any(|instruction| instruction.opcode == 0xc4)
    {
        return false;
    }
    if method
        .control_flow_edges
        .iter()
        .filter(|edge| edge.kind != ControlFlowEdgeKind::Fallthrough)
        .count()
        != 2
    {
        return false;
    }
    let Some(exit) = method
        .calls
        .iter()
        .find(|call| call.name == "<init>")
        .and_then(|call| {
            if let Some(ValueOrigin::Instruction(offset)) = call.receiver_origin {
                Some(offset)
            } else {
                None
            }
        })
    else {
        return false;
    };
    method.instructions.windows(4).any(|guard| {
        if local_load(&guard[0]) != Some(index_slot)
            || local_load(&guard[1]) != Some(array_slot)
            || guard[2].opcode != 0xbe
            || guard[3].opcode != if post_test { 0xa1 } else { 0xa2 }
        {
            return false;
        }
        let Some(branch) = method.control_flow_edges.iter().find(|edge| {
            edge.from_offset == guard[3].offset && edge.kind == ControlFlowEdgeKind::Branch
        }) else {
            return false;
        };
        if post_test {
            method.instructions.windows(3).any(|body| {
                local_load(&body[0]) == Some(array_slot)
                    && local_load(&body[1]) == Some(index_slot)
                    && body[2].opcode == 0x34
                    && branch.to_offset == body[0].offset
            }) && method
                .instructions
                .iter()
                .find(|instruction| instruction.offset > guard[3].offset)
                .is_some_and(|instruction| instruction.offset == exit)
                && method.control_flow_edges.iter().any(|edge| {
                    edge.to_offset == guard[0].offset
                        && edge.kind == ControlFlowEdgeKind::Branch
                        && edge.from_offset < branch.to_offset
                        && method.instructions.iter().any(|instruction| {
                            instruction.offset == edge.from_offset && instruction.opcode == 0xa7
                        })
                })
        } else {
            branch.to_offset == exit
                && method.control_flow_edges.iter().any(|edge| {
                    edge.to_offset == guard[0].offset
                        && edge.kind == ControlFlowEdgeKind::Branch
                        && edge.from_offset > guard[3].offset
                        && method.instructions.iter().any(|instruction| {
                            instruction.offset == edge.from_offset && instruction.opcode == 0xa7
                        })
                })
        }
    })
}

fn split_part(method: &MethodScanData, origin: &ValueOrigin, split: &CallSite, index: i32) -> bool {
    method.array_reads.iter().any(|read| {
        *origin == ValueOrigin::Instruction(read.offset)
            && split.result_origin.as_ref() == Some(&read.array_origin)
            && read.index_origin == ValueOrigin::Constant(ConstantValue::Integer(index))
    })
}

/// Recognizes numeric-name dispatch through an immutable literal String[] table.
/// Both the row layout and the virtual/static branch must match the lookup code.
fn dispatch_table(method: &MethodScanData) -> Option<ValueOrigin> {
    let parse = method.calls.iter().find(|call| {
        call.owner.as_deref() == Some("java/lang/Integer")
            && call.name == "parseInt"
            && call.argument_origins == [ValueOrigin::Local(1)]
    })?;
    let split = method.calls.iter().find(|call| {
        call.owner.as_deref() == Some("java/lang/String")
            && call.name == "split"
            && call.argument_origins
                == [ValueOrigin::Constant(ConstantValue::String(":".to_owned()))]
    })?;
    let table = method.array_reads.iter().find(|read| {
        split.receiver_origin == Some(ValueOrigin::Instruction(read.offset))
            && parse.result_origin.as_ref() == Some(&read.index_origin)
    })?;
    if !matches!(&table.array_origin, ValueOrigin::Field { owner, descriptor, .. } if owner == &method.class_name && descriptor == "[Ljava/lang/String;")
    {
        return None;
    }
    let owner = method.calls.iter().find(|call| {
        call.owner.as_deref() == Some("java/lang/Class")
            && call.name == "forName"
            && call
                .argument_origins
                .first()
                .is_some_and(|origin| split_part(method, origin, split, 0))
    })?;
    let descriptor = method.calls.iter().find(|call| {
        call.owner.as_deref() == Some("java/lang/invoke/MethodType")
            && call.name == "fromMethodDescriptorString"
            && call
                .argument_origins
                .first()
                .is_some_and(|origin| split_part(method, origin, split, 2))
    })?;
    let kind_length = method.calls.iter().find(|call| {
        call.owner.as_deref() == Some("java/lang/String")
            && call.name == "length"
            && call
                .receiver_origin
                .as_ref()
                .is_some_and(|origin| split_part(method, origin, split, 3))
    })?;
    let valid_lookup = |call: &&CallSite, name: &str| {
        call.owner.as_deref() == Some("java/lang/invoke/MethodHandles$Lookup")
            && call.name == name
            && call.receiver_origin == Some(ValueOrigin::Local(0))
            && call.argument_origins.len() == 3
            && owner.result_origin.as_ref() == call.argument_origins.first()
            && split_part(method, &call.argument_origins[1], split, 1)
            && descriptor.result_origin.as_ref() == call.argument_origins.get(2)
    };
    let virtual_call = method
        .calls
        .iter()
        .find(|call| valid_lookup(call, "findVirtual"))?;
    let static_call = method
        .calls
        .iter()
        .find(|call| valid_lookup(call, "findStatic"))?;
    let branch = method.branch_conditions.iter().find(|branch| {
        branch.opcode == 0xa0
            && kind_length.result_origin.as_ref() == Some(&branch.value_origin)
            && branch.compared_origin == Some(ValueOrigin::Constant(ConstantValue::Integer(2)))
    })?;
    let target = method
        .control_flow_edges
        .iter()
        .find(|edge| edge.from_offset == branch.offset && edge.kind == ControlFlowEdgeKind::Branch)?
        .to_offset;
    if !(branch.offset < virtual_call.offset
        && virtual_call.offset < target
        && target <= static_call.offset)
    {
        return None;
    }
    if !returns_lookup_result(method, virtual_call, static_call) {
        return None;
    }
    Some(table.array_origin.clone())
}

fn returns_lookup_result(
    method: &MethodScanData,
    virtual_call: &CallSite,
    static_call: &CallSite,
) -> bool {
    let constructors = method
        .calls
        .iter()
        .filter(|call| {
            call.owner.as_deref() == Some("java/lang/invoke/ConstantCallSite")
                && call.name == "<init>"
        })
        .collect::<Vec<_>>();
    let [constructor] = constructors.as_slice() else {
        return false;
    };
    if constructor.descriptor != "(Ljava/lang/invoke/MethodHandle;)V" {
        return false;
    }
    let Some(index) = method
        .instructions
        .iter()
        .position(|instruction| instruction.offset == constructor.offset)
    else {
        return false;
    };
    let Some(prefix) = index
        .checked_sub(3)
        .and_then(|start| method.instructions.get(start..index))
    else {
        return false;
    };
    let Some(load) = prefix.last() else {
        return false;
    };
    let slot = match load.opcode {
        0x19 => load.operands.first().copied().map(u16::from),
        0x2a..=0x2d => Some(u16::from(load.opcode - 0x2a)),
        _ => None,
    };
    let Some(slot) = slot else { return false };
    if prefix[0].opcode != 0xbb
        || prefix[1].opcode != 0x59
        || constructor.receiver_origin != Some(ValueOrigin::Instruction(prefix[0].offset))
        || method
            .instructions
            .get(index + 1)
            .is_none_or(|instruction| instruction.opcode != 0xb0)
        || !method
            .return_origins
            .iter()
            .any(|returned| returned.value_origin == constructor.receiver_origin)
    {
        return false;
    }
    [virtual_call, static_call].into_iter().all(|lookup| {
        let Some(call_index) = method
            .instructions
            .iter()
            .position(|instruction| instruction.offset == lookup.offset)
        else {
            return false;
        };
        let Some(store) = method.instructions.get(call_index + 1) else {
            return false;
        };
        let stored_slot = match store.opcode {
            0x3a => store.operands.first().copied().map(u16::from),
            0x4b..=0x4e => Some(u16::from(store.opcode - 0x4b)),
            _ => None,
        };
        stored_slot == Some(slot)
            && method.local_origins.iter().any(|record| {
                record.offset == store.offset
                    && record.local_index == slot
                    && Some(&record.origin) == lookup.result_origin.as_ref()
            })
            && method
                .instructions
                .get(call_index + 2)
                .is_some_and(|jump| jump_reaches(method, jump.offset, prefix[0].offset))
    })
}

fn jump_reaches(method: &MethodScanData, mut offset: u32, target: u32) -> bool {
    for _ in 0..4 {
        if method
            .instructions
            .iter()
            .find(|instruction| instruction.offset == offset)
            .is_none_or(|instruction| instruction.opcode != 0xa7)
        {
            return false;
        }
        let Some(edge) = method
            .control_flow_edges
            .iter()
            .find(|edge| edge.from_offset == offset && edge.kind == ControlFlowEdgeKind::Branch)
        else {
            return false;
        };
        if edge.to_offset == target {
            return true;
        }
        offset = edge.to_offset;
    }
    false
}

fn literal_table(
    methods: &[MethodScanData],
    table: &ValueOrigin,
) -> Option<std::collections::HashMap<u16, String>> {
    let ValueOrigin::Field {
        owner,
        name,
        descriptor,
    } = table
    else {
        return None;
    };
    let mut writes = methods
        .iter()
        .flat_map(|method| method.field_writes.iter().map(move |write| (method, write)))
        .filter(|(_, write)| {
            write.owner == *owner && write.name == *name && write.descriptor == *descriptor
        });
    let (initializer, assignment) = writes.next()?;
    if initializer.method_name != "<clinit>"
        && !methods.iter().any(|method| {
            method.method_name == "<clinit>"
                && method.calls.first().is_some_and(|call| {
                    call.offset == 0
                        && call.kind == InvokeKind::Static
                        && call.owner.as_deref() == Some(initializer.class_name.as_str())
                        && call.name == initializer.method_name
                        && call.descriptor == "()V"
                })
        })
    {
        return None;
    }
    if writes.next().is_some()
        || !initializer.is_static
        || initializer.descriptor != "()V"
        || initializer
            .control_flow_edges
            .iter()
            .any(|edge| edge.kind != ControlFlowEdgeKind::Fallthrough)
        || !matches!(assignment.value_origin, Some(ValueOrigin::Instruction(offset)) if initializer.instructions.iter().any(|instruction| instruction.offset == offset && instruction.opcode == 0xbd))
    {
        return None;
    }
    let allocation = assignment.value_origin.as_ref()?;
    if initializer.field_writes.iter().any(|write| {
        write.offset != assignment.offset && write.value_origin.as_ref() == Some(allocation)
    }) || initializer.array_elements.iter().any(|element| {
        element.value_origin == *allocation
            || (element.array_origin == *allocation && element.offset > assignment.offset)
    }) || initializer.calls.iter().any(|call| {
        call.argument_origins.contains(allocation)
            || call.receiver_origin.as_ref() == Some(allocation)
    }) || initializer
        .return_origins
        .iter()
        .any(|value| value.value_origin.as_ref() == Some(allocation))
    {
        return None;
    }
    // The supported initializer is literal-only. It must not expose the table
    // to another call/field/array or permit later stores through aliases.
    if methods.iter().any(|method| {
        method.calls.iter().any(|call| {
            call.argument_origins.contains(table) || call.receiver_origin.as_ref() == Some(table)
        }) || method
            .field_writes
            .iter()
            .any(|write| write.value_origin.as_ref() == Some(table))
            || method
                .return_origins
                .iter()
                .any(|value| value.value_origin.as_ref() == Some(table))
            || method.array_elements.iter().any(|element| {
                element.value_origin == *table
                    || (element.array_origin == *table && !std::ptr::eq(method, initializer))
            })
    }) {
        return None;
    }
    if initializer.calls.iter().any(|call| {
        !matches!(
            call.result_origin,
            Some(ValueOrigin::Constant(ConstantValue::String(_)))
        ) && !(call.owner.as_deref() == Some("java/lang/String")
            && call.name == "<init>"
            && initializer.constants.iter().any(|value| {
                value.offset == call.offset && matches!(value.value, ConstantValue::String(_))
            }))
    }) {
        return None;
    }
    let mut rows = std::collections::HashMap::new();
    for element in initializer
        .array_elements
        .iter()
        .filter(|element| element.array_origin == *table)
    {
        let ValueOrigin::Constant(ConstantValue::String(value)) = &element.value_origin else {
            return None;
        };
        let index = element.index?;
        if element.offset < assignment.offset
            || value.len() > 2048
            || rows.len() == 512
            || rows.insert(index, value.clone()).is_some()
        {
            return None;
        }
    }
    (!rows.is_empty()).then_some(rows)
}

fn resolve_table_calls(
    entries: &[ConstantPoolEntry],
    methods: &mut [MethodScanData],
    handles: &[u16],
    class_name: &str,
    private_fields: &[(String, String)],
) {
    const DESCRIPTOR: &str = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;";
    let tables = methods
        .iter()
        .filter(|method| method.is_static && method.descriptor == DESCRIPTOR)
        .take(8)
        .filter_map(|factory| {
            let table = dispatch_table(factory)?;
            let ValueOrigin::Field {
                name, descriptor, ..
            } = &table
            else {
                return None;
            };
            if !private_fields
                .iter()
                .any(|field| field.0 == *name && field.1 == *descriptor)
            {
                return None;
            }
            Some((factory.method_name.clone(), literal_table(methods, &table)?))
        })
        .collect::<std::collections::HashMap<_, _>>();
    let mut targets = std::collections::HashMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let ConstantPoolEntry::Dynamic {
            bootstrap_method_attr_index,
            name_and_type_index,
        } = entry
        else {
            continue;
        };
        let Some(bootstrap) = handles
            .get(usize::from(*bootstrap_method_attr_index))
            .and_then(|handle| resolve_method_handle(entries, *handle))
        else {
            continue;
        };
        if bootstrap.owner != class_name || bootstrap.descriptor != DESCRIPTOR {
            continue;
        }
        let Some(table) = tables.get(&bootstrap.name) else {
            continue;
        };
        let Some((name, site_descriptor)) = resolve_name_and_type(entries, *name_and_type_index)
        else {
            continue;
        };
        let Ok(row_index) = name.parse::<u16>() else {
            continue;
        };
        let Some(row) = table.get(&row_index) else {
            continue;
        };
        let parts = row.split(':').collect::<Vec<_>>();
        let [owner, name, descriptor, kind] = parts.as_slice() else {
            continue;
        };
        let kind = match *kind {
            " " => InvokeKind::Static,
            "  " => InvokeKind::Virtual,
            _ => continue,
        };
        if !descriptor.starts_with('(') || descriptor_shape(descriptor).is_none() {
            continue;
        }
        let owner = owner.replace('.', "/");
        let expected = if kind == InvokeKind::Virtual {
            format!("(L{owner};{}", &descriptor[1..])
        } else {
            descriptor.to_string()
        };
        if site_descriptor != expected {
            continue;
        }
        targets.insert(
            index as u16,
            (owner, name.to_string(), descriptor.to_string(), kind),
        );
    }
    for method in methods {
        for call in method
            .calls
            .iter_mut()
            .filter(|call| call.kind == InvokeKind::Dynamic)
        {
            let Some(instruction) = method.instructions.iter().find(|instruction| {
                instruction.offset == call.offset && instruction.opcode == 0xba
            }) else {
                continue;
            };
            let Some(bytes) = instruction.operands.get(..2) else {
                continue;
            };
            let index = u16::from_be_bytes([bytes[0], bytes[1]]);
            let Some((owner, name, descriptor, kind)) = targets.get(&index) else {
                continue;
            };
            if *kind == InvokeKind::Virtual {
                if call.argument_origins.is_empty() {
                    continue;
                }
                call.receiver_origin = Some(call.argument_origins.remove(0));
            }
            call.owner = Some(owner.clone());
            call.name = name.clone();
            call.descriptor = descriptor.clone();
            call.kind = *kind;
        }
    }
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
                let units = modified_utf16(bytes)?;
                entries[index] = match String::from_utf16(&units) {
                    Ok(value) => ConstantPoolEntry::Utf8(value),
                    Err(_) => ConstantPoolEntry::Utf16(units),
                };
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
                entries[index] = ConstantPoolEntry::Dynamic {
                    bootstrap_method_attr_index: cursor.read_u16()?,
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
                let _reference_kind = cursor.read_u8()?;
                entries[index] = ConstantPoolEntry::MethodHandle {
                    reference_index: cursor.read_u16()?,
                };
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
            ConstantPoolEntry::Utf8(value) | ConstantPoolEntry::ResolvedString(value) => {
                Some(value.clone())
            }
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

fn private_static_fields(
    cursor: &mut ClassCursor<'_>,
    entries: &[ConstantPoolEntry],
) -> anyhow::Result<Vec<(String, String)>> {
    let mut fields = Vec::new();
    let member_count = cursor.read_u16()? as usize;
    for _ in 0..member_count {
        let access_flags = cursor.read_u16()?;
        let name_index = cursor.read_u16()?;
        let descriptor_index = cursor.read_u16()?;
        if access_flags & 0x000a == 0x000a {
            if let (Some(name), Some(descriptor)) =
                (utf8(entries, name_index), utf8(entries, descriptor_index))
            {
                fields.push((name.to_owned(), descriptor.to_owned()));
            }
        }
        skip_attributes(cursor)?;
    }
    Ok(fields)
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
        let access_flags = cursor.read_u16()?;
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
                    access_flags & 0x0008 != 0,
                )?;
                methods.push(method);
            }
        }
    }
    Ok(())
}

/// Reads the class-level attributes and returns the method-handle index of each
/// `BootstrapMethods` entry together with its constant-pool arguments.
fn parse_bootstrap_method_handles(
    cursor: &mut ClassCursor<'_>,
    entries: &[ConstantPoolEntry],
) -> anyhow::Result<(Vec<u16>, Vec<Vec<u16>>)> {
    let mut handles = Vec::new();
    let mut arguments = Vec::new();
    let attribute_count = cursor.read_u16()? as usize;
    for _ in 0..attribute_count {
        let attribute_name_index = cursor.read_u16()?;
        let attribute_length = cursor.read_u32()? as usize;
        let attribute_bytes = cursor.read_bytes(attribute_length)?;
        if utf8(entries, attribute_name_index) != Some("BootstrapMethods") {
            continue;
        }
        let mut attribute = ClassCursor::new(attribute_bytes);
        let bootstrap_count = attribute.read_u16()? as usize;
        for _ in 0..bootstrap_count {
            handles.push(attribute.read_u16()?);
            let argument_count = attribute.read_u16()? as usize;
            let mut values = Vec::with_capacity(argument_count);
            for _ in 0..argument_count {
                values.push(attribute.read_u16()?);
            }
            arguments.push(values);
        }
    }
    Ok((handles, arguments))
}

/// Resolves bootstrap methods actually referenced from the constant pool and
/// keeps those outside the factories emitted by javac and common JVM languages.
fn custom_bootstrap_methods(
    entries: &[ConstantPoolEntry],
    bootstrap_method_handles: &[u16],
) -> Vec<BootstrapMethodRef> {
    let mut methods = Vec::new();
    for entry in entries {
        let ConstantPoolEntry::Dynamic {
            bootstrap_method_attr_index,
            ..
        } = entry
        else {
            continue;
        };
        let Some(method) = bootstrap_method_handles
            .get(*bootstrap_method_attr_index as usize)
            .and_then(|handle| resolve_method_handle(entries, *handle))
        else {
            continue;
        };
        if !is_standard_bootstrap_owner(&method.owner) && !methods.contains(&method) {
            methods.push(method);
        }
    }
    methods
}

fn resolve_method_handle(entries: &[ConstantPoolEntry], index: u16) -> Option<BootstrapMethodRef> {
    let ConstantPoolEntry::MethodHandle { reference_index } = entries.get(index as usize)? else {
        return None;
    };
    let ConstantPoolEntry::Ref {
        class_index,
        name_and_type_index,
        ..
    } = entries.get(*reference_index as usize)?
    else {
        return None;
    };
    let (name, descriptor) = resolve_name_and_type(entries, *name_and_type_index)?;
    Some(BootstrapMethodRef {
        owner: resolve_class_name(entries, *class_index)?,
        name,
        descriptor,
    })
}

fn is_standard_bootstrap_owner(owner: &str) -> bool {
    owner.starts_with("java/lang/invoke/")
        || owner.starts_with("java/lang/runtime/")
        || owner.starts_with("scala/runtime/")
        || owner.starts_with("org/codehaus/groovy/vmplugin/")
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
    is_static: bool,
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

    parse_method_code(
        entries,
        code,
        class_name,
        method_name,
        descriptor,
        is_static,
    )
}

fn parse_method_code(
    entries: &[ConstantPoolEntry],
    code: &[u8],
    class_name: &str,
    method_name: &str,
    descriptor: &str,
    is_static: bool,
) -> anyhow::Result<MethodScanData> {
    let instructions = decode_instructions(code)?;
    let (control_flow_edges, basic_blocks) = build_cfg(&instructions, code.len())?;
    let mut data = MethodScanData {
        class_name: class_name.to_owned(),
        method_name: method_name.to_owned(),
        descriptor: descriptor.to_owned(),
        is_static,
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
    populate_value_origins_with_budget(entries, data, &[], &mut 0)
}

#[cfg(test)]
fn populate_value_origins_with_decoders(
    entries: &[ConstantPoolEntry],
    data: &mut MethodScanData,
    decoder_names: &[String],
) -> anyhow::Result<()> {
    let mut remaining_bytes = MAX_NORMALIZED_STRING_BYTES;
    populate_value_origins_with_budget(entries, data, decoder_names, &mut remaining_bytes)
}

fn populate_value_origins_with_budget(
    entries: &[ConstantPoolEntry],
    data: &mut MethodScanData,
    decoder_names: &[String],
    remaining_bytes: &mut usize,
) -> anyhow::Result<()> {
    let mut stack = Vec::new();
    let mut locals = std::collections::BTreeMap::<u16, ValueOrigin>::new();
    let mut char_array_lengths = Vec::<(ValueOrigin, usize)>::new();
    let mut branch_target_offsets = std::collections::BTreeSet::new();

    for instruction in &data.instructions {
        for (target, _) in branch_targets(instruction)? {
            if let Ok(target) = u32::try_from(target) {
                branch_target_offsets.insert(target);
            }
        }
    }

    for instruction in data.instructions.clone() {
        let offset = instruction.offset;
        if branch_target_offsets.contains(&offset) {
            invalidate_control_flow_state(&mut stack, &mut locals, &mut char_array_lengths);
        }
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
            0x2e..=0x35 => {
                let index_origin = stack.pop().unwrap_or(ValueOrigin::Unknown);
                let array_origin = stack.pop().unwrap_or(ValueOrigin::Unknown);
                if matches!(instruction.opcode, 0x32 | 0x33) {
                    data.array_reads.push(ArrayReadOrigin {
                        offset,
                        array_origin,
                        index_origin,
                    });
                }
                stack.push(ValueOrigin::Instruction(offset));
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
            0x74..=0x77 | 0x85..=0x93 => {
                let operand = stack.pop().unwrap_or(ValueOrigin::Unknown);
                stack.push(
                    fold_unary_integer(instruction.opcode, &operand)
                        .map(|value| ValueOrigin::Constant(ConstantValue::Integer(value)))
                        .unwrap_or(ValueOrigin::Instruction(offset)),
                );
            }
            0x60..=0x73 | 0x78..=0x83 | 0x94..=0x98 => {
                let right = stack.pop().unwrap_or(ValueOrigin::Unknown);
                let left = stack.pop().unwrap_or(ValueOrigin::Unknown);
                stack.push(
                    fold_binary_integer(instruction.opcode, &left, &right)
                        .map(|value| ValueOrigin::Constant(ConstantValue::Integer(value)))
                        .unwrap_or(ValueOrigin::Instruction(offset)),
                );
            }
            0x84 => {
                let index = u16::from(instruction.operands[0]);
                locals.insert(index, ValueOrigin::Instruction(offset));
            }
            0x4f..=0x56 => store_array_element(
                &mut stack,
                data,
                offset,
                instruction.opcode,
                &mut char_array_lengths,
            ),
            0x99..=0x9e | 0xc6 | 0xc7 => {
                let value_origin = stack.pop().unwrap_or(ValueOrigin::Unknown);
                data.branch_conditions.push(BranchCondition {
                    offset,
                    opcode: instruction.opcode,
                    value_origin,
                    compared_origin: None,
                });
            }
            0x9f..=0xa6 => {
                let compared_origin = stack.pop();
                let value_origin = stack.pop().unwrap_or(ValueOrigin::Unknown);
                data.branch_conditions.push(BranchCondition {
                    offset,
                    opcode: instruction.opcode,
                    value_origin,
                    compared_origin,
                });
            }
            0xb2..=0xb5 => {
                if matches!(instruction.opcode, 0xb3 | 0xb5) {
                    if let Some(value) = stack.last() {
                        invalidate_cached_char_array(value, &mut char_array_lengths);
                    }
                }
                populate_field_access(entries, &instruction, &mut stack, data)?;
            }
            0xb6..=0xb9 | 0xba => populate_call(
                entries,
                &instruction,
                &mut stack,
                data,
                decoder_names,
                &mut char_array_lengths,
                remaining_bytes,
            )?,
            0xbb => stack.push(ValueOrigin::Instruction(offset)),
            0xbd => {
                let _ = stack.pop();
                stack.push(ValueOrigin::Instruction(offset));
            }
            0xc5 => {
                let dimensions = instruction.operands.get(2).copied().unwrap_or_default();
                for _ in 0..dimensions {
                    let _ = stack.pop();
                }
                stack.push(ValueOrigin::Instruction(offset));
            }
            0xbc => {
                let length = stack.pop().unwrap_or(ValueOrigin::Unknown);
                let array_origin = ValueOrigin::Instruction(offset);
                if instruction.operands.first() == Some(&5) {
                    if let ValueOrigin::Constant(ConstantValue::Integer(length)) = length {
                        if (0..=MAX_CONSTANT_CHAR_ARRAY_LENGTH as i32).contains(&length) {
                            char_array_lengths.push((array_origin.clone(), length as usize));
                        }
                    }
                }
                stack.push(array_origin);
            }
            0xbe => {
                let _ = stack.pop();
                stack.push(ValueOrigin::Instruction(offset));
            }
            0xc4 if instruction.operands.first() == Some(&0x84) => {
                let index = u16::from_be_bytes([instruction.operands[1], instruction.operands[2]]);
                locals.insert(index, ValueOrigin::Instruction(offset));
            }
            0xac..=0xb0 => {
                data.return_origins.push(ReturnOrigin {
                    offset,
                    value_origin: stack.pop(),
                });
                stack.clear();
            }
            0xb1 | 0xbf => stack.clear(),
            _ => {}
        }

        if !branch_targets(&instruction)?.is_empty() {
            // A single linear state cannot soundly represent a join. Clear it
            // rather than fabricating a value relationship across branches.
            invalidate_control_flow_state(&mut stack, &mut locals, &mut char_array_lengths);
        }
    }
    Ok(())
}

const MAX_CONSTANT_CHAR_ARRAY_LENGTH: usize = 16 * 1024;
const MAX_NORMALIZED_STRING_BYTES: usize = 256 * 1024;

fn invalidate_control_flow_state(
    stack: &mut Vec<ValueOrigin>,
    locals: &mut std::collections::BTreeMap<u16, ValueOrigin>,
    char_array_lengths: &mut Vec<(ValueOrigin, usize)>,
) {
    stack.clear();
    char_array_lengths.clear();
    for (index, origin) in locals {
        if matches!(origin, ValueOrigin::Constant(_)) {
            *origin = ValueOrigin::Local(*index);
        }
    }
}

fn invalidate_cached_char_array(
    array_origin: &ValueOrigin,
    char_array_lengths: &mut Vec<(ValueOrigin, usize)>,
) {
    char_array_lengths.retain(|(origin, _)| origin != array_origin);
}

fn fold_unary_integer(opcode: u8, operand: &ValueOrigin) -> Option<i32> {
    let ValueOrigin::Constant(ConstantValue::Integer(value)) = operand else {
        return None;
    };
    match opcode {
        0x74 => Some(value.wrapping_neg()),
        0x91 => Some((*value as i8) as i32),
        0x92 => Some((*value as u16) as i32),
        0x93 => Some((*value as i16) as i32),
        _ => None,
    }
}

fn fold_binary_integer(opcode: u8, left: &ValueOrigin, right: &ValueOrigin) -> Option<i32> {
    let (
        ValueOrigin::Constant(ConstantValue::Integer(left)),
        ValueOrigin::Constant(ConstantValue::Integer(right)),
    ) = (left, right)
    else {
        return None;
    };
    match opcode {
        0x60 => Some(left.wrapping_add(*right)),
        0x64 => Some(left.wrapping_sub(*right)),
        0x68 => Some(left.wrapping_mul(*right)),
        0x6c if *right != 0 => Some(if *left == i32::MIN && *right == -1 {
            i32::MIN
        } else {
            *left / *right
        }),
        0x70 if *right != 0 => Some(if *left == i32::MIN && *right == -1 {
            0
        } else {
            *left % *right
        }),
        0x78 => Some(left.wrapping_shl((*right as u32) & 0x1f)),
        0x7a => Some(*left >> ((*right as u32) & 0x1f)),
        0x7c => Some(((*left as u32) >> ((*right as u32) & 0x1f)) as i32),
        0x7e => Some(*left & *right),
        0x80 => Some(*left | *right),
        0x82 => Some(*left ^ *right),
        _ => None,
    }
}

fn store_array_element(
    stack: &mut Vec<ValueOrigin>,
    data: &mut MethodScanData,
    offset: u32,
    opcode: u8,
    char_array_lengths: &mut Vec<(ValueOrigin, usize)>,
) {
    let value_origin = stack.pop().unwrap_or(ValueOrigin::Unknown);
    if opcode == 0x53 {
        invalidate_cached_char_array(&value_origin, char_array_lengths);
    }
    let index = match stack.pop() {
        Some(ValueOrigin::Constant(ConstantValue::Integer(value))) if value >= 0 => {
            u16::try_from(value).ok()
        }
        _ => None,
    };
    let array_origin = stack.pop().unwrap_or(ValueOrigin::Unknown);
    if matches!(opcode, 0x53 | 0x54 | 0x55) {
        data.array_elements.push(ArrayElementOrigin {
            offset,
            array_origin,
            index,
            value_origin,
        });
    }
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
                receiver_origin: None,
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
                receiver_origin: None,
                value_origin: Some(value_origin),
            });
        }
        0xb4 => {
            let receiver_origin = stack.pop().unwrap_or(ValueOrigin::Unknown);
            data.field_reads.push(FieldAccess {
                offset: instruction.offset,
                owner: owner.clone(),
                name: name.clone(),
                descriptor: descriptor.clone(),
                receiver_origin: Some(receiver_origin),
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
            let receiver_origin = stack.pop().unwrap_or(ValueOrigin::Unknown);
            data.field_writes.push(FieldAccess {
                offset: instruction.offset,
                owner,
                name,
                descriptor,
                receiver_origin: Some(receiver_origin),
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
    decoder_names: &[String],
    char_array_lengths: &mut Vec<(ValueOrigin, usize)>,
    remaining_bytes: &mut usize,
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
    let is_string_char_array_copy = kind == InvokeKind::Special
        && owner == "java/lang/String"
        && name == "<init>"
        && descriptor == "([C)V";
    let normalized_string = (*remaining_bytes > 0)
        .then(|| {
            decode_char_array_call(
                &owner,
                &name,
                &descriptor,
                kind,
                data,
                &argument_origins,
                decoder_names,
                char_array_lengths,
                instruction.offset,
            )
            .or_else(|| {
                if is_string_char_array_copy {
                    let array = argument_origins.first()?;
                    let units =
                        constant_char_array(data, array, char_array_lengths, instruction.offset)?;
                    String::from_utf16(&units).ok()
                } else {
                    None
                }
            })
        })
        .flatten()
        .filter(|value| {
            if value.len().max(1) > *remaining_bytes {
                *remaining_bytes = 0;
                false
            } else {
                *remaining_bytes -= value.len().max(1);
                true
            }
        });
    if !is_string_char_array_copy {
        // Calls may mutate char[] arguments. The recognized decoder is also
        // treated as in-place after its current contents have been normalized.
        char_array_lengths
            .retain(|(origin, _)| !argument_origins.iter().any(|argument| argument == origin));
    }
    data.stack_origins.push(StackOrigin {
        offset: instruction.offset,
        values: argument_origins.clone(),
    });
    let result_origin = if has_result {
        if let Some(value) = normalized_string.as_ref() {
            Some(ValueOrigin::Constant(ConstantValue::String(value.clone())))
        } else {
            Some(ValueOrigin::Instruction(instruction.offset))
        }
    } else {
        None
    };
    data.calls.push(CallSite {
        offset: instruction.offset,
        kind,
        owner: (!owner.is_empty()).then_some(owner),
        name,
        descriptor,
        receiver_origin: receiver_origin.clone(),
        argument_origins,
        result_origin: result_origin.clone(),
    });
    if let Some(origin) = result_origin {
        stack.push(origin);
    }
    if let Some(value) = normalized_string {
        data.constants.push(LoadedConstant {
            offset: instruction.offset,
            value: ConstantValue::String(value.clone()),
        });
        if !has_result {
            if let Some(receiver) = receiver_origin.as_ref() {
                let normalized = ValueOrigin::Constant(ConstantValue::String(value));
                for origin in stack {
                    if origin == receiver {
                        *origin = normalized.clone();
                    }
                }
            }
        }
    }
    Ok(())
}

fn decode_char_array_call(
    owner: &str,
    name: &str,
    descriptor: &str,
    kind: InvokeKind,
    data: &MethodScanData,
    arguments: &[ValueOrigin],
    decoder_names: &[String],
    char_array_lengths: &[(ValueOrigin, usize)],
    call_offset: u32,
) -> Option<String> {
    if kind != InvokeKind::Static
        || owner != data.class_name
        || descriptor != "([CLjava/lang/String;I)Ljava/lang/String;"
        || !decoder_names.iter().any(|decoder| decoder == name)
    {
        return None;
    }
    let array = arguments.first()?;
    let key = match arguments.get(1)? {
        ValueOrigin::Constant(ConstantValue::String(key)) => key,
        _ => return None,
    };
    let shift = match arguments.get(2)? {
        ValueOrigin::Constant(ConstantValue::Integer(value)) => *value as u16,
        _ => return None,
    };
    let units = constant_char_array(data, array, char_array_lengths, call_offset)?;
    let key_units: Vec<u16> = key.encode_utf16().collect();
    if key_units.is_empty() {
        return None;
    }
    let decoded: Vec<u16> = units
        .iter()
        .enumerate()
        .map(|(index, unit)| {
            unit.wrapping_add(shift)
                .wrapping_sub(key_units[index % key_units.len()])
        })
        .collect();
    String::from_utf16(&decoded).ok()
}

fn constant_char_array(
    data: &MethodScanData,
    array_origin: &ValueOrigin,
    char_array_lengths: &[(ValueOrigin, usize)],
    before_offset: u32,
) -> Option<Vec<u16>> {
    let length = char_array_lengths
        .iter()
        .find(|(origin, _)| origin == array_origin)
        .map(|(_, length)| *length)?;
    if length > MAX_CONSTANT_CHAR_ARRAY_LENGTH {
        return None;
    }
    let mut values = vec![None; length];
    for element in data
        .array_elements
        .iter()
        .filter(|element| element.array_origin == *array_origin && element.offset < before_offset)
    {
        let index = usize::from(element.index?);
        if index >= length {
            return None;
        }
        let ValueOrigin::Constant(ConstantValue::Integer(value)) = &element.value_origin else {
            return None;
        };
        values[index] = Some(*value as u16);
    }
    values.into_iter().collect()
}

fn constant_value(entries: &[ConstantPoolEntry], index: u16) -> ConstantValue {
    match entries.get(index as usize) {
        Some(ConstantPoolEntry::ResolvedString(value)) => ConstantValue::String(value.clone()),
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
        ..
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

pub fn descriptor_shape(descriptor: &str) -> Option<(usize, bool)> {
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
        0x10 | 0x12 | 0x15..=0x19 | 0x36..=0x3a | 0xa9 | 0xbc => Some(2),
        0x11 | 0x13 | 0x14 | 0x84 | 0x99..=0xa8 | 0xbb..=0xbd | 0xc0 | 0xc1 | 0xc6 | 0xc7 => {
            Some(3)
        }
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
    // The JVM rejects high < low; wrapping arithmetic here could yield a zero
    // length and stall or panic the bytecode walkers.
    if high < low {
        return None;
    }
    let entries = usize::try_from(i64::from(high) - i64::from(low) + 1).ok()?;
    entries.checked_mul(4)?.checked_add(1 + padding + 12)
}

fn lookup_switch_length(code: &[u8], offset: usize) -> Option<usize> {
    let padding = (4 - ((offset + 1) % 4)) % 4;
    let header = offset + 1 + padding;
    if header + 8 > code.len() {
        return None;
    }
    let pairs = usize::try_from(read_i32(code, header + 4)?).ok()?;
    pairs.checked_mul(8)?.checked_add(1 + padding + 8)
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
    #[test]
    fn modified_utf8_preserves_encrypted_surrogates_and_nulls() {
        assert_eq!(super::modified_utf16(&[0xc0, 0x80]).unwrap(), [0]);
        assert_eq!(
            super::modified_utf16(&[0xed, 0xa0, 0x80]).unwrap(),
            [0xd800]
        );
        assert_eq!(
            super::modified_utf16(&[0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]).unwrap(),
            [0xd83d, 0xde00]
        );
        assert!(super::modified_utf16(&[0xed, 0xa0]).is_err());
    }

    #[test]
    fn resolves_only_the_supported_indexed_string_bootstrap() {
        use super::ConstantPoolEntry::*;
        const DESCRIPTOR: &str = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/String;II)Ljava/lang/String;";
        let encoded = "/login "
            .encode_utf16()
            .enumerate()
            .map(|(i, unit)| unit ^ 0xd800 ^ i as u16)
            .collect();
        let entries = vec![
            Other,
            Utf8("java/lang/String".to_owned()),
            Class { name_index: 1 },
            Utf8("toCharArray".to_owned()),
            Utf8("()[C".to_owned()),
            NameAndType {
                name_index: 3,
                descriptor_index: 4,
            },
            Ref {
                tag: 10,
                class_index: 2,
                name_and_type_index: 5,
            },
            Utf8("<init>".to_owned()),
            Utf8("([C)V".to_owned()),
            NameAndType {
                name_index: 7,
                descriptor_index: 8,
            },
            Ref {
                tag: 10,
                class_index: 2,
                name_and_type_index: 9,
            },
            Utf8("example/Test".to_owned()),
            Class { name_index: 11 },
            Utf8("decode".to_owned()),
            Utf8(DESCRIPTOR.to_owned()),
            NameAndType {
                name_index: 13,
                descriptor_index: 14,
            },
            Ref {
                tag: 10,
                class_index: 12,
                name_and_type_index: 15,
            },
            MethodHandle {
                reference_index: 16,
            },
            Utf16(encoded),
            String { string_index: 18 },
            Integer(0xd800),
            Integer(0),
            Utf8("hidden".to_owned()),
            Utf8("Ljava/lang/String;".to_owned()),
            NameAndType {
                name_index: 22,
                descriptor_index: 23,
            },
            Dynamic {
                bootstrap_method_attr_index: 0,
                name_and_type_index: 24,
            },
        ];
        let code = [
            0x2d, 0xb6, 0, 6, 0x3a, 6, 0x11, 0x1c, 0xd0, 0x11, 0x82, 0x20, 0x7e, 0x36, 7, 0x15, 7,
            0x19, 6, 0xbe, 0xa2, 0, 29, 0x19, 6, 0x15, 7, 0x19, 6, 0x15, 7, 0x34, 0x15, 4, 0x15, 5,
            0x15, 7, 0x60, 0x82, 0x82, 0x92, 0x55, 0x84, 7, 1, 0xa7, 0xff, 0xe1, 0xbb, 0, 2, 0x59,
            0x19, 6, 0xb7, 0, 10, 0xb0,
        ];
        let method =
            super::parse_method_code(&entries, &code, "example/Test", "decode", DESCRIPTOR, true)
                .unwrap();
        assert!(super::indexed_constant_decoder(&method));
        let mut wide_update = method.clone();
        wide_update.instructions.push(super::Instruction {
            offset: 59,
            opcode: 0xc4,
            operands: vec![0x84, 0, 7, 0, 1],
        });
        assert!(!super::indexed_constant_decoder(&wide_update));
        let mut resolved = entries.clone();
        super::normalize_hidden_literals(
            &mut resolved,
            &mut [method.clone()],
            &[17],
            &[vec![19, 20, 21]],
            "example/Test",
            &[],
        )
        .unwrap();
        assert_eq!(
            super::constant_value(&resolved, 25),
            super::ConstantValue::String("/login ".to_owned())
        );
        let mut expanded = entries.clone();
        expanded[18] = Utf16((0..16 * 1024).map(|i| 65 ^ 0xd800 ^ i as u16).collect());
        expanded.extend((0..32).map(|_| Dynamic {
            bootstrap_method_attr_index: 0,
            name_and_type_index: 24,
        }));
        super::normalize_hidden_literals(
            &mut expanded,
            &mut [method.clone()],
            &[17],
            &[vec![19, 20, 21]],
            "example/Test",
            &[],
        )
        .unwrap();
        assert_eq!(
            expanded
                .iter()
                .filter(|entry| matches!(entry, ResolvedString(_)))
                .count(),
            super::MAX_NORMALIZED_STRING_BYTES / (16 * 1024 * 3)
        );
        let mut changed_condition = code;
        changed_condition[20] = 0xa1;
        let skipped = super::parse_method_code(
            &entries,
            &changed_condition,
            "example/Test",
            "decode",
            DESCRIPTOR,
            true,
        )
        .unwrap();
        assert!(!super::indexed_constant_decoder(&skipped));
        let mut changed_key = code;
        changed_key[33] = 5;
        let method = super::parse_method_code(
            &entries,
            &changed_key,
            "example/Test",
            "decode",
            DESCRIPTOR,
            true,
        )
        .unwrap();
        let mut unresolved = entries;
        super::normalize_hidden_literals(
            &mut unresolved,
            &mut [method],
            &[17],
            &[vec![19, 20, 21]],
            "example/Test",
            &[],
        )
        .unwrap();
        assert_eq!(
            super::constant_value(&unresolved, 25),
            super::ConstantValue::Unknown
        );
    }

    #[test]
    fn dispatch_must_return_the_selected_lookup_handle() {
        use super::{
            CallSite, ControlFlowEdge, ControlFlowEdgeKind, Instruction, InvokeKind,
            LocalValueOrigin, MethodScanData, ReturnOrigin, ValueOrigin,
        };
        let lookup = |offset| CallSite {
            offset,
            kind: InvokeKind::Virtual,
            owner: Some("java/lang/invoke/MethodHandles$Lookup".to_owned()),
            name: "lookup".to_owned(),
            descriptor: "()Ljava/lang/invoke/MethodHandle;".to_owned(),
            receiver_origin: Some(ValueOrigin::Local(0)),
            argument_origins: vec![],
            result_origin: Some(ValueOrigin::Instruction(offset)),
        };
        let virtual_call = lookup(1);
        let static_call = lookup(10);
        let constructor = CallSite {
            offset: 25,
            kind: InvokeKind::Special,
            owner: Some("java/lang/invoke/ConstantCallSite".to_owned()),
            name: "<init>".to_owned(),
            descriptor: "(Ljava/lang/invoke/MethodHandle;)V".to_owned(),
            receiver_origin: Some(ValueOrigin::Instruction(20)),
            argument_origins: vec![ValueOrigin::Instruction(10)],
            result_origin: None,
        };
        let mut method = MethodScanData {
            calls: vec![virtual_call.clone(), static_call.clone(), constructor],
            instructions: [
                (1, 0xb6, vec![]),
                (4, 0x3a, vec![6]),
                (6, 0xa7, vec![]),
                (10, 0xb6, vec![]),
                (13, 0x3a, vec![6]),
                (15, 0xa7, vec![]),
                (20, 0xbb, vec![]),
                (23, 0x59, vec![]),
                (24, 0x19, vec![6]),
                (25, 0xb7, vec![]),
                (28, 0xb0, vec![]),
            ]
            .into_iter()
            .map(|(offset, opcode, operands)| Instruction {
                offset,
                opcode,
                operands,
            })
            .collect(),
            local_origins: vec![
                LocalValueOrigin {
                    offset: 4,
                    local_index: 6,
                    origin: ValueOrigin::Instruction(1),
                },
                LocalValueOrigin {
                    offset: 13,
                    local_index: 6,
                    origin: ValueOrigin::Instruction(10),
                },
            ],
            control_flow_edges: vec![
                ControlFlowEdge {
                    from_offset: 6,
                    to_offset: 15,
                    kind: ControlFlowEdgeKind::Branch,
                },
                ControlFlowEdge {
                    from_offset: 15,
                    to_offset: 20,
                    kind: ControlFlowEdgeKind::Branch,
                },
            ],
            return_origins: vec![ReturnOrigin {
                offset: 28,
                value_origin: Some(ValueOrigin::Instruction(20)),
            }],
            ..Default::default()
        };
        assert!(super::returns_lookup_result(
            &method,
            &virtual_call,
            &static_call
        ));
        method.instructions[8].operands = vec![5];
        assert!(!super::returns_lookup_result(
            &method,
            &virtual_call,
            &static_call
        ));
    }

    #[test]
    fn dispatch_table_must_be_literal_private_and_not_escape() {
        use super::{
            ArrayElementOrigin, ConstantPoolEntry, ConstantValue, FieldAccess, Instruction,
            MethodScanData, ValueOrigin,
        };
        let table = ValueOrigin::Field {
            owner: "example/Test".to_owned(),
            name: "targets".to_owned(),
            descriptor: "[Ljava/lang/String;".to_owned(),
        };
        let initial = MethodScanData {
            method_name: "<clinit>".to_owned(),
            is_static: true,
            descriptor: "()V".to_owned(),
            instructions: vec![Instruction {
                offset: 0,
                opcode: 0xbd,
                operands: vec![],
            }],
            field_writes: vec![FieldAccess {
                offset: 3,
                owner: "example/Test".to_owned(),
                name: "targets".to_owned(),
                descriptor: "[Ljava/lang/String;".to_owned(),
                receiver_origin: None,
                value_origin: Some(ValueOrigin::Instruction(0)),
            }],
            array_elements: vec![ArrayElementOrigin {
                offset: 6,
                array_origin: table.clone(),
                index: Some(0),
                value_origin: ValueOrigin::Constant(ConstantValue::String(
                    "example/Sink:post:()V: ".to_owned(),
                )),
            }],
            ..Default::default()
        };
        assert!(super::literal_table(std::slice::from_ref(&initial), &table).is_some());
        let mut unused = initial.clone();
        unused.method_name = "unused".to_owned();
        assert!(super::literal_table(&[unused], &table).is_none());
        let mut allocation_alias = initial.clone();
        let mut alias_store = allocation_alias.array_elements[0].clone();
        alias_store.array_origin = ValueOrigin::Instruction(0);
        alias_store.offset = 7;
        allocation_alias.array_elements.push(alias_store);
        assert!(super::literal_table(&[allocation_alias], &table).is_none());
        let mut reassigned = initial.clone();
        reassigned
            .field_writes
            .push(reassigned.field_writes[0].clone());
        assert!(super::literal_table(&[reassigned], &table).is_none());
        let mut dynamic_index = initial.clone();
        dynamic_index.array_elements[0].index = None;
        assert!(super::literal_table(&[dynamic_index], &table).is_none());
        let mut escaped = initial.clone();
        escaped.field_writes.push(FieldAccess {
            offset: 7,
            owner: "example/Test".to_owned(),
            name: "alias".to_owned(),
            descriptor: "[Ljava/lang/String;".to_owned(),
            receiver_origin: None,
            value_origin: Some(table.clone()),
        });
        assert!(super::literal_table(&[escaped], &table).is_none());
        let mut conditional = initial;
        conditional.control_flow_edges.push(super::ControlFlowEdge {
            from_offset: 0,
            to_offset: 6,
            kind: super::ControlFlowEdgeKind::Branch,
        });
        assert!(super::literal_table(&[conditional], &table).is_none());
        let pool = [
            ConstantPoolEntry::Other,
            ConstantPoolEntry::Utf8("targets".to_owned()),
            ConstantPoolEntry::Utf8("[Ljava/lang/String;".to_owned()),
        ];
        for flags in [0x000a_u16, 0x0009] {
            let bytes = [0, 1, 0, flags as u8, 0, 1, 0, 2, 0, 0];
            let fields =
                super::private_static_fields(&mut super::ClassCursor::new(&bytes), &pool).unwrap();
            assert_eq!(fields.len(), usize::from(flags == 0x000a));
        }
    }
    /// Verifies the parser rejects non-class bytes instead of silently ignoring them.
    #[test]
    fn parse_class_file_rejects_invalid_magic() {
        let error = super::parse_class_file(b"not a class").expect_err("invalid class must fail");
        assert!(
            error.to_string().contains("invalid class magic")
                || error.to_string().contains("truncated")
        );
    }

    /// A tableswitch with high < low once wrapped to a zero instruction length,
    /// panicking the decoder and looping the byte-array recovery forever.
    #[test]
    fn malformed_tableswitch_is_rejected_without_panic_or_hang() {
        let tableswitch = [
            0xaa, 0, 0, 0, // opcode and padding
            0, 0, 0, 0, // default
            0, 0, 0, 0, // low = 0
            0xff, 0xff, 0xff, 0xfb, // high = -5
        ];
        assert!(super::decode_instructions(&tableswitch).is_err());

        let mut with_newarray = tableswitch.to_vec();
        with_newarray.extend_from_slice(&[0xbc, 0x08]);
        super::recover_byte_array_strings(&with_newarray);

        let negative_lookupswitch = [0xab, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff];
        assert!(super::decode_instructions(&negative_lookupswitch).is_err());
    }

    /// Obfuscators link hidden calls through mod-defined bootstraps; javac
    /// lambdas use JDK factories and must not be reported.
    #[test]
    fn reports_only_non_standard_bootstrap_methods() {
        use super::ConstantPoolEntry::*;
        let bootstrap_ref = |class_index, name_and_type_index| Ref {
            tag: 10,
            class_index,
            name_and_type_index,
        };
        let entries = vec![
            Other,
            Class { name_index: 2 },
            Utf8("example/Hidden".to_owned()),
            NameAndType {
                name_index: 4,
                descriptor_index: 5,
            },
            Utf8("bootstrap".to_owned()),
            Utf8("(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;".to_owned()),
            bootstrap_ref(1, 3),
            MethodHandle { reference_index: 6 },
            Class { name_index: 9 },
            Utf8("java/lang/invoke/LambdaMetafactory".to_owned()),
            bootstrap_ref(8, 3),
            MethodHandle { reference_index: 10 },
            Dynamic {
                bootstrap_method_attr_index: 0,
                name_and_type_index: 3,
            },
            Dynamic {
                bootstrap_method_attr_index: 1,
                name_and_type_index: 3,
            },
            Dynamic {
                bootstrap_method_attr_index: 0,
                name_and_type_index: 3,
            },
        ];

        let methods = super::custom_bootstrap_methods(&entries, &[7, 11]);

        assert_eq!(
            methods,
            vec![super::BootstrapMethodRef {
                owner: "example/Hidden".to_owned(),
                name: "bootstrap".to_owned(),
                descriptor: "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;".to_owned(),
            }]
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

        let method = super::parse_method_code(&entries, &code, "example/Test", "run", "()V", true)
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
    fn tracks_instance_field_receivers_and_leaves_static_receivers_empty() {
        use super::ConstantPoolEntry;

        let entries = vec![
            ConstantPoolEntry::Other,
            ConstantPoolEntry::Class { name_index: 2 },
            ConstantPoolEntry::Utf8("example/Receiver".to_owned()),
            ConstantPoolEntry::NameAndType {
                name_index: 4,
                descriptor_index: 5,
            },
            ConstantPoolEntry::Utf8("response".to_owned()),
            ConstantPoolEntry::Utf8("[B".to_owned()),
            ConstantPoolEntry::Ref {
                tag: 9,
                class_index: 1,
                name_and_type_index: 3,
            },
            ConstantPoolEntry::Class { name_index: 8 },
            ConstantPoolEntry::Utf8("example/Network".to_owned()),
            ConstantPoolEntry::NameAndType {
                name_index: 10,
                descriptor_index: 11,
            },
            ConstantPoolEntry::Utf8("fetch".to_owned()),
            ConstantPoolEntry::Utf8("()Lexample/Receiver;".to_owned()),
            ConstantPoolEntry::Ref {
                tag: 10,
                class_index: 7,
                name_and_type_index: 9,
            },
        ];

        // invokestatic fetch; iconst_1; i2c; pop; getfield response; areturn.
        // Unary conversions must preserve the object below the converted value.
        let read = super::parse_method_code(
            &entries,
            &[0xb8, 0x00, 0x0c, 0x04, 0x92, 0x57, 0xb4, 0x00, 0x06, 0xb0],
            "example/Test",
            "read",
            "()[B",
            true,
        )
        .expect("bounded static parse must succeed");

        assert_eq!(
            read.field_reads[0].receiver_origin,
            Some(super::ValueOrigin::Instruction(0))
        );
        assert_eq!(read.field_reads[0].value_origin, None);
        assert_eq!(
            read.return_origins[0].value_origin,
            Some(super::ValueOrigin::Field {
                owner: "example/Receiver".to_owned(),
                name: "response".to_owned(),
                descriptor: "[B".to_owned(),
            })
        );

        // invokestatic fetch; iconst_2; newarray byte; putfield response; return
        let write = super::parse_method_code(
            &entries,
            &[0xb8, 0x00, 0x0c, 0x05, 0xbc, 0x08, 0xb5, 0x00, 0x06, 0xb1],
            "example/Test",
            "write",
            "()V",
            true,
        )
        .expect("bounded static parse must succeed");

        assert_eq!(
            write.field_writes[0].receiver_origin,
            Some(super::ValueOrigin::Instruction(0))
        );
        assert_eq!(
            write.field_writes[0].value_origin,
            Some(super::ValueOrigin::Instruction(4))
        );

        // getstatic response; areturn
        let static_read = super::parse_method_code(
            &entries,
            &[0xb2, 0x00, 0x06, 0xb0],
            "example/Test",
            "static_read",
            "()[B",
            true,
        )
        .expect("bounded static parse must succeed");
        assert_eq!(static_read.field_reads[0].receiver_origin, None);

        // iconst_0; putstatic response; return
        let static_write = super::parse_method_code(
            &entries,
            &[0x03, 0xb3, 0x00, 0x06, 0xb1],
            "example/Test",
            "static_write",
            "()V",
            true,
        )
        .expect("bounded static parse must succeed");
        assert_eq!(static_write.field_writes[0].receiver_origin, None);
    }

    #[test]
    fn tracks_both_arrays_and_operands_in_byte_comparisons() {
        let method = super::parse_method_code(
            &[],
            &[0x2a, 0x03, 0x33, 0x2b, 0x03, 0x33, 0x9f, 0x00, 0x03, 0xb1],
            "example/Test",
            "compare",
            "([B[B)V",
            true,
        )
        .expect("byte-array comparison parses");
        assert_eq!(method.array_reads.len(), 2);
        assert_eq!(
            method.array_reads[0].array_origin,
            super::ValueOrigin::Local(0)
        );
        assert_eq!(
            method.array_reads[1].array_origin,
            super::ValueOrigin::Local(1)
        );
        assert_eq!(
            method.branch_conditions[0].value_origin,
            super::ValueOrigin::Instruction(2)
        );
        assert_eq!(
            method.branch_conditions[0].compared_origin,
            Some(super::ValueOrigin::Instruction(5))
        );
    }

    #[test]
    fn tracks_byte_array_store_origins_and_constant_values() {
        // iconst_2; newarray byte; dup; iconst_0; bipush 42; bastore; areturn
        let method = super::parse_method_code(
            &[],
            &[0x05, 0xbc, 0x08, 0x59, 0x03, 0x10, 0x2a, 0x54, 0xb0],
            "example/Test",
            "bytes",
            "()[B",
            true,
        )
        .expect("bounded static parse must succeed");

        assert_eq!(
            method.array_elements,
            vec![super::ArrayElementOrigin {
                offset: 7,
                array_origin: super::ValueOrigin::Instruction(1),
                index: Some(0),
                value_origin: super::ValueOrigin::Constant(super::ConstantValue::Integer(42)),
            }]
        );
    }

    #[test]
    fn folds_constant_integer_arithmetic_with_java_narrowing() {
        // iconst_2; iconst_3; imul; iconst_4; iadd; ineg; i2b; ireturn
        let method = super::parse_method_code(
            &[],
            &[0x05, 0x06, 0x68, 0x07, 0x60, 0x74, 0x91, 0xac],
            "example/Test",
            "number",
            "()I",
            true,
        )
        .expect("bounded static parse must succeed");

        assert_eq!(
            method.return_origins[0].value_origin,
            Some(super::ValueOrigin::Constant(super::ConstantValue::Integer(
                -10
            )))
        );
    }

    #[test]
    fn normalizes_only_recognized_same_class_char_array_decoders() {
        use super::ConstantPoolEntry;

        let entries = vec![
            ConstantPoolEntry::Other,
            ConstantPoolEntry::Class { name_index: 2 },
            ConstantPoolEntry::Utf8("example/Test".to_owned()),
            ConstantPoolEntry::NameAndType {
                name_index: 4,
                descriptor_index: 5,
            },
            ConstantPoolEntry::Utf8("decode".to_owned()),
            ConstantPoolEntry::Utf8("([CLjava/lang/String;I)Ljava/lang/String;".to_owned()),
            ConstantPoolEntry::Ref {
                tag: 10,
                class_index: 1,
                name_and_type_index: 3,
            },
            ConstantPoolEntry::String { string_index: 8 },
            ConstantPoolEntry::Utf8("xy".to_owned()),
        ];
        // char[] { 182, 213, 231 }; "xy"; 5; decode(char[], key, k); areturn
        let code = [
            0x06, 0xbc, 0x05, // new char[3]
            0x59, 0x03, 0x11, 0x00, 0xb6, 0x55, // array[0] = 182
            0x59, 0x04, 0x11, 0x00, 0xd5, 0x55, // array[1] = 213
            0x59, 0x05, 0x11, 0x00, 0xe7, 0x55, // array[2] = 231
            0x12, 0x07, 0x08, 0xb8, 0x00, 0x06, 0xb0,
        ];
        let make_method = || super::MethodScanData {
            class_name: "example/Test".to_owned(),
            method_name: "decodeTable".to_owned(),
            descriptor: "()Ljava/lang/String;".to_owned(),
            is_static: true,
            instructions: super::decode_instructions(&code).expect("code must decode"),
            ..super::MethodScanData::default()
        };

        let mut normalized = make_method();
        super::populate_value_origins_with_decoders(
            &entries,
            &mut normalized,
            &["decode".to_owned()],
        )
        .expect("origin pass must succeed");
        assert_eq!(
            normalized.return_origins[0].value_origin,
            Some(super::ValueOrigin::Constant(super::ConstantValue::String(
                "Cat".to_owned()
            )))
        );
        assert!(normalized.constants.iter().any(|constant| {
            constant.offset == 24
                && constant.value == super::ConstantValue::String("Cat".to_owned())
        }));

        let mut unrecognized = make_method();
        super::populate_value_origins_with_decoders(&entries, &mut unrecognized, &[])
            .expect("origin pass must succeed");
        assert_eq!(
            unrecognized.return_origins[0].value_origin,
            Some(super::ValueOrigin::Instruction(24))
        );
    }

    #[test]
    fn invalidates_char_array_constants_after_mutating_calls() {
        use super::ConstantPoolEntry;

        let entries = vec![
            ConstantPoolEntry::Other,
            ConstantPoolEntry::Class { name_index: 2 },
            ConstantPoolEntry::Utf8("example/Test".to_owned()),
            ConstantPoolEntry::NameAndType {
                name_index: 4,
                descriptor_index: 5,
            },
            ConstantPoolEntry::Utf8("decode".to_owned()),
            ConstantPoolEntry::Utf8("([CLjava/lang/String;I)Ljava/lang/String;".to_owned()),
            ConstantPoolEntry::Ref {
                tag: 10,
                class_index: 1,
                name_and_type_index: 3,
            },
            ConstantPoolEntry::String { string_index: 8 },
            ConstantPoolEntry::Utf8("x".to_owned()),
            ConstantPoolEntry::NameAndType {
                name_index: 10,
                descriptor_index: 11,
            },
            ConstantPoolEntry::Utf8("mutate".to_owned()),
            ConstantPoolEntry::Utf8("([C)V".to_owned()),
            ConstantPoolEntry::Ref {
                tag: 10,
                class_index: 1,
                name_and_type_index: 9,
            },
        ];
        let decoder_names = ["decode".to_owned()];
        let run = |method_name: &str, code: &[u8]| {
            let mut method = super::MethodScanData {
                class_name: "example/Test".to_owned(),
                method_name: method_name.to_owned(),
                descriptor: "()Ljava/lang/String;".to_owned(),
                is_static: true,
                instructions: super::decode_instructions(code).expect("code must decode"),
                ..super::MethodScanData::default()
            };
            super::populate_value_origins_with_decoders(&entries, &mut method, &decoder_names)
                .expect("origin pass must succeed");
            method
        };

        // An unknown call receives a duplicate of char[] before the decoder.
        // The pre-call literal must not be reused after that call.
        let after_mutation = run(
            "afterMutation",
            &[
                0x04, 0xbc, 0x05, 0x59, 0x03, 0x10, 0x41, 0x55, 0x59, 0xb8, 0x00, 0x0c, 0x12, 0x07,
                0x10, 0x78, 0xb8, 0x00, 0x06, 0xb0,
            ],
        );
        assert_eq!(
            after_mutation.return_origins[0].value_origin,
            Some(super::ValueOrigin::Instruction(16))
        );

        // The first recognized decoder normalizes the current contents, then
        // invalidates the in-place array before the second invocation.
        let after_decoder = run(
            "afterDecoder",
            &[
                0x04, 0xbc, 0x05, 0x59, 0x03, 0x10, 0x41, 0x55, 0x59, 0x12, 0x07, 0x10, 0x78, 0xb8,
                0x00, 0x06, 0x57, 0x59, 0x12, 0x07, 0x10, 0x78, 0xb8, 0x00, 0x06, 0xb0,
            ],
        );
        assert_eq!(
            after_decoder.return_origins[0].value_origin,
            Some(super::ValueOrigin::Instruction(22))
        );
    }

    #[test]
    fn invalidates_literals_and_scalar_constants_at_control_flow_joins() {
        use super::ConstantPoolEntry;

        let entries = vec![
            ConstantPoolEntry::Other,
            ConstantPoolEntry::Class { name_index: 2 },
            ConstantPoolEntry::Utf8("example/Test".to_owned()),
            ConstantPoolEntry::NameAndType {
                name_index: 4,
                descriptor_index: 5,
            },
            ConstantPoolEntry::Utf8("decode".to_owned()),
            ConstantPoolEntry::Utf8("([CLjava/lang/String;I)Ljava/lang/String;".to_owned()),
            ConstantPoolEntry::Ref {
                tag: 10,
                class_index: 1,
                name_and_type_index: 3,
            },
            ConstantPoolEntry::String { string_index: 8 },
            ConstantPoolEntry::Utf8("x".to_owned()),
        ];
        // The conditional target skips the char[] allocation and stores.
        // Linear fallthrough reaches the join after creating a literal array.
        let code = [
            0x03, 0x99, 0x00, 0x0c, // iconst_0; ifeq target at 13
            0x04, 0xbc, 0x05, // new char[1]
            0x59, 0x03, 0x10, 0x41, 0x55, // array[0] = 'A'
            0x4b, // astore_0
            0x2a, 0x12, 0x07, 0x10, 0x78, 0xb8, 0x00, 0x06, 0xb0,
        ];
        let mut method = super::MethodScanData {
            class_name: "example/Test".to_owned(),
            method_name: "conditionalArray".to_owned(),
            descriptor: "()Ljava/lang/String;".to_owned(),
            is_static: true,
            instructions: super::decode_instructions(&code).expect("code must decode"),
            ..super::MethodScanData::default()
        };
        super::populate_value_origins_with_decoders(&entries, &mut method, &["decode".to_owned()])
            .expect("origin pass must succeed");
        assert_eq!(
            method.return_origins[0].value_origin,
            Some(super::ValueOrigin::Instruction(18))
        );

        // A join also invalidates scalar constants while retaining the local
        // identity needed by downstream dataflow.
        let scalar = super::parse_method_code(
            &[],
            &[
                0x10, 0x07, 0x3b, 0x03, 0x99, 0x00, 0x05, 0x1a, 0xac, 0x1a, 0xac,
            ],
            "example/Test",
            "conditionalScalar",
            "()I",
            true,
        )
        .expect("bounded static parse must succeed");
        assert_eq!(
            scalar
                .return_origins
                .iter()
                .map(|returned| returned.value_origin.clone())
                .collect::<Vec<_>>(),
            vec![
                Some(super::ValueOrigin::Local(0)),
                Some(super::ValueOrigin::Local(0)),
            ]
        );
    }

    #[test]
    fn invalidates_char_arrays_when_they_escape_to_fields_or_object_arrays() {
        use super::ConstantPoolEntry;

        let entries = vec![
            ConstantPoolEntry::Other,
            ConstantPoolEntry::Class { name_index: 2 },
            ConstantPoolEntry::Utf8("example/Test".to_owned()),
            ConstantPoolEntry::NameAndType {
                name_index: 4,
                descriptor_index: 5,
            },
            ConstantPoolEntry::Utf8("decode".to_owned()),
            ConstantPoolEntry::Utf8("([CLjava/lang/String;I)Ljava/lang/String;".to_owned()),
            ConstantPoolEntry::Ref {
                tag: 10,
                class_index: 1,
                name_and_type_index: 3,
            },
            ConstantPoolEntry::String { string_index: 8 },
            ConstantPoolEntry::Utf8("x".to_owned()),
            ConstantPoolEntry::NameAndType {
                name_index: 10,
                descriptor_index: 11,
            },
            ConstantPoolEntry::Utf8("chars".to_owned()),
            ConstantPoolEntry::Utf8("[C".to_owned()),
            ConstantPoolEntry::Ref {
                tag: 9,
                class_index: 1,
                name_and_type_index: 9,
            },
        ];
        let decoder_names = ["decode".to_owned()];
        let run = |method_name: &str, descriptor: &str, is_static: bool, code: &[u8]| {
            let mut method = super::MethodScanData {
                class_name: "example/Test".to_owned(),
                method_name: method_name.to_owned(),
                descriptor: descriptor.to_owned(),
                is_static,
                instructions: super::decode_instructions(code).expect("code must decode"),
                ..super::MethodScanData::default()
            };
            super::populate_value_origins_with_decoders(&entries, &mut method, &decoder_names)
                .expect("origin pass must succeed");
            method
        };

        let setup = [0x04, 0xbc, 0x05, 0x59, 0x03, 0x10, 0x41, 0x55, 0x4c];
        let putstatic = run(
            "putstaticEscape",
            "()Ljava/lang/String;",
            true,
            &[
                setup.as_slice(),
                &[
                    0x2b, 0xb3, 0x00, 0x0c, 0x2b, 0x12, 0x07, 0x10, 0x78, 0xb8, 0x00, 0x06, 0xb0,
                ],
            ]
            .concat(),
        );
        assert_eq!(
            putstatic.return_origins[0].value_origin,
            Some(super::ValueOrigin::Instruction(18))
        );

        let putfield = run(
            "putfieldEscape",
            "()Ljava/lang/String;",
            false,
            &[
                setup.as_slice(),
                &[
                    0x2a, 0x2b, 0xb5, 0x00, 0x0c, 0x2b, 0x12, 0x07, 0x10, 0x78, 0xb8, 0x00, 0x06,
                    0xb0,
                ],
            ]
            .concat(),
        );
        assert_eq!(
            putfield.return_origins[0].value_origin,
            Some(super::ValueOrigin::Instruction(19))
        );

        let aastore = run(
            "aastoreEscape",
            "([Ljava/lang/Object;)Ljava/lang/String;",
            true,
            &[
                setup.as_slice(),
                &[
                    0x2a, 0x03, 0x2b, 0x53, 0x2b, 0x12, 0x07, 0x10, 0x78, 0xb8, 0x00, 0x06, 0xb0,
                ],
            ]
            .concat(),
        );
        assert_eq!(
            aastore.return_origins[0].value_origin,
            Some(super::ValueOrigin::Instruction(18))
        );
    }

    #[test]
    fn iinc_invalidates_constant_local_origins_including_wide_iinc() {
        use super::ConstantPoolEntry;

        let entries = vec![
            ConstantPoolEntry::Other,
            ConstantPoolEntry::Class { name_index: 2 },
            ConstantPoolEntry::Utf8("example/Test".to_owned()),
            ConstantPoolEntry::NameAndType {
                name_index: 4,
                descriptor_index: 5,
            },
            ConstantPoolEntry::Utf8("decode".to_owned()),
            ConstantPoolEntry::Utf8("([CLjava/lang/String;I)Ljava/lang/String;".to_owned()),
            ConstantPoolEntry::Ref {
                tag: 10,
                class_index: 1,
                name_and_type_index: 3,
            },
            ConstantPoolEntry::String { string_index: 8 },
            ConstantPoolEntry::Utf8("x".to_owned()),
        ];
        let code = [
            0x04, 0xbc, 0x05, 0x59, 0x03, 0x10, 0x41, 0x55, 0x4c, // char[] 'A' in local 1
            0x10, 0x78, 0x3b, 0x84, 0x00, 0x01, // local 0 = 120; iinc 0, 1
            0x2b, 0x12, 0x07, 0x1a, 0xb8, 0x00, 0x06, 0xb0,
        ];
        let mut method = super::MethodScanData {
            class_name: "example/Test".to_owned(),
            method_name: "incrementedKey".to_owned(),
            descriptor: "()Ljava/lang/String;".to_owned(),
            is_static: true,
            instructions: super::decode_instructions(&code).expect("code must decode"),
            ..super::MethodScanData::default()
        };
        super::populate_value_origins_with_decoders(&entries, &mut method, &["decode".to_owned()])
            .expect("origin pass must succeed");
        assert_eq!(
            method.return_origins[0].value_origin,
            Some(super::ValueOrigin::Instruction(19))
        );

        let wide = super::parse_method_code(
            &[],
            &[
                0x10, 0x78, 0x3b, 0xc4, 0x84, 0x00, 0x00, 0x00, 0x01, 0x1a, 0xac,
            ],
            "example/Test",
            "wideIncrement",
            "()I",
            true,
        )
        .expect("bounded static parse must succeed");
        assert_eq!(
            wide.return_origins[0].value_origin,
            Some(super::ValueOrigin::Instruction(3))
        );
    }

    #[test]
    fn decodes_bipush_and_sipush_with_their_operands() {
        let code = [0x10, 0x7f, 0x11, 0x01, 0x00, 0xb1];

        let method = super::parse_method_code(&[], &code, "example/Test", "numbers", "()V", true)
            .expect("bounded static parse must succeed");

        assert_eq!(method.instructions[0].operands, vec![0x7f]);
        assert_eq!(method.instructions[1].operands, vec![0x01, 0x00]);
    }

    #[test]
    fn builds_cfg_using_valid_bytecode_offsets() {
        // iconst_0; ifeq +4; return; return
        let code = [0x03, 0x99, 0x00, 0x04, 0xb1, 0xb1];
        let method = super::parse_method_code(&[], &code, "example/Test", "branch", "()V", true)
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
