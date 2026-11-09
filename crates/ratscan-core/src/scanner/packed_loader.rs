//! Recognizes concealed image-container loaders from connected bytecode operations.
//!
//! This is a specific loader signature, not a confirmed write/execute taint chain:
//! the names and contents of a remote ZIP are unavailable to static analysis.
use std::collections::{HashMap, HashSet};

use super::{
    archive::{ClassScanData, ScanData},
    class_file::{CallSite, ConstantValue, FieldAccess, MethodScanData, ValueOrigin},
};
use crate::models::scan::{CodeScope, Confidence, Evidence, Finding, FindingKind, Severity};

pub(crate) const RULE_ID: &str = "CONCEALED_ARCHIVE_PAYLOAD_EXEC";
type Classes<'a> = HashMap<(&'a str, &'a str), &'a ClassScanData>;

pub(crate) fn finding(data: &ScanData) -> Option<Finding> {
    let classes: Classes<'_> = data
        .class_files
        .iter()
        .filter_map(|class| {
            Some((
                (class.archive_id.as_str(), class.class_name.as_deref()?),
                class,
            ))
        })
        .collect();
    for class in &data.class_files {
        if !matches!(class.scope, CodeScope::FirstParty | CodeScope::NestedMod) {
            continue;
        }
        let Some(name) = class.class_name.as_deref() else {
            continue;
        };
        for decoder in class.methods.iter().filter(|method| png_decoder(method)) {
            let Some(inflate) = decoder.calls.iter().find(|call| {
                local_call(call, name)
                    && call.descriptor == "([B)[B"
                    && returned(decoder, call.result_origin.as_ref())
                    && decoder.calls.iter().any(|slice| {
                        api(slice, "java/util/Arrays", "copyOfRange")
                            && slice.argument_origins.first() == Some(&ValueOrigin::Local(1))
                            && same(slice.result_origin.as_ref(), call.argument_origins.first())
                            && slice.offset < call.offset
                    })
                    && target_method(class, call).is_some_and(inflates_parameter)
            }) else {
                continue;
            };
            for extractor in &class.methods {
                let Some((root, extraction)) = extraction(extractor) else {
                    continue;
                };
                for stage in &class.methods {
                    let Some(unpack) = stage
                        .calls
                        .iter()
                        .find(|call| calls_method(call, extractor) && local_call(call, name))
                    else {
                        continue;
                    };
                    let Some(decode) = stage.calls.iter().find(|call| {
                        calls_method(call, decoder)
                            && local_call(call, name)
                            && call.offset < unpack.offset
                            && same(call.result_origin.as_ref(), unpack.argument_origins.first())
                    }) else {
                        continue;
                    };
                    let Some(body) =
                        field_at(stage, decode.argument_origins.first(), decode.offset)
                            .filter(|field| field.descriptor == "[B")
                    else {
                        continue;
                    };
                    let Some(source) = stage.calls.iter().find(|call| {
                        call.offset < body.offset
                            && call.descriptor.ends_with(&format!(")L{};", body.owner))
                            && same(call.result_origin.as_ref(), body.receiver_origin.as_ref())
                    }) else {
                        continue;
                    };
                    let Some((network_class, network_method, network)) =
                        network_source(&classes, &class.archive_id, source)
                    else {
                        continue;
                    };
                    for launch in &class.methods {
                        let Some(launch_calls) = launch_from_root(launch, root) else {
                            continue;
                        };
                        let Some((controller, stage_call, launch_call)) =
                            class.methods.iter().find_map(|method| {
                                let stage_call = method.calls.iter().find(|call| {
                                    calls_method(call, stage) && local_call(call, name)
                                })?;
                                let launch_call = method.calls.iter().find(|call| {
                                    calls_method(call, launch)
                                        && local_call(call, name)
                                        && call.offset > stage_call.offset
                                })?;
                                Some((method, stage_call, launch_call))
                            })
                        else {
                            continue;
                        };
                        let mut evidence = vec![
                            evidence(network_class, network_method, network),
                            evidence(class, stage, source),
                            at(
                                class,
                                stage,
                                body.offset,
                                format!("{}.{}", body.owner, body.name),
                            ),
                            evidence(class, stage, decode),
                            evidence(class, decoder, inflate),
                            evidence(class, stage, unpack),
                            evidence(class, controller, stage_call),
                            evidence(class, controller, launch_call),
                        ];
                        evidence.extend(
                            extraction
                                .into_iter()
                                .map(|call| self::evidence(class, extractor, call)),
                        );
                        evidence.extend(
                            launch_calls
                                .into_iter()
                                .map(|call| self::evidence(class, launch, call)),
                        );
                        return Some(Finding {
                            rule_id: RULE_ID.to_owned(), category: "loader".to_owned(),
                            kind: FindingKind::Finding, severity: Severity::Critical,
                            confidence: Confidence::High, score_contribution: 80,
                            scope: class.scope.clone(),
                            message: "Связанный код передаёт сетевой ответ в декодер PNG-контейнера, распаковывает скрытый ZIP и запускает процесс из того же корневого каталога. Это характерная цепочка скрытого загрузчика. Состав удалённого архива и факт выполнения статически не установлены.".to_owned(),
                            evidence, related_chain_id: None,
                        });
                    }
                }
            }
        }
    }
    None
}

fn api(call: &CallSite, owner: &str, name: &str) -> bool {
    call.owner.as_deref() == Some(owner) && call.name == name
}

fn same(left: Option<&ValueOrigin>, right: Option<&ValueOrigin>) -> bool {
    matches!((left, right), (Some(left), Some(right)) if *left != ValueOrigin::Unknown && left == right)
}

fn local_call(call: &CallSite, owner: &str) -> bool {
    call.owner.as_deref() == Some(owner) && call.receiver_origin == Some(ValueOrigin::Local(0))
}

fn calls_method(call: &CallSite, method: &MethodScanData) -> bool {
    call.owner.as_deref() == Some(method.class_name.as_str())
        && call.name == method.method_name
        && call.descriptor == method.descriptor
}

fn target_method<'a>(class: &'a ClassScanData, call: &CallSite) -> Option<&'a MethodScanData> {
    class
        .methods
        .iter()
        .find(|method| calls_method(call, method))
}

fn returned(method: &MethodScanData, origin: Option<&ValueOrigin>) -> bool {
    method
        .return_origins
        .iter()
        .any(|value| same(value.value_origin.as_ref(), origin))
}

// Field origins omit the receiver. Match the nearest actual access, never a
// convenient earlier read of the same field on a different object.
fn field_at<'a>(
    method: &'a MethodScanData,
    origin: Option<&ValueOrigin>,
    offset: u32,
) -> Option<&'a FieldAccess> {
    let ValueOrigin::Field {
        owner,
        name,
        descriptor,
    } = origin?
    else {
        return None;
    };
    let read = method.field_reads.iter().rev().find(|read| {
        read.offset < offset
            && read.owner == *owner
            && read.name == *name
            && read.descriptor == *descriptor
    })?;
    // A Field origin also survives local stores. If the same field was read
    // from different objects, even the nearest access cannot resolve that alias.
    if method.field_reads.iter().any(|other| {
        other.offset < offset
            && other.owner == *owner
            && other.name == *name
            && other.descriptor == *descriptor
            && other.receiver_origin != read.receiver_origin
    }) {
        return None;
    }
    Some(read)
}

fn same_root(left: &FieldAccess, right: &FieldAccess) -> bool {
    left.owner == right.owner
        && left.name == right.name
        && left.descriptor == right.descriptor
        && left.receiver_origin == Some(ValueOrigin::Local(0))
        && right.receiver_origin == Some(ValueOrigin::Local(0))
}

fn png_decoder(method: &MethodScanData) -> bool {
    const MAGIC: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];
    !method.is_static && method.descriptor == "([B)[B"
        && method.array_elements.windows(8).any(|elements| {
            elements.iter().enumerate().all(|(index, element)| {
                same(Some(&element.array_origin), Some(&elements[0].array_origin))
                    && element.index == Some(index as u16)
                    && matches!(element.value_origin, ValueOrigin::Constant(ConstantValue::Integer(value)) if value as u8 == MAGIC[index])
            }) && method.branch_conditions.iter().any(|branch| {
                if !matches!(branch.opcode, 0x9f | 0xa0) { return false }
                let left = method.array_reads.iter().find(|read| branch.value_origin == ValueOrigin::Instruction(read.offset));
                let right = method.array_reads.iter().find(|read| branch.compared_origin == Some(ValueOrigin::Instruction(read.offset)));
                matches!((left, right), (Some(left), Some(right)) if
                    left.array_origin == ValueOrigin::Local(1)
                    && right.array_origin == elements[0].array_origin
                    && same(Some(&left.index_origin), Some(&right.index_origin)))
            })
        })
}

fn inflates_parameter(method: &MethodScanData) -> bool {
    let Some(set_input) = method.calls.iter().find(|call| {
        api(call, "java/util/zip/Inflater", "setInput")
            && call.argument_origins.first() == Some(&ValueOrigin::Local(1))
    }) else {
        return false;
    };
    method.calls.iter().any(|inflate| {
        api(inflate, "java/util/zip/Inflater", "inflate")
            && inflate.offset > set_input.offset
            && same(
                inflate.receiver_origin.as_ref(),
                set_input.receiver_origin.as_ref(),
            )
            && method.calls.iter().any(|write| {
                api(write, "java/io/ByteArrayOutputStream", "write")
                    && write.offset > inflate.offset
                    && write.descriptor == "([BII)V"
                    && write.argument_origins.get(1)
                        == Some(&ValueOrigin::Constant(ConstantValue::Integer(0)))
                    && same(
                        write.argument_origins.get(2),
                        inflate.result_origin.as_ref(),
                    )
                    && same(
                        write.argument_origins.first(),
                        inflate.argument_origins.first(),
                    )
                    && method.calls.iter().any(|output| {
                        api(output, "java/io/ByteArrayOutputStream", "toByteArray")
                            && output.offset > write.offset
                            && same(
                                output.receiver_origin.as_ref(),
                                write.receiver_origin.as_ref(),
                            )
                            && returned(method, output.result_origin.as_ref())
                    })
            })
    })
}

fn extraction(method: &MethodScanData) -> Option<(&FieldAccess, Vec<&CallSite>)> {
    if method.is_static || !method.descriptor.starts_with("([B)") {
        return None;
    }
    let bytes = method.calls.iter().find(|call| {
        api(call, "java/io/ByteArrayInputStream", "<init>")
            && call.argument_origins.first() == Some(&ValueOrigin::Local(1))
    })?;
    let zip = method.calls.iter().find(|call| {
        api(call, "java/util/zip/ZipInputStream", "<init>")
            && same(
                call.argument_origins.first(),
                bytes.receiver_origin.as_ref(),
            )
    })?;
    let entry = method.calls.iter().find(|call| {
        api(call, "java/util/zip/ZipInputStream", "getNextEntry")
            && same(call.receiver_origin.as_ref(), zip.receiver_origin.as_ref())
    })?;
    let name = method.calls.iter().find(|call| {
        api(call, "java/util/zip/ZipEntry", "getName")
            && same(call.receiver_origin.as_ref(), entry.result_origin.as_ref())
    })?;
    let resolve = method.calls.iter().find(|call| {
        api(call, "java/nio/file/Path", "resolve")
            && same(call.argument_origins.first(), name.result_origin.as_ref())
    })?;
    let root = field_at(method, resolve.receiver_origin.as_ref(), resolve.offset)?;
    if root.descriptor != "Ljava/nio/file/Path;"
        || root.receiver_origin != Some(ValueOrigin::Local(0))
    {
        return None;
    }
    let file = method.calls.iter().find(|call| {
        api(call, "java/nio/file/Path", "toFile")
            && same(
                call.receiver_origin.as_ref(),
                resolve.result_origin.as_ref(),
            )
    })?;
    let output = method.calls.iter().find(|call| {
        api(call, "java/io/FileOutputStream", "<init>")
            && same(call.argument_origins.first(), file.result_origin.as_ref())
    })?;
    let buffered = method.calls.iter().find(|call| {
        api(call, "java/io/BufferedOutputStream", "<init>")
            && same(
                call.argument_origins.first(),
                output.receiver_origin.as_ref(),
            )
    })?;
    let read = method.calls.iter().find(|call| {
        api(call, "java/util/zip/ZipInputStream", "read")
            && same(call.receiver_origin.as_ref(), zip.receiver_origin.as_ref())
            && call.descriptor.starts_with("([B")
    })?;
    let write = method.calls.iter().find(|call| {
        api(call, "java/io/BufferedOutputStream", "write")
            && call.offset > read.offset
            && call.descriptor == "([BII)V"
            && call.argument_origins.get(1)
                == Some(&ValueOrigin::Constant(ConstantValue::Integer(0)))
            && same(call.argument_origins.get(2), read.result_origin.as_ref())
            && same(
                call.receiver_origin.as_ref(),
                buffered.receiver_origin.as_ref(),
            )
            && same(call.argument_origins.first(), read.argument_origins.first())
    })?;
    Some((root, vec![zip, entry, name, resolve, output, read, write]))
}

fn path_root<'a>(
    method: &'a MethodScanData,
    origin: Option<&ValueOrigin>,
    before: u32,
    depth: usize,
) -> Option<&'a FieldAccess> {
    if depth == 0 {
        return None;
    }
    if let Some(field) = field_at(method, origin, before) {
        return Some(field);
    }
    let call = method
        .calls
        .iter()
        .find(|call| call.offset < before && same(call.result_origin.as_ref(), origin))?;
    if call.owner.as_deref() != Some("java/nio/file/Path")
        || !matches!(call.name.as_str(), "resolve" | "toString" | "toFile")
    {
        return None;
    }
    path_root(
        method,
        call.receiver_origin.as_ref(),
        call.offset,
        depth - 1,
    )
}

fn launch_from_root<'a>(
    method: &'a MethodScanData,
    root: &FieldAccess,
) -> Option<Vec<&'a CallSite>> {
    if method.is_static {
        return None;
    }
    let builder = method.calls.iter().find(|call| {
        api(call, "java/lang/ProcessBuilder", "<init>") && call.descriptor == "(Ljava/util/List;)V"
    })?;
    let first_argument = method.calls.iter().find(|call| {
        call.offset < builder.offset
            && matches!(
                call.owner.as_deref(),
                Some("java/util/List" | "java/util/ArrayList")
            )
            && call.name == "add"
            && same(
                call.receiver_origin.as_ref(),
                builder.argument_origins.first(),
            )
    })?;
    if !path_root(
        method,
        first_argument.argument_origins.first(),
        first_argument.offset,
        8,
    )
    .is_some_and(|field| same_root(root, field))
    {
        return None;
    }
    let directory = method.calls.iter().find(|call| {
        api(call, "java/lang/ProcessBuilder", "directory")
            && same(
                call.receiver_origin.as_ref(),
                builder.receiver_origin.as_ref(),
            )
            && path_root(method, call.argument_origins.first(), call.offset, 8)
                .is_some_and(|field| same_root(root, field))
    })?;
    let start = method.calls.iter().find(|call| {
        api(call, "java/lang/ProcessBuilder", "start")
            && call.offset > directory.offset
            && same(
                call.receiver_origin.as_ref(),
                builder.receiver_origin.as_ref(),
            )
    })?;
    Some(vec![first_argument, builder, directory, start])
}

// A small, bounded same-archive call walk. Uncalled network methods and classes
// in a different nested archive cannot supply the response-body signature.
fn network_source<'a>(
    classes: &Classes<'a>,
    archive: &str,
    source: &CallSite,
) -> Option<(&'a ClassScanData, &'a MethodScanData, &'a CallSite)> {
    let class = *classes.get(&(archive, source.owner.as_deref()?))?;
    let mut pending = vec![(class, target_method(class, source)?, 0)];
    let mut seen = HashSet::new();
    while let Some((class, method, depth)) = pending.pop() {
        if !seen.insert((
            method.class_name.as_str(),
            method.method_name.as_str(),
            method.descriptor.as_str(),
        )) {
            continue;
        }
        if seen.len() > 64 {
            return None;
        }
        for call in &method.calls {
            let owner = call.owner.as_deref().unwrap_or_default();
            if (matches!(
                owner,
                "java/net/Socket"
                    | "javax/net/ssl/SSLSocket"
                    | "java/net/URLConnection"
                    | "java/net/HttpURLConnection"
                    | "javax/net/ssl/HttpsURLConnection"
            ) && call.name == "getInputStream")
                || (owner == "java/net/URL" && call.name == "openStream")
                || (owner == "java/net/http/HttpClient"
                    && matches!(call.name.as_str(), "send" | "sendAsync"))
            {
                return Some((class, method, call));
            }
            if depth < 4 {
                if let Some(next) = classes.get(&(archive, owner)) {
                    if let Some(callee) = target_method(next, call) {
                        pending.push((next, callee, depth + 1));
                    }
                }
            }
        }
    }
    None
}

fn evidence(class: &ClassScanData, method: &MethodScanData, call: &CallSite) -> Evidence {
    at(
        class,
        method,
        call.offset,
        format!(
            "{}.{}",
            call.owner.as_deref().unwrap_or("<unknown>"),
            call.name
        ),
    )
}

fn at(class: &ClassScanData, method: &MethodScanData, offset: u32, operation: String) -> Evidence {
    Evidence {
        archive_id: class.archive_id.clone(),
        archive_path: class.archive_path.clone(),
        class_name: Some(method.class_name.clone()),
        method_name: Some(method.method_name.clone()),
        method_descriptor: Some(method.descriptor.clone()),
        bytecode_offset: Some(offset),
        resource_path: Some(class.path.clone()),
        operation,
        value_preview: None,
        source_value: None,
        target_value: None,
        confidence: Confidence::High,
        scope: class.scope.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::class_file::{InvokeKind, ReturnOrigin};

    #[test]
    fn field_aliases_from_different_responses_are_ambiguous_in_either_order() {
        let origin = ValueOrigin::Field {
            owner: "example/Response".to_owned(),
            name: "body".to_owned(),
            descriptor: "[B".to_owned(),
        };
        let read = FieldAccess {
            offset: 10,
            owner: "example/Response".to_owned(),
            name: "body".to_owned(),
            descriptor: "[B".to_owned(),
            receiver_origin: Some(ValueOrigin::Instruction(1)),
            value_origin: None,
        };
        let mut second = read.clone();
        second.offset = 20;
        let mut method = MethodScanData {
            field_reads: vec![read, second],
            ..Default::default()
        };
        assert!(field_at(&method, Some(&origin), 30).is_some());
        method.field_reads[1].receiver_origin = Some(ValueOrigin::Instruction(2));
        assert!(field_at(&method, Some(&origin), 30).is_none());
        method.field_reads[0].receiver_origin = Some(ValueOrigin::Instruction(2));
        method.field_reads[1].receiver_origin = Some(ValueOrigin::Instruction(1));
        assert!(field_at(&method, Some(&origin), 30).is_none());
    }

    #[test]
    fn inflater_must_return_the_bytes_written_after_decompression() {
        let call = |owner: &str, name: &str, offset, receiver, arguments, result| CallSite {
            offset,
            kind: InvokeKind::Virtual,
            owner: Some(owner.to_owned()),
            name: name.to_owned(),
            descriptor: if name == "write" { "([BII)V" } else { "()V" }.to_owned(),
            receiver_origin: Some(ValueOrigin::Instruction(receiver)),
            argument_origins: arguments,
            result_origin: result,
        };
        let method = MethodScanData {
            calls: vec![
                call(
                    "java/util/zip/Inflater",
                    "setInput",
                    5,
                    0,
                    vec![ValueOrigin::Local(1)],
                    None,
                ),
                call(
                    "java/util/zip/Inflater",
                    "inflate",
                    10,
                    0,
                    vec![ValueOrigin::Local(2)],
                    Some(ValueOrigin::Instruction(10)),
                ),
                call(
                    "java/io/ByteArrayOutputStream",
                    "write",
                    20,
                    2,
                    vec![
                        ValueOrigin::Local(2),
                        ValueOrigin::Constant(ConstantValue::Integer(0)),
                        ValueOrigin::Instruction(10),
                    ],
                    None,
                ),
                call(
                    "java/io/ByteArrayOutputStream",
                    "toByteArray",
                    30,
                    2,
                    vec![],
                    Some(ValueOrigin::Instruction(30)),
                ),
            ],
            return_origins: vec![ReturnOrigin {
                offset: 31,
                value_origin: Some(ValueOrigin::Instruction(30)),
            }],
            ..Default::default()
        };
        assert!(inflates_parameter(&method));
        let mut empty_write = method.clone();
        empty_write.calls[2].argument_origins[2] = ValueOrigin::Constant(ConstantValue::Integer(0));
        assert!(!inflates_parameter(&empty_write));
        let mut premature_snapshot = method.clone();
        premature_snapshot.calls[3].offset = 15;
        assert!(!inflates_parameter(&premature_snapshot));
        let mut late_input = method.clone();
        late_input.calls[0].offset = 15;
        assert!(!inflates_parameter(&late_input));
        let mut other_buffer = method.clone();
        other_buffer.calls[2].argument_origins[0] = ValueOrigin::Local(3);
        assert!(!inflates_parameter(&other_buffer));
        let mut other_output = method.clone();
        other_output.calls[3].receiver_origin = Some(ValueOrigin::Instruction(3));
        assert!(!inflates_parameter(&other_output));
    }
}
