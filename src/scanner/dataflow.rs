//! Bounded, evidence-preserving taint propagation for bytecode adapters.
//!
//! This module deliberately does not parse JVM bytecode. `class_file` (or a later
//! bytecode parser) is responsible for translating instructions into `Operation`s.
//! Keeping that boundary explicit prevents an API-name match in unrelated methods
//! from being reported as a behavioural chain.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Stable identity of a method in an archive layer.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MethodId {
    pub archive_id: String,
    pub class_name: String,
    pub method_name: String,
    pub descriptor: String,
}

/// A local slot as exposed by the bytecode-to-flow adapter.
pub type LocalId = u16;

/// Location information attached to every operation that can contribute to a chain.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FlowEvidence {
    pub archive_id: String,
    pub archive_path: String,
    pub class_name: String,
    pub method_name: String,
    pub method_descriptor: String,
    pub bytecode_offset: u32,
    pub operation: String,
    pub value_preview: Option<String>,
    pub source_value: Option<String>,
    pub target_value: Option<String>,
}

impl FlowEvidence {
    pub fn for_method(
        method: &MethodId,
        bytecode_offset: u32,
        operation: impl Into<String>,
    ) -> Self {
        Self {
            archive_id: method.archive_id.clone(),
            archive_path: method.archive_id.clone(),
            class_name: method.class_name.clone(),
            method_name: method.method_name.clone(),
            method_descriptor: method.descriptor.clone(),
            bytecode_offset,
            operation: operation.into(),
            value_preview: None,
            source_value: None,
            target_value: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    HttpResponse,
    SocketInput,
    CredentialFile,
    EnvironmentVariable,
    Clipboard,
    ProcessOutput,
    EmbeddedEncryptedResource,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransformKind {
    Base64Decode,
    XorDecode,
    Decrypt,
    Decompress,
    BytesToString,
    StringToUrl,
    Other,
}

impl TransformKind {
    fn is_decoder(self) -> bool {
        matches!(
            self,
            Self::Base64Decode | Self::XorDecode | Self::Decrypt | Self::Decompress
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DynamicLoadKind {
    ClassDefinition,
    NativeLibrary,
}

/// Canonical destination identity supplied by the adapter.
///
/// The engine intentionally refuses to guess whether two dynamically-built paths
/// are equal. An adapter may use `Known` after proving the path value, otherwise it
/// must use `Unknown`; the latter cannot form a write/execute chain.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FileTarget {
    Known(String),
    Unknown,
}

/// A method expressed as a small, parser-independent flow program.
#[derive(Clone, Debug)]
pub struct MethodFlow {
    pub id: MethodId,
    pub parameter_count: u16,
    pub operations: Vec<Operation>,
}

/// Operations emitted from individual bytecode instructions or recognised API calls.
#[derive(Clone, Debug)]
pub enum Operation {
    Source {
        output: LocalId,
        kind: SourceKind,
        evidence: FlowEvidence,
    },
    Copy {
        input: LocalId,
        output: LocalId,
    },
    Transform {
        input: LocalId,
        output: LocalId,
        kind: TransformKind,
        evidence: FlowEvidence,
    },
    WriteFile {
        input: LocalId,
        destination: FileTarget,
        evidence: FlowEvidence,
    },
    ExecuteFile {
        target: FileTarget,
        evidence: FlowEvidence,
    },
    NetworkSend {
        body: LocalId,
        evidence: FlowEvidence,
    },
    DynamicLoad {
        input: LocalId,
        kind: DynamicLoadKind,
        evidence: FlowEvidence,
    },
    Call {
        callee: MethodId,
        arguments: Vec<LocalId>,
        return_to: Option<LocalId>,
        evidence: FlowEvidence,
    },
    Return {
        value: Option<LocalId>,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConfirmedChainKind {
    DownloadWriteExecute,
    CredentialExfiltration,
    DecodedDynamicLoad,
    RemoteDynamicLoad,
}

/// A chain is emitted only after all its listed operations carry the same taint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedChainCandidate {
    pub chain_id: String,
    pub kind: ConfirmedChainKind,
    pub source: FlowEvidence,
    pub transformations: Vec<FlowEvidence>,
    pub operations: Vec<FlowEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowLimitation {
    MissingMethod { caller: MethodId, callee: MethodId },
    InterproceduralDepthReached { method: MethodId },
    RecursiveCallSkipped { method: MethodId },
}

#[derive(Clone, Debug)]
pub struct DataFlowConfig {
    /// A value of two means a root method may inspect a callee and that callee's
    /// callee. This is deliberately bounded until a full call graph is available.
    pub max_interprocedural_depth: u8,
}

impl Default for DataFlowConfig {
    fn default() -> Self {
        Self {
            max_interprocedural_depth: 2,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DataFlowResult {
    pub confirmed_chains: Vec<ConfirmedChainCandidate>,
    pub limitations: Vec<FlowLimitation>,
}

/// Runs a conservative flow analysis over independently parsed methods.
pub fn analyze_method_flows(methods: &[MethodFlow], config: &DataFlowConfig) -> DataFlowResult {
    let method_index: HashMap<MethodId, &MethodFlow> = methods
        .iter()
        .map(|method| (method.id.clone(), method))
        .collect();
    let mut analyzer = Analyzer::new(method_index, config);

    // Every method is a possible entry point. Parameter-only methods produce no
    // results here, but are analysed with real taints when reached by a call.
    for method in methods {
        let mut state = ExecutionState::default();
        analyzer.execute(&method.id, Vec::new(), 0, &mut BTreeSet::new(), &mut state);
    }
    analyzer.result
}

#[derive(Clone, Debug)]
struct Taint {
    source_kind: SourceKind,
    source: FlowEvidence,
    transformations: Vec<FlowEvidence>,
    decoded: bool,
}

#[derive(Clone, Debug)]
struct WrittenValue {
    taint: Taint,
    evidence: FlowEvidence,
}

struct FrameResult {
    return_values: Vec<Taint>,
}

#[derive(Default)]
struct ExecutionState {
    /// File writes are scoped to one reachable call tree. Keeping this state out
    /// of `Analyzer` prevents a write in one unrelated class from being joined to
    /// an execution in another independent class merely because both spell a path
    /// the same way.
    written_files: BTreeMap<FileTarget, Vec<WrittenValue>>,
}

struct Analyzer<'a> {
    methods: HashMap<MethodId, &'a MethodFlow>,
    config: &'a DataFlowConfig,
    result: DataFlowResult,
    emitted: HashSet<String>,
}

impl<'a> Analyzer<'a> {
    fn new(methods: HashMap<MethodId, &'a MethodFlow>, config: &'a DataFlowConfig) -> Self {
        Self {
            methods,
            config,
            result: DataFlowResult::default(),
            emitted: HashSet::new(),
        }
    }

    fn execute(
        &mut self,
        method_id: &MethodId,
        arguments: Vec<Vec<Taint>>,
        depth: u8,
        call_stack: &mut BTreeSet<MethodId>,
        state: &mut ExecutionState,
    ) -> FrameResult {
        let Some(method) = self.methods.get(method_id).copied() else {
            return FrameResult {
                return_values: Vec::new(),
            };
        };
        if !call_stack.insert(method_id.clone()) {
            self.result
                .limitations
                .push(FlowLimitation::RecursiveCallSkipped {
                    method: method_id.clone(),
                });
            return FrameResult {
                return_values: Vec::new(),
            };
        }

        let mut locals = HashMap::<LocalId, Vec<Taint>>::new();
        for (index, value) in arguments.into_iter().enumerate() {
            if index < method.parameter_count as usize {
                locals.insert(index as LocalId, value);
            }
        }
        let mut returned = Vec::new();

        for operation in &method.operations {
            match operation {
                Operation::Source {
                    output,
                    kind,
                    evidence,
                } => {
                    let taint = Taint {
                        source_kind: *kind,
                        source: evidence.clone(),
                        transformations: Vec::new(),
                        decoded: false,
                    };
                    locals.insert(*output, vec![taint]);
                }
                Operation::Copy { input, output } => {
                    locals.insert(*output, values(&locals, *input));
                }
                Operation::Transform {
                    input,
                    output,
                    kind,
                    evidence,
                } => {
                    let transformed = values(&locals, *input)
                        .into_iter()
                        .map(|mut taint| {
                            taint.transformations.push(evidence.clone());
                            taint.decoded |= kind.is_decoder();
                            taint
                        })
                        .collect();
                    locals.insert(*output, transformed);
                }
                Operation::WriteFile {
                    input,
                    destination,
                    evidence,
                } if !matches!(destination, FileTarget::Unknown) => {
                    state
                        .written_files
                        .entry(destination.clone())
                        .or_default()
                        .extend(
                            values(&locals, *input)
                                .into_iter()
                                .map(|taint| WrittenValue {
                                    taint,
                                    evidence: evidence.clone(),
                                }),
                        );
                }
                Operation::WriteFile { .. } => {}
                Operation::ExecuteFile { target, evidence }
                    if !matches!(target, FileTarget::Unknown) =>
                {
                    if let Some(writes) = state.written_files.get(target).cloned() {
                        for write in writes {
                            if write.taint.source_kind == SourceKind::HttpResponse {
                                self.emit(
                                    ConfirmedChainKind::DownloadWriteExecute,
                                    &write.taint,
                                    vec![write.evidence, evidence.clone()],
                                );
                            }
                        }
                    }
                }
                Operation::ExecuteFile { .. } => {}
                Operation::NetworkSend { body, evidence } => {
                    for taint in values(&locals, *body) {
                        if taint.source_kind == SourceKind::CredentialFile {
                            self.emit(
                                ConfirmedChainKind::CredentialExfiltration,
                                &taint,
                                vec![evidence.clone()],
                            );
                        }
                    }
                }
                Operation::DynamicLoad {
                    input,
                    kind: _,
                    evidence,
                } => {
                    for taint in values(&locals, *input) {
                        if taint.decoded {
                            self.emit(
                                ConfirmedChainKind::DecodedDynamicLoad,
                                &taint,
                                vec![evidence.clone()],
                            );
                        } else if taint.source_kind == SourceKind::HttpResponse {
                            self.emit(
                                ConfirmedChainKind::RemoteDynamicLoad,
                                &taint,
                                vec![evidence.clone()],
                            );
                        }
                    }
                }
                Operation::Call {
                    callee,
                    arguments,
                    return_to,
                    evidence: _,
                } => {
                    if depth >= self.config.max_interprocedural_depth {
                        self.result
                            .limitations
                            .push(FlowLimitation::InterproceduralDepthReached {
                                method: method_id.clone(),
                            });
                        continue;
                    }
                    if !self.methods.contains_key(callee) {
                        self.result.limitations.push(FlowLimitation::MissingMethod {
                            caller: method_id.clone(),
                            callee: callee.clone(),
                        });
                        continue;
                    }
                    let call_arguments = arguments
                        .iter()
                        .map(|local| values(&locals, *local))
                        .collect();
                    let call_result =
                        self.execute(callee, call_arguments, depth + 1, call_stack, state);
                    if let Some(output) = return_to {
                        locals.insert(*output, call_result.return_values);
                    }
                }
                Operation::Return { value } => {
                    returned = value
                        .map(|local| values(&locals, local))
                        .unwrap_or_default();
                    break;
                }
            }
        }
        call_stack.remove(method_id);
        FrameResult {
            return_values: returned,
        }
    }

    fn emit(&mut self, kind: ConfirmedChainKind, taint: &Taint, operations: Vec<FlowEvidence>) {
        let signature = format!(
            "{:?}:{}:{}",
            kind,
            operations
                .iter()
                .map(|evidence| format!(
                    "{}:{}:{}",
                    evidence.class_name, evidence.method_name, evidence.bytecode_offset
                ))
                .collect::<Vec<_>>()
                .join(","),
            taint.source.bytecode_offset
        );
        if !self.emitted.insert(signature.clone()) {
            return;
        }
        self.result.confirmed_chains.push(ConfirmedChainCandidate {
            chain_id: format!("flow-{signature}"),
            kind,
            source: taint.source.clone(),
            transformations: taint.transformations.clone(),
            operations,
        });
    }
}

fn values(locals: &HashMap<LocalId, Vec<Taint>>, local: LocalId) -> Vec<Taint> {
    locals.get(&local).cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method(name: &str, operations: Vec<Operation>) -> MethodFlow {
        MethodFlow {
            id: MethodId {
                archive_id: "root".into(),
                class_name: "example.Mod".into(),
                method_name: name.into(),
                descriptor: "()V".into(),
            },
            parameter_count: 0,
            operations,
        }
    }

    fn evidence(method: &MethodId, offset: u32, operation: &str) -> FlowEvidence {
        FlowEvidence::for_method(method, offset, operation)
    }

    #[test]
    fn confirms_download_write_execute_for_the_same_value_and_path() {
        let id = method("run", Vec::new()).id;
        let flow = MethodFlow {
            id: id.clone(),
            parameter_count: 0,
            operations: vec![
                Operation::Source {
                    output: 0,
                    kind: SourceKind::HttpResponse,
                    evidence: evidence(&id, 1, "http_response"),
                },
                Operation::WriteFile {
                    input: 0,
                    destination: FileTarget::Known("/tmp/update.jar".into()),
                    evidence: evidence(&id, 2, "file_write"),
                },
                Operation::ExecuteFile {
                    target: FileTarget::Known("/tmp/update.jar".into()),
                    evidence: evidence(&id, 3, "java_launch"),
                },
            ],
        };

        let result = analyze_method_flows(&[flow], &DataFlowConfig::default());
        assert_eq!(result.confirmed_chains.len(), 1);
        assert_eq!(
            result.confirmed_chains[0].kind,
            ConfirmedChainKind::DownloadWriteExecute
        );
    }

    #[test]
    fn rejects_http_and_execution_when_the_downloaded_value_was_not_written() {
        let id = method("run", Vec::new()).id;
        let flow = MethodFlow {
            id: id.clone(),
            parameter_count: 0,
            operations: vec![
                Operation::Source {
                    output: 0,
                    kind: SourceKind::HttpResponse,
                    evidence: evidence(&id, 1, "http_response"),
                },
                Operation::WriteFile {
                    input: 1,
                    destination: FileTarget::Known("/tmp/update.jar".into()),
                    evidence: evidence(&id, 2, "file_write"),
                },
                Operation::ExecuteFile {
                    target: FileTarget::Known("/tmp/update.jar".into()),
                    evidence: evidence(&id, 3, "java_launch"),
                },
            ],
        };
        assert!(analyze_method_flows(&[flow], &DataFlowConfig::default())
            .confirmed_chains
            .is_empty());
    }

    #[test]
    fn rejects_unrelated_file_targets() {
        let id = method("run", Vec::new()).id;
        let flow = MethodFlow {
            id: id.clone(),
            parameter_count: 0,
            operations: vec![
                Operation::Source {
                    output: 0,
                    kind: SourceKind::HttpResponse,
                    evidence: evidence(&id, 1, "http_response"),
                },
                Operation::WriteFile {
                    input: 0,
                    destination: FileTarget::Known("/tmp/a.jar".into()),
                    evidence: evidence(&id, 2, "file_write"),
                },
                Operation::ExecuteFile {
                    target: FileTarget::Known("/tmp/b.jar".into()),
                    evidence: evidence(&id, 3, "java_launch"),
                },
            ],
        };
        assert!(analyze_method_flows(&[flow], &DataFlowConfig::default())
            .confirmed_chains
            .is_empty());
    }

    #[test]
    fn rejects_write_and_execution_in_unrelated_root_methods() {
        let writer_id = method("writer", Vec::new()).id;
        let runner_id = MethodId {
            method_name: "runner".into(),
            ..writer_id.clone()
        };
        let writer = MethodFlow {
            id: writer_id.clone(),
            parameter_count: 0,
            operations: vec![
                Operation::Source {
                    output: 0,
                    kind: SourceKind::HttpResponse,
                    evidence: evidence(&writer_id, 1, "http_response"),
                },
                Operation::WriteFile {
                    input: 0,
                    destination: FileTarget::Known("/tmp/update.jar".into()),
                    evidence: evidence(&writer_id, 2, "file_write"),
                },
            ],
        };
        let runner = MethodFlow {
            id: runner_id.clone(),
            parameter_count: 0,
            operations: vec![Operation::ExecuteFile {
                target: FileTarget::Known("/tmp/update.jar".into()),
                evidence: evidence(&runner_id, 3, "java_launch"),
            }],
        };

        assert!(
            analyze_method_flows(&[writer, runner], &DataFlowConfig::default())
                .confirmed_chains
                .is_empty()
        );
    }

    #[test]
    fn follows_a_taint_into_one_level_helper_method() {
        let caller_id = method("run", Vec::new()).id;
        let helper_id = MethodId {
            method_name: "writeAndRun".into(),
            ..caller_id.clone()
        };
        let caller = MethodFlow {
            id: caller_id.clone(),
            parameter_count: 0,
            operations: vec![
                Operation::Source {
                    output: 0,
                    kind: SourceKind::HttpResponse,
                    evidence: evidence(&caller_id, 1, "http_response"),
                },
                Operation::Call {
                    callee: helper_id.clone(),
                    arguments: vec![0],
                    return_to: None,
                    evidence: evidence(&caller_id, 2, "call"),
                },
            ],
        };
        let helper = MethodFlow {
            id: helper_id.clone(),
            parameter_count: 1,
            operations: vec![
                Operation::WriteFile {
                    input: 0,
                    destination: FileTarget::Known("/tmp/update.jar".into()),
                    evidence: evidence(&helper_id, 3, "file_write"),
                },
                Operation::ExecuteFile {
                    target: FileTarget::Known("/tmp/update.jar".into()),
                    evidence: evidence(&helper_id, 4, "java_launch"),
                },
            ],
        };
        let result = analyze_method_flows(&[caller, helper], &DataFlowConfig::default());
        assert!(result
            .confirmed_chains
            .iter()
            .any(|chain| chain.kind == ConfirmedChainKind::DownloadWriteExecute));
    }

    #[test]
    fn confirms_only_credential_data_sent_to_network() {
        let id = method("run", Vec::new()).id;
        let flow = MethodFlow {
            id: id.clone(),
            parameter_count: 0,
            operations: vec![
                Operation::Source {
                    output: 0,
                    kind: SourceKind::CredentialFile,
                    evidence: evidence(&id, 1, "credential_read"),
                },
                Operation::Source {
                    output: 1,
                    kind: SourceKind::HttpResponse,
                    evidence: evidence(&id, 2, "http_response"),
                },
                Operation::NetworkSend {
                    body: 1,
                    evidence: evidence(&id, 3, "http_request_body"),
                },
            ],
        };
        assert!(analyze_method_flows(&[flow], &DataFlowConfig::default())
            .confirmed_chains
            .is_empty());
    }

    #[test]
    fn requires_a_decoder_before_reporting_decoded_dynamic_load() {
        let id = method("run", Vec::new()).id;
        let flow = MethodFlow {
            id: id.clone(),
            parameter_count: 0,
            operations: vec![
                Operation::Source {
                    output: 0,
                    kind: SourceKind::EmbeddedEncryptedResource,
                    evidence: evidence(&id, 1, "resource_read"),
                },
                Operation::Transform {
                    input: 0,
                    output: 1,
                    kind: TransformKind::XorDecode,
                    evidence: evidence(&id, 2, "xor_decode"),
                },
                Operation::DynamicLoad {
                    input: 1,
                    kind: DynamicLoadKind::ClassDefinition,
                    evidence: evidence(&id, 3, "define_class"),
                },
            ],
        };
        let result = analyze_method_flows(&[flow], &DataFlowConfig::default());
        assert_eq!(
            result.confirmed_chains[0].kind,
            ConfirmedChainKind::DecodedDynamicLoad
        );
    }
}
