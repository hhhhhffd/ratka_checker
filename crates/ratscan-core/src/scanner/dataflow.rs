//! Bounded, evidence-preserving taint propagation for bytecode adapters.
//!
//! This module deliberately does not parse JVM bytecode. `class_file` (or a later
//! bytecode parser) is responsible for translating instructions into `Operation`s.
//! Keeping that boundary explicit prevents an API-name match in unrelated methods
//! from being reported as a behavioural chain.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::models::scan::CodeScope;

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
    pub scope: CodeScope,
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
            scope: CodeScope::FirstParty,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    HttpResponse,
    FileRead,
    SocketInput,
    CredentialFile,
    /// A Minecraft authentication command entered through `ClientChatEvent`.
    ChatCredential,
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
    /// Extracts a token, cookie, password, or browser secret from file data.
    SecretExtract,
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
    /// Number of Java parameters, excluding the implicit `this` receiver.
    pub parameter_count: u16,
    /// JVM local slots that receive the declared parameters. Instance methods
    /// start at slot one because slot zero is `this`.
    pub parameter_slots: Vec<LocalId>,
    pub scope: CodeScope,
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
    /// A cryptographic verification that is proven to guard the success path.
    /// The adapter emits this only after linking the downloaded value to a digest
    /// or signature check and its boolean result to a rejecting branch.
    IntegrityVerify {
        input: LocalId,
        evidence: Vec<FlowEvidence>,
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
    IntegrityVerifiedDownloadWriteExecute,
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
    MissingMethod {
        caller: MethodId,
        callee: MethodId,
    },
    InterproceduralDepthReached {
        method: MethodId,
    },
    RecursiveCallSkipped {
        method: MethodId,
    },
    UnknownFileTarget {
        method: MethodId,
        offset: u32,
    },
    UnsupportedInstruction {
        method: MethodId,
        offset: u32,
        opcode: u8,
    },
    ObjectTrackingUnavailable {
        method: MethodId,
        offset: u32,
        object_type: String,
    },
    LinearControlFlow {
        method: MethodId,
    },
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
            max_interprocedural_depth: 4,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DataFlowResult {
    pub confirmed_chains: Vec<ConfirmedChainCandidate>,
    pub limitations: Vec<FlowLimitation>,
    pub analyzed_method_ids: BTreeSet<MethodId>,
    pub analyzed_methods: u32,
    pub resolved_calls: u32,
    pub unresolved_calls: u32,
    pub unknown_file_targets: u32,
    pub resolved_value_targets: u32,
}

/// Runs a conservative flow analysis over independently parsed methods.
pub fn analyze_method_flows(methods: &[MethodFlow], config: &DataFlowConfig) -> DataFlowResult {
    let roots = methods
        .iter()
        .filter(|method| method.scope != CodeScope::BundledDependency)
        .map(|method| method.id.clone())
        .collect::<Vec<_>>();
    analyze_method_flows_from_roots(methods, &roots, config)
}

/// Selects bounded call-tree roots around operations that can terminate a
/// dangerous chain. Benign methods such as configuration writes never become
/// roots by themselves.
pub fn dangerous_flow_roots(methods: &[MethodFlow], max_depth: u8) -> Vec<MethodId> {
    let method_index = methods
        .iter()
        .map(|method| (method.id.clone(), method))
        .collect::<HashMap<_, _>>();
    let mut callers = HashMap::<MethodId, BTreeSet<MethodId>>::new();
    for method in methods {
        if method.scope == CodeScope::BundledDependency {
            continue;
        }
        for operation in &method.operations {
            if let Operation::Call { callee, .. } = operation {
                callers
                    .entry(callee.clone())
                    .or_default()
                    .insert(method.id.clone());
            }
        }
    }

    let terminal_methods = methods
        .iter()
        .filter(|method| method.scope != CodeScope::BundledDependency)
        .filter(|method| method.operations.iter().any(is_dangerous_terminal))
        .map(|method| method.id.clone())
        .collect::<Vec<_>>();
    let mut roots = BTreeSet::new();
    for terminal in terminal_methods {
        collect_root_candidates(&terminal, max_depth, &callers, &method_index, &mut roots);
    }
    roots.into_iter().collect()
}

fn is_dangerous_terminal(operation: &Operation) -> bool {
    matches!(
        operation,
        Operation::NetworkSend { .. }
            | Operation::ExecuteFile { .. }
            | Operation::DynamicLoad { .. }
    )
}

fn collect_root_candidates(
    method_id: &MethodId,
    remaining_depth: u8,
    callers: &HashMap<MethodId, BTreeSet<MethodId>>,
    method_index: &HashMap<MethodId, &MethodFlow>,
    roots: &mut BTreeSet<MethodId>,
) {
    let eligible_callers = callers
        .get(method_id)
        .into_iter()
        .flatten()
        .filter(|caller| {
            method_index
                .get(*caller)
                .is_some_and(|method| method.scope != CodeScope::BundledDependency)
        })
        .collect::<Vec<_>>();
    if remaining_depth == 0 || eligible_callers.is_empty() {
        roots.insert(method_id.clone());
        return;
    }
    for caller in eligible_callers {
        collect_root_candidates(caller, remaining_depth - 1, callers, method_index, roots);
    }
}

/// Runs only from first-party/nested roots. Dependency methods can still be
/// traversed when reached through an explicit call from one of those roots.
pub fn analyze_method_flows_from_roots(
    methods: &[MethodFlow],
    roots: &[MethodId],
    config: &DataFlowConfig,
) -> DataFlowResult {
    let method_index: HashMap<MethodId, &MethodFlow> = methods
        .iter()
        .map(|method| (method.id.clone(), method))
        .collect();
    let mut analyzer = Analyzer::new(method_index, config);

    // Every method is a possible entry point. Parameter-only methods produce no
    // results here, but are analysed with real taints when reached by a call.
    for method_id in roots {
        let mut state = ExecutionState::default();
        analyzer.execute(method_id, Vec::new(), 0, &mut BTreeSet::new(), &mut state);
    }
    analyzer.result
}

#[derive(Clone, Debug)]
struct Taint {
    source_kind: SourceKind,
    source: FlowEvidence,
    transformations: Vec<FlowEvidence>,
    decoded: bool,
    secret_extracted: bool,
}

#[derive(Clone, Debug)]
struct WrittenValue {
    taint: Taint,
    evidence: FlowEvidence,
}

#[derive(Clone, Debug)]
struct VerifiedValue {
    source: FlowEvidence,
    evidence: Vec<FlowEvidence>,
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
    verified_values: Vec<VerifiedValue>,
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
        self.result.analyzed_method_ids.insert(method_id.clone());
        self.result.analyzed_methods = self.result.analyzed_methods.saturating_add(1);
        for (index, value) in arguments.into_iter().enumerate() {
            if index < method.parameter_count as usize {
                if let Some(slot) = method.parameter_slots.get(index) {
                    locals.insert(*slot, value);
                }
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
                        secret_extracted: false,
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
                            taint.secret_extracted |= matches!(kind, TransformKind::SecretExtract);
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
                    self.result.resolved_value_targets =
                        self.result.resolved_value_targets.saturating_add(1);
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
                Operation::WriteFile { evidence, .. } => {
                    self.result.unknown_file_targets =
                        self.result.unknown_file_targets.saturating_add(1);
                    self.result
                        .limitations
                        .push(FlowLimitation::UnknownFileTarget {
                            method: method_id.clone(),
                            offset: evidence.bytecode_offset,
                        });
                }
                Operation::ExecuteFile { target, evidence }
                    if !matches!(target, FileTarget::Unknown) =>
                {
                    self.result.resolved_value_targets =
                        self.result.resolved_value_targets.saturating_add(1);
                    if let Some(writes) = state.written_files.get(target).cloned() {
                        for write in writes {
                            if is_remote_payload_source(write.taint.source_kind) {
                                self.emit(
                                    ConfirmedChainKind::DownloadWriteExecute,
                                    &write.taint,
                                    vec![write.evidence.clone(), evidence.clone()],
                                );
                                if let Some(verification) = state
                                    .verified_values
                                    .iter()
                                    .find(|verified| verified.source == write.taint.source)
                                {
                                    let mut operations = verification.evidence.clone();
                                    operations.push(write.evidence);
                                    operations.push(evidence.clone());
                                    self.emit(
                                        ConfirmedChainKind::IntegrityVerifiedDownloadWriteExecute,
                                        &write.taint,
                                        operations,
                                    );
                                }
                            }
                        }
                    }
                }
                Operation::ExecuteFile { evidence, .. } => {
                    self.result.unknown_file_targets =
                        self.result.unknown_file_targets.saturating_add(1);
                    self.result
                        .limitations
                        .push(FlowLimitation::UnknownFileTarget {
                            method: method_id.clone(),
                            offset: evidence.bytecode_offset,
                        });
                }
                Operation::NetworkSend { body, evidence } => {
                    for taint in values(&locals, *body) {
                        if matches!(
                            taint.source_kind,
                            SourceKind::CredentialFile | SourceKind::ChatCredential
                        ) || taint.secret_extracted
                        {
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
                        } else if is_remote_payload_source(taint.source_kind) {
                            self.emit(
                                ConfirmedChainKind::RemoteDynamicLoad,
                                &taint,
                                vec![evidence.clone()],
                            );
                        }
                    }
                }
                Operation::IntegrityVerify { input, evidence } => {
                    for taint in values(&locals, *input) {
                        if is_remote_payload_source(taint.source_kind) {
                            state.verified_values.push(VerifiedValue {
                                source: taint.source,
                                evidence: evidence.clone(),
                            });
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
                    let Some(resolved_callee) = self.resolve_callee(callee) else {
                        self.result.unresolved_calls =
                            self.result.unresolved_calls.saturating_add(1);
                        self.result.limitations.push(FlowLimitation::MissingMethod {
                            caller: method_id.clone(),
                            callee: callee.clone(),
                        });
                        continue;
                    };
                    self.result.resolved_calls = self.result.resolved_calls.saturating_add(1);
                    let call_arguments = arguments
                        .iter()
                        .map(|local| values(&locals, *local))
                        .collect();
                    let call_result = self.execute(
                        &resolved_callee,
                        call_arguments,
                        depth + 1,
                        call_stack,
                        state,
                    );
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

    /// Resolves an interface/virtual call only when there is one unambiguous
    /// first-party implementation in the same archive layer. Falling back to a
    /// name match with multiple candidates would create false taint chains.
    fn resolve_callee(&self, callee: &MethodId) -> Option<MethodId> {
        if self.methods.contains_key(callee) {
            return Some(callee.clone());
        }
        let candidates = self
            .methods
            .iter()
            .filter(|(candidate, method)| {
                candidate.archive_id == callee.archive_id
                    && candidate.method_name == callee.method_name
                    && candidate.descriptor == callee.descriptor
                    && method.scope != CodeScope::BundledDependency
            })
            .map(|(candidate, _)| candidate.clone())
            .collect::<Vec<_>>();
        (candidates.len() == 1)
            .then(|| candidates.into_iter().next())
            .flatten()
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

fn is_remote_payload_source(kind: SourceKind) -> bool {
    matches!(kind, SourceKind::HttpResponse | SourceKind::SocketInput)
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
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
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
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
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
    fn resolves_a_unique_first_party_interface_implementation() {
        let root_id = method("run", Vec::new()).id;
        let interface_method = MethodId {
            class_name: "example/Transport".into(),
            method_name: "receive".into(),
            descriptor: "()[B".into(),
            ..root_id.clone()
        };
        let implementation_id = MethodId {
            class_name: "example/SocketTransport".into(),
            ..interface_method.clone()
        };
        let root = MethodFlow {
            id: root_id.clone(),
            parameter_count: 0,
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
            operations: vec![
                Operation::Call {
                    callee: interface_method,
                    arguments: Vec::new(),
                    return_to: Some(0),
                    evidence: evidence(&root_id, 1, "transport.receive"),
                },
                Operation::WriteFile {
                    input: 0,
                    destination: FileTarget::Known("/tmp/payload.jar".into()),
                    evidence: evidence(&root_id, 2, "file_write"),
                },
                Operation::ExecuteFile {
                    target: FileTarget::Known("/tmp/payload.jar".into()),
                    evidence: evidence(&root_id, 3, "java_launch"),
                },
            ],
        };
        let implementation = MethodFlow {
            id: implementation_id.clone(),
            parameter_count: 0,
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
            operations: vec![
                Operation::Source {
                    output: 0,
                    kind: SourceKind::SocketInput,
                    evidence: evidence(&implementation_id, 4, "socket_receive"),
                },
                Operation::Return { value: Some(0) },
            ],
        };

        let result = analyze_method_flows(&[root, implementation], &DataFlowConfig::default());

        assert_eq!(result.resolved_calls, 1);
        assert_eq!(result.confirmed_chains.len(), 1);
        assert_eq!(
            result.confirmed_chains[0].kind,
            ConfirmedChainKind::DownloadWriteExecute
        );
    }

    #[test]
    fn demand_driven_roots_skip_configuration_only_methods() {
        let config_id = method("saveConfig", Vec::new()).id;
        let sender_id = MethodId {
            method_name: "send".into(),
            ..config_id.clone()
        };
        let config = MethodFlow {
            id: config_id.clone(),
            parameter_count: 0,
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
            operations: vec![Operation::WriteFile {
                input: 0,
                destination: FileTarget::Known("config.json".into()),
                evidence: evidence(&config_id, 1, "config_write"),
            }],
        };
        let sender = MethodFlow {
            id: sender_id.clone(),
            parameter_count: 1,
            parameter_slots: vec![0],
            scope: CodeScope::FirstParty,
            operations: vec![Operation::NetworkSend {
                body: 0,
                evidence: evidence(&sender_id, 2, "network_send"),
            }],
        };

        let roots = dangerous_flow_roots(&[config, sender], 2);
        assert_eq!(roots, vec![sender_id]);
    }

    #[test]
    fn demand_driven_roots_preserve_source_to_sink_chains() {
        let root_id = method("run", Vec::new()).id;
        let source_id = MethodId {
            method_name: "readCredentials".into(),
            descriptor: "()[B".into(),
            ..root_id.clone()
        };
        let sink_id = MethodId {
            method_name: "send".into(),
            descriptor: "([B)V".into(),
            ..root_id.clone()
        };
        let root = MethodFlow {
            id: root_id.clone(),
            parameter_count: 0,
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
            operations: vec![
                Operation::Call {
                    callee: source_id.clone(),
                    arguments: Vec::new(),
                    return_to: Some(0),
                    evidence: evidence(&root_id, 1, "read_credentials"),
                },
                Operation::Call {
                    callee: sink_id.clone(),
                    arguments: vec![0],
                    return_to: None,
                    evidence: evidence(&root_id, 2, "send"),
                },
            ],
        };
        let source = MethodFlow {
            id: source_id.clone(),
            parameter_count: 0,
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
            operations: vec![
                Operation::Source {
                    output: 0,
                    kind: SourceKind::CredentialFile,
                    evidence: evidence(&source_id, 3, "credential_read"),
                },
                Operation::Return { value: Some(0) },
            ],
        };
        let sink = MethodFlow {
            id: sink_id.clone(),
            parameter_count: 1,
            parameter_slots: vec![0],
            scope: CodeScope::FirstParty,
            operations: vec![Operation::NetworkSend {
                body: 0,
                evidence: evidence(&sink_id, 4, "network_send"),
            }],
        };
        let flows = vec![root.clone(), source, sink];
        let roots = dangerous_flow_roots(&flows, 2);

        assert_eq!(roots, vec![root_id]);
        assert!(
            analyze_method_flows_from_roots(&flows, &roots, &DataFlowConfig::default())
                .confirmed_chains
                .iter()
                .any(|chain| chain.kind == ConfirmedChainKind::CredentialExfiltration)
        );
    }

    #[test]
    fn records_an_integrity_verified_chain_only_after_the_guard() {
        let id = method("run", Vec::new()).id;
        let flow = MethodFlow {
            id: id.clone(),
            parameter_count: 0,
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
            operations: vec![
                Operation::Source {
                    output: 0,
                    kind: SourceKind::HttpResponse,
                    evidence: evidence(&id, 1, "http_response"),
                },
                Operation::IntegrityVerify {
                    input: 0,
                    evidence: vec![
                        evidence(&id, 2, "java/security/MessageDigest.digest"),
                        evidence(&id, 3, "java/util/Arrays.equals"),
                        evidence(&id, 4, "integrity_success_branch"),
                    ],
                },
                Operation::WriteFile {
                    input: 0,
                    destination: FileTarget::Known("/tmp/update.jar".into()),
                    evidence: evidence(&id, 5, "file_write"),
                },
                Operation::ExecuteFile {
                    target: FileTarget::Known("/tmp/update.jar".into()),
                    evidence: evidence(&id, 6, "java_launch"),
                },
            ],
        };

        let result = analyze_method_flows(&[flow], &DataFlowConfig::default());
        assert!(result.confirmed_chains.iter().any(|chain| {
            chain.kind == ConfirmedChainKind::IntegrityVerifiedDownloadWriteExecute
        }));
    }

    #[test]
    fn rejects_http_and_execution_when_the_downloaded_value_was_not_written() {
        let id = method("run", Vec::new()).id;
        let flow = MethodFlow {
            id: id.clone(),
            parameter_count: 0,
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
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
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
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
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
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
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
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
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
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
            parameter_slots: vec![0],
            scope: CodeScope::FirstParty,
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
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
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
    fn confirms_authentication_chat_data_sent_to_network() {
        let id = method("onChatMessage", Vec::new()).id;
        let flow = MethodFlow {
            id: id.clone(),
            parameter_count: 0,
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
            operations: vec![
                Operation::Source {
                    output: 0,
                    kind: SourceKind::ChatCredential,
                    evidence: evidence(&id, 1, "ClientChatEvent.getMessage"),
                },
                Operation::NetworkSend {
                    body: 0,
                    evidence: evidence(&id, 2, "java/io/OutputStream.write"),
                },
            ],
        };

        assert!(analyze_method_flows(&[flow], &DataFlowConfig::default())
            .confirmed_chains
            .iter()
            .any(|chain| chain.kind == ConfirmedChainKind::CredentialExfiltration));
    }

    #[test]
    fn requires_a_decoder_before_reporting_decoded_dynamic_load() {
        let id = method("run", Vec::new()).id;
        let flow = MethodFlow {
            id: id.clone(),
            parameter_count: 0,
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
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

    #[test]
    fn propagates_return_value_through_an_instance_method_slot_layout() {
        let caller_id = method("run", Vec::new()).id;
        let helper_id = MethodId {
            method_name: "identity".into(),
            descriptor: "([B)[B".into(),
            ..caller_id.clone()
        };
        let caller = MethodFlow {
            id: caller_id.clone(),
            parameter_count: 0,
            parameter_slots: Vec::new(),
            scope: CodeScope::FirstParty,
            operations: vec![
                Operation::Source {
                    output: 0,
                    kind: SourceKind::HttpResponse,
                    evidence: evidence(&caller_id, 1, "http_response"),
                },
                Operation::Call {
                    callee: helper_id.clone(),
                    arguments: vec![0],
                    return_to: Some(1),
                    evidence: evidence(&caller_id, 2, "call"),
                },
                Operation::WriteFile {
                    input: 1,
                    destination: FileTarget::Known("Temp/update.jar".into()),
                    evidence: evidence(&caller_id, 3, "file_write"),
                },
                Operation::ExecuteFile {
                    target: FileTarget::Known("Temp/update.jar".into()),
                    evidence: evidence(&caller_id, 4, "exec"),
                },
            ],
        };
        let helper = MethodFlow {
            id: helper_id,
            parameter_count: 1,
            parameter_slots: vec![1], // slot 0 is `this`
            scope: CodeScope::FirstParty,
            operations: vec![Operation::Return { value: Some(1) }],
        };

        let result = analyze_method_flows(&[caller, helper], &DataFlowConfig::default());
        assert!(result
            .confirmed_chains
            .iter()
            .any(|chain| chain.kind == ConfirmedChainKind::DownloadWriteExecute));
        assert_eq!(result.resolved_calls, 1);
    }

    #[test]
    fn excludes_unreached_dependency_roots_and_file_reads_from_credential_exfiltration() {
        let id = method("dependency", Vec::new()).id;
        let dependency = MethodFlow {
            id: id.clone(),
            parameter_count: 0,
            parameter_slots: Vec::new(),
            scope: CodeScope::BundledDependency,
            operations: vec![
                Operation::Source {
                    output: 0,
                    kind: SourceKind::FileRead,
                    evidence: evidence(&id, 1, "read_config"),
                },
                Operation::NetworkSend {
                    body: 0,
                    evidence: evidence(&id, 2, "send"),
                },
            ],
        };
        let result = analyze_method_flows(&[dependency], &DataFlowConfig::default());
        assert!(result.confirmed_chains.is_empty());
    }
}
