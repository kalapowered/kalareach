//! A complete example package.
//!
//! This is the smallest package that does something useful: it recognises an application, it
//! contributes a document, and it registers one action a control invokes. It ships no Wasm,
//! because a declarative package needs none.
//!
//! The example is here rather than only in a fixture directory so it stays correct. The fixture
//! files under `fixtures/plugins/` are written from these values, the tests validate the result,
//! and a package author reading the SDK sees the same package the tests use.

use kr_protocol::scalars::Nullable;

use crate::capability::{CapabilityRequest, PluginCapability};
use crate::digest::{ByteSize, PayloadDigest};
use crate::effect::{
    ActionDeclaration, ActionImplementation, EffectClass, ParameterDeclaration, ParameterKind,
    ParameterSchema,
};
use crate::ids::{ActionName, ControlId, NodeId, ParameterName, PluginName, PublisherId};
use crate::matching::{
    Architecture, DistributionMatch, ExecutableMatch, MatchConfidence, MatchRule, OperatingSystem,
    PlatformSupport,
};
use crate::package::PRESENTATION_FILE;
use crate::paths::PackagePath;
use crate::plugin::{PayloadRef, PayloadRole, PluginManifest, SourcePin};
use crate::predicate::{BindingState, Predicate, PresentationFlag};
use crate::presentation::{
    Control, DocumentNode, NodeBody, NodeRevision, PresentationManifest, ProgressState,
    SemanticPriority, StandardIcon, VoiceProjection,
};
use crate::text::{AccessibleDescription, CompactDescription, Label, Summary};
use crate::version::{PackageVersion, VersionRange};

/// The example publisher.
pub const PUBLISHER: &str = "kalareach";

/// The example plugin name.
pub const PLUGIN_NAME: &str = "example-declarative";

fn label(text: &str) -> Label {
    Label::new(text).expect("a literal label is within bounds")
}

fn summary(text: &str) -> Summary {
    Summary::new(text).expect("a literal summary is within bounds")
}

/// Returns the example presentation document.
///
/// # Panics
///
/// Panics when a literal in this function is not a valid identifier or label, which is a
/// compile-time mistake rather than a runtime condition.
#[must_use]
pub fn example_presentation() -> PresentationManifest {
    let refresh = Control {
        id: ControlId::new("refresh").expect("a literal control id"),
        revision: NodeRevision::new(1),
        label: label("Refresh status"),
        icon: StandardIcon::Retry,
        accessible_description: AccessibleDescription::new(
            "Read the current status of the bound application again",
        )
        .expect("a literal description"),
        action_id: ActionName::new("status.refresh").expect("a literal action name"),
        parameters: ParameterSchema {
            parameters: vec![ParameterDeclaration {
                name: ParameterName::new("detail").expect("a literal parameter name"),
                kind: ParameterKind::Choice {
                    choices: vec![
                        crate::effect::ParameterChoice {
                            id: ParameterName::new("summary").expect("a literal choice id"),
                            label: label("Summary"),
                        },
                        crate::effect::ParameterChoice {
                            id: ParameterName::new("full").expect("a literal choice id"),
                            label: label("Everything"),
                        },
                    ],
                },
                label: label("Detail"),
                required: false,
            }],
        },
        priority: SemanticPriority::Secondary,
        visible_when: Predicate::Not {
            term: Box::new(Predicate::Binding {
                state: BindingState::Disabled,
            }),
        },
        enabled_when: Predicate::All {
            terms: vec![
                Predicate::Binding {
                    state: BindingState::Bound,
                },
                Predicate::Not {
                    term: Box::new(Predicate::Flag {
                        flag: PresentationFlag::TransferInProgress,
                    }),
                },
            ],
        },
        disabled_reason: Nullable(None),
    };

    PresentationManifest {
        manifest_version: 1,
        base_revision: NodeRevision::new(1),
        nodes: vec![
            DocumentNode {
                id: NodeId::new("intro").expect("a literal node id"),
                revision: NodeRevision::new(1),
                body: NodeBody::Markdown {
                    source:
                        "The example package recognises an application and presents its status."
                            .to_owned(),
                },
            },
            DocumentNode {
                id: NodeId::new("status").expect("a literal node id"),
                revision: NodeRevision::new(1),
                body: NodeBody::Progress {
                    label: label("Waiting for the application"),
                    state: ProgressState::Indeterminate {},
                },
            },
            DocumentNode {
                id: NodeId::new("controls").expect("a literal node id"),
                revision: NodeRevision::new(1),
                body: NodeBody::ActionGroup {
                    label: label("Status"),
                    controls: vec![refresh],
                },
            },
        ],
        voice: VoiceProjection {
            status_nodes: vec![NodeId::new("status").expect("a literal node id")],
            choice_controls: vec![ControlId::new("refresh").expect("a literal control id")],
            detail_nodes: vec![NodeId::new("intro").expect("a literal node id")],
        },
    }
}

/// Returns the example manifest, with the presentation payload's digest and size filled in.
///
/// # Panics
///
/// Panics when a literal in this function is not a valid identifier or label.
#[must_use]
pub fn example_manifest_for(presentation_bytes: &[u8]) -> PluginManifest {
    PluginManifest {
        manifest_version: PluginManifest::CURRENT_VERSION,
        publisher_id: PublisherId::new(PUBLISHER).expect("a literal publisher id"),
        plugin_name: PluginName::new(PLUGIN_NAME).expect("a literal plugin name"),
        version: PackageVersion::parse("0.1.0").expect("a literal version"),
        display_name: label("Example declarative package"),
        description: CompactDescription::new(
            "Recognises the example agent and presents its status with one declarative control.",
        )
        .expect("a literal description"),
        sdk_range: VersionRange::parse(">=0.1.0, <0.2.0").expect("a literal range"),
        wit_range: VersionRange::parse(">=0.1.0, <0.2.0").expect("a literal range"),
        source: SourcePin {
            repository: "https://github.com/kalapowered/kalareach-plugins".to_owned(),
            revision: "refs/tags/example-declarative-0.1.0".to_owned(),
        },
        match_rules: vec![MatchRule {
            id: PluginName::new("example-agent").expect("a literal rule id"),
            executable: ExecutableMatch {
                file_stem: "example-agent".to_owned(),
                path_suffix: Vec::new(),
                version_range: Nullable(None),
            },
            distribution: Nullable(Some(DistributionMatch::Npm {
                package: "@kalareach/example-agent".to_owned(),
            })),
            confidence: MatchConfidence::Exact,
        }],
        platforms: vec![
            PlatformSupport {
                os: OperatingSystem::Linux,
                architectures: vec![Architecture::X86_64, Architecture::Aarch64],
            },
            PlatformSupport {
                os: OperatingSystem::MacOs,
                architectures: vec![Architecture::Aarch64],
            },
            PlatformSupport {
                os: OperatingSystem::Windows,
                architectures: vec![Architecture::X86_64],
            },
        ],
        payloads: vec![PayloadRef {
            role: PayloadRole::Presentation,
            path: PackagePath::new(PRESENTATION_FILE).expect("a literal path"),
            digest: PayloadDigest::of(presentation_bytes),
            size_bytes: ByteSize::new(presentation_bytes.len() as u64),
        }],
        capabilities: vec![
            CapabilityRequest {
                capability: PluginCapability::MetadataMatch,
                reason: summary("Recognise the example agent from its executable name"),
            },
            CapabilityRequest {
                capability: PluginCapability::DeclarativePresentation,
                reason: summary("Present the application's status and one control"),
            },
            CapabilityRequest {
                capability: PluginCapability::BrokerSemanticEvents,
                reason: summary("Update the status from events the actor may already see"),
            },
        ],
        actions: vec![ActionDeclaration {
            id: ActionName::new("status.refresh").expect("a literal action name"),
            label: label("Refresh status"),
            effect: EffectClass::Observe,
            implementation: ActionImplementation::Presentation {},
            parameters: ParameterSchema {
                parameters: vec![ParameterDeclaration {
                    name: ParameterName::new("detail").expect("a literal parameter name"),
                    kind: ParameterKind::Choice {
                        choices: vec![
                            crate::effect::ParameterChoice {
                                id: ParameterName::new("summary").expect("a literal choice id"),
                                label: label("Summary"),
                            },
                            crate::effect::ParameterChoice {
                                id: ParameterName::new("full").expect("a literal choice id"),
                                label: label("Everything"),
                            },
                        ],
                    },
                    label: label("Detail"),
                    required: false,
                }],
            },
            description: summary("Read the bound application's status again and redraw it"),
            confirmation_required: false,
        }],
        attachments: Nullable(None),
        native_bridge: Nullable(None),
    }
}

/// Returns the example manifest against the canonical rendering of the example presentation.
///
/// # Panics
///
/// Panics when the example presentation cannot be serialised.
#[must_use]
pub fn example_manifest() -> PluginManifest {
    example_manifest_for(example_presentation_json().as_bytes())
}

/// Returns the canonical rendering of the example presentation document.
///
/// # Panics
///
/// Panics when the example presentation cannot be serialised.
#[must_use]
pub fn example_presentation_json() -> String {
    render(&example_presentation())
}

/// Returns the canonical rendering of the example manifest.
///
/// # Panics
///
/// Panics when the example manifest cannot be serialised.
#[must_use]
pub fn example_manifest_json() -> String {
    render(&example_manifest())
}

fn render<T: serde::Serialize>(value: &T) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("the example is serialisable");
    text.push('\n');
    text
}

/// The example connector plugin name.
pub const CONNECTOR_PLUGIN_NAME: &str = "example-connector";

/// Returns the example connector's presentation document.
///
/// # Panics
///
/// Panics when a literal in this function is not a valid identifier or label.
#[must_use]
pub fn example_connector_presentation() -> PresentationManifest {
    let send = Control {
        id: ControlId::new("send").expect("a literal control id"),
        revision: NodeRevision::new(1),
        label: label("Send prompt"),
        icon: StandardIcon::Send,
        accessible_description: AccessibleDescription::new(
            "Send the prompt to the bound application",
        )
        .expect("a literal description"),
        action_id: ActionName::new("prompt.send").expect("a literal action name"),
        parameters: prompt_parameters(),
        priority: SemanticPriority::Primary,
        visible_when: Predicate::Grant {
            right: crate::effect::ActionRight::AgentPrompt,
        },
        enabled_when: Predicate::All {
            terms: vec![
                Predicate::Binding {
                    state: BindingState::Bound,
                },
                Predicate::Not {
                    term: Box::new(Predicate::Binding {
                        state: BindingState::UpstreamBusy,
                    }),
                },
            ],
        },
        disabled_reason: Nullable(Some(
            crate::text::DisabledReason::new("The application is working on the last prompt")
                .expect("a literal reason"),
        )),
    };

    // One control per decision. Each narrows the answer's decision to its own choice, and each is
    // shown only to an actor who may answer while an approval is waiting. Which approval a press
    // answers is not the document's to say: the invocation names the pending resource.
    let answer = |id: &str, choice: &str, text: &str, icon, priority| Control {
        id: ControlId::new(id).expect("a literal control id"),
        revision: NodeRevision::new(1),
        label: label(text),
        icon,
        accessible_description: AccessibleDescription::new(format!(
            "{text} the tool call the application is waiting on"
        ))
        .expect("a literal description"),
        action_id: ActionName::new("approval.answer").expect("a literal action name"),
        parameters: decision_parameters(&[(choice, text)]),
        priority,
        visible_when: Predicate::All {
            terms: vec![
                Predicate::Grant {
                    right: crate::effect::ActionRight::AgentApprovalRespond,
                },
                Predicate::Flag {
                    flag: PresentationFlag::PendingApproval,
                },
            ],
        },
        enabled_when: Predicate::Not {
            term: Box::new(Predicate::Binding {
                state: BindingState::NativeOnlyVolatile,
            }),
        },
        disabled_reason: Nullable(Some(
            crate::text::DisabledReason::new("Answers wait until this host can record them again")
                .expect("a literal reason"),
        )),
    };

    PresentationManifest {
        manifest_version: 1,
        base_revision: NodeRevision::new(1),
        nodes: vec![
            DocumentNode {
                id: NodeId::new("compose").expect("a literal node id"),
                revision: NodeRevision::new(1),
                body: NodeBody::Form {
                    title: label("Prompt"),
                    fields: prompt_parameters(),
                    submit: send,
                },
            },
            DocumentNode {
                id: NodeId::new("activity").expect("a literal node id"),
                revision: NodeRevision::new(1),
                body: NodeBody::Progress {
                    label: label("Working"),
                    state: ProgressState::Indeterminate {},
                },
            },
            DocumentNode {
                id: NodeId::new("approval").expect("a literal node id"),
                revision: NodeRevision::new(1),
                body: NodeBody::ActionGroup {
                    label: label("Tool approval"),
                    controls: vec![
                        answer(
                            "allow",
                            "allow",
                            "Allow",
                            StandardIcon::Check,
                            SemanticPriority::Primary,
                        ),
                        answer(
                            "deny",
                            "deny",
                            "Deny",
                            StandardIcon::Cross,
                            SemanticPriority::Secondary,
                        ),
                    ],
                },
            },
        ],
        voice: VoiceProjection {
            status_nodes: vec![NodeId::new("activity").expect("a literal node id")],
            choice_controls: vec![
                ControlId::new("send").expect("a literal control id"),
                ControlId::new("allow").expect("a literal control id"),
                ControlId::new("deny").expect("a literal control id"),
            ],
            detail_nodes: Vec::new(),
        },
    }
}

/// The parameters of the example's answer: one required decision, from the choices given.
fn decision_parameters(choices: &[(&str, &str)]) -> ParameterSchema {
    ParameterSchema {
        parameters: vec![ParameterDeclaration {
            name: ParameterName::new("decision").expect("a literal parameter name"),
            kind: ParameterKind::Choice {
                choices: choices
                    .iter()
                    .map(|(id, text)| crate::effect::ParameterChoice {
                        id: ParameterName::new(*id).expect("a literal choice id"),
                        label: label(text),
                    })
                    .collect(),
            },
            label: label("Decision"),
            required: true,
        }],
    }
}

fn prompt_parameters() -> ParameterSchema {
    ParameterSchema {
        parameters: vec![
            ParameterDeclaration {
                name: ParameterName::new("text").expect("a literal parameter name"),
                kind: ParameterKind::Text {
                    max_length: crate::scalars::Count::new(8_000),
                    multiline: true,
                },
                label: label("Prompt"),
                required: true,
            },
            ParameterDeclaration {
                name: ParameterName::new("queue").expect("a literal parameter name"),
                kind: ParameterKind::Boolean {},
                label: label("Queue behind the current turn"),
                required: false,
            },
        ],
    }
}

fn member(name: &str) -> crate::connector::FieldSegment {
    crate::connector::FieldSegment::Member {
        name: name.to_owned(),
    }
}

/// Returns the example connector's native-proxy table.
///
/// # Panics
///
/// Panics when a literal in this function is not a valid identifier.
#[must_use]
pub fn example_connector_table() -> crate::connector::ConnectorManifest {
    use crate::connector::{
        BrokerTransport, ConnectorManifest, DecisionDestination, DecisionValue, FieldPath, Framing,
        MethodClass, MethodClassification, ProtocolPin, ResponseCorrelation, Route, RouteDirection,
    };
    use crate::ids::MethodName;

    let path = |name: &str| FieldPath {
        segments: vec![member(name)],
    };

    ConnectorManifest {
        manifest_version: 1,
        plugin_id: crate::ids::plugin_id(
            &PublisherId::new(PUBLISHER).expect("a literal publisher id"),
            &PluginName::new(CONNECTOR_PLUGIN_NAME).expect("a literal plugin name"),
        ),
        protocol: ProtocolPin {
            name: "example-agent-rpc".to_owned(),
            qualified_range: VersionRange::parse(">=1.0.0, <2.0.0").expect("a literal range"),
            tested_version: PackageVersion::parse("1.2.0").expect("a literal version"),
        },
        transport: BrokerTransport::Stdio,
        framing: Framing::LineDelimitedJson {
            max_message_bytes: crate::scalars::U64::new(1_048_576),
        },
        request_id_path: path("id"),
        method_path: path("method"),
        response_correlation: ResponseCorrelation::MatchingId {
            id_path: path("id"),
        },
        routes: vec![
            Route {
                method: MethodName::new("turn.start").expect("a literal method name"),
                wire_name: "turn/start".to_owned(),
                direction: RouteDirection::HostToUpstream,
            },
            Route {
                method: MethodName::new("turn.cancel").expect("a literal method name"),
                wire_name: "turn/cancel".to_owned(),
                direction: RouteDirection::HostToUpstream,
            },
            Route {
                method: MethodName::new("status.read").expect("a literal method name"),
                wire_name: "status/read".to_owned(),
                direction: RouteDirection::HostToUpstream,
            },
            Route {
                method: MethodName::new("credential.read").expect("a literal method name"),
                wire_name: "credential/read".to_owned(),
                direction: RouteDirection::UpstreamToHost,
            },
            Route {
                method: MethodName::new("approval.request").expect("a literal method name"),
                wire_name: "approval/request".to_owned(),
                direction: RouteDirection::UpstreamToHost,
            },
            Route {
                method: MethodName::new("approval.answer").expect("a literal method name"),
                wire_name: "approval/answer".to_owned(),
                direction: RouteDirection::HostToUpstream,
            },
        ],
        methods: vec![
            MethodClassification {
                method: MethodName::new("turn.start").expect("a literal method name"),
                class: MethodClass::Mutation,
                evidence: summary("Starts a turn, which writes to the workspace"),
            },
            MethodClassification {
                method: MethodName::new("turn.cancel").expect("a literal method name"),
                class: MethodClass::Mutation,
                evidence: summary("Ends the current turn"),
            },
            MethodClassification {
                method: MethodName::new("status.read").expect("a literal method name"),
                class: MethodClass::Observation,
                evidence: summary("Returns the current turn state and nothing else"),
            },
            MethodClassification {
                method: MethodName::new("credential.read").expect("a literal method name"),
                class: MethodClass::Credential,
                evidence: summary("Carries the upstream token; the broker keeps it"),
            },
            MethodClassification {
                method: MethodName::new("approval.request").expect("a literal method name"),
                class: MethodClass::Mutation,
                evidence: summary(
                    "Asks for a decision on a tool call the agent is waiting on; answering it runs or refuses the call",
                ),
            },
            MethodClassification {
                method: MethodName::new("approval.answer").expect("a literal method name"),
                class: MethodClass::Mutation,
                evidence: summary(
                    "Answers the request whose identifier it repeats, which runs or refuses the tool call",
                ),
            },
        ],
        decision_destination: Nullable(Some(DecisionDestination {
            answers: MethodName::new("approval.request").expect("a literal method name"),
            method: MethodName::new("approval.answer").expect("a literal method name"),
            request_id_path: path("id"),
            decision_path: FieldPath {
                segments: vec![member("params"), member("decision")],
            },
            decisions: vec![
                DecisionValue {
                    decision: ParameterName::new("allow").expect("a literal decision"),
                    value: "approved".to_owned(),
                },
                DecisionValue {
                    decision: ParameterName::new("deny").expect("a literal decision"),
                    value: "denied".to_owned(),
                },
            ],
        })),
        volatile_forwarding: false,
        qualification_note: Nullable(Some(summary(
            "Qualified against example-agent 1.2.0 with the published protocol reference",
        ))),
    }
}

/// Returns the example connector's manifest for the given payload bytes.
///
/// # Panics
///
/// Panics when a literal in this function is not a valid identifier or label.
#[must_use]
pub fn example_connector_manifest(
    presentation_bytes: &[u8],
    connector_bytes: &[u8],
) -> PluginManifest {
    use crate::connector::FieldPath;
    use crate::effect::{ActionImplementation, ParameterBinding};
    use crate::ids::MethodName;

    PluginManifest {
        manifest_version: PluginManifest::CURRENT_VERSION,
        publisher_id: PublisherId::new(PUBLISHER).expect("a literal publisher id"),
        plugin_name: PluginName::new(CONNECTOR_PLUGIN_NAME).expect("a literal plugin name"),
        version: PackageVersion::parse("0.1.0").expect("a literal version"),
        display_name: label("Example connector package"),
        description: CompactDescription::new(
            "Recognises the example agent, reads its protocol through a declarative table, sends prompts and answers its tool approvals.",
        )
        .expect("a literal description"),
        sdk_range: VersionRange::parse(">=0.1.1, <0.2.0").expect("a literal range"),
        wit_range: VersionRange::parse(">=0.1.0, <0.2.0").expect("a literal range"),
        source: SourcePin {
            repository: "https://github.com/kalapowered/kalareach-plugins".to_owned(),
            revision: "refs/tags/example-connector-0.1.0".to_owned(),
        },
        match_rules: vec![MatchRule {
            id: PluginName::new("example-agent").expect("a literal rule id"),
            executable: ExecutableMatch {
                file_stem: "example-agent".to_owned(),
                path_suffix: Vec::new(),
                version_range: Nullable(Some(
                    VersionRange::parse(">=1.0.0, <2.0.0").expect("a literal range"),
                )),
            },
            distribution: Nullable(Some(DistributionMatch::Npm {
                package: "@kalareach/example-agent".to_owned(),
            })),
            confidence: MatchConfidence::Exact,
        }],
        platforms: vec![
            PlatformSupport {
                os: OperatingSystem::Linux,
                architectures: vec![Architecture::X86_64, Architecture::Aarch64],
            },
            PlatformSupport {
                os: OperatingSystem::MacOs,
                architectures: vec![Architecture::Aarch64],
            },
        ],
        payloads: vec![
            PayloadRef {
                role: PayloadRole::Connector,
                path: PackagePath::new(crate::package::CONNECTOR_FILE).expect("a literal path"),
                digest: PayloadDigest::of(connector_bytes),
                size_bytes: ByteSize::new(connector_bytes.len() as u64),
            },
            PayloadRef {
                role: PayloadRole::Presentation,
                path: PackagePath::new(PRESENTATION_FILE).expect("a literal path"),
                digest: PayloadDigest::of(presentation_bytes),
                size_bytes: ByteSize::new(presentation_bytes.len() as u64),
            },
        ],
        capabilities: vec![
            CapabilityRequest {
                capability: PluginCapability::MetadataMatch,
                reason: summary("Recognise the example agent from its executable and its package"),
            },
            CapabilityRequest {
                capability: PluginCapability::DeclarativePresentation,
                reason: summary("Present the prompt form and the current activity"),
            },
            CapabilityRequest {
                capability: PluginCapability::BrokerSemanticEvents,
                reason: summary("Read turn state from the application's own protocol"),
            },
            CapabilityRequest {
                capability: PluginCapability::UpstreamAction,
                reason: summary("Send a prompt the person wrote to the bound application"),
            },
            CapabilityRequest {
                capability: PluginCapability::ApprovalDecode,
                reason: summary(
                    "Read which tool call an approval request is about and the decisions it offers",
                ),
            },
            CapabilityRequest {
                capability: PluginCapability::ApprovalRespond,
                reason: summary(
                    "Answer a tool approval the application is waiting on with the decision a person made",
                ),
            },
        ],
        actions: vec![
            ActionDeclaration {
            id: ActionName::new("prompt.send").expect("a literal action name"),
            label: label("Send prompt"),
            effect: EffectClass::UpstreamPrompt,
            implementation: ActionImplementation::UpstreamMethod {
                method: MethodName::new("turn.start").expect("a literal method name"),
                bindings: vec![
                    ParameterBinding {
                        parameter: ParameterName::new("text").expect("a literal parameter name"),
                        field: FieldPath {
                            segments: vec![member("params"), member("prompt")],
                        },
                    },
                    ParameterBinding {
                        parameter: ParameterName::new("queue").expect("a literal parameter name"),
                        field: FieldPath {
                            segments: vec![member("params"), member("queue")],
                        },
                    },
                ],
            },
            parameters: prompt_parameters(),
            description: summary("Start a turn with the prompt the person wrote"),
            confirmation_required: false,
        },
        ActionDeclaration {
            id: ActionName::new("approval.answer").expect("a literal action name"),
            label: label("Answer"),
            effect: EffectClass::ApprovalRespond,
            implementation: ActionImplementation::DecisionDestination {
                decision: ParameterName::new("decision").expect("a literal parameter name"),
            },
            parameters: decision_parameters(&[("allow", "Allow"), ("deny", "Deny")]),
            description: summary("Answer the tool approval the application is waiting on"),
            confirmation_required: false,
        },
        ],
        attachments: Nullable(None),
        native_bridge: Nullable(None),
    }
}

/// Returns the canonical rendering of the example connector's presentation document.
///
/// # Panics
///
/// Panics when the document cannot be serialised.
#[must_use]
pub fn example_connector_presentation_json() -> String {
    render(&example_connector_presentation())
}

/// Returns the canonical rendering of the example connector's native-proxy table.
///
/// # Panics
///
/// Panics when the table cannot be serialised.
#[must_use]
pub fn example_connector_table_json() -> String {
    render(&example_connector_table())
}

/// Returns the canonical rendering of the example connector's manifest.
///
/// # Panics
///
/// Panics when the manifest cannot be serialised.
#[must_use]
pub fn example_connector_manifest_json() -> String {
    render(&example_connector_manifest(
        example_connector_presentation_json().as_bytes(),
        example_connector_table_json().as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_example_stays_inside_the_default_repository_ceiling() {
        let manifest = example_manifest();
        for request in &manifest.capabilities {
            assert!(
                request.capability.within_default_ceiling(),
                "{} needs a grant the example should not require",
                request.capability
            );
        }
        assert!(!manifest.has_component());
    }

    #[test]
    fn every_control_names_a_registered_action() {
        let manifest = example_manifest();
        let presentation = example_presentation();
        let registered: Vec<_> = manifest.actions.iter().map(|a| a.id.clone()).collect();
        for node in &presentation.nodes {
            for action_id in node.body.action_ids() {
                assert!(
                    registered.contains(&action_id),
                    "{action_id} is not registered"
                );
            }
        }
    }

    #[test]
    fn the_rendering_is_stable() {
        assert_eq!(example_manifest_json(), example_manifest_json());
        assert_eq!(example_presentation_json(), example_presentation_json());
    }
}
