//! The method groups: agent state, the five agent mutations, the plugin action call and the
//! adapter checkpoint.

use kr_protocol::actor::ActorIngress;
use kr_protocol::agent::{
    AgentApprovalRespondParams, AgentCancelParams, AgentCapabilitiesParams, AgentCommandsParams,
    AgentMutationTarget, AgentPromptParams, AgentSnapshotParams, AgentSteerParams,
    PluginActionInvokeParams, PromptText,
};
use kr_protocol::authority::{AuthorityDecision, EffectClass};
use kr_protocol::broker::{
    ActionName, ActionProvenance, BrokerGrant, BrokerGrants, DecodedProjection, DecodingTrust,
    InstanceCapabilityIdentity, InstanceCapabilityRecord, InstanceCapabilityState,
    InstanceEvidenceSource, InstanceInvalidation, IntegrationMode, OfferedDecision,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::gateway::{
    DeclarativeEntry, DeclarativeTable, NativeFraming, NativeMethodClass, PendingState,
    RichMethodTable, RichOperation,
};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ActorId, AgentBindingRevision, AgentTurnId, ApplicationInstanceId, BrokerBindingId,
    CapabilityId, CapabilityRevision, GatewayConnectionId, GrantId, MethodTableVersion, PluginId,
    PublisherId, SessionId, StreamCursor, UpstreamMethod, UpstreamRequestId,
};
use kr_protocol::method::{Method, MethodVersion, decide};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Bytes, Digest256, Nullable, TimestampMs, U64, Uuid};
use kr_worker::broker::{
    Broker, BrokerError, BrokerTransport, Caller, Credential, GrantLowerBound, ManagedProcess,
    RegisteredAction, TransportHandle, UpstreamBody, UpstreamDispatch, UpstreamOutcome,
    UpstreamRequest, command, subject,
};

const CREDENTIAL: [u8; 32] = [9; 32];

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
}

fn binding() -> BrokerBindingId {
    BrokerBindingId::new(Uuid::from_bytes([9; 16]))
}

fn caller() -> Caller {
    Caller {
        actor_id: ActorId::new("device-1").expect("valid"),
        grant_id: Some(GrantId::new(Uuid::from_bytes([7; 16]))),
    }
}

fn method(name: &str) -> UpstreamMethod {
    UpstreamMethod::new(name).expect("valid")
}

fn capability(name: &str) -> CapabilityId {
    CapabilityId::new(name).expect("valid")
}

fn process_identity() -> ProcessStartIdentity {
    ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900)
}

fn managed() -> ManagedProcess {
    ManagedProcess::new(
        instance(),
        process_identity(),
        TransportHandle {
            transport: BrokerTransport::PrivateSocket,
            application_instance_id: instance(),
            executable_digest: Digest256::from_bytes([3; 32]),
            process: process_identity(),
        },
        Credential::from_bytes(CREDENTIAL),
        true,
        TimestampMs::new(1),
    )
}

fn trust() -> DecodingTrust {
    DecodingTrust {
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
        package_digest: Digest256::from_bytes([5; 32]),
        methods: [method("session/request_permission")].into_iter().collect(),
        schema_versions: ["kr-approval/1".to_owned()].into_iter().collect(),
        max_decisions: U64::new(4),
        may_encode_response: true,
        granted_at: TimestampMs::new(1),
    }
}

fn projection() -> DecodedProjection {
    DecodedProjection {
        schema_version: "kr-approval/1".to_owned(),
        summary: "the agent wants to write a file".to_owned(),
        decisions: vec![
            OfferedDecision {
                option_id: "allow".to_owned(),
                label: "Allow".to_owned(),
            },
            OfferedDecision {
                option_id: "deny".to_owned(),
                label: "Deny".to_owned(),
            },
        ],
    }
}

fn package() -> PluginId {
    PluginId::new("kalareach.codex").expect("valid")
}

fn table() -> DeclarativeTable {
    let mut table = DeclarativeTable {
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
        table_version: MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        digest: Digest256::from_bytes([1; 32]),
        framing: NativeFraming::JsonLines,
        request_id_field: "id".to_owned(),
        response_id_field: "id".to_owned(),
        method_field: "method".to_owned(),
        params_field: "params".to_owned(),
        result_field: "result".to_owned(),
        error_field: "error".to_owned(),
        entries: vec![DeclarativeEntry {
            method: method("session/request_permission"),
            class: NativeMethodClass::Mutation,
            expects_response: true,
            approval_option_field: Nullable::some("option_id".to_owned()),
            reverse: Nullable::null(),
        }],
    };
    table.digest = table.canonical_digest().expect("encodable");
    table
}

fn rich() -> RichMethodTable {
    RichMethodTable {
        table_version: MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        entries: vec![kr_protocol::gateway::RichMethodEntry {
            method: method("session/cancel"),
            class: NativeMethodClass::Mutation,
            required_right: ActionRight::AgentCancel,
            operation: Nullable::some(RichOperation::TurnCancel),
            provenance: ActionProvenance::UpstreamTypedRpc,
        }],
    }
}

fn evidence(name: &str, state: InstanceCapabilityState) -> InstanceCapabilityRecord {
    InstanceCapabilityRecord {
        capability_id: capability(name),
        capability_version: "1".to_owned(),
        application_instance_id: instance(),
        identity: InstanceCapabilityIdentity::default(),
        revision: CapabilityRevision::new(1),
        state,
        source: InstanceEvidenceSource::HostProbe,
        invalidated_by: [InstanceInvalidation::BindingChanged].into_iter().collect(),
        disabled_reason: if state.is_usable() {
            Nullable::null()
        } else {
            Nullable::some("this installation cannot do it".to_owned())
        },
        observed_at: TimestampMs::new(1),
    }
}

fn target(revision: u64) -> AgentMutationTarget {
    AgentMutationTarget {
        subject: subject(session(), instance()),
        binding_revision: AgentBindingRevision::new(revision),
    }
}

/// A transport that records what it was asked to carry, and answers as an upstream would.
///
/// It is what a connector supplies in the product: section 12's bundled adapters are the plugins
/// repository's, and each drives its own upstream. What this establishes here is that the broker
/// actually hands the operation over rather than reporting it as applied.
#[derive(Debug, Default)]
struct RecordingUpstream {
    submitted: std::sync::Mutex<Vec<UpstreamRequest>>,
    refuse: bool,
}

impl RecordingUpstream {
    fn submitted(&self) -> Vec<UpstreamRequest> {
        self.submitted
            .lock()
            .expect("the record is not poisoned")
            .clone()
    }
}

impl UpstreamDispatch for RecordingUpstream {
    fn admit(&self, _request: &kr_worker::broker::UpstreamRequest) -> Result<(), BrokerError> {
        Ok(())
    }

    fn submit(&self, request: &UpstreamRequest) -> Result<UpstreamOutcome, BrokerError> {
        self.submitted
            .lock()
            .expect("the record is not poisoned")
            .push(request.clone());
        if self.refuse {
            return Err(BrokerError::UpstreamUnavailable {
                detail: "the framing connection ended".to_owned(),
            });
        }
        Ok(UpstreamOutcome {
            upstream_request_id: Some(UpstreamRequestId::new("upstream-1").expect("valid")),
            turn_id: request.turn_id.clone(),
            provenance: ActionProvenance::UpstreamTypedRpc,
        })
    }
}

/// The digest of the parameters every invocation in this suite is made with.
///
/// A plan is checked against the arguments that will execute, so a test that supplies a hash of
/// its own is testing nothing: this is what the host itself computes.
fn arguments_digest() -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(b"{}"))
}

/// A draft store that holds exactly the drafts it was told about.
#[derive(Debug)]
struct KnownDrafts {
    known: std::collections::BTreeSet<kr_protocol::ids::DraftId>,
}

impl kr_worker::broker::DraftResolver for KnownDrafts {
    fn resolve(
        &self,
        draft_id: &kr_protocol::ids::DraftId,
    ) -> Result<kr_worker::broker::DraftSnapshot, BrokerError> {
        if self.known.contains(draft_id) {
            Ok(kr_worker::broker::DraftSnapshot {
                draft_id: *draft_id,
                revision: kr_protocol::scalars::U64::new(1),
            })
        } else {
            Err(BrokerError::PreconditionFailed {
                detail: format!("no draft {draft_id}"),
            })
        }
    }
}

/// A transport that will not admit the operation it is offered.
///
/// A connector whose qualified tables name no method for an operation is this: the refusal
/// belongs to admission, before anything is claimed or marked.
#[derive(Debug, Default)]
struct RefusingUpstream;

impl UpstreamDispatch for RefusingUpstream {
    fn admit(&self, _request: &kr_worker::broker::UpstreamRequest) -> Result<(), BrokerError> {
        Err(BrokerError::UnsupportedCapability {
            detail: "this upstream names no method for it".to_owned(),
        })
    }

    fn submit(
        &self,
        _request: &kr_worker::broker::UpstreamRequest,
    ) -> Result<kr_worker::broker::UpstreamOutcome, BrokerError> {
        panic!("a transport that admits nothing is never asked to carry anything")
    }
}

/// A broker with every capability the agent mutations need, and a transport that records.
fn agent_broker_with(upstream: std::sync::Arc<RecordingUpstream>) -> Broker {
    let broker = agent_broker();
    broker
        .bind_dispatch(instance(), std::sync::Arc::clone(&upstream) as _)
        .expect("the transport is bound");
    // An answer goes out on the connection whose resource it resolves, so the connection has its
    // own transport as well as the instance.
    broker.bind_connection_dispatch(GatewayConnectionId::new(1), upstream);
    broker
}

/// A broker with every capability the agent mutations need.
fn agent_broker() -> Broker {
    let broker = Broker::open(None, session()).expect("the broker opens");
    broker
        .register_instance(instance(), IntegrationMode::Gateway, None, Some(managed()))
        .expect("the instance is registered");
    broker
        .bind(
            binding(),
            instance(),
            PluginId::new("kalareach.codex").expect("valid"),
            PublisherId::new("kalareach").expect("valid"),
            Digest256::from_bytes([5; 32]),
            BrokerGrants::granted([
                BrokerGrant::UpstreamAction,
                BrokerGrant::ApprovalInterpreter,
            ]),
            Some(trust()),
            TimestampMs::new(1),
        )
        .expect("the binding is recorded");
    broker
        .pin_table(instance(), table(), rich())
        .expect("the installed tables are pinned");
    broker
        .open_native_connection(
            instance(),
            &CREDENTIAL,
            &process_identity(),
            &package(),
            "1",
        )
        .expect("the native connection is authenticated");
    for name in [
        "agent.prompt",
        "agent.prompt.queue",
        "agent.steer",
        "agent.cancel",
        "agent.approval",
    ] {
        broker
            .record_capability(evidence(name, InstanceCapabilityState::QualifiedAvailable))
            .expect("recorded");
    }
    broker
}

/// KR-REQ-23.39: an agent read names the exact instance, carries the capability evidence it was
/// answered under, and says what the history filter withheld and whether a range was evicted.
///
/// The `session.view` half is the method registry's, and the assertion below reads it from there
/// rather than restating it.
#[test]
fn kr_req_23_39_an_agent_read_names_the_instance_carries_its_evidence_and_reports_what_was_withheld()
 {
    let broker = agent_broker();
    broker
        .set_commands(
            instance(),
            vec![command("/new", "start a new conversation", "none")],
        )
        .expect("the commands are recorded");
    for index in 1..=5 {
        broker
            .observe(
                instance(),
                "message",
                &format!("entry {index}"),
                TimestampMs::new(index),
            )
            .expect("observed");
    }

    // Every agent-state method requires `session.view` and names the exact instance.
    for method in [
        Method::AgentCapabilities,
        Method::AgentSnapshot,
        Method::AgentCommands,
    ] {
        let AuthorityDecision::Listed(entry) = decide(
            method.as_str(),
            MethodVersion::V1,
            ActorIngress::PairedDevice,
        ) else {
            panic!("{} is listed", method.as_str());
        };
        assert_eq!(entry.effect, EffectClass::Read);
        assert!(
            entry.required_rights.iter().any(|required| matches!(
                required.authority,
                kr_protocol::authority::RequiredAuthority::Right {
                    right: ActionRight::SessionView
                }
            )),
            "{} requires session.view",
            method.as_str()
        );
        assert!(
            entry
                .resource_selectors
                .contains(&kr_protocol::authority::ResourceSelectorKind::ApplicationInstance),
            "{} names the exact instance",
            method.as_str()
        );
        assert_eq!(
            entry.history_filter,
            kr_protocol::authority::HistoryFilter::GrantLowerBound,
            "{} applies the shared history filter",
            method.as_str()
        );
    }

    let capabilities = broker
        .agent_capabilities(&AgentCapabilitiesParams {
            subject: subject(session(), instance()),
        })
        .expect("the read succeeds");
    assert_eq!(
        capabilities
            .capabilities
            .record(&capability("agent.prompt"))
            .expect("the evidence is carried with the answer")
            .state,
        InstanceCapabilityState::QualifiedAvailable
    );
    assert_eq!(
        capabilities.binding.binding_revision,
        AgentBindingRevision::new(1)
    );

    let commands = broker
        .agent_commands(&AgentCommandsParams {
            subject: subject(session(), instance()),
        })
        .expect("the read succeeds");
    assert_eq!(commands.commands.len(), 1);
    assert_eq!(commands.commands[0].name, "/new");

    // The filter's lower bound is applied, and the answer says how much it withheld.
    let filtered = broker
        .agent_snapshot(
            &AgentSnapshotParams {
                subject: subject(session(), instance()),
                from_node: Nullable::null(),
            },
            &GrantLowerBound {
                from: StreamCursor::new(4),
            },
        )
        .expect("the read succeeds");
    assert_eq!(filtered.entries.len(), 2);
    assert_eq!(filtered.withheld_entries.get(), 3);
    assert!(!filtered.history_gap);

    // A read of another session's instance is refused rather than answered.
    let elsewhere = broker.agent_capabilities(&AgentCapabilitiesParams {
        subject: subject(SessionId::new(Uuid::from_bytes([9; 16])), instance()),
    });
    assert!(elsewhere.is_err());
}

/// KR-REQ-23.40 and KR-REQ-12.06: the five agent mutations carry the rights the method registry
/// names for them, and every one of them refuses a revision that is not the one in force.
#[test]
fn kr_req_23_40_the_five_mutations_carry_the_registrys_rights_and_check_their_binding() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    broker
        .set_turn(instance(), Some(AgentTurnId::new("turn-1").expect("valid")))
        .expect("a turn is running");

    // Five methods, and the rights the registry requires of them are not one right repeated.
    let rights: Vec<ActionRight> = [
        Method::AgentPromptSubmit,
        Method::AgentPromptQueue,
        Method::AgentTurnSteer,
        Method::AgentTurnCancel,
        Method::AgentApprovalRespond,
    ]
    .into_iter()
    .map(|method| {
        let AuthorityDecision::Listed(entry) = decide(
            method.as_str(),
            MethodVersion::V1,
            ActorIngress::PairedDevice,
        ) else {
            panic!("{} is listed", method.as_str());
        };
        assert_eq!(entry.effect, EffectClass::Write);
        match entry.required_rights[0].authority {
            kr_protocol::authority::RequiredAuthority::Right { right } => right,
            ref other => panic!("{} requires a named right, not {other:?}", method.as_str()),
        }
    })
    .collect();
    assert_eq!(
        rights,
        vec![
            ActionRight::AgentPrompt,
            ActionRight::AgentPrompt,
            ActionRight::AgentPrompt,
            ActionRight::AgentCancel,
            ActionRight::AgentApprovalRespond,
        ]
    );
    let distinct: std::collections::BTreeSet<ActionRight> = rights.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        3,
        "prompt, cancel and approval are distinct"
    );

    // Each one applies at the revision in force.
    let prompt = AgentPromptParams {
        target: target(1),
        draft_id: Nullable::null(),
        text: Nullable::some(PromptText::new("hello").expect("valid")),
    };
    let applied = broker
        .agent_prompt(&caller(), &prompt, false, TimestampMs::new(20))
        .expect("the prompt applies");
    assert_eq!(applied.binding_revision, AgentBindingRevision::new(1));
    assert_eq!(applied.provenance, ActionProvenance::UpstreamTypedRpc);
    assert_eq!(
        applied.upstream_request_id.as_ref().map(|id| id.as_str()),
        Some("upstream-1"),
        "the answer names what the upstream called it"
    );
    broker
        .agent_prompt(&caller(), &prompt, true, TimestampMs::new(21))
        .expect("and so does a queued one");
    broker
        .agent_steer(
            &caller(),
            &AgentSteerParams {
                target: target(1),
                turn_id: AgentTurnId::new("turn-1").expect("valid"),
                text: PromptText::new("try the other file").expect("valid"),
            },
            TimestampMs::new(22),
        )
        .expect("the steer applies to the turn that is running");
    broker
        .agent_cancel(
            &caller(),
            &AgentCancelParams {
                target: target(1),
                turn_id: AgentTurnId::new("turn-1").expect("valid"),
            },
            TimestampMs::new(23),
        )
        .expect("the cancellation applies");

    // Each of those reached the upstream, with the operation it was for.
    let submitted: Vec<kr_protocol::gateway::RichOperation> = upstream
        .submitted()
        .into_iter()
        .map(|request| request.operation)
        .collect();
    assert_eq!(
        submitted,
        vec![
            kr_protocol::gateway::RichOperation::PromptSubmit,
            kr_protocol::gateway::RichOperation::PromptQueue,
            kr_protocol::gateway::RichOperation::TurnSteer,
            kr_protocol::gateway::RichOperation::TurnCancel,
        ],
        "a mutation that reports success is one that reached the upstream"
    );

    // An instance with nothing bound to carry its operations refuses rather than reporting them
    // as applied.
    let unreachable = agent_broker();
    assert!(
        unreachable
            .agent_prompt(&caller(), &prompt, false, TimestampMs::new(20))
            .is_err(),
        "a prompt with no transport is refused, not applied"
    );

    // A turn that is not the one running is refused rather than redirected.
    assert!(
        broker
            .agent_cancel(
                &caller(),
                &AgentCancelParams {
                    target: target(1),
                    turn_id: AgentTurnId::new("turn-9").expect("valid"),
                },
                TimestampMs::new(23),
            )
            .is_err()
    );

    // The conversation changes. Everything prepared against the old revision is stale.
    broker
        .advance_binding(instance(), None, TimestampMs::new(10))
        .expect("the selected thread changed");
    let stale = broker
        .agent_prompt(&caller(), &prompt, false, TimestampMs::new(20))
        .expect_err("a prompt prepared against the old conversation is stale");
    assert_eq!(stale.code(), ErrorCode::StaleSession);

    // And a prompt that names neither a draft nor text, or both, is an argument failure.
    assert!(
        broker
            .agent_prompt(
                &caller(),
                &AgentPromptParams {
                    target: target(2),
                    draft_id: Nullable::null(),
                    text: Nullable::null(),
                },
                false,
                TimestampMs::new(24),
            )
            .is_err()
    );
}

/// KR-REQ-23.40: `agent.approval.respond` answers the exact pending resource, with a decision the
/// request actually offered, once.
#[test]
fn kr_req_23_40_an_approval_answer_is_one_of_the_decisions_the_request_offered() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    let body = r#"{"id":11,"method":"session/request_permission"}"#;
    let opaque = broker
        .forward_native(
            GatewayConnectionId::new(1),
            body.as_bytes(),
            TimestampMs::new(2),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response");
    let resource = broker
        .interpret(
            binding(),
            opaque.resource_id,
            projection(),
            None,
            TimestampMs::new(3),
        )
        .expect("interpreted");

    let invented = broker.agent_approval_respond(
        &caller(),
        &AgentApprovalRespondParams {
            target: target(1),
            resource_id: resource.resource_id,
            option_id: "allow_always".to_owned(),
        },
        TimestampMs::new(4),
    );
    assert!(
        invented.is_err(),
        "a decision the request never offered is not an answer this host encodes"
    );

    let (answered, admission) = broker
        .agent_approval_respond(
            &caller(),
            &AgentApprovalRespondParams {
                target: target(1),
                resource_id: resource.resource_id,
                option_id: "allow".to_owned(),
            },
            TimestampMs::new(5),
        )
        .expect("the answer is applied");
    assert_eq!(answered.state, PendingState::Resolved);
    assert_eq!(answered.resource_id, resource.resource_id);
    assert_eq!(
        answered.mutation.provenance,
        ActionProvenance::UpstreamTypedRpc
    );
    assert_eq!(
        admission.resource_id(),
        Some(resource.resource_id),
        "the admission names the resource it answered"
    );

    // And once.
    assert!(
        broker
            .agent_approval_respond(
                &caller(),
                &AgentApprovalRespondParams {
                    target: target(1),
                    resource_id: resource.resource_id,
                    option_id: "allow".to_owned(),
                },
                TimestampMs::new(6),
            )
            .is_err()
    );
}

/// KR-REQ-23.40 and KR-REQ-11.27: an approval answer that cannot be dispatched is refused by the
/// broker's own admission, which is what the service asks before it writes a receipt marker.
///
/// What this establishes is the broker's half. The receipt a refused answer leaves is the
/// service's, and `agent_service.rs` is where that is asserted.
#[test]
fn kr_req_23_40_an_approval_that_cannot_be_answered_is_refused_at_admission() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));

    // One request with a deadline the upstream stated.
    let opaque = broker
        .forward_native(
            GatewayConnectionId::new(1),
            r#"{"id":11,"method":"session/request_permission"}"#.as_bytes(),
            TimestampMs::new(2),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response");
    let resource = broker
        .interpret(
            binding(),
            opaque.resource_id,
            projection(),
            Some(TimestampMs::new(50)),
            TimestampMs::new(3),
        )
        .expect("interpreted");

    // A decision the interpretation never offered.
    assert!(
        broker
            .check_answerable(
                &target(1),
                resource.resource_id,
                "allow_always",
                TimestampMs::new(4)
            )
            .is_err()
    );
    // Past the upstream's own deadline, an answer would reach nothing.
    assert!(
        broker
            .check_answerable(
                &target(1),
                resource.resource_id,
                "allow",
                TimestampMs::new(51)
            )
            .is_err(),
        "an answer after the upstream's deadline is refused here, not discovered at dispatch"
    );
    // Inside it, the same answer is admissible.
    broker
        .check_answerable(
            &target(1),
            resource.resource_id,
            "allow",
            TimestampMs::new(5),
        )
        .expect("the decision was offered and the deadline has not passed");

    // The interpretation is only worth acting on while its decoder still holds the grant.
    broker
        .withdraw_grant(binding(), BrokerGrant::ApprovalInterpreter)
        .expect("the grant is withdrawn");
    assert!(
        broker
            .check_answerable(
                &target(1),
                resource.resource_id,
                "allow",
                TimestampMs::new(6)
            )
            .is_err(),
        "a withdrawn interpreter grant leaves nothing to act on"
    );
}

/// KR-REQ-23.30 and KR-REQ-12.08: `plugin.action.invoke` validates the registered action, the
/// grant, the effect class and the preconditions, and an action's capability is separate from the
/// observation beside it.
#[test]
fn kr_req_23_30_a_plugin_action_validates_its_action_grant_effect_and_preconditions() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    broker
        .register_actions(
            binding(),
            [
                RegisteredAction {
                    name: ActionName::new("prompt.submit").expect("valid"),
                    grant: BrokerGrant::UpstreamAction,
                    effect: EffectClass::Write,
                    capability: Some(capability("agent.prompt")),
                    needs_draft: false,
                    operation: kr_protocol::broker::PreparedOperation::UpstreamSubmit,
                },
                RegisteredAction {
                    name: ActionName::new("draft.attach").expect("valid"),
                    grant: BrokerGrant::UpstreamAction,
                    effect: EffectClass::Write,
                    capability: Some(capability("agent.prompt")),
                    needs_draft: true,
                    operation: kr_protocol::broker::PreparedOperation::UpstreamAttachment,
                },
                RegisteredAction {
                    name: ActionName::new("conversation.read").expect("valid"),
                    grant: BrokerGrant::Observation,
                    effect: EffectClass::Read,
                    capability: None,
                    needs_draft: false,
                    operation: kr_protocol::broker::PreparedOperation::UpstreamSubmit,
                },
            ],
        )
        .expect("the actions are registered");

    // The effect a component would return for one action, as the broker receives it.
    let prepared = |action: &str, draft: Nullable<kr_protocol::ids::DraftId>| {
        kr_protocol::broker::PreparedEffect {
            action: ActionName::new(action).expect("valid"),
            class: EffectClass::Write,
            operation: if action == "draft.attach" {
                kr_protocol::broker::PreparedOperation::UpstreamAttachment
            } else {
                kr_protocol::broker::PreparedOperation::UpstreamSubmit
            },
            draft_id: draft,
            argument_hash: arguments_digest(),
        }
    };
    let invoke = |action: &str, draft: Nullable<kr_protocol::ids::DraftId>| {
        broker.plugin_action_invoke(
            &caller(),
            binding(),
            &PluginActionInvokeParams {
                target: target(1),
                plugin_id: PluginId::new("kalareach.codex").expect("valid"),
                action: ActionName::new(action).expect("valid"),
                draft_id: draft,
                parameters: Bytes::from(b"{}".to_vec()),
            },
            &prepared(action, draft),
            TimestampMs::new(4),
        )
    };

    let applied = invoke("prompt.submit", Nullable::null()).expect("a registered action runs");
    assert_eq!(applied.action.as_str(), "prompt.submit");

    // An action the package never registered.
    assert!(invoke("prompt.inject", Nullable::null()).is_err());

    // An action declared as a read, arriving on the write path.
    assert!(invoke("conversation.read", Nullable::null()).is_err());

    // An action that acts on a draft, with no draft named.
    let missing_draft = invoke("draft.attach", Nullable::null())
        .expect_err("a precondition the action declares is checked");
    assert_eq!(missing_draft.code(), ErrorCode::DraftConflict);

    // Naming one is not enough either: a draft this host cannot resolve is a precondition nobody
    // has established, and the action waits for it rather than being sent hopefully.
    let draft = kr_protocol::ids::DraftId::new(Uuid::from_bytes([4; 16]));
    let unresolvable =
        invoke("draft.attach", Nullable::some(draft)).expect_err("nothing here resolves a draft");
    assert_eq!(unresolvable.code(), ErrorCode::DraftConflict);
    broker.bind_drafts(std::sync::Arc::new(KnownDrafts {
        known: [draft].into_iter().collect(),
    }));
    assert!(
        invoke(
            "draft.attach",
            Nullable::some(kr_protocol::ids::DraftId::new(Uuid::from_bytes([5; 16]))),
        )
        .is_err(),
        "and a draft the store does not hold is refused"
    );
    invoke("draft.attach", Nullable::some(draft))
        .expect("and it runs once the draft is one this host can resolve");
    // And what goes to the upstream names the revision the draft stood at when it was admitted,
    // not only the identifier: the identifier alone would denote whatever the draft holds by the
    // time the frame lands.
    let carried = upstream.submitted();
    let UpstreamBody::PluginAction {
        draft_id: carried_draft,
        draft_revision,
        ..
    } = &carried.last().expect("the action was carried").body
    else {
        panic!("a plugin action was carried");
    };
    assert_eq!(*carried_draft, Some(draft));
    assert_eq!(*draft_revision, Some(kr_protocol::scalars::U64::new(1)));

    // The grant is the binding's, not the action's wish: withdrawing it refuses the action.
    broker
        .withdraw_grant(binding(), BrokerGrant::UpstreamAction)
        .expect("the grant is withdrawn");
    let refusal = invoke("prompt.submit", Nullable::null())
        .expect_err("an action needs the grant it declares");
    assert!(matches!(refusal, BrokerError::Grant(_)));
    // And the same refusal is reachable before anything is marked, so it is a rejection rather
    // than an outcome nobody can establish.
    assert!(
        matches!(
            broker
                .check_invocable(
                    &caller(),
                    binding(),
                    &PluginActionInvokeParams {
                        target: target(1),
                        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
                        action: ActionName::new("prompt.submit").expect("valid"),
                        draft_id: Nullable::null(),
                        parameters: Bytes::from(b"{}".to_vec()),
                    },
                    TimestampMs::new(25),
                )
                .expect_err("the withdrawn grant is found before the marker"),
            BrokerError::Grant(_)
        ),
        "the invocation's own authority is checked before the receipt marker"
    );

    // And the capability an action needs is separate from the observation beside it: withdrawing
    // the evidence refuses the action while the read still answers.
    let broker = agent_broker_with(std::sync::Arc::new(RecordingUpstream::default()));
    broker
        .register_actions(
            binding(),
            [RegisteredAction {
                name: ActionName::new("prompt.submit").expect("valid"),
                grant: BrokerGrant::UpstreamAction,
                effect: EffectClass::Write,
                capability: Some(capability("agent.prompt")),
                needs_draft: false,
                operation: kr_protocol::broker::PreparedOperation::UpstreamSubmit,
            }],
        )
        .expect("the actions are registered");
    broker.invalidate_capabilities(
        InstanceInvalidation::BindingChanged,
        "the selected thread changed",
        TimestampMs::new(5),
    );
    assert!(
        broker
            .plugin_action_invoke(
                &caller(),
                binding(),
                &PluginActionInvokeParams {
                    target: target(1),
                    plugin_id: PluginId::new("kalareach.codex").expect("valid"),
                    action: ActionName::new("prompt.submit").expect("valid"),
                    draft_id: Nullable::null(),
                    parameters: Bytes::from(b"{}".to_vec()),
                },
                &kr_protocol::broker::PreparedEffect {
                    action: ActionName::new("prompt.submit").expect("valid"),
                    class: EffectClass::Write,
                    operation: kr_protocol::broker::PreparedOperation::UpstreamSubmit,
                    draft_id: Nullable::null(),
                    argument_hash: Digest256::from_bytes([8; 32]),
                },
                TimestampMs::new(6),
            )
            .is_err()
    );
    broker
        .agent_capabilities(&AgentCapabilitiesParams {
            subject: subject(session(), instance()),
        })
        .expect("the observation beside it still answers");
}

/// KR-REQ-24.24: an adapter replays from the cursor it consumed, and an evicted range rebuilds
/// with a visible history gap.
#[test]
fn kr_req_24_24_a_replay_starts_after_the_consumed_cursor_and_an_eviction_shows_a_gap() {
    let directory = std::env::temp_dir().join(format!("kr-methods-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&directory).expect("the directory is created");
    let path = directory.join("session.sqlite");

    let consumed = {
        let broker = Broker::open(Some(&path), session()).expect("the broker opens");
        broker
            .register_instance(instance(), IntegrationMode::Gateway, None, None)
            .expect("the instance is registered");
        for index in 1..=5 {
            broker
                .observe(
                    instance(),
                    "message",
                    &format!("entry {index}"),
                    TimestampMs::new(index),
                )
                .expect("observed");
        }
        let replay = broker
            .replay(
                instance(),
                None,
                &GrantLowerBound {
                    from: StreamCursor::new(1),
                },
            )
            .expect("the replay succeeds");
        assert_eq!(replay.entries.len(), 5);
        assert!(!replay.history_gap);
        broker
            .checkpoint(instance(), replay.consumed, TimestampMs::new(6))
            .expect("the cursor is recorded");
        replay.consumed
    };

    // A restart replays from the cursor that was consumed, and nothing before it.
    let restarted = Broker::open(Some(&path), session()).expect("the broker reopens");
    assert_eq!(
        restarted
            .consumed_cursor(instance())
            .expect("the read succeeds"),
        Some(consumed)
    );
    restarted
        .register_instance(instance(), IntegrationMode::Gateway, None, None)
        .expect("the instance is registered");
    for index in 6..=8 {
        restarted
            .observe(
                instance(),
                "message",
                &format!("entry {index}"),
                TimestampMs::new(index),
            )
            .expect("observed");
    }
    let replay = restarted
        .replay(
            instance(),
            Some(consumed),
            &GrantLowerBound {
                from: StreamCursor::new(1),
            },
        )
        .expect("the replay succeeds");
    assert!(
        replay.entries.is_empty() || replay.entries[0].text.starts_with("entry"),
        "the replay starts after what was consumed"
    );
    assert!(!replay.history_gap);

    // An evicted range rebuilds from what is verifiably retained, and says there is a gap.
    let broker = Broker::open(None, session()).expect("the broker opens");
    broker
        .register_instance(instance(), IntegrationMode::Gateway, None, None)
        .expect("the instance is registered");
    for index in 1..=(kr_worker::broker::semantic::MAX_RETAINED_ENTRIES as u64 + 10) {
        broker
            .observe(
                instance(),
                "message",
                &format!("entry {index}"),
                TimestampMs::new(index),
            )
            .expect("observed");
    }
    let rebuilt = broker
        .replay(
            instance(),
            Some(StreamCursor::new(1)),
            &GrantLowerBound {
                from: StreamCursor::new(1),
            },
        )
        .expect("the replay succeeds");
    assert!(
        rebuilt.history_gap,
        "a range that was evicted is a visible gap, not a shorter answer"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// KR-REQ-11.22 and KR-REQ-12.06: one broker admission carries every check a mutation depends on,
/// so nothing it checked can move before the answer is transmitted.
///
/// The admission is the only authority `dispatch_mutation` takes, and only the broker makes one.
/// What this establishes is that every refusal happens at the admission rather than during the
/// dispatch, and that the transport is taken there too: an admission is authority over a specific
/// upstream rather than permission to go and find one afterwards.
#[test]
fn kr_req_11_22_one_admission_carries_every_check_and_the_transport_it_will_use() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    let prompt = AgentPromptParams {
        target: target(1),
        draft_id: Nullable::null(),
        text: Nullable::some(PromptText::new("hello").expect("valid")),
    };

    // The admission carries the prepared operation, the revision it was taken at and the
    // capability it was rechecked against.
    let admitted = broker
        .admit_prompt(&caller(), &prompt, false, TimestampMs::new(2))
        .expect("the prompt is admitted");
    assert_eq!(admitted.binding_revision(), AgentBindingRevision::new(1));
    assert_eq!(
        admitted.capability(),
        Some(&capability("agent.prompt")),
        "the admission names what it rechecked"
    );
    assert_eq!(
        admitted.operation(),
        kr_protocol::gateway::RichOperation::PromptSubmit
    );
    assert!(
        upstream.submitted().is_empty(),
        "admitting reaches no upstream"
    );

    // Nothing was transmitted until the admission was spent, and spending it is what reaches the
    // upstream.
    broker
        .dispatch_mutation(&admitted, TimestampMs::new(3))
        .expect("the admitted operation is carried");
    assert_eq!(upstream.submitted().len(), 1);

    // Every one of these is refused at the admission. A mutation that reaches `dispatch_mutation`
    // has already passed all of them, under one lock, at one moment.
    broker
        .suspend_rich_mutations(instance(), "a native selection could not be observed")
        .expect("suspended");
    let suspended = broker
        .admit_prompt(&caller(), &prompt, false, TimestampMs::new(4))
        .expect_err("a suspended instance admits nothing");
    assert_eq!(suspended.code(), ErrorCode::DraftConflict);
    broker.resume_rich_mutations(instance()).expect("resumed");

    let wrong_turn = broker
        .admit_steer(
            &caller(),
            &AgentSteerParams {
                target: target(1),
                turn_id: AgentTurnId::new("turn-9").expect("valid"),
                text: PromptText::new("try the other file").expect("valid"),
            },
            TimestampMs::new(5),
        )
        .expect_err("a turn that is not running is refused at the admission");
    assert_eq!(wrong_turn.code(), ErrorCode::DraftConflict);

    broker.invalidate_capabilities(
        InstanceInvalidation::BindingChanged,
        "the binary changed",
        TimestampMs::new(6),
    );
    let unusable = broker
        .admit_prompt(&caller(), &prompt, false, TimestampMs::new(7))
        .expect_err("an invalidated capability is refused at the admission");
    assert_eq!(unusable.code(), ErrorCode::UnsupportedCapability);

    // And an instance with nothing bound to carry its operations is refused before anything is
    // admitted, rather than discovered when the dispatch goes looking for a transport.
    let unreachable = agent_broker();
    let nothing = unreachable
        .admit_prompt(&caller(), &prompt, false, TimestampMs::new(8))
        .expect_err("no transport is bound");
    assert_eq!(nothing.code(), ErrorCode::UnsupportedCapability);

    // A stale revision is the admission's refusal too.
    let broker = agent_broker_with(std::sync::Arc::new(RecordingUpstream::default()));
    broker
        .advance_binding(instance(), None, TimestampMs::new(9))
        .expect("the selected thread changed");
    let stale = broker
        .admit_prompt(&caller(), &prompt, false, TimestampMs::new(10))
        .expect_err("a prompt prepared against the old conversation is stale");
    assert_eq!(stale.code(), ErrorCode::StaleSession);
}

/// KR-REQ-11.31: a dispatch is refused by the component answerable for it, not by the set of
/// components the instance happens to have.
///
/// This is the per-binding half of the fence. A second component that is working cannot admit an
/// action through the one whose rich capabilities a fault disabled.
#[test]
fn kr_req_11_31_a_disabled_provider_refuses_its_own_dispatch_beside_a_working_one() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    broker
        .register_actions(
            binding(),
            [RegisteredAction {
                name: ActionName::new("prompt.submit").expect("valid"),
                grant: BrokerGrant::UpstreamAction,
                effect: EffectClass::Write,
                capability: Some(capability("agent.prompt")),
                needs_draft: false,
                operation: kr_protocol::broker::PreparedOperation::UpstreamSubmit,
            }],
        )
        .expect("the actions are registered");
    // A second component, bound to the same instance and working perfectly.
    let other = BrokerBindingId::new(Uuid::from_bytes([11; 16]));
    broker
        .bind(
            other,
            instance(),
            PluginId::new("kalareach.other").expect("valid"),
            PublisherId::new("kalareach").expect("valid"),
            Digest256::from_bytes([6; 32]),
            BrokerGrants::granted([BrokerGrant::Observation]),
            None,
            TimestampMs::new(1),
        )
        .expect("the second binding is recorded");

    let invoke = PluginActionInvokeParams {
        target: target(1),
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        action: ActionName::new("prompt.submit").expect("valid"),
        draft_id: Nullable::null(),
        parameters: Bytes::from(b"{}".to_vec()),
    };
    broker
        .admit_plugin_action(&caller(), binding(), &invoke, TimestampMs::new(2))
        .expect("the action is admitted while its own component works");

    // The component that would run the action faults. The other one is untouched, and under the
    // old rule that was enough to let this action through.
    broker.disable_rich(binding(), "the component trapped");
    let refusal = broker
        .admit_plugin_action(&caller(), binding(), &invoke, TimestampMs::new(3))
        .expect_err("the component answerable for this action is disabled");
    assert_eq!(refusal.code(), ErrorCode::UnsupportedCapability);
    assert!(
        broker
            .check_invocable(&caller(), binding(), &invoke, TimestampMs::new(4))
            .is_err(),
        "and the same refusal is reachable before anything is marked"
    );
    assert_eq!(
        upstream.submitted().len(),
        0,
        "nothing reached the upstream through a disabled provider"
    );
}

/// KR-REQ-11.28: a returned effect plan may use only what the invocation it was prepared under
/// permits.
///
/// Proposing is not doing. Four ways a component could ask for something it was not invited to do
/// are refused here: another action's name, an operation whose grant the binding does not hold, a
/// class that disagrees with what the operation does, and a draft other than the invocation's own.
#[test]
fn kr_req_11_28_a_prepared_effect_may_use_only_what_its_invocation_permits() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    let draft = kr_protocol::ids::DraftId::new(Uuid::from_bytes([4; 16]));
    broker.bind_drafts(std::sync::Arc::new(KnownDrafts {
        known: [draft].into_iter().collect(),
    }));
    broker
        .register_actions(
            binding(),
            [RegisteredAction {
                name: ActionName::new("draft.attach").expect("valid"),
                grant: BrokerGrant::UpstreamAction,
                effect: EffectClass::Write,
                capability: None,
                needs_draft: true,
                operation: kr_protocol::broker::PreparedOperation::UpstreamAttachment,
            }],
        )
        .expect("the actions are registered");
    let admitted = broker
        .admit_plugin_action(
            &caller(),
            binding(),
            &PluginActionInvokeParams {
                target: target(1),
                plugin_id: PluginId::new("kalareach.codex").expect("valid"),
                action: ActionName::new("draft.attach").expect("valid"),
                draft_id: Nullable::some(draft),
                parameters: Bytes::from(b"{}".to_vec()),
            },
            TimestampMs::new(2),
        )
        .expect("the invocation is admitted");
    assert!(
        !admitted.carries_a_validated_plan(),
        "nothing is validated until a plan arrives"
    );

    let plan = |action: &str,
                class: EffectClass,
                operation: kr_protocol::broker::PreparedOperation,
                draft_id: Nullable<kr_protocol::ids::DraftId>| {
        kr_protocol::broker::PreparedEffect {
            action: ActionName::new(action).expect("valid"),
            class,
            operation,
            draft_id,
            argument_hash: arguments_digest(),
        }
    };
    let attachment = kr_protocol::broker::PreparedOperation::UpstreamAttachment;

    broker
        .validate_effect(
            &admitted,
            &plan(
                "draft.attach",
                EffectClass::Write,
                attachment,
                Nullable::some(draft),
            ),
        )
        .expect("the plan is the invocation's own");

    // Another action's name.
    assert!(matches!(
        broker
            .validate_effect(
                &admitted,
                &plan(
                    "prompt.submit",
                    EffectClass::Write,
                    attachment,
                    Nullable::some(draft),
                ),
            )
            .expect_err("a plan belongs to the invocation it was prepared under"),
        BrokerError::Token(_)
    ));

    // A class that disagrees with what the operation does.
    assert!(
        broker
            .validate_effect(
                &admitted,
                &plan(
                    "draft.attach",
                    EffectClass::Read,
                    attachment,
                    Nullable::some(draft),
                ),
            )
            .is_err()
    );

    // A draft other than the one the invocation named.
    let elsewhere = kr_protocol::ids::DraftId::new(Uuid::from_bytes([6; 16]));
    assert_eq!(
        broker
            .validate_effect(
                &admitted,
                &plan(
                    "draft.attach",
                    EffectClass::Write,
                    attachment,
                    Nullable::some(elsewhere),
                ),
            )
            .expect_err("a plan acts on the invocation's own draft")
            .code(),
        ErrorCode::DraftConflict
    );

    // And an operation whose grant the binding no longer holds.
    broker
        .withdraw_grant(binding(), BrokerGrant::UpstreamAction)
        .expect("the grant is withdrawn");
    assert!(matches!(
        broker
            .validate_effect(
                &admitted,
                &plan(
                    "draft.attach",
                    EffectClass::Write,
                    attachment,
                    Nullable::some(draft),
                ),
            )
            .expect_err("a grant withdrawn while the component worked is not a grant"),
        BrokerError::Grant(_)
    ));
}

/// KR-REQ-11.27 and KR-REQ-11.33: one admission carries one transmission, and a caller that
/// reaches it after the winner transmits nothing and settles nothing.
///
/// The two calls here are sequential, which is the shape a losing concurrent caller ends up in:
/// the permit is taken atomically, so whichever caller loses the race arrives at exactly this
/// state.
#[test]
fn kr_req_11_27_a_later_caller_on_one_admission_transmits_nothing_and_settles_nothing() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    let opaque = broker
        .forward_native(
            GatewayConnectionId::new(1),
            br#"{"id":11,"method":"session/request_permission"}"#,
            TimestampMs::new(2),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response");
    let resource = broker
        .interpret(
            binding(),
            opaque.resource_id,
            projection(),
            None,
            TimestampMs::new(3),
        )
        .expect("interpreted");

    let admitted = broker
        .admit_approval(
            &caller(),
            &AgentApprovalRespondParams {
                target: target(1),
                resource_id: resource.resource_id,
                option_id: "allow".to_owned(),
            },
            TimestampMs::new(4),
        )
        .expect("the answer is admitted");
    let answered = broker
        .record_approval(&admitted, TimestampMs::new(5))
        .expect("the winner transmits");
    assert_eq!(answered.state, PendingState::Resolved);
    assert_eq!(upstream.submitted().len(), 1);

    // The loser finds the permit gone. It does not transmit, and it does not reach the
    // arbitration at all, so the answer the winner settled stays settled.
    let loser = broker
        .record_approval(&admitted, TimestampMs::new(6))
        .expect_err("one admission carries one answer");
    assert!(matches!(loser, BrokerError::AlreadyTransmitted));
    assert_eq!(upstream.submitted().len(), 1, "and it wrote nothing");
    assert_eq!(
        broker
            .recorded(resource.resource_id)
            .expect("readable")
            .expect("retained")
            .state,
        PendingState::Resolved,
        "the winner's resolution is untouched"
    );
    assert!(!admitted.executable());
}

/// KR-REQ-11.28 and KR-REQ-23.30: an invocation whose prepared effect was never validated
/// transmits nothing on either of the broker's dispatch routes, and a plan whose arguments are
/// not the ones that will execute is not this invocation's plan.
#[test]
fn kr_req_11_28_an_unvalidated_effect_transmits_on_neither_dispatch_route() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    broker
        .register_actions(
            binding(),
            [RegisteredAction {
                name: ActionName::new("prompt.submit").expect("valid"),
                grant: BrokerGrant::UpstreamAction,
                effect: EffectClass::Write,
                capability: Some(capability("agent.prompt")),
                needs_draft: false,
                operation: kr_protocol::broker::PreparedOperation::UpstreamSubmit,
            }],
        )
        .expect("the actions are registered");
    let invoke = || PluginActionInvokeParams {
        target: target(1),
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        action: ActionName::new("prompt.submit").expect("valid"),
        draft_id: Nullable::null(),
        parameters: Bytes::from(b"{}".to_vec()),
    };

    // The generic dispatch route, which any consumer of the broker can reach.
    let admitted = broker
        .admit_plugin_action(&caller(), binding(), &invoke(), TimestampMs::new(2))
        .expect("the invocation is admitted");
    assert!(
        broker
            .dispatch_mutation(&admitted, TimestampMs::new(3))
            .is_err(),
        "a plugin action with no validated plan is not a mutation to dispatch"
    );

    // And the plugin route.
    let admitted = broker
        .admit_plugin_action(&caller(), binding(), &invoke(), TimestampMs::new(4))
        .expect("the invocation is admitted");
    assert!(
        broker
            .record_plugin_action(&admitted, TimestampMs::new(5))
            .is_err(),
        "nor is it one to record"
    );
    assert!(upstream.submitted().is_empty(), "and nothing was written");

    // A plan whose arguments are not the ones that will execute is not this invocation's plan,
    // whatever hash it carries.
    let admitted = broker
        .admit_plugin_action(&caller(), binding(), &invoke(), TimestampMs::new(6))
        .expect("the invocation is admitted");
    assert!(
        broker
            .validate_effect(
                &admitted,
                &kr_protocol::broker::PreparedEffect {
                    action: ActionName::new("prompt.submit").expect("valid"),
                    class: EffectClass::Write,
                    operation: kr_protocol::broker::PreparedOperation::UpstreamSubmit,
                    draft_id: Nullable::null(),
                    argument_hash: Digest256::from_bytes([8; 32]),
                },
            )
            .is_err(),
        "a hash a component wrote is not evidence about the arguments"
    );
    assert!(
        broker
            .record_plugin_action(&admitted, TimestampMs::new(7))
            .is_err()
    );
    assert!(upstream.submitted().is_empty());
}

/// KR-REQ-23.30: the declaration an admission checks is the one in force when it admits, and a
/// registration that replaces it afterwards refuses both the next admission and the plan the
/// admitted invocation returns.
#[test]
fn kr_req_23_30_a_replaced_declaration_refuses_the_plan_of_the_invocation_it_replaced() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    broker
        .register_actions(
            binding(),
            [RegisteredAction {
                name: ActionName::new("prompt.submit").expect("valid"),
                grant: BrokerGrant::UpstreamAction,
                effect: EffectClass::Write,
                capability: Some(capability("agent.prompt")),
                needs_draft: false,
                operation: kr_protocol::broker::PreparedOperation::UpstreamSubmit,
            }],
        )
        .expect("the actions are registered");
    let invoke = PluginActionInvokeParams {
        target: target(1),
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        action: ActionName::new("prompt.submit").expect("valid"),
        draft_id: Nullable::null(),
        parameters: Bytes::from(b"{}".to_vec()),
    };
    let admitted = broker
        .admit_plugin_action(&caller(), binding(), &invoke, TimestampMs::new(2))
        .expect("the invocation is admitted");

    // The package re-registers the same action as a read. The invocation already admitted is not
    // re-decided by it, and the plan it prepares is still checked against a declaration.
    broker
        .register_actions(
            binding(),
            [RegisteredAction {
                name: ActionName::new("prompt.submit").expect("valid"),
                grant: BrokerGrant::UpstreamAction,
                effect: EffectClass::Read,
                capability: Some(capability("agent.prompt")),
                needs_draft: false,
                operation: kr_protocol::broker::PreparedOperation::UpstreamSubmit,
            }],
        )
        .expect("the package registers its actions");
    assert!(
        broker
            .admit_plugin_action(&caller(), binding(), &invoke, TimestampMs::new(3))
            .is_err(),
        "the declaration in force now is a read, and this is the write path"
    );
    assert!(
        broker
            .validate_effect(
                &admitted,
                &kr_protocol::broker::PreparedEffect {
                    action: ActionName::new("prompt.submit").expect("valid"),
                    class: EffectClass::Write,
                    operation: kr_protocol::broker::PreparedOperation::UpstreamSubmit,
                    draft_id: Nullable::null(),
                    argument_hash: arguments_digest(),
                },
            )
            .is_err(),
        "and a plan is checked against the declaration, not against the admission's memory of it"
    );
}

/// KR-REQ-11.33 and KR-REQ-12.13: an answer goes out on the connection whose resource it
/// resolves, and one instance's two connections never answer each other's.
#[test]
fn kr_req_12_13_each_connection_answers_its_own_resource() {
    let first = std::sync::Arc::new(RecordingUpstream::default());
    let second = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&first));
    let other = broker
        .open_native_connection(
            instance(),
            &CREDENTIAL,
            &process_identity(),
            &package(),
            "1",
        )
        .expect("a second native connection is authenticated");
    broker.bind_connection_dispatch(other, std::sync::Arc::clone(&second) as _);

    let answer = |connection: GatewayConnectionId, id: &str, at: u64| {
        let opaque = broker
            .forward_native(
                connection,
                format!(r#"{{"id":{id},"method":"session/request_permission"}}"#).as_bytes(),
                TimestampMs::new(at),
            )
            .expect("forwarded")
            .1
            .expect("it expects a response");
        let resource = broker
            .interpret(
                binding(),
                opaque.resource_id,
                projection(),
                None,
                TimestampMs::new(at + 1),
            )
            .expect("interpreted");
        broker
            .agent_approval_respond(
                &caller(),
                &AgentApprovalRespondParams {
                    target: target(1),
                    resource_id: resource.resource_id,
                    option_id: "allow".to_owned(),
                },
                TimestampMs::new(at + 2),
            )
            .expect("the answer is applied")
    };

    answer(GatewayConnectionId::new(1), "11", 2);
    assert_eq!(first.submitted().len(), 1);
    assert!(
        second.submitted().is_empty(),
        "the other connection was not written to"
    );

    answer(other, "12", 10);
    assert_eq!(second.submitted().len(), 1, "its own connection carries it");
    assert_eq!(first.submitted().len(), 1, "and the first is untouched");
}

/// KR-REQ-11.33: a native answer that has already resolved the resource leaves the rich answer
/// nothing to admit, so the rich path writes no frame and takes no claim.
#[test]
fn kr_req_11_33_a_resolved_resource_leaves_the_rich_answer_nothing_to_admit() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    let opaque = broker
        .forward_native(
            GatewayConnectionId::new(1),
            br#"{"id":11,"method":"session/request_permission"}"#,
            TimestampMs::new(2),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response");
    let resource = broker
        .interpret(
            binding(),
            opaque.resource_id,
            projection(),
            None,
            TimestampMs::new(3),
        )
        .expect("interpreted");

    // The person answers in the terminal first. Its answer takes the resource's one transmission
    // admission, commits the marker and goes.
    let mut carried = Vec::new();
    broker
        .native_answer_through(
            GatewayConnectionId::new(1),
            br#"{"id":11,"result":{"outcome":"allow"}}"#,
            TimestampMs::new(4),
            |bytes| {
                carried.push(bytes.to_vec());
                Ok(())
            },
        )
        .expect("the native answer is arbitrated");
    assert_eq!(carried.len(), 1);

    // The rich answer arrives a moment later. It is refused at admission, before a claim, before
    // a marker and before any byte, and what the upstream already has is what stands.
    let refusal = broker
        .admit_approval(
            &caller(),
            &AgentApprovalRespondParams {
                target: target(1),
                resource_id: resource.resource_id,
                option_id: "allow".to_owned(),
            },
            TimestampMs::new(5),
        )
        .expect_err("one resource takes one answer");
    assert_eq!(refusal.code(), ErrorCode::QuestionResolved);
    assert!(
        upstream.submitted().is_empty(),
        "the rich path wrote no frame"
    );
    assert_eq!(
        broker
            .recorded(resource.resource_id)
            .expect("readable")
            .expect("retained")
            .state,
        PendingState::Resolved,
        "and the resolution the native answer made is the one that stands"
    );
}

/// KR-REQ-11.27 and KR-REQ-24.24: an admission that is abandoned before its bytes leaves the
/// resource answerable, because the reservation and the dispatch marker are two moments.
#[test]
fn kr_req_11_27_an_abandoned_answer_leaves_the_resource_answerable() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    let opaque = broker
        .forward_native(
            GatewayConnectionId::new(1),
            br#"{"id":11,"method":"session/request_permission"}"#,
            TimestampMs::new(2),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response");
    let resource = broker
        .interpret(
            binding(),
            opaque.resource_id,
            projection(),
            None,
            TimestampMs::new(3),
        )
        .expect("interpreted");
    let params = AgentApprovalRespondParams {
        target: target(1),
        resource_id: resource.resource_id,
        option_id: "allow".to_owned(),
    };

    let admitted = broker
        .admit_approval(&caller(), &params, TimestampMs::new(4))
        .expect("the answer is admitted");
    broker.abandon(&admitted);
    assert!(!admitted.executable(), "the permit is gone");
    assert!(
        upstream.submitted().is_empty(),
        "an abandoned admission sent nothing"
    );
    assert_eq!(
        broker
            .pending(resource.resource_id)
            .expect("retained")
            .state,
        PendingState::Pending,
        "and the resource is answerable again"
    );

    // Which the next answer proves: it admits, transmits and settles.
    let answered = broker
        .agent_approval_respond(&caller(), &params, TimestampMs::new(5))
        .expect("the next answer is applied")
        .0;
    assert_eq!(answered.state, PendingState::Resolved);
    assert_eq!(upstream.submitted().len(), 1);
}

/// KR-REQ-11.28 and KR-REQ-23.30: a plan is carried only while the invocation's own authority
/// still holds, and an admission handed to the wrong dispatch route comes back unspent.
#[test]
fn kr_req_11_28_a_plan_is_refused_when_the_invocations_authority_has_moved() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    broker
        .register_actions(
            binding(),
            [RegisteredAction {
                name: ActionName::new("prompt.submit").expect("valid"),
                grant: BrokerGrant::UpstreamAction,
                effect: EffectClass::Write,
                capability: Some(capability("agent.prompt")),
                needs_draft: false,
                operation: kr_protocol::broker::PreparedOperation::UpstreamSubmit,
            }],
        )
        .expect("the actions are registered");
    let invoke = PluginActionInvokeParams {
        target: target(1),
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        action: ActionName::new("prompt.submit").expect("valid"),
        draft_id: Nullable::null(),
        parameters: Bytes::from(b"{}".to_vec()),
    };
    let plan = kr_protocol::broker::PreparedEffect {
        action: ActionName::new("prompt.submit").expect("valid"),
        class: EffectClass::Write,
        operation: kr_protocol::broker::PreparedOperation::UpstreamSubmit,
        draft_id: Nullable::null(),
        argument_hash: arguments_digest(),
    };

    // An admission whose approval route is asked for it keeps its permit: the mistake is refused
    // before anything is consumed, and the right route still works.
    let admitted = broker
        .admit_plugin_action(&caller(), binding(), &invoke, TimestampMs::new(2))
        .expect("the invocation is admitted");
    assert!(
        broker
            .record_approval(&admitted, TimestampMs::new(3))
            .is_err(),
        "a plugin action is not an approval to settle"
    );
    assert!(admitted.executable(), "and its permit is still there");
    broker
        .validate_effect(&admitted, &plan)
        .expect("the plan is the invocation's own");
    broker
        .record_plugin_action(&admitted, TimestampMs::new(4))
        .expect("and the right route carries it");
    assert_eq!(upstream.submitted().len(), 1);

    // The thread selection moves while the component is preparing its plan. The token was spent
    // to invite that work, so what refuses the plan is the authority as it stands now.
    let admitted = broker
        .admit_plugin_action(&caller(), binding(), &invoke, TimestampMs::new(5))
        .expect("the invocation is admitted");
    broker
        .advance_binding(instance(), None, TimestampMs::new(6))
        .expect("the binding advances");
    let refusal = broker
        .validate_effect(&admitted, &plan)
        .expect_err("the invocation's revision is not the one in force");
    assert_eq!(refusal.code(), kr_protocol::error::ErrorCode::StaleSession);
    assert!(
        broker
            .record_plugin_action(&admitted, TimestampMs::new(7))
            .is_err(),
        "and nothing carries a plan this host did not validate"
    );
    assert_eq!(upstream.submitted().len(), 1, "nothing more was written");
}

/// KR-REQ-12.06 and KR-REQ-11.27: a transport that cannot carry an answer refuses it at
/// admission, gives the resource back, and lets the next answer through.
#[test]
fn kr_req_12_06_a_transport_that_cannot_carry_an_answer_gives_the_resource_back() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    let opaque = broker
        .forward_native(
            GatewayConnectionId::new(1),
            br#"{"id":11,"method":"session/request_permission"}"#,
            TimestampMs::new(2),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response");
    let resource = broker
        .interpret(
            binding(),
            opaque.resource_id,
            projection(),
            None,
            TimestampMs::new(3),
        )
        .expect("interpreted");
    let params = AgentApprovalRespondParams {
        target: target(1),
        resource_id: resource.resource_id,
        option_id: "allow".to_owned(),
    };

    // The connection's transport cannot carry this answer.
    broker.bind_connection_dispatch(
        GatewayConnectionId::new(1),
        std::sync::Arc::new(RefusingUpstream) as _,
    );
    let refusal = broker
        .admit_approval(&caller(), &params, TimestampMs::new(4))
        .expect_err("nothing carries this answer");
    assert_eq!(refusal.code(), ErrorCode::UnsupportedCapability);
    assert_eq!(
        broker
            .pending(resource.resource_id)
            .expect("retained")
            .state,
        PendingState::Pending,
        "and the resource is still answerable"
    );

    // A transport that can carry it answers it, which is what proves the claim went back.
    broker.bind_connection_dispatch(
        GatewayConnectionId::new(1),
        std::sync::Arc::clone(&upstream) as _,
    );
    let answered = broker
        .agent_approval_respond(&caller(), &params, TimestampMs::new(5))
        .expect("the next answer is applied")
        .0;
    assert_eq!(answered.state, PendingState::Resolved);
    assert_eq!(upstream.submitted().len(), 1);
}

/// KR-REQ-11.35 and KR-REQ-11.28: a plan that arrives while rich work is fenced is refused, and
/// nothing carries it.
#[test]
fn kr_req_11_35_a_fence_refuses_a_plan_that_arrives_after_it() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    broker
        .register_actions(
            binding(),
            [RegisteredAction {
                name: ActionName::new("prompt.submit").expect("valid"),
                grant: BrokerGrant::UpstreamAction,
                effect: EffectClass::Write,
                capability: Some(capability("agent.prompt")),
                needs_draft: false,
                operation: kr_protocol::broker::PreparedOperation::UpstreamSubmit,
            }],
        )
        .expect("the actions are registered");
    let admitted = broker
        .admit_plugin_action(
            &caller(),
            binding(),
            &PluginActionInvokeParams {
                target: target(1),
                plugin_id: PluginId::new("kalareach.codex").expect("valid"),
                action: ActionName::new("prompt.submit").expect("valid"),
                draft_id: Nullable::null(),
                parameters: Bytes::from(b"{}".to_vec()),
            },
            TimestampMs::new(2),
        )
        .expect("the invocation is admitted");

    // The journal faults while the component is preparing its plan.
    broker
        .enter_volatile("the journal could not be written", TimestampMs::new(3))
        .expect("the fence comes down");
    let refusal = broker
        .validate_effect(
            &admitted,
            &kr_protocol::broker::PreparedEffect {
                action: ActionName::new("prompt.submit").expect("valid"),
                class: EffectClass::Write,
                operation: kr_protocol::broker::PreparedOperation::UpstreamSubmit,
                draft_id: Nullable::null(),
                argument_hash: arguments_digest(),
            },
        )
        .expect_err("rich work is fenced");
    assert_eq!(refusal.code(), ErrorCode::UpstreamUnavailable);
    assert!(
        broker
            .record_plugin_action(&admitted, TimestampMs::new(4))
            .is_err(),
        "and nothing carries a plan this host did not validate"
    );
    assert!(upstream.submitted().is_empty());
}

/// A draft store whose draft moves between one read and the next.
#[derive(Debug)]
struct MovingDrafts {
    draft_id: kr_protocol::ids::DraftId,
    revision: std::sync::atomic::AtomicU64,
}

impl MovingDrafts {
    fn moved(&self) {
        self.revision
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl kr_worker::broker::DraftResolver for MovingDrafts {
    fn resolve(
        &self,
        draft_id: &kr_protocol::ids::DraftId,
    ) -> Result<kr_worker::broker::DraftSnapshot, BrokerError> {
        if draft_id == &self.draft_id {
            Ok(kr_worker::broker::DraftSnapshot {
                draft_id: *draft_id,
                revision: kr_protocol::scalars::U64::new(
                    self.revision.load(std::sync::atomic::Ordering::SeqCst),
                ),
            })
        } else {
            Err(BrokerError::PreconditionFailed {
                detail: format!("no draft {draft_id}"),
            })
        }
    }
}

/// Forwards one request and interprets it, the way a live gateway does.
fn offered(broker: &Broker, id: &str, at: u64) -> kr_protocol::gateway::PendingResource {
    let opaque = broker
        .forward_native(
            GatewayConnectionId::new(1),
            format!(r#"{{"id":{id},"method":"session/request_permission"}}"#).as_bytes(),
            TimestampMs::new(at),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response");
    broker
        .interpret(
            binding(),
            opaque.resource_id,
            projection(),
            None,
            TimestampMs::new(at + 1),
        )
        .expect("interpreted")
}

/// KR-REQ-11.27: two callers reach one admission at the same moment, and one answer goes.
///
/// The exclusion is not "the second caller arrives later and finds the resource settled": both
/// callers are inside the same admission at once, and what separates them is the permit, which
/// only one of them can take. The loser transmits nothing, and it does not record the winner's
/// answer as uncertain.
#[test]
fn kr_req_11_27_two_callers_on_one_admission_at_once_transmit_once() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    let resource = offered(&broker, "11", 2);
    let admitted = broker
        .admit_approval(
            &caller(),
            &AgentApprovalRespondParams {
                target: target(1),
                resource_id: resource.resource_id,
                option_id: "allow".to_owned(),
            },
            TimestampMs::new(4),
        )
        .expect("the answer is admitted once");

    let start = std::sync::Barrier::new(2);
    let (first, second) = std::thread::scope(|scope| {
        let one = scope.spawn(|| {
            start.wait();
            broker.record_approval(&admitted, TimestampMs::new(5))
        });
        let two = scope.spawn(|| {
            start.wait();
            broker.record_approval(&admitted, TimestampMs::new(5))
        });
        (
            one.join().expect("the thread finished"),
            two.join().expect("the thread finished"),
        )
    });

    let refused = match (first, second) {
        (Ok(applied), Err(refused)) | (Err(refused), Ok(applied)) => {
            assert_eq!(applied.state, PendingState::Resolved);
            refused
        }
        (Ok(_), Ok(_)) => panic!("one admission carries one answer"),
        (Err(one), Err(two)) => panic!("one of the two answers goes: {one:?} and {two:?}"),
    };
    assert!(
        matches!(refused, BrokerError::AlreadyTransmitted),
        "the loser is told the answer has gone, not that the resource is uncertain: {refused:?}"
    );
    assert_eq!(
        upstream.submitted().len(),
        1,
        "one answer reached the upstream"
    );
    assert_eq!(
        broker
            .recorded(resource.resource_id)
            .expect("readable")
            .expect("retained")
            .state,
        PendingState::Resolved,
        "and the winner's resolution is what stands"
    );
}

/// KR-REQ-23.30: a draft that moves while a component prepares its plan leaves nothing to carry.
///
/// The invocation binds to the revision the draft stood at when it was admitted. A plan prepared
/// against that revision is not a plan against what the draft holds now, and the difference is
/// `DRAFT_CONFLICT` rather than an operation on a draft nobody admitted.
#[test]
fn kr_req_23_30_a_draft_that_moved_while_the_plan_was_prepared_transmits_nothing() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    let draft_id = kr_protocol::ids::DraftId::new(Uuid::from_bytes([4; 16]));
    let drafts = std::sync::Arc::new(MovingDrafts {
        draft_id,
        revision: std::sync::atomic::AtomicU64::new(1),
    });
    broker.bind_drafts(std::sync::Arc::clone(&drafts) as _);
    broker
        .register_actions(
            binding(),
            [RegisteredAction {
                name: ActionName::new("draft.attach").expect("valid"),
                grant: BrokerGrant::UpstreamAction,
                effect: EffectClass::Write,
                capability: Some(capability("agent.prompt")),
                needs_draft: true,
                operation: kr_protocol::broker::PreparedOperation::UpstreamAttachment,
            }],
        )
        .expect("the action is registered");
    let params = PluginActionInvokeParams {
        target: target(1),
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        action: ActionName::new("draft.attach").expect("valid"),
        draft_id: Nullable::some(draft_id),
        parameters: Bytes::from(b"{}".to_vec()),
    };
    let effect = kr_protocol::broker::PreparedEffect {
        action: ActionName::new("draft.attach").expect("valid"),
        class: EffectClass::Write,
        operation: kr_protocol::broker::PreparedOperation::UpstreamAttachment,
        draft_id: Nullable::some(draft_id),
        argument_hash: arguments_digest(),
    };

    let admitted = broker
        .admit_plugin_action(&caller(), binding(), &params, TimestampMs::new(4))
        .expect("the invocation is admitted against the draft as it stands");
    // The person edits the draft while the component is preparing its plan.
    drafts.moved();
    let refusal = broker
        .validate_effect(&admitted, &effect)
        .expect_err("the plan was prepared against a draft that has moved");
    assert_eq!(refusal.code(), ErrorCode::DraftConflict);
    assert!(
        broker
            .record_plugin_action(&admitted, TimestampMs::new(5))
            .is_err(),
        "and an invocation with no validated plan has nothing to transmit"
    );
    assert!(
        upstream.submitted().is_empty(),
        "no frame went for a draft nobody admitted"
    );
}

/// KR-REQ-11.28: arguments that name a member twice are refused before anything is marked.
///
/// The parse keeps the last member and another reader of the same bytes may keep the first, so
/// what this host hashed would not be what the upstream acted on. The refusal is at admission,
/// where it is a rejection rather than an outcome nobody can establish.
#[test]
fn kr_req_11_28_arguments_that_name_a_member_twice_are_refused_before_the_marker() {
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
    broker
        .register_actions(
            binding(),
            [RegisteredAction {
                name: ActionName::new("prompt.submit").expect("valid"),
                grant: BrokerGrant::UpstreamAction,
                effect: EffectClass::Write,
                capability: Some(capability("agent.prompt")),
                needs_draft: false,
                operation: kr_protocol::broker::PreparedOperation::UpstreamSubmit,
            }],
        )
        .expect("the action is registered");
    let invoke = |parameters: &[u8]| {
        broker.admit_plugin_action(
            &caller(),
            binding(),
            &PluginActionInvokeParams {
                target: target(1),
                plugin_id: PluginId::new("kalareach.codex").expect("valid"),
                action: ActionName::new("prompt.submit").expect("valid"),
                draft_id: Nullable::null(),
                parameters: Bytes::from(parameters.to_vec()),
            },
            TimestampMs::new(4),
        )
    };

    let refusal = invoke(br#"{"text":"first","text":"second"}"#)
        .expect_err("two members of one name are two readings of the same bytes");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    assert!(
        upstream.submitted().is_empty(),
        "nothing went for arguments this host would not carry"
    );
    invoke(br#"{"text":"first"}"#).expect("one member of each name is carried");
}

/// KR-REQ-11.27 and KR-REQ-11.33: the two answer paths race for one resource and one wins.
///
/// The rich answer and the person's own answer in the terminal are started at the same moment.
/// Whichever takes the resource's one transmission admission is the one that writes; the other
/// writes nothing, and the resource carries one resolution either way.
#[test]
fn kr_req_11_27_the_native_and_rich_answers_race_and_one_of_them_writes() {
    for attempt in 0..16u64 {
        let upstream = std::sync::Arc::new(RecordingUpstream::default());
        let broker = agent_broker_with(std::sync::Arc::clone(&upstream));
        let resource = offered(&broker, "11", 2);
        let carried = std::sync::Mutex::new(Vec::new());
        let start = std::sync::Barrier::new(2);

        let (rich, native) = std::thread::scope(|scope| {
            let one = scope.spawn(|| {
                start.wait();
                broker.agent_approval_respond(
                    &caller(),
                    &AgentApprovalRespondParams {
                        target: target(1),
                        resource_id: resource.resource_id,
                        option_id: "allow".to_owned(),
                    },
                    TimestampMs::new(4),
                )
            });
            let two = scope.spawn(|| {
                start.wait();
                broker.native_answer_through(
                    GatewayConnectionId::new(1),
                    br#"{"id":11,"result":{"outcome":"allow"}}"#,
                    TimestampMs::new(4),
                    |bytes| {
                        carried
                            .lock()
                            .expect("the record is not poisoned")
                            .push(bytes.to_vec());
                        Ok(())
                    },
                )
            });
            (
                one.join().expect("the thread finished"),
                two.join().expect("the thread finished"),
            )
        });

        let native_frames = carried.lock().expect("the record is not poisoned").len();
        let rich_frames = upstream.submitted().len();
        assert_eq!(
            usize::from(rich.is_ok()) + usize::from(native.is_ok()),
            1,
            "attempt {attempt}: one of the two answers takes the admission"
        );
        assert_eq!(
            rich_frames + native_frames,
            1,
            "attempt {attempt}: exactly one answer reached the upstream"
        );
        assert_eq!(
            usize::from(rich.is_ok()),
            rich_frames,
            "attempt {attempt}: the loser wrote nothing"
        );
        let recorded = broker
            .recorded(resource.resource_id)
            .expect("readable")
            .expect("retained");
        assert_eq!(
            recorded.state,
            PendingState::Resolved,
            "attempt {attempt}: one resolution, whichever writer made it"
        );
    }
}
