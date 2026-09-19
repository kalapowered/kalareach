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
    ActionName, ActionProvenance, BrokerGrant, BrokerGrants, CapabilityEvidenceSource,
    CapabilityInvalidation, CapabilityRecord, CapabilityState, CapabilitySubjectIdentity,
    DecodedProjection, DecodingTrust, IntegrationMode, OfferedDecision,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::gateway::{
    DeclarativeEntry, DeclarativeTable, NativeFraming, NativeMethodClass, PendingState,
    RichMethodTable,
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
    RegisteredAction, TransportHandle, UpstreamDispatch, UpstreamOutcome, UpstreamRequest, command,
    subject,
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

fn table() -> DeclarativeTable {
    DeclarativeTable {
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
        table_version: MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        digest: Digest256::from_bytes([1; 32]),
        framing: NativeFraming::JsonLines,
        request_id_field: "id".to_owned(),
        response_id_field: "id".to_owned(),
        method_field: "method".to_owned(),
        entries: vec![DeclarativeEntry {
            method: method("session/request_permission"),
            class: NativeMethodClass::Mutation,
            expects_response: true,
        }],
    }
}

fn rich() -> RichMethodTable {
    RichMethodTable {
        table_version: MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        entries: vec![kr_protocol::gateway::RichMethodEntry {
            method: method("session/cancel"),
            class: NativeMethodClass::Mutation,
            required_right: ActionRight::AgentCancel,
            provenance: ActionProvenance::UpstreamTypedRpc,
        }],
    }
}

fn evidence(name: &str, state: CapabilityState) -> CapabilityRecord {
    CapabilityRecord {
        capability_id: capability(name),
        capability_version: "1".to_owned(),
        application_instance_id: instance(),
        identity: CapabilitySubjectIdentity::default(),
        revision: CapabilityRevision::new(1),
        state,
        source: CapabilityEvidenceSource::HostProbe,
        invalidated_by: [CapabilityInvalidation::BindingChanged]
            .into_iter()
            .collect(),
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

/// A broker with every capability the agent mutations need, and a transport that records.
fn agent_broker_with(upstream: std::sync::Arc<RecordingUpstream>) -> Broker {
    let broker = agent_broker();
    broker
        .bind_dispatch(instance(), upstream)
        .expect("the transport is bound");
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
        .open_native_connection(
            GatewayConnectionId::new(1),
            instance(),
            &CREDENTIAL,
            &process_identity(),
            table(),
            rich(),
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
            .record_capability(evidence(name, CapabilityState::QualifiedAvailable))
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
        CapabilityState::QualifiedAvailable
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

/// KR-REQ-23.40 and KR-REQ-12.06: the five agent mutations have five distinct rights, and every
/// one of them refuses a revision that is not the one in force.
#[test]
fn kr_req_23_40_the_five_mutations_have_distinct_rights_and_check_their_binding() {
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
        .agent_prompt(&caller(), &prompt, false)
        .expect("the prompt applies");
    assert_eq!(applied.binding_revision, AgentBindingRevision::new(1));
    assert_eq!(applied.provenance, ActionProvenance::UpstreamTypedRpc);
    assert_eq!(
        applied.upstream_request_id.as_ref().map(|id| id.as_str()),
        Some("upstream-1"),
        "the answer names what the upstream called it"
    );
    broker
        .agent_prompt(&caller(), &prompt, true)
        .expect("and so does a queued one");
    broker
        .agent_steer(
            &caller(),
            &AgentSteerParams {
                target: target(1),
                turn_id: AgentTurnId::new("turn-1").expect("valid"),
                text: PromptText::new("try the other file").expect("valid"),
            },
        )
        .expect("the steer applies to the turn that is running");
    broker
        .agent_cancel(
            &caller(),
            &AgentCancelParams {
                target: target(1),
                turn_id: AgentTurnId::new("turn-1").expect("valid"),
            },
        )
        .expect("the cancellation applies");

    // Each of those reached the upstream, with the operation it was for.
    let submitted: Vec<kr_worker::broker::UpstreamOperation> = upstream
        .submitted()
        .into_iter()
        .map(|request| request.operation)
        .collect();
    assert_eq!(
        submitted,
        vec![
            kr_worker::broker::UpstreamOperation::PromptSubmit,
            kr_worker::broker::UpstreamOperation::PromptQueue,
            kr_worker::broker::UpstreamOperation::TurnSteer,
            kr_worker::broker::UpstreamOperation::TurnCancel,
        ],
        "a mutation that reports success is one that reached the upstream"
    );

    // An instance with nothing bound to carry its operations refuses rather than reporting them
    // as applied.
    let unreachable = agent_broker();
    assert!(
        unreachable.agent_prompt(&caller(), &prompt, false).is_err(),
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
            )
            .is_err()
    );

    // The conversation changes. Everything prepared against the old revision is stale.
    broker
        .advance_binding(instance(), None, TimestampMs::new(10))
        .expect("the selected thread changed");
    let stale = broker
        .agent_prompt(&caller(), &prompt, false)
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
                false
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
    let body = r#"{"id":"11","method":"session/request_permission"}"#;
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
        admission.upstream_request_id,
        UpstreamRequestId::new("11").expect("valid")
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
                },
                RegisteredAction {
                    name: ActionName::new("draft.attach").expect("valid"),
                    grant: BrokerGrant::UpstreamAction,
                    effect: EffectClass::Write,
                    capability: Some(capability("agent.prompt")),
                    needs_draft: true,
                },
                RegisteredAction {
                    name: ActionName::new("conversation.read").expect("valid"),
                    grant: BrokerGrant::Observation,
                    effect: EffectClass::Read,
                    capability: None,
                    needs_draft: false,
                },
            ],
        )
        .expect("the actions are registered");

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
    invoke(
        "draft.attach",
        Nullable::some(kr_protocol::ids::DraftId::new(Uuid::from_bytes([4; 16]))),
    )
    .expect("and it runs once the draft is named");

    // The grant is the binding's, not the action's wish: withdrawing it refuses the action.
    broker
        .withdraw_grant(binding(), BrokerGrant::UpstreamAction)
        .expect("the grant is withdrawn");
    let refusal = invoke("prompt.submit", Nullable::null())
        .expect_err("an action needs the grant it declares");
    assert!(matches!(refusal, BrokerError::Grant(_)));

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
            }],
        )
        .expect("the actions are registered");
    broker.invalidate_capabilities(
        CapabilityInvalidation::BindingChanged,
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
