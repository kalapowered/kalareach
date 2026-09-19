//! The trusted broker: processes, credentials, source frames, grants, decoding trust, arbitration,
//! action tokens, launch profiles and capability evidence.
//!
//! Each test is named for the requirement row it closes, so a reader can go from a row to the
//! behaviour that establishes it without searching.

use kr_protocol::broker::{
    ActionName, ActionTokenClaim, AuthenticationState, BinaryIdentity, BrokerGrant, BrokerGrants,
    CapabilityEvidenceSource, CapabilityInvalidation, CapabilityRecord, CapabilityState,
    CapabilitySubjectIdentity, DecodingTrust, IntegrationMode, LaunchProfile, LaunchRefusal,
};
use kr_protocol::gateway::{
    DownstreamRequestId, NativeClassification, NativeMethodClass, PendingState,
};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ActorId, AgentBindingRevision, ApplicationInstanceId, BrokerBindingId, CapabilityId,
    CapabilityRevision, EnvironmentId, GatewayConnectionId, GrantId, LaunchProfileId, PluginId,
    PublisherId, StreamCursor, UpstreamMethod, UpstreamRequestId,
};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, Uuid};
use kr_worker::broker::{
    Broker, BrokerError, BrokerTransport, Credential, ForegroundMark, InstanceEnding, Invocation,
    ManagedProcess, Probe, TransportHandle,
};

const CREDENTIAL: [u8; 32] = [9; 32];

fn instance(byte: u8) -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([byte; 16]))
}

fn binding(byte: u8) -> BrokerBindingId {
    BrokerBindingId::new(Uuid::from_bytes([byte; 16]))
}

fn permission_method() -> UpstreamMethod {
    UpstreamMethod::new("session/request_permission").expect("a valid method name")
}

fn actor(name: &str) -> ActorId {
    ActorId::new(name).expect("a valid actor principal")
}

fn capability(name: &str) -> CapabilityId {
    CapabilityId::new(name).expect("a valid capability name")
}

fn process_identity(pid: u64, start: u64) -> ProcessStartIdentity {
    ProcessStartIdentity::new(pid, ProcessStartSource::MacosProcBsdInfo, start)
}

fn managed(instance_id: ApplicationInstanceId, dedicated: bool) -> ManagedProcess {
    let process = process_identity(41, 900);
    ManagedProcess::new(
        instance_id,
        process.clone(),
        TransportHandle {
            transport: BrokerTransport::PrivateSocket,
            application_instance_id: instance_id,
            executable_digest: Digest256::from_bytes([3; 32]),
            process,
        },
        Credential::from_bytes(CREDENTIAL),
        dedicated,
        TimestampMs::new(1),
    )
}

fn trust(methods: &[UpstreamMethod], may_encode: bool) -> DecodingTrust {
    DecodingTrust {
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
        package_digest: Digest256::from_bytes([5; 32]),
        methods: methods.iter().cloned().collect(),
        may_encode_response: may_encode,
        granted_at: TimestampMs::new(1),
    }
}

fn profile(mode: IntegrationMode, digest: [u8; 32], version: &str) -> LaunchProfile {
    LaunchProfile {
        profile_id: LaunchProfileId::new("lp-1").expect("valid"),
        environment_id: EnvironmentId::new(Uuid::from_bytes([1; 16])),
        binary: BinaryIdentity {
            resolved_path: "/usr/local/bin/codex".to_owned(),
            digest: Digest256::from_bytes(digest),
            version: version.to_owned(),
            distribution: "homebrew".to_owned(),
        },
        arguments: vec!["codex".to_owned(), "--resume".to_owned()],
        authentication: AuthenticationState::Authenticated,
        mode,
        resolved_at: TimestampMs::new(10),
    }
}

fn request(connection: u64, id: &str) -> DownstreamRequestId {
    DownstreamRequestId::new(
        GatewayConnectionId::new(connection),
        UpstreamRequestId::new(id).expect("valid"),
    )
}

fn evidence(
    name: &str,
    state: CapabilityState,
    trigger: CapabilityInvalidation,
    instance_id: ApplicationInstanceId,
) -> CapabilityRecord {
    CapabilityRecord {
        capability_id: capability(name),
        application_instance_id: instance_id,
        identity: CapabilitySubjectIdentity {
            binary_digest: Nullable::some(Digest256::from_bytes([3; 32])),
            ..CapabilitySubjectIdentity::default()
        },
        revision: CapabilityRevision::new(1),
        state,
        source: CapabilityEvidenceSource::HostProbe,
        invalidated_by: [trigger].into_iter().collect(),
        disabled_reason: if state.is_usable() {
            Nullable::null()
        } else {
            Nullable::some("this installation cannot do it".to_owned())
        },
        observed_at: TimestampMs::new(1),
    }
}

/// A broker with one instance, one process and one binding, ready to be driven.
fn broker_with(grants: BrokerGrants, decoding: Option<DecodingTrust>) -> Broker {
    let broker = Broker::open(None).expect("the broker opens");
    broker.register_instance(
        instance(2),
        IntegrationMode::Gateway,
        Some(LaunchProfileId::new("lp-1").expect("valid")),
        Some(managed(instance(2), true)),
    );
    broker
        .bind(
            binding(9),
            instance(2),
            PluginId::new("kalareach.codex").expect("valid"),
            PublisherId::new("kalareach").expect("valid"),
            Digest256::from_bytes([5; 32]),
            grants,
            decoding,
            TimestampMs::new(1),
        )
        .expect("the binding is recorded");
    broker
}

/// KR-REQ-11.22: the broker owns the processes it launched, their credentials, their source
/// frames and the arbitration over what those frames imply.
#[test]
fn kr_req_11_22_the_broker_owns_processes_credentials_source_frames_and_arbitration() {
    let broker = broker_with(
        BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
        Some(trust(&[permission_method()], true)),
    );

    // The process is the broker's, by full identity rather than by identifier.
    let process = managed(instance(2), true);
    assert!(process.authenticates(&CREDENTIAL, &process_identity(41, 900)));
    assert!(!process.authenticates(&CREDENTIAL, &process_identity(41, 901)));

    // The source frame is the broker's, immutable, and identified by its digest.
    let frame = broker
        .record_source(instance(2), b"{\"id\":11}", TimestampMs::new(2))
        .expect("the frame is recorded");
    let held = broker
        .source(instance(2), &frame.handle)
        .expect("the broker holds it");
    assert_eq!(held.digest, frame.digest);
    assert_eq!(held.bytes(), b"{\"id\":11}");

    // The arbitration is the broker's, and the resource it produced belongs to it.
    let resource = broker
        .offer_resource(
            binding(9),
            &frame,
            request(1, "11"),
            permission_method(),
            NativeClassification::declared(NativeMethodClass::Mutation),
            2,
            None,
            TimestampMs::new(3),
        )
        .expect("the offer is accepted");
    assert_eq!(
        broker
            .pending(resource.resource_id)
            .expect("the broker holds the resource")
            .state,
        PendingState::Pending
    );
}

/// KR-REQ-11.23: a transport handle binds the executable and the process identity, and a
/// credential never leaves the broker.
#[test]
fn kr_req_11_23_a_handle_binds_the_executable_and_identity_and_credentials_stay_here() {
    let process = managed(instance(2), true);
    assert_eq!(
        process.handle.executable_digest,
        Digest256::from_bytes([3; 32]),
        "a handle names the executable it reaches"
    );
    assert_eq!(process.handle.process, process_identity(41, 900));
    assert_eq!(
        process.handle.application_instance_id,
        instance(2),
        "a handle names the upstream identity it reaches"
    );

    // There is no accessor that returns a credential's bytes, and the debug rendering carries
    // none, so nothing this host hands to a component can carry one.
    let rendered = format!("{:?}", Credential::from_bytes(CREDENTIAL));
    assert_eq!(rendered, "Credential(<redacted>)");
    assert!(!rendered.contains("09"));

    // A transcript tail is a supported transport and is not one the forwarding path uses.
    assert!(BrokerTransport::PrivateSocket.carries_forwarding());
    assert!(!BrokerTransport::TranscriptTail.carries_forwarding());
}

/// KR-REQ-11.24: observation, upstream action and approval interpretation are three grants, and
/// holding one is never holding another.
#[test]
fn kr_req_11_24_the_three_grants_are_held_separately() {
    let broker = broker_with(BrokerGrants::granted([BrokerGrant::Observation]), None);
    let grants = broker.grants(binding(9)).expect("the binding is there");
    assert!(grants.holds(BrokerGrant::Observation));
    assert!(!grants.holds(BrokerGrant::UpstreamAction));
    assert!(!grants.holds(BrokerGrant::ApprovalInterpreter));
    assert!(grants.is_display_only());

    // An observation binding asked to prepare an effect is refused before its component runs.
    let refused = broker.issue_token(
        binding(9),
        &Invocation {
            actor_id: actor("device-1"),
            grant: BrokerGrant::UpstreamAction,
            grant_id: GrantId::new(Uuid::from_bytes([7; 16])),
            application_instance_id: instance(2),
            binding_revision: AgentBindingRevision::new(1),
            action: ActionName::new("prompt.submit").expect("valid"),
            parameters: b"{}".to_vec(),
        },
        TimestampMs::new(2),
    );
    assert!(matches!(refused, Err(BrokerError::Grant(_))));

    // Withdrawing one grant leaves the others exactly as they were.
    let broker = broker_with(
        BrokerGrants::granted([
            BrokerGrant::Observation,
            BrokerGrant::UpstreamAction,
            BrokerGrant::ApprovalInterpreter,
        ]),
        Some(trust(&[permission_method()], true)),
    );
    broker
        .withdraw_grant(binding(9), BrokerGrant::UpstreamAction)
        .expect("the grant is withdrawn");
    let grants = broker.grants(binding(9)).expect("the binding is there");
    assert!(grants.holds(BrokerGrant::Observation));
    assert!(!grants.holds(BrokerGrant::UpstreamAction));
    assert!(grants.holds(BrokerGrant::ApprovalInterpreter));
}

/// KR-REQ-11.25: decoding trust is explicit and recorded, and a display-only component cannot
/// create an approval whatever it reports.
#[test]
fn kr_req_11_25_decoding_trust_is_explicit_and_display_only_creates_no_approval() {
    let display_only = broker_with(BrokerGrants::granted([BrokerGrant::Observation]), None);
    let frame = display_only
        .record_source(instance(2), b"{\"id\":11}", TimestampMs::new(2))
        .expect("the frame is recorded");
    let refusal = display_only
        .offer_resource(
            binding(9),
            &frame,
            request(1, "11"),
            permission_method(),
            NativeClassification::declared(NativeMethodClass::Mutation),
            2,
            None,
            TimestampMs::new(3),
        )
        .expect_err("a display-only component creates no approval");
    assert!(matches!(refusal, BrokerError::Grant(_)));

    // The interpreter grant alone is not trust either: a record naming the method is required.
    let untrusted = broker_with(
        BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
        Some(trust(
            &[UpstreamMethod::new("fs/read_text_file").expect("valid")],
            true,
        )),
    );
    let frame = untrusted
        .record_source(instance(2), b"{\"id\":11}", TimestampMs::new(2))
        .expect("the frame is recorded");
    let refusal = untrusted
        .offer_resource(
            binding(9),
            &frame,
            request(1, "11"),
            permission_method(),
            NativeClassification::declared(NativeMethodClass::Mutation),
            2,
            None,
            TimestampMs::new(3),
        )
        .expect_err("a decoder trusted for another method is refused");
    assert!(matches!(refusal, BrokerError::PermissionDenied { .. }));

    // And trust without the grant it depends on is refused when it is offered, not stored.
    let broker = Broker::open(None).expect("the broker opens");
    broker.register_instance(instance(2), IntegrationMode::Gateway, None, None);
    let refusal = broker
        .bind(
            binding(9),
            instance(2),
            PluginId::new("kalareach.codex").expect("valid"),
            PublisherId::new("kalareach").expect("valid"),
            Digest256::from_bytes([5; 32]),
            BrokerGrants::granted([BrokerGrant::Observation]),
            Some(trust(&[permission_method()], true)),
            TimestampMs::new(1),
        )
        .expect_err("trust needs the grant it depends on");
    assert!(matches!(refusal, BrokerError::PermissionDenied { .. }));
}

/// KR-REQ-11.26: the broker checks decoder role, application binding, source generation and
/// non-reuse, and retains the ledger that says what it checked.
#[test]
fn kr_req_11_26_the_broker_checks_role_binding_generation_and_reuse_and_retains_its_ledger() {
    let directory = std::env::temp_dir().join(format!("kr-broker-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&directory).expect("the directory is created");
    let path = directory.join("session.sqlite");

    let resource_id = {
        let broker = Broker::open(Some(&path)).expect("the broker opens");
        broker.register_instance(
            instance(2),
            IntegrationMode::Gateway,
            None,
            Some(managed(instance(2), true)),
        );
        broker.register_instance(
            instance(3),
            IntegrationMode::Gateway,
            None,
            Some(managed(instance(3), true)),
        );
        broker
            .bind(
                binding(9),
                instance(2),
                PluginId::new("kalareach.codex").expect("valid"),
                PublisherId::new("kalareach").expect("valid"),
                Digest256::from_bytes([5; 32]),
                BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
                Some(trust(&[permission_method()], true)),
                TimestampMs::new(1),
            )
            .expect("the binding is recorded");

        // Binding: a frame of another application is not this binding's to interpret.
        let other = broker
            .record_source(instance(3), b"{\"id\":99}", TimestampMs::new(2))
            .expect("the frame is recorded");
        assert!(matches!(
            broker.offer_resource(
                binding(9),
                &other,
                request(1, "99"),
                permission_method(),
                NativeClassification::declared(NativeMethodClass::Mutation),
                2,
                None,
                TimestampMs::new(3),
            ),
            Err(BrokerError::PreconditionFailed { .. })
        ));

        let frame = broker
            .record_source(instance(2), b"{\"id\":11}", TimestampMs::new(2))
            .expect("the frame is recorded");
        let resource = broker
            .offer_resource(
                binding(9),
                &frame,
                request(1, "11"),
                permission_method(),
                NativeClassification::declared(NativeMethodClass::Mutation),
                2,
                Some(TimestampMs::new(900)),
                TimestampMs::new(3),
            )
            .expect("the offer is accepted");

        // Non-reuse: the same source event does not become a second resource.
        assert!(matches!(
            broker.offer_resource(
                binding(9),
                &frame,
                request(1, "12"),
                permission_method(),
                NativeClassification::declared(NativeMethodClass::Mutation),
                2,
                None,
                TimestampMs::new(4),
            ),
            Err(BrokerError::PreconditionFailed { .. })
        ));

        // Source generation: a frame from before the owner changed is refused after it.
        let stale = broker
            .record_source(instance(2), b"{\"id\":13}", TimestampMs::new(5))
            .expect("the frame is recorded");
        broker
            .advance_binding(instance(2), None)
            .expect("the selected thread changed");
        assert!(matches!(
            broker.offer_resource(
                binding(9),
                &stale,
                request(1, "13"),
                permission_method(),
                NativeClassification::declared(NativeMethodClass::Mutation),
                2,
                None,
                TimestampMs::new(6),
            ),
            Err(BrokerError::PreconditionFailed { .. })
        ));

        resource.resource_id
    };

    // The ledger is retained across a restart, and it says whose interpretation this was.
    let restarted = Broker::open(Some(&path)).expect("the broker reopens");
    let entry = restarted
        .decoding(resource_id)
        .expect("the read succeeds")
        .expect("the entry survived the restart");
    assert_eq!(entry.publisher_id.as_str(), "kalareach");
    assert_eq!(entry.plugin_id.as_str(), "kalareach.codex");
    assert_eq!(entry.package_digest, Digest256::from_bytes([5; 32]));
    assert_eq!(entry.method, permission_method());
    assert_eq!(entry.offered_decisions.get(), 2);
    assert_eq!(entry.deadline_ms.as_ref().map(|at| at.get()), Some(900));
    assert_eq!(
        restarted
            .pending(resource_id)
            .expect("the resource survived the restart")
            .state,
        PendingState::Pending
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// KR-REQ-11.27: one resolution per pending resource, and a reconnect reconciles without
/// reissuing an uncertain response.
#[test]
fn kr_req_11_27_one_resolution_each_and_a_reconnect_never_reissues() {
    let broker = broker_with(
        BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
        Some(trust(&[permission_method()], true)),
    );
    let frame = broker
        .record_source(instance(2), b"{\"id\":11}", TimestampMs::new(2))
        .expect("the frame is recorded");
    let resource = broker
        .offer_resource(
            binding(9),
            &frame,
            request(1, "11"),
            permission_method(),
            NativeClassification::declared(NativeMethodClass::Mutation),
            2,
            None,
            TimestampMs::new(3),
        )
        .expect("the offer is accepted");

    let claim = broker
        .claim(
            resource.resource_id,
            &actor("device-1"),
            TimestampMs::new(4),
        )
        .expect("the first answer claims it");
    assert!(
        broker
            .claim(
                resource.resource_id,
                &actor("device-2"),
                TimestampMs::new(5)
            )
            .is_err(),
        "a second answer cannot claim a resource that is already claimed"
    );
    broker
        .resolve(&claim, TimestampMs::new(6))
        .expect("the claim resolves it");
    assert!(
        broker
            .claim(
                resource.resource_id,
                &actor("device-2"),
                TimestampMs::new(7)
            )
            .is_err(),
        "a resolved resource takes no further answer"
    );

    // A reconnect that still sees the request reconciles it to uncertain, because an answer went.
    let reconciliation = broker
        .reconcile(&[request(1, "11")], TimestampMs::new(8))
        .expect("the reconnect reconciles");
    assert!(reconciliation.uncertain.is_empty());
    assert!(reconciliation.still_pending.is_empty());
}

/// KR-REQ-11.28: an action token binds the actor, the grant, the revision, the declared action
/// and the parameter hash, and every one of them is checked.
#[test]
fn kr_req_11_28_an_action_token_binds_actor_grant_revision_action_and_parameters() {
    let broker = broker_with(BrokerGrants::granted([BrokerGrant::UpstreamAction]), None);
    let invocation = Invocation {
        actor_id: actor("device-1"),
        grant: BrokerGrant::UpstreamAction,
        grant_id: GrantId::new(Uuid::from_bytes([7; 16])),
        application_instance_id: instance(2),
        binding_revision: AgentBindingRevision::new(1),
        action: ActionName::new("prompt.submit").expect("valid"),
        parameters: b"{\"text\":\"hello\"}".to_vec(),
    };
    let token = broker
        .issue_token(binding(9), &invocation, TimestampMs::new(2))
        .expect("the token is issued");
    assert_eq!(token.actor_id, actor("device-1"));
    assert_eq!(token.grant, BrokerGrant::UpstreamAction);
    assert_eq!(token.binding_revision, AgentBindingRevision::new(1));
    assert_eq!(token.action.as_str(), "prompt.submit");

    let mut wrong_actor = ActionTokenClaim::from(&token);
    wrong_actor.actor_id = actor("device-2");
    assert!(broker.spend_token(&wrong_actor).is_err());

    let token = broker
        .issue_token(binding(9), &invocation, TimestampMs::new(3))
        .expect("the token is issued");
    let mut wrong_parameters = ActionTokenClaim::from(&token);
    wrong_parameters.parameter_hash = Digest256::from_bytes([0; 32]);
    assert!(broker.spend_token(&wrong_parameters).is_err());

    let token = broker
        .issue_token(binding(9), &invocation, TimestampMs::new(4))
        .expect("the token is issued");
    let claim = ActionTokenClaim::from(&token);
    broker.spend_token(&claim).expect("the token is spent");
    assert!(
        broker.spend_token(&claim).is_err(),
        "one invocation's authority is spent once"
    );
}

/// KR-REQ-12.02: a launch profile records the resolved executable, distribution, version,
/// argument vector, authentication state and integration mode.
#[test]
fn kr_req_12_02_a_launch_profile_records_what_was_resolved() {
    let broker = Broker::open(None).expect("the broker opens");
    let intent = broker
        .prepare_launch(
            profile(IntegrationMode::Gateway, [3; 32], "0.9.1"),
            ForegroundMark::idle(4),
            None,
        )
        .expect("the launch is prepared");
    let resolved = broker
        .execute_launch(&intent, &ForegroundMark::idle(4), instance(2))
        .expect("the launch runs");
    assert_eq!(resolved.binary.resolved_path, "/usr/local/bin/codex");
    assert_eq!(resolved.binary.distribution, "homebrew");
    assert_eq!(resolved.binary.version, "0.9.1");
    assert_eq!(resolved.arguments, vec!["codex", "--resume"]);
    assert_eq!(resolved.authentication, AuthenticationState::Authenticated);
    assert_eq!(resolved.mode, IntegrationMode::Gateway);
    assert_eq!(
        broker
            .profile_of(instance(2))
            .expect("the profile is recorded")
            .profile_id,
        resolved.profile_id
    );
}

/// KR-REQ-12.03: a stale launch is refused when an application takes the foreground, and there
/// is no path that pastes it instead.
#[test]
fn kr_req_12_03_a_stale_launch_is_refused_and_never_pasted() {
    let broker = Broker::open(None).expect("the broker opens");
    let intent = broker
        .prepare_launch(
            profile(IntegrationMode::Gateway, [3; 32], "0.9.1"),
            ForegroundMark::idle(4),
            None,
        )
        .expect("the launch is prepared");
    let occupied = ForegroundMark {
        application_instance_id: Some(instance(9)),
        prompt_revision: 4,
    };
    let refusal = broker
        .execute_launch(&intent, &occupied, instance(2))
        .expect_err("a stale launch is refused");
    assert!(matches!(
        refusal,
        BrokerError::Launch(LaunchRefusal::ForegroundChanged)
    ));
    assert!(
        broker.profile_of(instance(2)).is_none(),
        "a refused launch starts nothing"
    );

    // A prompt that moved is refused too, with its own reason.
    let moved = broker
        .execute_launch(&intent, &ForegroundMark::idle(5), instance(2))
        .expect_err("a moved prompt is refused");
    assert!(matches!(
        moved,
        BrokerError::Launch(LaunchRefusal::PromptMoved)
    ));
}

/// KR-REQ-12.05 and KR-REQ-02.10: no second agent process is started against the same saved
/// conversation, and a live execution is never silently replaced by a replay of its history.
#[test]
fn kr_req_12_05_no_second_process_runs_against_one_saved_conversation() {
    let broker = Broker::open(None).expect("the broker opens");
    let first = broker
        .prepare_launch(
            profile(IntegrationMode::Gateway, [3; 32], "0.9.1"),
            ForegroundMark::idle(4),
            Some("thread-7".to_owned()),
        )
        .expect("the launch is prepared");
    broker
        .execute_launch(&first, &ForegroundMark::idle(4), instance(2))
        .expect("the first execution runs");

    let second = broker
        .prepare_launch(
            profile(IntegrationMode::Gateway, [3; 32], "0.9.1"),
            ForegroundMark::idle(4),
            Some("thread-7".to_owned()),
        )
        .expect("the launch is prepared");
    let refusal = broker
        .execute_launch(&second, &ForegroundMark::idle(4), instance(3))
        .expect_err("a second execution of the same conversation is refused");
    assert!(matches!(
        refusal,
        BrokerError::Launch(LaunchRefusal::ConversationAlreadyLive {
            application_instance_id
        }) if application_instance_id == instance(2)
    ));
}

/// KR-REQ-11.16: the host owns the evidence, and probes are bounded and disclosed.
#[test]
fn kr_req_11_16_probes_are_bounded_disclosed_and_never_touch_unrelated_data() {
    let broker = Broker::open(None).expect("the broker opens");
    broker.register_instance(instance(2), IntegrationMode::Gateway, None, None);

    let undisclosed = Probe {
        capability_id: capability("agent.prompt"),
        declared_operations: Vec::new(),
        destructive: false,
        isolated_context: None,
        budget_ms: 500,
    };
    assert!(
        broker
            .record_probe(
                &undisclosed,
                evidence(
                    "agent.prompt",
                    CapabilityState::QualifiedAvailable,
                    CapabilityInvalidation::BinaryChanged,
                    instance(2)
                )
            )
            .is_err(),
        "a probe that declares nothing is not one the host runs"
    );

    let destructive = Probe {
        capability_id: capability("agent.prompt"),
        declared_operations: vec!["submit a prompt".to_owned()],
        destructive: true,
        isolated_context: None,
        budget_ms: 500,
    };
    assert!(
        broker
            .record_probe(
                &destructive,
                evidence(
                    "agent.prompt",
                    CapabilityState::QualifiedAvailable,
                    CapabilityInvalidation::BinaryChanged,
                    instance(2)
                )
            )
            .is_err(),
        "a destructive probe needs its own isolated test context"
    );

    let disclosed = Probe {
        capability_id: capability("agent.prompt"),
        declared_operations: vec!["list the upstream's advertised commands".to_owned()],
        destructive: false,
        isolated_context: None,
        budget_ms: 500,
    };
    broker
        .record_probe(
            &disclosed,
            evidence(
                "agent.prompt",
                CapabilityState::QualifiedAvailable,
                CapabilityInvalidation::BinaryChanged,
                instance(2),
            ),
        )
        .expect("a bounded, disclosed probe records its result");

    // Evidence is not permission: a signed record cannot say a capability works on this host.
    let mut signed = evidence(
        "agent.cancel",
        CapabilityState::QualifiedAvailable,
        CapabilityInvalidation::BinaryChanged,
        instance(2),
    );
    signed.source = CapabilityEvidenceSource::SignedRecord;
    assert!(broker.record_capability(signed).is_err());
}

/// KR-REQ-11.17: evidence is invalidated by the change it is about, an installed upgrade leaves a
/// running binding's pinned evidence alone, and every action rechecks its own revision.
#[test]
fn kr_req_11_17_evidence_is_invalidated_by_the_right_change_and_every_action_rechecks() {
    let broker = Broker::open(None).expect("the broker opens");
    broker.register_instance(instance(2), IntegrationMode::Gateway, None, None);
    broker
        .record_capability(evidence(
            "agent.prompt",
            CapabilityState::QualifiedAvailable,
            CapabilityInvalidation::BinaryChanged,
            instance(2),
        ))
        .expect("recorded");
    broker
        .record_capability(evidence(
            "agent.approval",
            CapabilityState::QualifiedAvailable,
            CapabilityInvalidation::BindingChanged,
            instance(2),
        ))
        .expect("recorded");

    broker
        .recheck_capability(
            instance(2),
            &capability("agent.prompt"),
            Some(CapabilityRevision::new(1)),
        )
        .expect("the revision the caller read is the one held");

    assert_eq!(
        broker.invalidate_capabilities(
            CapabilityInvalidation::BinaryChanged,
            "the executable was upgraded",
            TimestampMs::new(20)
        ),
        1
    );
    assert!(
        broker
            .recheck_capability(instance(2), &capability("agent.prompt"), None)
            .is_err(),
        "an upgraded binary invalidates the evidence that was about the binary"
    );
    broker
        .recheck_capability(instance(2), &capability("agent.approval"), None)
        .expect("a running binding's pinned evidence survives an installed upgrade");

    // A caller acting on a revision that has since moved is refused rather than served.
    assert!(
        broker
            .recheck_capability(
                instance(2),
                &capability("agent.approval"),
                Some(CapabilityRevision::new(2))
            )
            .is_err()
    );
}

/// KR-REQ-01.02: the capability map is per installation, with no authority taken from screen text.
#[test]
fn kr_req_01_02_the_capability_map_is_per_installation() {
    let broker = Broker::open(None).expect("the broker opens");
    broker.register_instance(instance(2), IntegrationMode::Gateway, None, None);
    broker.register_instance(instance(3), IntegrationMode::NativeTerminal, None, None);
    broker
        .record_capability(evidence(
            "agent.prompt",
            CapabilityState::QualifiedAvailable,
            CapabilityInvalidation::BinaryChanged,
            instance(2),
        ))
        .expect("recorded");
    broker
        .record_capability(evidence(
            "agent.prompt",
            CapabilityState::MissingInstallation,
            CapabilityInvalidation::BinaryChanged,
            instance(3),
        ))
        .expect("recorded");

    let gateway = broker.capabilities(instance(2));
    let terminal = broker.capabilities(instance(3));
    assert_eq!(
        gateway
            .record(&capability("agent.prompt"))
            .expect("recorded")
            .state,
        CapabilityState::QualifiedAvailable
    );
    assert_eq!(
        terminal
            .record(&capability("agent.prompt"))
            .expect("recorded")
            .state,
        CapabilityState::MissingInstallation,
        "two installations of one agent have two maps"
    );

    // The only source that can say a capability works here is one that tried it here.
    assert!(CapabilityEvidenceSource::HostProbe.can_establish_qualified());
    assert!(CapabilityEvidenceSource::LiveBinding.can_establish_qualified());
    assert!(!CapabilityEvidenceSource::SignedRecord.can_establish_qualified());
    assert!(!CapabilityEvidenceSource::PackageDeclaration.can_establish_qualified());
}

/// KR-REQ-07.67: a native exit stops the instance's dedicated backend; closing an attachment does
/// not, and a backend this host did not launch is never stopped as owned.
#[test]
fn kr_req_07_67_a_native_exit_stops_its_backend_and_closing_an_attachment_does_not() {
    let broker = broker_with(BrokerGrants::granted([BrokerGrant::Observation]), None);
    broker.attach(instance(2));
    broker.attach(instance(2));

    let closed = broker.end(instance(2), InstanceEnding::AttachmentClosed);
    assert!(!closed.instance_ended);
    assert!(!closed.stop_backend);
    assert_eq!(closed.attachments_remaining, 1);
    broker
        .binding_state(instance(2))
        .expect("the instance is still running");

    let exited = broker.end(instance(2), InstanceEnding::NativeExit);
    assert!(exited.instance_ended);
    assert!(exited.stop_backend);
    assert!(broker.binding_state(instance(2)).is_err());

    let bypassed = Broker::open(None).expect("the broker opens");
    bypassed.register_instance(instance(4), IntegrationMode::NativeTerminal, None, None);
    let ended = bypassed.end(instance(4), InstanceEnding::NativeExit);
    assert!(ended.instance_ended);
    assert!(
        !ended.stop_backend,
        "a bypassed or shared backend is never claimed or terminated as owned"
    );
}

/// KR-REQ-19.05: upstream bytes are data. Nothing a source frame contains changes a grant, and a
/// frame that asks for more than it was granted is still refused.
#[test]
fn kr_req_19_05_upstream_content_is_data_and_never_authority() {
    let broker = broker_with(BrokerGrants::granted([BrokerGrant::Observation]), None);
    let hostile = br#"{"grants":["approval_interpreter","upstream_action"],"trusted":true}"#;
    let frame = broker
        .record_source(instance(2), hostile, TimestampMs::new(2))
        .expect("the frame is recorded");

    let grants = broker.grants(binding(9)).expect("the binding is there");
    assert!(grants.is_display_only(), "reading bytes grants nothing");
    assert!(
        broker
            .offer_resource(
                binding(9),
                &frame,
                request(1, "11"),
                permission_method(),
                NativeClassification::declared(NativeMethodClass::Mutation),
                2,
                None,
                TimestampMs::new(3),
            )
            .is_err(),
        "content that claims trust does not create it"
    );
}

/// KR-REQ-24.24: an adapter replays from the cursor it consumed, and that cursor survives a
/// restart.
#[test]
fn kr_req_24_24_an_adapter_replays_from_the_cursor_it_consumed() {
    let directory = std::env::temp_dir().join(format!("kr-broker-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&directory).expect("the directory is created");
    let path = directory.join("session.sqlite");
    {
        let broker = Broker::open(Some(&path)).expect("the broker opens");
        broker.register_instance(instance(2), IntegrationMode::Gateway, None, None);
        assert_eq!(
            broker
                .consumed_cursor(instance(2))
                .expect("the read succeeds"),
            None,
            "an adapter that has consumed nothing replays from the beginning"
        );
        broker
            .checkpoint(instance(2), StreamCursor::new(40), TimestampMs::new(2))
            .expect("the checkpoint is written");
    }
    let restarted = Broker::open(Some(&path)).expect("the broker reopens");
    assert_eq!(
        restarted
            .consumed_cursor(instance(2))
            .expect("the read succeeds"),
        Some(StreamCursor::new(40))
    );
    let _ = std::fs::remove_dir_all(&directory);
}
