//! Section 9 at the worker: receipts, de-duplication, revalidation, action windows, the time
//! contract and the raw input stream.
//!
//! Every test here names the contract it closes. Where the contract is about the *store* the test
//! drives the journal directly, because that is where the durability order lives; where it is
//! about the *dispatch path* the test goes through the real endpoint, the real handshake and the
//! real signatures, because a check that only holds when called directly is not a check.
//!
//! The time contract's own decisions are unit-tested beside the code that makes them, in
//! `kr_worker::action::time`, because a suspension and a wall-clock rollback are not things a test
//! can arrange with the machine's real clocks. What is here is the part that has to touch this
//! machine: the platform time adapter, read through the interface the platform actually supports,
//! and the recorded readings in `fixtures/time/adapter.json` that say what each platform's answer
//! must classify to.

use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::action::{
    ActionObservation, HostTimeState, MAX_TRUSTED_UNCERTAINTY_US, MAX_WALL_CLOCK_ROLLBACK_MS,
    ObservationProvenance, ObservedResult, RetrustEvidence, TimeSyncSource, TimeSyncStatus,
    WallClockTrust,
};
use kr_protocol::envelope::{
    ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue, Request,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, BuildId, ControllerGeneration, RequestId, SessionEpoch,
    SessionId,
};
use kr_protocol::limits::{
    DEDUPLICATION_RETENTION, DEFAULT_MUTATION_TTL, MAX_ACTION_WINDOW, MAX_CONCURRENT_ATTACHMENTS,
    MAX_CONTROL_FRAME_LEN, MAX_INPUT_FRAME_LEN, MAX_MUTATION_TTL, MAX_OUTSTANDING_MUTATIONS,
    MAX_REMOTE_DISPATCH_LEASE, MAX_SEND_QUEUE_BYTES,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::receipt::{ReceiptState, RejectionReason};
use kr_protocol::scalars::{Digest256, DurationMs, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::action::adapter::{
    PlatformTimeAdapter, TimeAdapter as _, UnixTimex, classify_unix, classify_windows,
    platform_name,
};
use kr_worker::journal::{Journal, MAX_HELD_REVOCATIONS, RETENTION_MS, Submission};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

// ---------------------------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------------------------

struct Host {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    session_id: SessionId,
    journal_path: std::path::PathBuf,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
    environment_id: kr_protocol::ids::EnvironmentId,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host() -> Host {
    host_prepared(|_| {}).await
}

/// Starts a host whose journal already holds whatever `prepare` writes into it.
///
/// That is what a host that has run before looks like: the records are there before the session
/// opens, and the host's recovery and its own maintenance are what act on them. A test that wrote
/// them afterwards would be testing a different sequence.
async fn host_prepared(prepare: impl FnOnce(&std::path::Path)) -> Host {
    host_with(prepare, |_| kr_worker::action::time::TimeSources::system()).await
}

/// Starts a host as [`host_prepared`] does, whose session's time contract reads the clocks and
/// the clock floor `time` gives it for the environment.
async fn host_with(
    prepare: impl FnOnce(&std::path::Path),
    time: impl FnOnce(&kr_ipc::paths::EnvironmentPaths) -> kr_worker::action::time::TimeSources,
) -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process,
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller = Arc::new(
        ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity"),
    );
    let journal_path = environment.journal_database(session_id);
    if let Some(parent) = journal_path.parent() {
        std::fs::create_dir_all(parent).expect("the journal directory");
    }
    prepare(&journal_path);
    let config = SessionConfig {
        time: time(&environment),
        ..session_config(&environment, session_id)
    };
    let journal_path = config
        .journal_path
        .clone()
        .expect("the harness journals its session");
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts the runtime"),
    );

    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot.clone(),
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                journal_path: Some(journal_path.clone()),
                build_id: build(),
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    Host {
        _temp: temp,
        service,
        session_id,
        journal_path,
        endpoint,
        controller,
        boot,
        environment_id,
    }
}

/// The configuration of the session every test here serves.
fn session_config(
    environment: &kr_ipc::paths::EnvironmentPaths,
    session_id: SessionId,
) -> SessionConfig {
    SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: environment.environment_id(),
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script("sleep 30"),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    }
}

async fn cli(host: &Host) -> LocalClient {
    LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects")
}

async fn controller_client(host: &Host) -> LocalClient {
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Controller, build())
        .await
        .expect("connects");
    let identity = Arc::clone(&host.controller);
    let boot = host.boot.clone();
    client
        .present_generation(move |nonce| {
            identity
                .generation_token(ControllerGeneration::new(1), &boot, nonce)
                .map_err(kr_ipc::IpcError::from)
        })
        .await
        .expect("the worker accepts the generation");
    client
}

fn target(host: &Host) -> ActionTarget {
    ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::some(host.session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// A `session.close` mutation, which is the one mutation every worker serves.
fn close_mutation(
    client: &LocalClient,
    host: &Host,
    ttl_ms: u64,
    expected: ParamsValue,
) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(91),
        method: Method::SessionClose.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: target(host),
        expected,
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: DurationMs::new(ttl_ms),
        params: ParamsValue::from_typed(&kr_protocol::session::SessionCloseParams {
            session_id: host.session_id,
        })
        .expect("encodes"),
    }
}

async fn send_mutation(client: &mut LocalClient, mutation: MutationRequest) -> Outcome {
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("writes the mutation");
    loop {
        match client.recv().await.expect("the worker answers") {
            ControlFrame::Response(response) => return response.outcome,
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

async fn send_frame(client: &mut LocalClient, frame: ControlFrame) -> Outcome {
    client
        .writer()
        .write_message(&frame)
        .await
        .expect("writes the frame");
    loop {
        match client.recv().await.expect("the worker answers") {
            ControlFrame::Response(response) => return response.outcome,
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

async fn send_request(client: &mut LocalClient, request: Request) -> Outcome {
    client
        .writer()
        .write_message(&ControlFrame::Request(request))
        .await
        .expect("writes the request");
    loop {
        match client.recv().await.expect("the worker answers") {
            ControlFrame::Response(response) => return response.outcome,
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

/// Renders one byte as the two hexadecimal digits a SQLite blob literal spells it with.
fn hex_byte(value: u8) -> String {
    format!("{value:02x}")
}

fn actor(name: &str) -> ActorId {
    ActorId::new(name).expect("a principal")
}

fn action(byte: u8) -> ActionId {
    ActionId::new(Uuid::from_bytes([byte; 16]))
}

fn submission(action: u8, digest: u8, subject: u8) -> Submission {
    at(action, digest, subject, TimestampMs::new(1_000))
}

/// A submission recorded at this machine's own wall clock.
///
/// The retention period is real: a journal a live worker writes to prunes records past it, so a
/// record seeded at a fixed moment in 1970 is gone the first time the dispatch path admits
/// anything. A test that seeds the store a running worker is serving has to seed it with a time
/// that worker would call recent.
fn fresh(action: u8, digest: u8, subject: u8) -> Submission {
    at(action, digest, subject, kr_ipc::now_ms())
}

fn at(action: u8, digest: u8, subject: u8, now_ms: TimestampMs) -> Submission {
    Submission {
        actor_id: actor("device:phone"),
        action_id: crate::action(action),
        method: Method::AgentApprovalRespond.into(),
        method_version: MethodVersion::V1,
        payload_digest: Digest256::from_bytes([digest; 32]),
        subject_digest: Digest256::from_bytes([subject; 32]),
        intent: vec![0xa0],
        accepted_deadline_ms: Some(TimestampMs::new(now_ms.get() + 120_000)),
        now_ms,
    }
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-09.03, 09.04: the transition contract and the monotonic revision
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.03: the journal writes only the transitions the section 9 table permits.
#[test]
fn the_journal_writes_only_the_transitions_section_nine_permits() {
    let mut journal = Journal::in_memory().expect("a journal");
    let accepted = journal
        .accept(&submission(1, 1, 1))
        .expect("the intent is committed")
        .receipt;
    assert_eq!(accepted.state, ReceiptState::Accepted);
    assert_eq!(accepted.revision.get(), 1);

    // accepted -> dispatching -> applied, each one revision later.
    let marked = journal
        .mark_dispatching(actor("device:phone"), action(1), TimestampMs::new(2_000))
        .expect("the marker is committed");
    assert_eq!(marked.state, ReceiptState::Dispatching);
    assert_eq!(marked.revision.get(), 2);
    let applied = journal
        .settle(
            actor("device:phone"),
            action(1),
            ReceiptState::Applied,
            Some(&[0xa0]),
            None,
            TimestampMs::new(3_000),
        )
        .expect("the outcome is recorded");
    assert_eq!(applied.state, ReceiptState::Applied);
    assert_eq!(applied.revision.get(), 3);

    // A terminal state moves nowhere, and past a dispatch marker there is no rejection.
    for refused in [
        ReceiptState::Dispatching,
        ReceiptState::Rejected,
        ReceiptState::Unknown,
        ReceiptState::Refused,
    ] {
        assert!(
            journal
                .settle(
                    actor("device:phone"),
                    action(1),
                    refused,
                    None,
                    None,
                    TimestampMs::new(4_000),
                )
                .is_err(),
            "applied cannot become {refused}"
        );
    }

    // accepted -> rejected, and a rejection always names its reason.
    journal
        .accept(&submission(2, 2, 2))
        .expect("a second intent");
    let rejected = journal
        .reject(
            actor("device:phone"),
            action(2),
            RejectionReason::AdmissionFailed,
            None,
            TimestampMs::new(5_000),
        )
        .expect("the rejection is recorded");
    assert_eq!(rejected.state, ReceiptState::Rejected);
    assert_eq!(
        rejected.reason.as_ref(),
        Some(&RejectionReason::AdmissionFailed)
    );

    // A marker with no outcome becomes unknown, and only reconciliation moves it on.
    journal
        .accept(&submission(3, 3, 3))
        .expect("a third intent");
    journal
        .mark_dispatching(actor("device:phone"), action(3), TimestampMs::new(6_000))
        .expect("the marker is committed");
    journal
        .settle(
            actor("device:phone"),
            action(3),
            ReceiptState::Unknown,
            None,
            None,
            TimestampMs::new(7_000),
        )
        .expect("the uncertain outcome is recorded");
    assert!(
        journal
            .settle(
                actor("device:phone"),
                action(3),
                ReceiptState::Rejected,
                None,
                None,
                TimestampMs::new(8_000),
            )
            .is_err(),
        "no transition out of unknown may imply the side effect did not happen"
    );
    let reconciled = journal
        .settle(
            actor("device:phone"),
            action(3),
            ReceiptState::Refused,
            None,
            None,
            TimestampMs::new(9_000),
        )
        .expect("authoritative reconciliation is permitted");
    assert_eq!(reconciled.state, ReceiptState::Refused);
}

/// KR-REQ-09.04: `received` is transient and never durable, and revisions only increase.
#[test]
fn received_is_never_durable_and_every_revision_increases() {
    assert!(
        !ReceiptState::Received.is_durable(),
        "a connection acknowledgement is not an acceptance"
    );
    for state in ReceiptState::ALL
        .iter()
        .copied()
        .filter(|state| *state != ReceiptState::Received)
    {
        assert!(state.is_durable(), "{state}");
    }

    let mut journal = Journal::in_memory().expect("a journal");
    journal.accept(&submission(1, 1, 1)).expect("an intent");
    // Nothing the journal writes is ever `received`: the first durable state is `accepted`.
    let events = journal.events_after(0, 16).expect("the recorded events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].state, ReceiptState::Accepted);
    assert_eq!(events[0].revision.get(), 1);

    let mut revisions = vec![1_u64];
    journal
        .mark_dispatching(actor("device:phone"), action(1), TimestampMs::new(2_000))
        .expect("a marker");
    journal
        .settle(
            actor("device:phone"),
            action(1),
            ReceiptState::Applied,
            None,
            None,
            TimestampMs::new(3_000),
        )
        .expect("an outcome");
    for event in journal.events_after(0, 16).expect("the recorded events") {
        if event.revision.get() > 1 {
            revisions.push(event.revision.get());
        }
    }
    assert_eq!(
        revisions,
        vec![1, 2, 3],
        "revisions increase and never repeat"
    );

    // A revision that does not increase is refused on an edge the contract permits, which is what
    // makes it a statement about the revision rather than about the edge. An uncertain outcome may
    // be reconciled to applied; it may not be reconciled at the revision it already stands at.
    journal
        .accept(&submission(4, 4, 4))
        .expect("a fourth intent");
    journal
        .mark_dispatching(actor("device:phone"), action(4), TimestampMs::new(4_000))
        .expect("a marker");
    let mut uncertain = journal
        .settle(
            actor("device:phone"),
            action(4),
            ReceiptState::Unknown,
            None,
            None,
            TimestampMs::new(5_000),
        )
        .expect("an uncertain outcome");
    let standing = uncertain.revision;
    assert!(
        uncertain.state.can_transition_to(ReceiptState::Applied),
        "the edge itself is permitted"
    );
    assert!(
        uncertain
            .advance(ReceiptState::Applied, standing, None)
            .is_err(),
        "and the revision still has to increase"
    );
    assert!(
        uncertain
            .advance(ReceiptState::Applied, U64::new(standing.get() - 1), None)
            .is_err()
    );
    assert!(
        uncertain
            .advance(ReceiptState::Applied, U64::new(standing.get() + 1), None)
            .is_ok()
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-09.05: observation is additive evidence
// ---------------------------------------------------------------------------------------------

fn observation(
    action_id: ActionId,
    provenance: ObservationProvenance,
    claimed_result: ObservedResult,
) -> ActionObservation {
    ActionObservation {
        action_id,
        provenance,
        subject: "agent.approval:upstream-opaque-request-id".to_owned(),
        subject_revision: Nullable::some(U64::new(3)),
        source_cursor: Nullable::some(U64::new(4_096)),
        claimed_result,
        observed_at_ms: TimestampMs::new(10_000),
    }
}

/// KR-REQ-09.05: an observation is recorded beside the receipt and never promotes an uncertain
/// outcome to applied unless the answer is authoritative.
#[test]
fn an_observation_is_additive_and_an_inferred_screen_never_promotes_an_uncertain_outcome() {
    let mut journal = Journal::in_memory().expect("a journal");
    journal.accept(&submission(1, 1, 1)).expect("an intent");
    journal
        .mark_dispatching(actor("device:phone"), action(1), TimestampMs::new(2_000))
        .expect("a marker");
    journal
        .settle(
            actor("device:phone"),
            action(1),
            ReceiptState::Unknown,
            None,
            None,
            TimestampMs::new(3_000),
        )
        .expect("an uncertain outcome");

    // A screen the host parsed says it worked. The receipt does not move, and the evidence is kept
    // with its provenance so a reader can see what it is.
    let screen = journal
        .record_observation(
            &actor("device:phone"),
            &observation(
                action(1),
                ObservationProvenance::InferredScreen,
                ObservedResult::Applied,
            ),
        )
        .expect("the observation is recorded");
    assert_eq!(screen.state, ReceiptState::Unknown);
    let kept = journal
        .observations(&actor("device:phone"), action(1))
        .expect("the observations");
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].provenance, ObservationProvenance::InferredScreen);
    assert_eq!(kept[0].claimed_result, ObservedResult::Applied);
    assert_eq!(kept[0].subject_revision.as_ref().map(|r| r.get()), Some(3));
    assert_eq!(kept[0].source_cursor.as_ref().map(|c| c.get()), Some(4_096));

    // A person's report does not either.
    let reported = journal
        .record_observation(
            &actor("device:phone"),
            &observation(
                action(1),
                ObservationProvenance::UserReport,
                ObservedResult::Applied,
            ),
        )
        .expect("the observation is recorded");
    assert_eq!(reported.state, ReceiptState::Unknown);

    // The interface that owns the subject does.
    let authoritative = journal
        .record_observation(
            &actor("device:phone"),
            &observation(
                action(1),
                ObservationProvenance::AuthoritativeInterface,
                ObservedResult::Applied,
            ),
        )
        .expect("the observation is recorded");
    assert_eq!(authoritative.state, ReceiptState::Applied);
    assert_eq!(
        journal
            .observations(&actor("device:phone"), action(1))
            .expect("the observations")
            .len(),
        3,
        "every observation is kept, including the ones that moved nothing"
    );
}

/// KR-REQ-09.05: an observation never creates a receipt for an action this host never admitted.
#[test]
fn an_observation_of_an_action_this_host_never_admitted_creates_nothing() {
    let mut journal = Journal::in_memory().expect("a journal");
    let refused = journal.record_observation(
        &actor("device:phone"),
        &observation(
            action(9),
            ObservationProvenance::AuthoritativeInterface,
            ObservedResult::Applied,
        ),
    );
    assert!(refused.is_err());
    assert!(journal.is_empty().expect("reads"));
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-09.06, 23.46: cancellation
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.06: a cancellation before dispatch is atomically `rejected(cancelled)`, and after a
/// dispatch marker there is nothing here to cancel.
#[test]
fn a_cancellation_before_dispatch_is_atomic_and_after_it_is_refused() {
    let mut journal = Journal::in_memory().expect("a journal");
    journal.accept(&submission(1, 1, 1)).expect("an intent");
    let cancelled = journal
        .cancel(actor("device:phone"), action(1), TimestampMs::new(2_000))
        .expect("the intent is cancelled");
    assert_eq!(cancelled.state, ReceiptState::Rejected);
    assert_eq!(cancelled.reason.as_ref(), Some(&RejectionReason::Cancelled));
    assert_eq!(cancelled.revision.get(), 2, "one revision, one commit");

    journal
        .accept(&submission(2, 2, 2))
        .expect("a second intent");
    journal
        .mark_dispatching(actor("device:phone"), action(2), TimestampMs::new(3_000))
        .expect("a marker");
    let refused = journal.cancel(actor("device:phone"), action(2), TimestampMs::new(4_000));
    assert!(
        refused.is_err(),
        "past the marker the effect may already have happened, so cancelling it is a separate \
         upstream action with its own receipt"
    );
    let unchanged = journal
        .read(actor("device:phone"), action(2))
        .expect("reads")
        .expect("a receipt");
    assert_eq!(unchanged.state, ReceiptState::Dispatching);
    assert_eq!(unchanged.revision.get(), 2);
}

/// KR-REQ-23.46: `action.cancel` reaches the caller's own undispatched intent, or another actor's
/// under host-owner authority, and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_cancel_reaches_an_own_intent_or_anothers_under_owner_authority() {
    let host = host().await;
    let mut client = cli(&host).await;

    // Two intents in the journal: one belonging to this connection's own principal, one to a
    // device. Neither has been dispatched.
    let caller = {
        let mut session = host.service.runtime().session();
        let journal = session.journal_mut().expect("a journal");
        let mut own = fresh(1, 1, 1);
        own.actor_id = actor("local:501");
        journal.accept(&own).expect("the caller's own intent");
        journal
            .accept(&fresh(2, 2, 2))
            .expect("another actor's intent");
        own.actor_id
    };

    // The caller's own principal is whatever the listener authenticated, so the "own" case is
    // exercised through the identifier the worker itself recorded for this connection.
    let mine = {
        let mut session = host.service.runtime().session();
        let journal = session.journal_mut().expect("a journal");
        let mut own = fresh(3, 3, 3);
        own.actor_id = actor(&format!("local:{}", kr_ipc::paths::current_uid()));
        journal.accept(&own).expect("this connection's own intent");
        own.action_id
    };
    let _ = caller;

    let cancel = MutationRequest {
        request_id: RequestId::new(1),
        method: Method::ActionCancel.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: host.environment_id,
            session_id: Nullable::null(),
            session_epoch: Nullable::null(),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: DEFAULT_MUTATION_TTL,
        params: ParamsValue::from_typed(&kr_protocol::receipt::ActionCancelParams {
            action_id: mine,
        })
        .expect("encodes"),
    };
    let own = send_mutation(&mut client, cancel).await;
    assert!(
        matches!(own, Outcome::Ok(_)),
        "a caller cancels its own undispatched intent: {own:?}"
    );

    // The same connection is the host owner, so it also reaches the device's intent.
    let others = MutationRequest {
        request_id: RequestId::new(2),
        action_id: ActionId::new(kr_ipc::new_uuid()),
        action_window_id: client.action_window().action_window_id.clone(),
        params: ParamsValue::from_typed(&kr_protocol::receipt::ActionCancelParams {
            action_id: action(2),
        })
        .expect("encodes"),
        ..MutationRequest {
            request_id: RequestId::new(2),
            method: Method::ActionCancel.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable::null(),
            target: ActionTarget {
                environment_id: host.environment_id,
                session_id: Nullable::null(),
                session_epoch: Nullable::null(),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            expected: ParamsValue::empty(),
            action_window_id: client.action_window().action_window_id.clone(),
            requested_ttl_ms: DEFAULT_MUTATION_TTL,
            params: ParamsValue::empty(),
        }
    };
    let owner = send_mutation(&mut client, others).await;
    assert!(
        matches!(owner, Outcome::Ok(_)),
        "the authenticated operating-system owner cancels another actor's intent: {owner:?}"
    );
    {
        let mut session = host.service.runtime().session();
        let journal = session.journal_mut().expect("a journal");
        let receipt = journal
            .read(actor("device:phone"), action(2))
            .expect("reads")
            .expect("a receipt");
        assert_eq!(receipt.state, ReceiptState::Rejected);
        assert_eq!(receipt.reason.as_ref(), Some(&RejectionReason::Cancelled));
    }

    // An action nothing recorded is refused rather than reported as cancelled.
    let missing = MutationRequest {
        request_id: RequestId::new(3),
        method: Method::ActionCancel.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: host.environment_id,
            session_id: Nullable::null(),
            session_epoch: Nullable::null(),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: DEFAULT_MUTATION_TTL,
        params: ParamsValue::from_typed(&kr_protocol::receipt::ActionCancelParams {
            action_id: action(200),
        })
        .expect("encodes"),
    };
    let Outcome::Error(error) = send_mutation(&mut client, missing).await else {
        panic!("an action this host never admitted cannot be cancelled");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-09.07, 09.08: de-duplication and the restart contract
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.07: the key is the verified actor and the action, the payload digest is stored, and a
/// reused identifier with a different payload is `ID_CONFLICT`.
/// KR-REQ-06.05: an action identifier names one submitted intent and its retained receipt.
#[test]
fn deduplication_is_keyed_by_the_verified_actor_and_the_action_with_its_digest() {
    let mut journal = Journal::in_memory().expect("a journal");
    let first = journal.accept(&submission(1, 1, 1)).expect("an intent");
    assert!(!first.deduplicated);
    assert_eq!(
        first.receipt.payload_digest,
        Digest256::from_bytes([1; 32]),
        "the digest is stored with the receipt"
    );

    // The same actor and the same identifier with the same payload: the retained receipt, and no
    // second action.
    let retry = journal.accept(&submission(1, 1, 1)).expect("the retry");
    assert!(retry.deduplicated);
    assert_eq!(retry.receipt.revision.get(), first.receipt.revision.get());
    assert_eq!(journal.len().expect("reads"), 1);

    // The same identifier with a different payload is a conflict, not a second action.
    let conflict = journal.accept(&submission(1, 9, 1));
    assert!(matches!(
        conflict,
        Err(kr_worker::WorkerError::IdConflict { .. })
    ));
    assert_eq!(
        conflict.err().map(|error| error.code()),
        Some(ErrorCode::IdConflict)
    );

    // Another actor's identical identifier is another action, because the key is both halves.
    let mut other = submission(1, 1, 1);
    other.actor_id = actor("local:501");
    let separate = journal.accept(&other).expect("another actor's action");
    assert!(!separate.deduplicated);
    assert_eq!(journal.len().expect("reads"), 2);
}

/// KR-REQ-09.08, KR-ACC-009 (the worker's half): a restart turns a dispatch marker with no
/// authoritative outcome into `unknown`, and that identifier is never dispatched again.
#[test]
fn a_restart_turns_a_dispatch_marker_without_an_outcome_into_unknown_and_never_redispatches() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = temp
        .environment()
        .journal_database(SessionId::new(kr_ipc::new_uuid()));
    {
        let mut journal = Journal::open(&path).expect("a journal");
        journal.accept(&submission(1, 1, 1)).expect("an intent");
        journal
            .mark_dispatching(actor("device:phone"), action(1), TimestampMs::new(2_000))
            .expect("the marker is committed before the effect");
        // An accepted intent with no marker, for the contrast: it is still open to a decision.
        journal.accept(&submission(2, 2, 2)).expect("an intent");
    }

    let mut journal = Journal::open(&path).expect("the journal reopens");
    let resolved = journal
        .resolve_unfinished_dispatches(TimestampMs::new(9_000))
        .expect("the markers are resolved");
    assert_eq!(
        resolved, 1,
        "only the marker without an outcome is resolved"
    );

    let uncertain = journal
        .read(actor("device:phone"), action(1))
        .expect("reads")
        .expect("a receipt");
    assert_eq!(uncertain.state, ReceiptState::Unknown);
    assert_eq!(
        uncertain.error.as_ref().map(|error| error.code),
        Some(ErrorCode::OutcomeUnknown)
    );
    assert!(
        !uncertain.state.can_transition_to(ReceiptState::Dispatching),
        "the identifier is never dispatched again simply because the receipt is incomplete"
    );
    assert!(
        journal
            .mark_dispatching(actor("device:phone"), action(1), TimestampMs::new(10_000))
            .is_err(),
        "and the journal refuses to write a second marker for it"
    );

    let accepted = journal
        .read(actor("device:phone"), action(2))
        .expect("reads")
        .expect("a receipt");
    assert_eq!(
        accepted.state,
        ReceiptState::Accepted,
        "an intent with no marker may still proceed after recovery, or be rejected"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-23.24: retained receipts, and superseding an uncertain outcome
// ---------------------------------------------------------------------------------------------

/// KR-REQ-23.24: a duplicate from a still-authorised actor returns the retained receipt without
/// dispatch, and current authority is checked before it is returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_duplicate_returns_the_retained_receipt_and_lost_authority_returns_nothing() {
    let host = host().await;
    let mut first = controller_client(&host).await;
    let mutation = close_mutation(
        &first,
        &host,
        DEFAULT_MUTATION_TTL.get(),
        ParamsValue::empty(),
    );
    let admitted = send_mutation(&mut first, mutation.clone()).await;
    assert!(matches!(admitted, Outcome::Ok(_)), "{admitted:?}");
    assert_eq!(host.service.runtime().state().as_str(), "closing");

    // The same request again on the same connection: the retained receipt and no second effect.
    let duplicate = send_mutation(&mut first, mutation.clone()).await;
    assert!(
        matches!(duplicate, Outcome::Ok(_)),
        "a duplicate from a still-authorised actor is answered: {duplicate:?}"
    );

    // A later controller connection of the same generation fences this one. The retained action is
    // now asked for by a connection whose authority has been withdrawn.
    let _second = controller_client(&host).await;
    let refused = send_mutation(&mut first, mutation).await;
    let Outcome::Error(error) = refused else {
        panic!("a fenced connection cannot retrieve a retained receipt");
    };
    assert_eq!(
        error.code,
        ErrorCode::PermissionDenied,
        "current authority is checked before the retained receipt is returned"
    );
}

/// KR-REQ-23.24: an automatically issued replacement identifier after an uncertain result is
/// rejected, and an explicit later request that shows the earlier result is admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replacement_identifier_after_an_uncertain_result_is_rejected_until_it_is_shown() {
    let host = host().await;
    let mut client = cli(&host).await;
    let caller = actor(&format!("local:{}", kr_ipc::paths::current_uid()));

    // A first attempt at this subject whose outcome is uncertain. The subject digest is what two
    // requests for the same thing have in common, so it is derived from the mutation itself.
    let first = close_mutation(
        &client,
        &host,
        DEFAULT_MUTATION_TTL.get(),
        ParamsValue::empty(),
    );
    let subject = kr_protocol::action::subject_digest(&first).expect("a subject digest");
    {
        let mut session = host.service.runtime().session();
        let journal = session.journal_mut().expect("a journal");
        let mut earlier = fresh(50, 50, 50);
        earlier.actor_id = caller.clone();
        earlier.subject_digest = subject;
        earlier.method = first.method.clone();
        journal.accept(&earlier).expect("the earlier intent");
        journal
            .mark_dispatching(caller.clone(), action(50), kr_ipc::now_ms())
            .expect("a marker");
        journal
            .settle(
                caller.clone(),
                action(50),
                ReceiptState::Unknown,
                None,
                None,
                kr_ipc::now_ms(),
            )
            .expect("an uncertain outcome");
    };

    // The caller reads the earlier result the way a caller has to: over the wire, under current
    // authority, through the method section 23 provides for it. The revision it then quotes is one
    // it has actually been shown rather than one it was handed by the store.
    let read = send_request(
        &mut client,
        Request {
            request_id: RequestId::new(4),
            method: Method::ActionRead.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(&kr_protocol::receipt::ActionReadParams {
                action_id: action(50),
                session_id: None,
            })
            .expect("encodes"),
        },
    )
    .await;
    let Outcome::Ok(value) = read else {
        panic!("the earlier result is readable: {read:?}");
    };
    let shown_receipt: kr_protocol::receipt::ActionReadResult = value.to_typed().expect("decodes");
    assert_eq!(
        shown_receipt.receipt.state,
        ReceiptState::Unknown,
        "what the caller is shown is the uncertain outcome itself"
    );
    let uncertain_revision = shown_receipt.receipt.revision.get();

    // A fresh identifier for the same subject, naming nothing. This is the service quietly
    // choosing a new identifier, and it is refused.
    let Outcome::Error(error) = send_mutation(&mut client, first.clone()).await else {
        panic!("a fresh identifier must not take an uncertain outcome's place");
    };
    assert_eq!(error.code, ErrorCode::DraftConflict);
    assert!(
        error.message.contains(&action(50).to_string()),
        "the refusal names the result the caller has to show: {}",
        error.message
    );
    assert_eq!(host.service.runtime().state().as_str(), "live");

    // The explicit later request names the earlier action and the revision it was read at.
    let mut expected = kr_cbor::CanonicalMap::new();
    expected
        .insert(
            kr_protocol::action::SUPERSEDES_ACTION_KEY.to_owned(),
            kr_cbor::to_canonical_value(&action(50)).expect("encodes"),
        )
        .expect("one key");
    expected
        .insert(
            kr_protocol::action::SUPERSEDES_REVISION_KEY.to_owned(),
            kr_cbor::CanonicalValue::integer(i128::from(uncertain_revision)).expect("a revision"),
        )
        .expect("a second key");
    let shown = MutationRequest {
        action_id: ActionId::new(kr_ipc::new_uuid()),
        expected: ParamsValue::new(kr_cbor::CanonicalValue::Map(expected)),
        ..first.clone()
    };
    let admitted = send_mutation(&mut client, shown).await;
    assert!(
        matches!(admitted, Outcome::Ok(_)),
        "an explicit later request that shows the earlier unknown result is admitted: {admitted:?}"
    );

    // And a request that quotes a revision it cannot have read is not showing anything.
    let mut wrong = kr_cbor::CanonicalMap::new();
    wrong
        .insert(
            kr_protocol::action::SUPERSEDES_ACTION_KEY.to_owned(),
            kr_cbor::to_canonical_value(&action(50)).expect("encodes"),
        )
        .expect("one key");
    wrong
        .insert(
            kr_protocol::action::SUPERSEDES_REVISION_KEY.to_owned(),
            kr_cbor::CanonicalValue::integer(i128::from(uncertain_revision + 7))
                .expect("a revision"),
        )
        .expect("a second key");
    let stale = MutationRequest {
        action_id: ActionId::new(kr_ipc::new_uuid()),
        expected: ParamsValue::new(kr_cbor::CanonicalValue::Map(wrong)),
        ..first
    };
    let Outcome::Error(error) = send_mutation(&mut client, stale).await else {
        panic!("quoting a revision the caller cannot have read shows nothing");
    };
    assert_eq!(error.code, ErrorCode::DraftConflict);
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-02.08, 23.23: what a caller may assert
// ---------------------------------------------------------------------------------------------

/// KR-REQ-02.08: the host authorises against current state, and nothing a caller puts in an
/// envelope creates permission.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_host_authorises_against_current_state_and_a_relayed_envelope_grants_nothing() {
    let host = host().await;
    let mut client = cli(&host).await;

    // A command-line caller that claims to be forwarding somebody else's verified envelope. Only
    // the control daemon forwards, and this connection said it was a command line.
    let forwarded = ControlFrame::Forwarded(Box::new(kr_protocol::local::ForwardedMutation {
        mutation: close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        ),
        grant_rights: [kr_protocol::rights::ActionRight::SessionClose]
            .into_iter()
            .collect(),
        actor: kr_protocol::actor::ActorEnvelope {
            actor_id: actor("device:somebody-elses-phone"),
            ingress: kr_protocol::actor::ActorIngress::PairedDevice,
            device_id: Nullable::some(kr_protocol::ids::DeviceId::new(Uuid::from_bytes([9; 16]))),
            grant_id: Nullable::some(kr_protocol::ids::GrantId::new(Uuid::from_bytes([8; 16]))),
            grant_revision: Nullable::some(kr_protocol::ids::AuthorityRevision::new(99)),
            controller_generation: ControllerGeneration::new(1),
            connection_id: kr_protocol::ids::ConnectionId::new(Uuid::from_bytes([7; 16])),
        },
        accepted_deadline_boot_ms: U64::new(u64::MAX),
    }));
    client
        .writer()
        .write_message(&forwarded)
        .await
        .expect("writes the frame");
    let answer = loop {
        match client.recv().await.expect("the worker answers") {
            ControlFrame::Response(response) => break response.outcome,
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    };
    let Outcome::Error(error) = answer else {
        panic!("a caller cannot forward an envelope it constructed for itself");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(host.service.runtime().state().as_str(), "live");

    // A grant identifier from a local caller is a claim the worker cannot check, so it is refused
    // rather than read as authority.
    let claimed = MutationRequest {
        grant_id: Nullable::some(kr_protocol::ids::GrantId::new(Uuid::from_bytes([8; 16]))),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let Outcome::Error(error) = send_mutation(&mut client, claimed).await else {
        panic!("a local caller acts under its authenticated identity, not a grant it names");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(host.service.runtime().state().as_str(), "live");
}

/// KR-REQ-23.23: request and notification shapes, and an upstream identifier that never becomes a
/// KalaReach identifier.
#[test]
fn an_upstream_identifier_never_becomes_a_kalareach_identifier() {
    // Every KalaReach durable identity is sixteen bytes on the wire, so an opaque upstream string
    // cannot be one of them whatever a connector does with it.
    let upstream = "upstream-opaque-request-id";
    let decoded: std::result::Result<ActionId, _> = kr_cbor::from_canonical_slice(
        &kr_cbor::encode(&kr_cbor::CanonicalValue::text(upstream)),
        &kr_cbor::Limits::DEFAULT,
    );
    assert!(
        decoded.is_err(),
        "an upstream identifier cannot be decoded as an action identifier"
    );
    let decoded: std::result::Result<SessionId, _> = kr_cbor::from_canonical_slice(
        &kr_cbor::encode(&kr_cbor::CanonicalValue::text(upstream)),
        &kr_cbor::Limits::DEFAULT,
    );
    assert!(decoded.is_err());

    // An upstream identifier that happens to look like a UUID is still not one of ours. What makes
    // a KalaReach action identity is that the host or its client generated it for this action; an
    // upstream value is carried as a precondition and never adopted, so the two are different
    // fields of the same envelope and the digest covers both.
    let upstream_uuid = "e52e8d1a-6818-4be7-b4b8-f93a8b1c0c6d";
    let mut namespaced = kr_cbor::CanonicalMap::new();
    namespaced
        .insert(
            "approval_request_id".to_owned(),
            kr_cbor::CanonicalValue::text(upstream_uuid),
        )
        .expect("one key");
    let adopted: std::result::Result<ActionId, _> = kr_cbor::from_canonical_slice(
        &kr_cbor::encode(&kr_cbor::CanonicalValue::text(upstream_uuid)),
        &kr_cbor::Limits::DEFAULT,
    );
    assert!(
        adopted.is_err(),
        "an upstream identifier in uuid form is text on the wire, and an action identity is \
         sixteen bytes; the two cannot be the same value"
    );

    // An upstream identifier travels as opaque text inside the preconditions, where it is covered
    // by the mutation digest and is not an identity of ours.
    let mut expected = kr_cbor::CanonicalMap::new();
    expected
        .insert(
            "approval_request_id".to_owned(),
            kr_cbor::CanonicalValue::text(upstream),
        )
        .expect("one key");
    let mutation = MutationRequest {
        request_id: RequestId::new(41),
        method: Method::AgentApprovalRespond.into(),
        method_version: MethodVersion::V1,
        action_id: action(1),
        grant_id: Nullable::some(kr_protocol::ids::GrantId::new(Uuid::from_bytes([2; 16]))),
        target: ActionTarget {
            environment_id: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([3; 16])),
            session_id: Nullable::some(SessionId::new(Uuid::from_bytes([4; 16]))),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::new(kr_cbor::CanonicalValue::Map(expected)),
        action_window_id: ActionWindowId::new("host-issued-window-id".to_owned())
            .expect("a window name"),
        requested_ttl_ms: DEFAULT_MUTATION_TTL,
        params: ParamsValue::empty(),
    };
    let caller = actor("device:phone");
    let digest = kr_protocol::digest::mutation_digest(&mutation, &caller).expect("a digest");

    // The correlator is not the identity. A retry on another connection carries another
    // `request_id` and the same digest, so the durable identity is the action alone.
    let retried = MutationRequest {
        request_id: RequestId::new(42),
        ..mutation.clone()
    };
    assert_eq!(
        digest,
        kr_protocol::digest::mutation_digest(&retried, &caller).expect("a digest"),
        "request_id correlates a response and is not part of the action's identity"
    );

    // Changing the upstream identifier changes the digest, because it is a precondition the host
    // signs over rather than an identifier it adopts.
    let mut other = kr_cbor::CanonicalMap::new();
    other
        .insert(
            "approval_request_id".to_owned(),
            kr_cbor::CanonicalValue::text("a-different-upstream-id"),
        )
        .expect("one key");
    let changed = MutationRequest {
        expected: ParamsValue::new(kr_cbor::CanonicalValue::Map(other)),
        ..mutation
    };
    assert_ne!(
        digest,
        kr_protocol::digest::mutation_digest(&changed, &caller).expect("a digest")
    );

    // A notification carries a stream, a sequence, an event type and a payload, and no action of
    // any kind: a notification is not something a caller correlates or retries.
    let mut shape = kr_cbor::CanonicalMap::new();
    for (key, value) in [
        ("stream_id", kr_cbor::CanonicalValue::text("session.output")),
        ("event_type", kr_cbor::CanonicalValue::text("output")),
    ] {
        shape.insert(key.to_owned(), value).expect("one key");
    }
    shape
        .insert(
            "sequence".to_owned(),
            kr_cbor::CanonicalValue::integer(7).expect("a sequence"),
        )
        .expect("one key");
    shape
        .insert(
            "payload".to_owned(),
            kr_cbor::CanonicalValue::Map(kr_cbor::CanonicalMap::new()),
        )
        .expect("one key");
    let decoded: kr_protocol::envelope::Notification = kr_cbor::from_canonical_slice(
        &kr_cbor::encode(&kr_cbor::CanonicalValue::Map(shape)),
        &kr_cbor::Limits::DEFAULT,
    )
    .expect("a notification is a stream, a sequence, an event type and a payload");
    assert_eq!(decoded.sequence.get(), 7);
    assert_eq!(decoded.stream_id.as_str(), "session.output");
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-09.09: revalidation in the serial dispatch path
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.09: authority, expiry, identity, binding and preconditions are all rechecked in the
/// serial dispatch path, and a refusal commits a rejection rather than an effect.
/// KR-REQ-06.02: a mutation naming any session epoch but the current one, 1, is refused as stale.
/// A worker states the clock floor it maps, by the floor's identity, in its answer to every hello,
/// so a control daemon can tell whether it decides UTC deadlines from the daemon's own floor. A
/// worker that maps none states no floor, whatever else it states about itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_states_the_clock_floor_it_maps_in_its_hello() {
    let identity = std::sync::Mutex::new(None);
    let floored = host_with(
        |_| {},
        |environment| {
            let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
            let floor = kr_ipc::floor::SharedFloor::create(
                &environment.utc_floor_file(),
                environment.environment_id(),
                kr_ipc::identity::boot_epoch(&boot).expect("a boot epoch"),
                0,
            )
            .expect("the environment's floor");
            *identity.lock().expect("not poisoned") = floor.identity();
            kr_worker::action::time::TimeSources::system().with_floor(Arc::new(floor))
        },
    )
    .await;
    let identity = identity
        .into_inner()
        .expect("not poisoned")
        .expect("a mapped floor has an identity");
    let client = cli(&floored).await;
    assert_eq!(
        kr_protocol::local::stated_utc_floor(&client.acknowledgement().capabilities),
        Some(*identity.as_bytes())
    );

    // The control: a worker that maps no floor states none.
    let unfloored = host().await;
    let client = cli(&unfloored).await;
    let stated = &client.acknowledgement().capabilities;
    assert!(
        stated.iter().all(|capability| !capability
            .as_str()
            .starts_with(kr_protocol::local::UTC_FLOOR_PREFIX)),
        "a worker that maps no floor states none: {stated:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_serial_path_rechecks_authority_expiry_identity_binding_and_preconditions() {
    let host = host().await;

    // Authority: a controller connection fenced by a later one of the same generation.
    let mut fenced = controller_client(&host).await;
    let _current = controller_client(&host).await;
    let stale = close_mutation(
        &fenced,
        &host,
        DEFAULT_MUTATION_TTL.get(),
        ParamsValue::empty(),
    );
    let Outcome::Error(error) = send_mutation(&mut fenced, stale).await else {
        panic!("a fenced controller cannot dispatch");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);

    let mut client = cli(&host).await;

    // Expiry: a lifetime of zero is spent by the time the barrier is taken.
    let spent = close_mutation(&client, &host, 0, ParamsValue::empty());
    let Outcome::Error(error) = send_mutation(&mut client, spent).await else {
        panic!("an action with no lifetime left is not dispatched");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);

    // Session identity: another session's identifier is stale rather than served.
    let other = MutationRequest {
        target: ActionTarget {
            session_id: Nullable::some(SessionId::new(Uuid::from_bytes([9; 16]))),
            ..target(&host)
        },
        params: ParamsValue::from_typed(&kr_protocol::session::SessionCloseParams {
            session_id: SessionId::new(Uuid::from_bytes([9; 16])),
        })
        .expect("encodes"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let Outcome::Error(error) = send_mutation(&mut client, other).await else {
        panic!("a worker serves one session");
    };
    assert_eq!(error.code, ErrorCode::StaleSession);

    // Session epoch: an epoch that is not the current one is stale.
    let stale_epoch = MutationRequest {
        target: ActionTarget {
            session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::new(9)),
            ..target(&host)
        },
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let Outcome::Error(error) = send_mutation(&mut client, stale_epoch).await else {
        panic!("a stale epoch is refused");
    };
    assert_eq!(error.code, ErrorCode::StaleSession);

    // Agent binding: this endpoint serves the session itself, so naming an application instance
    // and its binding revision is a request it cannot serve rather than a field it ignores.
    let bound = MutationRequest {
        target: ActionTarget {
            application_instance_id: Nullable::some(kr_protocol::ids::ApplicationInstanceId::new(
                Uuid::from_bytes([5; 16]),
            )),
            agent_binding_revision: Nullable::some(kr_protocol::ids::AgentBindingRevision::new(2)),
            ..target(&host)
        },
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let Outcome::Error(error) = send_mutation(&mut client, bound).await else {
        panic!("an application instance is not something this endpoint acts for");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);

    // Preconditions: a subject fact that no longer holds refuses the mutation, and the receipt it
    // leaves behind is a rejection rather than a dispatch.
    let mut expected = kr_cbor::CanonicalMap::new();
    expected
        .insert(
            "session_state".to_owned(),
            kr_cbor::CanonicalValue::text("closed"),
        )
        .expect("one key");
    let precondition = close_mutation(
        &client,
        &host,
        DEFAULT_MUTATION_TTL.get(),
        ParamsValue::new(kr_cbor::CanonicalValue::Map(expected)),
    );
    let named = precondition.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, precondition).await else {
        panic!("a precondition that does not hold refuses the mutation");
    };
    assert_eq!(error.code, ErrorCode::DraftConflict);
    assert_eq!(host.service.runtime().state().as_str(), "live");
    {
        let caller = actor(&format!("local:{}", kr_ipc::paths::current_uid()));
        let mut session = host.service.runtime().session();
        let journal = session.journal_mut().expect("a journal");
        let receipt = journal
            .read(caller, named)
            .expect("reads")
            .expect("the intent was committed before it was revalidated");
        assert_eq!(receipt.state, ReceiptState::Rejected);
        assert_eq!(
            receipt.reason.as_ref(),
            Some(&RejectionReason::StalePreconditions),
            "durable acceptance does not preserve a precondition that has moved"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-09.14, 09.15, 09.16, 09.22: retention, lifetimes, windows and the protocol defaults
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.14: 30-day retention, a two-minute default lifetime, a five-minute cap, and no
/// refreshed deadline on a retry.
#[test]
fn the_retention_the_default_lifetime_and_the_cap_are_what_section_nine_states() {
    assert_eq!(RETENTION_MS, 30 * 24 * 60 * 60 * 1000);
    assert_eq!(DEDUPLICATION_RETENTION.get(), RETENTION_MS);
    assert_eq!(DEFAULT_MUTATION_TTL.get(), 120_000);
    assert_eq!(MAX_MUTATION_TTL.get(), 300_000);

    let mut journal = Journal::in_memory().expect("a journal");
    let first = journal.accept(&submission(1, 1, 1)).expect("an intent");
    let deadline = first
        .receipt
        .accepted_deadline_ms
        .as_ref()
        .map(|stamp| stamp.get());
    assert_eq!(deadline, Some(121_000));

    // The retry arrives a minute later and would derive a later deadline. It receives the one the
    // first admission committed.
    let mut later = submission(1, 1, 1);
    later.now_ms = TimestampMs::new(61_000);
    later.accepted_deadline_ms = Some(TimestampMs::new(61_000 + 120_000));
    let retry = journal.accept(&later).expect("the retry");
    assert!(retry.deduplicated);
    assert_eq!(
        retry
            .receipt
            .accepted_deadline_ms
            .as_ref()
            .map(|stamp| stamp.get()),
        deadline,
        "an exact retry never receives a new deadline"
    );

    // Retention itself: a record inside the period is kept, and one past it goes with its result,
    // its events and its observations. Both of these records are this run's, so the guard that
    // keeps a record whose window could still admit it is stood down by making the record read as
    // an earlier run's, which is what a record thirty days old always is.
    assert_eq!(
        journal
            .prune(TimestampMs::new(RETENTION_MS))
            .expect("prunes"),
        0
    );
    assert_eq!(journal.len().expect("reads"), 1);
}

/// KR-REQ-09.14: retention is kept while a worker runs, not only when it starts, and its schedule
/// advances only when it succeeded.
#[test]
fn a_live_journal_prunes_on_its_own_schedule() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = temp
        .environment()
        .journal_database(SessionId::new(kr_ipc::new_uuid()));
    let mut journal = Journal::open(&path).expect("a journal");
    journal
        .accept(&at(1, 1, 1, TimestampMs::new(1_000)))
        .expect("an intent from an earlier run");
    journal
        .accept(&at(2, 2, 2, TimestampMs::new(2_000)))
        .expect("a second one");
    // Both read as an earlier run's, which is what a record thirty days old always is: the windows
    // that admitted it live in the memory of a host that has restarted since.
    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute(
            "UPDATE receipts SET created_boot = NULL, created_continuous_ms = NULL",
            [],
        )
        .expect("the records read as an earlier run's");

    // The first prune of a journal's life is due at once, and it forgets both records: each one is
    // past the retention period, and neither belongs to a run whose windows still exist.
    assert_eq!(
        journal
            .prune_if_due(TimestampMs::new(RETENTION_MS + 10_000), true)
            .expect("prunes"),
        2,
        "retention is kept while the worker runs rather than only when it starts"
    );
    assert_eq!(journal.len().expect("reads"), 0);

    // Within the interval nothing runs again, so the cost falls on neither the mutation path nor
    // the store.
    journal
        .accept(&at(3, 3, 3, TimestampMs::new(RETENTION_MS + 11_000)))
        .expect("a third intent");
    assert_eq!(
        journal
            .prune_if_due(TimestampMs::new(RETENTION_MS + 12_000), true)
            .expect("nothing is due"),
        0
    );
    assert_eq!(journal.len().expect("reads"), 1);

    // And a host that cannot prove what its wall clock reads collects nothing at all, whatever
    // the schedule says. Section 9 stops expiry-based collection there, because collecting against
    // an unproved clock is how a rollback deletes something that had not expired.
    assert_eq!(
        journal
            .prune_if_due(TimestampMs::new(RETENTION_MS * 3), false)
            .expect("nothing is collected"),
        0
    );
    assert_eq!(journal.len().expect("reads"), 1);
}

/// KR-REQ-09.15, KR-ACC-027: first admission needs a window bound to this connection, this boot
/// and a continuous deadline at most five minutes away; an expired or unknown window admits
/// nothing, and a replaced window is a new payload rather than a retry.
/// KR-REQ-23.20: a local IPC connection gets its action window from the host, and a window it did
/// not issue to this connection admits nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_admission_needs_this_connections_window_and_a_replacement_is_a_new_payload() {
    let host = host().await;
    let mut client = cli(&host).await;
    let window = client.action_window().clone();
    assert!(
        window.valid_for_ms.get() <= MAX_ACTION_WINDOW.get(),
        "a window is at most five minutes"
    );
    assert_eq!(
        window.boot_epoch,
        host.service.boot_epoch(),
        "the window is bound to this host's boot"
    );

    // A window this host never issued admits nothing.
    let invented = MutationRequest {
        action_window_id: ActionWindowId::new("never-issued".to_owned()).expect("a window name"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let Outcome::Error(error) = send_mutation(&mut client, invented).await else {
        panic!("an unknown window cannot first-admit a request");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);

    // Another connection's window admits nothing here, even though this host issued it.
    let other = cli(&host).await;
    let borrowed = MutationRequest {
        action_window_id: other.action_window().action_window_id.clone(),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let Outcome::Error(error) = send_mutation(&mut client, borrowed).await else {
        panic!("a window belongs to one connection");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(host.service.runtime().state().as_str(), "live");

    // Replacing the window changes the payload digest, so the same action identifier under a new
    // window is a different payload rather than an automatic retry.
    let original = close_mutation(
        &client,
        &host,
        DEFAULT_MUTATION_TTL.get(),
        ParamsValue::empty(),
    );
    let caller = actor(&format!("local:{}", kr_ipc::paths::current_uid()));
    let first_digest = kr_protocol::digest::mutation_digest(&original, &caller).expect("a digest");
    let replaced = MutationRequest {
        action_window_id: other.action_window().action_window_id.clone(),
        ..original.clone()
    };
    assert_ne!(
        first_digest,
        kr_protocol::digest::mutation_digest(&replaced, &caller).expect("a digest"),
        "a replaced window changes the payload"
    );

    let action_id = original.action_id;
    let admitted = send_mutation(&mut client, original).await;
    assert!(matches!(admitted, Outcome::Ok(_)), "{admitted:?}");

    // The same identifier under another window is that identifier with a different payload, which
    // is a conflict rather than a retry. That is what makes replacing a window a new first
    // admission rather than an automatic replay of this one.
    let conflict = MutationRequest {
        action_id,
        action_window_id: other.action_window().action_window_id.clone(),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let Outcome::Error(error) = send_mutation(&mut client, conflict).await else {
        panic!("the same identifier under another window is a different payload");
    };
    assert_eq!(error.code, ErrorCode::IdConflict);
}

/// KR-REQ-09.16: a retained receipt stays readable under current authority after its window has
/// gone, an exact retry is answered from it without redispatch, and that window first-admits
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retained_receipt_is_read_after_its_window_is_gone_without_redispatch() {
    let host = host().await;

    // A real attachment, admitted through a real window on a real connection.
    let mut first = cli(&host).await;
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let window = first.action_window().action_window_id.clone();
    let attach = MutationRequest {
        request_id: RequestId::new(11),
        method: Method::SessionAttach.into(),
        method_version: MethodVersion::V1,
        action_id,
        grant_id: Nullable::null(),
        target: target(&host),
        expected: ParamsValue::empty(),
        action_window_id: window.clone(),
        requested_ttl_ms: DurationMs::new(DEFAULT_MUTATION_TTL.get()),
        params: ParamsValue::from_typed(&kr_protocol::attachment::SessionAttachParams {
            session_id: host.session_id,
            mode: kr_protocol::attachment::AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested,
        })
        .expect("encodes"),
    };
    let admitted = send_mutation(&mut first, attach.clone()).await;
    let Outcome::Ok(value) = admitted else {
        panic!("the attachment is accepted: {admitted:?}");
    };
    let original: kr_protocol::attachment::SessionAttachResult = value.to_typed().expect("decodes");

    // The connection goes, and its windows go with it: a window that outlived its connection could
    // first-admit a request through a connection that no longer exists.
    drop(first);
    // The worker retires a connection's windows when it notices the connection has ended, which is
    // its own read failing rather than anything this test can announce.
    let mut client = cli(&host).await;
    for _ in 0..50 {
        if host.service.outstanding_windows() <= 1 {
            break;
        }
        tokio::task::spawn_blocking(|| std::thread::sleep(std::time::Duration::from_millis(40)))
            .await
            .expect("the waiting thread finishes");
    }
    let attachments_before = host.service.runtime().session().attachments().len();

    // The exact same action, on a connection that never held its window. The de-duplication key is
    // the actor and the action, so it is answered from the journal: the same attachment comes back,
    // and nothing is dispatched a second time.
    let retried = send_mutation(&mut client, attach).await;
    let Outcome::Ok(value) = retried else {
        panic!("an exact retry is answered from the retained receipt: {retried:?}");
    };
    let replayed: kr_protocol::attachment::SessionAttachResult = value.to_typed().expect("decodes");
    assert_eq!(
        replayed.attachment.attachment_id, original.attachment.attachment_id,
        "the retained result comes back rather than a second attachment"
    );
    assert_eq!(
        host.service.runtime().session().attachments().len(),
        attachments_before,
        "nothing was dispatched again"
    );

    // And that window admits nothing new. A different action presenting it is refused for the
    // window itself, before anything about this request could be durable.
    let fresh_action = MutationRequest {
        action_id: ActionId::new(kr_ipc::new_uuid()),
        action_window_id: window,
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let named = fresh_action.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, fresh_action).await else {
        panic!("a window that went with its connection first-admits nothing");
    };
    assert_eq!(
        error.code,
        ErrorCode::PermissionDenied,
        "refused for the window rather than for anything else: {error:?}"
    );
    {
        let mut session = host.service.runtime().session();
        let journal = session.journal_mut().expect("a journal");
        let receipt = journal
            .read(
                actor(&format!("local:{}", kr_ipc::paths::current_uid())),
                named,
            )
            .expect("reads");
        assert!(
            receipt.is_none(),
            "a first admission refused for its window leaves no receipt behind"
        );
    }

    // The receipt the action left behind is still readable under current authority, on a
    // connection whose own window has nothing to do with it. `action.read` is a read: no window,
    // no dispatch.
    let read = send_request(
        &mut client,
        Request {
            request_id: RequestId::new(5),
            method: Method::ActionRead.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(&kr_protocol::receipt::ActionReadParams {
                action_id,
                session_id: None,
            })
            .expect("encodes"),
        },
    )
    .await;
    let Outcome::Ok(value) = read else {
        panic!("a retained receipt is readable after its window is gone: {read:?}");
    };
    let result: kr_protocol::receipt::ActionReadResult = value.to_typed().expect("decodes");
    assert_eq!(result.receipt.state, ReceiptState::Applied);
    assert_eq!(result.receipt.action_id, action_id);
    assert!(
        result.result.as_ref().is_some(),
        "the result the action produced is retained with it"
    );
    assert_eq!(host.service.runtime().state().as_str(), "live");
}

/// KR-REQ-09.07, KR-REQ-09.08: a journal an earlier build wrote opens, migrates and keeps every
/// record it held.
///
/// The order matters and it is the order a reader would not guess. A `CREATE TABLE IF NOT EXISTS`
/// adds no column to a table that already exists, so creating this build's schema over an older
/// one would leave the old shape in place and then fail on the first index naming a new column,
/// and the whole journal would read as unavailable.
#[test]
fn a_journal_an_earlier_build_wrote_opens_and_keeps_its_receipts() {
    let temp = kr_ipc::testing::TempHost::create();
    // Version 1 had no `intent` column and no `session` or `host_events` table; version 2 added
    // those and nothing else. Each one is written here exactly as that build wrote it.
    for (version, extra, intent) in [(1_i64, "", ""), (2_i64, "", "intent BLOB,")] {
        let path = temp
            .environment()
            .journal_database(SessionId::new(kr_ipc::new_uuid()));
        {
            // The schema exactly as that build wrote it, with one accepted intent, one past its
            // dispatch marker, one settled with a retained result, and the events beside them.
            let connection = rusqlite::Connection::open(&path).expect("a database");
            connection
                .execute_batch(&format!(
                    "CREATE TABLE schema_version (version INTEGER NOT NULL);
                     CREATE TABLE receipts (
                         actor_id             TEXT    NOT NULL,
                         action_id            BLOB    NOT NULL,
                         method               TEXT    NOT NULL,
                         method_version       INTEGER NOT NULL,
                         revision             INTEGER NOT NULL,
                         state                TEXT    NOT NULL,
                         reason               TEXT,
                         payload_digest       BLOB    NOT NULL,
                         {extra}
                         {intent}
                         accepted_deadline_ms INTEGER,
                         error_code           TEXT,
                         error_message        TEXT,
                         created_at_ms        INTEGER NOT NULL,
                         updated_at_ms        INTEGER NOT NULL,
                         PRIMARY KEY (actor_id, action_id)
                     );
                     CREATE INDEX receipts_created_at ON receipts (created_at_ms);
                     CREATE TABLE results (
                         actor_id  TEXT NOT NULL,
                         action_id BLOB NOT NULL,
                         result    BLOB NOT NULL,
                         PRIMARY KEY (actor_id, action_id)
                     );
                     CREATE TABLE receipt_events (
                         sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
                         actor_id       TEXT    NOT NULL,
                         action_id      BLOB    NOT NULL,
                         revision       INTEGER NOT NULL,
                         state          TEXT    NOT NULL,
                         recorded_at_ms INTEGER NOT NULL
                     );
                     CREATE TABLE closure (
                         session_id BLOB PRIMARY KEY,
                         record     BLOB NOT NULL
                     );"
                ))
                .expect("the earlier schema");
            connection
                .execute(
                    "INSERT INTO schema_version (version) VALUES (?1)",
                    rusqlite::params![version],
                )
                .expect("the recorded version");
            let now = i64::try_from(kr_ipc::now_ms().get()).expect("a timestamp");
            for (byte, state) in [(1_u8, "accepted"), (2, "dispatching"), (3, "applied")] {
                connection
                    .execute(
                        &format!(
                            "INSERT INTO receipts (actor_id, action_id, method, method_version,
                                 revision, state, payload_digest, {extra_names}{intent_name}
                                 created_at_ms, updated_at_ms)
                             VALUES (?1, ?2, 'session.close', 1, 1, ?3, ?4,                                  {extra_values}{intent_value} ?5, ?5)",
                            extra_names = if extra.is_empty() { "" } else { "subject_digest," },
                            extra_values = if extra.is_empty() { "" } else { "NULL," },
                            intent_name = if intent.is_empty() { "" } else { " intent," },
                            intent_value = if intent.is_empty() {
                                String::new()
                            } else {
                                format!("x'{}',", hex_byte(0xa0))
                            },
                        ),
                        rusqlite::params![
                            "device:phone",
                            [byte; 16].as_slice(),
                            state,
                            [byte; 32].as_slice(),
                            now
                        ],
                    )
                    .expect("a receipt the earlier build wrote");
            }
            connection
                .execute(
                    "INSERT INTO results (actor_id, action_id, result) VALUES (?1, ?2, ?3)",
                    rusqlite::params!["device:phone", [3_u8; 16].as_slice(), [0xa0_u8].as_slice()],
                )
                .expect("a retained result");
        }

        // This build opens it, migrates it and reads every record.
        let mut journal = Journal::open(&path).expect("the earlier journal opens");
        for byte in [1_u8, 2, 3] {
            assert!(
                journal
                    .read(actor("device:phone"), action(byte))
                    .expect("reads")
                    .is_some(),
                "version {version}: receipt {byte} survived the migration"
            );
        }
        assert!(
            journal
                .read_result(&actor("device:phone"), action(3))
                .expect("reads")
                .is_some(),
            "version {version}: the retained result survived"
        );
        // And the records it wrote are usable: an exact retry is de-duplicated, and a reused
        // identifier with a different payload is still a conflict.
        let mut same = fresh(3, 3, 3);
        same.actor_id = actor("device:phone");
        same.payload_digest = Digest256::from_bytes([3; 32]);
        assert!(
            journal.accept(&same).expect("the retry").deduplicated,
            "version {version}: the migrated digest still de-duplicates"
        );

        // Recovery runs on the migrated journal: the marker becomes unknown and the accepted
        // intent is rejected, because neither can be proved after a restart.
        assert_eq!(
            journal
                .resolve_unfinished_dispatches(kr_ipc::now_ms())
                .expect("resolves"),
            1,
            "version {version}"
        );
        assert_eq!(
            journal
                .reject_unrevalidated_intents(kr_ipc::now_ms())
                .expect("rejects"),
            1,
            "version {version}"
        );
    }
}

/// KR-REQ-09.07, KR-REQ-23.24: the subject of a migrated record is derived from the intent that
/// build retained, so a fresh identifier cannot quietly take an uncertain outcome's place across
/// an update.
#[test]
fn a_migrated_record_keeps_the_subject_its_retained_intent_describes() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = temp
        .environment()
        .journal_database(SessionId::new(kr_ipc::new_uuid()));
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let caller = actor("device:phone");
    // The mutation an earlier build recorded, with an outcome nobody could establish.
    let mutation = MutationRequest {
        request_id: RequestId::new(1),
        method: Method::SessionClose.into(),
        method_version: MethodVersion::V1,
        action_id: crate::action(5),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: temp.environment_id(),
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: kr_protocol::ids::ActionWindowId::new("kr-window-of-an-earlier-build")
            .expect("a window identifier"),
        requested_ttl_ms: DurationMs::new(DEFAULT_MUTATION_TTL.get()),
        params: ParamsValue::from_typed(&kr_protocol::session::SessionCloseParams { session_id })
            .expect("encodes"),
    };
    let intent = kr_cbor::to_canonical_vec(&mutation).expect("the intent encodes");
    {
        // Version 2's schema: the payload digest and the retained intent, and no subject digest.
        let connection = rusqlite::Connection::open(&path).expect("a database");
        connection
            .execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 CREATE TABLE receipts (
                     actor_id             TEXT    NOT NULL,
                     action_id            BLOB    NOT NULL,
                     method               TEXT    NOT NULL,
                     method_version       INTEGER NOT NULL,
                     revision             INTEGER NOT NULL,
                     state                TEXT    NOT NULL,
                     reason               TEXT,
                     payload_digest       BLOB    NOT NULL,
                     intent               BLOB,
                     accepted_deadline_ms INTEGER,
                     error_code           TEXT,
                     error_message        TEXT,
                     created_at_ms        INTEGER NOT NULL,
                     updated_at_ms        INTEGER NOT NULL,
                     PRIMARY KEY (actor_id, action_id)
                 );
                 CREATE INDEX receipts_created_at ON receipts (created_at_ms);
                 CREATE TABLE results (
                     actor_id  TEXT NOT NULL,
                     action_id BLOB NOT NULL,
                     result    BLOB NOT NULL,
                     PRIMARY KEY (actor_id, action_id)
                 );
                 CREATE TABLE receipt_events (
                     sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
                     actor_id       TEXT    NOT NULL,
                     action_id      BLOB    NOT NULL,
                     revision       INTEGER NOT NULL,
                     state          TEXT    NOT NULL,
                     recorded_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE closure (
                     session_id BLOB PRIMARY KEY,
                     record     BLOB NOT NULL
                 );
                 CREATE TABLE session (
                     session_id BLOB PRIMARY KEY,
                     summary    BLOB NOT NULL
                 );
                 CREATE TABLE host_events (
                     sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
                     kind           TEXT    NOT NULL,
                     detail         TEXT    NOT NULL,
                     output_cursor  INTEGER NOT NULL,
                     recorded_at_ms INTEGER NOT NULL
                 );",
            )
            .expect("the earlier schema");
        connection
            .execute(
                "INSERT INTO schema_version (version) VALUES (2)",
                rusqlite::params![],
            )
            .expect("the recorded version");
        let now = i64::try_from(kr_ipc::now_ms().get()).expect("a timestamp");
        connection
            .execute(
                "INSERT INTO receipts (actor_id, action_id, method, method_version, revision,
                     state, payload_digest, intent, created_at_ms, updated_at_ms)
                 VALUES (?1, ?2, 'session.close', 1, 2, 'unknown', ?3, ?4, ?5, ?5)",
                rusqlite::params![
                    "device:phone",
                    crate::action(5).get().as_bytes().as_slice(),
                    [5_u8; 32].as_slice(),
                    intent,
                    now
                ],
            )
            .expect("a receipt with an uncertain outcome");
        // And one whose intent this build cannot read, which keeps no subject at all.
        connection
            .execute(
                "INSERT INTO receipts (actor_id, action_id, method, method_version, revision,
                     state, payload_digest, intent, created_at_ms, updated_at_ms)
                 VALUES (?1, ?2, 'session.close', 1, 2, 'unknown', ?3, ?4, ?5, ?5)",
                rusqlite::params![
                    "device:phone",
                    crate::action(6).get().as_bytes().as_slice(),
                    [6_u8; 32].as_slice(),
                    [0xa0_u8].as_slice(),
                    now
                ],
            )
            .expect("a receipt whose intent this build cannot read");
    }

    let journal = Journal::open(&path).expect("the earlier journal opens");
    let subject = kr_protocol::action::subject_digest(&mutation).expect("a subject");
    assert_eq!(
        journal
            .uncertain_for_subject(&caller, subject)
            .expect("reads")
            .map(|(action_id, _)| action_id),
        Some(crate::action(5)),
        "the migrated record stands in the way of a fresh identifier for the same subject"
    );
    // The record whose intent could not be read stands in nothing's way, and the migration said
    // so by leaving its subject empty rather than guessing at one.
    assert_eq!(
        journal
            .uncertain_for_subject(&caller, Digest256::from_bytes([0; 32]))
            .expect("reads"),
        None
    );
}

/// KR-REQ-09.08, KR-REQ-09.09: recovery rejects an intent whose freshness cannot be proved again,
/// and frees the capacity it was holding.
#[test]
fn recovery_rejects_an_accepted_intent_and_frees_what_it_held() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = temp
        .environment()
        .journal_database(SessionId::new(kr_ipc::new_uuid()));
    let caller = actor("device:phone");
    {
        let mut journal = Journal::open(&path).expect("a journal");
        for index in 0..MAX_OUTSTANDING_MUTATIONS {
            let byte = u8::try_from(40 + index).expect("a small index");
            journal.accept(&fresh(byte, byte, byte)).expect("an intent");
        }
        assert_eq!(
            journal.outstanding(&caller).expect("reads"),
            MAX_OUTSTANDING_MUTATIONS
        );
    }

    let mut journal = Journal::open(&path).expect("the journal reopens");
    assert_eq!(
        journal
            .reject_unrevalidated_intents(kr_ipc::now_ms())
            .expect("rejects"),
        MAX_OUTSTANDING_MUTATIONS
    );
    assert_eq!(
        journal.outstanding(&caller).expect("reads"),
        0,
        "an actor whose worker restarted mid-admission is not left unable to submit anything"
    );
    let rejected = journal
        .read(caller, action(40))
        .expect("reads")
        .expect("a receipt");
    assert_eq!(rejected.state, ReceiptState::Rejected);
    assert_eq!(rejected.reason.as_ref(), Some(&RejectionReason::Expired));
}

/// KR-REQ-09.22, KR-REQ-23.46: a caller holding the outstanding limit can still cancel and still
/// stop the session, because those are what release the capacity the limit counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_limit_never_stops_a_caller_getting_back_under_it() {
    let host = host().await;
    let mut client = cli(&host).await;
    let caller = actor(&format!("local:{}", kr_ipc::paths::current_uid()));
    let held: Vec<ActionId> = {
        let mut session = host.service.runtime().session();
        let journal = session.journal_mut().expect("a journal");
        let mut held = Vec::new();
        for index in 0..MAX_OUTSTANDING_MUTATIONS {
            let byte = u8::try_from(110 + index).expect("a small index");
            let mut intent = fresh(byte, byte, byte);
            intent.actor_id = caller.clone();
            journal.accept(&intent).expect("an admitted intent");
            held.push(intent.action_id);
        }
        held
    };

    // The cancellation is admitted although the actor is at the limit, and it releases a slot.
    let cancel = MutationRequest {
        params: ParamsValue::from_typed(&kr_protocol::receipt::ActionCancelParams {
            action_id: held[0],
        })
        .expect("encodes"),
        target: ActionTarget {
            session_id: Nullable::null(),
            session_epoch: Nullable::null(),
            ..target(&host)
        },
        method: Method::ActionCancel.into(),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let cancelled = send_mutation(&mut client, cancel).await;
    assert!(
        matches!(cancelled, Outcome::Ok(_)),
        "a cancellation is what releases the capacity, so the limit cannot bound it: {cancelled:?}"
    );

    // And the authorised stop is admitted too, which section 7 requires whatever else is held.
    let close = close_mutation(
        &client,
        &host,
        DEFAULT_MUTATION_TTL.get(),
        ParamsValue::empty(),
    );
    let closed = send_mutation(&mut client, close).await;
    assert!(
        matches!(closed, Outcome::Ok(_)),
        "an authorised stop proceeds on the worker's current authority: {closed:?}"
    );
}

/// KR-REQ-09.07, KR-REQ-23.46: an identifier two actors both used names no single action, so the
/// host owner's cancellation refuses it rather than choosing one.
#[test]
fn an_identifier_two_actors_used_identifies_nothing_to_cancel() {
    let mut journal = Journal::in_memory().expect("a journal");
    journal.accept(&submission(1, 1, 1)).expect("one actor's");
    let mut other = submission(1, 2, 2);
    other.actor_id = actor("local:501");
    journal.accept(&other).expect("another actor's");

    let refused = journal.find_any(action(1));
    assert!(
        matches!(refused, Err(kr_worker::WorkerError::InvalidArgument(ref detail))
            if detail.contains("two actors") || detail.contains("2 actors")),
        "{refused:?}"
    );
    // Each actor's own lookup still finds its own, because that key is complete.
    assert!(
        journal
            .read(actor("device:phone"), action(1))
            .expect("reads")
            .is_some()
    );
    assert!(
        journal
            .read(actor("local:501"), action(1))
            .expect("reads")
            .is_some()
    );
}

/// KR-REQ-09.14, KR-REQ-09.15: retention never deletes a record whose own freshness window could
/// still admit its exact original request.
#[test]
fn retention_keeps_a_record_a_live_window_could_still_admit() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = temp
        .environment()
        .journal_database(SessionId::new(kr_ipc::new_uuid()));
    let mut journal = Journal::open(&path).expect("a journal");
    journal
        .accept(&fresh(1, 1, 1))
        .expect("an action admitted a moment ago");

    // The wall clock is pushed a year past the retention period, which is what a clock nobody can
    // prove looks like. The record's own window is at most five minutes old on the continuous
    // clock, so it can still admit the original request, and the record has to stay.
    let far_ahead = TimestampMs::new(kr_ipc::now_ms().get() + RETENTION_MS * 12);
    assert_eq!(
        journal.prune(far_ahead).expect("prunes"),
        0,
        "a record whose window can still admit its request is kept"
    );
    assert!(
        journal
            .read(actor("device:phone"), action(1))
            .expect("reads")
            .is_some()
    );

    // A record from an earlier run has no live window: the windows a host issues live in its
    // memory, and this one has restarted since.
    journal
        .accept(&at(2, 2, 2, TimestampMs::new(1_000)))
        .expect("an older action");
    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute(
            "UPDATE receipts SET created_boot = NULL, created_continuous_ms = NULL
             WHERE action_id = ?1",
            rusqlite::params![action(2).get().as_bytes().as_slice()],
        )
        .expect("the record reads as an earlier run's");
    assert_eq!(
        journal.prune(far_ahead).expect("prunes"),
        1,
        "an earlier run's record past the retention period is forgotten"
    );
    assert!(
        journal
            .read(actor("device:phone"), action(1))
            .expect("reads")
            .is_some(),
        "and this run's is still there"
    );
}

/// KR-REQ-09.09: a refusal the host can decide before the dispatch marker leaves a rejection, not
/// an uncertain outcome.
///
/// Section 9 has no `dispatching -> rejected` edge, on purpose: past the marker nothing may imply
/// that an uncertain side effect did not happen. The corollary is that every check the host can
/// make has to happen before the marker, because a refusal written after it would have to be
/// recorded as uncertain when nothing uncertain occurred.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_the_host_could_decide_leaves_a_rejection_rather_than_an_uncertain_outcome() {
    let host = host().await;
    let mut client = cli(&host).await;
    let caller = actor(&format!("local:{}", kr_ipc::paths::current_uid()));

    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    requested.insert(kr_protocol::attachment::AttachmentCapability::Geometry);
    requested.insert(kr_protocol::attachment::AttachmentCapability::Input);
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &kr_protocol::attachment::SessionAttachParams {
                session_id: host.session_id,
                mode: kr_protocol::attachment::AttachMode::Terminal,
                claim_geometry: true,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("the attachment is accepted")
        .to_typed()
        .expect("decodes");

    // A resize that quotes an epoch the session has moved past. The host knows it is stale, so it
    // never crosses the effect boundary and the receipt says `rejected`.
    let stale = kr_protocol::ids::GeometryEpoch::new(attached.geometry.epoch.get() + 7);
    let resize = MutationRequest {
        method: Method::TerminalResize.into(),
        params: ParamsValue::from_typed(&kr_protocol::attachment::TerminalResizeParams {
            attachment_id: attached.attachment.attachment_id,
            dimensions: Dimensions::new(100, 30),
            expected_geometry_epoch: stale,
        })
        .expect("encodes"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let named = resize.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, resize).await else {
        panic!("a resize at an epoch the session has moved past is refused");
    };
    // The refusal the session itself makes, decided before the marker rather than inside the
    // effect: a caller working from a size that has already changed does not own the one it is
    // describing.
    assert_eq!(error.code, ErrorCode::GeometryNotOwner);
    {
        let mut session = host.service.runtime().session();
        let journal = session.journal_mut().expect("a journal");
        let receipt = journal
            .read(caller.clone(), named)
            .expect("reads")
            .expect("the intent was committed before it was revalidated");
        assert_eq!(
            receipt.state,
            ReceiptState::Rejected,
            "the host could decide this, so it never wrote a dispatch marker"
        );
        assert_eq!(
            receipt.reason.as_ref(),
            Some(&RejectionReason::StalePreconditions)
        );
    }

    // The same for an input release from an attachment that holds no lease.
    let release = MutationRequest {
        method: Method::InputRelease.into(),
        params: ParamsValue::from_typed(&kr_protocol::input::InputReleaseParams {
            session_id: host.session_id,
            attachment_id: attached.attachment.attachment_id,
            epoch: kr_protocol::ids::InputLeaseEpoch::new(9),
        })
        .expect("encodes"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let named = release.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, release).await else {
        panic!("a release from an attachment that holds no lease is refused");
    };
    assert_eq!(error.code, ErrorCode::LeaseLost);
    rejected(&host, &caller, named);

    // Three refusals that used to be decided inside the effect, each one something this host can
    // decide from what it already holds: an attachment whose parameters the table would refuse, a
    // lease acquired by an attachment that cannot supply the encoding the application reads, and a
    // geometry transfer to an attachment holding no eligible claim. A refusal the host can decide
    // is a rejection, whatever code path happens to notice it.
    let semantic_claiming_geometry = MutationRequest {
        method: Method::SessionAttach.into(),
        params: ParamsValue::from_typed(&kr_protocol::attachment::SessionAttachParams {
            session_id: host.session_id,
            mode: kr_protocol::attachment::AttachMode::Semantic,
            claim_geometry: true,
            dimensions: Nullable::null(),
            terminal_profile_id: Nullable::null(),
            requested: kr_protocol::scalars::CanonicalSet::new(),
        })
        .expect("encodes"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let named = semantic_claiming_geometry.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, semantic_claiming_geometry).await else {
        panic!("a semantic attachment cannot claim geometry");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    rejected(&host, &caller, named);

    // A second terminal attachment that declares a profile with no enhanced keyboard, while the
    // application has negotiated one. It may watch; it may not take the keys.
    let plain: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &kr_protocol::attachment::SessionAttachParams {
                session_id: host.session_id,
                mode: kr_protocol::attachment::AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("dumb".to_owned()),
                requested: {
                    let mut requested = kr_protocol::scalars::CanonicalSet::new();
                    requested.insert(kr_protocol::attachment::AttachmentCapability::Input);
                    requested
                        .insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
                    // Granted the geometry right without claiming the size: eligibility is the
                    // claim rather than the capability, which is what the transfer below turns on.
                    requested.insert(kr_protocol::attachment::AttachmentCapability::Geometry);
                    requested
                },
            },
        )
        .await
        .expect("reaches the worker")
        .expect("a plain terminal may still attach")
        .to_typed()
        .expect("decodes");
    // The application negotiates the Kitty keyboard protocol, which is what makes the plain
    // terminal's ordinary encoding insufficient: the two mean different keys.
    host.service.runtime().session().ingest_output(b"\x1b[>5u");
    let acquire = MutationRequest {
        method: Method::InputAcquire.into(),
        params: ParamsValue::from_typed(&kr_protocol::input::InputAcquireParams {
            session_id: host.session_id,
            attachment_id: plain.attachment.attachment_id,
            expected_epoch: Nullable::null(),
        })
        .expect("encodes"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let named = acquire.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, acquire).await else {
        panic!("an attachment that cannot supply the encoding does not take the lease");
    };
    assert_eq!(error.code, ErrorCode::InputIncompatible);
    rejected(&host, &caller, named);

    // And a transfer to that attachment, which holds no eligible geometry claim.
    let transfer = MutationRequest {
        method: Method::TerminalGeometryTransfer.into(),
        params: ParamsValue::from_typed(&kr_protocol::attachment::TerminalGeometryTransferParams {
            attachment_id: plain.attachment.attachment_id,
            expected_geometry_epoch: host.service.runtime().session().geometry().epoch,
        })
        .expect("encodes"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let named = transfer.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, transfer).await else {
        panic!("a transfer to an attachment with no eligible claim is refused");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    rejected(&host, &caller, named);

    // A size no terminal serves, from the attachment that owns the geometry. The dimensions are a
    // refusal this host can decide from the request alone.
    let resize = MutationRequest {
        method: Method::TerminalResize.into(),
        params: ParamsValue::from_typed(&kr_protocol::attachment::TerminalResizeParams {
            attachment_id: attached.attachment.attachment_id,
            dimensions: Dimensions::new(0, 0),
            expected_geometry_epoch: host.service.runtime().session().geometry().epoch,
        })
        .expect("encodes"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let named = resize.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, resize).await else {
        panic!("a size no terminal serves is refused");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    rejected(&host, &caller, named);

    // Two things wrong at once, which is where the order of the checks shows. Moving a refusal
    // before the marker must not change which refusal it is, so each of these is answered the way
    // the effect answers it: the size is looked at before whose size it is, and a lease takeover's
    // quoted epoch is looked at before what the attachment can encode.
    let both = MutationRequest {
        method: Method::TerminalResize.into(),
        params: ParamsValue::from_typed(&kr_protocol::attachment::TerminalResizeParams {
            attachment_id: attached.attachment.attachment_id,
            dimensions: Dimensions::new(0, 0),
            expected_geometry_epoch: kr_protocol::ids::GeometryEpoch::new(
                host.service.runtime().session().geometry().epoch.get() + 4,
            ),
        })
        .expect("encodes"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let named = both.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, both).await else {
        panic!("a size no terminal serves is refused whatever epoch it quotes");
    };
    assert_eq!(
        error.code,
        ErrorCode::InvalidArgument,
        "an impossible size is an impossible size before it is anybody's to set"
    );
    rejected(&host, &caller, named);

    let stale_takeover = MutationRequest {
        method: Method::InputAcquire.into(),
        params: ParamsValue::from_typed(&kr_protocol::input::InputAcquireParams {
            session_id: host.session_id,
            attachment_id: plain.attachment.attachment_id,
            expected_epoch: Nullable::some(kr_protocol::ids::InputLeaseEpoch::new(9)),
        })
        .expect("encodes"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let named = stale_takeover.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, stale_takeover).await else {
        panic!("a takeover of a lease that has moved is refused");
    };
    assert_eq!(
        error.code,
        ErrorCode::LeaseLost,
        "the lease it named is gone, whatever this attachment could have encoded"
    );
    rejected(&host, &caller, named);

    // A precondition the caller stated, against a request that is also impossible. Moving a
    // refusal in front of the marker must not move it in front of what the caller asked this host
    // to check first: the generic `expected` comparison is the caller's own precondition, and it
    // is answered before the size is.
    let mut expected = kr_cbor::CanonicalMap::new();
    expected
        .insert(
            "geometry_epoch".to_owned(),
            kr_cbor::CanonicalValue::integer(i128::from(
                host.service
                    .runtime()
                    .session()
                    .geometry()
                    .epoch
                    .get()
                    .saturating_add(6),
            ))
            .expect("an epoch"),
        )
        .expect("a precondition this request states");
    let stale_precondition = MutationRequest {
        method: Method::TerminalResize.into(),
        expected: ParamsValue::new(kr_cbor::CanonicalValue::Map(expected)),
        params: ParamsValue::from_typed(&kr_protocol::attachment::TerminalResizeParams {
            attachment_id: attached.attachment.attachment_id,
            dimensions: Dimensions::new(0, 0),
            expected_geometry_epoch: host.service.runtime().session().geometry().epoch,
        })
        .expect("encodes"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let named = stale_precondition.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, stale_precondition).await else {
        panic!("a precondition that does not hold is refused");
    };
    assert_eq!(
        error.code,
        ErrorCode::DraftConflict,
        "the caller's own precondition is answered before the size it asked for"
    );
    rejected(&host, &caller, named);

    // The same two rules for the lease and for a cancellation: what the effect answers is answered
    // after the caller's own precondition, not before it.
    let mut expected = kr_cbor::CanonicalMap::new();
    expected
        .insert(
            "geometry_epoch".to_owned(),
            kr_cbor::CanonicalValue::integer(i128::from(
                host.service
                    .runtime()
                    .session()
                    .geometry()
                    .epoch
                    .get()
                    .saturating_add(9),
            ))
            .expect("an epoch"),
        )
        .expect("a precondition this request states");
    let release = MutationRequest {
        method: Method::InputRelease.into(),
        expected: ParamsValue::new(kr_cbor::CanonicalValue::Map(expected)),
        params: ParamsValue::from_typed(&kr_protocol::input::InputReleaseParams {
            session_id: host.session_id,
            attachment_id: attached.attachment.attachment_id,
            epoch: kr_protocol::ids::InputLeaseEpoch::new(9),
        })
        .expect("encodes"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let named = release.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, release).await else {
        panic!("a release under a precondition that does not hold is refused");
    };
    assert_eq!(
        error.code,
        ErrorCode::DraftConflict,
        "the caller's own precondition is answered before the lease it names"
    );
    rejected(&host, &caller, named);

    let mut expected = kr_cbor::CanonicalMap::new();
    expected
        .insert(
            "geometry_epoch".to_owned(),
            kr_cbor::CanonicalValue::integer(i128::from(
                host.service
                    .runtime()
                    .session()
                    .geometry()
                    .epoch
                    .get()
                    .saturating_add(9),
            ))
            .expect("an epoch"),
        )
        .expect("a precondition this request states");
    let cancel = MutationRequest {
        method: Method::ActionCancel.into(),
        expected: ParamsValue::new(kr_cbor::CanonicalValue::Map(expected)),
        params: ParamsValue::from_typed(&kr_protocol::receipt::ActionCancelParams {
            action_id: ActionId::new(kr_ipc::new_uuid()),
        })
        .expect("encodes"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let named = cancel.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, cancel).await else {
        panic!("a cancellation under a precondition that does not hold is refused");
    };
    assert_eq!(
        error.code,
        ErrorCode::DraftConflict,
        "the caller's own precondition is answered before the receipt it names"
    );
    rejected(&host, &caller, named);

    // The same size reported as a viewport, which is refused for the same reason and in the same
    // place rather than inside the effect.
    let viewport = MutationRequest {
        method: Method::AttachmentViewport.into(),
        params: ParamsValue::from_typed(&kr_protocol::attachment::AttachmentViewportParams {
            attachment_id: attached.attachment.attachment_id,
            dimensions: Dimensions::new(0, 0),
            position: Nullable::null(),
        })
        .expect("encodes"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let named = viewport.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, viewport).await else {
        panic!("a viewport no terminal serves is refused");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    rejected(&host, &caller, named);

    // An intent this host has already settled is not a pending action. The first cancellation
    // takes it back; the second is refused before the marker rather than failing a transition
    // inside the effect.
    let doomed = {
        let mut session = host.service.runtime().session();
        let journal = session.journal_mut().expect("a journal");
        let mut submission = fresh(70, 70, 70);
        submission.actor_id = caller.clone();
        journal.accept(&submission).expect("an admitted intent");
        crate::action(70)
    };
    let cancel = |client: &LocalClient| MutationRequest {
        method: Method::ActionCancel.into(),
        params: ParamsValue::from_typed(&kr_protocol::receipt::ActionCancelParams {
            action_id: doomed,
        })
        .expect("encodes"),
        ..close_mutation(
            client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let first = cancel(&client);
    let cancelled = send_mutation(&mut client, first).await;
    assert!(matches!(cancelled, Outcome::Ok(_)), "{cancelled:?}");
    let again = cancel(&client);
    let named = again.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, again).await else {
        panic!("an intent already cancelled has nothing left to cancel");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    rejected(&host, &caller, named);
}

/// Asserts that this action's receipt says the host decided the refusal before it dispatched.
#[track_caller]
fn rejected(host: &Host, caller: &ActorId, action_id: ActionId) {
    let mut session = host.service.runtime().session();
    let journal = session.journal_mut().expect("a journal");
    let receipt = journal
        .read(caller.clone(), action_id)
        .expect("reads")
        .expect("the intent was committed before it was revalidated");
    assert_eq!(
        receipt.state,
        ReceiptState::Rejected,
        "the host could decide this, so it never wrote a dispatch marker: {:?}",
        receipt.error.as_ref().map(|error| error.message.clone())
    );
    assert_eq!(
        receipt.reason.as_ref(),
        Some(&RejectionReason::StalePreconditions),
        "a refusal the host decided is a stale precondition rather than an expiry"
    );
    assert!(!receipt.state.has_dispatch_marker());
}

/// KR-REQ-09.16, KR-REQ-23.24: a forwarded retry whose accepted deadline has passed is still
/// answered from the journal, because a receipt outlives the freshness that admitted it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forwarded_retry_is_answered_after_its_deadline_and_never_first_admitted() {
    let host = host().await;
    let mut daemon = controller_client(&host).await;
    let actor_envelope = |actor_id: ActorId| kr_protocol::actor::ActorEnvelope {
        actor_id,
        ingress: kr_protocol::actor::ActorIngress::LocalIpc,
        device_id: Nullable::null(),
        grant_id: Nullable::null(),
        grant_revision: Nullable::null(),
        controller_generation: ControllerGeneration::new(1),
        connection_id: kr_protocol::ids::ConnectionId::new(Uuid::from_bytes([7; 16])),
    };
    let forwarded = |deadline: u64, mutation: MutationRequest| {
        ControlFrame::Forwarded(Box::new(kr_protocol::local::ForwardedMutation {
            mutation,
            actor: actor_envelope(actor("local:501")),
            // A local caller acts under no grant, so there are no rights to narrow it by.
            grant_rights: kr_protocol::scalars::CanonicalSet::new(),
            accepted_deadline_boot_ms: U64::new(deadline),
        }))
    };

    // Admitted with a live deadline, well past the present reading of the machine's clock.
    let mutation = MutationRequest {
        method: Method::SessionAttach.into(),
        params: ParamsValue::from_typed(&kr_protocol::attachment::SessionAttachParams {
            session_id: host.session_id,
            mode: kr_protocol::attachment::AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested: {
                let mut requested = kr_protocol::scalars::CanonicalSet::new();
                requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
                requested
            },
        })
        .expect("encodes"),
        ..close_mutation(
            &daemon,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let live = kr_ipc::clock::boot_elapsed_ms() + 120_000;
    let admitted = send_frame(&mut daemon, forwarded(live, mutation.clone())).await;
    assert!(matches!(admitted, Outcome::Ok(_)), "{admitted:?}");

    // The same mutation again, with a deadline that has already passed. The action is retained, so
    // the retry is answered rather than refused for being stale.
    let retried = send_frame(&mut daemon, forwarded(1, mutation.clone())).await;
    assert!(
        matches!(retried, Outcome::Ok(_)),
        "a retained action is answered after its deadline: {retried:?}"
    );

    // A *first* admission with the same spent deadline is refused, because there is no lifetime
    // left to admit one under.
    let first = MutationRequest {
        action_id: ActionId::new(kr_ipc::new_uuid()),
        ..mutation
    };
    let Outcome::Error(error) = send_frame(&mut daemon, forwarded(1, first)).await else {
        panic!("a first admission with no lifetime left is refused");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);
}

/// KR-REQ-09.22: a connection that offers to hold no outstanding mutation is refused at the
/// handshake rather than read as one that holds one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_admits_no_mutation_is_refused_at_the_handshake() {
    let host = host().await;
    let connection = kr_ipc::endpoint::Connection::connect(&host.endpoint)
        .await
        .expect("connects");
    let (mut reader, mut writer) =
        kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
    writer
        .write_message(&ControlFrame::Hello(kr_protocol::local::LocalHello {
            offered_versions: vec![PROTOCOL_VERSION],
            build_id: build(),
            client: LocalClientKind::Cli,
            capabilities: kr_protocol::scalars::CanonicalSet::new(),
            max_receive: kr_protocol::hello::ReceiveLimits {
                max_outstanding_mutations: U64::new(0),
                ..kr_protocol::hello::ReceiveLimits::default()
            },
        }))
        .await
        .expect("writes the hello");
    let frame: ControlFrame = reader.read_message().await.expect("the host answers");
    let ControlFrame::Response(response) = frame else {
        panic!("a connection that admits nothing is refused: {frame:?}");
    };
    let Outcome::Error(error) = response.outcome else {
        panic!("a connection that admits nothing is refused");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);
}

/// KR-REQ-09.22: the protocol defaults, asserted from the one place that defines them.
#[test]
fn the_protocol_defaults_are_what_section_nine_states() {
    assert_eq!(MAX_CONTROL_FRAME_LEN, 1024 * 1024);
    assert_eq!(MAX_INPUT_FRAME_LEN, 64 * 1024);
    assert_eq!(MAX_OUTSTANDING_MUTATIONS, 8);
    assert_eq!(MAX_CONCURRENT_ATTACHMENTS, 32);
    assert_eq!(MAX_SEND_QUEUE_BYTES, 8 * 1024 * 1024);
    assert_eq!(MAX_REMOTE_DISPATCH_LEASE.get(), 5_000);
    assert_eq!(MAX_ACTION_WINDOW.get(), 300_000);

    // The frame bounds the codec enforces are the same figures, read from the same constants
    // rather than repeated beside them.
    use kr_protocol::frame::StreamKind;
    assert_eq!(StreamKind::Control.max_frame_len(), MAX_CONTROL_FRAME_LEN);
    assert_eq!(
        StreamKind::TerminalInput.max_frame_len(),
        MAX_INPUT_FRAME_LEN
    );
    // And the limits a host offers in `hello` are the same figures too.
    let offered = kr_protocol::hello::ReceiveLimits::default();
    assert_eq!(
        offered.max_control_frame_len.get(),
        MAX_CONTROL_FRAME_LEN as u64
    );
    assert_eq!(
        offered.max_input_frame_len.get(),
        MAX_INPUT_FRAME_LEN as u64
    );
    assert_eq!(
        offered.max_outstanding_mutations.get(),
        MAX_OUTSTANDING_MUTATIONS as u64
    );
    assert_eq!(
        offered.max_send_queue_bytes.get(),
        MAX_SEND_QUEUE_BYTES as u64
    );
}

/// KR-REQ-09.22: a ninth outstanding mutation is refused rather than admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ninth_outstanding_mutation_is_refused() {
    let host = host().await;
    let mut client = cli(&host).await;
    let caller = actor(&format!("local:{}", kr_ipc::paths::current_uid()));
    {
        let mut session = host.service.runtime().session();
        let journal = session.journal_mut().expect("a journal");
        // Eight intents this host accepted and has not settled. That is what a worker holds after
        // it restarted with admitted intents that were never dispatched.
        for index in 0..MAX_OUTSTANDING_MUTATIONS {
            let byte = u8::try_from(100 + index).expect("a small index");
            let mut held = fresh(byte, byte, byte);
            held.actor_id = caller.clone();
            journal.accept(&held).expect("an admitted intent");
        }
        assert_eq!(
            journal.outstanding(&caller).expect("reads"),
            MAX_OUTSTANDING_MUTATIONS
        );
    }
    // An ordinary mutation, which the limit bounds. The two that release capacity do not count,
    // and `the_limit_never_stops_a_caller_getting_back_under_it` is where that is proved.
    let ninth = bounded_mutation(&client, &host);
    let Outcome::Error(error) = send_mutation(&mut client, ninth).await else {
        panic!("a ninth outstanding mutation is refused");
    };
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(host.service.runtime().state().as_str(), "live");

    // Settling one of them makes room again.
    {
        let mut session = host.service.runtime().session();
        let journal = session.journal_mut().expect("a journal");
        journal
            .reject(
                caller.clone(),
                action(100),
                RejectionReason::Expired,
                None,
                kr_ipc::now_ms(),
            )
            .expect("one is settled");
    }
    let again = bounded_mutation(&client, &host);
    let admitted = send_mutation(&mut client, again).await;
    assert!(matches!(admitted, Outcome::Ok(_)), "{admitted:?}");
}

/// An ordinary mutation the outstanding-mutation limit bounds.
fn bounded_mutation(client: &LocalClient, host: &Host) -> MutationRequest {
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    MutationRequest {
        method: Method::SessionAttach.into(),
        params: ParamsValue::from_typed(&kr_protocol::attachment::SessionAttachParams {
            session_id: host.session_id,
            mode: kr_protocol::attachment::AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested,
        })
        .expect("encodes"),
        ..close_mutation(
            client,
            host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-09.19: the platform time adapter
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.19: the adapter reads this machine's own time service, and records the source, the
/// status and a bounded uncertainty rather than an invented certainty.
#[test]
fn the_platform_time_adapter_reads_this_machines_own_time_service() {
    let reading = PlatformTimeAdapter::new().read();
    assert_eq!(reading.platform, platform_name());
    assert!(
        matches!(reading.platform.as_str(), "macos" | "linux" | "windows"),
        "this build qualifies three platforms and names anything else as unqualified: {}",
        reading.platform
    );
    assert!(
        reading.api == "ntp_adjtime(2)" || reading.api == "w32tm /query /status",
        "the reading names the interface it came from: {}",
        reading.api
    );
    assert!(TimeSyncSource::ALL.contains(&reading.source));
    assert!(TimeSyncStatus::ALL.contains(&reading.status));
    assert!(reading.wall_clock_ms.get() > 0);
    match reading.status {
        TimeSyncStatus::Unavailable => {
            assert!(
                reading.uncertainty_us.as_ref().is_none(),
                "a reading that could not be taken carries no bound"
            );
            assert!(!reading.is_qualified());
        }
        _ => {
            // Whatever the machine says, a qualified reading has to have a bound: nothing here
            // reports a synchronised clock with no statement of how wrong it may be.
            if reading.is_qualified() {
                assert!(reading.uncertainty_us.as_ref().is_some());
                assert!(
                    reading.uncertainty_us.as_ref().expect("a bound").get()
                        <= MAX_TRUSTED_UNCERTAINTY_US
                );
                assert!(reading.source.is_disciplined());
            }
        }
    }
}

/// KR-REQ-09.19: every recorded platform reading classifies the way `fixtures/time/adapter.json`
/// states, for all three platforms, from one classifier.
#[test]
fn every_recorded_platform_reading_classifies_the_way_the_fixture_states() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/time/adapter.json");
    let text = std::fs::read_to_string(&path).expect("the time fixture is committed");
    let fixture: serde_json::Value = serde_json::from_str(&text).expect("the fixture parses");
    assert_eq!(fixture["version"], 1);
    assert_eq!(
        fixture["bounds"]["max_trusted_uncertainty_us"].as_u64(),
        Some(MAX_TRUSTED_UNCERTAINTY_US)
    );
    assert_eq!(
        fixture["bounds"]["max_wall_clock_rollback_ms"].as_u64(),
        Some(MAX_WALL_CLOCK_ROLLBACK_MS)
    );

    let stamp = TimestampMs::new(1_700_000_000_000);
    let platforms = fixture["platforms"]
        .as_array()
        .expect("the fixture lists platforms");
    let mut named = Vec::new();
    let mut cases = 0_usize;
    for platform in platforms {
        let name = platform["platform"].as_str().expect("a platform name");
        let api = platform["api"].as_str().expect("an interface name");
        named.push(name.to_owned());
        for case in platform["cases"].as_array().expect("cases") {
            cases += 1;
            let reading = if let Some(raw) = case.get("raw") {
                classify_unix(
                    name,
                    api,
                    UnixTimex {
                        time_state: i32::try_from(
                            raw["time_state"].as_i64().expect("a time state"),
                        )
                        .expect("a small state"),
                        status: i32::try_from(raw["status"].as_i64().expect("a status word"))
                            .expect("a status word"),
                        maxerror_us: raw["maxerror_us"].as_i64().expect("a bound"),
                        esterror_us: raw["esterror_us"].as_i64().expect("an estimate"),
                    },
                    stamp,
                )
            } else {
                classify_windows(
                    name,
                    api,
                    case["report"].as_str().expect("a service report"),
                    stamp,
                )
            };
            let expect = &case["expect"];
            let label = case["name"].as_str().unwrap_or("a case");
            assert_eq!(
                reading.source.as_str(),
                expect["source"].as_str().expect("an expected source"),
                "{name}: {label}"
            );
            assert_eq!(
                reading.status.as_str(),
                expect["status"].as_str().expect("an expected status"),
                "{name}: {label}"
            );
            assert_eq!(
                reading.uncertainty_us.as_ref().map(|bound| bound.get()),
                expect["uncertainty_us"].as_u64(),
                "{name}: {label}"
            );
            if let Some(estimate) = expect.get("estimated_error_us").and_then(|v| v.as_u64()) {
                assert_eq!(
                    reading.estimated_error_us.as_ref().map(|bound| bound.get()),
                    Some(estimate),
                    "{name}: {label}"
                );
            }
            assert_eq!(
                reading.is_qualified(),
                expect["qualified"].as_bool().expect("a qualification"),
                "{name}: {label}"
            );
        }
    }
    assert_eq!(named, vec!["macos", "linux", "windows"]);
    assert!(cases >= 12, "the fixture covers each platform's states");
    assert!(
        named.contains(&platform_name().to_owned()),
        "this machine's platform is one the fixture records"
    );
}

/// KR-REQ-09.19: automatic retrust needs qualified evidence from the configured host time
/// authority; otherwise the owner retrusts explicitly, and an ordinary paired peer never can.
#[test]
fn retrust_needs_the_host_time_authority_or_the_owner_and_never_a_paired_peer() {
    let qualified = classify_unix(
        "macos",
        "ntp_adjtime(2)",
        UnixTimex {
            time_state: kr_worker::action::adapter::unix_model::TIME_OK,
            status: kr_worker::action::adapter::unix_model::STA_PLL,
            maxerror_us: 62_192,
            esterror_us: 500,
        },
        TimestampMs::new(1_700_000_000_000),
    );
    assert!(
        RetrustEvidence::HostTimeAuthority {
            authority: "time.example".to_owned(),
            reading: qualified,
        }
        .qualifies_for("time.example")
        .is_ok()
    );

    let unsynchronised = classify_unix(
        "linux",
        "ntp_adjtime(2)",
        UnixTimex {
            time_state: kr_worker::action::adapter::unix_model::TIME_ERROR,
            status: kr_worker::action::adapter::unix_model::STA_UNSYNC,
            maxerror_us: 16_000_000,
            esterror_us: 16_000_000,
        },
        TimestampMs::new(1_700_000_000_000),
    );
    assert!(
        RetrustEvidence::HostTimeAuthority {
            authority: "time.example".to_owned(),
            reading: unsynchronised,
        }
        .qualifies_for("time.example")
        .is_err(),
        "an authority that cannot say what the time is is not evidence"
    );

    assert!(
        RetrustEvidence::OwnerRetrust {
            action_digest: Digest256::from_bytes([7; 32]),
        }
        .qualifies_for("time.example")
        .is_ok()
    );
    assert!(
        RetrustEvidence::PairedPeer {
            device_id: kr_protocol::ids::DeviceId::new(Uuid::from_bytes([5; 16])),
        }
        .qualifies_for("time.example")
        .is_err(),
        "an ordinary paired peer's clock is not a trusted time authority"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-09.20, 09.23: the raw input stream and a slow client
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.20: every input frame carries the lease epoch and an increasing sequence on this
/// connection's own stream, and nothing about a keystroke is journalled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_input_frame_carries_the_epoch_and_an_increasing_sequence_on_one_connection() {
    let host = host().await;
    let mut client = cli(&host).await;
    let attachment = attach(&mut client, &host).await;
    let epoch = acquire(&mut client, &host, attachment).await;

    for sequence in 0..3_u64 {
        let result = write_input(&mut client, &host, attachment, epoch, sequence, b"a")
            .await
            .expect("an in-order write is accepted");
        assert_eq!(result.sequence.get(), sequence);
    }

    // A sequence that has already been consumed does not follow, so it is refused rather than
    // applied twice. Its own position is what the refusal names.
    for replayed in [0_u64, 1, 2] {
        let error = write_input(&mut client, &host, attachment, epoch, replayed, b"a")
            .await
            .expect_err("a consumed sequence is refused");
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{replayed}");
        assert!(
            error.message.contains("does not follow"),
            "{replayed}: {}",
            error.message
        );
    }

    // A stale epoch is refused and never acquires the lease implicitly.
    let stale = kr_protocol::ids::InputLeaseEpoch::new(epoch.get().saturating_sub(1));
    let error = write_input(&mut client, &host, attachment, stale, 3, b"a")
        .await
        .expect_err("a stale epoch is refused");
    assert_eq!(error.code, ErrorCode::LeaseLost);

    // Nothing a keystroke did is in the journal: input is a stream, not a mutation. The two
    // receipts here are the attachment and the lease, which are mutations; neither is a keystroke.
    let mut session = host.service.runtime().session();
    let journal = session.journal_mut().expect("a journal");
    assert_eq!(
        journal.len().expect("reads"),
        2,
        "the attach and the acquire leave receipts; the three writes leave none"
    );
}

/// KR-REQ-09.20: a reconnection acquires a new stream identity and discards what the old one had
/// not delivered, rather than replaying it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reconnect_discards_unsent_keystrokes_rather_than_replaying_them() {
    let host = host().await;
    let mut first = cli(&host).await;
    let attachment = attach(&mut first, &host).await;
    let epoch = acquire(&mut first, &host, attachment).await;
    write_input(&mut first, &host, attachment, epoch, 0, b"x")
        .await
        .expect("the holder writes");

    // The client goes away and comes back. Its new attachment takes the lease, which advances the
    // epoch, and the new stream starts at sequence zero rather than continuing the old one.
    drop(first);
    let mut second = cli(&host).await;
    let reattached = attach(&mut second, &host).await;
    let next = acquire(&mut second, &host, reattached).await;
    assert!(
        next.get() > epoch.get(),
        "a reconnection acquires a new stream identity"
    );

    let error = write_input(&mut second, &host, reattached, next, 1, b"y")
        .await
        .expect_err("the new stream starts at zero rather than continuing the old positions");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    write_input(&mut second, &host, reattached, next, 0, b"y")
        .await
        .expect("the new stream's first position is accepted");

    // And the old stream cannot write again, so nothing it held is replayed. Its attachment went
    // with its connection, which is a stronger answer than a lost lease: there is no longer an
    // attachment for the old position to belong to.
    let error = write_input(&mut second, &host, attachment, epoch, 1, b"z")
        .await
        .expect_err("the previous stream identity is gone");
    assert_eq!(error.code, ErrorCode::AmbiguousAttachment);

    // The epoch it held is not the current one either, so even an attachment that survived a
    // reconnection could not continue the old stream.
    let survivor = attach(&mut second, &host).await;
    let error = write_input(&mut second, &host, survivor, epoch, 0, b"z")
        .await
        .expect_err("the previous epoch is invalid at once");
    assert_eq!(error.code, ErrorCode::LeaseLost);
}

async fn attach(client: &mut LocalClient, host: &Host) -> kr_protocol::ids::AttachmentId {
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    requested.insert(kr_protocol::attachment::AttachmentCapability::Input);
    let outcome = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target(host),
            &kr_protocol::attachment::SessionAttachParams {
                session_id: host.session_id,
                mode: kr_protocol::attachment::AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("the attachment is accepted");
    let result: kr_protocol::attachment::SessionAttachResult = outcome.to_typed().expect("decodes");
    result.attachment.attachment_id
}

async fn acquire(
    client: &mut LocalClient,
    host: &Host,
    attachment_id: kr_protocol::ids::AttachmentId,
) -> kr_protocol::ids::InputLeaseEpoch {
    let outcome = client
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            target(host),
            &kr_protocol::input::InputAcquireParams {
                session_id: host.session_id,
                attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("the lease is acquired");
    let result: kr_protocol::input::InputAcquireResult = outcome.to_typed().expect("decodes");
    result.lease.epoch
}

async fn write_input(
    client: &mut LocalClient,
    host: &Host,
    attachment_id: kr_protocol::ids::AttachmentId,
    epoch: kr_protocol::ids::InputLeaseEpoch,
    sequence: u64,
    bytes: &[u8],
) -> std::result::Result<kr_protocol::input::InputWriteResult, kr_protocol::error::ProtocolError> {
    client
        .request(
            Method::InputWrite,
            &kr_protocol::input::InputWriteParams {
                session_id: host.session_id,
                attachment_id,
                epoch,
                sequence: kr_protocol::ids::InputSequence::new(sequence),
                bytes: kr_protocol::scalars::Bytes::new(bytes.to_vec()),
            },
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
}

/// KR-REQ-09.23: an input batch beyond the frame bound is refused rather than truncated, so the
/// parser is never told about bytes the host decided not to carry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_input_batch_beyond_the_frame_bound_is_refused_rather_than_truncated() {
    let host = host().await;
    let mut client = cli(&host).await;
    let attachment = attach(&mut client, &host).await;
    let epoch = acquire(&mut client, &host, attachment).await;
    let oversized = vec![b'a'; MAX_INPUT_FRAME_LEN + 1];
    let error = write_input(&mut client, &host, attachment, epoch, 0, &oversized)
        .await
        .expect_err("a batch beyond the input frame bound is refused");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(
        error.message.contains(&MAX_INPUT_FRAME_LEN.to_string()),
        "the refusal names the bound: {}",
        error.message
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-09.14, 09.17, 09.18: the host's own time contract, while it is live
// ---------------------------------------------------------------------------------------------

/// Writes a record into `path` that a host which ran thirty days ago would have left.
///
/// Two things make it collectable: its wall-clock stamp is past the retention period, and it reads
/// as an earlier run's, which is what a thirty-day-old record always is. The windows that could
/// have admitted it live in the memory of a host that has restarted since.
fn record_from_an_earlier_run(path: &std::path::Path, action: u8) {
    let mut journal = Journal::open(path).expect("a journal");
    journal
        .accept(&at(action, action, action, TimestampMs::new(1_000)))
        .expect("an intent from an earlier run");
    rusqlite::Connection::open(path)
        .expect("the same database")
        .execute(
            "UPDATE receipts SET created_boot = NULL, created_continuous_ms = NULL",
            [],
        )
        .expect("the record reads as an earlier run's");
}

/// Writes down that this host's owner confirmed its wall clock.
///
/// Retention is expiry-based collection, and the host time contract stops that while the wall clock
/// cannot be proved. Whether *this machine's* clock is provable is not what a collection test is
/// about, and it differs by machine: a macOS host disciplined by `timed` qualifies, while a Linux
/// continuous-integration runner reports `ntp_adjtime(2)` with neither a discipline flag nor an
/// unsynchronised one - a clock somebody set that nothing claims to be keeping - which this
/// contract reads as unproved however small the kernel's error bound happens to be. A test that
/// inherited that from the machine would pass on one and fail on the other while the code under it
/// behaved identically.
///
/// So a collection test says what it needs instead: a host whose owner confirmed its clock, which
/// is the route section 9 leaves open to a host with no configured time authority. It is written
/// into the journal rather than asked for afterwards because the first maintenance tick runs the
/// moment the host comes up, and it survives every later observation precisely because the
/// confirmation is the owner's.
fn owner_confirmed_clock(path: &std::path::Path) {
    let mut journal = Journal::open(path).expect("a journal");
    journal
        .record_host_time(&HostTimeState {
            checkpoint: Nullable::null(),
            trust: WallClockTrust::Trusted,
            owner_confirmed: true,
            proven: Nullable::null(),
            tombstones: Vec::new(),
        })
        .expect("the owner's confirmation is written down");
}

/// What this host's time contract says about its wall clock, for a message that has to explain a
/// collection that did not run.
fn clock_state(session: &Session) -> String {
    let time = session.time();
    format!(
        "{:?}, may_collect_expired={}, reading={:?}",
        time.trust(),
        time.may_collect_expired(),
        time.checkpoint().map(|checkpoint| checkpoint.reading)
    )
}

/// Waits for `condition` to hold, and says whether it did.
async fn within(timeout: std::time::Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if condition() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

/// KR-REQ-09.14: a live host collects records past the retention period on its own, and on a
/// schedule rather than on a caller's request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_live_host_collects_records_past_the_retention_period_on_its_own() {
    // Nothing in this test asks the host to collect anything. The record is there before the
    // session opens, and what removes it is the host's own maintenance while it serves.
    let host = host_prepared(|path| {
        record_from_an_earlier_run(path, 40);
        owner_confirmed_clock(path);
    })
    .await;
    let gone = within(std::time::Duration::from_secs(10), || {
        host.service
            .runtime()
            .session()
            .journal()
            .expect("a journal")
            .len()
            .expect("reads")
            == 0
    })
    .await;
    assert!(
        gone,
        "a live host collects what the retention period covers; this host's clock is {}",
        clock_state(&host.service.runtime().session())
    );

    // And it is a schedule, not something every request drags along: a second record that arrives
    // after the collection has run is still there, because the next collection is an interval
    // away rather than one mutation away.
    {
        let mut session = host.service.runtime().session();
        let journal = session.journal_mut().expect("a journal");
        journal
            .accept(&at(41, 41, 41, TimestampMs::new(2_000)))
            .expect("a second record from an earlier run");
    }
    let mut client = cli(&host).await;
    let refused = close_mutation(&client, &host, 0, ParamsValue::empty());
    let refused = send_mutation(&mut client, refused).await;
    assert!(matches!(refused, Outcome::Error(_)), "a zero lifetime");
    assert_eq!(
        host.service
            .runtime()
            .session()
            .journal()
            .expect("a journal")
            .len()
            .expect("reads"),
        2,
        "collection runs on the host's interval rather than on a mutation's back"
    );
}

/// KR-REQ-09.17: what a host writes down about its clocks is what the next one reads back.
#[test]
fn a_restarted_host_reads_back_what_it_recorded_about_its_clocks() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let path = environment.journal_database(session_id);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");

    let first = Session::open(session_config(&environment, session_id)).expect("opens");
    let recorded = first.time().checkpoint().expect("a checkpoint");
    let trust = first.time().trust();
    drop(first);

    // The row is there, written by the session that took the mark rather than by anything a
    // caller asked for.
    let row: Vec<u8> = rusqlite::Connection::open(&path)
        .expect("the same database")
        .query_row("SELECT state FROM host_time WHERE id = 1", [], |row| {
            row.get(0)
        })
        .expect("the recorded state");
    let state: kr_protocol::action::HostTimeState =
        kr_cbor::from_canonical_slice(&row, &kr_cbor::Limits::DEFAULT).expect("decodes");
    assert_eq!(state.trust, trust);
    assert_eq!(
        state
            .checkpoint
            .as_ref()
            .map(|mark| mark.reading.platform.as_str()),
        Some(platform_name())
    );

    // A second host on the same journal starts from what the first one wrote rather than from
    // whatever its own clock happens to say.
    let second = Session::open(session_config(&environment, session_id)).expect("reopens");
    assert_eq!(second.time().trust(), trust);
    let restored = second.time().checkpoint().expect("a checkpoint");
    assert_eq!(restored.boot_identity, recorded.boot_identity);
}

/// KR-REQ-09.18: a host whose recorded clock cannot be proved stops collecting and keeps serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clock_that_cannot_be_proved_stops_collection_and_not_the_session() {
    // The state a host wrote down in an earlier boot, having proved its wall clock had reached a
    // point thirty days beyond what this one reads. Time does not go backwards, so the only
    // reading of that is a clock this host cannot prove: section 9 marks trust unresolved and
    // stops expiry-based collection, and leaves everything bounded by this boot's continuous
    // clock working.
    let host = host_prepared(|path| {
        record_from_an_earlier_run(path, 42);
        let future = kr_ipc::now_ms().get() + 30 * 86_400_000;
        let state = kr_protocol::action::HostTimeState {
            checkpoint: Nullable::null(),
            trust: kr_protocol::action::WallClockTrust::Trusted,
            owner_confirmed: false,
            proven: Nullable::some(kr_protocol::action::ProvenWallClock {
                boot_identity: kr_protocol::identity::BootIdentity {
                    source: kr_protocol::identity::BootIdentitySource::MacosBootSessionUuid,
                    value: kr_protocol::scalars::Bytes::new(vec![9; 16]),
                },
                wall_clock_ms: TimestampMs::new(future),
                continuous_ms: U64::new(0),
            }),
            tombstones: Vec::new(),
        };
        Journal::open(path)
            .expect("a journal")
            .record_host_time(&state)
            .expect("the recorded state");
    })
    .await;

    // The clock is unresolved, and it was the host's own observation that decided that.
    let unresolved = within(std::time::Duration::from_secs(10), || {
        host.service.runtime().session().time().trust()
            == kr_protocol::action::WallClockTrust::Unresolved
    })
    .await;
    assert!(unresolved, "a clock behind what was proved is not evidence");
    assert!(
        !host
            .service
            .runtime()
            .session()
            .time()
            .may_collect_expired()
    );
    assert_eq!(
        host.service
            .runtime()
            .session()
            .journal()
            .expect("a journal")
            .len()
            .expect("reads"),
        1,
        "collecting against a clock this host cannot prove is how a rollback deletes what had \
         not expired"
    );

    // And the session still serves. A fresh action is bounded by this boot's continuous clock,
    // which nothing about the wall clock bears on, so it is admitted and applied as usual.
    let mut client = cli(&host).await;
    let attach = bounded_mutation(&client, &host);
    let attached = send_mutation(&mut client, attach).await;
    assert!(
        matches!(attached, Outcome::Ok(_)),
        "an unresolved wall clock does not stop a fresh action: {attached:?}"
    );

    // What the host observed is written down, so a restart does not start by trusting the clock
    // this one rejected.
    let row: Vec<u8> = rusqlite::Connection::open(&host.journal_path)
        .expect("the same database")
        .query_row("SELECT state FROM host_time WHERE id = 1", [], |row| {
            row.get(0)
        })
        .expect("the recorded state");
    let state: kr_protocol::action::HostTimeState =
        kr_cbor::from_canonical_slice(&row, &kr_cbor::Limits::DEFAULT).expect("decodes");
    assert_eq!(state.trust, kr_protocol::action::WallClockTrust::Unresolved);
}

/// KR-REQ-09.12, 09.13: a fence report bigger than one acknowledgement is delivered a page at a
/// time from the journal, every page encodes inside one control frame, and the pages together name
/// every affected action however many there are.
#[test]
fn a_fence_report_too_big_for_one_acknowledgement_is_delivered_a_page_at_a_time() {
    let mut journal = Journal::in_memory().expect("a journal");
    // More than one page, and more than a worker could hold names for in memory: the names are in
    // the journal, so the only bound is the page.
    let affected = kr_protocol::action::MAX_NAMED_FENCED_ACTIONS * 17 + 40;
    for index in 0..affected {
        let action_id = ActionId::new(Uuid::from_bytes(index_bytes(index)));
        journal
            .accept(&Submission {
                action_id,
                ..fresh(1, 1, 1)
            })
            .expect("an admitted intent");
    }
    let (fenced, outcome) = journal.fence_for_revocation(4, None, kr_ipc::now_ms(), 0, 1);
    outcome.expect("the fence runs");
    assert_eq!(
        fenced.named(),
        affected as u64,
        "every affected action is named"
    );

    // The daemon takes the names a page at a time, from where the previous page ended, until the
    // journal says nothing remains. What it ends up with is everything the fence named.
    let mut taken: Vec<kr_protocol::action::FencedAction> = Vec::new();
    let mut from = 0;
    loop {
        let page = journal.evidence_page(4, from).expect("a page");
        let evidence = page.evidence();
        let frame = kr_cbor::to_canonical_vec(&ControlFrame::AuthorityRevisionAck(
            kr_protocol::worker::AuthorityRevisionAck {
                session_id: SessionId::new(kr_ipc::new_uuid()),
                revision: kr_protocol::ids::AuthorityRevision::new(4),
                fence: Some(evidence.clone()),
            },
        ))
        .expect("the acknowledgement encodes");
        let names = page.rejected.len() + page.possibly_executed.len();
        assert!(
            frame.len() < MAX_CONTROL_FRAME_LEN,
            "a page of {names} names encodes to {} bytes",
            frame.len()
        );
        assert!(names <= kr_protocol::action::MAX_NAMED_FENCED_ACTIONS);
        assert_eq!(evidence.omitted.get(), 0, "nothing is omitted: it is paged");
        taken.extend(page.rejected.iter().cloned());
        from += names as u64;
        if page.remaining == 0 {
            break;
        }
    }
    assert_eq!(
        taken.len(),
        affected,
        "the pages together name every action the fence took back"
    );
    for index in 0..affected {
        let action_id = ActionId::new(Uuid::from_bytes(index_bytes(index)));
        assert!(
            taken.iter().any(
                |named| named.action_id == action_id && named.actor_id == actor("device:phone")
            ),
            "action {index} is named under the actor whose action it was"
        );
        let receipt = journal
            .read(actor("device:phone"), action_id)
            .expect("reads")
            .expect("a receipt");
        assert_eq!(receipt.state, ReceiptState::Rejected);
        assert_eq!(receipt.reason.as_ref(), Some(&RejectionReason::Revoked));
    }
}

/// KR-REQ-09.12, 09.13: a revocation's names survive collection, the worker's own restart and
/// every newer revocation, until the daemon has taken them.
#[test]
fn fence_evidence_outlives_collection_and_a_restart_and_every_revocation_until_it_is_taken() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = temp
        .environment()
        .journal_database(SessionId::new(kr_ipc::new_uuid()));
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    let caller = actor("device:phone");
    {
        let mut journal = Journal::open(&path).expect("a journal");
        let mut old = at(21, 21, 21, TimestampMs::new(1_000));
        old.actor_id = caller.clone();
        journal.accept(&old).expect("an admitted intent");
        let (fenced, outcome) = journal.fence_for_revocation(4, None, kr_ipc::now_ms(), 0, 1);
        outcome.expect("the fence runs");
        assert_eq!(fenced.rejected, 1);
        // The record it named is now old enough to collect, and from an earlier run. Collection
        // takes the receipt; the revocation's name for it is not the receipt.
        rusqlite::Connection::open(&path)
            .expect("the same database")
            .execute(
                "UPDATE receipts SET created_boot = NULL, created_continuous_ms = NULL",
                [],
            )
            .expect("the record reads as an earlier run's");
        assert_eq!(
            journal
                .prune(TimestampMs::new(RETENTION_MS + 2_000))
                .expect("prunes"),
            1
        );
        let page = journal.evidence_page(4, 0).expect("a page");
        assert_eq!(
            page.rejected,
            vec![kr_protocol::action::FencedAction {
                actor_id: caller.clone(),
                action_id: crate::action(21),
            }],
            "what the revocation owes a caller is not deleted with the receipt"
        );
    }

    // And it survives the worker restarting, because it is in the journal rather than in memory.
    let mut journal = Journal::open(&path).expect("the journal reopens");
    assert_eq!(
        journal.evidence_page(4, 0).expect("a page").rejected.len(),
        1
    );

    // Newer revocations keep them, because a page of them may still be owed: the daemon takes the
    // names a page at a time, and a revision that advanced between two pages would otherwise take
    // the rest of the answer with it. Two revisions pass here, which is what used to be enough to
    // lose them.
    for revision in [5, 6] {
        let (_, outcome) = journal.fence_for_revocation(revision, None, kr_ipc::now_ms(), 0, 1);
        outcome.expect("the fence runs");
        assert_eq!(
            journal.evidence_page(4, 0).expect("a page").rejected.len(),
            1,
            "revision 4's name is still answerable after revision {revision}"
        );
    }

    // The daemon says it has the name, which is what finishes revocation 4. An announcement asks
    // for the page after the names it already holds, and that is the count; the generation is
    // which controller holds them.
    journal
        .note_evidence_delivered(4, 1, 1)
        .expect("the delivery is recorded");
    let (_, outcome) = journal.fence_for_revocation(7, None, kr_ipc::now_ms(), 0, 1);
    outcome.expect("the fence runs");
    let page = journal.evidence_page(4, 0).expect("a page");
    assert!(
        page.rejected.is_empty(),
        "a revocation the daemon has taken the names of keeps none"
    );
    assert_eq!(
        page.omitted, 0,
        "nothing is missing: the daemon holds what this journal forgot"
    );
}

/// KR-REQ-09.12, 09.13: names that go because a daemon stopped taking them are reported as
/// missing rather than as a fence that named nothing.
///
/// Keeping every revocation's names for a daemon that never asks again would grow the journal a
/// revocation at a time. The bound is what stops it; what the bound may not do is let the page
/// that replaces them read as complete. Every announcement is recorded here the way the service
/// records it, because a record per announcement is what the bound has to survive.
#[test]
fn names_a_daemon_never_took_are_bounded_and_the_page_says_how_many_went() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = temp
        .environment()
        .journal_database(SessionId::new(kr_ipc::new_uuid()));
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    let caller = actor("device:phone");
    let revisions = MAX_HELD_REVOCATIONS as u64 + 2;
    {
        let mut journal = Journal::open(&path).expect("a journal");
        // One undispatched intent per revocation, so every revocation's fence names exactly one
        // action and no two revocations are about the same one. Each announcement then says what
        // the daemon holds, which for a daemon that never collects a page is nothing.
        for revision in 1..=revisions {
            let byte = u8::try_from(revision).expect("a small revision");
            let mut intent = at(byte, byte, byte, TimestampMs::new(1_000));
            intent.actor_id = caller.clone();
            journal.accept(&intent).expect("an admitted intent");
            let (fenced, outcome) =
                journal.fence_for_revocation(revision, None, kr_ipc::now_ms(), revision - 1, 1);
            outcome.expect("the fence runs");
            assert_eq!(fenced.rejected, 1, "revision {revision} rejects its intent");
            journal
                .note_evidence_delivered(revision, 0, 1)
                .expect("the announcement is recorded");
        }
    }

    // Read back from a journal this host reopened, because what the bound keeps has to be what a
    // restarted worker answers from.
    let journal = Journal::open(&path).expect("the journal reopens");
    let held = (1..=revisions)
        .filter(|revision| {
            !journal
                .evidence_page(*revision, 0)
                .expect("a page")
                .rejected
                .is_empty()
        })
        .count();
    assert!(
        held <= MAX_HELD_REVOCATIONS,
        "at most {MAX_HELD_REVOCATIONS} revocations keep their names, and {held} did"
    );

    // The newest are kept whole, because they are the ones a person is waiting on.
    let newest = journal.evidence_page(revisions, 0).expect("a page");
    assert_eq!(newest.rejected.len(), 1);
    assert_eq!(newest.omitted, 0);

    // The oldest went, and the page says so rather than carrying nothing and reading as a fence
    // that found nothing to take back.
    let oldest = journal.evidence_page(1, 0).expect("a page");
    assert!(oldest.rejected.is_empty(), "the oldest names went");
    assert_eq!(oldest.remaining, 0);
    assert_eq!(
        oldest.omitted, 1,
        "a name that went without reaching the daemon is reported as missing"
    );
    assert_eq!(
        oldest.evidence().omitted.get(),
        1,
        "and the acknowledgement carries the figure"
    );
    assert!(
        journal.evidence_answerable(1).expect("reads"),
        "this journal can still say what that revocation is missing"
    );
}

/// KR-REQ-09.12, 09.13: a revocation this journal can no longer count for is unanswerable rather
/// than empty.
///
/// The counts outlive the names, and they are bounded too. Past that bound this journal cannot say
/// how many names a revocation is missing, and what it must not do is answer as though it had
/// named nothing: absent evidence and empty evidence are different statements.
#[test]
fn a_revocation_this_journal_can_no_longer_count_for_is_not_answered_as_an_empty_one() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = temp
        .environment()
        .journal_database(SessionId::new(kr_ipc::new_uuid()));
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    let caller = actor("device:phone");
    // Enough revocations for the names of the oldest to go, and then for its count to go as well.
    let revisions = MAX_HELD_REVOCATIONS as u64 * 2 + 2;
    {
        let mut journal = Journal::open(&path).expect("a journal");
        for revision in 1..=revisions {
            let byte = u8::try_from(revision).expect("a small revision");
            let mut intent = at(byte, byte, byte, TimestampMs::new(1_000));
            intent.actor_id = caller.clone();
            journal.accept(&intent).expect("an admitted intent");
            let (_, outcome) =
                journal.fence_for_revocation(revision, None, kr_ipc::now_ms(), revision - 1, 1);
            outcome.expect("the fence runs");
            journal
                .note_evidence_delivered(revision, 0, 1)
                .expect("the announcement is recorded");
        }
    }
    let journal = Journal::open(&path).expect("the journal reopens");
    assert!(
        !journal.evidence_answerable(1).expect("reads"),
        "the oldest revocation is one this journal can no longer answer for"
    );
    // And an announcement about it does not make it answerable again. The service records what
    // the daemon holds on every announcement, and a record written now would say the names were
    // all taken, which is the opposite of what happened to them.
    journal
        .note_evidence_delivered(1, 0, 1)
        .expect("the announcement is recorded");
    assert!(
        !journal.evidence_answerable(1).expect("reads"),
        "an announcement does not resurrect a revocation this journal has forgotten"
    );
    assert!(
        journal.evidence_answerable(revisions).expect("reads"),
        "the newest is answerable, because its names are here"
    );
    assert!(
        journal.evidence_answerable(revisions + 5).expect("reads"),
        "a revocation this journal never ran is answerable: it named nothing"
    );
}

/// KR-REQ-09.12, 09.13: what one controller took is not what a replacement holds.
///
/// The daemon keeps the names it has collected in its own memory, so a replacement starts with
/// none of them. A journal that counted the previous controller's pages as delivered would drop
/// names the new one has never seen and cannot ask for again.
#[test]
fn a_replacement_controller_does_not_inherit_what_the_previous_one_took() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = temp
        .environment()
        .journal_database(SessionId::new(kr_ipc::new_uuid()));
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    let caller = actor("device:phone");
    let mut journal = Journal::open(&path).expect("a journal");
    let mut intent = at(31, 31, 31, TimestampMs::new(1_000));
    intent.actor_id = caller.clone();
    journal.accept(&intent).expect("an admitted intent");
    let (fenced, outcome) = journal.fence_for_revocation(4, None, kr_ipc::now_ms(), 0, 1);
    outcome.expect("the fence runs");
    assert_eq!(fenced.rejected, 1);

    // The controller of generation one takes the name.
    journal
        .note_evidence_delivered(4, 1, 1)
        .expect("the delivery is recorded");

    // It is replaced, and the replacement announces the next revocation before it asks about this
    // one. The fence runs for generation two, which holds nothing of what generation one took.
    let (_, outcome) = journal.fence_for_revocation(5, None, kr_ipc::now_ms(), 0, 2);
    outcome.expect("the fence runs");
    let page = journal.evidence_page(4, 0).expect("a page");
    assert_eq!(
        page.rejected.len(),
        1,
        "the name is kept for the controller that has not taken it"
    );
    assert_eq!(page.omitted, 0);

    // And when the bound takes the names, what is left says they are missing rather than that they
    // were taken: the count the previous controller's collection produced is not this one's.
    for revision in 6..=(MAX_HELD_REVOCATIONS as u64 + 8) {
        let byte = u8::try_from(revision).expect("a small revision");
        let mut later = at(byte, byte, byte, TimestampMs::new(1_000));
        later.actor_id = caller.clone();
        journal.accept(&later).expect("an admitted intent");
        let (_, outcome) =
            journal.fence_for_revocation(revision, None, kr_ipc::now_ms(), revision - 1, 2);
        outcome.expect("the fence runs");
    }
    let page = journal.evidence_page(4, 0).expect("a page");
    assert!(page.rejected.is_empty(), "the bound took the names");
    assert_eq!(
        page.omitted, 1,
        "a name the controller asking now never took is reported as missing"
    );

    // Once this controller has taken it, the next revocation forgets it.
    let mut journal = Journal::open(&path).expect("the journal reopens");
    let mut again = at(60, 60, 60, TimestampMs::new(1_000));
    again.actor_id = caller.clone();
    journal.accept(&again).expect("an admitted intent");
    let (_, outcome) = journal.fence_for_revocation(60, None, kr_ipc::now_ms(), 0, 2);
    outcome.expect("the fence runs");
    journal
        .note_evidence_delivered(60, 1, 2)
        .expect("the delivery is recorded");
    let mut last = at(61, 61, 61, TimestampMs::new(1_000));
    last.actor_id = caller.clone();
    journal.accept(&last).expect("an admitted intent");
    let (_, outcome) = journal.fence_for_revocation(61, None, kr_ipc::now_ms(), 0, 2);
    outcome.expect("the fence runs");
    assert!(
        journal
            .evidence_page(60, 0)
            .expect("a page")
            .rejected
            .is_empty(),
        "a revocation this controller has taken the names of keeps none"
    );
}

/// KR-REQ-09.12, 09.13: a journal an earlier build of this schema wrote keeps answering.
///
/// `fence_delivery` gained the generation that took a revocation's names after the first build
/// that wrote this schema version. A journal from before that has the table without the column,
/// and `CREATE TABLE IF NOT EXISTS` leaves it alone, so the column is added when the journal is
/// opened. Nought is what an older record's generation reads as, which matches no controller this
/// host accepts: what it says is that nobody has taken those names.
#[test]
fn a_delivery_record_an_earlier_build_wrote_keeps_its_names_until_this_daemon_takes_them() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = temp
        .environment()
        .journal_database(SessionId::new(kr_ipc::new_uuid()));
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    let caller = actor("device:phone");
    {
        let mut journal = Journal::open(&path).expect("a journal");
        let mut intent = at(41, 41, 41, TimestampMs::new(1_000));
        intent.actor_id = caller.clone();
        journal.accept(&intent).expect("an admitted intent");
        let (_, outcome) = journal.fence_for_revocation(4, None, kr_ipc::now_ms(), 0, 1);
        outcome.expect("the fence runs");
        journal
            .note_evidence_delivered(4, 1, 1)
            .expect("the delivery is recorded");
    }
    // The table as the earlier build wrote it: the same rows, without the generation.
    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute_batch(
            "CREATE TABLE fence_delivery_old (
                 revision  INTEGER PRIMARY KEY,
                 named     INTEGER NOT NULL,
                 delivered INTEGER NOT NULL
             );
             INSERT INTO fence_delivery_old (revision, named, delivered)
                 SELECT revision, named, delivered FROM fence_delivery;
             DROP TABLE fence_delivery;
             ALTER TABLE fence_delivery_old RENAME TO fence_delivery;",
        )
        .expect("the journal reads as an earlier build's");

    let mut journal = Journal::open(&path).expect("the journal reopens");
    let (_, outcome) = journal.fence_for_revocation(5, None, kr_ipc::now_ms(), 0, 1);
    outcome.expect("the fence runs");
    assert_eq!(
        journal.evidence_page(4, 0).expect("a page").rejected.len(),
        1,
        "what an earlier build recorded is not read as taken by the daemon asking now"
    );
    journal
        .note_evidence_delivered(4, 1, 1)
        .expect("the delivery is recorded");
    let (_, outcome) = journal.fence_for_revocation(6, None, kr_ipc::now_ms(), 0, 1);
    outcome.expect("the fence runs");
    assert!(
        journal
            .evidence_page(4, 0)
            .expect("a page")
            .rejected
            .is_empty(),
        "and once this daemon has taken them, they go"
    );
}

/// KR-REQ-09.09: a refusal moved before the marker keeps its place in the order.
///
/// A session that has begun closing refuses a resize, and so does an attachment identifier this
/// connection does not hold. Both are refusals this host can decide, and the caller is told the
/// one it was always told: the identifier is answered before the session's own state, because that
/// is the order the request is read in rather than the order the effect happens to check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_moved_before_the_marker_keeps_its_place_in_the_order() {
    let host = host().await;
    let mut client = cli(&host).await;
    let caller = actor(&format!("local:{}", kr_ipc::paths::current_uid()));

    // The session begins closing, so a resize is refused by the session as well.
    host.service
        .runtime()
        .session()
        .begin_close(kr_protocol::session::ClosureReason::CloseRequested);

    let resize = MutationRequest {
        method: Method::TerminalResize.into(),
        params: ParamsValue::from_typed(&kr_protocol::attachment::TerminalResizeParams {
            attachment_id: kr_protocol::ids::AttachmentId::new(kr_ipc::new_uuid()),
            dimensions: Dimensions::new(100, 30),
            expected_geometry_epoch: host.service.runtime().session().geometry().epoch,
        })
        .expect("encodes"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let named = resize.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, resize).await else {
        panic!("a resize naming an attachment this connection does not hold is refused");
    };
    assert_eq!(
        error.code,
        ErrorCode::AmbiguousAttachment,
        "the identifier is answered before the session's own state"
    );
    rejected(&host, &caller, named);
}

/// KR-REQ-09.12, 09.13: a rejection whose name the store refuses is not a rejection.
///
/// The receipt, its event and the name a revocation owes are one transaction. A rejection
/// committed without its name would be an action the result owes and cannot produce, and the next
/// pass would not find it: a pass selects intents that are still accepted, and a rejected one is
/// not. So a failure at the name has to take the rejection back with it.
#[test]
fn a_rejection_whose_name_cannot_be_written_leaves_the_receipt_where_it_was() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = temp
        .environment()
        .journal_database(SessionId::new(kr_ipc::new_uuid()));
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    let mut journal = Journal::open(&path).expect("a journal");
    let caller = actor("device:phone");
    let mut submission = fresh(21, 21, 21);
    submission.actor_id = caller.clone();
    journal.accept(&submission).expect("an admitted intent");
    let admitted = journal
        .read(caller.clone(), crate::action(21))
        .expect("reads")
        .expect("a receipt");
    let events_before = recorded_events(&path);

    // The store refuses the name rather than the rejection. This is the write that happens last in
    // the transaction, so what it proves is what the other two do when it fails.
    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute_batch(
            "CREATE TRIGGER refuse_name BEFORE INSERT ON fence_evidence
             BEGIN SELECT RAISE(ABORT, 'this store refused the name'); END;",
        )
        .expect("the store will refuse the name");
    let (fenced, outcome) = journal.fence_for_revocation(4, None, kr_ipc::now_ms(), 0, 1);
    assert!(outcome.is_err(), "the pass could not name what it rejected");
    assert_eq!(fenced.rejected, 0, "nothing was rejected: {fenced:?}");

    let held = journal
        .read(caller.clone(), crate::action(21))
        .expect("reads")
        .expect("a receipt");
    assert_eq!(
        held.state,
        ReceiptState::Accepted,
        "the rejection went back with the name"
    );
    assert_eq!(held.revision, admitted.revision);
    assert!(held.reason.0.is_none());
    assert_eq!(
        recorded_events(&path),
        events_before,
        "and so did the event it appended"
    );
    assert!(
        journal
            .evidence_page(4, 0)
            .expect("a page")
            .rejected
            .is_empty()
    );

    // The store accepts the name, and the next pass finds the intent exactly where it was.
    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute_batch("DROP TRIGGER refuse_name;")
        .expect("the store accepts writes again");
    let (second, outcome) = journal.fence_for_revocation(4, None, kr_ipc::now_ms(), 0, 1);
    outcome.expect("the pass finishes");
    assert_eq!(second.rejected, 1);
    let rejected = journal
        .read(caller.clone(), crate::action(21))
        .expect("reads")
        .expect("a receipt");
    assert_eq!(rejected.state, ReceiptState::Rejected);
    assert_eq!(rejected.reason.as_ref(), Some(&RejectionReason::Revoked));
    assert_eq!(
        journal.evidence_page(4, 0).expect("a page").rejected,
        vec![kr_protocol::action::FencedAction {
            actor_id: caller,
            action_id: crate::action(21),
        }]
    );
}

/// How many state changes this journal has recorded.
fn recorded_events(path: &std::path::Path) -> i64 {
    rusqlite::Connection::open(path)
        .expect("the same database")
        .query_row("SELECT COUNT(*) FROM receipt_events", [], |row| row.get(0))
        .expect("counts the events")
}

/// The identifier bytes of the `index`th action of a large fence.
fn index_bytes(index: usize) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
    bytes
}

/// KR-REQ-09.14: a collection this host could not finish is recorded against the session, and the
/// session goes on serving: maintenance is not something a caller waits for or is refused by.
#[test]
fn a_collection_that_fails_is_recorded_and_the_session_keeps_serving() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let path = environment.journal_database(session_id);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    record_from_an_earlier_run(&path, 60);
    owner_confirmed_clock(&path);
    // The store refuses the write the collection has to make. A trigger is how a test arranges
    // that deterministically; what it stands for is a full disk or a store that cannot be written.
    let refuse = "CREATE TRIGGER refuse_collection BEFORE DELETE ON receipts
                  BEGIN SELECT RAISE(ABORT, 'this store refused the write'); END;";
    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute_batch(refuse)
        .expect("the store will refuse the collection");
    let mut session = Session::open(session_config(&environment, session_id)).expect("opens");
    assert!(
        session.journal_failure().is_none(),
        "the journal opened: {:?}",
        session.journal_failure()
    );

    // The collection fails. Nothing is returned to a caller, the failure is recorded, and this
    // session is still answerable: the collection did not leave a lock behind it.
    assert_eq!(session.collect_expired(), 0);
    assert!(
        session.journal_failure().is_some(),
        "a collection this host could not finish is recorded; this host's clock is {}",
        clock_state(&session)
    );
    assert_eq!(
        session.state(),
        kr_protocol::session::SessionState::Creating
    );
    assert!(session.attachments().is_empty());
    assert_eq!(session.geometry().dimensions, Dimensions::new(80, 24));

    // And once the store accepts writes again, the collection it owed happens on the next run.
    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute_batch("DROP TRIGGER refuse_collection;")
        .expect("the store accepts writes again");
    assert_eq!(
        session.collect_expired(),
        1,
        "the record past the retention period goes on the next run"
    );
}

/// KR-REQ-09.12, 09.13: a fence that failed part way names what it did reject when it runs again,
/// and its window is a position in this journal's own order rather than a reading of the clock.
#[test]
fn a_fence_that_failed_part_way_names_what_both_passes_did() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = temp
        .environment()
        .journal_database(SessionId::new(kr_ipc::new_uuid()));
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    let mut journal = Journal::open(&path).expect("a journal");
    let caller = actor("device:phone");
    for byte in [11_u8, 12, 13] {
        let mut submission = fresh(byte, byte, byte);
        submission.actor_id = caller.clone();
        journal.accept(&submission).expect("an admitted intent");
    }
    // The store refuses the rejection of one of them, so the pass stops there. Which one is
    // decided by the journal's own order, so the assertion below is about the count rather than
    // about a particular identifier.
    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute_batch(
            "CREATE TRIGGER refuse_one BEFORE UPDATE OF state ON receipts
             WHEN new.state = 'rejected' AND old.action_id = x'0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d'
             BEGIN SELECT RAISE(ABORT, 'this store refused the write'); END;",
        )
        .expect("the store will refuse one rejection");
    let (first, outcome) = journal.fence_for_revocation(4, None, kr_ipc::now_ms(), 0, 1);
    assert!(outcome.is_err(), "the pass did not finish");
    assert!(
        first.rejected > 0 && first.rejected < 3,
        "the pass rejected some of them: {first:?}"
    );

    // The second pass runs from the same boundary, because the first never reached the end. What
    // it rejects, added to what the first did, is all three.
    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute_batch("DROP TRIGGER refuse_one;")
        .expect("the store accepts writes again");
    let (_, outcome) = journal.fence_for_revocation(4, None, kr_ipc::now_ms(), 0, 1);
    let reached = outcome.expect("the pass finishes");
    assert!(reached > 0, "the fence reports where the journal stood");
    let page = journal.evidence_page(4, 0).expect("a page");
    assert_eq!(
        page.rejected.len(),
        3,
        "the two passes together name every intent the revocation took back"
    );
    assert_eq!(page.remaining, 0);
    for byte in [11_u8, 12, 13] {
        let receipt = journal
            .read(caller.clone(), crate::action(byte))
            .expect("reads")
            .expect("a receipt");
        assert_eq!(receipt.state, ReceiptState::Rejected);
        assert_eq!(receipt.reason.as_ref(), Some(&RejectionReason::Revoked));
    }

    // And an action that settled after that boundary is named whatever the wall clock reads. Its
    // receipt is stamped an hour in the past, which is what a rollback between two revocations
    // leaves behind; the boundary is the journal's own order, so the action is still in the window.
    let mut later = fresh(14, 14, 14);
    later.actor_id = caller.clone();
    later.now_ms = TimestampMs::new(kr_ipc::now_ms().get().saturating_sub(3_600_000));
    journal.accept(&later).expect("an admitted intent");
    journal
        .mark_dispatching(caller.clone(), crate::action(14), later.now_ms)
        .expect("marks");
    journal
        .settle(
            caller.clone(),
            crate::action(14),
            ReceiptState::Applied,
            None,
            None,
            later.now_ms,
        )
        .expect("settles");
    let (third, outcome) = journal.fence_for_revocation(4, None, kr_ipc::now_ms(), reached, 1);
    outcome.expect("the pass finishes");
    assert_eq!(third.possibly_executed, 1);
    let page = journal.evidence_page(4, 0).expect("a page");
    assert_eq!(
        page.possibly_executed
            .iter()
            .map(|action| action.action_id)
            .collect::<Vec<_>>(),
        vec![crate::action(14)],
        "an action that ran after the previous fence is named however its stamp reads"
    );
}

/// A window the host can refuse is refused before the marker, not after it.
///
/// Both answers about where a window may go are about the request: a caller shown the live screen
/// and no retained content beyond it may not look above it, and a window whose smallest screen will
/// not cross the queue this attachment holds cannot be installed. Neither depends on anything the
/// report would change, so both belong before the marker that says the effect may have happened.
/// Raised after it, each would be an outcome nobody can read and the requests behind it would wait
/// on a receipt that never resolves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_window_the_host_can_refuse_never_reaches_the_marker() {
    let host = host().await;
    let mut client = cli(&host).await;
    let caller = actor(&format!("local:{}", kr_ipc::paths::current_uid()));

    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &kr_protocol::attachment::SessionAttachParams {
                session_id: host.session_id,
                mode: kr_protocol::attachment::AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(40, 10)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("the attachment is accepted")
        .to_typed()
        .expect("decodes");
    let attachment_id = attached.attachment.attachment_id;

    // The narrowing a forwarded caller is given: the screen that is showing, and no retained
    // content beyond it.
    host.service
        .runtime()
        .session()
        .narrow_content(attachment_id, kr_worker::render::Scope::LiveScreen);

    let above = MutationRequest {
        method: Method::AttachmentViewport.into(),
        params: ParamsValue::from_typed(&kr_protocol::attachment::AttachmentViewportParams {
            attachment_id,
            dimensions: Dimensions::new(40, 10),
            position: Nullable::some(kr_protocol::attachment::ViewportPosition::Above(
                kr_protocol::scalars::U64::new(40),
            )),
        })
        .expect("encodes"),
        ..close_mutation(
            &client,
            &host,
            DEFAULT_MUTATION_TTL.get(),
            ParamsValue::empty(),
        )
    };
    let named = above.action_id;
    let Outcome::Error(error) = send_mutation(&mut client, above).await else {
        panic!("an attachment shown the live screen cannot place its window above it");
    };
    assert_eq!(error.code, ErrorCode::UnsupportedCapability);
    {
        let mut session = host.service.runtime().session();
        let journal = session.journal_mut().expect("a journal");
        let receipt = journal
            .read(caller.clone(), named)
            .expect("reads")
            .expect("the intent was committed before it was revalidated");
        assert_eq!(
            receipt.state,
            ReceiptState::Rejected,
            "the host could decide this, so it never wrote a dispatch marker"
        );
    }

    // The other answer this path can give is about the queue a window has to cross, which needs
    // a session with rows above its live page; `kr-worker/tests/snapshot.rs` asks that one of
    // `Session::viewportable` directly, which is the same call this dispatch makes before its
    // marker.
}
