use std::sync::Arc;
use std::time::Duration;

use kr_ipc::endpoint::Listener;
use kr_ipc::framed::split;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ActionWindow, ReceiveLimits};
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{
    ActionId, ActionWindowId, BuildId, ConnectionId, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::local::{LocalHelloAck, LocalRole};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable};
use kr_protocol::session::{DisplayNumber, SessionCloseParams};
use kr_protocol::worker::{GenerationAccepted, GenerationChallenge, WorkerDescriptor};
use kr_transport::window::{AcceptedDeadline, DeadlineBound};

use crate::directory::KnownWorker;
use crate::error::ControllerError;
use crate::service::{CLOSE_EXCHANGE, Controller, ControllerSetup};
use crate::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};

#[derive(Debug)]
struct RefusingSupervisor;

impl WorkerSupervisor for RefusingSupervisor {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

/// Every frame a recording worker was sent after its handshake, in arrival order.
pub(super) type Recorded = Arc<std::sync::Mutex<Vec<ControlFrame>>>;

/// An endpoint that proves itself as a worker and then performs nothing.
///
/// It completes the handshake the daemon makes before it will speak to a worker at all (the
/// version exchange, the challenge over the descriptor's key and the controller generation).
/// A silent one (`recorded` absent) then reads whatever arrives without replying. That is a
/// worker that has stopped answering, which is different from one that has gone: the
/// connection stays open. A recording one keeps every frame it is sent and refuses each
/// request and forwarded frame at once, so a test can read exactly what reached a worker.
fn serve_fake_worker(
    listener: Listener,
    identity: Arc<WorkerIdentity>,
    endpoint_text: String,
    recorded: Option<Recorded>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((connection, peer)) = listener.accept().await else {
                return;
            };
            let identity = Arc::clone(&identity);
            let endpoint_text = endpoint_text.clone();
            let recorded = recorded.clone();
            tokio::spawn(async move {
                let (mut reader, mut writer) = split(connection, StreamKind::Control);
                let connection_id = ConnectionId::new(kr_ipc::new_uuid());
                while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                    let handshake = handshake(
                        &frame,
                        &identity,
                        &endpoint_text,
                        connection_id,
                        &peer,
                        &CanonicalSet::new(),
                    );
                    let answers = match (handshake, frame) {
                        (Some(answers), _) => answers,
                        // A recording worker installs the revision announced to it, with
                        // nothing to fence, so this daemon may dispatch to it.
                        (None, ControlFrame::AuthorityRevision(notice)) if recorded.is_some() => {
                            vec![ControlFrame::AuthorityRevisionAck(
                                kr_protocol::worker::AuthorityRevisionAck {
                                    session_id: identity.session_id(),
                                    revision: notice.revision,
                                    fence: None,
                                },
                            )]
                        }
                        // A silent worker never answers what arrives here, a close among it.
                        (None, other) => match &recorded {
                            None => Vec::new(),
                            Some(recorded) => {
                                let refusal = answer_of(&other, identity.session_id());
                                recorded
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .push(other);
                                refusal.into_iter().collect()
                            }
                        },
                    };
                    for answer in answers {
                        if writer.write_message(&answer).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    })
}

/// What a fake worker answers the handshake with that the daemon makes before it will speak
/// to a worker at all: the version exchange, stating `stated` about itself, the challenge over
/// the descriptor's key, the controller generation and the role a link says it is for. Any
/// other frame is `None`, and the fake worker answers it in its own way.
pub(super) fn handshake(
    frame: &ControlFrame,
    identity: &WorkerIdentity,
    endpoint_text: &str,
    connection_id: ConnectionId,
    peer: &kr_ipc::peer::PeerIdentity,
    stated: &CanonicalSet<kr_protocol::ids::CapabilityId>,
) -> Option<Vec<ControlFrame>> {
    match frame {
        ControlFrame::Hello(_) => Some(vec![
            ControlFrame::HelloAck(Box::new(LocalHelloAck {
                selected_version: kr_protocol::hello::PROTOCOL_VERSION,
                role: LocalRole::Worker,
                connection_id,
                environment_id: identity_environment(),
                boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
                peer: peer.to_wire(),
                action_window: ActionWindow {
                    action_window_id: ActionWindowId::new("worker:test").expect("a window"),
                    connection_id,
                    boot_epoch: kr_protocol::ids::BootEpoch::new(1),
                    issued_at_ms: kr_ipc::now_ms(),
                    valid_for_ms: DurationMs::new(60_000),
                },
                capabilities: stated.clone(),
                max_receive: ReceiveLimits::default(),
                build: Some(kr_protocol::local::LocalBuild::this(
                    BuildId::new("kr-worker/0").ok()?,
                )),
            })),
            ControlFrame::GenerationChallenge(GenerationChallenge {
                nonce: kr_ipc::verify::fresh_challenge()
                    .expect("a challenge")
                    .nonce,
            }),
        ]),
        ControlFrame::VerifyChallenge(challenge) => Some(vec![ControlFrame::VerifyProof(
            identity
                .answer(challenge, endpoint_text)
                .expect("answers its own challenge"),
        )]),
        ControlFrame::GenerationToken(token) => {
            Some(vec![ControlFrame::GenerationAccepted(GenerationAccepted {
                generation: token.generation,
                fenced_previous: false,
            })])
        }
        // A proxy link says what it is for, and the worker agrees.
        ControlFrame::ControllerRole(role) => Some(vec![ControlFrame::ControllerRole(*role)]),
        _ => None,
    }
}

/// What a recording worker answers a request or a forwarded frame with: the daemon's own
/// `session.read` is answered with a live session, and everything else is refused.
fn answer_of(frame: &ControlFrame, session_id: SessionId) -> Option<ControlFrame> {
    let request_id = match frame {
        ControlFrame::Request(request) => {
            if request.method == Method::SessionRead.into() {
                return Some(ControlFrame::Response(kr_protocol::envelope::Response {
                    request_id: request.request_id,
                    outcome: kr_protocol::envelope::Outcome::Ok(
                        ParamsValue::from_typed(&read_result(session_id)).expect("encodes"),
                    ),
                }));
            }
            request.request_id
        }
        ControlFrame::Forwarded(forwarded) => forwarded.mutation.request_id,
        ControlFrame::ForwardedRead(forwarded) => forwarded.request.request_id,
        _ => return None,
    };
    Some(ControlFrame::Response(kr_protocol::envelope::Response {
        request_id,
        outcome: kr_protocol::envelope::Outcome::Error(kr_protocol::error::ProtocolError::new(
            ErrorCode::ResourceUnavailable,
            "this worker records what it is sent and performs none of it",
        )),
    }))
}

/// A live session, as a worker answers the daemon's own `session.read`.
pub(super) fn read_result(session_id: SessionId) -> kr_protocol::session::SessionReadResult {
    kr_protocol::session::SessionReadResult {
        session: kr_protocol::session::SessionSummary {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id: identity_environment(),
            display_number: DisplayNumber::new(1),
            state: kr_protocol::session::SessionState::Live,
            shell_mode: kr_protocol::session::ShellMode::Managed,
            shell_path: "/bin/zsh".to_owned(),
            cwd: "/work".to_owned(),
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: kr_protocol::identity::DesktopBinding::none(),
            created_at_ms: kr_ipc::now_ms(),
            dimensions: kr_protocol::session::INVISIBLE_DEFAULT_DIMENSIONS,
            attachment_count: kr_protocol::scalars::U64::ZERO,
            application_state: Nullable::null(),
            root_process: Nullable::null(),
            closure: Nullable::null(),
            environment_sources: None,
        },
        endpoint: Nullable::null(),
        launch_profile: Nullable::null(),
        last_command_block: Nullable::null(),
        outstanding_launches: Nullable::null(),
    }
}

/// The environment the fake worker's acknowledgement names.
///
/// The daemon does not compare it with its own, so any identity does; this keeps one value in
/// one place rather than inventing a second.
fn identity_environment() -> kr_protocol::ids::EnvironmentId {
    kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::NIL)
}

pub(super) fn close_request(
    environment_id: kr_protocol::ids::EnvironmentId,
    session_id: SessionId,
) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(1),
        method: Method::SessionClose.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("local:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(&SessionCloseParams { session_id }).expect("encodes"),
    }
}

/// A daemon with one silent worker in its directory, and everything a close needs.
/// Registers one caller and returns the admission its close carries: the connection it
/// arrived on, the revision in force and the deadline this host accepted.
pub(super) async fn admission(
    controller: &Controller,
    accepted: AcceptedDeadline,
) -> crate::authority::AdmittedMutation {
    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
    let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    controller
        .admit_connection(
            connection_id,
            &actor_id,
            &kr_ipc::peer::PeerIdentity {
                uid: kr_ipc::paths::current_uid(),
                gid: 0,
                pid: None,
            },
            kr_protocol::local::LocalClientKind::Cli,
        )
        .await
        .expect("the connection is registered");
    crate::authority::AdmittedMutation {
        connection_id,
        admitted_revision: controller.leases.authority_revision(),
        deadline: Some(accepted.deadline),
    }
}

pub(super) struct Silent {
    pub(super) _temp: kr_ipc::testing::TempHost,
    pub(super) controller: Arc<Controller>,
    pub(super) environment_id: kr_protocol::ids::EnvironmentId,
    pub(super) session_id: SessionId,
    pub(super) worker: KnownWorker,
    pub(super) actor: kr_protocol::actor::ActorEnvelope,
    pub(super) accepted: AcceptedDeadline,
    pub(super) serving: tokio::task::JoinHandle<()>,
}

/// A daemon with one silent worker in its directory, and everything a close needs.
async fn silent_worker() -> Silent {
    fake_worker(None).await
}

/// A daemon with one fake worker in its directory, silent or recording
/// ([`serve_fake_worker`]), and everything a close needs.
pub(super) async fn fake_worker(recorded: Option<Recorded>) -> Silent {
    fake_world(move |listener, identity, endpoint_text| {
        serve_fake_worker(listener, identity, endpoint_text, recorded)
    })
    .await
}

/// What a fake world's daemon is started with. The daemon's identity is kept in the
/// environment's own secret store, so a daemon started again on the same environment is the
/// same controller.
pub(super) fn setup(temp: &kr_ipc::testing::TempHost) -> ControllerSetup {
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    ControllerSetup {
        paths: environment,
        environment_id,
        identity: Box::new(move || {
            let store = kr_crypto::store::open_store_in(&secrets)
                .expect("a secret store for the test environment");
            Ok(kr_ipc::verify::ControllerIdentity::open(
                store.store.as_ref(),
                environment_id,
                false,
            )
            .expect("an identity"))
        }),
        secret_store: kr_crypto::store::StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(RefusingSupervisor),
        worker_program: temp.root().join("kr-worker"),
        build_id: BuildId::new("kr-test/0").expect("a build identifier"),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(crate::supervision::NoTerminal),
    }
}

/// A daemon with one fake worker in its directory, served by `serve` on the worker's own
/// endpoint, and everything a close needs. The worker is admitted as a worker that has just
/// reported itself is, with no description of its session yet.
pub(super) async fn fake_world(
    serve: impl FnOnce(Listener, Arc<WorkerIdentity>, String) -> tokio::task::JoinHandle<()>,
) -> Silent {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let controller = Controller::start(setup(&temp))
        .await
        .expect("the daemon starts");

    let session_id = SessionId::new(kr_ipc::new_uuid());
    let worker_endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            kr_ipc::identity::boot_identity().expect("a boot identity"),
            kr_ipc::identity::process_start_identity(std::process::id())
                .expect("this process's start identity"),
            kr_protocol::hello::PROTOCOL_VERSION,
        )
        .expect("generates a worker identity"),
    );
    let descriptor = WorkerDescriptor {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        boot_identity: identity.boot_identity().clone(),
        process_start_identity: identity.process_start_identity().clone(),
        protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
        endpoint: worker_endpoint.as_text(),
        worker_public_key: *identity.public_key(),
        worker_profile: WorkerProfile::HeadlessUser,
        published_at_ms: kr_ipc::now_ms(),
    };
    let listener = Listener::bind(&worker_endpoint).expect("binds the worker endpoint");
    let serving = serve(listener, Arc::clone(&identity), worker_endpoint.as_text());
    let worker = KnownWorker {
        descriptor,
        endpoint: worker_endpoint,
    };
    controller
        .directory
        .lock()
        .await
        .insert(worker.clone(), None);

    let actor = crate::service::local_actor(
        kr_protocol::ids::ActorId::new("local:test").expect("a principal"),
        ConnectionId::new(kr_ipc::new_uuid()),
        controller.generation,
    );
    let accepted = AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(Duration::from_secs(300))
            .expect("a deadline five minutes out"),
        bound: DeadlineBound::RequestedTtl,
    };
    Silent {
        _temp: temp,
        controller,
        environment_id,
        session_id,
        worker,
        actor,
        accepted,
        serving,
    }
}

/// Records that this worker has acknowledged the revision in force, so its leases renew.
pub(super) fn acknowledged(controller: &Controller, session_id: SessionId) {
    let binding = controller.leases.binding(session_id);
    controller.leases.acknowledge(
        session_id,
        binding,
        controller.leases.authority_revision(),
        None,
    );
}

/// A close that has the worker's link and cannot read this daemon's own authority gives the
/// link back rather than holding it past what a closure may take.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_that_cannot_read_this_daemons_authority_in_time_gives_the_link_back() {
    let Silent {
        _temp,
        controller,
        environment_id,
        session_id,
        actor,
        accepted,
        serving,
        ..
    } = silent_worker().await;
    acknowledged(&controller, session_id);
    let carried = admission(&controller, accepted).await;

    // Something else is holding the registry for longer than a closure may take. The close
    // acquires the worker's link first and then waits for the registry, inside the same
    // budget as the exchange itself.
    let held = controller.registry.lock().await;
    let started = tokio::time::Instant::now();
    let refused = controller
        .session_close(
            &close_request(environment_id, session_id),
            &actor,
            Some(accepted),
            carried,
        )
        .await
        .expect_err("a close that cannot read this daemon's authority closes nothing");
    let waited = started.elapsed();
    drop(held);
    assert!(
        waited <= CLOSE_EXCHANGE + Duration::from_secs(2),
        "the wait is bounded by what a closure may take: {waited:?}"
    );
    assert_eq!(
        refused.code(),
        ErrorCode::ResourceUnavailable,
        "the caller is told this daemon could not answer, not that the worker did: {refused}"
    );

    // And the link is back: the next caller finds it rather than waiting behind this one.
    let link = tokio::time::timeout(
        Duration::from_secs(5),
        controller.worker_client_of(session_id),
    )
    .await
    .expect("the link is free")
    .expect("the link is this daemon's own");
    drop(link);
    serving.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_client_is_retired_rather_than_held_for_the_next_caller() {
    let Silent {
        _temp,
        controller,
        environment_id,
        session_id,
        actor,
        accepted,
        serving,
        ..
    } = silent_worker().await;

    // The worker holds this environment's authority revision, so its dispatch leases renew.
    acknowledged(&controller, session_id);
    assert!(
        matches!(
            controller
                .leases
                .renew(session_id, controller.generation, &*controller.clock),
            Ok(Ok(_))
        ),
        "an acknowledged worker's lease renews before the close"
    );

    let started = tokio::time::Instant::now();
    let first = controller
        .session_close(
            &close_request(environment_id, session_id),
            &actor,
            Some(accepted),
            admission(&controller, accepted).await,
        )
        .await
        .expect_err("a worker that never answers produces no closure");
    assert_eq!(
        first.code(),
        ErrorCode::OutcomeUnknown,
        "a close that was written and never answered is uncertain, not refused: {first}"
    );
    assert!(
        matches!(first, ControllerError::Uncertain { .. }),
        "the caller is told the outcome is not known: {first}"
    );

    // The path this daemon announces authority revisions over is the one it just gave up on,
    // so renewal stops with it: section 9 lets a remote dispatch lease be renewed only after
    // the worker has acknowledged the revision, and an acknowledgement can no longer arrive.
    assert!(
        controller.leases.is_fenced(session_id),
        "renewal is fenced for the worker whose link was retired"
    );
    assert!(
        matches!(
            controller
                .leases
                .renew(session_id, controller.generation, &*controller.clock),
            Ok(Err(
                kr_transport::lease::LeaseRefusal::RevisionNotAcknowledged
            ))
        ),
        "and a lease is refused until that worker acknowledges the revision again"
    );

    // The slot this daemon keeps for that worker is free, and what was in it has gone. A
    // client whose exchange was abandoned part way through would answer the next caller's
    // request with this close's reply, so it is retired rather than put back.
    let link = controller
        .connections
        .lock()
        .await
        .get(&session_id)
        .map(Arc::clone)
        .expect("the daemon opened a connection to this worker");
    let held = link
        .try_lock()
        .expect("the shared slot is free for the next caller");
    assert!(
        held.is_none(),
        "an interrupted client is retired rather than returned to the shared slot"
    );
    drop(held);

    // The second caller is not waiting behind the first. It opens its own connection to the
    // same silent worker and is bounded in its own right.
    let second = controller
        .session_close(
            &close_request(environment_id, session_id),
            &actor,
            Some(accepted),
            admission(&controller, accepted).await,
        )
        .await
        .expect_err("the second close meets the same silent worker");
    assert_eq!(second.code(), ErrorCode::OutcomeUnknown);
    assert!(
        started.elapsed() < CLOSE_EXCHANGE * 3,
        "two closes against a silent worker cost two bounded waits, not an unbounded one"
    );
    serving.abort();
}

/// The link a close fences is the link it actually ran over.
///
/// A close can queue for this daemon's one connection to a worker while another operation
/// loses that connection and a replacement is established and acknowledged. Fencing the
/// control path that was current when the close arrived would lift nothing: that path has
/// already been given up on, and the renewal the close means to stop belongs to the one it
/// used.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_link_a_close_fences_is_the_one_it_ran_over() {
    let Silent {
        _temp,
        controller,
        environment_id,
        session_id,
        worker,
        actor,
        accepted,
        serving,
        ..
    } = silent_worker().await;
    acknowledged(&controller, session_id);

    // The slot is held, so the close below waits for it.
    let occupied = controller
        .worker_client(&worker)
        .await
        .expect("the daemon opens its link to the worker");

    let close = tokio::spawn({
        let controller = Arc::clone(&controller);
        let actor = actor.clone();
        let mutation = close_request(environment_id, session_id);
        async move {
            let admission = admission(&controller, accepted).await;
            controller
                .session_close(&mutation, &actor, Some(accepted), admission)
                .await
        }
    });
    // Long enough for the close to be queueing for the slot.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Meanwhile the control path this worker was acknowledged over is lost, and a replacement
    // is established and acknowledged.
    let lost = controller.leases.binding(session_id);
    controller.leases.stop_renewal(session_id, lost);
    acknowledged(&controller, session_id);
    assert!(
        !controller.leases.is_fenced(session_id),
        "the replacement path renews before the close reaches the worker"
    );
    drop(occupied);

    let error = close
        .await
        .expect("the close finishes")
        .expect_err("a worker that never answers produces no closure");
    assert_eq!(error.code(), ErrorCode::OutcomeUnknown);
    assert!(
        controller.leases.is_fenced(session_id),
        "the close fences the path it used, not the one it was queued behind"
    );
    serving.abort();
}
