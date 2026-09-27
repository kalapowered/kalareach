//! A read of a session whose worker stops answering part way through it.
//!
//! A worker that has finished its closure stops answering before the kernel says its process
//! has ended, so a read that is waiting on it can meet its connection ending while nothing yet
//! says the worker has gone. The worker here is a double that goes that way when a test tells
//! it to. Its process is this test's own, so the kernel says it is running throughout, and the
//! registry names that process as the session's worker, as it names a real one.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use kr_ipc::endpoint::Listener;
use kr_ipc::framed::split;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Request, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{
    ActionId, AuthorityRevision, ConnectionId, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::root::{CwdRevision, PromptGeneration, RootCommandBlockParams};
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::session::{
    ClosureReason, ClosureRecord, Dimensions, Durability, INVISIBLE_DEFAULT_DIMENSIONS,
    OwnershipCoverage, SessionCloseResult, SessionListParams, SessionListResult, SessionReadParams,
    SessionReadResult, SessionState, SessionSummary,
};
use tokio::sync::{Notify, oneshot};

use super::a_close_a_worker_never_answers::{self as fake, Silent};
use crate::registry::{LaunchPhase, WorkerRecord};
use crate::service::Controller;

/// A worker whose session a test moves along, and which goes when the test says so.
///
/// It answers a read with the state a test has put its session in, live to begin with, and
/// accepts a close by saying the session is closing, as a worker does before it stops
/// anything, with its own description of the session in the acceptance. It keeps the answer to
/// each close as a worker's journal does, answers an exact retry from it and says so, and
/// answers `action.read` from it. Told to go, it goes the way a worker that has finished its
/// closure goes: at the next read it is sent, its endpoint stops accepting, and then the
/// connection that read is waiting on ends unanswered.
pub(super) struct Scripted {
    /// The state its session is in.
    state: std::sync::Mutex<SessionState>,
    /// Its session's size.
    dimensions: std::sync::Mutex<Dimensions>,
    /// When its session was created, which every description of the session says.
    created_at_ms: kr_protocol::scalars::TimestampMs,
    /// How many reads have reached it.
    reads: AtomicUsize,
    /// Whether it refuses to describe its session.
    refusing: AtomicBool,
    /// The read it goes at, once a test has set one.
    end: std::sync::Mutex<Option<End>>,
    /// Tells the endpoint to stop accepting.
    going: Notify,
    /// Says the endpoint has stopped accepting.
    gone: Notify,
    /// Whether it describes its session when it accepts a close, as a worker of this build does.
    describes_its_close: AtomicBool,
    /// The session its acceptances describe, where a test has them name another one.
    names: std::sync::Mutex<Option<SessionId>>,
    /// The answer it gave each close, by the close's action, as its journal keeps it.
    answered: std::sync::Mutex<BTreeMap<ActionId, ParamsValue>>,
    /// Every generation a daemon presented to it, in the order they came.
    generations: std::sync::Mutex<Vec<kr_protocol::ids::ControllerGeneration>>,
    /// How many connections it has accepted.
    connections: AtomicUsize,
}

/// Where a scripted worker goes: at the next read it is sent.
struct End {
    /// Told that the read has arrived.
    arrived: oneshot::Sender<()>,
    /// Waited for before the worker goes; dropping it is the same as sending.
    go: oneshot::Receiver<()>,
}

impl Scripted {
    /// A worker whose session is live.
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new(SessionState::Live),
            dimensions: std::sync::Mutex::new(INVISIBLE_DEFAULT_DIMENSIONS),
            created_at_ms: kr_ipc::now_ms(),
            reads: AtomicUsize::new(0),
            refusing: AtomicBool::new(false),
            end: std::sync::Mutex::new(None),
            going: Notify::new(),
            gone: Notify::new(),
            describes_its_close: AtomicBool::new(true),
            names: std::sync::Mutex::new(None),
            answered: std::sync::Mutex::new(BTreeMap::new()),
            generations: std::sync::Mutex::new(Vec::new()),
            connections: AtomicUsize::new(0),
        })
    }

    /// How many connections this worker has accepted, from any daemon.
    fn connections(&self) -> usize {
        self.connections.load(Ordering::Acquire)
    }

    /// Whether a daemon speaking for `generation` has presented it to this worker.
    fn presented(&self, generation: kr_protocol::ids::ControllerGeneration) -> bool {
        self.generations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&generation)
    }

    /// Has this worker accept a close as a worker built before the description does: with no
    /// description of its session in the acceptance.
    fn built_before_the_description(&self) {
        self.describes_its_close.store(false, Ordering::Release);
    }

    /// Has this worker's acceptances describe `session_id` in place of its own session.
    fn describing(&self, session_id: SessionId) {
        *self
            .names
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(session_id);
    }

    /// What this worker accepts a close of `session_id` with now: the session closing, and its own
    /// description of the session where it gives one.
    pub(super) fn acceptance(&self, session_id: SessionId) -> SessionCloseResult {
        let mut described = self.answer(session_id).session;
        described.state = SessionState::Closing;
        if let Some(named) = *self
            .names
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            described.session_id = named;
        }
        SessionCloseResult {
            session_id,
            state: SessionState::Closing,
            durability: Durability::Durable,
            closure: Nullable::null(),
            session: self
                .describes_its_close
                .load(Ordering::Acquire)
                .then_some(described),
        }
    }

    /// Answers the close `action_id` asks for: from what this worker kept where it answered that
    /// close before, which the second half says, and otherwise by accepting it and keeping the
    /// answer.
    fn close(&self, session_id: SessionId, action_id: ActionId) -> (ParamsValue, bool) {
        let mut answered = self
            .answered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(kept) = answered.get(&action_id) {
            return (kept.clone(), true);
        }
        if self.state() == SessionState::Live {
            self.set(SessionState::Closing);
        }
        let answer = ParamsValue::from_typed(&self.acceptance(session_id)).expect("encodes");
        answered.insert(action_id, answer.clone());
        (answer, false)
    }

    /// Keeps `answer` as this worker's answer to the close `action_id`, as its journal holds the
    /// answer to a close it accepted before the daemon asking now was started.
    pub(super) fn kept(&self, action_id: ActionId, answer: ParamsValue) {
        self.answered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(action_id, answer);
    }

    /// How this worker answers `action.read`: the receipt of a close it kept an answer to, with
    /// that answer, and otherwise a refusal.
    fn receipt(&self, request: &Request) -> ControlFrame {
        let kept = request
            .params
            .to_typed::<kr_protocol::receipt::ActionReadParams>()
            .ok()
            .and_then(|params| {
                self.answered
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&params.action_id)
                    .cloned()
                    .map(|answer| (params.action_id, answer))
            });
        let Some((action_id, answer)) = kept else {
            return ControlFrame::Response(Response {
                request_id: request.request_id,
                outcome: Outcome::Error(ProtocolError::new(
                    ErrorCode::ResourceUnavailable,
                    "this worker holds no receipt for that action",
                )),
            });
        };
        respond(
            request.request_id,
            &kr_protocol::receipt::ActionReadResult {
                receipt: kr_protocol::receipt::Receipt {
                    action_id,
                    actor_id: kr_protocol::ids::ActorId::new("device:test").expect("a principal"),
                    method: Method::SessionClose.into(),
                    method_version: MethodVersion::V1,
                    revision: U64::new(2),
                    state: kr_protocol::receipt::ReceiptState::Applied,
                    reason: Nullable::null(),
                    payload_digest: kr_protocol::scalars::Digest256::from_bytes([0; 32]),
                    accepted_deadline_ms: Nullable::null(),
                    error: Nullable::null(),
                    updated_at_ms: kr_ipc::now_ms(),
                },
                result: Nullable::some(answer),
            },
        )
    }

    /// Puts the session in `state`, which every later answer says.
    fn set(&self, state: SessionState) {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = state;
    }

    /// Resizes the session, as an attachment's window does.
    fn resize(&self, dimensions: Dimensions) {
        *self
            .dimensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = dimensions;
    }

    /// Has this worker refuse to describe its session, or answer again.
    pub(super) fn refuse_reads(&self, refusing: bool) {
        self.refusing.store(refusing, Ordering::Release);
    }

    /// How many reads have reached this worker.
    fn reads(&self) -> usize {
        self.reads.load(Ordering::Acquire)
    }

    /// The state the session is in.
    fn state(&self) -> SessionState {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Has this worker go at the next read it is sent. The first half says when that read has
    /// arrived, and the worker goes once the second is sent or dropped.
    pub(super) fn end_at_next_read(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (arrived, arrival) = oneshot::channel();
        let (go, going) = oneshot::channel();
        *self
            .end
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(End { arrived, go: going });
        (arrival, go)
    }

    /// How this worker answers a read: its session in the state it is in, with the worker's
    /// own closure once it has closed, and the last command the session ran, which is its
    /// content beside its description.
    fn answer(&self, session_id: SessionId) -> SessionReadResult {
        let mut read = fake::read_result(session_id);
        read.session.created_at_ms = self.created_at_ms;
        read.session.state = self.state();
        read.session.dimensions = *self
            .dimensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if read.session.state == SessionState::Closed {
            read.session.closure = Nullable::some(closure_of(session_id));
        }
        read.last_command_block = Nullable::some(RootCommandBlockParams {
            session_id,
            prompt_generation: PromptGeneration(U64::new(1)),
            command: "make test".to_owned(),
            started_at_ms: kr_ipc::now_ms(),
            duration_ms: Nullable::null(),
            exit_status: Nullable::null(),
            cwd: "/work".to_owned(),
            cwd_revision: CwdRevision(U64::new(1)),
        });
        read
    }
}

/// A closure of `session_id` that a close requested.
fn closure_of(session_id: SessionId) -> ClosureRecord {
    ClosureRecord {
        session_id,
        session_epoch: SessionEpoch::V1,
        reason: ClosureReason::CloseRequested,
        root_exit_code: Nullable::null(),
        root_signal: Nullable::null(),
        terminated: Vec::new(),
        surviving: Vec::new(),
        ownership_coverage: OwnershipCoverage::Complete,
        durability: Durability::Durable,
        closed_at_ms: kr_protocol::scalars::TimestampMs::new(1),
    }
}

/// A worker's answer to request `request_id`.
fn respond(request_id: RequestId, value: &impl serde::Serialize) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: Outcome::Ok(ParamsValue::from_typed(value).expect("encodes")),
    })
}

/// Serves `script` on a worker's endpoint.
fn serve_scripted(
    listener: Listener,
    identity: Arc<WorkerIdentity>,
    endpoint_text: String,
    script: Arc<Scripted>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                accepted = listener.accept() => accepted,
                () = script.going.notified() => break,
            };
            let Ok((connection, peer)) = accepted else {
                break;
            };
            let identity = Arc::clone(&identity);
            let endpoint_text = endpoint_text.clone();
            let script = Arc::clone(&script);
            script.connections.fetch_add(1, Ordering::AcqRel);
            tokio::spawn(async move {
                let (mut reader, mut writer) = split(connection, StreamKind::Control);
                let connection_id = ConnectionId::new(kr_ipc::new_uuid());
                while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                    if let ControlFrame::GenerationToken(token) = &frame {
                        script
                            .generations
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(token.generation);
                    }
                    let handshake = fake::handshake(
                        &frame,
                        &identity,
                        &endpoint_text,
                        connection_id,
                        &peer,
                        &kr_protocol::scalars::CanonicalSet::new(),
                    );
                    let answers = match (handshake, frame) {
                        (Some(answers), _) => answers,
                        (None, ControlFrame::Request(request))
                            if request.method == Method::SessionRead.into() =>
                        {
                            script.reads.fetch_add(1, Ordering::AcqRel);
                            let end = script
                                .end
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .take();
                            if let Some(end) = end {
                                let _ = end.arrived.send(());
                                let _ = end.go.await;
                                // The endpoint goes first and this connection after it, as a
                                // worker's do when its process exits.
                                script.going.notify_one();
                                script.gone.notified().await;
                                return;
                            }
                            if script.refusing.load(Ordering::Acquire) {
                                vec![ControlFrame::Response(Response {
                                    request_id: request.request_id,
                                    outcome: Outcome::Error(ProtocolError::new(
                                        ErrorCode::ResourceUnavailable,
                                        "this worker does not describe its session",
                                    )),
                                })]
                            } else {
                                let answer = script.answer(identity.session_id());
                                vec![respond(request.request_id, &answer)]
                            }
                        }
                        (None, ControlFrame::Forwarded(forwarded))
                            if forwarded.mutation.method == Method::SessionClose.into() =>
                        {
                            let (answer, kept) =
                                script.close(identity.session_id(), forwarded.mutation.action_id);
                            let response = Response {
                                request_id: forwarded.mutation.request_id,
                                outcome: Outcome::Ok(answer),
                            };
                            // A forwarded action this worker has answered before is answered
                            // from what it kept, and the frame says so, as a journal's answer
                            // does.
                            vec![if kept {
                                ControlFrame::RetainedResponse(Box::new(response))
                            } else {
                                ControlFrame::Response(response)
                            }]
                        }
                        (None, ControlFrame::ForwardedRead(forwarded))
                            if forwarded.request.method == Method::ActionRead.into() =>
                        {
                            vec![script.receipt(&forwarded.request)]
                        }
                        // It installs a revision it is told of, with nothing to fence, as a
                        // device's link to it asks it to.
                        (None, ControlFrame::AuthorityRevision(notice)) => {
                            vec![ControlFrame::AuthorityRevisionAck(
                                kr_protocol::worker::AuthorityRevisionAck {
                                    session_id: identity.session_id(),
                                    revision: notice.revision,
                                    fence: None,
                                },
                            )]
                        }
                        _ => Vec::new(),
                    };
                    for answer in answers {
                        if writer.write_message(&answer).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
        drop(listener);
        script.gone.notify_one();
    })
}

/// A daemon with a scripted worker in its directory, and the registry's own row for that
/// worker. The row names this test's process, which is the process the kernel is asked about.
/// The daemon has not heard from the worker yet, as after a start that found it running.
pub(super) async fn scripted(script: &Arc<Scripted>) -> Silent {
    let script = Arc::clone(script);
    let world = fake::fake_world(move |listener, identity, endpoint_text| {
        serve_scripted(listener, identity, endpoint_text, script)
    })
    .await;
    let descriptor = &world.worker.descriptor;
    world
        .controller
        .registry
        .lock()
        .await
        .adopt_worker(&WorkerRecord {
            session_id: world.session_id,
            display_number: descriptor.display_number,
            public_key: descriptor.worker_public_key,
            process_identity: descriptor.process_start_identity.clone(),
            endpoint: descriptor.endpoint.clone(),
            profile: WorkerProfile::HeadlessUser,
            state: SessionState::Live,
            acknowledged_revision: AuthorityRevision::new(0),
        })
        .expect("the registry records the worker");
    fake::acknowledged(&world.controller, world.session_id);
    world
}

/// The same world after its daemon was replaced: the one before it has let go of the
/// environment, and another has started on it and found the scripted worker still running, the
/// way a daemon that starts finds its workers, by the descriptor, the registry's row and a
/// challenge.
pub(super) async fn restarted(world: Silent) -> Silent {
    replaced(world, true).await
}

/// The same world after its daemon was replaced with the worker's descriptor gone: the daemon
/// that starts finds the worker only by the registry's row and its reservation, and recovers it
/// by a challenge.
async fn recovered(world: Silent) -> Silent {
    replaced(world, false).await
}

/// The same world after its daemon was replaced, with the worker's descriptor published or gone.
async fn replaced(world: Silent, descriptor: bool) -> Silent {
    let Silent {
        _temp,
        controller,
        environment_id,
        session_id,
        worker,
        serving,
        ..
    } = world;
    if descriptor {
        kr_ipc::descriptor::publish(&_temp.environment(), &worker.descriptor)
            .expect("publishes the worker's descriptor");
    } else {
        kr_ipc::descriptor::retire(&_temp.environment(), session_id)
            .expect("the worker's descriptor goes");
    }
    drop(controller);
    let started = std::time::Instant::now();
    let controller = loop {
        match Controller::start(fake::setup(&_temp)).await {
            Ok(controller) => break controller,
            Err(crate::error::ControllerError::AlreadyRunning { .. })
                if started.elapsed() < Duration::from_secs(60) =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(error) => panic!("the daemon does not start again: {error}"),
        }
    };
    fake::acknowledged(&controller, session_id);
    let actor = crate::service::local_actor(
        kr_protocol::ids::ActorId::new("local:test").expect("a principal"),
        ConnectionId::new(kr_ipc::new_uuid()),
        controller.generation,
    );
    let accepted = kr_transport::window::AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(Duration::from_secs(300))
            .expect("a deadline five minutes out"),
        bound: kr_transport::window::DeadlineBound::RequestedTtl,
    };
    Silent {
        _temp,
        controller,
        environment_id,
        session_id,
        worker,
        actor,
        accepted,
        serving,
    }
}

/// A daemon that recorded the scripted worker from its own ready report, as a daemon whose create
/// had stopped waiting for the report does: nothing has read the worker since, and the
/// reservation the create made is the registry's record of it.
async fn reported_late(script: &Arc<Scripted>) -> Silent {
    reported(script, true).await
}

/// The same daemon stopped part way through recording the worker's report: the registry holds the
/// worker's row and its descriptor is published, as they are before a daemon admits the worker,
/// and the daemon never reached the worker. They are all a daemon that starts has to go by.
async fn recorded_unreached(script: &Arc<Scripted>) -> Silent {
    reported(script, false).await
}

/// A daemon the scripted worker reported to, which admitted the worker or stopped just before.
async fn reported(script: &Arc<Scripted>, admitted: bool) -> Silent {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let controller = Controller::start(fake::setup(&temp))
        .await
        .expect("the daemon starts");
    let reservation = {
        let mut registry = controller.registry.lock().await;
        let intent = kr_cbor::to_canonical_vec(&kr_protocol::session::SessionCreateParams {
            environment_id,
            presentation: kr_protocol::session::Presentation::Invisible,
            shell: Nullable::null(),
            shell_mode: kr_protocol::session::ShellMode::NativeCompat,
            cwd: Nullable::some("/".to_owned()),
            dimensions: Nullable::null(),
            worker_profile: WorkerProfile::HeadlessUser,
            environment_snapshot: Vec::new(),
            palette: Nullable::null(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            terminal: Nullable::null(),
        })
        .expect("encodes");
        let admission = registry
            .reserve(
                &kr_protocol::ids::ActorId::new("local:test").expect("a principal"),
                kr_ipc::new_uuid(),
                kr_protocol::scalars::Digest256::from_bytes([0x5e; 32]),
                &intent,
                kr_ipc::now_ms(),
            )
            .expect("reserves");
        registry
            .set_phase(admission.reservation.reservation_id, LaunchPhase::Spawned)
            .expect("spawned");
        admission.reservation
    };
    let session_id = reservation.session_id;
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
    controller
        .registry
        .lock()
        .await
        .claim_rendezvous(reservation.reservation_id, *identity.public_key())
        .expect("claims");
    let endpoint = environment
        .worker_endpoint(reservation.display_number)
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the worker endpoint");
    let serving = serve_scripted(
        listener,
        Arc::clone(&identity),
        endpoint.as_text(),
        Arc::clone(script),
    );
    let claim = identity
        .rendezvous(kr_protocol::worker::ReservationId::new(
            reservation.reservation_id.get(),
        ))
        .expect("a startup claim");
    let report = kr_protocol::worker::WorkerReady {
        session_id,
        endpoint: endpoint.as_text(),
        root_process: identity.process_start_identity().clone(),
        shell_path: "/bin/zsh".to_owned(),
        dimensions: INVISIBLE_DEFAULT_DIMENSIONS,
        session: Box::new(script.answer(session_id).session),
    };
    let worker = if admitted {
        controller
            .record_ready(reservation.reservation_id, &claim, &report)
            .await
            .expect("records the worker from its report");
        controller
            .directory
            .lock()
            .await
            .get(session_id)
            .cloned()
            .expect("the report admits the worker")
    } else {
        // What recording the report writes before the daemon admits the worker: the worker's row,
        // with its key and the live phase, and its descriptor.
        controller
            .registry
            .lock()
            .await
            .record_worker(
                reservation.reservation_id,
                &WorkerRecord {
                    session_id,
                    display_number: reservation.display_number,
                    public_key: claim.worker_public_key,
                    process_identity: claim.process_start_identity.clone(),
                    endpoint: report.endpoint.clone(),
                    profile: WorkerProfile::HeadlessUser,
                    state: SessionState::Live,
                    acknowledged_revision: AuthorityRevision::new(0),
                },
            )
            .expect("records the worker");
        let descriptor = kr_protocol::worker::WorkerDescriptor {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: reservation.display_number,
            boot_identity: claim.boot_identity.clone(),
            process_start_identity: claim.process_start_identity.clone(),
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            endpoint: report.endpoint.clone(),
            worker_public_key: claim.worker_public_key,
            worker_profile: WorkerProfile::HeadlessUser,
            published_at_ms: kr_ipc::now_ms(),
        };
        kr_ipc::descriptor::publish(&environment, &descriptor)
            .expect("publishes the worker's descriptor");
        crate::directory::KnownWorker {
            descriptor,
            endpoint,
        }
    };
    fake::acknowledged(&controller, session_id);
    let actor = crate::service::local_actor(
        kr_protocol::ids::ActorId::new("local:test").expect("a principal"),
        ConnectionId::new(kr_ipc::new_uuid()),
        controller.generation,
    );
    let accepted = kr_transport::window::AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(Duration::from_secs(300))
            .expect("a deadline five minutes out"),
        bound: kr_transport::window::DeadlineBound::RequestedTtl,
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

/// Reads the session through the daemon, as a client's `session.read` does.
pub(super) async fn read(world: &Silent) -> crate::error::Result<SessionReadResult> {
    world
        .controller
        .session_read(
            &ParamsValue::from_typed(&SessionReadParams {
                session_id: world.session_id,
            })
            .expect("encodes"),
        )
        .await
        .map(|value| value.to_typed().expect("decodes"))
}

/// Reads the session through the daemon on a task of its own.
fn read_in_turn(
    world: &Silent,
) -> tokio::task::JoinHandle<crate::error::Result<SessionReadResult>> {
    let controller = Arc::clone(&world.controller);
    let params = ParamsValue::from_typed(&SessionReadParams {
        session_id: world.session_id,
    })
    .expect("encodes");
    tokio::spawn(async move {
        controller
            .session_read(&params)
            .await
            .map(|value| value.to_typed().expect("decodes"))
    })
}

/// Lists the sessions through the daemon, as a client's `session.list` does, and returns each
/// one's identity and state.
pub(super) async fn list(world: &Silent, include_closed: bool) -> Vec<(SessionId, SessionState)> {
    let listed: SessionListResult = world
        .controller
        .session_list(
            &ParamsValue::from_typed(&SessionListParams {
                environment_id: Nullable::null(),
                include_closed,
            })
            .expect("encodes"),
        )
        .await
        .expect("the daemon lists its sessions")
        .to_typed()
        .expect("decodes");
    listed
        .sessions
        .iter()
        .map(|session| (session.session_id, session.state))
        .collect()
}

/// Closes the session through the daemon, and returns what the worker accepted it with.
async fn close(world: &Silent) -> SessionCloseResult {
    world
        .controller
        .session_close(
            &fake::close_request(world.environment_id, world.session_id),
            &world.actor,
            Some(world.accepted),
            fake::admission(&world.controller, world.accepted).await,
        )
        .await
        .expect("the worker accepts the close")
        .to_typed()
        .expect("decodes")
}

/// Whether the registry has a closure recorded for the session.
pub(super) async fn recorded(world: &Silent) -> bool {
    world
        .controller
        .registry
        .lock()
        .await
        .closure(world.session_id)
        .expect("the registry answers")
        .is_some()
}

/// A read that meets the end of a worker whose close this daemon accepted is answered from
/// this daemon's own record: the session is closing, and what is left of its closure is this
/// host's to record once the kernel says the worker has ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_that_meets_the_end_of_a_worker_whose_close_was_accepted_answers_closing() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    let live = read(&world).await.expect("the worker answers");
    assert_eq!(live.session.state, SessionState::Live);
    assert!(live.last_command_block.0.is_some());
    assert_eq!(close(&world).await.state, SessionState::Closing);

    // The worker finishes its closure and goes while a read is waiting on it.
    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let answer = read(&world)
        .await
        .expect("a closing session is answered for from this daemon's own record");
    assert_eq!(
        answer.session,
        SessionSummary {
            state: SessionState::Closing,
            ..live.session
        },
        "the session as its worker last described it, closing"
    );
    assert!(
        answer.endpoint.0.is_none(),
        "an endpoint that has stopped answering is not handed out"
    );
    assert!(
        answer.last_command_block.0.is_none(),
        "and the session's content is its worker's to hand out, not this daemon's"
    );
    assert!(
        !recorded(&world).await,
        "and nothing is recorded over a worker the kernel says is still running"
    );
    world.serving.abort();
}

/// A worker a daemon finds when it starts is admitted with its own description of its session,
/// asked for over the connection it proved itself on. A close accepted before anything else
/// has read the worker therefore still leaves the session described: a read that meets the
/// worker's end answers it closing, as the worker described it at the start, including a size
/// the session was given while the daemon before this one ran. Nothing is asked of the worker
/// at the close, whose link the worker is holding the close on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_found_at_a_start_is_admitted_with_its_own_description() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    script.resize(Dimensions::new(100, 30));
    let world = restarted(world).await;
    assert_eq!(
        script.reads(),
        1,
        "the start asks the worker to describe its session"
    );

    // The worker goes at the first read it is sent after the close, whoever sends it.
    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    assert_eq!(close(&world).await.state, SessionState::Closing);
    assert_eq!(script.reads(), 1, "the close asks the worker nothing");
    let answer = read(&world)
        .await
        .expect("a closing session is answered for from this daemon's own record");
    assert_eq!(
        answer.session,
        SessionSummary {
            state: SessionState::Closing,
            dimensions: Dimensions::new(100, 30),
            created_at_ms: answer.session.created_at_ms,
            ..fake::read_result(world.session_id).session
        },
        "the session as its worker described it when this daemon started"
    );
    assert!(answer.endpoint.0.is_none());
    assert!(!recorded(&world).await);
    world.serving.abort();
}

/// A worker that proves itself when a daemon starts but does not describe its session is
/// admitted all the same, because a close has to be able to reach every worker that has proved
/// itself; the description it did not give is what it gives when it next answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_does_not_describe_its_session_at_a_start_can_still_be_closed() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    script.refuse_reads(true);
    let world = restarted(world).await;
    assert_eq!(script.reads(), 1, "the start asks for the description");
    assert!(
        world
            .controller
            .directory
            .lock()
            .await
            .get(world.session_id)
            .is_some(),
        "the worker that proved itself is admitted"
    );
    assert_eq!(
        close(&world).await.state,
        SessionState::Closing,
        "and a close reaches it"
    );

    script.refuse_reads(false);
    assert_eq!(
        read(&world)
            .await
            .expect("the worker answers")
            .session
            .state,
        SessionState::Closing
    );
    world.serving.abort();
}

/// A session that began closing on its own is answered for the same way: its worker said it
/// was closing, and that is what the session still is when the worker stops answering.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_that_meets_the_end_of_a_worker_that_said_it_was_closing_answers_closing() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    // The shell exits, and the worker begins the closure itself.
    script.set(SessionState::Closing);
    let closing = read(&world).await.expect("the worker answers");
    assert_eq!(closing.session.state, SessionState::Closing);

    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let answer = read(&world)
        .await
        .expect("a closing session is answered for from this daemon's own record");
    assert_eq!(answer.session, closing.session);
    assert!(!recorded(&world).await);
    world.serving.abort();
}

/// An answer that puts the session earlier in its lifecycle than an answer this daemon already
/// has does not take it back there: it is one an earlier moment gave, and a later one overtook.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_overtaken_by_a_later_one_does_not_move_the_session_back() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    script.set(SessionState::Closing);
    assert_eq!(
        read(&world)
            .await
            .expect("the worker answers")
            .session
            .state,
        SessionState::Closing
    );
    // An answer from before the closing began, arriving after the one that said it had.
    script.set(SessionState::Live);
    assert_eq!(
        read(&world)
            .await
            .expect("the worker answers")
            .session
            .state,
        SessionState::Live,
        "the worker's own answer is passed on as it stands"
    );

    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let answer = read(&world)
        .await
        .expect("the closing this daemon heard of is still what it answers from");
    assert_eq!(answer.session.state, SessionState::Closing);
    world.serving.abort();
}

/// A read that meets the end of a worker after the session's closure was recorded is answered
/// with that closure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_that_meets_the_end_of_a_worker_whose_closure_was_recorded_answers_it() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    assert_eq!(close(&world).await.state, SessionState::Closing);

    let (arrived, go) = script.end_at_next_read();
    let reading = read_in_turn(&world);
    arrived.await.expect("the read reaches the worker");
    // The closure is recorded while the read waits on the worker.
    let record = closure_of(world.session_id);
    world
        .controller
        .retire(&record)
        .await
        .expect("the closure is recorded");
    drop(go);

    let answer = reading
        .await
        .expect("the read finishes")
        .expect("a closed session is answered with its closure");
    assert_eq!(answer.session.state, SessionState::Closed);
    assert_eq!(answer.session.closure.0, Some(record));
    world.serving.abort();
}

/// A read whose worker goes while the session's closure is being recorded answers the
/// closure, however the recording and the read's look at what this daemon holds interleave.
///
/// The read is stopped once it has met the worker's end and asked the kernel, before it looks
/// at what this daemon holds of the session. The closure is recorded then, as a closure's
/// recording does it, the registry first and the worker out of the directory after, and the
/// read goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_that_meets_the_end_of_a_worker_as_its_closure_is_recorded_answers_it() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    assert_eq!(close(&world).await.state, SessionState::Closing);

    let (_at_the_worker, worker_goes) = script.end_at_next_read();
    drop(worker_goes);
    let (at_the_record, read_goes) = world.controller.before_the_record.arm();
    let reading = read_in_turn(&world);
    at_the_record
        .await
        .expect("the read meets the worker's end and asks the kernel");
    let record = closure_of(world.session_id);
    world
        .controller
        .registry
        .lock()
        .await
        .record_closure(&record)
        .expect("the closure is recorded");
    world
        .controller
        .directory
        .lock()
        .await
        .remove(world.session_id);
    let _ = read_goes.send(());

    let answer = reading
        .await
        .expect("the read finishes")
        .expect("a closed session is answered with its closure");
    assert_eq!(answer.session.state, SessionState::Closed);
    assert_eq!(answer.session.closure.0, Some(record));
    world.serving.abort();
}

/// A list that meets the end of a worker whose close this daemon accepted lists the session as
/// closing rather than leaving it out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_that_meets_the_end_of_a_worker_whose_close_was_accepted_lists_it_closing() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    assert_eq!(
        read(&world)
            .await
            .expect("the worker answers")
            .session
            .state,
        SessionState::Live
    );
    assert_eq!(close(&world).await.state, SessionState::Closing);

    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    assert_eq!(
        list(&world, false).await,
        vec![(world.session_id, SessionState::Closing)]
    );
    world.serving.abort();
}

/// A session whose worker says it has closed is listed only where closed sessions were asked
/// for, whether the worker says so itself or this daemon answers for a worker on its way out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_its_worker_says_has_closed_is_listed_only_with_the_closed_sessions() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    // The worker has finished its closure and not yet gone.
    script.set(SessionState::Closed);
    assert_eq!(list(&world, false).await, Vec::new());
    assert_eq!(
        list(&world, true).await,
        vec![(world.session_id, SessionState::Closed)]
    );

    // It goes while a list is waiting on it, and its endpoint is gone for the one after.
    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    assert_eq!(list(&world, false).await, Vec::new());
    assert_eq!(
        list(&world, true).await,
        vec![(world.session_id, SessionState::Closed)]
    );
    assert!(!recorded(&world).await);
    world.serving.abort();
}

/// Where this daemon has no word of an end, a worker that stops answering is not taken for
/// one: the session was live when its worker last answered, the kernel says the worker is
/// still running, and the read is refused as something to try again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_that_meets_a_live_workers_connection_ending_is_refused_for_now() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    assert_eq!(
        read(&world)
            .await
            .expect("the worker answers")
            .session
            .state,
        SessionState::Live
    );

    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let refused = read(&world)
        .await
        .expect_err("nothing this daemon holds says what the session is now");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable, "{refused}");
    assert!(
        refused.code().retry_category().permits_automatic_retry(),
        "and a read may be asked again: {refused}"
    );
    assert!(!recorded(&world).await);
    world.serving.abort();
}

/// Nor is a worker this daemon has not heard from at all, and whose close it has not passed
/// on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_that_meets_the_end_of_a_worker_never_heard_from_is_refused_for_now() {
    let script = Scripted::new();
    let world = scripted(&script).await;

    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let refused = read(&world)
        .await
        .expect_err("nothing this daemon holds says what the session is now");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable, "{refused}");
    assert!(!recorded(&world).await);
    world.serving.abort();
}

/// KR-REQ-23.34: a worker the daemon recorded from a ready report that came after its create had
/// stopped waiting, and whose close it passed on before anything read the worker, is answered for
/// from the worker's own words once it stops answering: the session as its acceptance described
/// it, closing, and a list that includes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_recorded_from_a_late_report_that_accepts_a_close_and_goes_is_answered_closing() {
    let script = Scripted::new();
    let world = reported_late(&script).await;
    let accepted = close(&world).await;
    assert_eq!(accepted.state, SessionState::Closing);
    assert_eq!(script.reads(), 0, "nothing has read the worker");

    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let answer = read(&world)
        .await
        .expect("a closing session is answered from the worker's own words");
    assert_eq!(
        Some(answer.session),
        accepted.session,
        "the session as its worker described it when it accepted the close"
    );
    assert!(answer.endpoint.0.is_none());
    assert!(answer.last_command_block.0.is_none());
    assert_eq!(
        list(&world, false).await,
        vec![(world.session_id, SessionState::Closing)]
    );
    assert!(!recorded(&world).await);
    world.serving.abort();
}

/// KR-REQ-23.34: the same for a worker a daemon finds at its start and admits without a
/// description, which accepts a close and goes before anything reads it: its acceptance carries
/// what the start did not hear.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_admitted_at_a_start_without_a_description_that_accepts_a_close_and_goes_is_answered_closing()
 {
    let script = Scripted::new();
    let world = scripted(&script).await;
    script.refuse_reads(true);
    let world = restarted(world).await;
    assert_eq!(
        script.reads(),
        1,
        "the start asked for a description and got none"
    );
    let accepted = close(&world).await;

    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let answer = read(&world)
        .await
        .expect("a closing session is answered from the acceptance");
    assert_eq!(Some(answer.session), accepted.session);
    assert_eq!(
        list(&world, false).await,
        vec![(world.session_id, SessionState::Closing)]
    );
    world.serving.abort();
}

/// KR-REQ-23.34: the same for a worker a replacement daemon recovers from the registry's row
/// without a description, its descriptor gone: a close passed through the replacement supplies
/// what the replacement never heard when it admitted the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_a_replacement_daemon_recovers_without_a_description_that_accepts_a_close_and_goes_is_answered_closing()
 {
    let script = Scripted::new();
    let world = reported_late(&script).await;
    script.refuse_reads(true);
    let world = recovered(world).await;
    assert!(
        world
            .controller
            .directory
            .lock()
            .await
            .get(world.session_id)
            .is_some(),
        "the replacement recovers the worker from the registry's row"
    );
    assert_eq!(
        script.reads(),
        1,
        "and asks it for a description, which it refuses"
    );
    let accepted = close(&world).await;

    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let answer = read(&world)
        .await
        .expect("a closing session is answered from the acceptance");
    assert_eq!(Some(answer.session), accepted.session);
    assert_eq!(
        list(&world, false).await,
        vec![(world.session_id, SessionState::Closing)]
    );
    world.serving.abort();
}

/// An answer that puts the session earlier in its lifecycle than an acceptance does not take the
/// description back: it is one an earlier moment gave, and the acceptance overtook it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_later_live_answer_does_not_take_back_what_an_acceptance_described() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    script.resize(Dimensions::new(100, 30));
    let accepted = close(&world).await;
    // An answer from before the close, arriving after the acceptance.
    script.set(SessionState::Live);
    script.resize(Dimensions::new(90, 20));
    assert_eq!(
        read(&world)
            .await
            .expect("the worker answers")
            .session
            .state,
        SessionState::Live,
        "the worker's own answer is passed on as it stands"
    );

    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let answer = read(&world)
        .await
        .expect("the acceptance is still what this daemon answers from");
    assert_eq!(Some(answer.session), accepted.session);
    world.serving.abort();
}

/// KR-REQ-23.34: a worker recorded from a late report that accepts no close is still read from
/// itself, and once it stops answering nothing this daemon holds says its session is ending: its
/// report and its last answer both say it is live, so the read is refused as one to try again and
/// a list leaves the session out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_recorded_from_a_late_report_that_goes_without_a_close_is_refused_for_now() {
    let script = Scripted::new();
    let world = reported_late(&script).await;
    let live = read(&world).await.expect("the worker answers");
    assert_eq!(live.session.state, SessionState::Live);
    assert_eq!(script.reads(), 1, "the read reached the worker");

    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let refused = read(&world)
        .await
        .expect_err("nothing this daemon holds says the session is ending");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable, "{refused}");
    assert_eq!(list(&world, false).await, Vec::new());
    world.serving.abort();
}

/// An acceptance from a worker built before the description gives this daemon none: a worker it
/// admitted without one, which then goes, is refused for now rather than described from anything
/// its worker did not say.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_acceptance_without_a_description_leaves_a_worker_admitted_without_one_undescribed() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    script.refuse_reads(true);
    script.built_before_the_description();
    let world = restarted(world).await;
    let accepted = close(&world).await;
    assert_eq!(accepted.state, SessionState::Closing);
    assert_eq!(
        accepted.session, None,
        "a worker of that build describes nothing"
    );

    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let refused = read(&world)
        .await
        .expect_err("nothing the worker said describes the session");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable, "{refused}");
    world.serving.abort();
}

/// A description that names another session is not kept as this one's: a worker admitted
/// without a description, whose acceptance describes another session and which then goes, is
/// refused for now rather than answered with the other session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_acceptance_that_describes_another_session_is_not_kept() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    script.refuse_reads(true);
    script.describing(SessionId::new(kr_ipc::new_uuid()));
    let world = restarted(world).await;
    let _ = close(&world).await;

    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let refused = read(&world)
        .await
        .expect_err("no description of this session reached the daemon");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable, "{refused}");
    world.serving.abort();
}

/// A worker whose reservation this host fenced is not reached by a daemon that starts: the daemon
/// does not even connect to it, presents it no generation, and leaves it out of the directory, as
/// recovery leaves such a worker. The control: a worker whose reservation stands is reached and
/// admitted as before.
///
/// The daemon before the restart recorded the worker and stopped before it admitted it, so it
/// never reached the worker, and every connection the worker accepts is the new daemon's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_that_starts_does_not_reach_a_worker_whose_reservation_is_fenced() {
    for fenced in [true, false] {
        let script = Scripted::new();
        let world = recorded_unreached(&script).await;
        if fenced {
            let mut registry = world.controller.registry.lock().await;
            let reservation = registry
                .reservation_for_session(world.session_id)
                .expect("the registry answers")
                .expect("the create's reservation");
            registry
                .fence(reservation.reservation_id)
                .expect("fences the reservation");
        }
        assert_eq!(
            script.connections(),
            0,
            "nothing reached the worker before the restart"
        );
        let world = restarted(world).await;
        let connections = script.connections();
        let reached = script.presented(world.controller.generation);
        let admitted = world
            .controller
            .directory
            .lock()
            .await
            .get(world.session_id)
            .is_some();
        if fenced {
            assert_eq!(
                connections, 0,
                "the daemon that started did not even connect to the worker"
            );
            assert!(!reached, "it presented the worker no generation");
            assert!(!admitted, "and the worker stays out of its directory");
        } else {
            assert!(
                reached,
                "the daemon that started reached the worker and presented it its generation"
            );
            assert!(admitted, "and admitted it");
        }
        world.serving.abort();
    }
}
