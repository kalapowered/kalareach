//! A read of a session whose worker stops answering part way through it.
//!
//! A worker that has finished its closure stops answering before the kernel says its process
//! has ended, so a read that is waiting on it can meet its connection ending while nothing yet
//! says the worker has gone. The worker here is a double that goes that way when a test tells
//! it to. Its process is this test's own, so the kernel says it is running throughout, and the
//! registry names that process as the session's worker, as it names a real one.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use kr_ipc::endpoint::Listener;
use kr_ipc::framed::split;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{AuthorityRevision, ConnectionId, RequestId, SessionEpoch, SessionId};
use kr_protocol::method::Method;
use kr_protocol::root::{CwdRevision, PromptGeneration, RootCommandBlockParams};
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::session::{
    ClosureReason, ClosureRecord, Dimensions, Durability, INVISIBLE_DEFAULT_DIMENSIONS,
    OwnershipCoverage, SessionCloseResult, SessionListParams, SessionListResult, SessionReadParams,
    SessionReadResult, SessionState, SessionSummary,
};
use tokio::sync::{Notify, oneshot};

use super::a_close_a_worker_never_answers::{self as fake, Silent};
use crate::registry::WorkerRecord;
use crate::service::Controller;

/// A worker whose session a test moves along, and which goes when the test says so.
///
/// It answers a read with the state a test has put its session in, live to begin with, and
/// accepts a close by saying the session is closing, as a worker does before it stops
/// anything. Told to go, it goes the way a worker that has finished its closure goes: at the
/// next read it is sent, its endpoint stops accepting, and then the connection that read is
/// waiting on ends unanswered.
struct Scripted {
    /// The state its session is in.
    state: std::sync::Mutex<SessionState>,
    /// Its session's size.
    dimensions: std::sync::Mutex<Dimensions>,
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
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new(SessionState::Live),
            dimensions: std::sync::Mutex::new(INVISIBLE_DEFAULT_DIMENSIONS),
            reads: AtomicUsize::new(0),
            refusing: AtomicBool::new(false),
            end: std::sync::Mutex::new(None),
            going: Notify::new(),
            gone: Notify::new(),
        })
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
    fn refuse_reads(&self, refusing: bool) {
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
    fn end_at_next_read(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
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
            tokio::spawn(async move {
                let (mut reader, mut writer) = split(connection, StreamKind::Control);
                let connection_id = ConnectionId::new(kr_ipc::new_uuid());
                while let Ok(frame) = reader.read_message::<ControlFrame>().await {
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
                            if script.state() == SessionState::Live {
                                script.set(SessionState::Closing);
                            }
                            vec![respond(
                                forwarded.mutation.request_id,
                                &SessionCloseResult {
                                    session_id: identity.session_id(),
                                    state: SessionState::Closing,
                                    durability: Durability::Durable,
                                    closure: Nullable::null(),
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
async fn scripted(script: &Arc<Scripted>) -> Silent {
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
async fn restarted(world: Silent) -> Silent {
    let Silent {
        _temp,
        controller,
        environment_id,
        session_id,
        worker,
        serving,
        ..
    } = world;
    kr_ipc::descriptor::publish(&_temp.environment(), &worker.descriptor)
        .expect("publishes the worker's descriptor");
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

/// Reads the session through the daemon, as a client's `session.read` does.
async fn read(world: &Silent) -> crate::error::Result<SessionReadResult> {
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
async fn list(world: &Silent, include_closed: bool) -> Vec<(SessionId, SessionState)> {
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
async fn recorded(world: &Silent) -> bool {
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
