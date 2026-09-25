//! Answers that did not reach their session: kept on this device, offered again, and sent only
//! when the person sends them.
//!
//! Section 11: offline answers remain drafts, and a reconnect never submits them. `kr question
//! answer` keeps an answer the session's worker could not take, or whose outcome is not known, and
//! says so. `kr question drafts` reads the questions again and says of each kept answer whether it
//! can still be sent or has been retired, and why; it sends nothing. `kr question send` is
//! the one step that sends a kept answer.
//!
//! The worker here is scripted, because what is under test is what the command does when a worker
//! behaves in ways a healthy one does not: ending the connection after the read, or moving the
//! question while an answer is kept. It speaks the real protocol on a real local socket, publishes
//! a real descriptor and proves itself with a key of its own, so `kr` finds, challenges and talks
//! to it exactly as it does a worker. It counts every answer it is sent, which is how "sends
//! nothing" is read.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use kr_ipc::endpoint::Listener;
use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{
    ActorId, ApplicationInstanceId, ConnectionId, EnvironmentId, QuestionId, QuestionRevision,
    SessionEpoch, SessionId,
};
use kr_protocol::question::{
    AnswerRecord, Question, QuestionAnswerParams, QuestionChoice, QuestionKind, QuestionReadParams,
    QuestionReadResult, QuestionResolveResult, QuestionSource, QuestionState,
};
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};
use kr_protocol::session::DisplayNumber;
use kr_protocol::worker::WorkerDescriptor;
use serde_json::Value;

mod support;

/// How the scripted worker behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Behaviour {
    /// Goes on serving the connection, and takes an answer to a pending question at the revision
    /// it names.
    Serves,
    /// Ends the connection as soon as a read is answered.
    EndsAfterTheRead,
    /// Takes an answer, then ends the connection without replying.
    TakesAnswersAndDropsTheReply,
    /// Refuses every read with `PERMISSION_DENIED`.
    RefusesReads,
    /// Replies to an answer with a frame that is not a message, and takes nothing.
    RepliesWithGarbage,
    /// Refuses an answer with `OUTCOME_UNKNOWN`: it cannot say what became of it.
    CannotSayWhatBecameOfAnswers,
    /// Takes an answer and replies with a result that is not an answered question.
    TakesAnswersAndRepliesUnreadably,
    /// Takes an answer, makes the store of kept answers read-only, and replies.
    TakesAnswersAndLocksTheStore,
}

/// Which environment the scripted session runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    /// This installation's own.
    Installation,
    /// A second environment on the same host.
    SecondEnvironment,
}

/// What a scripted control daemon says of the session when it is asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Registry {
    /// The session closed.
    Closed,
    /// The session is live.
    Live,
    /// The registry never held the session.
    NeverHeld,
}

/// What the scripted worker holds.
struct State {
    question: Question,
    behaviour: Behaviour,
    /// Every answer it was sent, whether or not it took it.
    answers_received: usize,
    /// The directory `kr` keeps answers in.
    store: PathBuf,
}

/// A host tree with one scripted session in it, holding one question.
struct Host {
    temp: kr_ipc::testing::TempHost,
    home: PathBuf,
    state: Arc<Mutex<State>>,
    serving: tokio::task::JoinHandle<()>,
    question_id: QuestionId,
    /// The environment the session runs in.
    environment: EnvironmentPaths,
    /// Where the session's descriptor is published.
    descriptor: PathBuf,
}

impl Drop for Host {
    fn drop(&mut self) {
        self.serving.abort();
        // The tree is removed afterwards, which a read-only store would stop.
        self.unlock_store();
    }
}

impl Host {
    async fn start(behaviour: Behaviour) -> Self {
        Self::start_in(behaviour, Place::Installation).await
    }

    async fn start_in(behaviour: Behaviour, place: Place) -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let home = temp.root().join("h");
        std::fs::create_dir(&home).expect("a home directory on the internal disk");
        let environment = match place {
            Place::Installation => temp.environment(),
            Place::SecondEnvironment => {
                let environment = temp
                    .paths()
                    .environment(EnvironmentId::new(kr_ipc::new_uuid()));
                environment.create().expect("a second environment");
                environment
            }
        };
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let display = DisplayNumber::new(1);
        let endpoint = environment.worker_endpoint(display).expect("an endpoint");
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let process =
            kr_ipc::identity::current_process_start_identity().expect("a process identity");
        let identity = Arc::new(
            WorkerIdentity::generate(
                session_id,
                SessionEpoch::V1,
                boot.clone(),
                process.clone(),
                PROTOCOL_VERSION,
            )
            .expect("a worker identity"),
        );
        let descriptor = WorkerDescriptor {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id: environment.environment_id(),
            display_number: display,
            boot_identity: boot,
            process_start_identity: process,
            protocol_version: PROTOCOL_VERSION,
            endpoint: endpoint.as_text(),
            worker_public_key: *identity.public_key(),
            worker_profile: WorkerProfile::HeadlessUser,
            published_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
        };
        let listener = Listener::bind(&endpoint).expect("binds the worker's endpoint");
        kr_ipc::descriptor::publish(&environment, &descriptor).expect("publishes the descriptor");
        let question = pending_question(session_id);
        let question_id = question.question_id;
        let state = Arc::new(Mutex::new(State {
            question,
            behaviour,
            answers_received: 0,
            store: temp.paths().state_root().join("kept-answers"),
        }));
        let serving = tokio::spawn(serve(
            listener,
            descriptor,
            Arc::clone(&identity),
            Arc::clone(&state),
        ));
        Self {
            descriptor: environment.descriptor_file(session_id),
            environment,
            temp,
            home,
            state,
            serving,
            question_id,
        }
    }

    fn behave(&self, behaviour: Behaviour) {
        self.state().behaviour = behaviour;
    }

    /// Lets `kr` write to the store of kept answers again.
    fn unlock_store(&self) {
        let store = self.state().store.clone();
        if store.is_dir() {
            std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700))
                .expect("the store is writable again");
        }
    }

    /// Stops the worker, as a worker that ended would, and leaves its descriptor where it was.
    async fn stop_worker(&mut self) {
        self.serving.abort();
        let _ = (&mut self.serving).await;
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn answers_received(&self) -> usize {
        self.state().answers_received
    }

    /// Where this user's kept answers live: the state directory `kr` is given.
    fn kept(&self) -> PathBuf {
        self.temp
            .paths()
            .state_root()
            .join("kept-answers")
            .join(format!("{}.answer", self.question_id))
    }

    fn kr(&self, line: &[&str]) -> std::process::Output {
        std::process::Command::new(support::kr())
            .args(line)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("KR_RUNTIME_DIR", self.temp.paths().runtime_root())
            .env("KR_STATE_DIR", self.temp.paths().state_root())
            .current_dir(self.temp.root())
            .stdin(std::process::Stdio::null())
            .output()
            .expect("kr runs")
    }

    /// Runs `kr` with `--json` and reads the one document it printed, with the status it exited
    /// with.
    fn json(&self, line: &[&str]) -> (Option<i32>, Value) {
        let mut asked = line.to_vec();
        asked.push("--json");
        let output = self.kr(&asked);
        let document = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "kr {} printed no document ({error}): {}{}",
                asked.join(" "),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code(), document)
    }

    fn question(&self) -> String {
        self.question_id.to_string()
    }
}

impl Host {
    /// Starts a control daemon for the session's environment that answers `session.read` for the
    /// scripted session as `registry` says, until the returned task is ended.
    fn daemon(&self, registry: Registry) -> tokio::task::JoinHandle<()> {
        self.daemon_in(&self.environment, registry)
    }

    /// Starts a control daemon for `environment` that answers `session.read` for the scripted
    /// session as `registry` says, until the returned task is ended.
    fn daemon_in(
        &self,
        environment: &EnvironmentPaths,
        registry: Registry,
    ) -> tokio::task::JoinHandle<()> {
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the control endpoint");
        let environment_id = environment.environment_id();
        let session_id = self.state().question.session_id;
        tokio::spawn(async move {
            while let Ok((connection, peer)) = listener.accept().await {
                tokio::spawn(serve_daemon(
                    connection,
                    peer,
                    environment_id,
                    session_id,
                    registry,
                ));
            }
        })
    }
}

/// Answers one caller of the scripted control daemon.
async fn serve_daemon(
    connection: kr_ipc::endpoint::Connection,
    peer: kr_ipc::peer::PeerIdentity,
    environment_id: kr_protocol::ids::EnvironmentId,
    session_id: SessionId,
    registry: Registry,
) {
    let (mut reader, mut writer) = kr_ipc::framed::split(connection, StreamKind::Control);
    let Ok(ControlFrame::Hello(hello)) = reader.read_message::<ControlFrame>().await else {
        return;
    };
    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
    let acknowledgement = kr_protocol::local::LocalHelloAck {
        selected_version: PROTOCOL_VERSION,
        role: kr_protocol::local::LocalRole::Controller,
        connection_id,
        environment_id,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        peer: kr_protocol::local::LocalPeer {
            uid: kr_protocol::scalars::U64::new(u64::from(peer.uid)),
            gid: kr_protocol::scalars::U64::new(u64::from(peer.gid)),
            pid: Nullable::null(),
        },
        action_window: kr_protocol::hello::ActionWindow {
            action_window_id: kr_protocol::ids::ActionWindowId::new("window-1")
                .expect("a window identifier"),
            connection_id,
            boot_epoch: kr_protocol::ids::BootEpoch::new(1),
            issued_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
            valid_for_ms: kr_protocol::scalars::DurationMs::new(60_000),
        },
        capabilities: CanonicalSet::new(),
        max_receive: hello.max_receive,
    };
    if writer
        .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
        .await
        .is_err()
    {
        return;
    }
    while let Ok(frame) = reader.read_message::<ControlFrame>().await {
        let ControlFrame::Request(request) = frame else {
            continue;
        };
        let outcome = match (request.method.as_str(), registry) {
            ("session.read", Registry::Closed) => Outcome::Error(ProtocolError::new(
                ErrorCode::SessionClosed,
                "the session has closed",
            )),
            ("session.read", Registry::Live) => Outcome::Ok(
                ParamsValue::from_typed(&live_session(environment_id, session_id))
                    .expect("a session"),
            ),
            ("session.read", Registry::NeverHeld) => Outcome::Error(ProtocolError::new(
                ErrorCode::UnknownSession,
                "this daemon has no such session",
            )),
            (other, _) => Outcome::Error(refusal(&format!("this daemon answers no {other}"))),
        };
        let response = ControlFrame::Response(Response {
            request_id: request.request_id,
            outcome,
        });
        if writer.write_message(&response).await.is_err() {
            return;
        }
    }
}

/// The scripted session, as a daemon reads it while it is live.
fn live_session(
    environment_id: kr_protocol::ids::EnvironmentId,
    session_id: SessionId,
) -> kr_protocol::session::SessionReadResult {
    kr_protocol::session::SessionReadResult {
        session: kr_protocol::session::SessionSummary {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: DisplayNumber::new(1),
            state: kr_protocol::session::SessionState::Live,
            shell_mode: kr_protocol::session::ShellMode::NativeCompat,
            shell_path: "/bin/sh".to_owned(),
            cwd: "/".to_owned(),
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: kr_protocol::identity::DesktopBinding::none(),
            created_at_ms: TimestampMs::new(1),
            dimensions: kr_protocol::session::Dimensions::new(80, 24),
            attachment_count: kr_protocol::scalars::U64::new(0),
            application_state: Nullable::null(),
            root_process: Nullable::null(),
            closure: Nullable::null(),
        },
        endpoint: Nullable::null(),
        launch_profile: Nullable::null(),
        last_command_block: Nullable::null(),
        outstanding_launches: Nullable::null(),
    }
}

/// A select question, pending at revision 1.
fn pending_question(session_id: SessionId) -> Question {
    let now = kr_ipc::now_ms().get();
    Question {
        question_id: QuestionId::new(kr_ipc::new_uuid()),
        revision: QuestionRevision::new(1),
        state: QuestionState::Pending,
        session_id,
        session_epoch: SessionEpoch::V1,
        kind: QuestionKind::Select,
        context: "two ways to go".to_owned(),
        question: "which one?".to_owned(),
        choices: vec![
            QuestionChoice {
                choice_id: "left".to_owned(),
                label: "Left".to_owned(),
            },
            QuestionChoice::something_else(),
        ],
        source: QuestionSource {
            application_instance_id: ApplicationInstanceId::new(kr_ipc::new_uuid()),
            process: kr_ipc::identity::current_process_start_identity()
                .expect("a process identity"),
            executable: Nullable::some("/usr/bin/an-agent".to_owned()),
            agent_label: Nullable::null(),
            connection_id: ConnectionId::new(kr_ipc::new_uuid()),
            launch_channel: false,
            session_member: true,
            ancestry: true,
            agent_binding_revision: Nullable::null(),
        },
        created_at_ms: TimestampMs::new(now),
        expires_at_ms: TimestampMs::new(now + 60 * 60 * 1000),
        answer: Nullable::null(),
        resolved_at_ms: Nullable::null(),
    }
}

/// Serves the scripted worker's endpoint until the test ends.
async fn serve(
    listener: Listener,
    descriptor: WorkerDescriptor,
    identity: Arc<WorkerIdentity>,
    state: Arc<Mutex<State>>,
) {
    while let Ok((connection, peer)) = listener.accept().await {
        tokio::spawn(serve_one(
            connection,
            peer,
            descriptor.clone(),
            Arc::clone(&identity),
            Arc::clone(&state),
        ));
    }
}

async fn serve_one(
    connection: kr_ipc::endpoint::Connection,
    peer: kr_ipc::peer::PeerIdentity,
    descriptor: WorkerDescriptor,
    identity: Arc<WorkerIdentity>,
    state: Arc<Mutex<State>>,
) {
    let (mut reader, mut writer) = kr_ipc::framed::split(connection, StreamKind::Control);
    let Ok(ControlFrame::Hello(hello)) = reader.read_message::<ControlFrame>().await else {
        return;
    };
    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
    let acknowledgement = kr_protocol::local::LocalHelloAck {
        selected_version: PROTOCOL_VERSION,
        role: kr_protocol::local::LocalRole::Worker,
        connection_id,
        environment_id: descriptor.environment_id,
        boot_identity: descriptor.boot_identity.clone(),
        peer: kr_protocol::local::LocalPeer {
            uid: kr_protocol::scalars::U64::new(u64::from(peer.uid)),
            gid: kr_protocol::scalars::U64::new(u64::from(peer.gid)),
            pid: Nullable::null(),
        },
        action_window: kr_protocol::hello::ActionWindow {
            action_window_id: kr_protocol::ids::ActionWindowId::new("window-1")
                .expect("a window identifier"),
            connection_id,
            boot_epoch: kr_protocol::ids::BootEpoch::new(1),
            issued_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
            valid_for_ms: kr_protocol::scalars::DurationMs::new(60_000),
        },
        capabilities: CanonicalSet::new(),
        max_receive: hello.max_receive,
    };
    if writer
        .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
        .await
        .is_err()
    {
        return;
    }
    while let Ok(frame) = reader.read_message::<ControlFrame>().await {
        let (answer, then_end) = match frame {
            ControlFrame::VerifyChallenge(challenge) => {
                let proof = identity
                    .answer(&challenge, &descriptor.endpoint)
                    .expect("a proof");
                if writer
                    .write_message(&ControlFrame::VerifyProof(proof))
                    .await
                    .is_err()
                {
                    return;
                }
                continue;
            }
            ControlFrame::Request(request) => {
                let behaviour = state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .behaviour;
                let outcome = match request.method.as_str() {
                    "question.read" if behaviour == Behaviour::RefusesReads => {
                        Err(ProtocolError::new(
                            ErrorCode::PermissionDenied,
                            "this worker will not show its questions",
                        ))
                    }
                    "question.read" => read(&state, &request.params),
                    other => Err(refusal(&format!("this worker answers no {other}"))),
                };
                (
                    (request.request_id, outcome),
                    behaviour == Behaviour::EndsAfterTheRead,
                )
            }
            ControlFrame::Mutation(mutation) => {
                let behaviour = state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .behaviour;
                if mutation.method.as_str() == "question.answer" {
                    match behaviour {
                        Behaviour::TakesAnswersAndDropsTheReply => {
                            let _ = take(&state, &mutation.params);
                            return;
                        }
                        Behaviour::RepliesWithGarbage => {
                            state
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .answers_received += 1;
                            let _ = writer.write_frame(&garbage()).await;
                            continue;
                        }
                        _ => {}
                    }
                }
                let outcome = match mutation.method.as_str() {
                    "question.answer" if behaviour == Behaviour::CannotSayWhatBecameOfAnswers => {
                        state
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .answers_received += 1;
                        Err(ProtocolError::new(
                            ErrorCode::OutcomeUnknown,
                            "this worker cannot say what became of the answer",
                        ))
                    }
                    "question.answer"
                        if behaviour == Behaviour::TakesAnswersAndRepliesUnreadably =>
                    {
                        take(&state, &mutation.params).and_then(|_| {
                            ParamsValue::from_typed(&QuestionReadResult {
                                questions: Vec::new(),
                            })
                            .map_err(|error| refusal(&error.to_string()))
                        })
                    }
                    "question.answer" if behaviour == Behaviour::TakesAnswersAndLocksTheStore => {
                        let taken = take(&state, &mutation.params);
                        let store = state
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .store
                            .clone();
                        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o500))
                            .expect("the store is read-only");
                        taken
                    }
                    "question.answer" => take(&state, &mutation.params),
                    other => Err(refusal(&format!("this worker answers no {other}"))),
                };
                ((mutation.request_id, outcome), false)
            }
            _ => continue,
        };
        let (request_id, outcome) = answer;
        let response = ControlFrame::Response(Response {
            request_id,
            outcome: match outcome {
                Ok(value) => Outcome::Ok(value),
                Err(error) => Outcome::Error(error),
            },
        });
        if writer.write_message(&response).await.is_err() || then_end {
            return;
        }
    }
}

/// A whole frame whose payload is not a message.
fn garbage() -> Vec<u8> {
    let payload = [0xff_u8, 0x00, 0xff, 0x00];
    let mut frame = u32::try_from(payload.len())
        .expect("a short payload")
        .to_be_bytes()
        .to_vec();
    frame.extend_from_slice(&payload);
    frame
}

fn refusal(message: &str) -> ProtocolError {
    ProtocolError::new(ErrorCode::InvalidArgument, message)
}

/// Answers `question.read` from what the worker holds.
fn read(state: &Mutex<State>, params: &ParamsValue) -> Result<ParamsValue, ProtocolError> {
    let params: QuestionReadParams = params
        .to_typed()
        .map_err(|error| refusal(&error.to_string()))?;
    let state = state.lock().unwrap_or_else(PoisonError::into_inner);
    let question = &state.question;
    let named = params
        .question_id
        .as_ref()
        .is_none_or(|question_id| *question_id == question.question_id);
    let shown = named
        && params.session_id == question.session_id
        && (params.include_resolved || !question.state.is_resolved());
    let questions = if shown {
        vec![question.clone()]
    } else {
        Vec::new()
    };
    ParamsValue::from_typed(&QuestionReadResult { questions })
        .map_err(|error| refusal(&error.to_string()))
}

/// Answers `question.answer`: takes an answer to the pending question at the revision it names.
fn take(state: &Mutex<State>, params: &ParamsValue) -> Result<ParamsValue, ProtocolError> {
    let params: QuestionAnswerParams = params
        .to_typed()
        .map_err(|error| refusal(&error.to_string()))?;
    let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
    state.answers_received += 1;
    let question = &mut state.question;
    if question.state.is_resolved() {
        return Err(ProtocolError::new(
            ErrorCode::QuestionResolved,
            "the question is already resolved",
        ));
    }
    if params.question_id != question.question_id || params.expected_revision != question.revision {
        return Err(ProtocolError::new(
            ErrorCode::StaleSession,
            "the question is at another revision",
        ));
    }
    let now = TimestampMs::new(kr_ipc::now_ms().get());
    question.answer = Nullable::some(AnswerRecord {
        answer: params.answer,
        actor_id: ActorId::new("local:test").expect("an actor"),
        device_id: Nullable::null(),
        question_revision: question.revision,
        answered_at_ms: now,
    });
    question.state = QuestionState::Answered;
    question.revision = QuestionRevision::new(question.revision.get() + 1);
    question.resolved_at_ms = Nullable::some(now);
    ParamsValue::from_typed(&QuestionResolveResult {
        question: question.clone(),
    })
    .map_err(|error| refusal(&error.to_string()))
}

/// KR-REQ-11.63: an answer the worker could not take is kept on this device, the person is told,
/// and the worker is sent nothing. The control is a worker that takes it: sent, and nothing kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_the_worker_could_not_take_is_kept_and_nothing_is_sent() {
    let host = Host::start(Behaviour::EndsAfterTheRead).await;
    let question = host.question();
    let output = host.kr(&["question", "answer", &question, "--choice", "left"]);
    assert_eq!(output.status.code(), Some(3), "the answer did not go");
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("kept on this device"), "{said}");
    assert!(said.contains("kr question send"), "{said}");
    assert!(host.kept().is_file(), "the answer is kept");
    let (status, document) = host.json(&["question", "answer", &question, "--choice", "left"]);
    assert_eq!(status, Some(3), "{document}");
    assert_eq!(document["ok"], Value::Bool(false), "{document}");
    assert_eq!(document["kept"], Value::Bool(true), "{document}");
    assert_eq!(document["question_id"], Value::String(question.clone()));
    // The worker ended the connection after the read, which the command sees either before it
    // writes the answer or while it waits for the reply. Either way it keeps the answer, and it
    // says only what it knows.
    let message = document["message"].as_str().expect("a message");
    match document["code"].as_str() {
        Some("RESOURCE_UNAVAILABLE") => {
            assert!(
                message.contains("this command did not send it"),
                "{message}"
            );
        }
        Some("OUTCOME_UNKNOWN") => {
            assert!(message.contains("is not known"), "{message}");
            assert!(!message.contains("did not send"), "{message}");
        }
        other => panic!("a kept answer carries {other:?}: {document}"),
    }
    assert_eq!(host.answers_received(), 0, "nothing was sent");
    assert_eq!(host.state().question.state, QuestionState::Pending);

    // The control: a worker that takes it.
    let host = Host::start(Behaviour::Serves).await;
    let question = host.question();
    let (status, document) = host.json(&["question", "answer", &question, "--choice", "left"]);
    assert_eq!(status, Some(0), "{document}");
    assert_eq!(document["state"], "answered", "{document}");
    assert_eq!(host.answers_received(), 1);
    assert!(!host.kept().exists(), "an answer that went is not kept");
}

/// KR-REQ-11.63: a kept answer whose question is still pending at the revision it answered is
/// offered by `kr question drafts`, which sends nothing however often it runs; `kr question send`
/// is what sends it, once, and then it is no longer kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_answer_is_offered_by_drafts_and_sent_only_by_send() {
    let host = Host::start(Behaviour::EndsAfterTheRead).await;
    let question = host.question();
    let (status, _) = host.json(&["question", "answer", &question, "--choice", "left"]);
    assert_eq!(status, Some(3));
    host.state().behaviour = Behaviour::Serves;

    for run in ["first", "second"] {
        let (status, document) = host.json(&["question", "drafts"]);
        assert_eq!(status, Some(0), "{run}: {document}");
        let drafts = document["drafts"].as_array().expect("a list");
        assert_eq!(drafts.len(), 1, "{run}: {document}");
        assert_eq!(drafts[0]["question_id"], Value::String(question.clone()));
        assert_eq!(drafts[0]["state"], "offered", "{run}: {document}");
        assert_eq!(host.answers_received(), 0, "the {run} run sent nothing");
        assert!(host.kept().is_file(), "and the answer is still kept");
    }
    let shown = host.kr(&["question", "drafts"]);
    let shown = String::from_utf8_lossy(&shown.stdout);
    assert!(shown.contains("offered"), "{shown}");
    assert_eq!(host.answers_received(), 0);

    let (status, document) = host.json(&["question", "send", &question]);
    assert_eq!(status, Some(0), "{document}");
    assert_eq!(document["state"], "answered", "{document}");
    assert_eq!(host.answers_received(), 1, "sent once");
    assert!(!host.kept().exists(), "and no longer kept");
    let (status, document) = host.json(&["question", "drafts"]);
    assert_eq!(status, Some(0));
    assert_eq!(document["drafts"], Value::Array(Vec::new()), "{document}");
    assert_eq!(host.answers_received(), 1);
}

/// KR-REQ-11.63: a kept answer whose question moved while it was kept is retired unsent, says why,
/// and is no longer kept, so `kr question send` has nothing to send. The control, a question that
/// did not move, is offered in the test above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_answer_whose_question_moved_is_retired_unsent() {
    let host = Host::start(Behaviour::EndsAfterTheRead).await;
    let question = host.question();
    let (status, _) = host.json(&["question", "answer", &question, "--choice", "left"]);
    assert_eq!(status, Some(3));
    {
        let mut state = host.state();
        state.behaviour = Behaviour::Serves;
        state.question.revision = QuestionRevision::new(2);
    }

    let shown = host.kr(&["question", "drafts"]);
    assert_eq!(shown.status.code(), Some(0));
    let shown = String::from_utf8_lossy(&shown.stdout);
    assert!(shown.contains("retired"), "{shown}");
    assert!(shown.contains("moved to revision 2"), "{shown}");
    assert!(shown.contains("this command did not send it"), "{shown}");
    assert_eq!(host.answers_received(), 0, "nothing was sent");
    assert!(!host.kept().exists(), "a retired answer is no longer kept");

    let (status, document) = host.json(&["question", "drafts"]);
    assert_eq!(status, Some(0));
    assert_eq!(document["drafts"], Value::Array(Vec::new()), "{document}");
    let (status, document) = host.json(&["question", "send", &question]);
    assert_ne!(status, Some(0), "{document}");
    assert_eq!(host.answers_received(), 0, "and nothing sends it");
    assert_eq!(host.state().question.state, QuestionState::Pending);

    // `kr question send` meeting the moved question retires the answer too, and says it did not
    // send it.
    let host = kept_answer().await;
    let question = host.question();
    host.state().question.revision = QuestionRevision::new(2);
    let (status, document) = host.json(&["question", "send", &question]);
    assert_eq!(status, Some(8), "{document}");
    assert_eq!(document["code"], "STALE_SESSION", "{document}");
    let message = document["message"].as_str().expect("a message");
    assert!(message.contains("moved to revision 2"), "{message}");
    assert!(
        message.contains("this command did not send the kept answer"),
        "{message}"
    );
    assert!(!host.kept().exists(), "a retired answer is no longer kept");
    assert_eq!(host.answers_received(), 0, "nothing was sent");
}

/// KR-REQ-11.63: an answer the worker took and whose reply was lost is kept as an answer whose
/// outcome is not known, and is never called unsent. The next `kr question drafts` finds the
/// question answered and retires it, so it is never sent twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_whose_reply_was_lost_is_kept_as_unknown_and_never_sent_twice() {
    let host = Host::start(Behaviour::TakesAnswersAndDropsTheReply).await;
    let question = host.question();
    let (status, document) = host.json(&["question", "answer", &question, "--choice", "left"]);
    assert_eq!(status, Some(3), "{document}");
    assert_eq!(document["code"], "OUTCOME_UNKNOWN", "{document}");
    assert_eq!(document["kept"], Value::Bool(true), "{document}");
    let message = document["message"].as_str().expect("a message");
    assert!(message.contains("is not known"), "{message}");
    assert!(!message.contains("did not send"), "{message}");
    assert!(host.kept().is_file());
    assert_eq!(host.answers_received(), 1, "the worker took it");

    host.behave(Behaviour::Serves);
    let (status, document) = host.json(&["question", "drafts"]);
    assert_eq!(status, Some(0), "{document}");
    assert_eq!(document["drafts"][0]["state"], "retired", "{document}");
    assert_eq!(document["drafts"][0]["reason_code"], "QUESTION_RESOLVED");
    assert!(!host.kept().exists(), "a retired answer is no longer kept");
    assert_eq!(host.answers_received(), 1, "and it was not sent again");

    // Retired by `kr question drafts` for a person, or by `kr question send`, an answer that may
    // well have arrived is never called unsent: what is said is that this command did not send it.
    for sends in [false, true] {
        let host = Host::start(Behaviour::TakesAnswersAndDropsTheReply).await;
        let question = host.question();
        let (status, _) = host.json(&["question", "answer", &question, "--choice", "left"]);
        assert_eq!(status, Some(3));
        host.behave(Behaviour::Serves);
        let line = if sends {
            vec!["question", "send", question.as_str()]
        } else {
            vec!["question", "drafts"]
        };
        let output = host.kr(&line);
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(said.contains("was answered"), "{line:?}: {said}");
        assert!(
            said.contains("this command did not send"),
            "{line:?}: {said}"
        );
        assert!(!said.contains("was not sent"), "{line:?}: {said}");
        assert!(
            !host.kept().exists(),
            "{line:?}: a retired answer is no longer kept"
        );
        assert_eq!(
            host.answers_received(),
            1,
            "{line:?}: and it was not sent again"
        );
    }
}

/// KR-REQ-11.63: a descriptor that cannot be read, or is not the owner's alone, says nothing about
/// the session, so `kr question drafts` fails and retires nothing. The control: the same
/// descriptor put right is offered again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_descriptor_that_cannot_be_read_retires_nothing() {
    let host = Host::start(Behaviour::EndsAfterTheRead).await;
    let question = host.question();
    let (status, _) = host.json(&["question", "answer", &question, "--choice", "left"]);
    assert_eq!(status, Some(3));
    host.behave(Behaviour::Serves);
    let published = std::fs::read(&host.descriptor).expect("the descriptor");

    // Not a descriptor at all.
    std::fs::write(&host.descriptor, b"not a descriptor").expect("overwritten");
    let (status, document) = host.json(&["question", "drafts"]);
    assert_ne!(status, Some(0), "{document}");
    assert!(
        host.kept().is_file(),
        "an unreadable descriptor retires nothing"
    );

    // A descriptor, readable by others.
    std::fs::write(&host.descriptor, &published).expect("put back");
    std::fs::set_permissions(&host.descriptor, std::fs::Permissions::from_mode(0o644))
        .expect("widened");
    let (status, document) = host.json(&["question", "drafts"]);
    assert_ne!(status, Some(0), "{document}");
    assert!(
        host.kept().is_file(),
        "an untrusted descriptor retires nothing"
    );

    // Put right, it is offered again.
    std::fs::set_permissions(&host.descriptor, std::fs::Permissions::from_mode(0o600))
        .expect("narrowed");
    let (status, document) = host.json(&["question", "drafts"]);
    assert_eq!(status, Some(0), "{document}");
    assert_eq!(document["drafts"][0]["state"], "offered", "{document}");
    assert_eq!(host.answers_received(), 0, "nothing was ever sent");
}

/// A fresh scripted session whose worker could not take an answer, which is kept, and which then
/// serves again.
async fn kept_answer() -> Host {
    let host = Host::start(Behaviour::EndsAfterTheRead).await;
    let (status, document) =
        host.json(&["question", "answer", &host.question(), "--choice", "left"]);
    assert_eq!(status, Some(3), "{document}");
    assert!(host.kept().is_file(), "the answer is kept");
    host.behave(Behaviour::Serves);
    host
}

/// KR-REQ-11.63: a session is gone only when its environment's daemon says so. With its descriptor
/// missing, a kept answer is retired unsent when the daemon's registry records the session closed
/// or never held it, and nothing is retired while there is no daemon to ask or the daemon reports
/// the session live, even though its worker cannot be found.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_missing_descriptor_retires_a_kept_answer_only_on_the_daemons_word() {
    for (registry, retired) in [
        (None, false),
        (Some(Registry::Live), false),
        (Some(Registry::NeverHeld), true),
        (Some(Registry::Closed), true),
    ] {
        let host = kept_answer().await;
        std::fs::remove_file(&host.descriptor).expect("the descriptor goes");
        let daemon = registry.map(|registry| host.daemon(registry));
        let (status, document) = host.json(&["question", "drafts"]);
        if retired {
            assert_eq!(status, Some(0), "{registry:?}: {document}");
            assert_eq!(
                document["drafts"][0]["state"], "retired",
                "{registry:?}: {document}"
            );
            assert_eq!(
                document["drafts"][0]["reason_code"], "UNKNOWN_SESSION",
                "{registry:?}: {document}"
            );
            assert!(
                !host.kept().exists(),
                "{registry:?}: a retired answer is not kept"
            );
        } else {
            assert_ne!(status, Some(0), "{registry:?}: {document}");
            let message = document["message"].as_str().expect("a message");
            assert!(message.contains("published no descriptor"), "{message}");
            if registry == Some(Registry::Live) {
                assert!(message.contains("reports it live"), "{message}");
            }
            assert!(host.kept().is_file(), "{registry:?}: nothing is retired");
        }
        assert_eq!(host.answers_received(), 0, "{registry:?}: nothing was sent");
        if let Some(daemon) = daemon {
            daemon.abort();
        }
    }
}

/// KR-REQ-11.63: a worker that cannot be reached retires its kept answer only on a closure its
/// daemon keeps. Its descriptor left behind says nothing either way, so with no daemon to ask, a
/// daemon that reports the session live, or one with no record of it, nothing is retired, and
/// `kr question drafts` names the worker it could not reach and what its daemon said.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_worker_retires_a_kept_answer_only_on_a_recorded_closure() {
    for (registry, retired) in [
        (None, false),
        (Some(Registry::Live), false),
        (Some(Registry::NeverHeld), false),
        (Some(Registry::Closed), true),
    ] {
        let mut host = kept_answer().await;
        host.stop_worker().await;
        assert!(host.descriptor.is_file(), "the descriptor is left behind");
        let daemon = registry.map(|registry| host.daemon(registry));
        let (status, document) = host.json(&["question", "drafts"]);
        if retired {
            assert_eq!(status, Some(0), "{registry:?}: {document}");
            assert_eq!(
                document["drafts"][0]["state"], "retired",
                "{registry:?}: {document}"
            );
            assert_eq!(
                document["drafts"][0]["reason_code"], "UNKNOWN_SESSION",
                "{registry:?}: {document}"
            );
            assert!(
                !host.kept().exists(),
                "{registry:?}: a retired answer is not kept"
            );
        } else {
            assert_eq!(status, Some(3), "{registry:?}: {document}");
            let message = document["message"].as_str().expect("a message");
            assert!(message.contains("worker could not be reached"), "{message}");
            assert!(message.contains("no kept answer was retired"), "{message}");
            match registry {
                Some(Registry::Live) => assert!(message.contains("reports it live"), "{message}"),
                Some(Registry::NeverHeld) => {
                    assert!(message.contains("has no record of it"), "{message}");
                }
                _ => assert!(message.contains("cannot be established"), "{message}"),
            }
            assert!(host.kept().is_file(), "{registry:?}: nothing is retired");
        }
        assert_eq!(host.answers_received(), 0, "{registry:?}: nothing was sent");
        if let Some(daemon) = daemon {
            daemon.abort();
        }
    }
}

/// KR-REQ-11.63: a descriptor directory that cannot be trusted says nothing about whether a
/// session published a descriptor, so while it cannot be read nothing is retired, even by a daemon
/// with no record of the session. The control: the same directory put right, with no descriptor in
/// it, proves the descriptor absent, and that daemon's word retires the answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_descriptor_directory_that_cannot_be_trusted_retires_nothing() {
    let host = kept_answer().await;
    let daemon = host.daemon(Registry::NeverHeld);
    let directory = host.environment.descriptors_dir();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).expect("widened");
    for published in [true, false] {
        if !published {
            std::fs::remove_file(&host.descriptor).expect("the descriptor goes");
        }
        let (status, document) = host.json(&["question", "drafts"]);
        assert_ne!(status, Some(0), "published {published}: {document}");
        let message = document["message"].as_str().expect("a message");
        assert!(
            message.contains("has published a descriptor cannot be read"),
            "{message}"
        );
        assert!(
            host.kept().is_file(),
            "published {published}: nothing is retired"
        );
    }

    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).expect("narrowed");
    let (status, document) = host.json(&["question", "drafts"]);
    assert_eq!(status, Some(0), "{document}");
    assert_eq!(document["drafts"][0]["state"], "retired", "{document}");
    assert_eq!(document["drafts"][0]["reason_code"], "UNKNOWN_SESSION");
    assert!(!host.kept().exists(), "a retired answer is not kept");
    assert_eq!(host.answers_received(), 0, "and it was never sent");
    daemon.abort();
}

/// KR-REQ-11.63: a kept answer's session is looked for, and asked after, only in the environment
/// it ran in. A session in a second environment is found and offered there; while that environment
/// cannot be identified nothing is retired; with its descriptor gone, this installation's own
/// daemon recording a closure retires nothing, and the session's own environment's daemon does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_answer_is_asked_after_only_in_its_own_environment() {
    let host = Host::start_in(Behaviour::EndsAfterTheRead, Place::SecondEnvironment).await;
    assert_ne!(
        host.environment.environment_id(),
        host.temp.environment_id(),
        "the session is not in this installation's own environment"
    );
    let question = host.question();
    let (status, document) = host.json(&["question", "answer", &question, "--choice", "left"]);
    assert_eq!(status, Some(3), "{document}");
    host.behave(Behaviour::Serves);
    let (status, document) = host.json(&["question", "drafts"]);
    assert_eq!(status, Some(0), "{document}");
    assert_eq!(document["drafts"][0]["state"], "offered", "{document}");

    // Its environment's identity cannot be read.
    let marker = host
        .environment
        .state_dir()
        .join(kr_ipc::paths::ENVIRONMENT_MARKER);
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o644)).expect("widened");
    let (status, document) = host.json(&["question", "drafts"]);
    assert_ne!(status, Some(0), "{document}");
    let message = document["message"].as_str().expect("a message");
    assert!(message.contains("cannot be looked for"), "{message}");
    assert!(host.kept().is_file(), "nothing is retired");
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).expect("narrowed");

    // Its descriptor gone, another environment's daemon is not asked.
    std::fs::remove_file(&host.descriptor).expect("the descriptor goes");
    let installation = host.daemon_in(&host.temp.environment(), Registry::Closed);
    let (status, document) = host.json(&["question", "drafts"]);
    assert_ne!(status, Some(0), "{document}");
    assert!(
        host.kept().is_file(),
        "another environment's daemon retires nothing"
    );
    installation.abort();

    // Its own environment's daemon is.
    let own = host.daemon(Registry::Closed);
    let (status, document) = host.json(&["question", "drafts"]);
    assert_eq!(status, Some(0), "{document}");
    assert_eq!(document["drafts"][0]["state"], "retired", "{document}");
    assert_eq!(document["drafts"][0]["reason_code"], "UNKNOWN_SESSION");
    assert!(!host.kept().exists(), "a retired answer is not kept");
    assert_eq!(host.answers_received(), 0, "and it was never sent");
    own.abort();
}

/// KR-REQ-11.63: a worker that cannot say what became of an answer leaves its fate unknown, so the
/// answer is kept and never called unsent or refused, whether it was answered or sent from what
/// was kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_a_worker_cannot_account_for_is_kept_as_unknown() {
    let host = Host::start(Behaviour::CannotSayWhatBecameOfAnswers).await;
    let question = host.question();
    for line in [
        vec!["question", "answer", question.as_str(), "--choice", "left"],
        vec!["question", "send", question.as_str()],
    ] {
        let (status, document) = host.json(&line);
        assert_ne!(status, Some(0), "{line:?}: {document}");
        assert_eq!(document["code"], "OUTCOME_UNKNOWN", "{line:?}: {document}");
        let message = document["message"].as_str().expect("a message");
        assert!(message.contains("is not known"), "{message}");
        assert!(!message.contains("did not send"), "{message}");
        assert!(!message.contains("did not take"), "{message}");
        assert!(host.kept().is_file(), "{line:?}: the answer is kept");
    }
}

/// KR-REQ-11.63: a kept answer sent to a worker whose reply cannot be read is still kept, under the
/// reply's own code, and is not called unsent, because the answer went out before the reply came
/// back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_answer_whose_reply_cannot_be_read_is_still_kept_as_unknown() {
    let host = Host::start(Behaviour::EndsAfterTheRead).await;
    let question = host.question();
    let (status, _) = host.json(&["question", "answer", &question, "--choice", "left"]);
    assert_eq!(status, Some(3));
    host.behave(Behaviour::RepliesWithGarbage);
    let (status, document) = host.json(&["question", "send", &question]);
    assert_eq!(status, Some(3), "{document}");
    assert_eq!(document["code"], "INVALID_ARGUMENT", "{document}");
    let message = document["message"].as_str().expect("a message");
    assert!(message.contains("is not known"), "{message}");
    assert!(!message.contains("did not send"), "{message}");
    assert!(host.kept().is_file(), "the answer is still kept");
    assert_eq!(host.answers_received(), 1);
}

/// KR-REQ-11.63: a worker that took an answer took it, even when its reply cannot be read, so the
/// answer is never called unsent and is not kept to be sent again. `kr question answer` says the
/// worker took it and keeps nothing; `kr question send` says so of a kept answer, and the next
/// `kr question drafts` finds the question answered and retires the copy without sending it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_a_worker_took_is_never_called_unsent_when_its_reply_cannot_be_read() {
    let host = Host::start(Behaviour::TakesAnswersAndRepliesUnreadably).await;
    let question = host.question();
    let (status, document) = host.json(&["question", "answer", &question, "--choice", "left"]);
    assert_eq!(status, Some(1), "{document}");
    assert_eq!(document["code"], "INVALID_ARGUMENT", "{document}");
    let message = document["message"].as_str().expect("a message");
    assert!(message.contains("worker took the answer"), "{message}");
    assert!(message.contains("nothing is kept"), "{message}");
    assert!(!message.contains("did not send"), "{message}");
    assert!(!message.contains("not known"), "{message}");
    assert!(
        !host.kept().exists(),
        "an answer the worker took is not kept"
    );
    assert_eq!(host.answers_received(), 1);

    let host = kept_answer().await;
    let question = host.question();
    host.behave(Behaviour::TakesAnswersAndRepliesUnreadably);
    let (status, document) = host.json(&["question", "send", &question]);
    assert_eq!(status, Some(1), "{document}");
    assert_eq!(document["code"], "INVALID_ARGUMENT", "{document}");
    assert!(document.get("kept").is_none(), "{document}");
    let message = document["message"].as_str().expect("a message");
    assert!(message.contains("worker took the answer"), "{message}");
    assert!(message.contains("still kept"), "{message}");
    assert!(!message.contains("did not send"), "{message}");
    assert_eq!(host.answers_received(), 1, "the worker took it");

    host.behave(Behaviour::Serves);
    let (status, document) = host.json(&["question", "drafts"]);
    assert_eq!(status, Some(0), "{document}");
    assert_eq!(document["drafts"][0]["state"], "retired", "{document}");
    assert_eq!(document["drafts"][0]["reason_code"], "QUESTION_RESOLVED");
    assert!(!host.kept().exists(), "the copy is retired");
    assert_eq!(host.answers_received(), 1, "and it was not sent again");
}

/// KR-REQ-11.63: an answer `kr question send` sent and its worker took is never called unsent, even
/// when the copy kept on this device cannot be removed afterwards. The command says the worker took
/// it and that the copy is still kept, and the next `kr question drafts` retires the copy without
/// sending it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sent_answer_whose_kept_copy_cannot_be_removed_is_never_called_unsent() {
    let host = kept_answer().await;
    let question = host.question();
    host.behave(Behaviour::TakesAnswersAndLocksTheStore);
    let (status, document) = host.json(&["question", "send", &question]);
    host.unlock_store();
    assert_eq!(status, Some(1), "{document}");
    assert_eq!(document["code"], "STORAGE_UNAVAILABLE", "{document}");
    let message = document["message"].as_str().expect("a message");
    assert!(message.contains("worker took the answer"), "{message}");
    assert!(message.contains("still kept"), "{message}");
    assert!(!message.contains("did not send"), "{message}");
    assert!(host.kept().is_file(), "the copy could not be removed");
    assert_eq!(host.answers_received(), 1, "the worker took it");

    host.behave(Behaviour::Serves);
    let (status, document) = host.json(&["question", "drafts"]);
    assert_eq!(status, Some(0), "{document}");
    assert_eq!(document["drafts"][0]["state"], "retired", "{document}");
    assert_eq!(document["drafts"][0]["reason_code"], "QUESTION_RESOLVED");
    assert!(!host.kept().exists(), "the copy is retired");
    assert_eq!(host.answers_received(), 1, "and it was not sent again");
}

/// KR-REQ-11.63: a worker that refuses the read `kr question send` makes first is reported with its
/// own code, and the answer is still kept, which the refusal says; `kr question drafts` retires
/// nothing either. The control is the same worker serving again, which takes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_read_keeps_its_code_and_the_answer() {
    let host = Host::start(Behaviour::EndsAfterTheRead).await;
    let question = host.question();
    let (status, _) = host.json(&["question", "answer", &question, "--choice", "left"]);
    assert_eq!(status, Some(3));

    host.behave(Behaviour::RefusesReads);
    let (status, document) = host.json(&["question", "send", &question]);
    assert_eq!(status, Some(8), "{document}");
    assert_eq!(document["code"], "PERMISSION_DENIED", "{document}");
    let message = document["message"].as_str().expect("a message");
    assert!(message.contains("still kept"), "{message}");
    assert!(
        message.contains("this command did not send it"),
        "{message}"
    );
    assert!(host.kept().is_file());
    let (status, document) = host.json(&["question", "drafts"]);
    assert_eq!(status, Some(8), "{document}");
    assert_eq!(document["code"], "PERMISSION_DENIED", "{document}");
    assert!(host.kept().is_file(), "and drafts retires nothing");
    assert_eq!(host.answers_received(), 0);

    host.behave(Behaviour::Serves);
    let (status, document) = host.json(&["question", "send", &question]);
    assert_eq!(status, Some(0), "{document}");
    assert_eq!(host.answers_received(), 1);
}

/// KR-REQ-11.63: a reply that is not a message is the worker's own answer, not a lost connection,
/// so the answer is shown as refused and not kept, as the drafts library rules.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_malformed_reply_is_shown_and_not_kept() {
    let host = Host::start(Behaviour::RepliesWithGarbage).await;
    let question = host.question();
    let (status, document) = host.json(&["question", "answer", &question, "--choice", "left"]);
    assert_eq!(status, Some(8), "{document}");
    assert_eq!(document["ok"], Value::Bool(false), "{document}");
    assert!(document.get("kept").is_none(), "{document}");
    assert_eq!(document["code"], "INVALID_ARGUMENT", "{document}");
    assert!(!host.kept().exists(), "a malformed reply keeps nothing");
    assert_eq!(host.answers_received(), 1);
}
