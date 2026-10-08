//! Section 23 and section 10 at the worker: what a caller is shown of an action's retained result
//! is decided for the caller as it is when it reads, and what the worker keeps does not change.
//!
//! Every test drives a real worker service over its real endpoint, with a control daemon that
//! proved its generation and forwards a paired device's mutations and reads as the daemon does:
//! the device's envelope, the rights its grant carried and the history scope of that grant. The
//! question is asked by an application bound to the session, as an agent asks.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-10.49 | the `kr_req_10_49_` tests here |
//! | KR-REQ-10.51 | the `kr_req_10_51_` tests here |
//! | KR-REQ-23.34 | the `kr_req_23_34_` tests here |

#![cfg(unix)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::envelope::{
    ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue, Request,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::HistoryScope;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, BuildId, ConnectionId, ControllerGeneration, DeviceId,
    GrantId, QuestionId, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::local::{ForwardedMutation, ForwardedRequest, LocalClientKind};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::question::{
    Question, QuestionAnswer, QuestionAnswerParams, QuestionCancelParams, QuestionCreateParams,
    QuestionKind, QuestionResolveResult, QuestionState,
};
use kr_protocol::receipt::{ActionReadParams, ActionReadResult, ReceiptResponse, ReceiptState};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::journal::Journal;
use kr_worker::questions::Now;
use kr_worker::questions::binding::VerifiedSource;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session as TerminalSession, SessionConfig};

mod common;

use common::LIVENESS_DEADLINE;

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn within<T>(what: &str, work: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIVENESS_DEADLINE, work)
        .await
        .unwrap_or_else(|_| panic!("{what} within {LIVENESS_DEADLINE:?}"))
}

fn next_request() -> RequestId {
    static NEXT: AtomicU64 = AtomicU64::new(2_000_000);
    RequestId::new(NEXT.fetch_add(1, Ordering::Relaxed))
}

// ---------------------------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------------------------

struct Host {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    journal_path: std::path::PathBuf,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
}

impl Host {
    fn target(&self) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::some(self.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }
}

async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let current = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            current,
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
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script("exec cat"),
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
    };
    let journal_path = config.journal_path.clone().expect("the harness journals");
    if let Some(parent) = journal_path.parent() {
        std::fs::create_dir_all(parent).expect("the journal directory");
    }
    let mut session = TerminalSession::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
            .expect("starts the runtime"),
    );
    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(
        WorkerService::new(
            runtime,
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
        environment_id,
        journal_path,
        endpoint,
        controller,
        boot,
    }
}

/// A control daemon of generation 1, which the worker accepts.
async fn daemon(host: &Host) -> LocalClient {
    let mut daemon = within(
        "the daemon's connection",
        LocalClient::connect(&host.endpoint, LocalClientKind::Controller, build()),
    )
    .await
    .expect("connects as the daemon");
    let identity = Arc::clone(&host.controller);
    let boot = host.boot.clone();
    within(
        "the worker's answer to the generation",
        daemon.present_generation(move |nonce| {
            identity
                .generation_token(ControllerGeneration::new(1), &boot, nonce)
                .map_err(kr_ipc::IpcError::from)
        }),
    )
    .await
    .expect("the worker accepts the generation");
    daemon
}

/// The local owner, on the worker's own socket.
async fn owner(host: &Host) -> LocalClient {
    within(
        "a local connection",
        LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build()),
    )
    .await
    .expect("connects")
}

/// A paired device, as the control daemon vouches for it.
fn device(name: &str) -> ActorEnvelope {
    ActorEnvelope {
        actor_id: ActorId::new(format!("device:{name}")).expect("a principal"),
        ingress: ActorIngress::PairedDevice,
        device_id: Nullable::some(DeviceId::new(Uuid::from_bytes([9; 16]))),
        grant_id: Nullable::some(GrantId::new(Uuid::from_bytes([8; 16]))),
        grant_revision: Nullable::null(),
        controller_generation: ControllerGeneration::new(1),
        connection_id: ConnectionId::new(Uuid::from_bytes([7; 16])),
    }
}

/// What a device's grant carries: the rights it was decided with, and its history scope.
#[derive(Clone)]
struct Grant {
    rights: Vec<ActionRight>,
    history: Option<HistoryScope>,
}

fn scope(bound: Option<u64>, named: &[QuestionId]) -> HistoryScope {
    HistoryScope {
        lower_bound_ms: Nullable(bound.map(TimestampMs::new)),
        include_live_screen: false,
        named_questions: named.iter().copied().collect(),
        named_approvals: CanonicalSet::new(),
    }
}

/// A grant that may view and answer, whose history reaches back to `bound`.
fn reaching(bound: u64) -> Grant {
    Grant {
        rights: vec![ActionRight::SessionView, ActionRight::QuestionRespond],
        history: Some(scope(Some(bound), &[])),
    }
}

async fn exchange(
    daemon: &mut LocalClient,
    frame: ControlFrame,
    request_id: RequestId,
) -> Result<ParamsValue, ProtocolError> {
    within("the worker's answer", async {
        daemon
            .writer()
            .write_message(&frame)
            .await
            .expect("writes the frame");
        loop {
            match daemon.recv().await.expect("the worker answers") {
                ControlFrame::Response(response) if response.request_id == request_id => {
                    return match response.outcome {
                        Outcome::Ok(value) => Ok(value),
                        Outcome::Error(error) => Err(error),
                    };
                }
                ControlFrame::Receipt(receipt) if receipt.request_id == request_id => {
                    return Ok(ParamsValue::from_typed(&*receipt).expect("encodes"));
                }
                _ => {}
            }
        }
    })
    .await
}

/// The mutation a device sends, and the frame the daemon forwards it in.
fn mutation_of<T: serde::Serialize>(
    host: &Host,
    action_id: ActionId,
    method: Method,
    params: &T,
) -> MutationRequest {
    MutationRequest {
        request_id: next_request(),
        method: method.into(),
        method_version: MethodVersion::V1,
        action_id,
        grant_id: Nullable::null(),
        target: host.target(),
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("forwarded").expect("a window identifier"),
        requested_ttl_ms: kr_protocol::limits::DEFAULT_MUTATION_TTL,
        params: ParamsValue::from_typed(params).expect("encodes"),
    }
}

async fn forward<T: serde::Serialize>(
    daemon: &mut LocalClient,
    host: &Host,
    actor: &ActorEnvelope,
    grant: &Grant,
    action_id: ActionId,
    method: Method,
    params: &T,
) -> Result<ParamsValue, ProtocolError> {
    let mutation = mutation_of(host, action_id, method, params);
    let request_id = mutation.request_id;
    let frame = ControlFrame::Forwarded(Box::new(ForwardedMutation {
        mutation,
        actor: actor.clone(),
        grant_rights: grant.rights.iter().copied().collect(),
        accepted_deadline_boot_ms: U64::new(kr_ipc::clock::boot_elapsed_ms() + 120_000),
        history: grant.history.clone(),
        screen_basis: None,
    }));
    exchange(daemon, frame, request_id).await
}

/// A read the daemon forwards for a device, holding it to the history scope of its grant.
async fn forward_read<T: serde::Serialize>(
    daemon: &mut LocalClient,
    actor: &ActorEnvelope,
    grant: &Grant,
    method: Method,
    params: &T,
) -> Result<ParamsValue, ProtocolError> {
    let request_id = next_request();
    let frame = ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
        request: Request {
            request_id,
            method: method.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(params).expect("encodes"),
        },
        actor: actor.clone(),
        authority_deadline_boot_ms: Nullable::null(),
        history: grant.history.clone(),
    }));
    exchange(daemon, frame, request_id).await
}

fn asker() -> VerifiedSource {
    VerifiedSource {
        process: kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        executable: Some("kr-test-agent".to_owned()),
        session_member: true,
        ancestry: true,
        launch_channel: true,
        connection_id: ConnectionId::new(Uuid::from_bytes([3; 16])),
    }
}

fn now() -> Now {
    Now {
        utc_ms: kr_ipc::now_ms(),
        boot_ms: kr_ipc::clock::boot_elapsed_ms(),
    }
}

/// The agent asks, and the question is pending in the worker's ledger.
fn ask(host: &Host, request: &str) -> Question {
    let (asked, _) = host
        .service
        .questions()
        .create(
            &asker(),
            &QuestionCreateParams {
                session_id: host.session_id,
                request_id: request.to_owned(),
                kind: QuestionKind::Confirm,
                context: "Two tests are failing.".to_owned(),
                question: "Push the branch anyway?".to_owned(),
                choices: Vec::new(),
                agent_name: Nullable::some("kr-test-agent".to_owned()),
                requested_expiry_ms: Nullable::some(DurationMs::new(600_000)),
                wait_ms: Nullable::null(),
            },
            now(),
        )
        .expect("the agent asks");
    asked.question
}

fn yes(host: &Host, question: &Question) -> QuestionAnswerParams {
    QuestionAnswerParams {
        session_id: host.session_id,
        question_id: question.question_id,
        expected_revision: question.revision,
        answer: QuestionAnswer::Decision { decided: true },
    }
}

fn action() -> ActionId {
    ActionId::new(kr_ipc::new_uuid())
}

/// What the worker's ledger holds of a question, whatever any caller was shown.
fn held(host: &Host, question_id: QuestionId) -> Question {
    host.service
        .questions()
        .question(question_id)
        .expect("the question is in the ledger")
}

/// The bytes the journal keeps as an action's result.
fn kept(host: &Host, actor: &ActorId, action_id: ActionId) -> Option<Vec<u8>> {
    Journal::open_read_only(&host.journal_path)
        .expect("the journal opens")
        .read_result(actor, action_id)
        .expect("the result reads")
}

fn resolved(value: ParamsValue) -> QuestionResolveResult {
    value.to_typed().expect("a resolution result")
}

fn words(value: &impl serde::Serialize) -> String {
    serde_json::to_string(value).expect("encodes")
}

const CONTENT: [&str; 3] = [
    "Push the branch anyway?",
    "Two tests are failing.",
    "kr-test-agent",
];

fn shows_none_of_the_question(value: &impl serde::Serialize) {
    let text = words(value);
    for content in CONTENT {
        assert!(!text.contains(content), "{content:?} in {text}");
    }
}

// ---------------------------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------------------------

/// KR-REQ-10.49: a device that holds `question.respond` answers a question its history reaches,
/// and a question asked before its history's bound, and not named by its grant, is refused as one
/// the session does not hold: the question stays pending, and the refusal says nothing of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_49_a_device_answers_only_a_question_its_history_reaches() {
    let host = host().await;
    let mut daemon = daemon(&host).await;
    let phone = device("phone");
    let asked = ask(&host, "before-the-bound");

    // A bound after the question was asked: it is outside the grant's history.
    let late = reaching(asked.created_at_ms.get() + 1);
    let refused = forward(
        &mut daemon,
        &host,
        &phone,
        &late,
        action(),
        Method::QuestionAnswer,
        &yes(&host, &asked),
    )
    .await
    .expect_err("a question before the bound is not the device's to answer");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused}");
    shows_none_of_the_question(&refused);
    assert!(
        !refused.message.contains("pending") && !refused.message.contains("revision"),
        "{refused}"
    );
    assert_eq!(held(&host, asked.question_id).state, QuestionState::Pending);

    // It is the refusal an unknown question gets.
    let unknown = QuestionAnswerParams {
        question_id: QuestionId::new(Uuid::from_bytes([77; 16])),
        ..yes(&host, &asked)
    };
    let nothing = forward(
        &mut daemon,
        &host,
        &phone,
        &late,
        action(),
        Method::QuestionAnswer,
        &unknown,
    )
    .await
    .expect_err("no such question");
    assert_eq!(nothing.code, refused.code);

    // The same question, for a grant whose history reaches it.
    let reaches = reaching(asked.created_at_ms.get());
    let answered = resolved(
        forward(
            &mut daemon,
            &host,
            &phone,
            &reaches,
            action(),
            Method::QuestionAnswer,
            &yes(&host, &asked),
        )
        .await
        .expect("the question is answered"),
    );
    assert_eq!(answered.state, QuestionState::Answered);
    assert_eq!(
        held(&host, asked.question_id).state,
        QuestionState::Answered
    );
}

/// KR-REQ-10.49: a cancellation is admitted the way an answer is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_49_a_device_cancels_only_a_question_its_history_reaches() {
    let host = host().await;
    let mut daemon = daemon(&host).await;
    let phone = device("phone");
    let asked = ask(&host, "to-cancel");
    let cancel = QuestionCancelParams {
        session_id: host.session_id,
        question_id: asked.question_id,
        expected_revision: asked.revision,
    };

    let refused = forward(
        &mut daemon,
        &host,
        &phone,
        &reaching(asked.created_at_ms.get() + 1),
        action(),
        Method::QuestionCancel,
        &cancel,
    )
    .await
    .expect_err("a question before the bound is not the device's to cancel");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused}");
    assert_eq!(held(&host, asked.question_id).state, QuestionState::Pending);

    let cancelled = resolved(
        forward(
            &mut daemon,
            &host,
            &phone,
            &reaching(asked.created_at_ms.get()),
            action(),
            Method::QuestionCancel,
            &cancel,
        )
        .await
        .expect("cancelled"),
    );
    assert_eq!(cancelled.state, QuestionState::Cancelled);
}

/// KR-REQ-10.51: a grant that names a question reaches it while it is open, whatever its bound, and
/// a grant that names another does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_grant_that_names_a_pending_question_may_answer_it_and_one_that_names_another_may_not()
 {
    let host = host().await;
    let mut daemon = daemon(&host).await;
    let phone = device("phone");
    let asked = ask(&host, "named");
    let after = asked.created_at_ms.get() + 10_000;

    let names_another = Grant {
        rights: vec![ActionRight::SessionView, ActionRight::QuestionRespond],
        history: Some(scope(
            Some(after),
            &[QuestionId::new(Uuid::from_bytes([66; 16]))],
        )),
    };
    forward(
        &mut daemon,
        &host,
        &phone,
        &names_another,
        action(),
        Method::QuestionAnswer,
        &yes(&host, &asked),
    )
    .await
    .expect_err("a question the grant does not name, from before its bound");

    let names_it = Grant {
        rights: vec![ActionRight::SessionView, ActionRight::QuestionRespond],
        history: Some(scope(Some(after), &[asked.question_id])),
    };
    let answered = resolved(
        forward(
            &mut daemon,
            &host,
            &phone,
            &names_it,
            action(),
            Method::QuestionAnswer,
            &yes(&host, &asked),
        )
        .await
        .expect("a named, pending question is the grant's to answer"),
    );
    assert_eq!(answered.state, QuestionState::Answered);
}

/// KR-REQ-10.49: a grant with no retained history, and one with no scope at all, answer nothing a
/// grant must reach; only the local owner answers whatever it likes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_49_a_grant_with_no_history_and_a_caller_with_no_scope_answer_nothing_but_what_they_name()
 {
    let host = host().await;
    let mut daemon = daemon(&host).await;
    let phone = device("phone");
    let asked = ask(&host, "no-history");

    let no_history = Grant {
        rights: vec![ActionRight::SessionView, ActionRight::QuestionRespond],
        history: Some(scope(None, &[])),
    };
    // The live screen is not a retained history: a grant that adds it has no bound all the same.
    let no_history_and_the_live_screen = Grant {
        rights: vec![ActionRight::SessionView, ActionRight::QuestionRespond],
        history: Some(HistoryScope {
            include_live_screen: true,
            ..scope(None, &[])
        }),
    };
    let unscoped = Grant {
        rights: vec![ActionRight::SessionView, ActionRight::QuestionRespond],
        history: None,
    };
    for grant in [&no_history, &no_history_and_the_live_screen, &unscoped] {
        forward(
            &mut daemon,
            &host,
            &phone,
            grant,
            action(),
            Method::QuestionAnswer,
            &yes(&host, &asked),
        )
        .await
        .expect_err("nothing reaches it");
    }
    assert_eq!(held(&host, asked.question_id).state, QuestionState::Pending);

    // The local owner, on the worker's own socket, answers it.
    let mut local = owner(&host).await;
    let value = within(
        "the owner's answer",
        local.mutate(
            Method::QuestionAnswer,
            action(),
            host.target(),
            &yes(&host, &asked),
        ),
    )
    .await
    .expect("the call reaches the worker")
    .expect("the owner answers");
    let answered = resolved(value);
    assert_eq!(answered.state, QuestionState::Answered);
    assert!(
        answered.question().is_some(),
        "the owner is shown everything"
    );
}

/// KR-REQ-10.49: answering needs `question.respond` and nothing else, so a grant that holds no
/// `session.view` answers a question its history reaches, and is told the state of it and no word
/// of what it asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_49_a_respond_only_grant_answers_and_is_shown_no_content() {
    let host = host().await;
    let mut daemon = daemon(&host).await;
    let phone = device("phone");
    let asked = ask(&host, "respond-only");
    let respond_only = Grant {
        rights: vec![ActionRight::QuestionRespond],
        history: Some(scope(Some(0), &[])),
    };
    let first = action();
    let answered = resolved(
        forward(
            &mut daemon,
            &host,
            &phone,
            &respond_only,
            first,
            Method::QuestionAnswer,
            &yes(&host, &asked),
        )
        .await
        .expect("a grant that may respond answers"),
    );
    assert_eq!(answered.state, QuestionState::Answered);
    assert_eq!(answered.question_id, asked.question_id);
    assert_eq!(answered.question(), None, "no session.view, no content");
    shows_none_of_the_question(&answered);
    // The ledger holds it whole.
    assert_eq!(
        held(&host, asked.question_id).state,
        QuestionState::Answered
    );
}

// ---------------------------------------------------------------------------------------------
// What a first answer and a replay show
// ---------------------------------------------------------------------------------------------

/// KR-REQ-10.49: the first answer shows the question to a device whose history reaches it; a retry
/// after the grant narrowed shows only the state, and the stored result is the bytes it was and
/// a reused identifier with another payload is still a conflict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_49_a_retry_after_the_grant_narrows_shows_the_state_and_changes_nothing_kept() {
    let host = host().await;
    let mut daemon = daemon(&host).await;
    let phone = device("phone");
    let asked = ask(&host, "narrowing");
    let wide = reaching(asked.created_at_ms.get());
    let first = action();
    let params = yes(&host, &asked);

    let answered = resolved(
        forward(
            &mut daemon,
            &host,
            &phone,
            &wide,
            first,
            Method::QuestionAnswer,
            &params,
        )
        .await
        .expect("answered"),
    );
    let shown = answered
        .question()
        .expect("the first answer shows the question");
    assert_eq!(shown.state, QuestionState::Answered);
    assert_eq!(shown.question, "Push the branch anyway?");
    let stored = kept(&host, &phone.actor_id, first).expect("a result is kept");

    // The same grant, read again: still shown, because its history reaches the question.
    let again = resolved(
        forward(
            &mut daemon,
            &host,
            &phone,
            &wide,
            first,
            Method::QuestionAnswer,
            &params,
        )
        .await
        .expect("a duplicate is answered"),
    );
    assert_eq!(again.question(), Some(shown));

    // The grant narrows: the question is now before its bound.
    let narrow = reaching(asked.created_at_ms.get() + 1);
    let retried = resolved(
        forward(
            &mut daemon,
            &host,
            &phone,
            &narrow,
            first,
            Method::QuestionAnswer,
            &params,
        )
        .await
        .expect("a duplicate is still answered"),
    );
    assert_eq!(retried.question(), None);
    assert_eq!(retried.state, QuestionState::Answered);
    assert_eq!(retried.question_id, asked.question_id);
    assert_eq!(retried.revision, shown.revision);
    shows_none_of_the_question(&retried);

    // Nothing kept moved: the same bytes, the same receipt revision, and a reused identifier with
    // another payload is still a conflict.
    assert_eq!(kept(&host, &phone.actor_id, first), Some(stored));
    let other = QuestionAnswerParams {
        answer: QuestionAnswer::Decision { decided: false },
        ..params
    };
    let conflict = forward(
        &mut daemon,
        &host,
        &phone,
        &wide,
        first,
        Method::QuestionAnswer,
        &other,
    )
    .await
    .expect_err("a reused identifier with another payload");
    assert_eq!(conflict.code, ErrorCode::IdConflict);
}

/// KR-REQ-10.51: a device whose grant names a pending question is shown it in the first answer it
/// gives, because it was admitted while the question was open, and not in a retry, because the
/// question has ended by then and the grant's bound decides.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_named_question_is_shown_to_its_first_answer_and_not_to_a_retry() {
    let host = host().await;
    let mut daemon = daemon(&host).await;
    let phone = device("phone");
    let asked = ask(&host, "named-first");
    let named = Grant {
        rights: vec![ActionRight::SessionView, ActionRight::QuestionRespond],
        history: Some(scope(
            Some(asked.created_at_ms.get() + 10_000),
            &[asked.question_id],
        )),
    };
    let first = action();
    let params = yes(&host, &asked);

    let answered = resolved(
        forward(
            &mut daemon,
            &host,
            &phone,
            &named,
            first,
            Method::QuestionAnswer,
            &params,
        )
        .await
        .expect("answered"),
    );
    assert!(answered.question().is_some(), "the first answer shows it");

    let retried = resolved(
        forward(
            &mut daemon,
            &host,
            &phone,
            &named,
            first,
            Method::QuestionAnswer,
            &params,
        )
        .await
        .expect("a duplicate is answered"),
    );
    assert_eq!(retried.question(), None, "the question has ended");
    assert_eq!(retried.state, QuestionState::Answered);
}

/// KR-REQ-10.49: a retry of a cancellation is held the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_49_a_retried_cancellation_is_shown_as_an_answer_is() {
    let host = host().await;
    let mut daemon = daemon(&host).await;
    let phone = device("phone");
    let asked = ask(&host, "cancel-retry");
    let cancel = QuestionCancelParams {
        session_id: host.session_id,
        question_id: asked.question_id,
        expected_revision: asked.revision,
    };
    let first = action();
    let wide = reaching(0);
    let cancelled = resolved(
        forward(
            &mut daemon,
            &host,
            &phone,
            &wide,
            first,
            Method::QuestionCancel,
            &cancel,
        )
        .await
        .expect("cancelled"),
    );
    assert!(cancelled.question().is_some());
    let narrow = reaching(asked.created_at_ms.get() + 1);
    let retried = resolved(
        forward(
            &mut daemon,
            &host,
            &phone,
            &narrow,
            first,
            Method::QuestionCancel,
            &cancel,
        )
        .await
        .expect("a duplicate is answered"),
    );
    assert_eq!(retried.question(), None);
    assert_eq!(retried.state, QuestionState::Cancelled);
}

// ---------------------------------------------------------------------------------------------
// action.read
// ---------------------------------------------------------------------------------------------

async fn read_action(
    daemon: &mut LocalClient,
    actor: &ActorEnvelope,
    grant: &Grant,
    action_id: ActionId,
) -> Result<ActionReadResult, ProtocolError> {
    forward_read(
        daemon,
        actor,
        grant,
        Method::ActionRead,
        &ActionReadParams {
            action_id,
            session_id: None,
        },
    )
    .await
    .map(|value| value.to_typed().expect("a receipt and its result"))
}

/// KR-REQ-10.49 and KR-REQ-23.34: `action.read` shows the owner everything, a device whose history
/// reaches the question the same, a device whose history does not reach it the receipt's state and
/// a withheld marker, and a device the daemon sent no scope for the state alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_34_action_read_shows_each_reader_what_its_authority_reaches() {
    let host = host().await;
    let mut daemon = daemon(&host).await;
    let phone = device("phone");
    let asked = ask(&host, "read");
    let first = action();
    forward(
        &mut daemon,
        &host,
        &phone,
        &reaching(0),
        first,
        Method::QuestionAnswer,
        &yes(&host, &asked),
    )
    .await
    .expect("answered");

    let shown = |read: &ActionReadResult| -> QuestionResolveResult {
        read.result
            .as_ref()
            .expect("a result is retained")
            .to_typed()
            .expect("a resolution result")
    };

    let reaching_read = read_action(&mut daemon, &phone, &reaching(0), first)
        .await
        .expect("read");
    assert_eq!(reaching_read.receipt.state, ReceiptState::Applied);
    assert!(shown(&reaching_read).question().is_some());

    let narrow = read_action(
        &mut daemon,
        &phone,
        &reaching(asked.created_at_ms.get() + 1),
        first,
    )
    .await
    .expect("read");
    assert_eq!(narrow.receipt.state, ReceiptState::Applied);
    assert_eq!(shown(&narrow).question(), None);
    assert_eq!(shown(&narrow).state, QuestionState::Answered);
    shows_none_of_the_question(&narrow);

    let unscoped = read_action(
        &mut daemon,
        &phone,
        &Grant {
            rights: vec![ActionRight::SessionView],
            history: None,
        },
        first,
    )
    .await
    .expect("read");
    assert_eq!(unscoped.receipt.state, ReceiptState::Applied);
    assert_eq!(shown(&unscoped).question(), None);
    shows_none_of_the_question(&unscoped);

    // The owner reads what its device did, as the device. The receipt is keyed by the actor, so
    // the owner reads its own: an answer it gives itself.
    let mut local = owner(&host).await;
    let own = action();
    let value = within(
        "the owner's answer",
        local.mutate(
            Method::QuestionAnswer,
            own,
            host.target(),
            &yes(&host, &ask(&host, "owner")),
        ),
    )
    .await
    .expect("the call reaches the worker")
    .expect("answered");
    assert!(resolved(value).question().is_some());
    let owner_read: ActionReadResult = within(
        "the owner's read",
        local.request(
            Method::ActionRead,
            &ActionReadParams {
                action_id: own,
                session_id: None,
            },
        ),
    )
    .await
    .expect("the call reaches the worker")
    .expect("the owner reads")
    .to_typed()
    .expect("a receipt");
    assert!(shown(&owner_read).question().is_some());
}

/// KR-REQ-10.49: a receipt's error text is the owner's alone. A refused answer's receipt keeps its
/// state, its code and its revision for the device that sent it, and loses the message, in
/// `action.read` and in a retry that answers with the receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_49_a_devices_receipt_keeps_its_code_and_loses_its_error_text() {
    let host = host().await;
    let mut daemon = daemon(&host).await;
    let phone = device("phone");
    let asked = ask(&host, "stale");
    let wide = reaching(0);
    // An answer to a revision that is not the question's: it is refused before it is dispatched,
    // and the refusal is what the receipt keeps.
    let stale = QuestionAnswerParams {
        expected_revision: kr_protocol::ids::QuestionRevision::new(asked.revision.get() + 5),
        ..yes(&host, &asked)
    };
    let first = action();
    let refusal = forward(
        &mut daemon,
        &host,
        &phone,
        &wide,
        first,
        Method::QuestionAnswer,
        &stale,
    )
    .await
    .expect_err("a stale revision is refused");
    assert_eq!(refusal.code, ErrorCode::DraftConflict, "{refusal}");

    let read = read_action(&mut daemon, &phone, &wide, first)
        .await
        .expect("the receipt reads");
    assert_eq!(read.receipt.state, ReceiptState::Rejected);
    assert!(read.result.0.is_none());
    let error = read.receipt.error.as_ref().expect("the error is recorded");
    assert_eq!(error.code, ErrorCode::DraftConflict);
    assert!(read.receipt.error_withheld);
    assert!(
        !error.message.contains("revision"),
        "the device is not told the question's revision: {}",
        error.message
    );

    // A retry is answered with the receipt as it stands, shown the same way.
    let retry = forward(
        &mut daemon,
        &host,
        &phone,
        &wide,
        first,
        Method::QuestionAnswer,
        &stale,
    )
    .await
    .expect("a duplicate is answered with its receipt");
    let receipt: ReceiptResponse = retry.to_typed().expect("a receipt response");
    assert_eq!(receipt.receipt.state, ReceiptState::Rejected);
    assert!(receipt.receipt.error_withheld);
    let kept_error = receipt.receipt.error.as_ref().expect("an error");
    assert_eq!(kept_error.code, ErrorCode::DraftConflict);
    assert!(!kept_error.message.contains("revision"));
}

/// KR-REQ-10.49: the local owner reads a refusal's text as it was written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_49_the_owner_reads_a_refusals_text_whole() {
    let host = host().await;
    let asked = ask(&host, "owner-stale");
    let mut local = owner(&host).await;
    let stale = QuestionAnswerParams {
        expected_revision: kr_protocol::ids::QuestionRevision::new(asked.revision.get() + 5),
        ..yes(&host, &asked)
    };
    let first = action();
    within(
        "the owner's answer",
        local.mutate(Method::QuestionAnswer, first, host.target(), &stale),
    )
    .await
    .expect("the call reaches the worker")
    .expect_err("refused");
    let read: ActionReadResult = within(
        "the owner's read",
        local.request(
            Method::ActionRead,
            &ActionReadParams {
                action_id: first,
                session_id: None,
            },
        ),
    )
    .await
    .expect("the call reaches the worker")
    .expect("the owner reads")
    .to_typed()
    .expect("a receipt");
    assert!(!read.receipt.error_withheld);
    let error = read.receipt.error.as_ref().expect("an error");
    assert!(error.message.contains("revision"), "{}", error.message);
}

// ---------------------------------------------------------------------------------------------
// The ingresses a worker serves
// ---------------------------------------------------------------------------------------------

/// KR-REQ-23.34: a workflow is not an ingress a worker serves, for `action.read` or for a
/// mutation: no door at this worker answers it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_34_a_workflow_ingress_reaches_neither_a_read_of_a_receipt_nor_a_mutation() {
    let host = host().await;
    let mut daemon = daemon(&host).await;
    let asked = ask(&host, "workflow");
    let mut workflow = device("workflow");
    workflow.ingress = ActorIngress::Workflow;
    workflow.device_id = Nullable::null();
    let grant = reaching(0);

    let refused = forward(
        &mut daemon,
        &host,
        &workflow,
        &grant,
        action(),
        Method::QuestionAnswer,
        &yes(&host, &asked),
    )
    .await
    .expect_err("a workflow does not answer a question");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused}");
    let refused = read_action(&mut daemon, &workflow, &grant, action())
        .await
        .expect_err("a workflow does not read a receipt");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused}");
    assert_eq!(held(&host, asked.question_id).state, QuestionState::Pending);
}
