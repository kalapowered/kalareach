//! The standing function at the worker's own boundary (section 9).
//!
//! A mutation is admitted once and dispatched later, and the checks that change nothing are asked
//! again at the second moment. Each case stops one admission at a seam, changes what the second
//! moment reads while it stands, lets it go, and reads what landed before it reads what the caller
//! was answered. Every pause is the seam's own signal, never a sleep.
//!
//! * the question that is due between the first admission and the dispatch refuses the dispatch,
//!   leaves a rejected receipt and no marker (C-S4);
//! * the uncertain outcome that an earlier launch settles while the admission waits for the
//!   session is refused by the second look, before any receipt is written (C-K1-S6);
//! * the same wait with a journal that fails from there on lets the authorised stop go on and
//!   report the volatile durability, which the second look must not take away (C-K1-S6-volatile).

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::{Client, Codec, LocalClient};
use kr_ipc::clock::{ManualSharedClock, SharedClock as _};
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, BuildId, ControllerGeneration, RequestId, SessionEpoch,
    SessionId,
};
use kr_protocol::limits::DEFAULT_MUTATION_TTL;
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::question::{
    Question, QuestionAnswer, QuestionAnswerParams, QuestionCreateParams, QuestionKind,
    QuestionState,
};
use kr_protocol::receipt::{Receipt, ReceiptState, RejectionReason};
use kr_protocol::scalars::{CanonicalSet, Digest256, DurationMs, Nullable, TimestampMs, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, Durability, ShellMode};
use kr_worker::journal::Submission;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// How long a case waits for something it waits for by condition, and fails after. Nothing is
/// decided by it.
const WAIT: Duration = Duration::from_secs(60);

/// How long the question of the first case lives, and how far its clock moves past that.
const QUESTION_LIFE: Duration = Duration::from_secs(60);
const PAST_THE_QUESTION: Duration = Duration::from_secs(61);

// ---------------------------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------------------------

struct Host {
    service: Arc<WorkerService>,
    session_id: SessionId,
    journal_path: std::path::PathBuf,
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: kr_protocol::ids::EnvironmentId,
    /// The boot clock the worker's questions are measured on, which a case moves by hand.
    boot: ManualSharedClock,
    // Declared last: the directory is removed after every field above has let go of its files.
    _temp: kr_ipc::testing::TempHost,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A worker for one local owner, whose boot clock a case moves by hand.
async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let boot_identity = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot_identity.clone(),
            process,
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller = ControllerIdentity::initialise(store.store.as_ref(), environment_id)
        .expect("a controller identity");
    let journal_path = environment.journal_database(session_id);
    if let Some(parent) = journal_path.parent() {
        std::fs::create_dir_all(parent).expect("the journal directory");
    }
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        // A shell that ends only on end of input, on a signal or when the session closes it, so no
        // case here decides by how long the shell lasts.
        shell: kr_worker::testing::posix_script("while read -r _; do :; done"),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(journal_path.clone()),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let boot = ManualSharedClock::new();
    boot.advance(Duration::from_secs(1_000));
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(boot.clone())).expect("starts the runtime"),
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
                boot_identity,
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
        environment_id,
        boot,
    }
}

async fn cli(host: &Host) -> LocalClient {
    LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects")
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

/// The principal of the local owner that `cli` connects as.
fn local_actor() -> ActorId {
    ActorId::new(format!("local:{}", kr_ipc::paths::current_uid())).expect("a principal")
}

/// A mutation of `method` under a fresh identifier, in the action window of `client`.
fn mutation_of(
    client: &Client<impl Codec>,
    host: &Host,
    method: Method,
    params: ParamsValue,
) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(91),
        method: method.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: target(host),
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new(
            client.action_window().action_window_id.as_str().to_owned(),
        )
        .expect("a window identifier"),
        requested_ttl_ms: DEFAULT_MUTATION_TTL,
        params,
    }
}

fn attach(client: &Client<impl Codec>, host: &Host) -> MutationRequest {
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    mutation_of(
        client,
        host,
        Method::SessionAttach,
        ParamsValue::from_typed(&SessionAttachParams {
            session_id: host.session_id,
            mode: AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested,
        })
        .expect("encodes"),
    )
}

fn close(client: &Client<impl Codec>, host: &Host) -> MutationRequest {
    mutation_of(
        client,
        host,
        Method::SessionClose,
        ParamsValue::from_typed(&kr_protocol::session::SessionCloseParams {
            session_id: host.session_id,
        })
        .expect("encodes"),
    )
}

fn answering(client: &Client<impl Codec>, host: &Host, question: &Question) -> MutationRequest {
    mutation_of(
        client,
        host,
        Method::QuestionAnswer,
        ParamsValue::from_typed(&QuestionAnswerParams {
            session_id: host.session_id,
            question_id: question.question_id,
            expected_revision: question.revision,
            answer: QuestionAnswer::Input {
                text: "orchid".to_owned(),
            },
        })
        .expect("encodes"),
    )
}

/// What a `mutation` is answered, over a connection that stays open until the case has read the
/// session.
async fn answer_to(mut client: LocalClient, mutation: MutationRequest) -> (LocalClient, Outcome) {
    client
        .send(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("writes the mutation");
    loop {
        match client.recv().await.expect("the worker answers") {
            ControlFrame::Response(response) => return (client, response.outcome),
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

/// Starts the answer to `mutation`, which stops at the seam after the admission's limits, and
/// returns once it stands there.
async fn stopped_after_the_limits(
    host: &Host,
    client: LocalClient,
    mutation: MutationRequest,
) -> (
    std::sync::mpsc::Sender<()>,
    tokio::task::JoinHandle<(LocalClient, Outcome)>,
) {
    let (reached, release) = host.service.stall_next_admission_after_its_limits();
    let answering = tokio::spawn(answer_to(client, mutation));
    tokio::time::timeout(WAIT, reached)
        .await
        .expect("the admission reaches the stop in time")
        .expect("the stop is armed");
    (release, answering)
}

/// The receipt of the local owner's action, if the journal has one.
fn receipt_of(host: &Host, action_id: ActionId) -> Option<Receipt> {
    let mut session = host.service.runtime().session();
    session
        .journal_mut()
        .expect("this session keeps a journal")
        .read(local_actor(), action_id)
        .expect("reads")
}

/// How many attachments the session holds: the effect of a `session.attach`, counted.
fn attachments(host: &Host) -> usize {
    host.service.runtime().session().attachments().len()
}

// ---------------------------------------------------------------------------------------------
// C-S4: a question that is due between the first admission and the dispatch
// ---------------------------------------------------------------------------------------------

/// A question that the agent `kr-test-agent` asks in the host's session, which lives for
/// [`QUESTION_LIFE`] on the host's boot clock.
fn asked(host: &Host) -> Question {
    let source = kr_worker::questions::binding::VerifiedSource {
        process: kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        executable: Some("kr-test-agent".to_owned()),
        session_member: true,
        ancestry: true,
        launch_channel: true,
        connection_id: kr_protocol::ids::ConnectionId::new(Uuid::from_bytes([7; 16])),
    };
    let params = QuestionCreateParams {
        session_id: host.session_id,
        request_id: "name-the-release".to_owned(),
        kind: QuestionKind::Input,
        context: "The build finished.".to_owned(),
        question: "What should the release be called?".to_owned(),
        choices: Vec::new(),
        agent_name: Nullable::some("kr-test-agent".to_owned()),
        requested_expiry_ms: Nullable::some(DurationMs::new(
            u64::try_from(QUESTION_LIFE.as_millis()).expect("fits"),
        )),
        wait_ms: Nullable::null(),
    };
    let now = kr_worker::questions::Now {
        utc_ms: kr_ipc::now_ms(),
        boot_ms: host.boot.boot_elapsed_ms(),
    };
    let (created, _) = host
        .service
        .questions()
        .create(&source, &params, now)
        .expect("the agent asks");
    created.question
}

/// What the local owner's answer to a question comes to when the host's boot clock moves by `moved`
/// while the admission stands after its limits, which is after the first admission's checks and
/// before the dispatch that follows the receipt.
async fn answer_while_the_clock_moves(
    moved: Duration,
) -> (Host, Question, MutationRequest, Outcome, LocalClient) {
    let host = host().await;
    let client = cli(&host).await;
    let question = asked(&host);
    let mutation = answering(&client, &host, &question);
    let (release, answering) = stopped_after_the_limits(&host, client, mutation.clone()).await;
    // The admission has read nothing of the question: no receipt exists, and the question is as it
    // was asked, pending and not yet due.
    assert!(
        receipt_of(&host, mutation.action_id).is_none(),
        "a receipt was written before the admission's checks ended"
    );
    let held = host
        .service
        .questions()
        .question(question.question_id)
        .expect("the question is in the ledger");
    assert_eq!(held.state, QuestionState::Pending);
    host.boot.advance(moved);
    release.send(()).expect("the admission is waiting to go on");
    let (client, outcome) = answering.await.expect("the admission ends");
    (host, question, mutation, outcome, client)
}

/// KR-REQ-09.16 and KR-REQ-25.09: a question that comes due after the first admission's checks and
/// before the dispatch refuses the dispatch. The pass that follows the receipt sweeps the questions
/// before it reads the one it names, so the question is `expired` when it refuses (a due question
/// that nothing has swept reads as pending, and the pass that asks again does not sweep). The
/// receipt is rejected and no marker was written, and the answer was not recorded. The control, the
/// same stop with the clock where it was, records the answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_question_that_comes_due_before_the_dispatch_refuses_it_and_writes_no_marker() {
    let (host, question, mutation, outcome, _client) =
        answer_while_the_clock_moves(PAST_THE_QUESTION).await;
    // What landed is read before what was answered, so that a dispatch that went on past the due
    // question is what this case reports.
    let receipt = receipt_of(&host, mutation.action_id).expect("the action has a receipt");
    assert_eq!(receipt.state, ReceiptState::Rejected, "{receipt:?}");
    assert!(
        !receipt.state.has_dispatch_marker(),
        "a marker was written for an answer to an expired question"
    );
    assert_eq!(
        receipt.reason.as_ref(),
        Some(&RejectionReason::StalePreconditions)
    );
    let held = host
        .service
        .questions()
        .question(question.question_id)
        .expect("the question is in the ledger");
    assert_eq!(held.state, QuestionState::Expired, "{held:?}");
    let Outcome::Error(error) = &outcome else {
        panic!("an answer to a question that came due was not refused: {outcome:?}");
    };
    assert_eq!(error.code, ErrorCode::QuestionExpired, "{error:?}");

    let (host, question, mutation, outcome, _client) =
        answer_while_the_clock_moves(Duration::ZERO).await;
    assert!(matches!(outcome, Outcome::Ok(_)), "{outcome:?}");
    assert_eq!(
        receipt_of(&host, mutation.action_id)
            .expect("the action has a receipt")
            .state,
        ReceiptState::Applied
    );
    let held = host
        .service
        .questions()
        .question(question.question_id)
        .expect("the question is in the ledger");
    assert_eq!(held.state, QuestionState::Answered, "{held:?}");
}

// ---------------------------------------------------------------------------------------------
// C-K1-S6: an uncertain outcome that settles while the admission waits for the session
// ---------------------------------------------------------------------------------------------

/// Settles an earlier action of the local owner for the same subject as `mutation` as `unknown`,
/// the way a launch whose confirmation was lost is settled: accepted, marked, then unknown.
fn an_earlier_launch_settles_unknown(host: &Host, mutation: &MutationRequest) {
    let subject = kr_protocol::action::subject_digest(mutation).expect("a subject digest");
    let now = kr_ipc::now_ms();
    let earlier = ActionId::new(kr_ipc::new_uuid());
    let mut session = host.service.runtime().session();
    let journal = session.journal_mut().expect("this session keeps a journal");
    journal
        .accept(&Submission {
            actor_id: local_actor(),
            action_id: earlier,
            method: mutation.method.clone(),
            method_version: MethodVersion::V1,
            payload_digest: Digest256::from_bytes([50; 32]),
            subject_digest: subject,
            intent: vec![0xa0],
            accepted_deadline_ms: Some(TimestampMs::new(now.get() + 120_000)),
            now_ms: now,
        })
        .expect("the earlier intent");
    journal
        .mark_dispatching(local_actor(), earlier, now)
        .expect("a marker");
    journal
        .settle(
            local_actor(),
            earlier,
            ReceiptState::Unknown,
            None,
            None,
            now,
        )
        .expect("an uncertain outcome");
}

/// What a local `session.attach` comes to when an earlier action for the same subject settles as
/// `unknown` (when `settles`) while the admission stands after its limits.
async fn attach_while_an_earlier_launch_settles(
    settles: bool,
) -> (Host, MutationRequest, Outcome, LocalClient) {
    let host = host().await;
    let client = cli(&host).await;
    let mutation = attach(&client, &host);
    let (release, answering) = stopped_after_the_limits(&host, client, mutation.clone()).await;
    assert!(
        receipt_of(&host, mutation.action_id).is_none(),
        "a receipt was written before the admission's checks ended"
    );
    if settles {
        an_earlier_launch_settles_unknown(&host, &mutation);
    }
    release.send(()).expect("the admission is waiting to go on");
    let (client, outcome) = answering.await.expect("the admission ends");
    (host, mutation, outcome, client)
}

/// KR-REQ-23.24: the uncertain outcome in the way of a fresh identifier is asked again under the
/// session that reaches the accept. An earlier launch that settles as unknown while the admission
/// waits for the session refuses it: no receipt is written for the action and nothing is attached.
/// The control, the same stop with nothing settled, attaches once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_outcome_that_settles_unknown_while_the_admission_waits_refuses_it_before_any_receipt() {
    let (host, mutation, outcome, _client) = attach_while_an_earlier_launch_settles(true).await;
    // What landed is read before what was answered.
    assert!(
        receipt_of(&host, mutation.action_id).is_none(),
        "a receipt exists for an action that the second look refused"
    );
    assert_eq!(attachments(&host), 0, "the effect was made");
    let Outcome::Error(error) = &outcome else {
        panic!("an uncertain outcome in the way did not refuse the second look: {outcome:?}");
    };
    assert_eq!(error.code, ErrorCode::DraftConflict, "{error:?}");

    let (host, mutation, outcome, _client) = attach_while_an_earlier_launch_settles(false).await;
    assert!(matches!(outcome, Outcome::Ok(_)), "{outcome:?}");
    assert_eq!(
        receipt_of(&host, mutation.action_id)
            .expect("the action has a receipt")
            .state,
        ReceiptState::Applied
    );
    assert_eq!(attachments(&host), 1, "the control attaches once");
}

// ---------------------------------------------------------------------------------------------
// C-K1-S6-volatile: the second look on a journal that fails from the stop on
// ---------------------------------------------------------------------------------------------

/// What a local `session.close` comes to when the journal's receipt table is taken away (when
/// `fails`) while the admission stands after its limits.
async fn close_while_the_journal_changes(
    fails: bool,
) -> (Host, MutationRequest, Outcome, LocalClient) {
    let host = host().await;
    let client = cli(&host).await;
    let mutation = close(&client, &host);
    let (release, answering) = stopped_after_the_limits(&host, client, mutation.clone()).await;
    // The first look has read the journal, and the journal answers.
    assert!(
        receipt_of(&host, mutation.action_id).is_none(),
        "a receipt was written before the admission's checks ended"
    );
    if fails {
        let connection = rusqlite::Connection::open(&host.journal_path).expect("opens the store");
        connection
            .execute_batch("DROP TABLE receipts;")
            .expect("takes the receipt table away");
    }
    release.send(()).expect("the admission is waiting to go on");
    let (client, outcome) = answering.await.expect("the admission ends");
    (host, mutation, outcome, client)
}

/// The close's answer, which a case reads after what landed.
fn the_close_answered(outcome: Outcome) -> kr_protocol::session::SessionCloseResult {
    let Outcome::Ok(value) = outcome else {
        panic!("a close whose journal failed after the first look was refused: {outcome:?}");
    };
    value.to_typed().expect("decodes")
}

/// KR-REQ-07.57: the authorised stop goes on without its receipt when the journal cannot answer,
/// and says so. The first look read the journal before the stop; the table goes while the admission
/// stands, so the second look is the first read that fails, and it must not refuse the stop. The
/// control, the same stop with the table in place, reports durable.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_close_whose_journal_fails_after_the_first_look_goes_on_and_reports_volatile() {
    let (host, mutation, outcome, _client) = close_while_the_journal_changes(true).await;
    // What landed is read before what was answered: the journal cannot answer now, and the close
    // was made without a receipt.
    {
        let mut session = host.service.runtime().session();
        let journal = session
            .journal_mut()
            .expect("the session keeps its journal");
        assert!(
            journal.read(local_actor(), mutation.action_id).is_err(),
            "the journal still answers after its table was taken away"
        );
    }
    let closed = the_close_answered(outcome);
    assert_eq!(
        closed.durability,
        Durability::Volatile,
        "the close says what it lost rather than claiming a receipt it could not write"
    );
    assert_eq!(closed.session_id, host.session_id);
    // The close was asked for above: its own steps end before the fixture's directory is removed.
    tokio::time::timeout(
        Duration::from_secs(30),
        host.service.runtime().wait_closed(),
    )
    .await
    .expect("the session's closure finishes");

    let (host, _mutation, outcome, _client) = close_while_the_journal_changes(false).await;
    let closed = the_close_answered(outcome);
    assert_eq!(
        closed.durability,
        Durability::Durable,
        "the control's journal answered, so the close claims what it kept"
    );
    assert_eq!(closed.session_id, host.session_id);
    tokio::time::timeout(
        Duration::from_secs(30),
        host.service.runtime().wait_closed(),
    )
    .await
    .expect("the control's closure finishes");
}
