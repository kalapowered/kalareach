//! An agent's questions on a real worker, answered the way the page answers them.
//!
//! The worker is the product's own: a session service over a real terminal, its question ledger
//! and its admission of every caller, serving a real local endpoint and publishing the descriptor
//! the application finds it by. What is checked is what a scripted worker cannot say: that the
//! envelope the application sends passes the worker's admission, that the worker resolves a
//! question once for whoever answers first, that it refuses an answer to a question that expired,
//! and that what it records of the answer is the answer the person gave.

#![cfg(unix)]

mod question_page;

use std::sync::Arc;

use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActorId, BuildId, ConnectionId, ControllerGeneration, DeviceId, QuestionId, QuestionRevision,
    SessionEpoch, SessionId,
};
use kr_protocol::question::{
    QuestionAnswer, QuestionAnswerParams, QuestionCreateParams, QuestionKind,
};
use kr_protocol::scalars::{DurationMs, Nullable, TimestampMs, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_protocol::worker::WorkerDescriptor;
use kr_worker::questions::Now;
use kr_worker::questions::binding::VerifiedSource;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session as TerminalSession, SessionConfig};
use question_page::{Page, answered, code_of};
use serde_json::{Value, json};

/// A worker serving one session, and the host tree it is published in.
struct Worker {
    session_id: SessionId,
    service: Arc<WorkerService>,
    serving: tokio::task::JoinHandle<kr_worker::Result<()>>,
    // Declared last: the directory is removed after every field above has let go of its files.
    temp: kr_ipc::testing::TempHost,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// Starts a worker for a session whose shell lasts as long as the session does.
async fn worker() -> Worker {
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
            process.clone(),
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
    let journal = config.journal_path.clone().expect("the harness journals");
    if let Some(parent) = journal.parent() {
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
            Arc::clone(&runtime),
            Arc::clone(&identity),
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot.clone(),
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                journal_path: Some(journal),
                build_id: BuildId::new("kr-test/0").expect("a build identifier"),
            },
        )
        .expect("a worker service"),
    );
    let serving = tokio::spawn(Arc::clone(&service).serve(listener));
    let descriptor = WorkerDescriptor {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        boot_identity: boot,
        process_start_identity: process,
        protocol_version: PROTOCOL_VERSION,
        endpoint: endpoint.as_text(),
        worker_public_key: *identity.public_key(),
        worker_profile: WorkerProfile::HeadlessUser,
        published_at_ms: TimestampMs::new(0),
    };
    kr_ipc::descriptor::publish(&environment, &descriptor).expect("publishes the descriptor");
    Worker {
        temp,
        session_id,
        service,
        serving,
    }
}

/// The time the worker's ledger is told, which is when the test says it is.
fn now(utc_ms: u64) -> Now {
    Now {
        utc_ms: TimestampMs::new(utc_ms),
        boot_ms: utc_ms,
    }
}

/// The helper the worker verified as the one that asked.
fn asker() -> VerifiedSource {
    VerifiedSource {
        process: kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        executable: Some("kr-test-agent".to_owned()),
        session_member: true,
        ancestry: true,
        launch_channel: true,
        connection_id: ConnectionId::new(Uuid::from_bytes([1; 16])),
    }
}

/// Has the agent ask a yes or no question that expires `expiry_ms` after `asked_at_ms`.
fn ask(worker: &Worker, request: &str, asked_at_ms: u64, expiry_ms: u64) -> QuestionId {
    let (created, _) = worker
        .service
        .questions()
        .create(
            &asker(),
            &QuestionCreateParams {
                session_id: worker.session_id,
                request_id: request.to_owned(),
                kind: QuestionKind::Confirm,
                context: "The build finished with two failing tests.".to_owned(),
                question: "Push the branch anyway?".to_owned(),
                choices: Vec::new(),
                agent_name: Nullable::some("kr-test-agent".to_owned()),
                requested_expiry_ms: Nullable::some(DurationMs::new(expiry_ms)),
                wait_ms: Nullable::null(),
            },
            now(asked_at_ms),
        )
        .expect("the agent asks");
    created.question.question_id
}

fn read(worker: &Worker) -> Value {
    json!({ "params": {
        "session_id": worker.session_id.to_string(),
        "question_id": null,
        "include_resolved": false
    } })
}

fn answer(worker: &Worker, question: QuestionId, revision: &str, decided: bool) -> Value {
    json!({ "params": {
        "session_id": worker.session_id.to_string(),
        "question_id": question.to_string(),
        "expected_revision": revision,
        "answer": { "kind": "decision", "decided": decided }
    } })
}

/// The page reads the question the worker's ledger holds, with who the worker verified asked it,
/// and its answer is recorded once, as the person gave it, under the principal the worker
/// authenticated and not under anything the page said.
#[tokio::test(flavor = "multi_thread")]
async fn a_question_the_worker_holds_is_read_and_its_answer_recorded_as_given() {
    let worker = worker().await;
    let page = Page::new(worker.temp.environment());
    let asked = ask(
        &worker,
        "push-after-failures",
        kr_ipc::now_ms().get(),
        600_000,
    );

    let listed = answered(page.call("question_read", read(&worker)))
        .await
        .expect("the questions");
    let first = &listed["questions"][0];
    assert_eq!(first["question_id"], asked.to_string());
    assert_eq!(first["state"], "pending");
    assert_eq!(first["source"]["executable"], "kr-test-agent");
    let revision = first["revision"].as_str().expect("a revision").to_owned();

    let told = answered(page.call("question_answer", answer(&worker, asked, &revision, true)))
        .await
        .expect("the worker takes the answer");
    assert_eq!(told["outcome"], "taken");
    assert_eq!(told["resolution"]["state"], "answered");

    let recorded = worker
        .service
        .questions()
        .question(asked)
        .expect("the question is held")
        .answer
        .0
        .expect("an answer is recorded");
    assert_eq!(recorded.answer, QuestionAnswer::Decision { decided: true });
    assert_eq!(
        recorded.question_revision.to_string(),
        revision,
        "the revision the person was shown"
    );
    assert!(
        !recorded.actor_id.to_string().is_empty(),
        "the actor is the one the worker authenticated"
    );
}

/// KR-REQ-11.60, KR-REQ-23.32: two people answer one question: the worker resolves it for the first, and the second is told so
/// and has no answer recorded. The page shows the refusal the worker gave, and keeps nothing.
#[tokio::test(flavor = "multi_thread")]
async fn the_first_answer_resolves_the_question_and_the_second_is_refused() {
    let worker = worker().await;
    let page = Page::new(worker.temp.environment());
    let asked = ask(&worker, "which-first", kr_ipc::now_ms().get(), 600_000);
    let listed = answered(page.call("question_read", read(&worker)))
        .await
        .expect("the questions");
    let revision = listed["questions"][0]["revision"]
        .as_str()
        .expect("a revision")
        .to_owned();

    // Another device answers first.
    worker
        .service
        .questions()
        .answer(
            &ActorId::new("device:phone").expect("a principal"),
            Some(DeviceId::new(Uuid::from_bytes([9; 16]))),
            &QuestionAnswerParams {
                session_id: worker.session_id,
                question_id: asked,
                expected_revision: QuestionRevision::new(revision.parse().expect("a revision")),
                answer: QuestionAnswer::Decision { decided: false },
            },
            now(kr_ipc::now_ms().get()),
        )
        .expect("the first device answers");

    let refused = answered(page.call("question_answer", answer(&worker, asked, &revision, true)))
        .await
        .expect_err("the second answer is refused");
    assert_eq!(code_of(&refused), "QUESTION_RESOLVED");
    let recorded = worker
        .service
        .questions()
        .question(asked)
        .expect("the question is held")
        .answer
        .0
        .expect("the first answer stands");
    assert_eq!(recorded.answer, QuestionAnswer::Decision { decided: false });
    let kept = answered(page.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(
        kept["answers"],
        json!([]),
        "a refusal is the worker's word, and nothing is kept"
    );
}

/// A question whose time ran out while a person was reading it is refused as ended, and nothing is
/// recorded as their answer.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_to_a_question_that_expired_while_it_was_read_is_refused() {
    let worker = worker().await;
    let page = Page::new(worker.temp.environment());
    let asked_at = kr_ipc::now_ms().get();
    let asked = ask(&worker, "short-lived", asked_at, 60_000);
    let listed = answered(page.call("question_read", read(&worker)))
        .await
        .expect("the questions");
    let revision = listed["questions"][0]["revision"]
        .as_str()
        .expect("a revision")
        .to_owned();

    // Its time runs out while the person is deciding.
    worker
        .service
        .questions()
        .sweep(now(asked_at + 120_000))
        .expect("the ledger sweeps");

    let refused = answered(page.call("question_answer", answer(&worker, asked, &revision, true)))
        .await
        .expect_err("the question ended");
    assert!(
        ["QUESTION_EXPIRED", "QUESTION_RESOLVED"].contains(&code_of(&refused)),
        "{refused}"
    );
    let held = worker
        .service
        .questions()
        .question(asked)
        .expect("the question is held");
    assert!(held.answer.0.is_none(), "no answer was recorded");
}

/// The kept answers' place for one environment, as the application keeps them.
fn kept_store(page: &Page, worker: &Worker) -> kr_client::answers::AnswerDrafts {
    kr_client::answers::AnswerDrafts::open(
        page.kept
            .path()
            .join("kept-answers")
            .join(worker.temp.environment_id().to_string()),
    )
    .expect("a store")
}

/// Records an answer to `question` under the send `id` and nothing more, as an attempt does before
/// it sends: what a crash right after leaves.
fn record_pair(
    page: &Page,
    worker: &Worker,
    question: QuestionId,
    revision: &str,
    id: kr_protocol::ids::ActionId,
) {
    let draft = kr_client::answers::AnswerDraft {
        version: kr_client::answers::ANSWER_FORMAT,
        target: session_target(worker),
        session_id: worker.session_id,
        question_id: question,
        question_revision: QuestionRevision::new(revision.parse().expect("a revision")),
        answer: QuestionAnswer::Decision { decided: true },
        drafted_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
    };
    let store = kept_store(page, worker);
    let root = page.kept.path().join("kept-answers");
    let writers = kr_ipc::install::hold_writers(
        &kr_ipc::install::Writing::in_roots(&root, &root),
        &mut || {},
    )
    .expect("the writers lock");
    let leave = kr_client::answers::Leave {
        answers: writers
            .permit(&kr_client::answers::WRITTEN)
            .expect("permitted"),
        sends: writers
            .permit(&kr_client::sends::WRITTEN)
            .expect("permitted"),
    };
    let basis = store.basis(question).expect("the pair reads");
    let carried = basis.sends().to_vec();
    store
        .begin(&draft, &basis, &carried, id, &leave)
        .expect("recorded");
}

/// The target the application sends an answer on: the session at its first epoch.
fn session_target(worker: &Worker) -> kr_protocol::envelope::ActionTarget {
    kr_protocol::envelope::ActionTarget {
        environment_id: worker.temp.environment_id(),
        session_id: Nullable::some(worker.session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// A local owner's connection to the worker, as `kr` has one.
async fn owner(worker: &Worker) -> kr_ipc::client::LocalClient {
    let endpoint = worker
        .temp
        .environment()
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    kr_ipc::client::LocalClient::connect(
        &endpoint,
        kr_protocol::local::LocalClientKind::Cli,
        BuildId::new("kr-test/0").expect("a build identifier"),
    )
    .await
    .expect("connects")
}

/// Sends the answer under the identifier `id` over `client`, as an application's send would.
async fn send_as(
    client: &mut kr_ipc::client::LocalClient,
    worker: &Worker,
    question: QuestionId,
    revision: &str,
    id: kr_protocol::ids::ActionId,
) -> Result<kr_protocol::envelope::ParamsValue, kr_protocol::error::ProtocolError> {
    client
        .mutate(
            kr_protocol::method::Method::QuestionAnswer,
            id,
            session_target(worker),
            &QuestionAnswerParams {
                session_id: worker.session_id,
                question_id: question,
                expected_revision: QuestionRevision::new(revision.parse().expect("a revision")),
                answer: QuestionAnswer::Decision { decided: true },
            },
        )
        .await
        .expect("the connection holds")
}

/// Puts an action of the local owner with an uncertain outcome on the subject of a question answer
/// into the worker's journal, as a send whose outcome the worker could not establish leaves it.
async fn an_uncertain_answer(
    worker: &Worker,
    client: &mut kr_ipc::client::LocalClient,
    question: QuestionId,
    revision: &str,
    id: kr_protocol::ids::ActionId,
) {
    let composed = client
        .compose(
            kr_protocol::method::Method::QuestionAnswer,
            id,
            session_target(worker),
            &QuestionAnswerParams {
                session_id: worker.session_id,
                question_id: question,
                expected_revision: QuestionRevision::new(revision.parse().expect("a revision")),
                answer: QuestionAnswer::Decision { decided: true },
            },
        )
        .await
        .expect("composes");
    let subject = kr_protocol::action::subject_digest(&composed).expect("a subject digest");
    let actor = ActorId::new(format!("local:{}", kr_ipc::paths::current_uid())).expect("an actor");
    let mut session = worker.service.runtime().session();
    let journal = session.journal_mut().expect("a journal");
    journal
        .accept(&kr_worker::journal::Submission {
            actor_id: actor.clone(),
            action_id: id,
            method: composed.method.clone(),
            method_version: composed.method_version,
            payload_digest: kr_protocol::scalars::Digest256::from_bytes([7; 32]),
            subject_digest: subject,
            intent: vec![0xa0],
            accepted_deadline_ms: Some(TimestampMs::new(kr_ipc::now_ms().get() + 120_000)),
            now_ms: kr_ipc::now_ms(),
        })
        .expect("the earlier intent");
    journal
        .mark_dispatching(actor.clone(), id, kr_ipc::now_ms())
        .expect("a marker");
    journal
        .settle(
            actor,
            id,
            kr_protocol::receipt::ReceiptState::Unknown,
            None,
            None,
            kr_ipc::now_ms(),
        )
        .expect("an uncertain outcome");
}

/// The page's settling of the answers kept for the session.
fn settle(worker: &Worker) -> Value {
    json!({ "params": { "sessionId": worker.session_id.to_string() } })
}

/// KR-REQ-11.63: an answer sent under a recorded identifier whose reply was lost, with the pair left
/// in place as a lost reply leaves it, is found taken from the worker's own receipt; a pair that was
/// recorded and never sent is found unrecorded, from the worker's own "no receipt".
#[tokio::test(flavor = "multi_thread")]
async fn the_worker_says_whether_an_answer_the_application_lost_the_reply_to_was_taken() {
    let worker = worker().await;
    let page = Page::new(worker.temp.environment());
    let asked = ask(&worker, "lost-reply", kr_ipc::now_ms().get(), 600_000);
    let listed = answered(page.call("question_read", read(&worker)))
        .await
        .expect("the questions");
    let revision = listed["questions"][0]["revision"]
        .as_str()
        .expect("a revision")
        .to_owned();
    let sent = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());

    // Recorded and never sent: the worker has no receipt of it.
    record_pair(&page, &worker, asked, &revision, sent);
    let standing = answered(page.call("question_settle", settle(&worker)))
        .await
        .expect("the standing");
    assert_eq!(standing[0]["standing"], "offered", "{standing}");
    assert_eq!(
        standing[0]["earlier"][0]["state"], "no_record",
        "{standing}"
    );
    assert_eq!(standing[0]["earlier"][0]["action_id"], sent.to_string());

    // Sent, and the reply lost: the worker took it, and its receipt says so.
    let mut client = owner(&worker).await;
    send_as(&mut client, &worker, asked, &revision, sent)
        .await
        .expect("the worker takes it");
    let standing = answered(page.call("question_settle", settle(&worker)))
        .await
        .expect("the standing");
    assert_eq!(standing[0]["standing"], "taken", "{standing}");
    assert_eq!(standing[0]["action_id"], sent.to_string());
    // Nothing is sent again, and dismissing removes both files.
    let again = answered(page.call(
        "question_send_kept",
        json!({ "params": {
            "questionId": asked.to_string(),
            "draftedAtMs": standing[0]["draft"]["drafted_at_ms"].clone()
        } }),
    ))
    .await
    .expect("nothing is sent");
    assert_eq!(again["outcome"], "landed", "{again}");
    let kept = kept_store(&page, &worker);
    assert!(
        kept.drafts().expect("reads").len() == 1,
        "the copy stays shown until dismissed"
    );
    let which = json!({ "params": {
        "questionId": asked.to_string(),
        "draftedAtMs": standing[0]["draft"]["drafted_at_ms"].clone()
    } });
    assert_eq!(
        answered(page.call("question_dismiss_kept", which))
            .await
            .expect("dismissed"),
        json!(true)
    );
    assert!(kept.drafts().expect("reads").is_empty());
}

/// KR-ACC-009: after an answer whose outcome the worker could not establish, the worker refuses the
/// next answer of that actor until it names the uncertain send after being shown it. The application
/// shows the outcome first, on both its commands: an answer or a send that finds an uncertain send
/// the page was not shown sends nothing, and the press that names it is admitted by the worker.
#[tokio::test(flavor = "multi_thread")]
async fn an_uncertain_send_is_shown_before_the_application_names_it_to_the_worker() {
    let worker = worker().await;
    let page = Page::new(worker.temp.environment());
    let asked = ask(&worker, "uncertain", kr_ipc::now_ms().get(), 600_000);
    let listed = answered(page.call("question_read", read(&worker)))
        .await
        .expect("the questions");
    let revision = listed["questions"][0]["revision"]
        .as_str()
        .expect("a revision")
        .to_owned();
    let uncertain = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let mut client = owner(&worker).await;
    an_uncertain_answer(&worker, &mut client, asked, &revision, uncertain).await;
    record_pair(&page, &worker, asked, &revision, uncertain);

    // The worker refuses a send that does not name the uncertain one: a plain answer from another
    // actor path is the control.
    let refused = send_as(
        &mut client,
        &worker,
        asked,
        &revision,
        kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
    )
    .await
    .expect_err("an unquoted send is refused");
    assert_eq!(refused.code, kr_protocol::error::ErrorCode::DraftConflict);

    // Settling shows the uncertain send, and a send of the kept answer that was not shown it
    // sends nothing.
    let standing = answered(page.call("question_settle", settle(&worker)))
        .await
        .expect("the standing");
    assert_eq!(standing[0]["standing"], "offered", "{standing}");
    assert_eq!(standing[0]["earlier"][0]["state"], "unknown", "{standing}");
    let drafted = standing[0]["draft"]["drafted_at_ms"].clone();
    let unshown = answered(page.call(
        "question_send_kept",
        json!({ "params": { "questionId": asked.to_string(), "draftedAtMs": drafted } }),
    ))
    .await
    .expect_err("an unshown uncertain send stops the send");
    assert_eq!(code_of(&unshown), "DRAFT_CONFLICT", "{unshown}");
    assert_eq!(
        worker
            .service
            .questions()
            .question(asked)
            .expect("held")
            .state,
        kr_protocol::question::QuestionState::Pending,
        "nothing was sent"
    );

    // A new answer meets the same: it says so and sends nothing, and the press that carries the
    // identifier is admitted.
    let held = answered(page.call(
        "question_answer",
        json!({ "params": answer(&worker, asked, &revision, true)["params"].clone() }),
    ))
    .await
    .expect("held");
    assert_eq!(held["outcome"], "held", "{held}");
    assert_eq!(held["action_id"], uncertain.to_string());
    let taken = answered(page.call(
        "question_answer",
        json!({
            "params": answer(&worker, asked, &revision, true)["params"].clone(),
            "acknowledged": uncertain.to_string()
        }),
    ))
    .await
    .expect("the worker admits the quoted answer");
    assert_eq!(taken["outcome"], "taken", "{taken}");
}
