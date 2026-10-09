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
    temp: kr_ipc::testing::TempHost,
    session_id: SessionId,
    service: Arc<WorkerService>,
    serving: tokio::task::JoinHandle<kr_worker::Result<()>>,
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
