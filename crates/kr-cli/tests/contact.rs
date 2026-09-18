//! The contact tools against a real session, spoken as an installed agent speaks them.
//!
//! These are the KR-ACC-018 cases this layer can reach. The tool server is not called in-process:
//! it runs as the session's own root shell, with its standard streams on a pair of named pipes,
//! and the test talks to it with a Model Context Protocol client. That is what makes the binding
//! real — the helper is inside the session because the operating system says it is, not because
//! the test said so.
//!
//! Everything a test launches lives on the internal disk: the `kr` binary is copied there, the
//! host's runtime and state directories are a temporary tree there, and every working directory is
//! `/`. Nothing a launched process opens is on the workspace volume.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{BuildId, ControllerGeneration, SessionEpoch, SessionId};
use kr_protocol::scalars::TimestampMs;
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_protocol::worker::WorkerDescriptor;
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};
use rmcp::ServiceExt as _;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use serde_json::{Value, json};

/// A session whose root shell is the tool server, and the client talking to it.
struct Hosted {
    temp: kr_ipc::testing::TempHost,
    session_id: SessionId,
    descriptor: WorkerDescriptor,
    binary: PathBuf,
    client: RunningService<rmcp::RoleClient, ()>,
    _service: Arc<WorkerService>,
    _pipes: Pipes,
}

/// The two named pipes the tool server's standard streams are on.
struct Pipes {
    directory: PathBuf,
}

impl Drop for Pipes {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// Copies the command under test to the internal disk.
///
/// A launched binary on the workspace volume asks the operating system for permission the first
/// time it opens anything there, and a test that waited on that dialog would hang. The copy also
/// keeps every path the launched process touches off that volume.
fn internal_copy(name: &str, source: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("kr-contact-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&directory).expect("a directory on the internal disk");
    let destination = directory.join(name);
    std::fs::copy(source, &destination).expect("copies the command");
    let mut permissions = std::fs::metadata(&destination)
        .expect("the copy")
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&destination, permissions).expect("makes the copy runnable");
    destination
}

fn make_fifo(path: &Path) {
    let status = std::process::Command::new("/usr/bin/mkfifo")
        .arg(path)
        .status()
        .expect("creates a pipe");
    assert!(status.success(), "mkfifo {}", path.display());
}

/// Starts a session whose root shell is `kr agent-tools --stdio`, and connects to it.
async fn hosted() -> Hosted {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let display = DisplayNumber::new(1);
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
    // An in-memory store, not the platform keychain. These tests only need a controller key the
    // worker will check a generation token against, and writing one to the operating system's own
    // keychain would leave a credential behind and serialise every run behind that keychain's lock.
    let store = kr_crypto::store::MemoryStore::new();
    let controller = kr_ipc::verify::ControllerIdentity::initialise(&store, environment_id)
        .expect("a controller identity");

    let binary = internal_copy("kr", env!("CARGO_BIN_EXE_kr"));
    let directory = binary.parent().expect("a directory").to_path_buf();
    let to_server = directory.join("to-server");
    let from_server = directory.join("from-server");
    make_fifo(&to_server);
    make_fifo(&from_server);

    let runtime_root = temp.paths().runtime_root().display().to_string();
    let state_root = temp.paths().state_root().display().to_string();
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: display,
        // The root shell becomes the tool server, so the helper is the session's own process
        // rather than something beside it. Its standard streams are the two pipes this test holds.
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec![
                "-c".to_owned(),
                format!(
                    "exec {} agent-tools --stdio < {} > {}",
                    binary.display(),
                    to_server.display(),
                    from_server.display()
                ),
            ],
            cwd: "/".to_owned(),
            environment: vec![
                ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
                ("KR_RUNTIME_DIR".to_owned(), runtime_root.clone()),
                ("KR_STATE_DIR".to_owned(), state_root.clone()),
            ],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 256 * 1024,
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the tool server");
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
            .expect("starts the runtime"),
    );

    let endpoint = environment.worker_endpoint(display).expect("an endpoint");
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
                build_id: BuildId::new("kr-test/0").expect("a build identifier"),
                journal_path: Some(environment.journal_database(session_id)),
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));

    let descriptor = WorkerDescriptor {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: display,
        boot_identity: boot,
        process_start_identity: process,
        protocol_version: PROTOCOL_VERSION,
        endpoint: endpoint.as_text(),
        worker_public_key: *identity.public_key(),
        worker_profile: WorkerProfile::HeadlessUser,
        published_at_ms: TimestampMs::new(0),
    };
    kr_ipc::descriptor::publish(&environment, &descriptor).expect("publishes the descriptor");

    // Both ends of both pipes rendezvous. The server opens its input first and its output second,
    // so these two opens have to be waiting at the same time.
    let writer = tokio::task::spawn_blocking(move || {
        std::fs::OpenOptions::new()
            .write(true)
            .open(&to_server)
            .expect("opens the server's input")
    });
    let reader = tokio::task::spawn_blocking(move || {
        std::fs::File::open(&from_server).expect("opens the server's output")
    });
    let writer = tokio::time::timeout(Duration::from_secs(30), writer)
        .await
        .expect("the server opened its input")
        .expect("the open finished");
    let reader = tokio::time::timeout(Duration::from_secs(30), reader)
        .await
        .expect("the server opened its output")
        .expect("the open finished");

    let client = ()
        .serve((
            tokio::fs::File::from_std(reader),
            tokio::fs::File::from_std(writer),
        ))
        .await
        .expect("the tool server answered the handshake");

    Hosted {
        temp,
        session_id,
        descriptor,
        binary,
        client,
        _service: service,
        _pipes: Pipes { directory },
    }
}

impl Hosted {
    /// Calls one tool and returns its structured content.
    async fn call(&self, name: &str, arguments: Value) -> (Value, bool) {
        let result: CallToolResult = self
            .client
            .call_tool(
                CallToolRequestParams::new(name.to_owned())
                    .with_arguments(arguments.as_object().cloned().unwrap_or_default()),
            )
            .await
            .unwrap_or_else(|error| panic!("{name} answered: {error}"));
        let content = result
            .structured_content
            .clone()
            .unwrap_or_else(|| panic!("{name} returned structured content"));
        (content, result.is_error.unwrap_or_default())
    }

    /// Runs the command line against this host.
    fn kr(&self, arguments: &[&str]) -> std::process::Output {
        std::process::Command::new(&self.binary)
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env(
                "KR_RUNTIME_DIR",
                self.temp.paths().runtime_root().display().to_string(),
            )
            .env(
                "KR_STATE_DIR",
                self.temp.paths().state_root().display().to_string(),
            )
            .current_dir("/")
            .output()
            .expect("runs the command")
    }

    /// Connects to this session's worker as a local owner would.
    async fn worker(&self) -> kr_ipc::client::LocalClient {
        let endpoint =
            kr_ipc::paths::Endpoint::from_path(&self.descriptor.endpoint).expect("an endpoint");
        let mut client = kr_ipc::client::LocalClient::connect(
            &endpoint,
            kr_protocol::local::LocalClientKind::Cli,
            BuildId::new("kr-test/0").expect("a build identifier"),
        )
        .await
        .expect("reaches the worker");
        client
            .verify_worker(&self.descriptor)
            .await
            .expect("the worker proves itself");
        client
    }
}

/// The four tools, their schemas and nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn the_server_offers_exactly_the_four_contact_tools() {
    let hosted = hosted().await;
    let listing = hosted
        .client
        .list_tools(Default::default())
        .await
        .expect("lists its tools");
    let mut names: Vec<String> = listing
        .tools
        .iter()
        .map(|tool| tool.name.to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "ask_user".to_owned(),
            "cancel_question".to_owned(),
            "send_notification".to_owned(),
            "wait_for_answer".to_owned()
        ]
    );
    let ask = listing
        .tools
        .iter()
        .find(|tool| tool.name == "ask_user")
        .expect("ask_user");
    let schema = serde_json::to_value(&ask.input_schema).expect("a schema");
    let required = schema["required"].as_array().expect("required fields");
    for field in ["request_id", "context", "question", "type"] {
        assert!(
            required.iter().any(|name| name == field),
            "{field} is required"
        );
    }
    assert!(
        hosted
            .client
            .peer_info()
            .and_then(|info| info.instructions.clone())
            .is_some_and(|instructions| instructions.contains("never approval")),
        "the server says what an unanswered question is not"
    );
}

/// A select question, answered with the free-text option from the command line.
///
/// This is the scripted end-to-end run: the agent asks, a person answers `--other`, and the agent's
/// wait returns that free text as free text.
#[tokio::test(flavor = "multi_thread")]
async fn a_select_is_answered_with_free_text_and_the_agent_reads_it_as_free_text() {
    let hosted = hosted().await;
    let (created, failed) = hosted
        .call(
            "ask_user",
            json!({
                "request_id": "ask-1",
                "agent_name": "a test agent",
                "context": "two ways to do it",
                "question": "which one?",
                "type": "select",
                "choices": [
                    {"choice_id": "left", "label": "Left"},
                    {"choice_id": "right", "label": "Right"}
                ]
            }),
        )
        .await;
    assert!(!failed, "the question was created: {created}");
    assert_eq!(created["state"], "pending");
    let identifiers: Vec<&str> = created["choices"]
        .as_array()
        .expect("choices")
        .iter()
        .map(|choice| choice["choice_id"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(identifiers, vec!["left", "right", "something_else"]);
    let question_id = created["question_id"].as_str().expect("an identifier");
    let token = created["caller_token"].as_str().expect("a token");
    assert_eq!(token.len(), 64);

    // The local answer surface lists it, with the identity the host verified.
    let listed = hosted.kr(&["question", "list", "--json"]);
    assert!(listed.status.success(), "kr question list");
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("json");
    let first = &listed["questions"][0];
    assert_eq!(first["question_id"], question_id);
    assert_eq!(first["unverified_agent_label"], "a test agent");
    assert!(
        first["verified_source"]["executable"]
            .as_str()
            .is_some_and(|executable| executable.contains("kr")),
        "the verified source names the executable: {first}"
    );

    let answered = hosted.kr(&[
        "question",
        "answer",
        question_id,
        "--other",
        "neither, use the third way",
        "--json",
    ]);
    assert!(
        answered.status.success(),
        "kr question answer: {}",
        String::from_utf8_lossy(&answered.stderr)
    );

    let (waited, failed) = hosted
        .call(
            "wait_for_answer",
            json!({"question_id": question_id, "caller_token": token, "wait_seconds": 20}),
        )
        .await;
    assert!(!failed, "the wait answered: {waited}");
    assert_eq!(waited["state"], "answered");
    assert_eq!(waited["answer"]["kind"], "other");
    assert_eq!(waited["answer"]["text"], "neither, use the third way");
}

/// Text and yes-or-no, answered from the command line.
#[tokio::test(flavor = "multi_thread")]
async fn text_and_confirm_answers_reach_the_agent() {
    let hosted = hosted().await;
    let (created, _) = hosted
        .call(
            "ask_user",
            json!({
                "request_id": "ask-text",
                "context": "",
                "question": "what should it be called?",
                "type": "input"
            }),
        )
        .await;
    let question_id = created["question_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let token = created["caller_token"]
        .as_str()
        .expect("a token")
        .to_owned();
    assert!(
        hosted
            .kr(&["question", "answer", &question_id, "--text", "Kalareach"])
            .status
            .success()
    );
    let (waited, _) = hosted
        .call(
            "wait_for_answer",
            json!({"question_id": question_id, "caller_token": token, "wait_seconds": 20}),
        )
        .await;
    assert_eq!(waited["answer"]["kind"], "input");
    assert_eq!(waited["answer"]["text"], "Kalareach");

    let (created, _) = hosted
        .call(
            "ask_user",
            json!({
                "request_id": "ask-confirm",
                "context": "this cannot be undone",
                "question": "delete the branch?",
                "type": "confirm"
            }),
        )
        .await;
    let question_id = created["question_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let token = created["caller_token"]
        .as_str()
        .expect("a token")
        .to_owned();
    // A confirm always carries the free-text option, and the agent cannot remove it.
    assert_eq!(created["choices"][0]["choice_id"], "something_else");
    assert!(
        hosted
            .kr(&["question", "answer", &question_id, "--no"])
            .status
            .success()
    );
    let (waited, _) = hosted
        .call(
            "wait_for_answer",
            json!({"question_id": question_id, "caller_token": token, "wait_seconds": 20}),
        )
        .await;
    assert_eq!(waited["answer"]["kind"], "decision");
    assert_eq!(waited["answer"]["decided"], json!(false));
}

/// Two clients answering at once: one wins, and the other is told the question is resolved.
#[tokio::test(flavor = "multi_thread")]
async fn exactly_one_of_two_simultaneous_answers_wins() {
    let hosted = hosted().await;
    let (created, _) = hosted
        .call(
            "ask_user",
            json!({
                "request_id": "ask-race",
                "context": "",
                "question": "shall I?",
                "type": "confirm"
            }),
        )
        .await;
    let question_id: kr_protocol::ids::QuestionId = created["question_id"]
        .as_str()
        .expect("an identifier")
        .parse()
        .expect("a question identifier");

    let mut first = hosted.worker().await;
    let mut second = hosted.worker().await;
    let answer = |decided: bool| kr_protocol::question::QuestionAnswerParams {
        session_id: hosted.session_id,
        question_id,
        expected_revision: kr_protocol::ids::QuestionRevision::new(1),
        answer: kr_protocol::question::QuestionAnswer::Decision { decided },
    };
    let target = kr_protocol::envelope::ActionTarget {
        environment_id: hosted.descriptor.environment_id,
        session_id: kr_protocol::scalars::Nullable::some(hosted.session_id),
        session_epoch: kr_protocol::scalars::Nullable::some(SessionEpoch::V1),
        application_instance_id: kr_protocol::scalars::Nullable::null(),
        agent_binding_revision: kr_protocol::scalars::Nullable::null(),
    };
    let yes = answer(true);
    let no = answer(false);
    let (left, right) = tokio::join!(
        first.mutate(
            kr_protocol::method::Method::QuestionAnswer,
            kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &yes,
        ),
        second.mutate(
            kr_protocol::method::Method::QuestionAnswer,
            kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            target,
            &no,
        ),
    );
    let outcomes = [
        left.expect("reaches the worker"),
        right.expect("reaches the worker"),
    ];
    let winners = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
    assert_eq!(winners, 1, "exactly one answer won: {outcomes:?}");
    let loser = outcomes
        .iter()
        .find_map(|outcome| outcome.as_ref().err())
        .expect("one answer lost");
    assert_eq!(
        loser.code,
        kr_protocol::error::ErrorCode::QuestionResolved,
        "the loser is told the question is resolved"
    );
}

/// The same request identifier, twice, and then with different words.
#[tokio::test(flavor = "multi_thread")]
async fn an_exact_retry_is_the_same_question_and_a_changed_one_is_a_conflict() {
    let hosted = hosted().await;
    let payload = json!({
        "request_id": "ask-idempotent",
        "context": "",
        "question": "shall I?",
        "type": "confirm"
    });
    let (first, _) = hosted.call("ask_user", payload.clone()).await;
    let (second, failed) = hosted.call("ask_user", payload).await;
    assert!(!failed);
    assert_eq!(first["question_id"], second["question_id"]);
    assert_eq!(first["caller_token"], second["caller_token"]);
    assert_eq!(second["deduplicated"], json!(true));

    let (conflict, failed) = hosted
        .call(
            "ask_user",
            json!({
                "request_id": "ask-idempotent",
                "context": "",
                "question": "shall I really?",
                "type": "confirm"
            }),
        )
        .await;
    assert!(failed, "a changed payload is refused: {conflict}");
    assert_eq!(conflict["code"], "ID_CONFLICT");
}

/// Cancelling a question, and then cancelling it again.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_question_stays_cancelled() {
    let hosted = hosted().await;
    let (created, _) = hosted
        .call(
            "ask_user",
            json!({
                "request_id": "ask-cancel",
                "context": "",
                "question": "shall I?",
                "type": "confirm"
            }),
        )
        .await;
    let question_id = created["question_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let token = created["caller_token"]
        .as_str()
        .expect("a token")
        .to_owned();
    let (cancelled, failed) = hosted
        .call(
            "cancel_question",
            json!({"question_id": question_id, "caller_token": token}),
        )
        .await;
    assert!(!failed, "the question was cancelled: {cancelled}");
    assert_eq!(cancelled["state"], "cancelled");

    let (again, failed) = hosted
        .call(
            "cancel_question",
            json!({"question_id": question_id, "caller_token": token}),
        )
        .await;
    assert!(failed, "a second cancellation changes nothing: {again}");
    assert_eq!(again["code"], "QUESTION_RESOLVED");

    // And a person cannot answer it either.
    let answered = hosted.kr(&["question", "answer", &question_id, "--yes"]);
    assert!(!answered.status.success());
}

/// A token from one question does not reach another.
#[tokio::test(flavor = "multi_thread")]
async fn a_token_reaches_only_the_question_it_was_issued_for() {
    let hosted = hosted().await;
    let (first, _) = hosted
        .call(
            "ask_user",
            json!({"request_id": "ask-a", "context": "", "question": "a?", "type": "confirm"}),
        )
        .await;
    let (second, _) = hosted
        .call(
            "ask_user",
            json!({"request_id": "ask-b", "context": "", "question": "b?", "type": "confirm"}),
        )
        .await;
    let (refused, failed) = hosted
        .call(
            "wait_for_answer",
            json!({
                "question_id": second["question_id"],
                "caller_token": first["caller_token"],
                "wait_seconds": 1
            }),
        )
        .await;
    assert!(failed, "the wrong token is refused: {refused}");
    assert_eq!(refused["code"], "PERMISSION_DENIED");
}

/// An alert, which asks for nothing and de-duplicates on its own identifier.
#[tokio::test(flavor = "multi_thread")]
async fn a_notification_asks_for_nothing_and_repeats_nothing() {
    let hosted = hosted().await;
    let payload = json!({
        "dedup_id": "build-failed",
        "agent_name": "a test agent",
        "text": "the build failed",
        "severity": "warning"
    });
    let (first, failed) = hosted.call("send_notification", payload.clone()).await;
    assert!(!failed, "the alert was raised: {first}");
    assert_eq!(first["deduplicated"], json!(false));
    assert_eq!(first["severity"], "warning");
    let (second, _) = hosted.call("send_notification", payload).await;
    assert_eq!(second["deduplicated"], json!(true));
    assert_eq!(first["created_at_ms"], second["created_at_ms"]);

    // An alert is not a question: nothing is waiting for an answer.
    let listed = hosted.kr(&["question", "list", "--json"]);
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("json");
    assert!(
        listed["questions"]
            .as_array()
            .expect("questions")
            .is_empty()
    );
}

/// A wait that runs out returns the same pending question, and nothing is recreated.
#[tokio::test(flavor = "multi_thread")]
async fn a_wait_that_times_out_returns_the_same_question() {
    let hosted = hosted().await;
    let (created, _) = hosted
        .call(
            "ask_user",
            json!({
                "request_id": "ask-wait",
                "context": "",
                "question": "shall I?",
                "type": "confirm",
                "wait_seconds": 1
            }),
        )
        .await;
    assert_eq!(created["state"], "pending");
    let (waited, failed) = hosted
        .call(
            "wait_for_answer",
            json!({
                "question_id": created["question_id"],
                "caller_token": created["caller_token"],
                "wait_seconds": 1
            }),
        )
        .await;
    assert!(!failed);
    assert_eq!(waited["question_id"], created["question_id"]);
    assert_eq!(waited["state"], "pending");
    assert_eq!(waited["revision"], created["revision"]);

    let listed = hosted.kr(&["question", "list", "--json"]);
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("json");
    assert_eq!(
        listed["questions"].as_array().expect("questions").len(),
        1,
        "a wait creates nothing"
    );
}

/// Outside a session, every tool refuses and creates nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_helper_outside_a_session_is_told_how_to_get_into_one() {
    // A host tree with a live session in it, and a tool server that is not inside that session:
    // it is a child of this test rather than of the session's own shell.
    let hosted = hosted().await;
    let mut command = tokio::process::Command::new(&hosted.binary);
    command
        .arg("agent-tools")
        .arg("--stdio")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(
            "KR_RUNTIME_DIR",
            hosted.temp.paths().runtime_root().display().to_string(),
        )
        .env(
            "KR_STATE_DIR",
            hosted.temp.paths().state_root().display().to_string(),
        )
        // Even told which session to look at, it is not in one.
        .env("KR_SESSION", hosted.session_id.to_string())
        .current_dir("/");
    let outside =
        ().serve(rmcp::transport::TokioChildProcess::new(command).expect("starts the tool server"))
            .await
            .expect("the tool server answered the handshake");
    let result = outside
        .call_tool(
            CallToolRequestParams::new("ask_user").with_arguments(
                json!({
                    "request_id": "ask-outside",
                    "context": "",
                    "question": "shall I?",
                    "type": "confirm"
                })
                .as_object()
                .cloned()
                .expect("an object"),
            ),
        )
        .await
        .expect("the tool answered");
    let content = result.structured_content.expect("structured content");
    assert_eq!(result.is_error, Some(true));
    assert_eq!(content["code"], "NOT_IN_KR_SESSION");
    assert!(
        content["setup"]
            .as_str()
            .is_some_and(|setup| setup.contains("kr new --attach")),
        "the refusal says how to get into a session: {content}"
    );
    let _ = outside.cancel().await;

    // And nothing was created in the session that does exist.
    let listed = hosted.kr(&["question", "list", "--json"]);
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("json");
    assert!(
        listed["questions"]
            .as_array()
            .expect("questions")
            .is_empty()
    );
}
