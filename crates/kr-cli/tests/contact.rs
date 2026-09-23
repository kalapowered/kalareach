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
///
/// The host tree is shared, so a second session can be started in the same environment.
struct Hosted {
    temp: Arc<kr_ipc::testing::TempHost>,
    session_id: SessionId,
    descriptor: WorkerDescriptor,
    journal: PathBuf,
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
    kr_ipc::testing::place_program(Path::new(source), &destination);
    destination
}

fn make_fifo(path: &Path) {
    let status = std::process::Command::new("/usr/bin/mkfifo")
        .arg(path)
        .status()
        .expect("creates a pipe");
    assert!(status.success(), "mkfifo {}", path.display());
}

/// What a session's root shell runs: the words of one command, and what it adds to the
/// environment.
struct Root {
    command: Vec<String>,
    environment: Vec<(String, String)>,
}

/// Quotes one word for the POSIX shell that starts the root command.
fn quoted(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// Starts a session whose root shell is `kr agent-tools --stdio`, and connects to it.
async fn hosted() -> Hosted {
    hosted_with(|binary| Root {
        command: vec![
            binary.display().to_string(),
            "agent-tools".to_owned(),
            "--stdio".to_owned(),
        ],
        environment: Vec::new(),
    })
    .await
}

/// Starts a session whose root shell runs the command `root` names for the copied `kr`, with its
/// standard streams on a pair of named pipes, and connects to it.
async fn hosted_with(root: impl FnOnce(&Path) -> Root) -> Hosted {
    session_in(
        Arc::new(kr_ipc::testing::TempHost::create()),
        DisplayNumber::new(1),
        root,
    )
    .await
}

/// Starts another session in the host tree and the environment `first` is in, under its own
/// display number, and connects to its tool server.
async fn beside(first: &Hosted, display: u64, root: impl FnOnce(&Path) -> Root) -> Hosted {
    session_in(Arc::clone(&first.temp), DisplayNumber::new(display), root).await
}

/// Starts one session in `temp`, whose root shell runs the command `root` names for the copied
/// `kr` with its standard streams on a pair of named pipes, and connects to it.
async fn session_in(
    temp: Arc<kr_ipc::testing::TempHost>,
    display: DisplayNumber,
    root: impl FnOnce(&Path) -> Root,
) -> Hosted {
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
    let root = root(&binary);
    let command: Vec<String> = root.command.iter().map(|word| quoted(word)).collect();
    let mut variables = vec![
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ("KR_RUNTIME_DIR".to_owned(), runtime_root.clone()),
        ("KR_STATE_DIR".to_owned(), state_root.clone()),
    ];
    variables.extend(root.environment);
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
                    "exec {} < {} > {}",
                    command.join(" "),
                    to_server.display(),
                    from_server.display()
                ),
            ],
            cwd: "/".to_owned(),
            environment: variables,
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 256 * 1024,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
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
        journal: environment.journal_database(session_id),
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
    // KR-REQ-11.52: the helper in the session serves exactly `ask_user`, `wait_for_answer`,
    // `cancel_question` and `send_notification`.
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
    // KR-REQ-01.18: an agent asks through the tools and reads the person's answer.
    // KR-REQ-11.59: a select carries "Something else" after its choices, and the free-text answer
    // reaches the agent as free text.
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
    // KR-REQ-01.18: text and yes-or-no answers reach the agent that asked.
    // KR-REQ-11.59: a confirm carries "Something else", which the agent cannot remove.
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
    // KR-REQ-11.60: two clients answer at once through the worker; the first answer wins
    // atomically, the other is told the question is resolved, and the answer stored is the
    // winner's.
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

    // What the journal holds is the answer whose call succeeded: the one that was turned away wrote
    // nothing, before its refusal or after it.
    let decided = outcomes[0].is_ok();
    let stored = ledger(&hosted).read(question_id).expect("the question");
    assert_eq!(stored.state, kr_protocol::question::QuestionState::Answered);
    assert_eq!(
        stored.answer.as_ref().map(|record| record.answer.clone()),
        Some(kr_protocol::question::QuestionAnswer::Decision { decided }),
        "the stored answer is the winner's"
    );
}

/// The same request identifier, twice, and then with different words.
#[tokio::test(flavor = "multi_thread")]
async fn an_exact_retry_is_the_same_question_and_a_changed_one_is_a_conflict() {
    // KR-REQ-11.55: an exact idempotent retry returns the same question and the same token to the
    // verified source.
    // KR-REQ-11.58: a changed payload under the same request identifier is `ID_CONFLICT`.
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
    // KR-REQ-11.56: the caller token a cancellation carries is in neither the journal nor its
    // write-ahead log.
    // KR-REQ-11.60: cancellation is a terminal state: cancelling again and answering afterwards
    // both change nothing.
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

    // A cancellation carries the caller token in its parameters, and the journal keeps every
    // mutation's intent. Section 11 keeps that token out of every durable record but the ledger's
    // own sealed copy, so it must not be anywhere in the journal or its write-ahead log.
    let token_bytes: Vec<u8> = (0..token.len() / 2)
        .map(|index| u8::from_str_radix(&token[index * 2..index * 2 + 2], 16).expect("hexadecimal"))
        .collect();
    for suffix in ["", "-wal", "-shm"] {
        let path = PathBuf::from(format!("{}{suffix}", hosted.journal.display()));
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        assert!(
            !bytes
                .windows(token_bytes.len())
                .any(|window| window == token_bytes.as_slice()),
            "the caller token is not in {}",
            path.display()
        );
    }

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
/// KR-REQ-23.31: a private question method checks the caller token of the question it names.
#[tokio::test(flavor = "multi_thread")]
async fn a_token_reaches_only_the_question_it_was_issued_for() {
    // KR-REQ-11.58: a wait needs the question's own caller token.
    // KR-REQ-11.63: another question's token retrieves nothing about this one.
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
    // KR-REQ-01.18: an agent raises an alert through the tools.
    // KR-REQ-11.65: an alert is raised with its severity, asks for nothing, creates no question,
    // and a repeat under its de-duplication identifier raises nothing new.
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
    // KR-REQ-11.55: a creation that waits returns the pending question when nobody answers, and a
    // wait timeout preserves it.
    // KR-REQ-11.57: a wait that runs out returns the same question at the same revision and
    // creates nothing.
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
/// KR-REQ-23.31: a helper the host cannot verify as inside the session is refused, whatever it
/// claims about the session.
/// KR-REQ-05.09: `KR_SESSION` names a candidate and is no credential: a helper told the identity of
/// a live session that it is not running inside is refused, and nothing is created there.
#[tokio::test(flavor = "multi_thread")]
async fn a_helper_outside_a_session_is_told_how_to_get_into_one() {
    // KR-REQ-11.53: outside a KR session every tool answers `NOT_IN_KR_SESSION` with the
    // `kr new --attach` setup instruction and creates nothing.
    // KR-REQ-11.52: a session named in the environment is a lookup hint, not a binding: a process
    // the kernel does not place inside the session is refused.
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

    // Every one of the four tools, each with arguments that would otherwise be accepted.
    let token = "ab".repeat(kr_protocol::question::CALLER_TOKEN_BYTES);
    let question = kr_ipc::new_uuid().to_string();
    for (tool, arguments) in [
        (
            "ask_user",
            json!({
                "request_id": "ask-outside",
                "context": "",
                "question": "shall I?",
                "type": "confirm"
            }),
        ),
        (
            "wait_for_answer",
            json!({"question_id": question, "caller_token": token, "wait_seconds": 1}),
        ),
        (
            "cancel_question",
            json!({"question_id": question, "caller_token": token}),
        ),
        (
            "send_notification",
            json!({"dedup_id": "outside", "text": "done", "severity": "info"}),
        ),
    ] {
        let result = outside
            .call_tool(
                CallToolRequestParams::new(tool)
                    .with_arguments(arguments.as_object().cloned().expect("an object")),
            )
            .await
            .unwrap_or_else(|error| panic!("{tool} answered: {error}"));
        let content = result.structured_content.expect("structured content");
        assert_eq!(result.is_error, Some(true), "{tool}: {content}");
        assert_eq!(content["code"], "NOT_IN_KR_SESSION", "{tool}: {content}");
        assert!(
            content["setup"]
                .as_str()
                .is_some_and(|setup| setup.contains("kr new --attach")),
            "{tool}: the refusal says how to get into a session: {content}"
        );
    }
    let _ = outside.cancel().await;

    // And nothing was created in the session that does exist: no question, no alert and nothing in
    // the feed the inbox and notifications are built from.
    let listed = hosted.kr(&["question", "list", "--include-resolved", "--json"]);
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("json");
    assert!(
        listed["questions"]
            .as_array()
            .expect("questions")
            .is_empty()
    );
    let journal = ledger(&hosted);
    assert!(journal.list(true).expect("the ledger lists").is_empty());
    assert!(journal.alerts().expect("the alerts read").is_empty());
    assert!(
        journal
            .events_since(0, 64)
            .expect("the feed reads")
            .is_empty()
    );
}

/// KR-REQ-11.54, KR-REQ-19.07: a helper reaches the session it runs in and no other. Two sessions
/// share one environment; the second session's helper is told the first session's identity in its
/// environment and handed the first session's question and caller token, and still every call it
/// makes lands in its own session: its question and its alert are its own session's, and it can
/// neither read, wait on nor cancel the first session's question, which stays pending and is still
/// the first helper's to read.
#[tokio::test(flavor = "multi_thread")]
async fn a_helper_reaches_only_the_session_it_runs_in() {
    let first = hosted().await;
    let (asked_first, failed) = first
        .call(
            "ask_user",
            json!({
                "request_id": "first-session",
                "context": "",
                "question": "shall I?",
                "type": "confirm"
            }),
        )
        .await;
    assert!(!failed, "{asked_first}");
    let first_question = asked_first["question_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let first_token = asked_first["caller_token"]
        .as_str()
        .expect("a token")
        .to_owned();

    // The second session's helper is told the first session's identity: a hint, not a binding.
    let hint = first.session_id.to_string();
    let second = beside(&first, 2, move |binary| Root {
        command: vec![
            binary.display().to_string(),
            "agent-tools".to_owned(),
            "--stdio".to_owned(),
        ],
        environment: vec![("KR_SESSION".to_owned(), hint)],
    })
    .await;
    assert_ne!(first.session_id, second.session_id);

    let (asked_second, failed) = second
        .call(
            "ask_user",
            json!({
                "request_id": "second-session",
                "context": "",
                "question": "and shall I?",
                "type": "confirm"
            }),
        )
        .await;
    assert!(!failed, "{asked_second}");
    assert_eq!(
        asked_second["session_id"],
        second.session_id.to_string(),
        "the question is the session's the helper runs in, whatever the hint named"
    );
    let (alerted, failed) = second
        .call(
            "send_notification",
            json!({"dedup_id": "second-alert", "text": "done", "severity": "info"}),
        )
        .await;
    assert!(!failed, "{alerted}");
    assert_eq!(alerted["session_id"], second.session_id.to_string());

    // Holding the first session's question and its token, the second helper gets nothing of it.
    for (tool, arguments) in [
        (
            "wait_for_answer",
            json!({"question_id": first_question, "caller_token": first_token, "wait_seconds": 1}),
        ),
        (
            "cancel_question",
            json!({"question_id": first_question, "caller_token": first_token}),
        ),
    ] {
        let (refused, failed) = second.call(tool, arguments).await;
        assert!(
            failed,
            "{tool} reached another session's question: {refused}"
        );
        assert_eq!(refused["code"], "PERMISSION_DENIED", "{tool}: {refused}");
        assert!(
            refused.get("state").is_none() && refused.get("answer").is_none(),
            "{tool} told another session's helper about the question: {refused}"
        );
    }

    // Each session holds exactly what its own helper created, and the first question is untouched.
    let first_ledger = ledger(&first);
    let held: Vec<(String, kr_protocol::question::QuestionState)> = first_ledger
        .list(true)
        .expect("the first ledger lists")
        .into_iter()
        .map(|question| (question.question_id.to_string(), question.state))
        .collect();
    assert_eq!(
        held,
        [(
            first_question.clone(),
            kr_protocol::question::QuestionState::Pending
        )]
    );
    assert!(first_ledger.alerts().expect("the alerts read").is_empty());
    let second_ledger = ledger(&second);
    let held: Vec<String> = second_ledger
        .list(true)
        .expect("the second ledger lists")
        .into_iter()
        .map(|question| question.question_id.to_string())
        .collect();
    assert_eq!(
        held,
        [asked_second["question_id"]
            .as_str()
            .expect("an identifier")
            .to_owned()]
    );
    assert_eq!(second_ledger.alerts().expect("the alerts read").len(), 1);

    // The first helper still reads its own question with its own token.
    let (own, failed) = first
        .call(
            "wait_for_answer",
            json!({"question_id": first_question, "caller_token": first_token, "wait_seconds": 1}),
        )
        .await;
    assert!(!failed, "{own}");
    assert_eq!(own["state"], "pending");
}

/// Runs `kr` against a host tree, from a task that does not hold the hosted session.
fn kr_against(
    binary: &Path,
    runtime_root: &Path,
    state_root: &Path,
    arguments: &[&str],
) -> std::process::Output {
    std::process::Command::new(binary)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("KR_RUNTIME_DIR", runtime_root)
        .env("KR_STATE_DIR", state_root)
        .current_dir("/")
        .output()
        .expect("runs the command")
}

/// Reads this session's question ledger through a connection of its own, as a restarted worker
/// would.
fn ledger(hosted: &Hosted) -> kr_worker::questions::store::Store {
    kr_worker::questions::store::Store::open(
        Some(&hosted.journal),
        hosted.session_id,
        SessionEpoch::V1,
    )
    .expect("a second connection to the journal")
}

/// KR-REQ-01.18, KR-REQ-11.66: the skill installs, and the tool server its installation registers
/// in the agent's own configuration is the one the agent runs: started from that entry inside a
/// session, it asks the person a question, returns the answer they gave and raises an alert. The
/// host has no account, no managed service and no entitlement configured.
#[tokio::test(flavor = "multi_thread")]
async fn an_installed_skill_asks_returns_the_answer_and_raises_an_alert() {
    let home = tempfile::tempdir().expect("a home directory on the internal disk");
    let state = tempfile::tempdir().expect("a state directory on the internal disk");
    let home_path = home.path().to_path_buf();
    let records = state.path().join("agent-tools");
    let hosted = hosted_with(|binary| {
        let installer = kr_controller::agent_tools::Installer::new(
            home_path.clone(),
            records.clone(),
            binary.display().to_string(),
        );
        let installed = installer
            .install(&kr_protocol::skill::AgentToolsParams {
                agent: kr_protocol::skill::AgentTarget::ClaudeCode,
                scope: kr_protocol::skill::InstallScope::User,
                project_dir: kr_protocol::scalars::Nullable::null(),
            })
            .expect("the skill installs");
        assert!(!installed.already_installed);
        let skill = home_path.join(".claude/skills/kalareach-contact");
        for file in ["SKILL.md", "TOOLS.md", "manifest.json"] {
            assert!(skill.join(file).is_file(), "{file} is installed");
        }
        let configuration: Value = serde_json::from_str(
            &std::fs::read_to_string(home_path.join(".claude.json"))
                .expect("the agent's configuration"),
        )
        .expect("JSON");
        let entry = &configuration["mcpServers"]["kalareach"];
        let mut command = vec![entry["command"].as_str().expect("a command").to_owned()];
        command.extend(
            entry["args"]
                .as_array()
                .expect("its arguments")
                .iter()
                .map(|word| word.as_str().expect("a word").to_owned()),
        );
        assert_eq!(command[1..], ["agent-tools", "--stdio"]);
        let environment = entry["env"]
            .as_object()
            .map(|variables| {
                variables
                    .iter()
                    .map(|(name, value)| {
                        (name.clone(), value.as_str().expect("a value").to_owned())
                    })
                    .collect()
            })
            .unwrap_or_default();
        Root {
            command,
            environment,
        }
    })
    .await;

    let (created, failed) = hosted
        .call(
            "ask_user",
            json!({
                "request_id": "installed-ask",
                "agent_name": "an installed agent",
                "context": "the release branch is ready",
                "question": "tag it now?",
                "type": "confirm"
            }),
        )
        .await;
    assert!(!failed, "the installed server asked: {created}");
    let question_id = created["question_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let token = created["caller_token"]
        .as_str()
        .expect("a token")
        .to_owned();
    let answered = hosted.kr(&["question", "answer", &question_id, "--yes"]);
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
    assert_eq!(
        waited["answer"],
        json!({"kind": "decision", "decided": true})
    );

    let (alerted, failed) = hosted
        .call(
            "send_notification",
            json!({
                "dedup_id": "release-tagged",
                "agent_name": "an installed agent",
                "text": "the release is tagged",
                "severity": "info"
            }),
        )
        .await;
    assert!(!failed, "the installed server raised an alert: {alerted}");
    assert_eq!(alerted["deduplicated"], json!(false));
    let listed = hosted.kr(&["question", "list", "--include-resolved", "--json"]);
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("json");
    assert_eq!(
        listed["questions"].as_array().expect("questions").len(),
        1,
        "the alert asked nothing"
    );
}

/// KR-REQ-11.52: the tool server is bound to the session by what the kernel reports about the
/// process at the other end of the worker's socket, not by anything it sends: the question it
/// created names that process with the start value the kernel records for it now, inside the
/// session's own boundary, running the `kr` this test launched; the name the caller gave itself is
/// kept apart as an unverified label.
#[tokio::test(flavor = "multi_thread")]
async fn the_helper_is_bound_to_its_own_process_and_its_start_time() {
    let hosted = hosted().await;
    let (created, failed) = hosted
        .call(
            "ask_user",
            json!({
                "request_id": "bound",
                "agent_name": "the host itself",
                "context": "",
                "question": "shall I?",
                "type": "confirm"
            }),
        )
        .await;
    assert!(!failed, "{created}");
    let question_id: kr_protocol::ids::QuestionId = created["question_id"]
        .as_str()
        .expect("an identifier")
        .parse()
        .expect("a question identifier");

    let mut worker = hosted.worker().await;
    let read: kr_protocol::question::QuestionReadResult = worker
        .request(
            kr_protocol::method::Method::QuestionRead,
            &kr_protocol::question::QuestionReadParams {
                session_id: hosted.session_id,
                question_id: kr_protocol::scalars::Nullable::some(question_id),
                include_resolved: false,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("the question reads")
        .to_typed()
        .expect("decodes");
    let source = &read.questions[0].source;
    let pid = u32::try_from(source.process.pid.get()).expect("a process identifier");
    assert_eq!(
        kr_ipc::identity::process_start_identity(pid).expect("the kernel names the process"),
        source.process,
        "the recorded identity is the live process, start value and all"
    );
    assert!(
        source.session_member,
        "the process is inside the session's boundary"
    );
    let executable = std::fs::canonicalize(
        source
            .executable
            .as_ref()
            .expect("the platform names the executable"),
    )
    .expect("the executable exists");
    assert_eq!(
        executable,
        std::fs::canonicalize(&hosted.binary).expect("the launched binary"),
        "the bound process runs the tool server this test launched"
    );
    assert_eq!(
        source.agent_label.as_ref().map(String::as_str),
        Some("the host itself"),
        "the caller's own name is a label beside the identity, not the identity"
    );
}

/// KR-REQ-11.55: `ask_user` returns, over the tool server's own standard streams, a durable
/// question: its identifier, revision, state and expiry, with a 32-byte caller token; a creation
/// that waits returns the question still pending when nobody answers; and the worker's journal,
/// read through a connection of its own, holds that question with a keyed tag and a sealed copy of
/// the token, never the token.
#[tokio::test(flavor = "multi_thread")]
async fn ask_user_returns_a_durable_question_and_its_token_over_the_helpers_own_streams() {
    let hosted = hosted().await;
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_millis() as u64;
    let (created, failed) = hosted
        .call(
            "ask_user",
            json!({
                "request_id": "durable",
                "context": "",
                "question": "shall I?",
                "type": "confirm",
                "wait_seconds": 1
            }),
        )
        .await;
    assert!(!failed, "{created}");
    assert_eq!(
        created["state"], "pending",
        "the wait ran out and the question stands"
    );
    assert_eq!(created["revision"], json!(1));
    let expires = created["expires_at_ms"].as_u64().expect("an expiry");
    assert!(
        expires > before && expires <= before + 24 * 60 * 60 * 1000 + 60_000,
        "expires at {expires}, created after {before}"
    );
    let token = created["caller_token"].as_str().expect("a token");
    assert_eq!(token.len(), 64, "32 bytes, in hexadecimal");
    let token: Vec<u8> = (0..32)
        .map(|index| u8::from_str_radix(&token[index * 2..index * 2 + 2], 16).expect("hexadecimal"))
        .collect();
    let question_id: kr_protocol::ids::QuestionId = created["question_id"]
        .as_str()
        .expect("an identifier")
        .parse()
        .expect("a question identifier");

    let ledger = ledger(&hosted);
    let stored = ledger.read(question_id).expect("the question is on disk");
    assert_eq!(stored.state, kr_protocol::question::QuestionState::Pending);
    assert_eq!(stored.revision.get(), 1);
    let row = ledger.read_row(question_id).expect("its row");
    assert_eq!(row.token_tag.len(), 32);
    assert_ne!(row.token_tag, token);
    assert!(
        !row.token_sealed
            .windows(token.len())
            .any(|window| window == token.as_slice()),
        "the sealed copy is not the token"
    );
}

/// KR-REQ-11.57: one `wait_for_answer` call, under an installed client's qualified deadline that
/// allows a long poll, stays open for longer than one renewal interval of the host's wait and
/// returns the answer as soon as a person gives it; while it is open, a truncating checkpoint from
/// another connection completes, so no connection holds a transaction on the session's journal at
/// that moment; and a wait that runs out returns the same question and neither recreates it nor
/// records a second creation to notify anybody about. Whether the tool server renews bounded
/// broker waits inside the call, and whether each wait holds only a subscription, cannot be seen
/// from outside the worker, and this test claims neither.
#[tokio::test(flavor = "multi_thread")]
async fn one_long_wait_stays_open_and_returns_the_answer_when_it_comes() {
    // The installation declared a qualified client deadline of four minutes, so a long poll is not
    // cut to the short wait an unqualified client gets.
    let hosted = hosted_with(|binary| Root {
        command: vec![
            binary.display().to_string(),
            "agent-tools".to_owned(),
            "--stdio".to_owned(),
        ],
        environment: vec![("KR_TOOL_DEADLINE_MS".to_owned(), "240000".to_owned())],
    })
    .await;
    let ask = |request_id: &str, expiry_seconds: Option<u64>| {
        let mut arguments = json!({
            "request_id": request_id,
            "context": "",
            "question": format!("shall I ({request_id})?"),
            "type": "confirm"
        });
        if let Some(seconds) = expiry_seconds {
            arguments["expiry_seconds"] = json!(seconds);
        }
        arguments
    };
    let (created, _) = hosted.call("ask_user", ask("long-wait", None)).await;
    let question_id = created["question_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let token = created["caller_token"]
        .as_str()
        .expect("a token")
        .to_owned();

    let (timed_out, failed) = hosted
        .call(
            "wait_for_answer",
            json!({"question_id": question_id, "caller_token": token, "wait_seconds": 1}),
        )
        .await;
    assert!(!failed, "{timed_out}");
    assert_eq!(timed_out["state"], "pending");
    assert_eq!(timed_out["question_id"], created["question_id"]);
    assert_eq!(timed_out["revision"], created["revision"]);

    // Two more questions from the same helper, due to expire ten and thirty seconds from now. The
    // host's wait expires whatever falls due while the call below is open, so the markers' expiries
    // are moments the test can wait for without a timer of its own.
    let (first_marker, _) = hosted
        .call("ask_user", ask("expires-first", Some(10)))
        .await;
    let (second_marker, _) = hosted
        .call("ask_user", ask("expires-second", Some(30)))
        .await;
    let first_marker = first_marker["question_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let second_marker = second_marker["question_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();

    // An observer watches the journal through a connection of its own. Once the first marker has
    // expired, a truncating checkpoint runs: it cannot complete while any connection holds a read
    // or a write transaction. Once the second marker has expired, a person answers, and only while
    // the call is still waiting.
    let waiting = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let still_waiting = Arc::clone(&waiting);
    let journal = hosted.journal.clone();
    let session_id = hosted.session_id;
    let binary = hosted.binary.clone();
    let runtime_root = hosted.temp.paths().runtime_root().to_path_buf();
    let state_root = hosted.temp.paths().state_root().to_path_buf();
    let answering = question_id.clone();
    let observer = tokio::task::spawn_blocking(move || {
        let store =
            kr_worker::questions::store::Store::open(Some(&journal), session_id, SessionEpoch::V1)
                .expect("a connection of the observer's own");
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        let expired_at = |marker: &str| -> u64 {
            loop {
                let expired = store
                    .events_since(0, 256)
                    .expect("the feed reads")
                    .into_iter()
                    .find(|(_, event)| {
                        event.kind == kr_protocol::question::QuestionEventKind::Expired
                            && event.question.question_id.to_string() == marker
                    })
                    .map(|(_, event)| event.recorded_at_ms.get());
                if let Some(at) = expired {
                    return at;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "the marker did not expire while the call was waiting"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        };

        let first_wait = expired_at(&first_marker);
        let connection = rusqlite::Connection::open_with_flags(
            &journal,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )
        .expect("a connection of the test's own");
        connection
            .busy_timeout(Duration::ZERO)
            .expect("no waiting on a lock");
        let mut checkpointed_at = None;
        for _ in 0..40 {
            let (busy, _, _): (i64, i64, i64) = connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .expect("the checkpoint runs");
            if busy == 0 {
                checkpointed_at = Some(kr_ipc::now_ms().get());
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let checkpointed_while_waiting = still_waiting.load(std::sync::atomic::Ordering::SeqCst);

        let second_wait = expired_at(&second_marker);
        let in_flight = still_waiting.load(std::sync::atomic::Ordering::SeqCst);
        let answered = kr_against(
            &binary,
            &runtime_root,
            &state_root,
            &["question", "answer", &answering, "--yes"],
        );
        (
            first_wait,
            checkpointed_at,
            checkpointed_while_waiting,
            second_wait,
            in_flight,
            answered,
        )
    });

    let started = std::time::Instant::now();
    let (waited, failed) = hosted
        .call(
            "wait_for_answer",
            json!({"question_id": question_id, "caller_token": token, "wait_seconds": 150}),
        )
        .await;
    waiting.store(false, std::sync::atomic::Ordering::SeqCst);
    let elapsed = started.elapsed();
    let (first_wait, checkpointed_at, checkpointed_while_waiting, second_wait, in_flight, answered) =
        observer.await.expect("the observer ran");
    eprintln!(
        "markers expired at {first_wait} and {second_wait}; checkpoint at {checkpointed_at:?}; \
         the call returned after {elapsed:?}"
    );

    assert!(
        answered.status.success(),
        "the answer was written during the wait: {}",
        String::from_utf8_lossy(&answered.stderr)
    );
    assert!(
        in_flight,
        "the one call was still waiting when the person answered"
    );
    let renewal = Duration::from_millis(kr_protocol::question::WAIT_RENEWAL.get());
    assert!(
        elapsed > renewal,
        "the one call stayed open longer than one renewal interval of {renewal:?}: {elapsed:?}"
    );
    assert!(
        checkpointed_at.is_some(),
        "a truncating checkpoint never completed while the call was waiting"
    );
    assert!(
        checkpointed_while_waiting,
        "the checkpoint completed while the call was waiting, at {checkpointed_at:?}"
    );
    assert!(!failed, "{waited}");
    assert_eq!(waited["state"], "answered");
    assert_eq!(
        waited["answer"],
        json!({"kind": "decision", "decided": true})
    );
    assert!(
        elapsed < Duration::from_secs(150),
        "the call returned when the answer came rather than at the end of its wait: {elapsed:?}"
    );

    let created_events = ledger(&hosted)
        .events_since(0, 64)
        .expect("the feed")
        .into_iter()
        .filter(|(_, event)| {
            event.kind == kr_protocol::question::QuestionEventKind::Created
                && event.question.question_id.to_string() == question_id
        })
        .count();
    assert_eq!(
        created_events, 1,
        "nothing was created twice, and nobody was told twice"
    );
    let listed = hosted.kr(&["question", "list", "--include-resolved", "--json"]);
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("json");
    assert_eq!(
        listed["questions"].as_array().expect("questions").len(),
        3,
        "the question and the two markers, and nothing recreated"
    );
}

/// Reads this session's attention inbox, acknowledged items included.
async fn inbox(
    hosted: &Hosted,
    worker: &mut kr_ipc::client::LocalClient,
) -> Vec<kr_protocol::attention::AttentionItem> {
    let result: kr_protocol::attention::AttentionReadResult = worker
        .request(
            kr_protocol::method::Method::AttentionRead,
            &kr_protocol::attention::AttentionReadParams {
                session_id: hosted.session_id,
                include_acknowledged: true,
                max_items: kr_protocol::scalars::U64::new(64),
                after: kr_protocol::scalars::Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("the inbox reads")
        .to_typed()
        .expect("decodes");
    result.items
}

/// KR-REQ-11.64: a person answering yes resolves the question and does nothing else in the
/// session's attention inbox. An upstream agent's approval request is pending there when the
/// question is asked; the yes resolves the question's own item, leaves the approval's item pending
/// exactly as it was, and raises no approval item of its own; and what the agent reads back is the
/// decision alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_yes_resolves_the_question_and_raises_no_approval() {
    use kr_protocol::attention::AttentionRule;

    let hosted = hosted().await;

    // An upstream agent asks for an approval in this session, through the engine's own entry for
    // the session's semantic events.
    let time = Arc::clone(hosted._service.runtime().session().time());
    let approval =
        kr_protocol::ids::ApprovalRequestId::new(format!("upstream-{}", kr_ipc::new_uuid()))
            .expect("an approval request identifier");
    hosted
        ._service
        .attention()
        .observe(
            &kr_attention::event::SourceEvent::new(
                kr_attention::event::EventCursor::new(
                    kr_protocol::attention::AttentionSource::Semantic,
                    1,
                ),
                kr_ipc::now_ms(),
                kr_attention::event::EventKind::ApprovalRequested {
                    request_id: approval,
                    session_id: hosted.session_id,
                    summary: "run the migration".to_owned(),
                },
            ),
            &time,
        )
        .expect("the engine records the approval request");

    let (created, _) = hosted
        .call(
            "ask_user",
            json!({
                "request_id": "approve-this",
                "context": "this deletes the release branch",
                "question": "delete it?",
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

    // The question reaches the inbox as a pending input from a verified source, beside the one
    // approval. The worker's own maintenance feeds the inbox on its cadence; the test runs that
    // same pass now rather than waiting for the next tick.
    let mut worker = hosted.worker().await;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let before = loop {
        let _ = hosted._service.attention_pass();
        let items = inbox(&hosted, &mut worker).await;
        if items
            .iter()
            .any(|item| item.rule == AttentionRule::PendingInput)
        {
            break items;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the question never reached the inbox: {items:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let approvals: Vec<_> = before
        .iter()
        .filter(|item| item.rule == AttentionRule::PendingApproval)
        .cloned()
        .collect();
    assert_eq!(
        approvals.len(),
        1,
        "the upstream approval is pending, and the question is not one: {before:?}"
    );

    let answered = hosted.kr(&["question", "answer", &question_id, "--yes"]);
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
    assert!(!failed, "{waited}");
    assert_eq!(waited["state"], "answered");
    assert_eq!(
        waited["answer"],
        json!({"kind": "decision", "decided": true}),
        "the agent reads the decision and nothing else"
    );

    // Once the inbox has read the answer, the question's item is gone and the approval is still
    // there, unchanged: the yes neither granted it nor raised another.
    let _ = hosted._service.attention_pass();
    let after = inbox(&hosted, &mut worker).await;
    assert!(
        after
            .iter()
            .all(|item| item.rule != AttentionRule::PendingInput),
        "the answer resolved the question's own item: {after:?}"
    );
    let still: Vec<_> = after
        .iter()
        .filter(|item| item.rule == AttentionRule::PendingApproval)
        .cloned()
        .collect();
    assert_eq!(
        still.len(),
        1,
        "the answer raised no approval and resolved none: {after:?}"
    );
    assert_eq!(still[0].key, approvals[0].key);
    assert_eq!(still[0].occurrences, approvals[0].occurrences);
    assert_eq!(still[0].first_seen_ms, approvals[0].first_seen_ms);
    assert!(!still[0].acknowledged);
}

/// Starts a tool call the test can cancel, the way a client cancels one when the person interrupts
/// the agent.
async fn cancellable_call(
    hosted: &Hosted,
    name: &str,
    arguments: Value,
) -> rmcp::service::RequestHandle<rmcp::RoleClient> {
    hosted
        .client
        .send_cancellable_request(
            rmcp::model::ClientRequest::CallToolRequest(rmcp::model::CallToolRequest::new(
                CallToolRequestParams::new(name.to_owned())
                    .with_arguments(arguments.as_object().cloned().unwrap_or_default()),
            )),
            rmcp::service::PeerRequestOptions::no_options(),
        )
        .await
        .unwrap_or_else(|error| panic!("{name} is sent: {error}"))
}

/// Reads every question in the session through the answering surface, as any client reads them.
async fn every_question(hosted: &Hosted) -> Vec<kr_protocol::question::Question> {
    let mut client = hosted.worker().await;
    let result: kr_protocol::question::QuestionReadResult = client
        .request(
            kr_protocol::method::Method::QuestionRead,
            &kr_protocol::question::QuestionReadParams {
                session_id: hosted.session_id,
                question_id: kr_protocol::scalars::Nullable::null(),
                include_resolved: true,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("question.read succeeds")
        .to_typed()
        .expect("decodes");
    result.questions
}

/// Waits until the session's one question is in a state `wanted` accepts, and returns it.
async fn question_once(
    hosted: &Hosted,
    what: &str,
    wanted: impl Fn(kr_protocol::question::QuestionState) -> bool,
) -> kr_protocol::question::Question {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let questions = every_question(hosted).await;
        assert!(questions.len() <= 1, "one question at most: {questions:?}");
        if let Some(question) = questions.into_iter().next()
            && wanted(question.state)
        {
            return question;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the question did not become {what} within thirty seconds"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// KR-REQ-11.63: upstream cancellation cancels the corresponding pending question. When the
/// client cancels a `wait_for_answer` call, as it does when the person interrupts the agent, the
/// question that call was waiting on ends as cancelled; every client reads it that way, a person's
/// answer to it is refused, and the agent's next wait reads the cancellation rather than waiting
/// on a question nobody will answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_wait_whose_call_is_cancelled_upstream_cancels_its_question() {
    let hosted = hosted().await;
    let (created, _) = hosted
        .call(
            "ask_user",
            json!({
                "request_id": "ask-interrupted",
                "context": "",
                "question": "shall I?",
                "type": "confirm"
            }),
        )
        .await;
    assert_eq!(created["state"], "pending");
    let question_id = created["question_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let waiting = cancellable_call(
        &hosted,
        "wait_for_answer",
        json!({
            "question_id": question_id,
            "caller_token": created["caller_token"],
            "wait_seconds": 30
        }),
    )
    .await;
    // A moment for the helper to be inside its wait. A cancellation that arrives before the wait
    // begins ends the question the same way.
    tokio::time::sleep(Duration::from_millis(500)).await;
    waiting
        .cancel(Some("the person interrupted the agent".to_owned()))
        .await
        .expect("the cancellation is sent");

    let question = question_once(&hosted, "cancelled", |state| {
        state == kr_protocol::question::QuestionState::Cancelled
    })
    .await;
    assert_eq!(question.question_id.to_string(), question_id);
    assert!(question.answer.as_ref().is_none());

    let answered = hosted.kr(&["question", "answer", &question_id, "--yes"]);
    assert!(
        !answered.status.success(),
        "an answer to a cancelled question is refused"
    );
    let (waited, failed) = hosted
        .call(
            "wait_for_answer",
            json!({
                "question_id": question_id,
                "caller_token": created["caller_token"],
                "wait_seconds": 1
            }),
        )
        .await;
    assert!(!failed, "{waited}");
    assert_eq!(waited["state"], "cancelled");
}

/// KR-REQ-11.63: an `ask_user` whose call the client cancels while it waits for the answer cancels
/// the question it asked, rather than leaving it in front of the person with nobody to take the
/// answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_question_whose_asking_call_is_cancelled_upstream_ends_cancelled() {
    let hosted = hosted().await;
    let asking = cancellable_call(
        &hosted,
        "ask_user",
        json!({
            "request_id": "ask-and-wait-interrupted",
            "context": "",
            "question": "which way?",
            "type": "input",
            "wait_seconds": 30
        }),
    )
    .await;
    let pending = question_once(&hosted, "asked", |state| {
        state == kr_protocol::question::QuestionState::Pending
    })
    .await;
    asking
        .cancel(Some("the person interrupted the agent".to_owned()))
        .await
        .expect("the cancellation is sent");

    let question = question_once(&hosted, "cancelled", |state| {
        state == kr_protocol::question::QuestionState::Cancelled
    })
    .await;
    assert_eq!(question.question_id, pending.question_id);
    let answered = hosted.kr(&[
        "question",
        "answer",
        &question.question_id.to_string(),
        "--text",
        "left",
    ]);
    assert!(
        !answered.status.success(),
        "an answer to a cancelled question is refused"
    );
}

/// KR-REQ-11.63: only the client's own cancellation cancels a question. When the helper's input
/// closes while it waits, as it does when the agent exits or restarts its tool server, the helper
/// stops without cancelling anything: no cancellation is ever recorded for the question, and it
/// ends with the helper's process as expired.
#[tokio::test(flavor = "multi_thread")]
async fn a_helper_whose_input_closes_leaves_its_question_to_end_as_expired() {
    let hosted = hosted().await;
    let (created, failed) = hosted
        .call(
            "ask_user",
            json!({
                "request_id": "ask-then-go",
                "context": "",
                "question": "shall I?",
                "type": "confirm"
            }),
        )
        .await;
    assert!(!failed, "{created}");
    let asked = every_question(&hosted).await;
    assert_eq!(asked.len(), 1);
    let question_id = asked[0].question_id;
    let helper = asked[0].source.process.clone();
    let _waiting = cancellable_call(
        &hosted,
        "wait_for_answer",
        json!({
            "question_id": created["question_id"],
            "caller_token": created["caller_token"],
            "wait_seconds": 30
        }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The client goes away, and with it the helper's standard input.
    let journal = hosted.journal.clone();
    let session_id = hosted.session_id;
    let _ = hosted.client.cancel().await;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !matches!(
        kr_ipc::identity::process_state(&helper),
        kr_ipc::identity::ProcessState::Ended
    ) {
        assert!(
            std::time::Instant::now() < deadline,
            "the helper did not exit within thirty seconds of its input closing"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Read as a restarted worker would read it: nothing cancelled the question, and it ends with
    // the process that asked.
    let mut store =
        kr_worker::questions::store::Store::open(Some(&journal), session_id, SessionEpoch::V1)
            .expect("a second connection to the journal");
    let cancelled = store
        .events_since(0, 64)
        .expect("the feed")
        .into_iter()
        .filter(|(_, event)| event.kind == kr_protocol::question::QuestionEventKind::Cancelled)
        .count();
    assert_eq!(cancelled, 0, "the helper stopping cancelled nothing");
    store
        .expire_due(
            kr_worker::questions::Now {
                utc_ms: kr_ipc::now_ms(),
                boot_ms: 0,
            },
            None,
        )
        .expect("sweeps");
    assert_eq!(
        store.read(question_id).expect("the question").state,
        kr_protocol::question::QuestionState::Expired
    );
}

/// KR-REQ-11.62: a helper whose agent the worker's broker launched asks for that agent, while a
/// question asked before the broker described it stays the helper's own. The broker proves which
/// agent the helper serves and not which thread a request came from, so a thread switch it reports
/// claims nothing and the question stays open. When the agent's instance ends, the question asked
/// for it is invalidated for every client: the answering surface reads it expired, the agent's own
/// wait returns it expired, and a person's answer to it is refused, while the other question stays
/// open.
#[tokio::test(flavor = "multi_thread")]
async fn a_question_asked_for_a_launched_agent_ends_with_the_agents_instance() {
    let hosted = hosted().await;
    let (before, failed) = hosted
        .call(
            "ask_user",
            json!({
                "request_id": "before-the-bridge",
                "context": "",
                "question": "asked before any bridge?",
                "type": "confirm"
            }),
        )
        .await;
    assert!(!failed, "{before}");
    let questions = every_question(&hosted).await;
    assert_eq!(questions.len(), 1);
    let helper = questions[0].source.process.clone();
    let helpers_own = questions[0].source.application_instance_id;

    // The broker launched this helper's agent. The helper's own process stands for the agent here:
    // a helper belongs to the nearest launched process at or above it.
    let instance = kr_protocol::ids::ApplicationInstanceId::new(kr_ipc::new_uuid());
    let broker = hosted._service.broker();
    broker
        .register_instance(
            instance,
            kr_protocol::broker::IntegrationMode::Gateway,
            None,
            Some(kr_worker::broker::ManagedProcess::new(
                instance,
                helper.clone(),
                kr_worker::broker::TransportHandle {
                    transport: kr_worker::broker::BrokerTransport::PrivateSocket,
                    application_instance_id: instance,
                    executable_digest: kr_protocol::scalars::Digest256::from_bytes([1; 32]),
                    process: helper,
                },
                kr_worker::broker::Credential::generate().expect("a launch credential"),
                false,
                TimestampMs::new(1),
            )),
        )
        .expect("the broker registers the agent");

    let (under, failed) = hosted
        .call(
            "ask_user",
            json!({
                "request_id": "under-the-bridge",
                "context": "",
                "question": "asked for the launched agent?",
                "type": "confirm"
            }),
        )
        .await;
    assert!(!failed, "{under}");
    let under_id = under["question_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let before_id = before["question_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let find = |questions: &[kr_protocol::question::Question], id: &str| {
        questions
            .iter()
            .find(|question| question.question_id.to_string() == id)
            .cloned()
            .expect("the question")
    };
    let bridged = find(&every_question(&hosted).await, &under_id);
    assert_eq!(bridged.source.application_instance_id, instance);
    assert!(bridged.source.agent_binding_revision.as_ref().is_none());
    assert_eq!(
        find(&every_question(&hosted).await, &before_id)
            .source
            .application_instance_id,
        helpers_own
    );

    // A thread switch the broker reports claims nothing for the helper's questions.
    broker
        .advance_binding(instance, None, kr_ipc::now_ms())
        .expect("the binding advances");
    assert_eq!(
        find(&every_question(&hosted).await, &under_id).state,
        kr_protocol::question::QuestionState::Pending
    );

    // The agent waits on its question, and meanwhile its instance ends.
    let waiting = cancellable_call(
        &hosted,
        "wait_for_answer",
        json!({
            "question_id": under_id,
            "caller_token": under["caller_token"],
            "wait_seconds": 30
        }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        broker
            .end(instance, kr_worker::broker::InstanceEnding::NativeExit)
            .instance_ended
    );

    // Every client reads the invalidation, and the other question is untouched.
    let after = every_question(&hosted).await;
    assert_eq!(
        find(&after, &under_id).state,
        kr_protocol::question::QuestionState::Expired
    );
    assert_eq!(
        find(&after, &before_id).state,
        kr_protocol::question::QuestionState::Pending
    );

    // The agent's own wait ends with the same state.
    let waited = tokio::time::timeout(Duration::from_secs(60), waiting.await_response())
        .await
        .expect("the wait ends within its renewal")
        .expect("the wait answered");
    let rmcp::model::ServerResult::CallToolResult(waited) = waited else {
        panic!("a tool result: {waited:?}");
    };
    let content = waited.structured_content.expect("structured content");
    assert_eq!(content["state"], "expired", "{content}");

    // A person answering what they were shown is refused.
    let answered = hosted.kr(&["question", "answer", &under_id, "--yes"]);
    assert!(
        !answered.status.success(),
        "an answer to an invalidated question is refused"
    );
}
