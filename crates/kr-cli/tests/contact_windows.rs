//! The contact tools against a real session on Windows, spoken as an installed agent speaks them.
//!
//! The suite beside this one, `contact.rs`, runs the tool server as the session's own root shell
//! with its standard streams on two FIFOs, which is a Unix arrangement. A Windows session's root
//! shell runs inside a pseudo-console and inside the session's job object, so here the root shell
//! is `cmd.exe`, and it starts the tool server with its standard streams on two named pipes this
//! test holds. The tool server is then the root shell's child rather than the shell itself. Its
//! parent proves nothing on this platform, because Windows keeps a parent's identifier after the
//! parent exits; what places it in the session is the session's job, which holds it because the
//! shell that started it was put there before it ran and nothing it starts may leave. That, the
//! named pipe that names it to the worker, and the start identity Windows gives it are the
//! mechanisms these rows rest on here:
//!
//! | Row | What is checked here |
//! | --- | --- |
//! | KR-REQ-11.52 | The helper is bound to its own process and the creation time Windows records for it, found in the session's job, running the `kr` this test launched |
//! | KR-REQ-11.54 | A helper reaches the session whose job holds it and no other, whatever it is told |
//! | KR-REQ-23.31 | The private question methods check the caller token of the question named, and refuse a helper the worker cannot place inside the session |
//!
//! Everything a test launches lives on the internal disk: the `kr` binary is copied to the
//! temporary directory, the host's runtime and state directories are a temporary tree there, and
//! every working directory is the system drive's root.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, ProcessStartSource, WorkerProfile};
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
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

/// How long a test waits for the root shell to start the tool server on its pipes.
///
/// A shell and a tool server start in well under a second on an idle machine, and a build machine
/// under load is slower. It bounds a wait; it measures nothing.
const PATIENCE: Duration = Duration::from_secs(60);

/// A session whose root shell started the tool server, and the client talking to it.
///
/// The host tree is shared, so a second session can be started in the same environment.
struct Hosted {
    temp: Arc<kr_ipc::testing::TempHost>,
    session_id: SessionId,
    descriptor: WorkerDescriptor,
    journal: PathBuf,
    binary: PathBuf,
    client: RunningService<rmcp::RoleClient, ()>,
    service: Arc<WorkerService>,
}

impl Drop for Hosted {
    fn drop(&mut self) {
        // The session's job holds the shell and the tool server, and ending it ends both: a
        // program that is running cannot be removed, and the copy it runs from is removed below.
        let root = self.service.runtime().session().root_identity();
        if let Some(job) = root
            .and_then(|root| u32::try_from(root.pid.get()).ok())
            .and_then(kr_worker::windows::job::holding)
        {
            let _ = job.terminate(1);
            let deadline = Instant::now() + PATIENCE;
            while job.process_ids().is_ok_and(|held| !held.is_empty()) && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        if let Some(directory) = self.binary.parent() {
            let _ = std::fs::remove_dir_all(directory);
        }
    }
}

/// Copies the command under test to the internal disk.
///
/// The copy's path goes into the root shell's command line unquoted, because the shell that reads
/// it takes quotation marks apart by rules of its own; a path with a space in it is refused here
/// rather than split there.
fn internal_copy(source: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("kr-contact-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&directory).expect("a directory on the internal disk");
    let destination = directory.join("kr.exe");
    assert!(
        !destination.to_string_lossy().contains(char::is_whitespace),
        "the temporary directory {} has a space in its path, and the root shell's command line \
         names the tool server by that path; point TEMP at a directory without one",
        directory.display()
    );
    kr_ipc::testing::place_program(Path::new(source), &destination);
    destination
}

/// What a session's root shell starts: the words of one command, and what it adds to the
/// environment.
struct Root {
    command: Vec<String>,
    environment: Vec<(String, String)>,
}

/// The command interpreter, by the path Windows names for it.
fn command_interpreter() -> String {
    std::env::var("ComSpec").unwrap_or_else(|_| {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        format!(r"{root}\System32\cmd.exe")
    })
}

/// The system drive's root, which is the nearest thing this platform has to `/`.
fn system_drive_root() -> String {
    std::env::var("SystemDrive").map_or_else(|_| r"C:\".to_owned(), |drive| format!(r"{drive}\"))
}

/// The environment a process this test starts is given, in place of this test's own.
///
/// What a program on this platform needs before it can start at all, a `PATH` that reaches the
/// system's own programs and nothing else, and the host tree's two roots.
fn environment(temp: &kr_ipc::testing::TempHost) -> Vec<(String, String)> {
    let mut environment = Vec::new();
    for name in [
        "SystemRoot",
        "SystemDrive",
        "windir",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "ComSpec",
        "PATHEXT",
    ] {
        if let Ok(value) = std::env::var(name) {
            environment.push((name.to_owned(), value));
        }
    }
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    environment.push(("PATH".to_owned(), format!(r"{root}\System32")));
    environment.push((
        "KR_RUNTIME_DIR".to_owned(),
        temp.paths().runtime_root().display().to_string(),
    ));
    environment.push((
        "KR_STATE_DIR".to_owned(),
        temp.paths().state_root().display().to_string(),
    ));
    environment
}

/// Creates a pipe this test serves, for one of the tool server's standard streams.
fn stream_pipe(name: &str) -> NamedPipeServer {
    ServerOptions::new()
        .first_pipe_instance(true)
        .create(name)
        .unwrap_or_else(|error| panic!("creates {name}: {error}"))
}

/// Starts a session whose root shell starts `kr agent-tools --stdio`, and connects to it.
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

/// Starts a session whose root shell starts the command `root` names for the copied `kr`, with its
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

/// Starts one session in `temp`, whose root shell starts the command `root` names for the copied
/// `kr` with its standard streams on a pair of named pipes, and connects to it.
async fn session_in(
    temp: Arc<kr_ipc::testing::TempHost>,
    display: DisplayNumber,
    root: impl FnOnce(&Path) -> Root,
) -> Hosted {
    let environment_paths = temp.environment();
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
    // An in-memory store, not the platform's credential store: these tests only need a controller
    // key the worker will check a generation token against.
    let store = kr_crypto::store::MemoryStore::new();
    let controller = kr_ipc::verify::ControllerIdentity::initialise(&store, environment_id)
        .expect("a controller identity");

    let binary = internal_copy(env!("CARGO_BIN_EXE_kr"));
    let pipes = kr_ipc::new_uuid();
    let to_server_name = format!(r"\\.\pipe\kr-contact-{pipes}-in");
    let from_server_name = format!(r"\\.\pipe\kr-contact-{pipes}-out");
    let to_server = stream_pipe(&to_server_name);
    let from_server = stream_pipe(&from_server_name);

    let root = root(&binary);
    for word in &root.command {
        assert!(
            !word.contains(char::is_whitespace) && !word.contains('"'),
            "{word:?} goes into the root shell's command line as it is"
        );
    }
    let mut variables = environment(&temp);
    variables.extend(root.environment);
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: display,
        // The root shell starts the tool server with its standard streams on the two pipes this
        // test holds, and waits for it. Both are inside the session's job: the shell because it
        // was put there before it ran, the tool server because the shell started it.
        shell: ShellCommand {
            program: command_interpreter(),
            arguments: vec![
                "/d".to_owned(),
                "/c".to_owned(),
                format!(
                    "{} < {to_server_name} > {from_server_name}",
                    root.command.join(" ")
                ),
            ],
            cwd: system_drive_root(),
            environment: variables,
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment_paths.journal_database(session_id)),
        spool_directory: Some(environment_paths.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 256 * 1024,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the root shell");
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
            .expect("starts the runtime"),
    );

    let endpoint = environment_paths
        .worker_endpoint(display)
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
                build_id: BuildId::new("kr-test/0").expect("a build identifier"),
                journal_path: Some(environment_paths.journal_database(session_id)),
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
    kr_ipc::descriptor::publish(&environment_paths, &descriptor).expect("publishes the descriptor");

    // The shell opens both pipes as it starts the tool server.
    tokio::time::timeout(PATIENCE, to_server.connect())
        .await
        .expect("the shell opened the tool server's input in time")
        .expect("the input connected");
    tokio::time::timeout(PATIENCE, from_server.connect())
        .await
        .expect("the shell opened the tool server's output in time")
        .expect("the output connected");
    let client =
        ().serve((from_server, to_server))
            .await
            .expect("the tool server answered the handshake");

    Hosted {
        journal: environment_paths.journal_database(session_id),
        temp,
        session_id,
        descriptor,
        binary,
        client,
        service,
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
            .envs(environment(&self.temp))
            .current_dir(system_drive_root())
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

/// Returns when Windows says one process was created, in hundreds of nanoseconds since 1970, read
/// through PowerShell's own process API rather than the reader under test.
fn created_at(pid: u32) -> u64 {
    let output = std::process::Command::new(kr_worker::testing::powershell())
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "(Get-Process -Id {pid}).StartTime.ToUniversalTime().Ticks - [DateTime]::UnixEpoch.Ticks"
            ),
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("PowerShell starts");
    let printed = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "PowerShell described process {pid}: {printed}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    printed
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("PowerShell printed a creation time: {printed:?}"))
}

/// KR-REQ-11.52: the tool server is bound to the session by what Windows reports about the process
/// at the other end of the worker's pipe, not by anything it sends. The question it created names
/// that process with the creation time Windows records for it, read here through PowerShell as
/// well as through the reader the worker uses; it is inside the session's job, which is what
/// admitted it, since its parent proves nothing on this platform; it is the root shell's child and
/// not the root shell; it runs the `kr` this test launched; and the name the caller gave itself is
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
        kr_ipc::identity::process_start_identity(pid).expect("Windows names the process"),
        source.process,
        "the recorded identity is the live process, start value and all"
    );
    assert_eq!(
        source.process.source,
        ProcessStartSource::WindowsProcessCreationTime
    );
    assert_eq!(
        source.process.start_value.get(),
        created_at(pid),
        "the start value is the creation time Windows records for the process"
    );
    assert!(
        source.session_member,
        "the process is inside the session's job"
    );
    assert!(
        !source.ancestry,
        "and it was not admitted by its parent, which proves nothing on this platform"
    );
    let root = hosted
        .service
        .runtime()
        .session()
        .root_identity()
        .expect("the session names its root shell");
    assert!(
        !root.matches(&source.process),
        "the tool server is the root shell's child, not the root shell"
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

/// KR-REQ-23.31: a private question method checks the caller token of the question it names.
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
    let (own, failed) = hosted
        .call(
            "wait_for_answer",
            json!({
                "question_id": second["question_id"],
                "caller_token": second["caller_token"],
                "wait_seconds": 1
            }),
        )
        .await;
    assert!(!failed, "the question's own token reads it: {own}");
    assert_eq!(own["state"], "pending");
}

/// KR-REQ-23.31: a helper the worker cannot place inside the session is refused, whatever it
/// claims about the session. On this platform what places a helper is the session's job, and a tool
/// server this test starts itself is in no session's job: told which session to look at, it is
/// still refused by every tool, and nothing is created in the session that does exist.
#[tokio::test(flavor = "multi_thread")]
async fn a_helper_outside_a_session_is_told_how_to_get_into_one() {
    let hosted = hosted().await;
    let mut command = tokio::process::Command::new(&hosted.binary);
    command
        .arg("agent-tools")
        .arg("--stdio")
        .env_clear()
        .envs(environment(&hosted.temp))
        // Even told which session to look at, it is not in one.
        .env("KR_SESSION", hosted.session_id.to_string())
        .current_dir(system_drive_root());
    let outside =
        ().serve(rmcp::transport::TokioChildProcess::new(command).expect("starts the tool server"))
            .await
            .expect("the tool server answered the handshake");

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

/// KR-REQ-11.54: a helper reaches the session it runs in and no other. Two sessions share one
/// environment, each with its own job; the second session's helper is told the first session's
/// identity in its environment and handed the first session's question and caller token, and still
/// every call it makes lands in its own session: its question and its alert are its own session's,
/// and it can neither wait on nor cancel the first session's question, which stays pending and is
/// still the first helper's to read.
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

    let (own, failed) = first
        .call(
            "wait_for_answer",
            json!({"question_id": first_question, "caller_token": first_token, "wait_seconds": 1}),
        )
        .await;
    assert!(!failed, "{own}");
    assert_eq!(own["state"], "pending");
}
