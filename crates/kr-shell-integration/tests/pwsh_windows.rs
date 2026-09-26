//! The PSReadLine package's bridge client, over the host's own named pipe on Windows.
//!
//! `pwsh.rs` drives the same package through a real pseudo-terminal on Unix, where the endpoint is
//! a Unix socket, and says in its own header that running the module on Windows is qualified
//! separately. This is that qualification: the worker binds a real [`HostEndpoint`], starts
//! PowerShell 7 on the module files in this checkout, and holds the worker's half of the
//! `kr-shell-bridge/1` handshake while the module holds the shell's.
//!
//! What is proved here is the transport, which on Windows is a named pipe rather than a socket: a
//! pipe answers no readiness question, so the client keeps one asynchronous read in flight and
//! collects it between the reader's operations. Section 7 makes that the qualification rather than
//! a detail, because a bridge that cannot prove its delivery fence is unqualified and must never
//! fall back to injecting a key into the pseudo-console; a client that never reads its endpoint
//! cannot complete a handshake, let alone prove a fence.
//!
//! The editor is deliberately out of the picture. The reader's own state needs a live PSReadLine,
//! and an installed module would make the result depend on a machine state nothing in this
//! repository records, so the package identity is supplied to the client and the worker expects
//! the same one. Everything below it, from the pipe to the proof over the bootstrap transcript, is
//! the shipped module's own code.

#![cfg(windows)]

use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::paths::Endpoint;
use kr_ipc::peer::PeerIdentity;
use kr_protocol::ids::{RequestId, SessionId};
use kr_protocol::root::{DETACH_HINT, PromptGeneration};
use kr_protocol::scalars::Uuid;
use kr_shell_integration::contract::events::{BridgeEvent, EofGesture, HooksActivated};
use kr_shell_integration::contract::qualification::QualificationReason;
use kr_shell_integration::contract::transport::{
    ENDPOINT_VARIABLE, EventOutcome, SECRET_VARIABLE, WorkerExpectation,
};
use kr_shell_integration::host::endpoint::HostEndpoint;
use kr_shell_integration::host::handshake::{admit, observe};
use kr_shell_integration::host::link::{BridgeReader, BridgeWriter, FromBridge, accept};
use kr_shell_integration::host::scripted::REFERENCE_INTEGRATION_VERSION;
use tokio::io::AsyncReadExt as _;

/// The editor ABI the client declares and this worker expects.
///
/// A published qualification reads this out of the installed PSReadLine. Here both halves are told
/// the same value, because what is under test is the pipe beneath the handshake.
const EDITOR_ABI: &str = "psreadline-2.4";

/// The upstream release the declared package was built against.
const UPSTREAM_VERSION: &str = "7.4";

/// The end-of-file byte this worker answers with.
///
/// Not the client's own default of 4. The accept is the only place this number can come from, so a
/// client that reports it back read the worker's reply and applied what was in it, which a value
/// the client already held would not establish.
const WORKER_EOF_BYTE: u64 = 26;

/// How long the client is given to reach the listener.
///
/// Bounded, because the failure worth reporting is the client's: an unbounded `accept()` turns a
/// client that could not open the pipe into a run that never ends and says nothing about why.
const CONNECTS_WITHIN: Duration = Duration::from_secs(30);

/// How long the client is given to finish and leave.
const ENDS_WITHIN: Duration = Duration::from_secs(30);

/// How long each step of the exchange is given, once the client is on the pipe.
///
/// Every read of the endpoint is inside this. `BridgeReader::recv()` waits without a deadline of
/// its own, so a client that connected and then stalled would leave this test waiting for a frame
/// that never comes, and the run would end on the harness's own timeout with nothing to say. The
/// deadline turns that into a failure that names the step it stopped at.
const EXCHANGES_WITHIN: Duration = Duration::from_secs(60);

/// Runs one step of the exchange under the deadline above, which each step gets in full.
async fn within<T>(step: &str, work: impl Future<Output = T>) -> T {
    tokio::time::timeout(EXCHANGES_WITHIN, work)
        .await
        .unwrap_or_else(|_| panic!("the client answered within {EXCHANGES_WITHIN:?}: {step}"))
}

/// Returns the module files this checkout ships.
fn module_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("shells")
        .join("psreadline")
        .join("module")
}

/// Returns the script that drives the module's own endpoint functions.
fn client_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("pwsh_windows")
        .join("bridge-client.ps1")
}

/// The started client, killed if a failing test leaves it behind.
struct Client(Child);

impl Drop for Client {
    fn drop(&mut self) {
        // Only this test's own child, started a few lines above: a client still running after the
        // worker has finished with it has nothing left to report.
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Starts PowerShell on the module in this checkout, with the bootstrap values the worker exports.
///
/// PowerShell 7 is the Windows root shell this package is qualified against and a release baseline
/// of the platform, so a host without it cannot run the shell under test; the failure says so
/// rather than passing quietly.
fn start_client(
    endpoint: &HostEndpoint,
    directory: &Path,
    mode: &str,
    arguments: &[&str],
) -> Client {
    let exported = endpoint
        .bootstrap()
        .exported_variables()
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect::<Vec<_>>();
    start_client_with(
        &exported,
        &endpoint.session_id().to_string(),
        directory,
        mode,
        arguments,
    )
}

/// The secret a client is given for an address no worker is behind: 32 zero bytes, as base64url.
///
/// The client computes its proof over it and nothing on the other side checks that proof.
const PLACEHOLDER_SECRET: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// The session a client is told it belongs to at an address no worker is behind.
const PLACEHOLDER_SESSION: &str = "71717171-7171-4171-8171-717171717171";

/// Starts the client against the named pipe `name`, which no worker is behind.
fn start_client_at(name: &str, directory: &Path, mode: &str, arguments: &[&str]) -> Client {
    let exported = vec![
        (ENDPOINT_VARIABLE.to_owned(), format!(r"\\.\pipe\{name}")),
        (SECRET_VARIABLE.to_owned(), PLACEHOLDER_SECRET.to_owned()),
    ];
    start_client_with(&exported, PLACEHOLDER_SESSION, directory, mode, arguments)
}

/// Starts the client with `exported` as the bootstrap values, reporting into `directory` and tracing
/// there too.
fn start_client_with(
    exported: &[(String, String)],
    session: &str,
    directory: &Path,
    mode: &str,
    arguments: &[&str],
) -> Client {
    let report = directory.join(format!("{mode}-report.txt"));
    let mut command = Command::new("pwsh.exe");
    command
        .arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-File")
        .arg(client_script())
        .arg("-ModuleDirectory")
        .arg(module_directory())
        .arg("-Report")
        .arg(&report)
        .arg("-Mode")
        .arg(mode)
        .args(arguments)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .env("KR_SESSION", session)
        .env(
            "KR_SHELL_BRIDGE_TRACE",
            directory.join(format!("{mode}-trace.txt")),
        )
        .env("KR_BRIDGE_EXECUTABLE", "pwsh.exe")
        .env("KR_BRIDGE_UPSTREAM_VERSION", UPSTREAM_VERSION)
        .env("KR_BRIDGE_EDITOR_ABI", EDITOR_ABI)
        .env(
            "KR_BRIDGE_INTEGRATION_VERSION",
            REFERENCE_INTEGRATION_VERSION,
        );
    for (name, value) in exported {
        command.env(name, value);
    }
    let child = command.spawn().unwrap_or_else(|error| {
        panic!(
            "PowerShell 7 is the Windows root shell this bridge is qualified against and it did \
             not start: {error}"
        )
    });
    Client(child)
}

/// Returns what the client reported, one step per line.
fn report(directory: &Path, mode: &str) -> String {
    let path = directory.join(format!("{mode}-report.txt"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} was not written: {error}", path.display()))
}

/// Takes the one connection the client makes, or says the client never arrived.
async fn accept_client(endpoint: &HostEndpoint) -> (BridgeReader, BridgeWriter, PeerIdentity) {
    let (connection, peer) = tokio::time::timeout(CONNECTS_WITHIN, endpoint.listener().accept())
        .await
        .expect("the client opens the pipe the worker exported")
        .expect("accepts");
    let (reader, writer) = accept(connection);
    (reader, writer, peer)
}

/// Answers the client's hello, and returns the identifier of the event it reports afterwards.
///
/// The expectation names the process the kernel reports on the other end of the pipe, which is
/// what a worker that launched the shell holds: the client computed its proof over its own
/// identity, and a hello that claims another process is refused by name rather than accepted. The
/// module names its start as the worker reads it, the creation time in hundreds of nanoseconds, so
/// the same hello naming a start one of those intervals later is refused before the real one is
/// answered.
async fn register(
    endpoint: &HostEndpoint,
    reader: &mut BridgeReader,
    writer: &mut BridgeWriter,
    peer: &PeerIdentity,
) -> RequestId {
    let FromBridge::Hello(hello) = within("the hello", reader.recv()).await.expect("a hello")
    else {
        panic!("the opening frame is a hello");
    };
    let observed = observe(peer);
    let root = observed
        .process
        .clone()
        .expect("the kernel identifies the connecting shell");
    let expectation = WorkerExpectation {
        session_id: endpoint.session_id(),
        root_process: root,
        supported_editor_abis: vec![EDITOR_ABI.to_owned()],
        supported_integration_versions: vec![REFERENCE_INTEGRATION_VERSION.to_owned()],
        launched_package: None,
        already_registered: false,
        gesture: EofGesture::TerminalEof {
            byte: kr_protocol::scalars::U64::new(WORKER_EOF_BYTE),
        },
    };
    let outcome = admit(
        endpoint.secret(),
        &expectation,
        endpoint.address(),
        peer,
        &hello,
    )
    .expect("decides");
    assert_eq!(
        outcome.refusal(),
        None,
        "the module's hello was refused: {outcome:?}\nthe kernel reported {observed:?}\nthe \
         client claimed {:?}",
        hello.shell_process
    );
    assert_eq!(
        hello.shell_process.source,
        kr_protocol::identity::ProcessStartSource::WindowsProcessCreationTime,
        "the module names its start as the creation time, the source the worker reads"
    );
    // The same hello naming a start one interval of the kernel's later is another process, and is
    // refused as one.
    let mut later = hello.clone();
    later.shell_process.start_value =
        kr_protocol::scalars::U64::new(hello.shell_process.start_value.get() + 1);
    let refused = admit(
        endpoint.secret(),
        &expectation,
        endpoint.address(),
        peer,
        &later,
    )
    .expect("decides");
    assert_eq!(
        refused.refusal(),
        Some(QualificationReason::ProcessMismatch),
        "a hello naming another start is refused: {refused:?}"
    );
    within("the accept", writer.send_handshake(&outcome))
        .await
        .expect("answers");

    let FromBridge::Event { id, event } =
        within("the event", reader.recv()).await.expect("an event")
    else {
        panic!("the client reports its activation");
    };
    assert_eq!(
        *event,
        BridgeEvent::HooksActivated(HooksActivated {
            session_id: endpoint.session_id(),
            prompt_generation: PromptGeneration::new(1),
        })
    );
    id
}

/// Waits for the client to finish, and returns how it ended.
async fn ends(client: &mut Client, report: impl Fn() -> String) -> ExitStatus {
    let deadline = Instant::now() + ENDS_WITHIN;
    loop {
        if let Some(status) = client.0.try_wait().expect("the client's state") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "the client did not finish; it reported:\n{}",
            report()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// KR-ACC-010, KR-REQ-07.37
///
/// The whole exchange over the pipe: the client connects to the address the worker exported, sends
/// its hello, reads the worker's accept, reports one reader event, collects the worker's answer to
/// it and then closes its end. Reading the accept is the step that decides the rest: the hint the
/// client reports back is the worker's own, so it came off the pipe rather than out of the
/// client's defaults.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_module_completes_the_handshake_over_the_hosts_named_pipe() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let session_id = SessionId::new(Uuid::from_bytes([0x71; 16]));
    let endpoint = HostEndpoint::open(session_id, directory.path()).expect("binds");
    let mut client = start_client(&endpoint, directory.path(), "exchange", &[]);

    let (mut reader, mut writer, peer) = accept_client(&endpoint).await;
    let id = register(&endpoint, &mut reader, &mut writer, &peer).await;
    within(
        "the answer to the event",
        writer.send_event_result(id, EventOutcome::Received),
    )
    .await
    .expect("answers the event");

    let status = ends(&mut client, || report(directory.path(), "exchange")).await;
    let observed = report(directory.path(), "exchange");
    assert!(status.success(), "the client ended {status}:\n{observed}");
    assert!(observed.contains("connected\n"), "{observed}");
    assert!(observed.contains("hello sent\n"), "{observed}");
    assert!(
        observed.contains(&format!("gesture_byte={WORKER_EOF_BYTE} ")),
        "the client did not apply the gesture the worker sent, so it did not read the accept off \
         the pipe:\n{observed}"
    );
    assert!(
        observed.contains(&format!("hint={DETACH_HINT}\n")),
        "and the hint it carries is the worker's:\n{observed}"
    );
    assert!(observed.contains("answer event_result\n"), "{observed}");
    assert!(observed.contains("disconnected\n"), "{observed}");

    // The client's end is gone, so the worker's next read ends rather than waiting: a shell that
    // exits leaves no half-open pipe behind for the session to wait on.
    let error = within("the end of the pipe", reader.recv())
        .await
        .expect_err("the client's end is closed");
    println!("the endpoint ended with: {error}");
}

/// KR-ACC-010, KR-REQ-07.37
///
/// The other direction of the same teardown: the worker drops the pipe while the client is between
/// operations. The outstanding read completes with nothing, which is the peer's close, and the
/// client reports the loss and gives up its registration instead of waiting for a frame that will
/// never come.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_client_reports_the_loss_when_the_worker_drops_the_pipe() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let session_id = SessionId::new(Uuid::from_bytes([0x72; 16]));
    let endpoint = HostEndpoint::open(session_id, directory.path()).expect("binds");
    let mut client = start_client(&endpoint, directory.path(), "closed", &[]);

    let (mut reader, mut writer, peer) = accept_client(&endpoint).await;
    let _id = register(&endpoint, &mut reader, &mut writer, &peer).await;
    drop(reader);
    drop(writer);

    let status = ends(&mut client, || report(directory.path(), "closed")).await;
    let observed = report(directory.path(), "closed");
    assert!(status.success(), "the client ended {status}:\n{observed}");
    assert!(
        observed.contains("loss reported\n"),
        "the client did not report the worker's close:\n{observed}"
    );
}

// ---- the server the client reaches ----------------------------------------------------------------
//
// The endpoint namespace is shared by every account, so the name a worker exported can be held by a
// pipe the worker never made. The client opens a pipe for identification only, so the server it
// reaches can read which account it is and never act as it, and before its hello it checks the pipe
// by the host's own client's rule: owned by this account's user or by the owner its new objects
// receive, with a protected list that names no other account. What follows proves each half against
// servers made for the purpose.

/// Returns the checkout's script `name` beside the client's.
fn helper_script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("pwsh_windows")
        .join(name)
}

/// A helper process a test started, ended when the test is done with it however the test ends, so
/// none keeps the run's output open.
struct Helper(Option<Child>);

impl Helper {
    /// Starts the checkout's script `name` in PowerShell 7 with `arguments`.
    fn start(name: &str, arguments: &[&str]) -> Self {
        let child = Command::new("pwsh.exe")
            .arg("-NoLogo")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-File")
            .arg(helper_script(name))
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| panic!("{name} did not start: {error}"));
        Self(Some(child))
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        // Only this test's own child, started above.
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// How long a helper is given to reach each line it reports.
const HELPER_WITHIN: Duration = Duration::from_secs(60);

/// Waits for `status` to hold a line starting with `prefix`, and returns that line; fails after
/// [`HELPER_WITHIN`], or at once when the helper reported an error, with what the file held.
async fn status_line(status: &Path, prefix: &str) -> String {
    let deadline = Instant::now() + HELPER_WITHIN;
    loop {
        let text = std::fs::read_to_string(status).unwrap_or_default();
        if let Some(line) = text.lines().find(|line| line.starts_with(prefix)) {
            return line.trim().to_owned();
        }
        assert!(
            !text.lines().any(|line| line.starts_with("error=")),
            "the helper failed before '{prefix}':\n{text}"
        );
        assert!(
            Instant::now() < deadline,
            "the helper did not report '{prefix}' within {HELPER_WITHIN:?}; {} held:\n{text}",
            status.display()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Returns what the client traced, or nothing when it traced nothing.
fn trace(directory: &Path, mode: &str) -> String {
    std::fs::read_to_string(directory.join(format!("{mode}-trace.txt"))).unwrap_or_default()
}

/// A pipe name of this test's own.
fn pipe_name() -> String {
    format!("kalareach-test-{}", kr_ipc::new_uuid())
}

/// Reads what an accepted connection delivers until its client leaves, sends something, or
/// [`CONNECTS_WITHIN`] passes, and returns what arrived.
async fn arriving(connection: &mut Connection) -> Vec<u8> {
    let mut buffer = [0_u8; 4096];
    match tokio::time::timeout(CONNECTS_WITHIN, connection.read(&mut buffer)).await {
        Ok(Ok(count)) => buffer[..count].to_vec(),
        Ok(Err(_)) | Err(_) => Vec::new(),
    }
}

/// KR-REQ-23.10, KR-REQ-07.22: the server the client reaches may identify it and never act as it.
///
/// The server here is the client's own account's, with the owner-only list a worker's pipe carries,
/// so the client's check lets its hello through; the server reads that first byte and then reads
/// the level the client's token was opened at.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_module_lets_the_server_identify_it_and_never_act_as_it() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let name = pipe_name();
    let status = directory.path().join("level-status.txt");
    let status_text = status.display().to_string();
    let _observer = Helper::start("impersonation-level.ps1", &[&name, &status_text]);
    status_line(&status, "ready").await;

    let mut client = start_client_at(&name, directory.path(), "hello", &[]);
    let level = status_line(&status, "level=").await;
    let ended = ends(&mut client, || report(directory.path(), "hello")).await;
    let observed = report(directory.path(), "hello");
    assert_eq!(
        level, "level=Identification",
        "the server may identify the client and nothing more; the client ended {ended}:\n{observed}"
    );
}

/// The lists a pipe of this account may carry that the host's own client refuses, each with what the
/// module's trace and the host's own client's refusal say about it.
///
/// Both clients read the list the same way, through `GetSecurityInfo` for a file object, and Windows
/// will not hand back through a pipe's handle a list that is not protected: it answers that the
/// parameter is incorrect. So both refuse that pipe as unreadable, for the same reason, and the
/// refusal of an inherited list itself is proved on a descriptor in memory below.
const REFUSED_LISTS: &[(&str, &str, &str, &str)] = &[
    (
        "widened",
        "D:P(A;;GA;;;OW)(A;;GA;;;WD)",
        "grants access to S-1-1-0",
        "grants access to",
    ),
    (
        "unprotected",
        "D:(A;;GA;;;OW)",
        "could not be read",
        "could not be read",
    ),
    (
        "missing",
        "D:PNO_ACCESS_CONTROL",
        "carries no access-control list",
        "carries no access-control list",
    ),
    (
        "empty-mask",
        "D:P(A;;GA;;;OW)(A;;0x0;;;WD)",
        "grants access to S-1-1-0",
        "grants access to",
    ),
    (
        "inherit-only",
        "D:P(A;;GA;;;OW)(A;IO;GA;;;WD)",
        "grants access to S-1-1-0",
        "grants access to",
    ),
    (
        "callback",
        "D:P(A;;GA;;;OW)(XA;;GA;;;SY;(Member_of {SID(BA)}))",
        "type-9 entry",
        "type-9 entry",
    ),
];

/// KR-REQ-23.10, KR-REQ-07.22: the client refuses, before its hello, every pipe of its own account
/// whose list the host's own client refuses, whatever an entry's mask or flags, and nothing it would
/// have sent reaches the pipe; a pipe with an empty list refuses the open itself.
///
/// Each pipe is made with its list exactly as written, so an entry that grants nothing, which .NET's
/// own reading of a list would drop, is there for the client to read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_module_refuses_before_its_hello_every_list_the_hosts_client_refuses() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    // Every case runs and says what went wrong, so one run shows each list's outcome.
    let mut problems = Vec::new();
    for (case, list, said, host_said) in REFUSED_LISTS {
        let case_directory = directory.path().join(case);
        std::fs::create_dir(&case_directory).expect("a directory for the case");
        let name = pipe_name();
        let endpoint = Endpoint::from_name(name.clone()).expect("a short name");
        let listener = Listener::bind_with_access_list(&endpoint, list)
            .unwrap_or_else(|error| panic!("{case}: the pipe is made with {list}: {error}"));
        // Both clients' connections are taken and read, until each leaves or sends something.
        let taken = tokio::spawn(async move {
            let mut received = Vec::new();
            for _ in 0..2 {
                let Ok(Ok((mut connection, _))) =
                    tokio::time::timeout(CONNECTS_WITHIN, listener.accept()).await
                else {
                    break;
                };
                received.push(arriving(&mut connection).await);
            }
            received
        });

        match Connection::connect(&endpoint).await {
            Err(kr_ipc::IpcError::PeerAccountRejected { detail }) if detail.contains(host_said) => {}
            other => problems.push(format!(
                "{case}: the host's own client was to refuse {list}, saying '{host_said}': {other:?}"
            )),
        }
        let mut client = start_client_at(&name, &case_directory, "hello", &[]);
        let ended = ends(&mut client, || report(&case_directory, "hello")).await;
        let observed = report(&case_directory, "hello");
        if !(ended.success() && observed.contains("refused\n")) {
            problems.push(format!(
                "{case}: the module did not refuse {list} ({ended}):\n{observed}"
            ));
        }
        let traced = trace(&case_directory, "hello");
        if !(traced.contains("refused before the hello") && traced.contains(said)) {
            problems.push(format!("{case}: the trace does not say '{said}': {traced}"));
        }
        let received = taken.await.expect("the pipe's connections are read");
        if received.len() != 2 || !received.iter().all(Vec::is_empty) {
            problems.push(format!(
                "{case}: both clients were to open the pipe and send it nothing: {received:?}"
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n\n"));

    // A list with no entry at all admits nobody, the owner included, so the open itself is refused
    // and neither client reaches the pipe.
    let case_directory = directory.path().join("empty");
    std::fs::create_dir(&case_directory).expect("a directory for the case");
    let name = pipe_name();
    let endpoint = Endpoint::from_name(name.clone()).expect("a short name");
    let listener = Listener::bind_with_access_list(&endpoint, "D:P").expect("the pipe is made");
    assert!(
        Connection::connect(&endpoint).await.is_err(),
        "the host's own client cannot open a pipe whose list is empty"
    );
    let mut client = start_client_at(&name, &case_directory, "hello", &[]);
    let ended = ends(&mut client, || report(&case_directory, "hello")).await;
    let observed = report(&case_directory, "hello");
    assert!(
        ended.success() && observed.contains("refused\n"),
        "the module cannot open a pipe whose list is empty ({ended}):\n{observed}"
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .is_err(),
        "nothing reached a pipe whose list is empty"
    );
}

/// KR-REQ-23.10, KR-REQ-07.22: a client that cannot read the pipe's owner and list sends nothing,
/// and the shell carries on as it does when the connect fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pipe_whose_descriptor_the_module_cannot_read_gets_no_hello() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let session_id = SessionId::new(Uuid::from_bytes([0x73; 16]));
    let endpoint = HostEndpoint::open(session_id, directory.path()).expect("binds");
    let mut client = start_client(
        &endpoint,
        directory.path(),
        "hello",
        &["-BreakDescriptorRead"],
    );
    let (mut connection, _) = tokio::time::timeout(CONNECTS_WITHIN, endpoint.listener().accept())
        .await
        .expect("the client opens the pipe")
        .expect("accepts");
    let received = arriving(&mut connection).await;
    drop(connection);
    let ended = ends(&mut client, || report(directory.path(), "hello")).await;
    let observed = report(directory.path(), "hello");
    assert!(
        received.is_empty(),
        "nothing reached the pipe: {received:?}; the client reported:\n{observed}"
    );
    assert!(
        ended.success() && observed.contains("refused\n"),
        "the module refuses a pipe it cannot read ({ended}):\n{observed}"
    );
    assert!(
        trace(directory.path(), "hello").contains("could not be read"),
        "the trace says why: {}",
        trace(directory.path(), "hello")
    );
}

/// Security descriptors, `{me}` standing for this account, with the decision the host's own client
/// makes about each: `None` for accepted, or what the refusal says.
const DESCRIPTORS: &[(&str, &str, Option<&str>)] = &[
    ("owner-only", "O:{me}D:P(A;;GA;;;OW)", None),
    ("protected-empty", "O:{me}D:P", None),
    (
        "machine-accounts",
        "O:{me}D:P(A;;GA;;;{me})(A;;GA;;;SY)(A;;GA;;;BA)(A;OICIIO;GA;;;CO)",
        None,
    ),
    ("a-denial", "O:{me}D:P(D;;GA;;;WD)(A;;GA;;;OW)", None),
    (
        "another-owner",
        "O:SYD:P(A;;GA;;;OW)",
        Some("belongs to S-1-5-18"),
    ),
    ("no-owner", "D:P(A;;GA;;;OW)", Some("records no owner")),
    (
        "widened",
        "O:{me}D:P(A;;GA;;;OW)(A;;GA;;;WD)",
        Some("grants access to S-1-1-0"),
    ),
    (
        "empty-mask",
        "O:{me}D:P(A;;0x0;;;WD)",
        Some("grants access to S-1-1-0"),
    ),
    (
        "inherit-only",
        "O:{me}D:P(A;IO;GA;;;WD)",
        Some("grants access to S-1-1-0"),
    ),
    (
        "unprotected",
        "O:{me}D:(A;;GA;;;OW)",
        Some("inherits its access-control list"),
    ),
    (
        "missing",
        "O:{me}D:PNO_ACCESS_CONTROL",
        Some("carries no access-control list"),
    ),
    (
        "callback",
        "O:{me}D:P(XA;;GA;;;SY;(Member_of {SID(BA)}))",
        Some("type-9 entry"),
    ),
];

/// KR-REQ-23.10: the client judges a descriptor as the host's own client does: every allow entry,
/// whatever its mask or flags, names the owner's account or one that already holds the machine; a
/// protected empty list is accepted; a missing or inherited list, another owner, and an entry of a
/// kind neither client evaluates are refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_module_judges_a_descriptor_as_the_hosts_client_does() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let fixtures = directory.path().join("descriptors.txt");
    let lines: Vec<String> = DESCRIPTORS
        .iter()
        .map(|(case, sddl, _)| format!("{case}\t{sddl}"))
        .collect();
    std::fs::write(&fixtures, lines.join("\n")).expect("the descriptors are written");
    let fixtures_text = fixtures.display().to_string();
    let mut client = start_client_at(
        &pipe_name(),
        directory.path(),
        "evaluate",
        &["-Fixtures", &fixtures_text],
    );
    let ended = ends(&mut client, || report(directory.path(), "evaluate")).await;
    let observed = report(directory.path(), "evaluate");
    assert!(ended.success(), "the check ran ({ended}):\n{observed}");
    let mut wrong = Vec::new();
    for (case, sddl, refusal) in DESCRIPTORS {
        let Some(line) = observed
            .lines()
            .find(|line| line.split(' ').next() == Some(case))
        else {
            wrong.push(format!("{case} was not judged"));
            continue;
        };
        let right = match refusal {
            None => line == format!("{case} accepted"),
            Some(said) => line.starts_with(&format!("{case} refused ")) && line.contains(said),
        };
        if !right {
            wrong.push(format!("{sddl}: {line}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{}\n\nthe whole report:\n{observed}",
        wrong.join("\n")
    );
}

/// The second local account this run was given, or `None` when it was not.
///
/// The name and password are exported by the machine's own test script for this session only, and
/// are never written to a log or a file here.
fn second_account() -> Option<String> {
    let user = std::env::var("KR_TEST_SECOND_USER")
        .ok()
        .filter(|value| !value.is_empty())?;
    std::env::var("KR_TEST_SECOND_PASS")
        .ok()
        .filter(|value| !value.is_empty())?;
    Some(user)
}

/// KR-REQ-23.10, KR-REQ-07.22: a pipe another account created first at the exported name gets
/// nothing from the client: it refuses the pipe by its owner before its hello, and says whose it is.
///
/// It needs a second local account, which the hosted runner does not have, so it is ignored there
/// and runs on the Windows test machine, whose script makes a standard second account for the run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a second local account; run on the Windows test machine"]
async fn the_module_sends_nothing_to_a_pipe_another_account_holds() {
    let user = second_account().expect("a second local account in the environment");
    let second = kr_ipc::starter::account_sid(&user).expect("the second account's identifier");
    let directory = tempfile::tempdir().expect("a temporary directory");
    let name = pipe_name();
    let status = directory.path().join("second-status.txt");
    let status_text = status.display().to_string();
    let _holder = Helper::start("as-second-account.ps1", &[&name, &status_text]);
    status_line(&status, "ready").await;

    let mut client = start_client_at(&name, directory.path(), "hello", &[]);
    let ended = ends(&mut client, || report(directory.path(), "hello")).await;
    let observed = report(directory.path(), "hello");
    let received = status_line(&status, "received=").await;
    assert_eq!(
        received, "received=0",
        "nothing the client would have sent reached the other account's pipe ({ended}):\n{observed}"
    );
    assert!(
        observed.contains("refused\n"),
        "the client refused the pipe:\n{observed}"
    );
    let traced = trace(directory.path(), "hello");
    assert!(
        traced.contains("refused before the hello") && traced.contains(&second),
        "the trace names the account that holds the pipe: {traced}"
    );
}
