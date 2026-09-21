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

use kr_ipc::peer::PeerIdentity;
use kr_protocol::ids::{RequestId, SessionId};
use kr_protocol::root::{DETACH_HINT, PromptGeneration};
use kr_protocol::scalars::Uuid;
use kr_shell_integration::contract::events::{BridgeEvent, EofGesture, HooksActivated};
use kr_shell_integration::contract::transport::{EventOutcome, WorkerExpectation};
use kr_shell_integration::host::endpoint::HostEndpoint;
use kr_shell_integration::host::handshake::{admit, observe};
use kr_shell_integration::host::link::{BridgeReader, BridgeWriter, FromBridge, accept};
use kr_shell_integration::host::scripted::REFERENCE_INTEGRATION_VERSION;

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
fn start_client(endpoint: &HostEndpoint, directory: &Path, mode: &str) -> Client {
    let report = directory.join(format!("{mode}-report.txt"));
    let bootstrap = endpoint.bootstrap();
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
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .env("KR_SESSION", endpoint.session_id().to_string())
        .env("KR_BRIDGE_EXECUTABLE", "pwsh.exe")
        .env("KR_BRIDGE_UPSTREAM_VERSION", UPSTREAM_VERSION)
        .env("KR_BRIDGE_EDITOR_ABI", EDITOR_ABI)
        .env(
            "KR_BRIDGE_INTEGRATION_VERSION",
            REFERENCE_INTEGRATION_VERSION,
        );
    for (name, value) in bootstrap.exported_variables() {
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
/// identity, and a hello that claims another process is refused by name rather than accepted.
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
    let mut client = start_client(&endpoint, directory.path(), "exchange");

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
    let mut client = start_client(&endpoint, directory.path(), "closed");

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
