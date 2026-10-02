//! `kr bridge --stdio` driven the way an invoker drives it.
//!
//! Each of these starts the real command as a child process with its standard streams piped, which
//! is exactly what `wsl.exe --exec` and a container runtime's exec produce. What stands in for the
//! destination environment is a stub control endpoint in this process: it speaks the local
//! handshake and answers one read, which is enough to show that the frames cross unchanged and
//! that what the destination answers is what the invoker receives.
//!
//! The command is copied to the internal disk before it is run. The build directory is on an
//! external volume, and a process launched from there is its own privacy identity to the operating
//! system, which puts a dialog in front of a test that is waiting for bytes.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use kr_protocol::actor::ActorIngress;
use kr_protocol::envelope::{
    ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{FrameCodec, StreamKind};
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION, ProtocolVersion, ReceiveLimits};
use kr_protocol::identity::{BridgeFrame, BridgeHello, BridgeTarget};
use kr_protocol::ids::{ActionId, ActionWindowId, BuildId, EnvironmentId, RequestId, SessionId};
use kr_protocol::local::{LocalHelloAck, LocalPeer, LocalRole};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable, U64, Uuid};

/// The codec both ends of a bridge use.
fn codec() -> FrameCodec {
    FrameCodec::new(StreamKind::Control)
}

/// Names the `kr` to test where it is not the one this suite was built beside.
///
/// The suite is an artefact of its own: the WSL acceptance installs it inside a distribution and
/// runs it there, away from the build tree the compiler baked into it. Where this is unset the
/// suite tests its own build, which is what `cargo test` gives it.
const COMMAND_BINARY_VARIABLE: &str = "KR_TEST_COMMAND_BINARY";

/// The `kr` these tests launch, on the internal disk.
///
/// A directory of this run's own, removed when the run ends.
fn command_binary() -> PathBuf {
    use std::sync::OnceLock;
    static COPIED: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    let (_directory, binary) = COPIED.get_or_init(|| {
        let directory = tempfile::TempDir::new().expect("a directory on the internal disk");
        let given = std::env::var_os(COMMAND_BINARY_VARIABLE).map(PathBuf::from);
        let source = given
            .as_deref()
            .unwrap_or_else(|| Path::new(env!("CARGO_BIN_EXE_kr")));
        let destination = directory
            .path()
            .join(source.file_name().expect("the command binary has a name"));
        kr_ipc::testing::place_program(source, &destination);
        // The operating system checks a binary it has not seen before on its first run, and that
        // check takes seconds where a run takes milliseconds. Pay it here, where nothing is timed.
        let _ = Command::new(&destination)
            .arg("--version")
            .current_dir(directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        (directory, destination)
    });
    binary.clone()
}

/// A bridge helper running as a child process, with its streams held here.
struct Helper {
    child: Child,
    input: std::process::ChildStdin,
    output: std::process::ChildStdout,
    /// Set once the helper has been waited for, which is what stops its watchdog.
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Helper {
    /// Starts `kr bridge --stdio` against the environment tree given.
    fn start(tree: &kr_ipc::testing::TempHost) -> Self {
        Self::start_with(tree, &[])
    }

    /// Starts `kr bridge --stdio` against the tree given, with these variables as well.
    fn start_with(tree: &kr_ipc::testing::TempHost, extra: &[(&str, &str)]) -> Self {
        Self::start_without(tree, extra, &[])
    }

    /// Starts `kr bridge --stdio` as [`Self::start_with`] does, with these variables absent.
    fn start_without(
        tree: &kr_ipc::testing::TempHost,
        extra: &[(&str, &str)],
        absent: &[&str],
    ) -> Self {
        let mut command = Command::new(command_binary());
        for name in absent {
            command.env_remove(name);
        }
        let mut child = command
            .args(["bridge", "--stdio"])
            .envs(extra.iter().copied())
            // The tree is the destination environment. Nothing else about this process's
            // environment reaches the helper's authority: these two say where the sockets are.
            .env(
                kr_ipc::paths::RUNTIME_DIR_VARIABLE,
                tree.paths().runtime_root(),
            )
            .env(kr_ipc::paths::STATE_DIR_VARIABLE, tree.paths().state_root())
            .current_dir(std::env::temp_dir())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the bridge helper starts");
        let input = child.stdin.take().expect("its standard input");
        let output = child.stdout.take().expect("its standard output");
        // A read that waits for a frame the helper will never write would hold this suite for good.
        // The helper is this test's own child and is not collected until `done` is set, so its
        // number is still its own when the watchdog ends it.
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watched = std::sync::Arc::clone(&done);
        let pid = child.id();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(90));
            if !watched.load(std::sync::atomic::Ordering::SeqCst) {
                let _ = Command::new("/bin/kill")
                    .args(["-9", &pid.to_string()])
                    .status();
            }
        });
        Self {
            child,
            input,
            output,
            done,
        }
    }

    /// Says the helper is about to be collected, so the watchdog leaves its number alone.
    fn disarm(&self) {
        self.done.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Writes one bridge frame to the helper.
    fn write(&mut self, frame: &BridgeFrame) {
        let bytes = codec().encode_message(frame).expect("the frame encodes");
        self.input.write_all(&bytes).expect("writes to the helper");
        self.input.flush().expect("flushes");
    }

    /// Writes raw bytes, for a test that is not sending a well-formed frame.
    fn write_bytes(&mut self, bytes: &[u8]) {
        let _ = self.input.write_all(bytes);
        let _ = self.input.flush();
    }

    /// Reads one bridge frame from the helper.
    fn read(&mut self) -> BridgeFrame {
        let mut prefix = [0_u8; 4];
        read_exact(&mut self.output, &mut prefix).expect("a length prefix");
        let declared = u32::from_be_bytes(prefix) as usize;
        assert!(
            declared <= StreamKind::Control.max_payload_len(),
            "the helper never writes a frame past the bound"
        );
        let mut payload = vec![0_u8; declared];
        read_exact(&mut self.output, &mut payload).expect("a payload");
        kr_cbor::from_canonical_slice(&payload, &StreamKind::Control.cbor_limits())
            .expect("a bridge frame")
    }

    /// Ends the helper's input and waits for it, returning its exit code and standard error.
    fn finish(mut self) -> (Option<i32>, String) {
        self.disarm();
        drop(self.input);
        let mut diagnostics = String::new();
        if let Some(mut stderr) = self.child.stderr.take() {
            let _ = stderr.read_to_string(&mut diagnostics);
        }
        let status = self.child.wait().expect("the helper ends");
        (status.code(), diagnostics)
    }
}

fn read_exact(source: &mut impl Read, buffer: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = source.read(&mut buffer[filled..])?;
        if read == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        filled += read;
    }
    Ok(())
}

fn hello(ingress: ActorIngress) -> BridgeFrame {
    hello_to(ingress, false, BridgeTarget::Controller)
}

fn hello_to(ingress: ActorIngress, start: bool, target: BridgeTarget) -> BridgeFrame {
    BridgeFrame::Hello(Box::new(BridgeHello {
        protocol_version: PROTOCOL_VERSION,
        build_id: BuildId::new("kr/test").expect("a build"),
        origin_environment_id: EnvironmentId::new(Uuid::from_bytes([8; 16])),
        origin_ingress: ingress,
        already_bridged: false,
        start,
        target,
    }))
}

/// A control endpoint that answers the local handshake and one read.
///
/// It stands in for the destination environment's control daemon. Nothing here checks authority:
/// what these tests are about is which frames cross the bridge and which do not.
async fn stub_controller(
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: EnvironmentId,
    answer: std::result::Result<ParamsValue, ProtocolError>,
) -> tokio::task::JoinHandle<()> {
    stub_controller_seeing(
        endpoint,
        environment_id,
        answer,
        u64::from(kr_ipc::paths::current_uid()),
    )
    .await
}

/// What a daemon acknowledges a hello with: the user it says it authenticated the caller as, and the
/// build it states, if it states one.
fn hello_ack(
    environment_id: EnvironmentId,
    authenticated_uid: u64,
    build: Option<kr_protocol::local::LocalBuild>,
) -> LocalHelloAck {
    hello_ack_as(
        LocalRole::Controller,
        environment_id,
        authenticated_uid,
        build,
    )
}

/// [`hello_ack`], for a daemon or a worker.
fn hello_ack_as(
    role: LocalRole,
    environment_id: EnvironmentId,
    authenticated_uid: u64,
    build: Option<kr_protocol::local::LocalBuild>,
) -> LocalHelloAck {
    let connection_id = kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid());
    LocalHelloAck {
        selected_version: PROTOCOL_VERSION,
        role,
        connection_id,
        environment_id,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        // The helper checks that the daemon it reached authenticated it as the user it runs as.
        peer: LocalPeer {
            uid: U64::new(authenticated_uid),
            gid: U64::new(0),
            pid: Nullable::null(),
        },
        action_window: ActionWindow {
            action_window_id: kr_protocol::ids::ActionWindowId::new("w").expect("a window"),
            connection_id,
            boot_epoch: kr_protocol::ids::BootEpoch::new(1),
            issued_at_ms: kr_protocol::scalars::TimestampMs::new(0),
            valid_for_ms: DurationMs::new(120_000),
        },
        capabilities: CanonicalSet::new(),
        max_receive: ReceiveLimits::default(),
        build,
    }
}

/// A daemon of a build from before a hello could say where an invocation began.
///
/// It answers an ordinary hello, stating `build`, and ends the connection a hello that carries an
/// origin arrived on without a word, which is what a host that cannot decode the frame does. It
/// serves every connection that is made to it, and counts the ones that said where they began.
async fn stub_earlier_peer(
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: EnvironmentId,
    role: LocalRole,
    build: Option<kr_protocol::local::LocalBuild>,
    bridged: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> tokio::task::JoinHandle<()> {
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the stub endpoint");
    tokio::spawn(async move {
        while let Ok((connection, _peer)) = listener.accept().await {
            let build = build.clone();
            let bridged = std::sync::Arc::clone(&bridged);
            tokio::spawn(async move {
                let (mut reader, mut writer) =
                    kr_ipc::framed::split(connection, StreamKind::Control);
                let Ok(ControlFrame::Hello(hello)) = reader.read_message::<ControlFrame>().await
                else {
                    return;
                };
                if hello.origin.is_some() {
                    bridged.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    return;
                }
                let acknowledgement = hello_ack_as(
                    role,
                    environment_id,
                    u64::from(kr_ipc::paths::current_uid()),
                    build,
                );
                if writer
                    .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
                    .await
                    .is_err()
                {
                    return;
                }
                while reader.read_message::<ControlFrame>().await.is_ok() {}
            });
        }
    })
}

/// [`stub_controller`], naming the user it says it authenticated the caller as.
async fn stub_controller_seeing(
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: EnvironmentId,
    answer: std::result::Result<ParamsValue, ProtocolError>,
    authenticated_uid: u64,
) -> tokio::task::JoinHandle<()> {
    stub_controller_hearing(endpoint, environment_id, answer, authenticated_uid, None).await
}

/// [`stub_controller_seeing`], keeping the hello it was sent where the test can read it.
async fn stub_controller_hearing(
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: EnvironmentId,
    answer: std::result::Result<ParamsValue, ProtocolError>,
    authenticated_uid: u64,
    heard: Option<std::sync::Arc<std::sync::Mutex<Option<kr_protocol::local::LocalHello>>>>,
) -> tokio::task::JoinHandle<()> {
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the stub endpoint");
    tokio::spawn(async move {
        let Ok((connection, _peer)) = listener.accept().await else {
            return;
        };
        let (mut reader, mut writer) = kr_ipc::framed::split(connection, StreamKind::Control);
        let Ok(ControlFrame::Hello(hello)) = reader.read_message::<ControlFrame>().await else {
            return;
        };
        if let Some(heard) = heard {
            *heard.lock().expect("the slot") = Some(hello);
        }
        let acknowledgement = hello_ack(
            environment_id,
            authenticated_uid,
            Some(kr_protocol::local::LocalBuild::this(
                BuildId::new("kr-controller/test").expect("a build"),
            )),
        );
        if writer
            .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
            .await
            .is_err()
        {
            return;
        }
        while let Ok(frame) = reader.read_message::<ControlFrame>().await {
            match frame {
                ControlFrame::Request(request) => {
                    let response = ControlFrame::Response(Response {
                        request_id: request.request_id,
                        outcome: match answer.clone() {
                            Ok(value) => Outcome::Ok(value),
                            Err(error) => Outcome::Error(error),
                        },
                    });
                    if writer.write_message(&response).await.is_err() {
                        return;
                    }
                }
                ControlFrame::Mutation(mutation) => {
                    let outcome = if mutation.action_window_id.as_str() == "w" {
                        match answer.clone() {
                            Ok(value) => Outcome::Ok(value),
                            Err(error) => Outcome::Error(error),
                        }
                    } else {
                        Outcome::Error(ProtocolError::new(
                            ErrorCode::PermissionDenied,
                            "this action carries an unknown or expired action window",
                        ))
                    };
                    let response = ControlFrame::Response(Response {
                        request_id: mutation.request_id,
                        outcome,
                    });
                    if writer.write_message(&response).await.is_err() {
                        return;
                    }
                }
                _ => {}
            }
        }
    })
}

/// KR-REQ-03.12: the helper refuses a bridge opened for any network ingress before it connects to
/// the destination, so a network actor is never served there as a local one.
#[test]
fn a_handshake_that_declares_a_network_actor_is_refused_before_anything_is_connected() {
    let tree = kr_ipc::testing::TempHost::create();
    // Nothing is listening on the destination's control endpoint. The refusal still arrives, which
    // is what says it came before the connection rather than after one failed.
    for ingress in ActorIngress::ALL
        .iter()
        .copied()
        .filter(|ingress| *ingress != ActorIngress::LocalIpc)
    {
        let mut helper = Helper::start(&tree);
        helper.write(&hello(ingress));
        match helper.read() {
            BridgeFrame::Refused(error) => {
                assert_eq!(error.code, ErrorCode::PermissionDenied, "{ingress:?}");
                assert!(
                    error.message.contains("locally authenticated"),
                    "{}",
                    error.message
                );
            }
            other => panic!("expected a refusal for {ingress:?}, got {other:?}"),
        }
        let (code, diagnostics) = helper.finish();
        assert_ne!(code, Some(0), "a refused bridge does not exit zero");
        // Standard error is diagnostic, and it says the same thing the frame said.
        assert!(
            diagnostics.contains("locally authenticated"),
            "{diagnostics}"
        );
    }
}

/// KR-REQ-03.12: a request that has already crossed a bridge is not carried over a second one.
#[test]
fn a_request_that_has_already_crossed_a_bridge_is_not_chained() {
    let tree = kr_ipc::testing::TempHost::create();
    let mut helper = Helper::start(&tree);
    let BridgeFrame::Hello(mut opening) = hello(ActorIngress::LocalIpc) else {
        unreachable!("the opening frame is a hello")
    };
    opening.already_bridged = true;
    helper.write(&BridgeFrame::Hello(opening));
    match helper.read() {
        BridgeFrame::Refused(error) => {
            assert_eq!(error.code, ErrorCode::PermissionDenied);
            assert!(error.message.contains("at most one"), "{}", error.message);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_ne!(helper.finish().0, Some(0));
}

#[test]
fn a_protocol_major_the_helper_does_not_speak_is_refused() {
    let tree = kr_ipc::testing::TempHost::create();
    let mut helper = Helper::start(&tree);
    let BridgeFrame::Hello(mut opening) = hello(ActorIngress::LocalIpc) else {
        unreachable!("the opening frame is a hello")
    };
    opening.protocol_version = ProtocolVersion {
        major: PROTOCOL_VERSION.major + 1,
        minor: 0,
    };
    helper.write(&BridgeFrame::Hello(opening));
    match helper.read() {
        BridgeFrame::Refused(error) => assert_eq!(error.code, ErrorCode::UnsupportedSchema),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_ne!(helper.finish().0, Some(0));
}

#[test]
fn a_frame_past_the_bound_is_refused_rather_than_truncated() {
    let tree = kr_ipc::testing::TempHost::create();
    let mut helper = Helper::start(&tree);
    // One byte past the control-frame payload maximum, and no payload behind it. A helper that
    // truncated would wait for the bytes; this one ends without connecting to anything.
    let declared = u32::try_from(StreamKind::Control.max_payload_len() + 1).expect("fits");
    helper.write_bytes(&declared.to_be_bytes());
    let (code, diagnostics) = helper.finish();
    assert_ne!(code, Some(0));
    assert!(
        diagnostics.contains("exceeds") || diagnostics.contains("limit"),
        "the helper says why it stopped: {diagnostics}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_locally_authenticated_invocation_carries_frames_to_the_destination_and_back() {
    let tree = kr_ipc::testing::TempHost::create();
    let environment = tree.environment();
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let served = ParamsValue::from_typed(&kr_protocol::hostinfo::EnvironmentListResult {
        environments: Vec::new(),
    })
    .expect("the answer encodes");
    let stub = stub_controller(endpoint, tree.environment_id(), Ok(served.clone())).await;

    let mut helper = Helper::start(&tree);
    helper.write(&hello(ActorIngress::LocalIpc));
    match helper.read() {
        BridgeFrame::HelloAck(acknowledgement) => {
            // The destination's own identity, not the invoker's.
            assert_eq!(acknowledgement.environment_id, tree.environment_id());
            assert_eq!(acknowledgement.role, LocalRole::Controller);
            assert_eq!(
                acknowledgement.max_frame_len,
                U64::new(StreamKind::Control.max_frame_len() as u64)
            );
        }
        other => panic!("expected an acknowledgement, got {other:?}"),
    }

    helper.write(&BridgeFrame::Control(Box::new(ControlFrame::Request(
        Request {
            request_id: RequestId::new(7),
            method: Method::EnvironmentList.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::empty(),
        },
    ))));
    match helper.read() {
        BridgeFrame::Control(carried) => match *carried {
            ControlFrame::Response(response) => {
                assert_eq!(response.request_id, RequestId::new(7));
                assert_eq!(response.outcome, Outcome::Ok(served));
            }
            other => panic!("expected a response, got {other:?}"),
        },
        other => panic!("expected a carried frame, got {other:?}"),
    }
    let (code, _) = helper.finish();
    assert_eq!(code, Some(0));
    stub.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_session_still_answers_session_closed_across_the_bridge() {
    // Section 3: an explicit create or attach may start the selected distribution and still
    // returns `SESSION_CLOSED` for an old closed session. The bridge carries that answer through
    // unchanged rather than turning it into a new session or a transport failure.
    let tree = kr_ipc::testing::TempHost::create();
    let environment = tree.environment();
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let closed = ProtocolError::new(ErrorCode::SessionClosed, "that session is closed");
    let stub = stub_controller(endpoint, tree.environment_id(), Err(closed.clone())).await;

    let mut helper = Helper::start(&tree);
    helper.write(&hello(ActorIngress::LocalIpc));
    assert!(matches!(helper.read(), BridgeFrame::HelloAck(_)));
    helper.write(&BridgeFrame::Control(Box::new(ControlFrame::Request(
        Request {
            request_id: RequestId::new(1),
            method: Method::SessionRead.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::empty(),
        },
    ))));
    match helper.read() {
        BridgeFrame::Control(carried) => match *carried {
            ControlFrame::Response(Response {
                outcome: Outcome::Error(error),
                ..
            }) => assert_eq!(error, closed),
            other => panic!("expected the destination's own refusal, got {other:?}"),
        },
        other => panic!("expected a carried frame, got {other:?}"),
    }
    helper.finish();
    stub.abort();
}

/// The command an invoker opens a bridge with in these tests.
///
/// The helper is the real `kr bridge --stdio`, started the way `wsl.exe --exec` and a container
/// runtime's exec start it: a child process with its standard streams piped. What differs from a
/// real invocation is only where the destination environment is, and `env` is how a test says that
/// without changing this process's own environment, which the other tests here share.
#[cfg(unix)]
fn opening_against(
    tree: &kr_ipc::testing::TempHost,
    environment_id: EnvironmentId,
    target: BridgeTarget,
) -> kr_controller::bridge::invoke::Opening {
    kr_controller::bridge::invoke::Opening {
        command: kr_controller::bridge::launch::BridgeCommand {
            program: "/usr/bin/env".to_owned(),
            arguments: vec![
                format!(
                    "{}={}",
                    kr_ipc::paths::RUNTIME_DIR_VARIABLE,
                    tree.paths().runtime_root().display()
                ),
                format!(
                    "{}={}",
                    kr_ipc::paths::STATE_DIR_VARIABLE,
                    tree.paths().state_root().display()
                ),
                command_binary().display().to_string(),
                "bridge".to_owned(),
                "--stdio".to_owned(),
            ],
        },
        environment_id,
        hello: BridgeHello {
            protocol_version: PROTOCOL_VERSION,
            build_id: BuildId::new("kr/test").expect("a build"),
            origin_environment_id: EnvironmentId::new(Uuid::from_bytes([8; 16])),
            origin_ingress: ActorIngress::LocalIpc,
            already_bridged: false,
            start: false,
            target,
        },
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invoker_opens_a_bridge_and_carries_a_request_over_it() {
    // The invoking half, end to end: the helper is started, the opening frames are exchanged, the
    // identity that answers is compared with the one the enrolment names, and a read crosses and
    // comes back. Nothing here stands in for the invoker.
    let tree = kr_ipc::testing::TempHost::create();
    let environment = tree.environment();
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let served = ParamsValue::from_typed(&kr_protocol::hostinfo::EnvironmentListResult {
        environments: Vec::new(),
    })
    .expect("the answer encodes");
    let stub = stub_controller(endpoint, tree.environment_id(), Ok(served.clone())).await;

    let opening = opening_against(&tree, tree.environment_id(), BridgeTarget::Controller);
    let mut invocation = opening.launch().await.expect("the bridge opens");
    assert_eq!(
        invocation.acknowledgement().environment_id,
        tree.environment_id()
    );
    assert_eq!(invocation.acknowledgement().role, LocalRole::Controller);

    let response = invocation
        .request(Request {
            request_id: RequestId::new(11),
            method: Method::EnvironmentList.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::empty(),
        })
        .await
        .expect("the destination answers");
    assert_eq!(response.request_id, RequestId::new(11));
    assert_eq!(response.outcome, Outcome::Ok(served.clone()));

    // A mutation quoting the window the destination acknowledged crosses the same way.
    let window = invocation.acknowledgement().action_window.clone();
    let mutated = invocation
        .mutate(MutationRequest {
            request_id: RequestId::new(12),
            method: Method::EnvironmentEnrol.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable::null(),
            target: ActionTarget::environment(tree.environment_id()),
            expected: ParamsValue::empty(),
            action_window_id: window.action_window_id,
            requested_ttl_ms: DurationMs::new(10_000),
            params: ParamsValue::empty(),
        })
        .await
        .expect("the destination answers");
    assert_eq!(mutated.outcome, Outcome::Ok(served));

    invocation.close().await.expect("the helper ends");
    stub.abort();
}

/// KR-REQ-03.12: a refresh carried over a bridge, which the destination would serve as a local
/// request and which would open a bridge of its own, is refused at the first bridge.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_that_would_open_a_second_bridge_is_refused_at_the_first() {
    // A federated proxy is outside this version. The destination serves what crosses as an ordinary
    // local request and cannot tell that it arrived over a bridge, so the helper refuses to carry a
    // method that would open another one. This goes through a real bridge rather than setting the
    // handshake's own flag.
    let tree = kr_ipc::testing::TempHost::create();
    let environment = tree.environment();
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let served = ParamsValue::from_typed(&kr_protocol::hostinfo::EnvironmentListResult {
        environments: Vec::new(),
    })
    .expect("the answer encodes");
    let stub = stub_controller(endpoint, tree.environment_id(), Ok(served)).await;

    let opening = opening_against(&tree, tree.environment_id(), BridgeTarget::Controller);
    let mut invocation = opening.launch().await.expect("the bridge opens");
    let window = invocation.acknowledgement().action_window.clone();
    let refusal = invocation
        .mutate(MutationRequest {
            request_id: RequestId::new(21),
            method: Method::EnvironmentRefresh.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable::null(),
            target: ActionTarget::environment(tree.environment_id()),
            expected: ParamsValue::empty(),
            action_window_id: window.action_window_id,
            requested_ttl_ms: DurationMs::new(10_000),
            params: ParamsValue::empty(),
        })
        .await
        .expect_err("a refusal");
    match refusal {
        kr_controller::bridge::invoke::Refusal::Destination(error) => {
            assert_eq!(error.code, ErrorCode::PermissionDenied);
            assert!(error.message.contains("at most one"), "{}", error.message);
        }
        other => panic!("expected the destination's refusal, got {other}"),
    }
    stub.abort();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_environment_that_answers_with_another_identity_is_refused() {
    // A distribution registered again under the name it had, or a container recreated under a
    // reused one, answers as a different installation. The record does not carry over to it, and
    // the refusal comes before any request crosses.
    let tree = kr_ipc::testing::TempHost::create();
    let environment = tree.environment();
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let served = ParamsValue::from_typed(&kr_protocol::hostinfo::EnvironmentListResult {
        environments: Vec::new(),
    })
    .expect("the answer encodes");
    let stub = stub_controller(endpoint, tree.environment_id(), Ok(served)).await;

    let enrolled = EnvironmentId::new(Uuid::from_bytes([77; 16]));
    assert_ne!(enrolled, tree.environment_id());
    let refusal = opening_against(&tree, enrolled, BridgeTarget::Controller)
        .launch()
        .await
        .expect_err("a refusal");
    assert_eq!(
        refusal,
        kr_controller::bridge::invoke::Refusal::IdentityMismatch {
            enrolled,
            answered: tree.environment_id(),
        }
    );
    stub.abort();
}

#[test]
fn the_command_asks_for_stdio_by_the_name_the_specification_uses() {
    // `wsl.exe --distribution <name> --user <user> --exec <absolute-kr-path> bridge --stdio` is
    // written out in section 3. The spelling is part of the contract: a helper that answered to
    // some other word would not be reachable by the invocation the specification names.
    let output = Command::new(command_binary())
        .args(["bridge", "--help"])
        .stdin(Stdio::null())
        .output()
        .expect("the command runs");
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--stdio"), "{help}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_locally_authenticated_invocation_carries_a_mutation_quoting_the_bridged_action_window() {
    let tree = kr_ipc::testing::TempHost::create();
    let environment = tree.environment();
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let served = ParamsValue::from_typed(&kr_protocol::hostinfo::EnvironmentListResult {
        environments: Vec::new(),
    })
    .expect("the answer encodes");
    let stub = stub_controller(endpoint, tree.environment_id(), Ok(served.clone())).await;

    let mut helper = Helper::start(&tree);
    helper.write(&hello(ActorIngress::LocalIpc));
    let window_id = match helper.read() {
        BridgeFrame::HelloAck(acknowledgement) => {
            assert_eq!(acknowledgement.environment_id, tree.environment_id());
            assert_eq!(acknowledgement.role, LocalRole::Controller);
            acknowledgement.action_window.action_window_id
        }
        other => panic!("expected an acknowledgement, got {other:?}"),
    };

    helper.write(&BridgeFrame::Control(Box::new(ControlFrame::Mutation(
        Box::new(MutationRequest {
            request_id: RequestId::new(42),
            method: Method::EnvironmentEnrol.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable::null(),
            target: ActionTarget::environment(tree.environment_id()),
            expected: ParamsValue::empty(),
            action_window_id: window_id,
            requested_ttl_ms: DurationMs::new(10_000),
            params: ParamsValue::empty(),
        }),
    ))));
    match helper.read() {
        BridgeFrame::Control(carried) => match *carried {
            ControlFrame::Response(response) => {
                assert_eq!(response.request_id, RequestId::new(42));
                assert_eq!(response.outcome, Outcome::Ok(served));
            }
            other => panic!("expected a response, got {other:?}"),
        },
        other => panic!("expected a carried frame, got {other:?}"),
    }
    let (code, _) = helper.finish();
    assert_eq!(code, Some(0));
    stub.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mutation_with_an_invalid_action_window_is_rejected_by_admission_checks() {
    let tree = kr_ipc::testing::TempHost::create();
    let environment = tree.environment();
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let served = ParamsValue::from_typed(&kr_protocol::hostinfo::EnvironmentListResult {
        environments: Vec::new(),
    })
    .expect("the answer encodes");
    let stub = stub_controller(endpoint, tree.environment_id(), Ok(served)).await;

    let mut helper = Helper::start(&tree);
    helper.write(&hello(ActorIngress::LocalIpc));
    assert!(matches!(helper.read(), BridgeFrame::HelloAck(_)));

    // Send mutation with an expired/wrong action window
    helper.write(&BridgeFrame::Control(Box::new(ControlFrame::Mutation(
        Box::new(MutationRequest {
            request_id: RequestId::new(43),
            method: Method::EnvironmentEnrol.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable::null(),
            target: ActionTarget::environment(tree.environment_id()),
            expected: ParamsValue::empty(),
            action_window_id: ActionWindowId::new("wrong-window").expect("valid id"),
            requested_ttl_ms: DurationMs::new(10_000),
            params: ParamsValue::empty(),
        }),
    ))));
    match helper.read() {
        BridgeFrame::Control(carried) => match *carried {
            ControlFrame::Response(response) => {
                assert_eq!(response.request_id, RequestId::new(43));
                match response.outcome {
                    Outcome::Error(error) => assert_eq!(error.code, ErrorCode::PermissionDenied),
                    Outcome::Ok(_) => panic!("expected rejection of invalid window"),
                }
            }
            other => panic!("expected a response, got {other:?}"),
        },
        other => panic!("expected a carried frame, got {other:?}"),
    }
    let (code, _) = helper.finish();
    assert_eq!(code, Some(0));
    stub.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_session_target_returns_session_closed_when_targeted_by_bridge() {
    let tree = kr_ipc::testing::TempHost::create();
    let environment = tree.environment();
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let closed_session_id = SessionId::new(kr_ipc::new_uuid());

    let stub = stub_controller(
        endpoint,
        tree.environment_id(),
        Err(ProtocolError::new(
            ErrorCode::SessionClosed,
            "that session is closed",
        )),
    )
    .await;

    let mut helper = Helper::start(&tree);
    let opening = BridgeHello {
        protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
        build_id: BuildId::new("kr/test").expect("a build"),
        origin_environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
        origin_ingress: ActorIngress::LocalIpc,
        already_bridged: false,
        start: false,
        target: BridgeTarget::Session {
            session_id: closed_session_id,
            clipboard_writes: true,
        },
    };
    helper.write(&BridgeFrame::Hello(Box::new(opening)));
    match helper.read() {
        BridgeFrame::Refused(error) => {
            assert_eq!(error.code, ErrorCode::SessionClosed);
        }
        other => panic!("expected refusal with SESSION_CLOSED, got {other:?}"),
    }
    let (code, _) = helper.finish();
    assert_ne!(code, None);
    stub.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_journal_left_behind_by_a_live_session_is_not_read_as_a_closure() {
    // A worker writes a session's journal while that session is running, so the file says a session
    // ran here and nothing about whether it ended. Answering `SESSION_CLOSED` from the file alone
    // would tell a caller that a live session had finished.
    let tree = kr_ipc::testing::TempHost::create();
    let environment = tree.environment();
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let journal = environment.journal_database(session_id);
    std::fs::create_dir_all(journal.parent().expect("a journals directory"))
        .expect("the journals directory");
    std::fs::write(&journal, b"a journal this run left behind").expect("a journal file");

    // The destination's daemon knows no such session: it has no closure record for it.
    let stub = stub_controller(
        endpoint,
        tree.environment_id(),
        Err(ProtocolError::new(
            ErrorCode::UnknownSession,
            "this host has no session by that identity",
        )),
    )
    .await;

    let mut helper = Helper::start(&tree);
    helper.write(&BridgeFrame::Hello(Box::new(BridgeHello {
        protocol_version: PROTOCOL_VERSION,
        build_id: BuildId::new("kr/test").expect("a build"),
        origin_environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
        origin_ingress: ActorIngress::LocalIpc,
        already_bridged: false,
        start: false,
        target: BridgeTarget::Session {
            session_id,
            clipboard_writes: true,
        },
    })));
    let (code, diagnostics) = helper.finish();
    assert_ne!(code, Some(0), "the helper ends rather than serving");
    assert!(
        !diagnostics.contains("that session is closed"),
        "the file alone is not a closure: {diagnostics}"
    );
    stub.abort();
}

#[test]
fn a_helper_exits_without_hanging_when_input_remains_open_after_refusal() {
    let tree = kr_ipc::testing::TempHost::create();
    let mut helper = Helper::start(&tree);
    // Write a refusal-triggering frame (network ingress).
    helper.write(&hello(ActorIngress::PairedDevice));
    match helper.read() {
        BridgeFrame::Refused(error) => {
            assert_eq!(error.code, ErrorCode::PermissionDenied);
        }
        other => panic!("expected refusal, got {other:?}"),
    }
    // Note: helper.input is NOT dropped yet. The helper process must terminate without
    // hanging even though the input pipe remains open.
    let (tx, rx) = std::sync::mpsc::channel();
    helper.disarm();
    let mut child = helper.child;
    let waiter = std::thread::spawn(move || {
        let status = child.wait().expect("child finishes");
        let _ = tx.send(status);
    });
    // Wait at most 2 seconds; a hung helper would block until test timeout.
    let status = rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("the helper exited promptly without waiting for stdin to close");
    assert!(!status.success());
    let _ = waiter.join();
}

/// The user this process runs as, by the account's own name.
fn own_account() -> String {
    let named = Command::new("/usr/bin/id")
        .arg("-un")
        .output()
        .expect("id runs");
    String::from_utf8(named.stdout)
        .expect("a name")
        .trim()
        .to_owned()
}

/// KR-REQ-03.14, 03.15: what the destination says it is, and where a session created through this
/// bridge starts, come from the helper's own environment inside it and not from the invoking host.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_acknowledgement_carries_the_destinations_own_account_base_and_build() {
    let tree = kr_ipc::testing::TempHost::create();
    let endpoint = tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let stub = stub_controller(endpoint, tree.environment_id(), Ok(ParamsValue::empty())).await;
    let mut helper = Helper::start_with(
        &tree,
        &[
            ("HOME", "/home/destination-user"),
            ("LANG", "en_ZA.UTF-8"),
            // Variables the person who started the helper has set, which are not the destination's
            // account and which a create must never carry from here to a shell there.
            ("USER", "name-the-caller-chose"),
            ("LOGNAME", "name-the-caller-chose"),
            ("AWS_SECRET_ACCESS_KEY", "a-credential"),
        ],
    );
    helper.write(&hello(ActorIngress::LocalIpc));
    let BridgeFrame::HelloAck(acknowledgement) = helper.read() else {
        panic!("expected an acknowledgement");
    };
    assert_eq!(acknowledgement.base.home, "/home/destination-user");
    let names: Vec<&str> = acknowledgement
        .base
        .variables
        .iter()
        .map(|variable| variable.name.as_str())
        .collect();
    assert!(
        names.contains(&"HOME") && names.contains(&"LANG"),
        "{names:?}"
    );
    assert!(
        names
            .iter()
            .all(|name| { kr_protocol::identity::DESTINATION_BASE_VARIABLES.contains(name) }),
        "only what the protocol allows is offered: {names:?}"
    );
    assert!(
        !names.contains(&"AWS_SECRET_ACCESS_KEY"),
        "a credential in the helper's environment is not offered: {names:?}"
    );
    // The account is the one the operating system has for this user, not a variable.
    assert_eq!(acknowledgement.os_user, own_account());
    assert_ne!(acknowledgement.os_user, "name-the-caller-chose");
    // The destination's own build and protocol version, as its daemon stated them.
    assert_eq!(
        acknowledgement.build,
        Some(kr_protocol::local::LocalBuild::this(
            BuildId::new("kr-controller/test").expect("a build")
        ))
    );
    drop(helper.finish());
    stub.abort();
}

/// KR-REQ-03.14, 03.15: a session created through a bridge starts in a home it also has, whatever
/// the helper's own `HOME` was. A destination whose login gave the helper no `HOME`, or one that is
/// not an absolute path, still offers a home directory, and the snapshot a shell is started with
/// names that same directory as `HOME` rather than carrying nothing or the invalid value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_home_a_session_starts_in_is_the_home_it_is_given() {
    // The login's own `HOME`: kept as it is.
    let (home, variable) = base_for(&[("HOME", "/home/destination-user")], &[]).await;
    assert_eq!(home, "/home/destination-user");
    assert_eq!(variable.as_deref(), Some("/home/destination-user"));
    // No `HOME`, a relative one and an empty one: the directory the base names, as an absolute
    // path, and the snapshot's `HOME` is that same directory.
    for (what, set, absent) in [
        ("absent", &[][..], &["HOME"][..]),
        ("relative", &[("HOME", "relative/home")][..], &[][..]),
        ("empty", &[("HOME", "")][..], &[][..]),
    ] {
        let (home, variable) = base_for(set, absent).await;
        assert!(
            home.starts_with('/'),
            "{what}: the home offered is an absolute path: {home:?}"
        );
        assert_eq!(
            variable.as_deref(),
            Some(home.as_str()),
            "{what}: the snapshot's HOME is the directory the session starts in"
        );
    }
}

/// What a helper acknowledges as the destination's home and its snapshot's `HOME`, started with
/// these variables set and these absent.
async fn base_for(set: &[(&str, &str)], absent: &[&str]) -> (String, Option<String>) {
    let tree = kr_ipc::testing::TempHost::create();
    let endpoint = tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let stub = stub_controller(endpoint, tree.environment_id(), Ok(ParamsValue::empty())).await;
    let mut helper = Helper::start_without(&tree, set, absent);
    helper.write(&hello(ActorIngress::LocalIpc));
    let BridgeFrame::HelloAck(acknowledgement) = helper.read() else {
        panic!("expected an acknowledgement");
    };
    let variable = acknowledgement
        .base
        .variables
        .iter()
        .find(|variable| variable.name == "HOME")
        .map(|variable| variable.value.clone());
    drop(helper.finish());
    stub.abort();
    (acknowledgement.base.home.clone(), variable)
}

/// KR-REQ-03.13: a connection says hello once. A second hello carried over an open bridge could
/// admit the connection again under something else, so it is refused and not carried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_hello_is_not_carried_over_an_open_bridge() {
    let tree = kr_ipc::testing::TempHost::create();
    let endpoint = tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let stub = stub_controller(endpoint, tree.environment_id(), Ok(ParamsValue::empty())).await;
    let mut helper = Helper::start(&tree);
    helper.write(&hello(ActorIngress::LocalIpc));
    assert!(matches!(helper.read(), BridgeFrame::HelloAck(_)));
    helper.write(&BridgeFrame::Control(Box::new(ControlFrame::Hello(
        kr_protocol::local::LocalHello {
            offered_versions: vec![PROTOCOL_VERSION],
            build_id: BuildId::new("kr/test").expect("a build"),
            client: kr_protocol::local::LocalClientKind::Cli,
            capabilities: CanonicalSet::new(),
            max_receive: ReceiveLimits::default(),
            origin: None,
        },
    ))));
    match helper.read() {
        BridgeFrame::Refused(error) => assert_eq!(error.code, ErrorCode::PermissionDenied),
        other => panic!("a second hello is refused, not carried: {other:?}"),
    }
    drop(helper.finish());
    stub.abort();
}

/// KR-REQ-25.26: a socket forwarded from somewhere else is authenticated as whoever forwarded it,
/// so a daemon that did not see this helper's own user is not this environment's own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_that_did_not_authenticate_the_helper_as_its_own_user_is_refused() {
    let tree = kr_ipc::testing::TempHost::create();
    let endpoint = tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let stub = stub_controller_seeing(
        endpoint,
        tree.environment_id(),
        Ok(ParamsValue::empty()),
        u64::from(kr_ipc::paths::current_uid()) + 1,
    )
    .await;
    let mut helper = Helper::start(&tree);
    helper.write(&hello(ActorIngress::LocalIpc));
    match helper.read() {
        BridgeFrame::Refused(error) => {
            assert_eq!(error.code, ErrorCode::PermissionDenied);
            assert!(
                error.message.contains("not this environment's own"),
                "{}",
                error.message
            );
        }
        other => panic!("a daemon that saw another user is refused: {other:?}"),
    }
    drop(helper.finish());
    stub.abort();
}

/// KR-REQ-03.14: an opening that may not start anything and finds no daemon says so in a frame. The
/// invoker that read only the end of the stream could name nothing.
#[test]
fn a_destination_with_no_daemon_says_so_in_a_frame_when_nothing_may_be_started() {
    let tree = kr_ipc::testing::TempHost::create();
    for target in [
        BridgeTarget::Controller,
        BridgeTarget::Session {
            session_id: SessionId::new(kr_ipc::new_uuid()),
            clipboard_writes: true,
        },
    ] {
        let mut helper = Helper::start(&tree);
        helper.write(&hello_to(ActorIngress::LocalIpc, false, target));
        match helper.read() {
            BridgeFrame::Refused(error) => {
                assert_ne!(error.code, ErrorCode::PermissionDenied, "{error:?}");
                assert!(!error.message.is_empty());
            }
            other => panic!("expected a refusal naming what is missing, got {other:?}"),
        }
        let (code, _) = helper.finish();
        assert_ne!(code, Some(0));
    }
}

/// KR-REQ-03.13, KR-ACC-021: the helper tells the destination where the invocation it carries
/// began, in the hello it makes to the destination's daemon, and that is the invoker's own
/// declaration and never a thing the destination's own side made up. A helper that is not asked to
/// carry one tells it nothing, so the daemon sees a client of its own as it always did.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_helper_tells_the_destination_where_the_invocation_began() {
    let tree = kr_ipc::testing::TempHost::create();
    let endpoint = tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let heard = std::sync::Arc::new(std::sync::Mutex::new(None));
    let stub = stub_controller_hearing(
        endpoint,
        tree.environment_id(),
        Ok(ParamsValue::empty()),
        u64::from(kr_ipc::paths::current_uid()),
        Some(std::sync::Arc::clone(&heard)),
    )
    .await;
    let mut helper = Helper::start(&tree);
    helper.write(&hello(ActorIngress::LocalIpc));
    assert!(matches!(helper.read(), BridgeFrame::HelloAck(_)));
    let said = heard
        .lock()
        .expect("the slot")
        .clone()
        .expect("the destination was sent a hello");
    assert_eq!(
        said.origin,
        Some(kr_protocol::local::BridgeOrigin {
            environment_id: EnvironmentId::new(Uuid::from_bytes([8; 16])),
            ingress: ActorIngress::LocalIpc,
            clipboard_writes: false,
        }),
        "the destination hears the origin the invoker declared"
    );
    assert_eq!(said.client, kr_protocol::local::LocalClientKind::Cli);
    drop(helper.finish());
    stub.abort();
}

/// What a helper refuses with when the daemon it reaches is of an earlier build that ends a
/// connection saying where the invocation began, for an opening that does or does not start what
/// it needs, and how many such connections the daemon was made.
async fn refusal_from_an_earlier_daemon(
    start: bool,
    build: Option<kr_protocol::local::LocalBuild>,
) -> (ProtocolError, usize) {
    let tree = kr_ipc::testing::TempHost::create();
    let endpoint = tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let bridged = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let stub = stub_earlier_peer(
        endpoint,
        tree.environment_id(),
        LocalRole::Controller,
        build,
        std::sync::Arc::clone(&bridged),
    )
    .await;
    let mut helper = Helper::start(&tree);
    helper.write(&hello_to(
        ActorIngress::LocalIpc,
        start,
        BridgeTarget::Controller,
    ));
    let BridgeFrame::Refused(error) = helper.read() else {
        panic!("a daemon that takes no bridge is a refusal, not an acknowledgement");
    };
    drop(helper.finish());
    stub.abort();
    (error, bridged.load(std::sync::atomic::Ordering::SeqCst))
}

/// KR-REQ-03.13: a daemon of a build from before a hello could say where an invocation began ends
/// the connection that says it, which reads like a daemon that is not running. It answers an
/// ordinary connection, though, so the helper says what is true: which build it is, which build
/// the helper is, and that a restart is what to do. It does not carry the request without the
/// origin, so the daemon is made exactly one connection that declares one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_of_an_earlier_build_is_named_and_not_reported_absent() {
    let earlier = Some(kr_protocol::local::LocalBuild {
        build_id: BuildId::new("kr-controller/0.0.9").expect("a build"),
        protocol_version: kr_protocol::hello::PackageVersion::new(0, 0, 9),
    });
    for start in [false, true] {
        let (error, bridged) = refusal_from_an_earlier_daemon(start, earlier.clone()).await;
        assert_eq!(error.code, ErrorCode::UnsupportedSchema, "start {start}");
        assert!(
            error.message.contains("control daemon")
                && error
                    .message
                    .contains("kr-controller/0.0.9 with protocol 0.0.9")
                && error.message.contains("this helper is kr/")
                && error.message.contains("restart it"),
            "start {start}: {}",
            error.message
        );
        assert!(
            !error.message.contains("no KalaReach host is running"),
            "start {start}: a daemon that answers is running: {}",
            error.message
        );
        assert_eq!(
            bridged, 1,
            "start {start}: nothing was retried without the origin"
        );
    }
}

/// The same, for a daemon of a build that states none, which is every one from before builds were
/// stated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_that_states_no_build_is_said_to_state_none() {
    let (error, _) = refusal_from_an_earlier_daemon(false, None).await;
    assert_eq!(error.code, ErrorCode::UnsupportedSchema);
    assert!(
        error
            .message
            .contains("a build that does not state its build or its protocol version"),
        "{}",
        error.message
    );
}

/// A daemon of this build's own level that ends the connection which declares an origin has not
/// failed for being of an earlier build, and is not said to be: the helper reports the failure it
/// saw, and does not tell a person to restart something that is current.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_of_this_level_that_ends_a_connection_is_not_said_to_be_of_an_earlier_build() {
    let current = Some(kr_protocol::local::LocalBuild::this(
        BuildId::new("kr-controller/test").expect("a build"),
    ));
    let (error, bridged) = refusal_from_an_earlier_daemon(false, current).await;
    assert_ne!(
        error.code,
        ErrorCode::UnsupportedSchema,
        "{}",
        error.message
    );
    assert!(
        !error.message.contains("earlier build") && !error.message.contains("restart it"),
        "{}",
        error.message
    );
    assert_eq!(bridged, 1);
}

/// The same for a session's worker, which a bridge to a session reaches through its published
/// descriptor: a worker of an earlier build is named, with what to do about a worker, which is not
/// to restart it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_of_an_earlier_build_is_named_and_not_reported_absent() {
    use kr_protocol::identity::{BootIdentity, BootIdentitySource, ProcessStartIdentity};
    use kr_protocol::scalars::{AuthorisationKey, Bytes, TimestampMs};

    let tree = kr_ipc::testing::TempHost::create();
    let session_id = SessionId::new(Uuid::from_bytes([0x51; 16]));
    let socket = tree.root().join("w.sock");
    let endpoint = kr_ipc::paths::Endpoint::from_path(&socket).expect("an endpoint");
    let bridged = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let stub = stub_earlier_peer(
        endpoint,
        tree.environment_id(),
        LocalRole::Worker,
        Some(kr_protocol::local::LocalBuild {
            build_id: BuildId::new("kr-worker/0.0.9").expect("a build"),
            protocol_version: kr_protocol::hello::PackageVersion::new(0, 0, 9),
        }),
        std::sync::Arc::clone(&bridged),
    )
    .await;
    kr_ipc::descriptor::publish(
        &tree.environment(),
        &kr_protocol::worker::WorkerDescriptor {
            session_id,
            session_epoch: kr_protocol::ids::SessionEpoch::V1,
            environment_id: tree.environment_id(),
            display_number: kr_protocol::session::DisplayNumber::new(1),
            boot_identity: BootIdentity {
                source: BootIdentitySource::LinuxBootId,
                value: Bytes::new(b"boot".to_vec()),
            },
            process_start_identity: ProcessStartIdentity::new(
                42,
                kr_protocol::identity::ProcessStartSource::LinuxProcStat,
                99,
            ),
            protocol_version: PROTOCOL_VERSION,
            endpoint: socket.display().to_string(),
            worker_public_key: AuthorisationKey::from_bytes([1; 32]),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            published_at_ms: TimestampMs::new(1),
        },
    )
    .expect("publishes the descriptor");

    let mut helper = Helper::start(&tree);
    helper.write(&hello_to(
        ActorIngress::LocalIpc,
        false,
        BridgeTarget::Session {
            session_id,
            clipboard_writes: true,
        },
    ));
    let BridgeFrame::Refused(error) = helper.read() else {
        panic!("a worker that takes no bridge is a refusal, not an acknowledgement");
    };
    drop(helper.finish());
    stub.abort();
    assert_eq!(
        error.code,
        ErrorCode::UnsupportedSchema,
        "{}",
        error.message
    );
    assert!(
        error.message.contains("session worker")
            && error
                .message
                .contains("kr-worker/0.0.9 with protocol 0.0.9")
            && error.message.contains("with the kr of its own build"),
        "{}",
        error.message
    );
    assert_eq!(bridged.load(std::sync::atomic::Ordering::SeqCst), 1);
}
