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

/// The `kr` these tests launch, on the internal disk.
///
/// A directory of this run's own, removed when the run ends.
fn command_binary() -> PathBuf {
    use std::sync::OnceLock;
    static COPIED: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    let (_directory, binary) = COPIED.get_or_init(|| {
        let directory = tempfile::TempDir::new().expect("a directory on the internal disk");
        let source = Path::new(env!("CARGO_BIN_EXE_kr"));
        let destination = directory
            .path()
            .join(source.file_name().expect("the command binary has a name"));
        std::fs::copy(source, &destination).expect("copies the command binary");
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
}

impl Helper {
    /// Starts `kr bridge --stdio` against the environment tree given.
    fn start(tree: &kr_ipc::testing::TempHost) -> Self {
        let mut child = Command::new(command_binary())
            .args(["bridge", "--stdio"])
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
        Self {
            child,
            input,
            output,
        }
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
    BridgeFrame::Hello(Box::new(BridgeHello {
        protocol_version: PROTOCOL_VERSION,
        build_id: BuildId::new("kr/test").expect("a build"),
        origin_environment_id: EnvironmentId::new(Uuid::from_bytes([8; 16])),
        origin_ingress: ingress,
        already_bridged: false,
        target: BridgeTarget::Controller,
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
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the stub endpoint");
    tokio::spawn(async move {
        let Ok((connection, _peer)) = listener.accept().await else {
            return;
        };
        let (mut reader, mut writer) = kr_ipc::framed::split(connection, StreamKind::Control);
        let Ok(ControlFrame::Hello(_)) = reader.read_message::<ControlFrame>().await else {
            return;
        };
        let connection_id = kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid());
        let acknowledgement = LocalHelloAck {
            selected_version: PROTOCOL_VERSION,
            role: LocalRole::Controller,
            connection_id,
            environment_id,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            peer: LocalPeer {
                uid: U64::new(0),
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
        };
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
        target: BridgeTarget::Session {
            session_id: closed_session_id,
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
        target: BridgeTarget::Session { session_id },
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
