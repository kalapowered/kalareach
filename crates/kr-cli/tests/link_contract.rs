//! What an attached terminal may rely on from the connection it is attached over, whether that is
//! a socket on this host or a bridge to another environment.
//!
//! The attach loop is written once, against [`Link`], and both connections implement it. The same
//! contract is run against each, with the same scripted peer behind it: a connection that pushes
//! a keepalive, a renewed window and two notifications ahead of the answer to a request, then a
//! third notification, and then ends. A connection that lost any of that, or put it in another
//! order, would show a terminal a different session from the one the destination is serving.

#![cfg(unix)]

use std::time::Duration;

use kr_cli::bridge::link::{BridgedLink, Link};
use kr_controller::bridge::invoke::Opening;
use kr_controller::bridge::launch::BridgeCommand;
use kr_ipc::client::LocalClient;
use kr_protocol::actor::ActorIngress;
use kr_protocol::envelope::{
    ControlEvent, ControlFrame, Notification, Outcome, ParamsValue, Response,
};
use kr_protocol::frame::{FrameCodec, StreamKind};
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::identity::{
    BootIdentity, BootIdentitySource, BridgeFrame, BridgeHello, BridgeHelloAck, BridgeTarget,
    DestinationBase,
};
use kr_protocol::ids::{
    ActionWindowId, BootEpoch, BuildId, ConnectionId, EnvironmentId, EventSequence, EventType,
    RequestId, StreamId,
};
use kr_protocol::local::{LocalClientKind, LocalHelloAck, LocalPeer, LocalRole};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Bytes, CanonicalSet, DurationMs, Nullable, TimestampMs, U64, Uuid};

fn environment() -> EnvironmentId {
    EnvironmentId::new(Uuid::from_bytes([3; 16]))
}

fn window(id: &str, connection_id: ConnectionId) -> ActionWindow {
    ActionWindow {
        action_window_id: ActionWindowId::new(id).expect("a window"),
        connection_id,
        boot_epoch: BootEpoch::new(1),
        issued_at_ms: TimestampMs::new(0),
        valid_for_ms: DurationMs::new(120_000),
    }
}

fn notification(sequence: u64) -> ControlFrame {
    ControlFrame::Notification(Notification {
        stream_id: StreamId::new("s1").expect("a stream"),
        sequence: EventSequence::new(sequence),
        event_type: EventType::new("session.output").expect("an event type"),
        payload: ParamsValue::empty(),
    })
}

/// What the peer sends once it has been asked its first question, in order.
fn pushed(connection_id: ConnectionId) -> Vec<ControlFrame> {
    vec![
        ControlFrame::Event(ControlEvent::Keepalive),
        ControlFrame::Event(ControlEvent::ActionWindowRenewed(window(
            "w-second",
            connection_id,
        ))),
        notification(1),
        notification(2),
        ControlFrame::Response(Response {
            request_id: RequestId::new(1),
            outcome: Outcome::Ok(ParamsValue::empty()),
        }),
        notification(3),
    ]
}

/// The contract. Everything here is something the attach loop depends on.
async fn the_contract(link: &mut impl Link) {
    assert_eq!(link.action_window_id().as_str(), "w-first");
    assert!(link.build().is_some(), "the peer states its build");

    // The answer comes from behind a keepalive, a renewal and two notifications.
    let answer = tokio::time::timeout(Duration::from_secs(30), link.request(Method::HostInfo, &()))
        .await
        .expect("the answer arrives")
        .expect("the connection carried the request");
    assert_eq!(answer, Ok(ParamsValue::empty()));
    // A renewal that came before the answer is applied, so the next mutation quotes it.
    assert_eq!(link.action_window_id().as_str(), "w-second");

    // What arrived ahead of the answer is held, comes first, and is in the order it was sent. A
    // receive that is given up on, over and over, loses none of it.
    let mut sequences = Vec::new();
    while sequences.len() < 3 {
        tokio::select! {
            biased;
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
            frame = link.recv() => match frame.expect("a held or pushed frame") {
                ControlFrame::Notification(notification) => {
                    sequences.push(notification.sequence.get());
                }
                other => panic!("expected a notification, got {other:?}"),
            },
        }
    }
    assert_eq!(sequences, [1, 2, 3]);

    // The end of the connection is an error, and not a frame or a hang.
    let ended = tokio::time::timeout(Duration::from_secs(30), link.recv())
        .await
        .expect("an ended connection does not hold its caller");
    assert!(ended.is_err(), "{ended:?}");
}

/// A control endpoint that says hello, waits to be asked, and then pushes what a peer pushes.
async fn local_peer(endpoint: kr_ipc::paths::Endpoint) -> tokio::task::JoinHandle<()> {
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
    tokio::spawn(async move {
        let Ok((connection, _)) = listener.accept().await else {
            return;
        };
        let (mut reader, mut writer) = kr_ipc::framed::split(connection, StreamKind::Control);
        let Ok(ControlFrame::Hello(_)) = reader.read_message::<ControlFrame>().await else {
            return;
        };
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let acknowledgement = LocalHelloAck {
            selected_version: PROTOCOL_VERSION,
            role: LocalRole::Worker,
            connection_id,
            environment_id: environment(),
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            peer: LocalPeer {
                uid: U64::new(u64::from(kr_ipc::paths::current_uid())),
                gid: U64::new(0),
                pid: Nullable::null(),
            },
            action_window: window("w-first", connection_id),
            capabilities: CanonicalSet::new(),
            max_receive: ReceiveLimits::default(),
            build: Some(kr_protocol::local::LocalBuild::this(
                BuildId::new("kr-worker/test").expect("a build"),
            )),
        };
        if writer
            .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
            .await
            .is_err()
        {
            return;
        }
        let Ok(ControlFrame::Request(_)) = reader.read_message::<ControlFrame>().await else {
            return;
        };
        for frame in pushed(connection_id) {
            if writer.write_message(&frame).await.is_err() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        // The connection ends here: the writer and reader are dropped.
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_connection_keeps_the_contract() {
    let tree = kr_ipc::testing::TempHost::create();
    let endpoint = tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let peer = local_peer(endpoint.clone()).await;
    let mut client = LocalClient::connect(
        &endpoint,
        LocalClientKind::Cli,
        BuildId::new("kr-test/0").expect("a build"),
    )
    .await
    .expect("connects");
    the_contract(&mut client).await;
    peer.abort();
}

/// A helper that writes the frames of a bridge to a destination that answers as `pushed` says, and
/// then ends half a second after it has written them.
fn bridge_helper() -> (tempfile::TempDir, Opening) {
    let connection_id = ConnectionId::new(Uuid::from_bytes([7; 16]));
    let acknowledgement = BridgeHelloAck {
        protocol_version: PROTOCOL_VERSION,
        build: Some(kr_protocol::local::LocalBuild::this(
            BuildId::new("kr-worker/test").expect("a build"),
        )),
        base: DestinationBase {
            home: "/home/kala".to_owned(),
            variables: Vec::new(),
        },
        environment_id: environment(),
        os_user: "kala".to_owned(),
        role: LocalRole::Worker,
        connection_id,
        boot_identity: BootIdentity {
            source: BootIdentitySource::LinuxBootId,
            value: Bytes::new(b"boot".to_vec()),
        },
        max_frame_len: U64::new(65_536),
        action_window: window("w-first", connection_id),
    };
    let directory = tempfile::tempdir().expect("a temporary directory");
    let codec = FrameCodec::new(StreamKind::Control);
    let first = directory.path().join("first");
    std::fs::write(
        &first,
        codec
            .encode_message(&BridgeFrame::HelloAck(Box::new(acknowledgement)))
            .expect("encodes"),
    )
    .expect("written");
    let rest = directory.path().join("rest");
    let mut bytes = Vec::new();
    for frame in pushed(connection_id) {
        bytes.extend(
            codec
                .encode_message(&BridgeFrame::Control(Box::new(frame)))
                .expect("encodes"),
        );
    }
    std::fs::write(&rest, bytes).expect("written");
    let opening = Opening {
        command: BridgeCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec![
                "-c".to_owned(),
                // The answer's frames follow the acknowledgement at once, which a peer that
                // answered a moment after the question would do no differently to a reader that
                // is not waiting for them. Then it ends.
                "head -c 4 >/dev/null; cat \"$1\"; cat \"$2\"; sleep 0.5".to_owned(),
                "sh".to_owned(),
                first.to_str().expect("text").to_owned(),
                rest.to_str().expect("text").to_owned(),
            ],
        },
        environment_id: environment(),
        hello: BridgeHello {
            protocol_version: PROTOCOL_VERSION,
            build_id: BuildId::new("kr-test/0").expect("a build"),
            origin_environment_id: EnvironmentId::new(Uuid::from_bytes([8; 16])),
            origin_ingress: ActorIngress::LocalIpc,
            already_bridged: false,
            start: false,
            target: BridgeTarget::Session {
                session_id: kr_protocol::ids::SessionId::new(Uuid::from_bytes([9; 16])),
            },
        },
    };
    (directory, opening)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bridged_connection_keeps_the_same_contract() {
    let (_directory, opening) = bridge_helper();
    let invocation = opening.launch().await.expect("the helper answered");
    let mut link = BridgedLink::new(invocation.into_stream());
    the_contract(&mut link).await;
    let _ = link.close().await;
}

/// A request from a link whose helper has gone is a failure of the link, and says so, rather than
/// waiting for an answer nobody will send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bridged_request_to_a_helper_that_has_gone_fails_instead_of_waiting() {
    let (_directory, mut opening) = bridge_helper();
    // The same helper, without the frames that would answer: it writes its acknowledgement and goes.
    opening.command.arguments[1] = "head -c 4 >/dev/null; cat \"$1\"; exit 0".to_owned();
    let invocation = opening.launch().await.expect("the helper answered");
    let mut link = BridgedLink::new(invocation.into_stream());
    let outcome =
        tokio::time::timeout(Duration::from_secs(30), link.request(Method::HostInfo, &()))
            .await
            .expect("a helper that has gone does not hold its caller");
    assert!(outcome.is_err(), "{outcome:?}");
    let _ = link.close().await;
}
