//! What an attached terminal may rely on from the connection it is attached over, whether that is
//! a socket on this host or a bridge to another environment.
//!
//! The attach loop is written once, against [`Link`], and both connections implement it. The same
//! contract is run against each, with the same scripted peer behind it: a connection that pushes
//! a keepalive, a renewed window and two notifications ahead of the answer to a request, then a
//! third notification, and then ends. A connection that lost any of that, or put it in another
//! order, would show a terminal a different session from the one the destination is serving.
//!
//! The peer is also where a mutation is read: what the connection wrote is what the destination
//! would act on, so the window a mutation quotes is checked from what arrived there and not from
//! the accessor that says what it would quote. And a frame that arrives in two parts, with the
//! receive given up on in between, is delivered whole once the rest comes.

#![cfg(unix)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kr_cli::bridge::link::{BridgedLink, Link};
use kr_controller::bridge::invoke::Opening;
use kr_controller::bridge::launch::BridgeCommand;
use kr_ipc::client::LocalClient;
use kr_protocol::actor::ActorIngress;
use kr_protocol::envelope::{
    ActionTarget, ControlEvent, ControlFrame, Notification, Outcome, ParamsValue, Response,
};
use kr_protocol::frame::{FrameCodec, StreamKind};
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::identity::{
    BootIdentity, BootIdentitySource, BridgeFrame, BridgeHello, BridgeHelloAck, BridgeTarget,
    DestinationBase,
};
use kr_protocol::ids::{
    ActionId, ActionWindowId, BootEpoch, BuildId, ConnectionId, EnvironmentId, EventSequence,
    EventType, RequestId, StreamId,
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

/// The answer to the one mutation the contract sends, which is the link's second request.
fn mutation_answer() -> ControlFrame {
    ControlFrame::Response(Response {
        request_id: RequestId::new(2),
        outcome: Outcome::Ok(ParamsValue::empty()),
    })
}

/// How long the peer is given to show what it was sent.
const SEEN_DEADLINE: Duration = Duration::from_secs(30);

/// The contract. Everything here is something the attach loop depends on.
///
/// `quoted` says what window the peer read in the mutation it was sent, once it has read one.
async fn the_contract(link: &mut impl Link, quoted: &dyn Fn() -> Option<String>) {
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

    // The mutation that follows says so on the wire: the peer reads the renewed window in it, and
    // not the one the connection began with.
    let answer = tokio::time::timeout(
        Duration::from_secs(30),
        link.mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment()),
            &(),
        ),
    )
    .await
    .expect("the mutation is answered")
    .expect("the connection carried the mutation");
    assert_eq!(answer, Ok(ParamsValue::empty()));
    let started = Instant::now();
    let read = loop {
        if let Some(window) = quoted() {
            break window;
        }
        assert!(
            started.elapsed() < SEEN_DEADLINE,
            "the peer was never sent the mutation"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(read, "w-second", "the mutation quotes the renewed window");

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

/// Reads one control frame from a raw connection, or nothing when it ends.
async fn read_frame(connection: &mut kr_ipc::endpoint::Connection) -> Option<ControlFrame> {
    use tokio::io::AsyncReadExt;

    let mut prefix = [0_u8; 4];
    connection.read_exact(&mut prefix).await.ok()?;
    let mut payload = vec![0_u8; u32::from_be_bytes(prefix) as usize];
    connection.read_exact(&mut payload).await.ok()?;
    kr_cbor::from_canonical_slice(&payload, &StreamKind::Control.cbor_limits()).ok()
}

/// The bytes one control frame is written as.
fn encoded(frame: &ControlFrame) -> Vec<u8> {
    FrameCodec::new(StreamKind::Control)
        .encode_message(frame)
        .expect("the frame encodes")
}

/// What a worker acknowledges a hello with.
fn acknowledgement_of_a_worker(connection_id: ConnectionId) -> ControlFrame {
    ControlFrame::HelloAck(Box::new(LocalHelloAck {
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
    }))
}

/// The window the first mutation a local peer read quoted.
type Quoted = Arc<Mutex<Option<String>>>;

/// A control endpoint that says hello, waits to be asked, pushes what a peer pushes, reads the
/// mutation that follows and answers it.
async fn local_peer(
    endpoint: kr_ipc::paths::Endpoint,
    quoted: Quoted,
) -> tokio::task::JoinHandle<()> {
    use tokio::io::AsyncWriteExt;

    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
    tokio::spawn(async move {
        let Ok((mut connection, _)) = listener.accept().await else {
            return;
        };
        let Some(ControlFrame::Hello(_)) = read_frame(&mut connection).await else {
            return;
        };
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        if connection
            .write_all(&encoded(&acknowledgement_of_a_worker(connection_id)))
            .await
            .is_err()
        {
            return;
        }
        let Some(ControlFrame::Request(_)) = read_frame(&mut connection).await else {
            return;
        };
        for frame in pushed(connection_id) {
            if connection.write_all(&encoded(&frame)).await.is_err() {
                return;
            }
        }
        let Some(ControlFrame::Mutation(mutation)) = read_frame(&mut connection).await else {
            return;
        };
        *quoted.lock().expect("the slot") = Some(mutation.action_window_id.as_str().to_owned());
        if connection
            .write_all(&encoded(&mutation_answer()))
            .await
            .is_err()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        // The connection ends here: it is dropped.
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_connection_keeps_the_contract() {
    let tree = kr_ipc::testing::TempHost::create();
    let endpoint = tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let quoted = Quoted::default();
    let peer = local_peer(endpoint.clone(), Arc::clone(&quoted)).await;
    let mut client = LocalClient::connect(
        &endpoint,
        LocalClientKind::Cli,
        BuildId::new("kr-test/0").expect("a build"),
    )
    .await
    .expect("connects");
    the_contract(&mut client, &|| quoted.lock().expect("the slot").clone()).await;
    peer.abort();
}

/// The acknowledgement of a destination's worker, as a bridge's helper writes it.
fn bridge_acknowledgement(connection_id: ConnectionId) -> BridgeHelloAck {
    BridgeHelloAck {
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
    }
}

/// The opening a bridge to a session sends, and the command that stands in for the destination.
fn bridge_opening(script: String, files: &[&std::path::Path]) -> Opening {
    let mut arguments = vec!["-c".to_owned(), script, "sh".to_owned()];
    arguments.extend(
        files
            .iter()
            .map(|file| file.to_str().expect("text").to_owned()),
    );
    Opening {
        command: BridgeCommand {
            program: "/bin/sh".to_owned(),
            arguments,
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
    }
}

/// Writes frames, one after another, into one file.
fn written_frames(path: &std::path::Path, frames: &[BridgeFrame]) {
    let codec = FrameCodec::new(StreamKind::Control);
    let mut bytes = Vec::new();
    for frame in frames {
        bytes.extend(codec.encode_message(frame).expect("encodes"));
    }
    std::fs::write(path, bytes).expect("written");
}

/// The window the first mutation in what a helper was sent quoted, once it has been sent one.
///
/// What the helper reads on its standard input is written to a file, whole, and this reads the
/// frames in it: the opening, then whatever the connection wrote.
fn quoted_in(capture: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(capture).ok()?;
    let mut at = 0;
    while at + 4 <= bytes.len() {
        let length = u32::from_be_bytes(bytes[at..at + 4].try_into().ok()?) as usize;
        let payload = bytes.get(at + 4..at + 4 + length)?;
        at += 4 + length;
        if let Ok(BridgeFrame::Control(frame)) =
            kr_cbor::from_canonical_slice(payload, &StreamKind::Control.cbor_limits())
            && let ControlFrame::Mutation(mutation) = *frame
        {
            return Some(mutation.action_window_id.as_str().to_owned());
        }
    }
    None
}

/// A helper that writes the frames of a bridge to a destination that answers as `pushed` says, and
/// then ends two seconds after it has written them. Everything it is sent is kept in `captured`.
fn bridge_helper() -> (tempfile::TempDir, Opening, std::path::PathBuf) {
    let connection_id = ConnectionId::new(Uuid::from_bytes([7; 16]));
    let directory = tempfile::tempdir().expect("a temporary directory");
    let first = directory.path().join("first");
    written_frames(
        &first,
        &[BridgeFrame::HelloAck(Box::new(bridge_acknowledgement(
            connection_id,
        )))],
    );
    let rest = directory.path().join("rest");
    let mut frames: Vec<BridgeFrame> = pushed(connection_id)
        .into_iter()
        .map(|frame| BridgeFrame::Control(Box::new(frame)))
        .collect();
    // The answer to the mutation, which a shell cannot wait to read the way a worker would.
    frames.push(BridgeFrame::Control(Box::new(mutation_answer())));
    written_frames(&rest, &frames);
    let captured = directory.path().join("captured");
    let opening = bridge_opening(
        // What the helper is sent is kept for the test to read. The answer's frames follow the
        // acknowledgement at once, which a peer that answered a moment after the question would
        // do no differently to a reader that is not waiting for them. Then it waits and ends.
        // A background command reads nothing from the shell's input, so it is handed a copy of it.
        "exec 9<&0; cat <&9 >\"$3\" & cat \"$1\"; cat \"$2\"; sleep 2".to_owned(),
        &[&first, &rest, &captured],
    );
    (directory, opening, captured)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bridged_connection_keeps_the_same_contract() {
    let (_directory, opening, captured) = bridge_helper();
    let invocation = opening.launch().await.expect("the helper answered");
    let mut link = BridgedLink::new(invocation.into_stream());
    the_contract(&mut link, &|| quoted_in(&captured)).await;
    let _ = link.close().await;
}

/// A request from a link whose helper has gone is a failure of the link, and says so, rather than
/// waiting for an answer nobody will send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bridged_request_to_a_helper_that_has_gone_fails_instead_of_waiting() {
    let (_directory, mut opening, _captured) = bridge_helper();
    // The same helper, without the frames that would answer: it writes its acknowledgement and goes.
    opening.command.arguments[1] = "cat \"$1\"; exit 0".to_owned();
    let invocation = opening.launch().await.expect("the helper answered");
    let mut link = BridgedLink::new(invocation.into_stream());
    let outcome =
        tokio::time::timeout(Duration::from_secs(30), link.request(Method::HostInfo, &()))
            .await
            .expect("a helper that has gone does not hold its caller");
    assert!(outcome.is_err(), "{outcome:?}");
    let _ = link.close().await;
}

/// Gives up on a receive, over and over, for `within`, and says what was received in that time and
/// how many receives were given up on.
async fn receives_given_up_on(link: &mut impl Link, within: Duration) -> (Vec<ControlFrame>, u32) {
    let mut received = Vec::new();
    let mut given_up = 0;
    let started = Instant::now();
    while started.elapsed() < within {
        tokio::select! {
            biased;
            () = tokio::time::sleep(Duration::from_millis(1)) => given_up += 1,
            frame = link.recv() => received.push(frame.expect("a frame, or none yet")),
        }
    }
    (received, given_up)
}

/// How long receives are given up on while half a frame is held. The first half has been written
/// by the time the peer says so, and reading it takes a moment, so this is far longer than that.
const HALF_A_FRAME: Duration = Duration::from_millis(300);

/// The partial-frame contract: a peer that has written the first half of a frame and not the rest,
/// a receive that is given up on many times while it waits, and then the rest. The frame is
/// delivered whole, once, and nothing was delivered before it.
async fn a_frame_in_two_parts_is_delivered_whole(
    link: &mut impl Link,
    release_the_rest: impl Fn(),
) {
    let (during, given_up) = receives_given_up_on(link, HALF_A_FRAME).await;
    assert!(during.is_empty(), "half a frame is not a frame: {during:?}");
    assert!(
        given_up >= 20,
        "the receive was given up on {given_up} times while half the frame was held"
    );
    release_the_rest();
    let frame = tokio::time::timeout(Duration::from_secs(30), link.recv())
        .await
        .expect("the rest of the frame arrives")
        .expect("a frame");
    match frame {
        ControlFrame::Notification(notification) => assert_eq!(notification.sequence.get(), 1),
        other => panic!("expected the notification that was split, got {other:?}"),
    }
}

/// A frame's bytes in two parts, cut inside the payload, after the length prefix has said how much
/// is coming.
fn split_bytes(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let at = bytes.len() / 2 + 2;
    (bytes[..at].to_vec(), bytes[at..].to_vec())
}

/// A control frame in two parts.
fn split_in_two(frame: &ControlFrame) -> (Vec<u8>, Vec<u8>) {
    split_bytes(&encoded(frame))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_frame_that_arrives_in_two_parts_is_not_lost_to_a_receive_given_up_on() {
    use tokio::io::AsyncWriteExt;

    let tree = kr_ipc::testing::TempHost::create();
    let endpoint = tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let release = Arc::new(tokio::sync::Notify::new());
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
    let waiting = Arc::clone(&release);
    let peer = tokio::spawn(async move {
        let Ok((mut connection, _)) = listener.accept().await else {
            return;
        };
        let Some(ControlFrame::Hello(_)) = read_frame(&mut connection).await else {
            return;
        };
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let _ = connection
            .write_all(&encoded(&acknowledgement_of_a_worker(connection_id)))
            .await;
        let (first, rest) = split_in_two(&notification(1));
        let _ = connection.write_all(&first).await;
        let _ = connection.flush().await;
        waiting.notified().await;
        let _ = connection.write_all(&rest).await;
        let _ = connection.flush().await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let mut client = LocalClient::connect(
        &endpoint,
        LocalClientKind::Cli,
        BuildId::new("kr-test/0").expect("a build"),
    )
    .await
    .expect("connects");
    a_frame_in_two_parts_is_delivered_whole(&mut client, || release.notify_one()).await;
    peer.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bridged_frame_that_arrives_in_two_parts_is_not_lost_to_a_receive_given_up_on() {
    let connection_id = ConnectionId::new(Uuid::from_bytes([7; 16]));
    let directory = tempfile::tempdir().expect("a temporary directory");
    let first = directory.path().join("first");
    written_frames(
        &first,
        &[BridgeFrame::HelloAck(Box::new(bridge_acknowledgement(
            connection_id,
        )))],
    );
    // The frame is wrapped as a bridge writes it, so the cut is taken of that.
    let wrapped = FrameCodec::new(StreamKind::Control)
        .encode_message(&BridgeFrame::Control(Box::new(notification(1))))
        .expect("encodes");
    let (head, tail) = split_bytes(&wrapped);
    let (half, rest) = (directory.path().join("half"), directory.path().join("rest"));
    std::fs::write(&half, head).expect("written");
    std::fs::write(&rest, tail).expect("written");
    let released = directory.path().join("released");
    let opening = bridge_opening(
        // The first half is written and flushed, and the rest waits for the test to say so.
        "cat \"$1\"; cat \"$2\"; while [ ! -e \"$4\" ]; do sleep 0.05; done; cat \"$3\"; sleep 5"
            .to_owned(),
        &[&first, &half, &rest, &released],
    );
    let invocation = opening.launch().await.expect("the helper answered");
    let mut link = BridgedLink::new(invocation.into_stream());
    a_frame_in_two_parts_is_delivered_whole(&mut link, || {
        std::fs::write(&released, b"go").expect("releases the rest");
    })
    .await;
    let _ = link.close().await;
}

/// The control for the two above: a receive that reads its frame inside itself loses it when it is
/// given up on part of the way through, which is what the peers above arrange. Without this, a link
/// that passed them might never have been cut in the middle of anything.
#[tokio::test]
async fn a_receive_that_reads_inside_itself_is_cut_by_giving_up_on_it_inside_a_frame() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn naive_receive(reader: &mut (impl AsyncReadExt + Unpin)) -> Option<ControlFrame> {
        let mut prefix = [0_u8; 4];
        reader.read_exact(&mut prefix).await.ok()?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length > StreamKind::Control.max_payload_len() {
            return None;
        }
        let mut payload = vec![0_u8; length];
        reader.read_exact(&mut payload).await.ok()?;
        kr_cbor::from_canonical_slice(&payload, &StreamKind::Control.cbor_limits()).ok()
    }

    let (mut writer, mut reader) = tokio::io::duplex(65_536);
    let (first, rest) = split_in_two(&notification(1));
    writer.write_all(&first).await.expect("writes");
    let given_up = tokio::time::timeout(Duration::from_millis(100), naive_receive(&mut reader))
        .await
        .is_err();
    assert!(given_up, "half a frame is not a frame");
    writer.write_all(&rest).await.expect("writes");
    // What is left to read is the second half of a frame, which is not the start of one.
    let again = tokio::time::timeout(Duration::from_millis(500), naive_receive(&mut reader))
        .await
        .ok()
        .flatten();
    assert_ne!(
        again,
        Some(notification(1)),
        "a receive given up on inside a frame lost what it had read of it"
    );
}
