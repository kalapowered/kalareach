//! What a local client keeps while one of its own calls is outstanding.
//!
//! Section 23 puts a client's calls and its subscription on one control connection, so the host
//! pushes events down the same socket a caller is reading its answer off. What arrives in that
//! moment belongs to the subscription, not to the call, and a client that threw it away would make
//! a subscriber's view depend on when it happened to ask the host a question. These tests drive a
//! real socket with a host that pushes at exactly those moments.

#![cfg(unix)]

use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::framed::split;
use kr_protocol::envelope::{
    ControlEvent, ControlFrame, Notification, Outcome, ParamsValue, Response,
};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::ids::{
    ActionWindowId, BootEpoch, BuildId, ConnectionId, EventSequence, EventType, StreamId,
};
use kr_protocol::local::{LocalClientKind, LocalHelloAck, LocalPeer, LocalRole};
use kr_protocol::method::Method;
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable, TimestampMs, U64};

/// How long a wait tolerates nothing happening at all.
///
/// It bounds a hang and nothing else: every wait below ends on a condition this host has already
/// been made to satisfy, so a slow machine costs a slow pass rather than a failure.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// The events this host pushes carry a payload of this many bytes each.
const EVENT_PAYLOAD_LEN: usize = 400;

/// One scripted host on a real local endpoint.
///
/// It answers the opening frame, then plays the script it was given: for each frame the client
/// sends, the batch the test wants pushed in reply, written in order down one socket.
struct Host {
    _tree: kr_ipc::testing::TempHost,
    endpoint: kr_ipc::paths::Endpoint,
    serving: tokio::task::JoinHandle<()>,
}

impl Host {
    /// Starts a host that pushes `unprompted` as soon as the connection is acknowledged, and then
    /// answers each frame the client sends with the next batch of `replies`.
    fn start(
        queue_bytes: u64,
        unprompted: Vec<ControlFrame>,
        replies: Vec<Vec<ControlFrame>>,
    ) -> Self {
        let tree = kr_ipc::testing::TempHost::create();
        let endpoint = tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint path");
        let listener = Listener::bind(&endpoint).expect("a local endpoint");
        let environment_id = tree.environment_id();
        let serving = tokio::spawn(async move {
            serve(listener, environment_id, queue_bytes, unprompted, replies).await;
        });
        Self {
            _tree: tree,
            endpoint,
            serving,
        }
    }

    /// Connects a client to this host.
    async fn client(&self) -> LocalClient {
        LocalClient::connect(
            &self.endpoint,
            LocalClientKind::Cli,
            BuildId::new("kr-ipc-tests").expect("a literal build identifier"),
        )
        .await
        .expect("the host answered the opening frame")
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// Answers one caller: the opening exchange, then the script.
async fn serve(
    listener: Listener,
    environment_id: kr_protocol::ids::EnvironmentId,
    queue_bytes: u64,
    unprompted: Vec<ControlFrame>,
    replies: Vec<Vec<ControlFrame>>,
) {
    let Ok((connection, peer)) = listener.accept().await else {
        return;
    };
    let (mut reader, mut writer) = split(connection, StreamKind::Control);
    let Ok(ControlFrame::Hello(_)) = reader.read_message::<ControlFrame>().await else {
        return;
    };
    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
    let acknowledgement = LocalHelloAck {
        selected_version: PROTOCOL_VERSION,
        role: LocalRole::Controller,
        connection_id,
        environment_id,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        peer: LocalPeer {
            uid: U64::new(u64::from(peer.uid)),
            gid: U64::new(u64::from(peer.gid)),
            pid: Nullable::null(),
        },
        action_window: window(connection_id, "window-1"),
        capabilities: CanonicalSet::new(),
        // What this connection negotiated. A client holds no more than the host would have queued
        // for it, so a host that states a small queue is what bounds the client as well.
        max_receive: ReceiveLimits {
            max_send_queue_bytes: U64::new(queue_bytes),
            ..ReceiveLimits::default()
        },
    };
    if writer
        .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
        .await
        .is_err()
    {
        return;
    }
    for frame in unprompted {
        if writer.write_message(&frame).await.is_err() {
            return;
        }
    }
    for batch in replies {
        let Ok(asked) = reader.read_message::<ControlFrame>().await else {
            return;
        };
        let asked = request_id(&asked);
        for frame in batch {
            // A response in the script carries whichever request this batch is answering, so the
            // script says what the host pushes and when, and never has to guess an identifier.
            let frame = match frame {
                ControlFrame::Response(response) => ControlFrame::Response(Response {
                    request_id: asked,
                    ..response
                }),
                other => other,
            };
            if writer.write_message(&frame).await.is_err() {
                return;
            }
        }
    }
    // Held open until the test is done with it, so a client that is still reading is never given a
    // closed connection in place of the frame it is waiting for.
    std::future::pending::<()>().await;
}

/// Returns the request identifier a client frame carries.
fn request_id(frame: &ControlFrame) -> kr_protocol::ids::RequestId {
    match frame {
        ControlFrame::Request(request) => request.request_id,
        ControlFrame::Mutation(mutation) => mutation.request_id,
        other => panic!("the client sent {other:?} rather than a call"),
    }
}

/// A window of this connection's, under a name the test can recognise.
fn window(connection_id: ConnectionId, name: &str) -> ActionWindow {
    ActionWindow {
        action_window_id: ActionWindowId::new(name).expect("a literal window identifier"),
        connection_id,
        boot_epoch: BootEpoch::new(1),
        issued_at_ms: TimestampMs::new(0),
        valid_for_ms: DurationMs::new(60_000),
    }
}

/// One event on this connection's subscription, numbered so a test can say which one it is.
fn event(sequence: u64) -> ControlFrame {
    ControlFrame::Notification(Notification {
        stream_id: StreamId::new("session.output").expect("a literal stream name"),
        sequence: EventSequence::new(sequence),
        event_type: EventType::new("session.output").expect("a literal event type"),
        payload: ParamsValue::from_typed(&"x".repeat(EVENT_PAYLOAD_LEN)).expect("a payload"),
    })
}

/// The sequence number of an event, or a description of whatever else arrived.
fn sequence_of(frame: &ControlFrame) -> std::result::Result<u64, String> {
    match frame {
        ControlFrame::Notification(notification) => Ok(notification.sequence.get()),
        other => Err(format!("{other:?}")),
    }
}

/// An answer to whatever request the batch is replying to.
fn answer() -> ControlFrame {
    ControlFrame::Response(Response {
        request_id: kr_protocol::ids::RequestId::new(0),
        outcome: Outcome::Ok(ParamsValue::empty()),
    })
}

#[tokio::test]
async fn a_call_keeps_the_events_that_arrive_while_it_is_outstanding() {
    // The moment section 23 leaves open: the host publishes on the same connection a caller is
    // reading its answer off. Both events here are pushed after the request arrives and before the
    // response, so a client that only looked for its answer would have read them and thrown them
    // away, and its subscriber would never learn they happened.
    let host = Host::start(
        u64::try_from(kr_protocol::limits::MAX_SEND_QUEUE_BYTES).expect("the bound fits"),
        Vec::new(),
        vec![vec![event(1), event(2), answer()]],
    );
    let mut client = host.client().await;

    client
        .request(Method::SessionList, &ParamsValue::empty())
        .await
        .expect("a round trip")
        .expect("a result");

    assert_eq!(
        client.held(),
        2,
        "both events the host pushed during the call are kept"
    );
    assert_eq!(
        client.take_held().as_ref().map(sequence_of),
        Some(Ok(1)),
        "the first event the host pushed comes back first"
    );
    assert_eq!(
        client.take_held().as_ref().map(sequence_of),
        Some(Ok(2)),
        "and the second after it"
    );
    assert!(
        client.take_held().is_none(),
        "and nothing the host did not send"
    );
}

#[tokio::test]
async fn what_a_call_kept_is_read_before_what_followed_the_answer() {
    // The order is the host's, not the client's bookkeeping: the event before the response and the
    // event after it reach a reader in that order. A client that kept the first one behind
    // whatever it read next would hand its subscriber a stream that jumps backwards.
    let host = Host::start(
        u64::try_from(kr_protocol::limits::MAX_SEND_QUEUE_BYTES).expect("the bound fits"),
        Vec::new(),
        vec![vec![event(1), answer(), event(2)]],
    );
    let mut client = host.client().await;

    client
        .request(Method::SessionList, &ParamsValue::empty())
        .await
        .expect("a round trip")
        .expect("a result");

    let first = tokio::time::timeout(LIVENESS_DEADLINE, client.recv())
        .await
        .expect("the host had already sent it")
        .expect("a frame");
    assert_eq!(
        sequence_of(&first),
        Ok(1),
        "the event that arrived during the call is read before the one that followed the answer"
    );
    let second = tokio::time::timeout(LIVENESS_DEADLINE, client.recv())
        .await
        .expect("the host had already sent it")
        .expect("a frame");
    assert_eq!(sequence_of(&second), Ok(2), "and then the one after it");
}

#[tokio::test]
async fn building_a_mutation_keeps_what_the_host_has_already_pushed() {
    // The other half of the seam. A mutation takes this connection's current window before it is
    // built, which means reading whatever the host has already put in the socket; an event found
    // there is this connection's subscription and is kept, rather than being spent on the reading.
    let host = Host::start(
        u64::try_from(kr_protocol::limits::MAX_SEND_QUEUE_BYTES).expect("the bound fits"),
        vec![event(7)],
        Vec::new(),
    );
    let mut client = host.client().await;

    // Composing reads what is ready and never waits, so an attempt made before the reactor has
    // reported the socket readable finds nothing and the next one finds the event. This polls that
    // readiness; it never waits for the host, which pushed the event before the client connected.
    tokio::time::timeout(LIVENESS_DEADLINE, async {
        loop {
            client
                .compose(
                    Method::SessionClose,
                    kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
                    kr_protocol::envelope::ActionTarget::environment(
                        kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()),
                    ),
                    &ParamsValue::empty(),
                )
                .await
                .expect("a composed mutation");
            if client.held() > 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the event the host pushed before the first call is kept rather than spent");

    assert_eq!(
        client.take_held().as_ref().map(sequence_of),
        Some(Ok(7)),
        "and it is the event the host pushed"
    );
}

#[tokio::test]
async fn the_connections_own_window_is_applied_rather_than_handed_to_the_caller() {
    // The boundary of what a client keeps. A renewed action window is this connection's resource
    // and no part of anybody's subscription, so it is applied where it arrives and never queued
    // for a caller that did not ask for one.
    let host = Host::start(
        u64::try_from(kr_protocol::limits::MAX_SEND_QUEUE_BYTES).expect("the bound fits"),
        Vec::new(),
        vec![vec![renewal("window-2"), answer()]],
    );
    let mut client = host.client().await;

    client
        .request(Method::SessionList, &ParamsValue::empty())
        .await
        .expect("a round trip")
        .expect("a result");

    assert_eq!(
        client.action_window().action_window_id.as_str(),
        "window-2",
        "the window the host pushed during the call is the one this connection now holds"
    );
    assert_eq!(
        client.held(),
        0,
        "and nothing about it is waiting for a caller"
    );
}

/// A renewal of this connection's window, under a name the test can recognise.
fn renewal(name: &str) -> ControlFrame {
    ControlFrame::Event(ControlEvent::ActionWindowRenewed(window(
        ConnectionId::new(kr_ipc::new_uuid()),
        name,
    )))
}

#[tokio::test]
async fn a_client_that_cannot_hold_what_it_is_told_is_told_so() {
    // Section 9 has a peer that cannot keep up told rather than waited for, and a client holding
    // events for a caller is no different: what it keeps is bounded by the send queue this
    // connection negotiated, and reaching that bound ends the call with the figure named. Silently
    // dropping the oldest would be the defect these tests exist for, one queue further along.
    let host = Host::start(
        512,
        Vec::new(),
        vec![vec![event(1), event(2), event(3), answer()]],
    );
    let mut client = host.client().await;

    let refused = client
        .request(Method::SessionList, &ParamsValue::empty())
        .await
        .expect_err("a connection that cannot hold what it is told says so");
    let said = refused.to_string();
    assert!(
        said.contains("512-byte bound"),
        "the refusal names the bound this connection negotiated: {said}"
    );
}
