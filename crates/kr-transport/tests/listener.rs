//! The one call that puts a host on the network, and the rules it enforces.
//!
//! These tests go through `listener::register` rather than calling the handshake directly, because
//! three of the guarantees only exist there: early data is refused on an authorised connection, a
//! connection's data streams and action windows end with its control stream, and the host renews
//! the action window on the live connection without being asked.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use iroh::endpoint::presets;
use kr_crypto::connect::PairedPeer;
use kr_protocol::envelope::{ControlEvent, ControlFrame};
use kr_protocol::error::ErrorCode;
use kr_protocol::frame::{StreamHeader, StreamKind, StreamResource};
use kr_protocol::hello::{ALPN, ClientOffer, HelloReply, PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::ids::{
    ActorId, AttachmentId, AuthorityRevision, BuildId, ConnectionId, ControllerGeneration,
    DeviceId, EnvironmentId, SessionId,
};
use kr_protocol::scalars::{CanonicalSet, EndpointKey, Nullable, Uuid};
use kr_transport::codec::{FrameReader, FrameWriter};
use kr_transport::config::EndpointConfig;
use kr_transport::handshake::{self, PairedDirectory};
use kr_transport::listener::{
    AuthorisedSession, BoxFuture, HostHandler, ListenerConfig, NetworkListener, register,
};
use kr_transport::preauth::PairingSurface;
use kr_transport::random::fresh_nonce;
use kr_transport::scheduler::SendLimits;
use kr_transport::streams::StreamRegistry;
use support::{Side, epochs, paired_pair};
use tokio::sync::Mutex;

/// A host that records what the listener handed it and then waits for the connection to end.
#[derive(Debug)]
struct TestHandler {
    client: PairedPeer,
    /// How many connections reached the handler.
    served: AtomicUsize,
    /// How many connections lost their control stream.
    lost: AtomicUsize,
    /// The connection identity of the last session, so a test can check the cleanup.
    last: Mutex<Option<ConnectionId>>,
    /// Data streams the handler accepted and is holding open.
    streams: Mutex<Vec<kr_transport::streams::StreamHandle>>,
    /// How many data streams the handler has accepted.
    accepted: AtomicUsize,
}

impl TestHandler {
    fn new(client: PairedPeer) -> Self {
        Self {
            client,
            served: AtomicUsize::new(0),
            lost: AtomicUsize::new(0),
            last: Mutex::new(None),
            streams: Mutex::new(Vec::new()),
            accepted: AtomicUsize::new(0),
        }
    }
}

impl PairedDirectory for TestHandler {
    fn paired_peer(&self, endpoint_id: &EndpointKey) -> Option<PairedPeer> {
        (endpoint_id == &self.client.endpoint_id).then_some(self.client)
    }
}

impl HostHandler for TestHandler {
    fn principal_for(&self, device_id: &DeviceId) -> ActorId {
        kr_transport::listener::device_principal(device_id)
    }

    fn authority_revision(&self) -> AuthorityRevision {
        AuthorityRevision::default()
    }

    fn pairing_surface(&self) -> Option<Arc<dyn PairingSurface>> {
        None
    }

    fn serve(self: Arc<Self>, mut session: AuthorisedSession) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            self.served.fetch_add(1, Ordering::AcqRel);
            *self.last.lock().await = Some(session.connection_id);
            // Accept whatever data streams the client opens, and read the control stream until it
            // ends. A real host would dispatch; here the point is only to hold the connection.
            let streams = Arc::clone(&session.streams);
            let connection = session.connection.clone();
            let handler = Arc::clone(&self);
            let accepting = tokio::spawn(async move {
                while let Ok(stream) = streams.accept(&connection).await {
                    handler.streams.lock().await.push(stream.handle());
                    handler.accepted.fetch_add(1, Ordering::AcqRel);
                    // The stream is kept alive by the registry's handle; dropping it here would
                    // deregister it, and the test wants to see it revoked.
                    std::mem::forget(stream);
                }
            });
            while session.control.recv().await.is_some() {}
            accepting.abort();
        })
    }

    fn control_stream_lost(&self, _connection_id: ConnectionId) {
        self.lost.fetch_add(1, Ordering::AcqRel);
    }
}

async fn start(host: &Side, handler: Arc<TestHandler>) -> NetworkListener {
    let config = ListenerConfig::new(
        EndpointConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
            ..EndpointConfig::default()
        },
        epochs(),
        ControllerGeneration::new(1),
    );
    register(
        config,
        Arc::clone(&host.identity),
        &host.keys.transport,
        handler,
    )
    .await
    .expect("a listener")
}

fn listener_addr(listener: &NetworkListener) -> iroh::EndpointAddr {
    let mut addr = iroh::EndpointAddr::new(listener.endpoint().id());
    for socket in listener.endpoint().bound_sockets() {
        addr = addr.with_ip_addr(socket);
    }
    addr
}

/// KR-REQ-23.18: ending the control connection revokes every data stream it authorised and runs
/// the host's control-loss hook, which is where the host stops renewing that connection's leases.
#[tokio::test]
async fn a_registered_host_serves_an_authorised_connection_and_ends_it_cleanly() {
    let (host, client) = paired_pair().await;
    let handler = Arc::new(TestHandler::new(client.record));
    let listener = start(&host, Arc::clone(&handler)).await;
    let addr = listener_addr(&listener);

    let connection = client
        .endpoint
        .connect(addr, ALPN)
        .await
        .expect("a connection");
    let authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");

    // The host issued this connection's first window, and the window is valid for it.
    assert!(
        listener
            .windows()
            .validate(
                &authorised.action_window.action_window_id,
                authorised.connection_id,
                epochs().boot_epoch,
            )
            .is_ok()
    );

    // A data stream on the authorised connection reaches the handler.
    let registry = Arc::new(StreamRegistry::new(
        authorised.connection_id,
        Arc::new(kr_transport::scheduler::StreamBudget::new(
            SendLimits::default(),
        )),
        None,
    ));
    let _stream = registry
        .open(&connection, terminal_header(authorised.connection_id))
        .await
        .expect("a data stream");
    wait_until(|| handler.accepted.load(Ordering::Acquire) == 1).await;

    // Ending the connection ends everything it authorised: the hook runs, and the window it could
    // have first-admitted through is retired.
    drop(authorised);
    connection.close(0u32.into(), b"done");
    wait_until(|| handler.lost.load(Ordering::Acquire) == 1).await;
    let handles = handler.streams.lock().await;
    assert!(
        handles
            .iter()
            .all(kr_transport::streams::StreamHandle::is_revoked),
        "every data stream was revoked"
    );
    drop(handles);

    listener.shutdown().await;
}

/// KR-REQ-23.18: losing the control stream alone is enough. With the connection itself left open,
/// the end of its control stream revokes every data stream it authorised and runs the host's
/// control-loss hook, which is where the host stops renewing that connection's leases.
#[tokio::test]
async fn losing_only_the_control_stream_revokes_its_data_streams() {
    let (host, client) = paired_pair().await;
    let handler = Arc::new(TestHandler::new(client.record));
    let listener = start(&host, Arc::clone(&handler)).await;
    let addr = listener_addr(&listener);

    let connection = client
        .endpoint
        .connect(addr, ALPN)
        .await
        .expect("a connection");
    let mut authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");
    let registry = Arc::new(StreamRegistry::new(
        authorised.connection_id,
        Arc::new(kr_transport::scheduler::StreamBudget::new(
            SendLimits::default(),
        )),
        None,
    ));
    let _stream = registry
        .open(&connection, terminal_header(authorised.connection_id))
        .await
        .expect("a data stream");
    wait_until(|| handler.accepted.load(Ordering::Acquire) == 1).await;
    assert_eq!(handler.lost.load(Ordering::Acquire), 0);

    // Only the control stream ends; the connection is not closed from this side.
    authorised.control_writer.reset();
    wait_until(|| handler.lost.load(Ordering::Acquire) == 1).await;
    let handles = handler.streams.lock().await;
    assert!(
        handles
            .iter()
            .all(kr_transport::streams::StreamHandle::is_revoked),
        "every data stream the control stream authorised was revoked"
    );
    drop(handles);

    drop(authorised);
    listener.shutdown().await;
}

/// KR-ACC-026: no data stream survives the failure of its control stream. With the connection
/// itself left open, the end of the control stream takes every data stream with it: the host's
/// side of each is revoked, the peer's own stream carries no more data, the host ends the
/// connection, and the connection takes no new data stream.
#[tokio::test]
async fn no_data_stream_survives_the_failure_of_its_control_stream() {
    let (host, client) = paired_pair().await;
    let handler = Arc::new(TestHandler::new(client.record));
    let listener = start(&host, Arc::clone(&handler)).await;
    let addr = listener_addr(&listener);

    let connection = client
        .endpoint
        .connect(addr, ALPN)
        .await
        .expect("a connection");
    let mut authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");
    let registry = Arc::new(StreamRegistry::new(
        authorised.connection_id,
        Arc::new(kr_transport::scheduler::StreamBudget::new(
            SendLimits::default(),
        )),
        None,
    ));
    let mut stream = registry
        .open(&connection, terminal_header(authorised.connection_id))
        .await
        .expect("a data stream");
    wait_until(|| handler.accepted.load(Ordering::Acquire) == 1).await;

    // Only the control stream fails.
    authorised.control_writer.reset();
    wait_until(|| handler.lost.load(Ordering::Acquire) == 1).await;

    // The host's side of the data stream is revoked.
    {
        let handles = handler.streams.lock().await;
        assert_eq!(handles.len(), 1);
        assert!(
            handles
                .iter()
                .all(kr_transport::streams::StreamHandle::is_revoked),
            "the data stream the control stream authorised was revoked"
        );
    }
    // The peer's own stream carries nothing more, and is not left waiting.
    match tokio::time::timeout(Duration::from_secs(10), stream.read_payload()).await {
        Ok(Ok(None)) | Ok(Err(_)) => {}
        Ok(Ok(Some(_))) => {
            panic!("a data stream delivered a frame after its control stream failed")
        }
        Err(_) => panic!("a data stream left the peer waiting after its control stream failed"),
    }
    // The host ended the connection, so there is nothing to open a new data stream on.
    tokio::time::timeout(Duration::from_secs(10), connection.closed())
        .await
        .expect("the host ended the connection when its control stream failed");
    assert!(
        registry
            .open(&connection, terminal_header(authorised.connection_id))
            .await
            .is_err(),
        "a new data stream was opened after the control stream failed"
    );
    assert_eq!(
        handler.accepted.load(Ordering::Acquire),
        1,
        "and the host accepted no other"
    );

    drop(authorised);
    listener.shutdown().await;
}

/// KR-REQ-23.18: nothing sent as 0-RTT early data reaches an authorised connection.
#[tokio::test]
async fn early_data_never_reaches_an_authorised_connection() {
    // KR-ACC-026: version 1 accepts no application mutation in QUIC 0-RTT. The listener accepts the
    // first stream while the handshake is still running, so it knows whether that stream carried
    // early data, and refuses to authorise one that did.
    let (host, client) = paired_pair().await;
    let handler = Arc::new(TestHandler::new(client.record));
    let listener = start(&host, Arc::clone(&handler)).await;
    let addr = listener_addr(&listener);

    // A peer that keeps session tickets, unlike this product's own client, which keeps none.
    let resuming = iroh::Endpoint::builder(presets::Minimal)
        .secret_key(iroh::SecretKey::from_bytes(
            client.keys.transport.export_endpoint_seed().expose(),
        ))
        .relay_mode(iroh::RelayMode::Disabled)
        // The loopback and nothing else: naming an address replaces iroh's default socket for its
        // own family only, so the defaults go first, as the product's endpoints do.
        .clear_ip_transports()
        .bind_addr(
            "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .expect("an address"),
        )
        .expect("a bind address")
        .bind()
        .await
        .expect("an endpoint");

    // One complete connection first, so the peer holds a ticket.
    let warm = resuming
        .connect(addr.clone(), ALPN)
        .await
        .expect("a connection");
    let authorised = handshake::connect(&warm, &client.identity, &host.record)
        .await
        .expect("an authorised connection");
    drop(authorised);
    warm.close(0u32.into(), b"done");
    wait_until(|| handler.served.load(Ordering::Acquire) == 1).await;

    // Now offer 0-RTT and write the offer as early data.
    let connecting = resuming
        .connect_with_opts(addr, ALPN, iroh::endpoint::ConnectOptions::new())
        .await
        .expect("a connection attempt");
    let Ok(zero_rtt) = connecting.into_0rtt() else {
        panic!("the peer holds a session ticket and can offer 0-RTT");
    };
    let (send, recv) = zero_rtt.open_bi().await.expect("a stream");
    let mut writer = FrameWriter::new(send, StreamKind::Control);
    let mut reader = FrameReader::new(recv, StreamKind::Control);
    writer
        .write_message(&offer(&client))
        .await
        .expect("the offer was sent as early data");
    let _ = zero_rtt.handshake_completed().await;

    let reply: HelloReply = reader
        .read_message()
        .await
        .expect("a reply")
        .expect("the stream did not end");
    let HelloReply::Refused(error) = reply else {
        panic!("a handshake that arrived as early data is refused");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(
        handler.served.load(Ordering::Acquire),
        1,
        "the early-data connection never reached the handler"
    );

    listener.shutdown().await;
}

/// KR-REQ-23.20: the host issues and renews the connection's action window itself.
#[tokio::test]
async fn the_host_renews_the_action_window_without_being_asked() {
    let (host, client) = paired_pair().await;
    let handler = Arc::new(TestHandler::new(client.record));
    let config = ListenerConfig {
        // A short validity so the renewal arrives inside the test rather than in five minutes.
        action_window_validity: Duration::from_millis(400),
        keepalive: Duration::from_millis(120),
        ..ListenerConfig::new(
            EndpointConfig {
                bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
                ..EndpointConfig::default()
            },
            epochs(),
            ControllerGeneration::new(1),
        )
    };
    let listener = register(
        config,
        Arc::clone(&host.identity),
        &host.keys.transport,
        Arc::clone(&handler),
    )
    .await
    .expect("a listener");
    let addr = listener_addr(&listener);

    let connection = client
        .endpoint
        .connect(addr, ALPN)
        .await
        .expect("a connection");
    let mut authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");
    let first = authorised.action_window.action_window_id.clone();

    // Read control frames until a renewal arrives, and check a keepalive came too.
    let mut renewed = None;
    let mut keepalives = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while renewed.is_none() && tokio::time::Instant::now() < deadline {
        let frame = tokio::time::timeout(
            Duration::from_secs(5),
            authorised.control_reader.read_message::<ControlFrame>(),
        )
        .await
        .expect("a frame arrived")
        .expect("a frame")
        .expect("the stream did not end");
        match frame {
            ControlFrame::Event(ControlEvent::ActionWindowRenewed(window)) => {
                renewed = Some(window);
            }
            ControlFrame::Event(ControlEvent::Keepalive) => keepalives += 1,
            _ => {}
        }
    }
    let renewed = renewed.expect("the host renewed the window");
    assert_ne!(renewed.action_window_id, first);
    assert_eq!(renewed.connection_id, authorised.connection_id);
    assert_eq!(renewed.boot_epoch, epochs().boot_epoch);
    assert!(keepalives >= 1, "a keepalive arrived on the control stream");

    listener.shutdown().await;
}

fn offer(client: &Side) -> ClientOffer {
    ClientOffer {
        offered_versions: vec![PROTOCOL_VERSION],
        build_id: BuildId::new("kr/0.1.0+test").expect("a build identity"),
        device_id: client.record.device_id,
        device_key_revision: client.record.device_key_revision,
        capabilities: CanonicalSet::new(),
        max_receive: ReceiveLimits::default(),
        client_nonce: fresh_nonce().expect("a nonce"),
        extensions: kr_protocol::extension::ExtensionOffers::new(),
    }
}

fn terminal_header(connection_id: ConnectionId) -> StreamHeader {
    StreamHeader {
        kind: StreamKind::TerminalOutput,
        connection_id,
        stream_id: Nullable::null(),
        resource: StreamResource {
            environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
            session_id: Nullable::some(SessionId::new(Uuid::from_bytes([8; 16]))),
            attachment_id: Nullable::some(AttachmentId::new(Uuid::from_bytes([7; 16]))),
            transfer_id: Nullable::null(),
        },
    }
}

/// Polls a condition until it holds, or fails the test.
async fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the condition never held");
}

/// A host that takes one control frame, holds its handler there until the test lets it go, and then
/// takes the next, recording when the listener read each.
#[derive(Debug)]
struct SlowHandler {
    client: PairedPeer,
    /// When the listener read each frame the handler took, on the host's clock.
    stamps: std::sync::Mutex<Vec<kr_transport::clock::ContinuousInstant>>,
    /// Said by the handler once the listener has read a frame the handler has not taken.
    queued: tokio::sync::Notify,
    /// Waited for before the handler takes its next frame.
    go: tokio::sync::Semaphore,
}

impl PairedDirectory for SlowHandler {
    fn paired_peer(&self, endpoint_id: &EndpointKey) -> Option<PairedPeer> {
        (endpoint_id == &self.client.endpoint_id).then_some(self.client)
    }
}

impl HostHandler for SlowHandler {
    fn principal_for(&self, device_id: &DeviceId) -> ActorId {
        kr_transport::listener::device_principal(device_id)
    }

    fn authority_revision(&self) -> AuthorityRevision {
        AuthorityRevision::default()
    }

    fn pairing_surface(&self) -> Option<Arc<dyn PairingSurface>> {
        None
    }

    fn serve(self: Arc<Self>, mut session: AuthorisedSession) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let mut taken = 0;
            while let Some(received) = session.control.recv().await {
                self.stamps
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(received.received_at());
                taken += 1;
                if taken == 1 {
                    // The handler is busy. What the client writes next is read by the listener and
                    // waits here, and this says when it does.
                    while session.control.queued() == 0 {
                        tokio::task::yield_now().await;
                    }
                    self.queued.notify_one();
                    self.go
                        .acquire()
                        .await
                        .expect("the semaphore is open")
                        .forget();
                }
            }
        })
    }
}

/// KR-REQ-09.16: a control frame is stamped when the listener reads it from the stream, not when
/// the handler gets to it. A frame that waits behind a handler that is busy with an earlier one has
/// its requested lifetime measured from its receipt, so the wait spends it.
#[tokio::test]
async fn a_control_frame_is_stamped_when_it_is_read_and_not_when_the_handler_reaches_it() {
    let (host, client) = paired_pair().await;
    let handler = Arc::new(SlowHandler {
        client: client.record,
        stamps: std::sync::Mutex::new(Vec::new()),
        queued: tokio::sync::Notify::new(),
        go: tokio::sync::Semaphore::new(0),
    });
    let clock = kr_transport::clock::ManualClock::new();
    let config = ListenerConfig::new(
        EndpointConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
            ..EndpointConfig::default()
        },
        epochs(),
        ControllerGeneration::new(1),
    );
    let listener = kr_transport::listener::register_with_clock(
        config,
        Arc::clone(&host.identity),
        &host.keys.transport,
        Arc::clone(&handler),
        Arc::new(clock.clone()),
    )
    .await
    .expect("a listener");
    let connection = client
        .endpoint
        .connect(listener_addr(&listener), ALPN)
        .await
        .expect("a connection");
    let mut authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");

    // The first frame is read and taken, and the handler is busy with it.
    authorised
        .control_writer
        .write_message(&ControlFrame::Event(ControlEvent::Keepalive))
        .await
        .expect("writes the first frame");
    // The second is written at the same reading of the clock, and the listener reads it while the
    // handler is still busy.
    authorised
        .control_writer
        .write_message(&ControlFrame::Event(ControlEvent::Keepalive))
        .await
        .expect("writes the second frame");
    tokio::time::timeout(Duration::from_secs(60), handler.queued.notified())
        .await
        .expect("the listener read the second frame while the handler was busy");

    // The clock moves while the second frame waits, and the handler then takes it.
    clock.advance(Duration::from_secs(7));
    handler.go.add_permits(1);
    wait_until(|| {
        handler
            .stamps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
            == 2
    })
    .await;
    let stamps = handler
        .stamps
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(
        stamps[1], stamps[0],
        "the second frame was read at the reading the first was, and not seven seconds later"
    );

    drop(authorised);
    listener.shutdown().await;
}
