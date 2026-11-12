//! The data streams a host takes from a device, and the deadlines they are held to.
//!
//! A device opens a stream, sends a header and then frames, and the listener takes the stream, reads
//! the header on a task of its own, checks it and hands the stream to the host. These cases go
//! through `listener::register` with a host that forwards what it is handed, and a device that
//! writes to its streams as bytes, so that a header with half its bytes and a frame that stops
//! half way can be sent at all.
//!
//! No case here waits for a time. Every deadline is a [`ManualDeadlines`] future that the case
//! fires once the host has reached the wait the deadline bounds, and what is asserted is what the
//! peer sees: a reset with the code a revoked stream carries, never a clean end. The one bound in
//! the file turns a host that stopped answering into a named failure instead of a job that runs
//! until it is killed; it decides nothing.

mod support;

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use futures::FutureExt as _;
use futures::future::select_all;
use iroh::endpoint::{Connection, ReadError, RecvStream, SendStream, WriteError};
use kr_cbor::CanonicalValue;
use kr_crypto::connect::PairedPeer;
use kr_protocol::envelope::{ControlEvent, ControlFrame, ParamsValue};
use kr_protocol::frame::{StreamHeader, StreamKind, StreamResource};
use kr_protocol::hello::ALPN;
use kr_protocol::ids::{
    ActorId, AttachmentId, AuthorityRevision, ConnectionId, ControllerGeneration, DeviceId,
    EnvironmentId, SessionId, TransferId,
};
use kr_protocol::scalars::{EndpointKey, Nullable, Uuid};
use kr_transport::codec::STREAM_REVOKED;
use kr_transport::config::EndpointConfig;
use kr_transport::deadlines::{DeadlineKind, ManualDeadlines};
use kr_transport::error::TransportError;
use kr_transport::handshake::{self, AuthorisedConnection, PairedDirectory};
use kr_transport::listener::{
    AuthorisedSession, BoxFuture, DATA_STREAM_QUEUE_DEPTH, DataStreams, HostHandler,
    ListenerConfig, NetworkListener, register,
};
use kr_transport::preauth::PairingSurface;
use kr_transport::scheduler::{PRIORITY_BULK, SendLimits, StreamBudget};
use kr_transport::streams::{DataStream, StreamRegistry};
use support::{Side, epochs, paired_pair};
use tokio::sync::{Notify, Semaphore, mpsc, oneshot};

/// How long a case waits for a host or a peer that should have answered by now.
///
/// A liveness bound and not a measurement: it turns a host that stopped answering into a failure
/// that names what was awaited. Nothing is decided by how long anything took.
const LIVENESS: Duration = Duration::from_secs(30);

/// Waits for `step`, or fails the case naming `what` was not reached.
async fn awaited<T>(what: &str, step: impl Future<Output = T>) -> T {
    tokio::time::timeout(LIVENESS, step)
        .await
        .unwrap_or_else(|_| panic!("{what} was never reached"))
}

/// What a test host does with the streams the listener hands it.
///
/// The connection's stream limit is raised at the first `recv` of the host's receiver, so a host
/// that is to hold streams back without reading them polls `recv` once before it announces its
/// session: that poll raises the limit and takes nothing, because the device has no credit to open
/// a stream before it, and a case sends its first stream only once it has the session. A host that
/// has not taken streams yet does not poll it at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Taking {
    /// Forwards each one to the case.
    Forward,
    /// Polls `recv` once and then holds the receiver until the case opens the gate, and then
    /// forwards.
    AfterTheGate,
    /// Does not poll `recv` until the case opens the gate, and then forwards.
    NotYet,
    /// Polls `recv` once and drops the receiver as soon as it has the session.
    Never,
    /// Polls `recv` once and holds the receiver until the case opens the gate, and then drops it.
    DropAfterTheGate,
    /// Polls `recv` once and keeps the receiver where the case can reach it, for a case that
    /// reads it itself.
    Stash,
    /// Moves the receiver to a task of its own that reads until the connection ends, and returns
    /// from `serve` at once.
    MoveAway,
    /// Moves the receiver to a task of its own that reads until the connection ends, and serves the
    /// control stream until it ends.
    KeepReading,
}

/// Where the host sends its session's registry and its end of the connection.
type SessionSender = oneshot::Sender<(Arc<StreamRegistry>, Connection)>;

/// A host that forwards the data streams it is handed to the case and otherwise only holds the
/// connection.
#[derive(Debug)]
struct ChunkHost {
    client: PairedPeer,
    taking: Taking,
    /// Opened by the case when a host that was holding back may start reading, or drop its receiver.
    gate: Semaphore,
    /// Where each stream the host takes is forwarded.
    forwarded: mpsc::UnboundedSender<DataStream>,
    /// The connection's registry and the host's end of the connection, sent to the case once the
    /// host has the session.
    session: std::sync::Mutex<Option<SessionSender>>,
    /// Holds the host's lookup of the device, and with it the device's authorisation, until the
    /// case lets it go.
    hold: Option<Arc<LookupHold>>,
    /// Said once the host has dropped the receiver, for [`Taking::Never`].
    dropped: Notify,
    receiver_dropped: AtomicBool,
    /// The receiver a host keeps for the case, for [`Taking::Stash`].
    stash: std::sync::Mutex<Option<DataStreams>>,
    /// Said once the task a receiver was moved to has seen the end of the streams, for
    /// [`Taking::MoveAway`] and [`Taking::KeepReading`].
    receiver_ended: AtomicBool,
    ended: Notify,
    /// Set when the connection's `serve` future has been dropped.
    serve_ended: Arc<AtomicBool>,
    /// What `serve_ended` said when the host's `control_stream_lost` hook ran.
    hook_saw_serve_ended: AtomicBool,
    hook_ran: AtomicBool,
    hook: Notify,
}

/// A hold on the host's lookup of a device, which the handshake cannot finish without.
///
/// The lookup is a plain call that blocks the thread it runs on, so the case holds the device's
/// authorisation where it is, with the device's offer read and nothing yet granted, for as long as
/// it needs to look at the connection in that state.
#[derive(Debug, Default)]
struct LookupHold {
    arrived: AtomicBool,
    arrival: Notify,
    released: std::sync::Mutex<bool>,
    release: std::sync::Condvar,
}

impl LookupHold {
    /// Called by the host's lookup: says it is here, and waits to be let go.
    fn wait(&self) {
        self.arrived.store(true, Ordering::Release);
        self.arrival.notify_waiters();
        let mut released = self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*released {
            released = self
                .release
                .wait(released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// Resolves once the host's lookup has been reached.
    async fn reached(&self) {
        until_set(&self.arrived, &self.arrival).await;
    }

    /// Lets the host's lookup, and the authorisation behind it, go on.
    fn let_go(&self) {
        *self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.release.notify_all();
    }
}

/// Sets a flag when it is dropped, as the host's handler does when the listener drops it.
struct SetWhenDropped(Arc<AtomicBool>);

impl Drop for SetWhenDropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Waits until `flag` is set, which `changed` announces.
async fn until_set(flag: &AtomicBool, changed: &Notify) {
    loop {
        let notified = changed.notified();
        if flag.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

impl PairedDirectory for ChunkHost {
    fn paired_peer(&self, endpoint_id: &EndpointKey) -> Option<PairedPeer> {
        if let Some(hold) = &self.hold {
            hold.wait();
        }
        (endpoint_id == &self.client.endpoint_id).then_some(self.client)
    }
}

impl HostHandler for ChunkHost {
    fn principal_for(&self, device_id: &DeviceId) -> ActorId {
        kr_transport::listener::device_principal(device_id)
    }

    fn authority_revision(&self) -> AuthorityRevision {
        AuthorityRevision::default()
    }

    fn pairing_surface(&self) -> Option<Arc<dyn PairingSurface>> {
        None
    }

    fn control_stream_lost(&self, _connection_id: ConnectionId) {
        self.hook_saw_serve_ended
            .store(self.serve_ended.load(Ordering::Acquire), Ordering::Release);
        self.hook_ran.store(true, Ordering::Release);
        self.hook.notify_waiters();
    }

    fn serve(self: Arc<Self>, mut session: AuthorisedSession) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let _serving = SetWhenDropped(Arc::clone(&self.serve_ended));
            // One poll raises the connection's stream limit, as any host's first read does. It
            // takes nothing: the device has no credit to open a stream before it. The session is
            // announced after it, so a case that sends a stream waits for it.
            if matches!(
                self.taking,
                Taking::AfterTheGate | Taking::Never | Taking::DropAfterTheGate | Taking::Stash
            ) {
                assert!(
                    session.data_streams.recv().now_or_never().is_none(),
                    "the host's first read took a stream, or found the streams ended"
                );
            }
            if let Some(sender) = self
                .session
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                let _ = sender.send((Arc::clone(&session.streams), session.connection.clone()));
            }
            match self.taking {
                Taking::Never | Taking::DropAfterTheGate => {
                    if self.taking == Taking::DropAfterTheGate {
                        self.gate
                            .acquire()
                            .await
                            .expect("the gate is never closed")
                            .forget();
                    }
                    drop(session.data_streams);
                    self.receiver_dropped.store(true, Ordering::Release);
                    self.dropped.notify_waiters();
                    // The frames the device sends are answered with themselves, so a device can
                    // make one round trip on the control stream.
                    while let Some(received) = session.control.recv().await {
                        let (frame, _) = received.into_parts();
                        let _ = session.control.send(&frame).await;
                    }
                }
                Taking::Stash => {
                    *self
                        .stash
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(session.data_streams);
                    while session.control.recv().await.is_some() {}
                }
                Taking::MoveAway | Taking::KeepReading => {
                    let mut receiver = session.data_streams;
                    let host = Arc::clone(&self);
                    tokio::spawn(async move {
                        while receiver.recv().await.is_some() {}
                        host.receiver_ended.store(true, Ordering::Release);
                        host.ended.notify_waiters();
                    });
                    if self.taking == Taking::KeepReading {
                        while session.control.recv().await.is_some() {}
                    }
                }
                Taking::Forward | Taking::AfterTheGate | Taking::NotYet => {
                    let mut admitted = session.data_streams;
                    let host = Arc::clone(&self);
                    let forwarding = tokio::spawn(async move {
                        if matches!(host.taking, Taking::AfterTheGate | Taking::NotYet) {
                            host.gate
                                .acquire()
                                .await
                                .expect("the gate is never closed")
                                .forget();
                        }
                        while let Some(stream) = admitted.recv().await {
                            if host.forwarded.send(stream).is_err() {
                                return;
                            }
                        }
                    });
                    while session.control.recv().await.is_some() {}
                    forwarding.abort();
                }
            }
        })
    }
}

/// A host on loopback, a device connected to it, and the streams the host has been handed.
struct Harness {
    listener: NetworkListener,
    connection: Connection,
    authorised: AuthorisedConnection,
    deadlines: Arc<ManualDeadlines>,
    host: Arc<ChunkHost>,
    /// Every stream the host took, in the order it took them.
    admitted: mpsc::UnboundedReceiver<DataStream>,
    /// The host's registry for the connection, and the host's end of it.
    registry: Arc<StreamRegistry>,
    host_connection: Connection,
    /// The device's own registry, which opens streams with a proper header.
    device: Arc<StreamRegistry>,
    _sides: (Side, Side),
}

/// A host on loopback and a device connected to it at the QUIC level, with nothing authorised yet.
struct Listening {
    listener: NetworkListener,
    connection: Connection,
    deadlines: Arc<ManualDeadlines>,
    host: Arc<ChunkHost>,
    admitted: mpsc::UnboundedReceiver<DataStream>,
    session: oneshot::Receiver<(Arc<StreamRegistry>, Connection)>,
    host_side: Side,
    client: Side,
}

impl Harness {
    async fn start(accepted: &[StreamKind], taking: Taking) -> Self {
        Self::listen(accepted, taking, None)
            .await
            .authorised()
            .await
    }

    /// Starts the host and connects the device to it, without the handshake.
    async fn listen(
        accepted: &[StreamKind],
        taking: Taking,
        hold: Option<Arc<LookupHold>>,
    ) -> Listening {
        let (host_side, client) = paired_pair().await;
        let (forwarded, admitted) = mpsc::unbounded_channel();
        let (session_tx, session) = oneshot::channel();
        let host = Arc::new(ChunkHost {
            client: client.record,
            taking,
            gate: Semaphore::new(0),
            forwarded,
            session: std::sync::Mutex::new(Some(session_tx)),
            hold,
            dropped: Notify::new(),
            receiver_dropped: AtomicBool::new(false),
            stash: std::sync::Mutex::new(None),
            receiver_ended: AtomicBool::new(false),
            ended: Notify::new(),
            serve_ended: Arc::new(AtomicBool::new(false)),
            hook_saw_serve_ended: AtomicBool::new(false),
            hook_ran: AtomicBool::new(false),
            hook: Notify::new(),
        });
        let deadlines = ManualDeadlines::new();
        let config = ListenerConfig {
            accepted_kinds: accepted.to_vec(),
            deadlines: deadlines.clone(),
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
            Arc::clone(&host_side.identity),
            &host_side.keys.transport,
            Arc::clone(&host),
        )
        .await
        .expect("a listener");
        let mut addr = iroh::EndpointAddr::new(listener.endpoint().id());
        for socket in listener.endpoint().bound_sockets() {
            addr = addr.with_ip_addr(socket);
        }
        let connection = client
            .endpoint
            .connect(addr, ALPN)
            .await
            .expect("a connection");
        Listening {
            listener,
            connection,
            deadlines,
            host,
            admitted,
            session,
            host_side,
            client,
        }
    }

    /// Opens a stream the way a device does, header first, and returns its two raw halves.
    async fn raw(&self, header: &StreamHeader) -> (SendStream, RecvStream) {
        let (mut send, recv) = awaited("a stream's credit", self.connection.open_bi())
            .await
            .expect("a stream");
        write_header(&mut send, header, None).await;
        (send, recv)
    }

    /// The next stream the host took.
    async fn next(&mut self) -> DataStream {
        awaited("a stream handed to the host", self.admitted.recv())
            .await
            .expect("the host is still forwarding")
    }

    async fn finish(self) {
        drop(self.authorised);
        self.connection.close(0u32.into(), b"done");
        self.listener.shutdown().await;
    }
}

impl Listening {
    /// Runs the device's side of the handshake, and returns once the host has the session.
    async fn authorised(self) -> Harness {
        let authorised = handshake::connect(
            &self.connection,
            &self.client.identity,
            &self.host_side.record,
        )
        .await
        .expect("an authorised connection");
        self.with(authorised).await
    }

    /// The harness for a device whose handshake the case has run.
    async fn with(self, authorised: AuthorisedConnection) -> Harness {
        let Self {
            listener,
            connection,
            deadlines,
            host,
            admitted,
            session,
            host_side,
            client,
        } = self;
        let (registry, host_connection) = awaited("the host's session", session)
            .await
            .expect("the host sent its session");
        let device = Arc::new(StreamRegistry::with_limits(
            authorised.connection_id,
            Arc::new(StreamBudget::new(SendLimits::default())),
            None,
            authorised.selection.limits,
        ));
        Harness {
            listener,
            connection,
            authorised,
            deadlines,
            host,
            admitted,
            registry,
            host_connection,
            device,
            _sides: (host_side, client),
        }
    }
}

/// Writes the header's length and the first `bytes` of its encoding, or all of it, and says how the
/// writes ended.
async fn try_write_header(
    send: &mut SendStream,
    header: &StreamHeader,
    bytes: Option<usize>,
) -> Result<(), WriteError> {
    let encoded = header.encode().expect("an encoded header");
    let length = u32::try_from(encoded.len()).expect("a header fits a length");
    send.write_all(&length.to_be_bytes()).await?;
    let sent = bytes.map_or(encoded.len(), |bytes| bytes.min(encoded.len()));
    send.write_all(&encoded[..sent]).await
}

/// Writes a header that the host reads before it can refuse or reset the stream, so every write of
/// it must be taken.
async fn write_header(send: &mut SendStream, header: &StreamHeader, bytes: Option<usize>) {
    try_write_header(send, header, bytes)
        .await
        .expect("the header's writes complete");
}

/// Writes a whole header to a host that resets the stream without reading it, as a host whose
/// receiver is gone does when the stream is accepted.
///
/// The host's reset stops the half the device writes with the revoked code as well as ending the
/// half it reads, and the length that announces the stream is enough for the host to reset it. The
/// stop can reach the device before the header's bytes are written, so a write that finds the
/// stream stopped with that code is the host's reset arriving early, and the case goes on to read
/// it. A write that fails in any other way fails the case.
async fn write_header_to_a_host_that_resets(send: &mut SendStream, header: &StreamHeader) {
    match try_write_header(send, header, None).await {
        Ok(()) => {}
        Err(WriteError::Stopped(code)) if code.into_inner() == u64::from(STREAM_REVOKED) => {}
        Err(other) => panic!("the header's writes ended other than in the host's reset: {other:?}"),
    }
}

fn attachment_header(connection_id: ConnectionId, transfer: u8) -> StreamHeader {
    StreamHeader {
        kind: StreamKind::AttachmentChunks,
        connection_id,
        stream_id: Nullable::null(),
        resource: StreamResource {
            environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
            session_id: Nullable::null(),
            attachment_id: Nullable::null(),
            transfer_id: Nullable::some(TransferId::new(Uuid::from_bytes([transfer; 16]))),
        },
    }
}

fn terminal_header(connection_id: ConnectionId, session: u8) -> StreamHeader {
    StreamHeader {
        kind: StreamKind::TerminalOutput,
        connection_id,
        stream_id: Nullable::null(),
        resource: StreamResource {
            environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
            session_id: Nullable::some(SessionId::new(Uuid::from_bytes([session; 16]))),
            attachment_id: Nullable::some(AttachmentId::new(Uuid::from_bytes([7; 16]))),
            transfer_id: Nullable::null(),
        },
    }
}

/// Reads a stream until the host resets it, and returns the code it reset it with.
///
/// A clean end of the stream, or a read that fails any other way, fails the case: a stream the host
/// refuses or cuts has to be seen taken away, never ended as though it had completed.
async fn reset_code(recv: &mut RecvStream) -> u64 {
    reset_after_bytes(recv).await.0
}

/// As [`reset_code`], and says how many bytes arrived before the reset.
async fn reset_after_bytes(recv: &mut RecvStream) -> (u64, usize) {
    let mut byte = [0u8; 4096];
    let mut received = 0;
    loop {
        match awaited("the host's reset of the stream", recv.read(&mut byte)).await {
            Err(ReadError::Reset(code)) => return (code.into_inner(), received),
            Ok(Some(count)) => received += count,
            other => panic!("the stream did not end in a reset: {other:?}"),
        }
    }
}

fn blob(length: usize) -> ParamsValue {
    ParamsValue::new(CanonicalValue::bytes(vec![0u8; length]))
}

/// A host that is never told to hold back a write.
fn admit_always(attempt: &mut dyn FnMut()) -> bool {
    attempt();
    true
}

/// KR-REQ-23.11: a stream whose header is half sent holds no one back. The listener reads each
/// header on a task of its own, so the stream behind it is taken and handed to the host while the
/// first still waits, and when the header deadline passes the first is reset with nothing admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_with_half_a_header_does_not_hold_back_the_next_one() {
    let mut harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Forward).await;
    let connection_id = harness.authorised.connection_id;

    // The first stream names a header and sends half of it, and stays open.
    let (mut half_send, mut half_recv) = awaited("a stream's credit", harness.connection.open_bi())
        .await
        .expect("a stream");
    let half = attachment_header(connection_id, 1);
    write_header(&mut half_send, &half, Some(12)).await;

    // The second is complete, and opened after it.
    let whole = attachment_header(connection_id, 2);
    let _second = harness
        .device
        .open(&harness.connection, whole.clone())
        .await
        .expect("a stream with a whole header");
    let admitted = harness.next().await;
    assert_eq!(
        admitted.header(),
        &whole,
        "the host was handed the stream with the whole header while the other still waited"
    );
    assert!(
        harness.admitted.try_recv().is_err(),
        "the stream with half a header was handed over too"
    );

    // Its deadline passes: the first stream is reset, and nothing was admitted for it.
    awaited(
        "the header deadline of the half-sent header",
        harness.deadlines.fire_when_armed(DeadlineKind::Header),
    )
    .await;
    assert_eq!(reset_code(&mut half_recv).await, u64::from(STREAM_REVOKED));
    assert!(
        harness.admitted.try_recv().is_err(),
        "a stream whose header never arrived was handed to the host"
    );
    assert_eq!(
        harness.registry.len(),
        1,
        "only the stream with the whole header is registered"
    );

    harness.finish().await;
}

/// KR-REQ-23.11: a stream the host does not take is reset, and the next one is taken as usual: a
/// kind the host does not accept, a header that names another connection, and a resource that does
/// not fit its kind are each refused, before any slot or registration is taken for them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_the_host_does_not_accept_is_reset_and_counted_nowhere() {
    let mut harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Forward).await;
    let connection_id = harness.authorised.connection_id;
    let other_connection = ConnectionId::new(Uuid::from_bytes([0xee; 16]));

    let mut second_control = attachment_header(connection_id, 3);
    second_control.kind = StreamKind::Control;
    let mut no_transfer = attachment_header(connection_id, 3);
    no_transfer.resource.transfer_id = Nullable::null();
    let refused = [
        ("a second control stream", second_control),
        (
            "a stream of a kind the host does not take",
            terminal_header(connection_id, 4),
        ),
        (
            "a header naming another connection",
            attachment_header(other_connection, 5),
        ),
        ("a header with no transfer", no_transfer),
    ];
    for (what, header) in refused {
        let (_send, mut recv) = harness.raw(&header).await;
        assert_eq!(
            reset_code(&mut recv).await,
            u64::from(STREAM_REVOKED),
            "{what} was not reset"
        );
    }
    assert_eq!(harness.registry.len(), 0, "a refused stream was registered");
    assert_eq!(
        harness.registry.budget().open_bulk_streams(),
        0,
        "a refused stream took a bulk slot"
    );

    // The control: the stream the host does take is handed over after all that.
    let wanted = attachment_header(connection_id, 6);
    let (_send, _recv) = harness.raw(&wanted).await;
    assert_eq!(harness.next().await.header(), &wanted);

    harness.finish().await;
}

/// A host that is not taking streams costs nothing. A stream that finds the queue full
/// is reset, and the streams already waiting are untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_that_finds_the_queue_full_is_reset() {
    // A terminal stream holds no bulk slot, so the queue is the only thing that can refuse it.
    let mut harness = Harness::start(&[StreamKind::TerminalOutput], Taking::AfterTheGate).await;
    let connection_id = harness.authorised.connection_id;

    let mut raw = Vec::new();
    for session in 0..=u8::try_from(DATA_STREAM_QUEUE_DEPTH).expect("a small depth") {
        raw.push(
            harness
                .raw(&terminal_header(connection_id, session + 1))
                .await,
        );
    }
    assert_eq!(raw.len(), DATA_STREAM_QUEUE_DEPTH + 1);

    // One of the five is reset, whichever the host decided last, and the others are left open.
    let resets = raw
        .iter_mut()
        .map(|(_, recv)| Box::pin(reset_code(recv)))
        .collect::<Vec<_>>();
    let (code, _, _) = select_all(resets).await;
    assert_eq!(code, u64::from(STREAM_REVOKED));

    // The host starts reading, and takes exactly the streams that fit.
    harness.host.gate.add_permits(1);
    let mut taken = Vec::new();
    for _ in 0..DATA_STREAM_QUEUE_DEPTH {
        taken.push(harness.next().await);
    }
    assert!(
        harness.admitted.try_recv().is_err(),
        "the stream that did not fit was handed over as well"
    );
    assert_eq!(
        harness.registry.len(),
        DATA_STREAM_QUEUE_DEPTH,
        "the reset stream stayed in the registry"
    );

    harness.finish().await;
}

/// A host that is gone from its queue costs nothing either: the stream is reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_for_a_host_that_dropped_its_receiver_is_reset() {
    let harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Never).await;
    awaited(
        "the host dropping its receiver",
        until_set(&harness.host.receiver_dropped, &harness.host.dropped),
    )
    .await;

    let header = attachment_header(harness.authorised.connection_id, 1);
    let (mut send, mut recv) = awaited("a stream's credit", harness.connection.open_bi())
        .await
        .expect("a stream");
    write_header_to_a_host_that_resets(&mut send, &header).await;
    assert_eq!(reset_code(&mut recv).await, u64::from(STREAM_REVOKED));
    awaited(
        "the stream leaving the registry",
        emptied(&harness.registry),
    )
    .await;
    assert_eq!(harness.registry.budget().open_bulk_streams(), 0);

    harness.finish().await;
}

/// Waits until the registry holds no stream: a reset is sent before the stream's accounting ends.
async fn emptied(registry: &StreamRegistry) {
    while !registry.is_empty() {
        tokio::task::yield_now().await;
    }
}

/// A host that stops taking streams while its connection stands tells the device each stream that
/// was still queued was taken away: the queue's streams are reset, not finished as though they had
/// ended cleanly, and what they held is returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_drops_its_queue_resets_the_streams_still_in_it() {
    let harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::DropAfterTheGate).await;
    let connection_id = harness.authorised.connection_id;
    let mut queued = vec![
        harness.raw(&attachment_header(connection_id, 1)).await,
        harness.raw(&attachment_header(connection_id, 2)).await,
    ];
    // Both are admitted, and so queued or about to be: the host has not read the queue.
    awaited("both streams being admitted", async {
        while harness.registry.len() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await;

    harness.host.gate.add_permits(1);
    for (_, recv) in &mut queued {
        assert_eq!(reset_code(recv).await, u64::from(STREAM_REVOKED));
    }
    awaited(
        "the streams leaving the registry",
        emptied(&harness.registry),
    )
    .await;
    assert_eq!(harness.registry.budget().open_bulk_streams(), 0);

    harness.finish().await;
}

/// The host's `control_stream_lost` hook runs once its handler has gone. The listener revokes the
/// streams as soon as the loss is declared, but a host that registers the connection while it serves
/// has to be asked to withdraw it after the handler, never before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hosts_hook_runs_after_its_handler_has_gone() {
    let mut harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Forward).await;
    harness.authorised.control_writer.reset();
    awaited(
        "the host's control_stream_lost hook",
        until_set(&harness.host.hook_ran, &harness.host.hook),
    )
    .await;
    assert!(
        harness.host.hook_saw_serve_ended.load(Ordering::Acquire),
        "the hook ran while the host's handler was still being served"
    );

    harness.finish().await;
}

/// A frame that stops arriving is cut by the stall deadline. The device sends a
/// frame's length and a few of its bytes and then nothing; the read ends, the stream is revoked and
/// the device sees it reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_that_stops_arriving_is_cut_by_the_stall_deadline() {
    let mut harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Forward).await;
    let header = attachment_header(harness.authorised.connection_id, 1);
    let (mut send, mut recv) = harness.raw(&header).await;
    let mut stream = harness.next().await;

    send.write_all(&100u32.to_be_bytes())
        .await
        .expect("a frame length");
    send.write_all(&[7u8; 10]).await.expect("part of the frame");
    let reading = tokio::spawn(async move {
        let outcome = stream.read_payload().await;
        (outcome, stream)
    });
    awaited(
        "the stall deadline of the unfinished frame",
        harness.deadlines.fire_when_armed(DeadlineKind::Stall),
    )
    .await;
    let (outcome, stream) = awaited("the read that was cut", reading)
        .await
        .expect("the read task ended");
    assert!(
        matches!(outcome, Err(TransportError::Deadline(DeadlineKind::Stall))),
        "the read was not cut by the stall deadline: {outcome:?}"
    );
    assert!(stream.is_revoked(), "a stream that stalled was left usable");
    // The host ends a stream it cut by dropping it, which is what resets a revoked stream.
    drop(stream);
    assert_eq!(reset_code(&mut recv).await, u64::from(STREAM_REVOKED));
    // The reset of the half the device reads says nothing of the stop of the half it writes: they
    // are two frames, so the write waits for the stop.
    let stopped = awaited("the stop of the device's half", send.stopped()).await;
    assert!(
        matches!(stopped, Ok(Some(code)) if code.into_inner() == u64::from(STREAM_REVOKED)),
        "the host did not stop the device's half with the revoked code: {stopped:?}"
    );
    assert!(
        matches!(
            send.write_all(&[0u8; 8]).await,
            Err(WriteError::Stopped(code)) if code.into_inner() == u64::from(STREAM_REVOKED)
        ),
        "the device could still write to a stream the host cut"
    );

    harness.finish().await;
}

/// A stream that is quiet between frames is cut by the idle deadline, and the device
/// sees it reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_that_sends_no_frame_is_cut_by_the_idle_deadline() {
    let mut harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Forward).await;
    let header = attachment_header(harness.authorised.connection_id, 1);
    let (_send, mut recv) = harness.raw(&header).await;
    let mut stream = harness.next().await;

    let waiting = tokio::spawn(async move {
        let outcome = stream.read_payload().await;
        (outcome, stream)
    });
    awaited(
        "the idle deadline of the waiting stream",
        harness.deadlines.fire_when_armed(DeadlineKind::Idle),
    )
    .await;
    let (outcome, stream) = awaited("the read that was cut", waiting)
        .await
        .expect("the read task ended");
    assert!(
        matches!(outcome, Err(TransportError::Deadline(DeadlineKind::Idle))),
        "the wait was not cut by the idle deadline: {outcome:?}"
    );
    assert!(stream.is_revoked());
    drop(stream);
    assert_eq!(reset_code(&mut recv).await, u64::from(STREAM_REVOKED));

    harness.finish().await;
}

/// A device that never reads its answers cannot hold the stream. A write that waits
/// for the device is cut by the write deadline, and because the stream is split, the half that
/// reads sees the stream revoked too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_the_device_does_not_read_is_cut_by_the_write_deadline() {
    let mut harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Forward).await;
    let header = attachment_header(harness.authorised.connection_id, 1);
    let (_send, mut recv) = harness.raw(&header).await;
    let (reader, mut writer) = harness.next().await.split();

    // The first frame fits in the flow-control credit the device gave the stream. The second does
    // not, and the device reads nothing, so it waits.
    let first_written = Arc::new(Notify::new());
    let signal = Arc::clone(&first_written);
    let writing = tokio::spawn(async move {
        let first = writer
            .write_message_while(&blob(1_000_000), &admit_always)
            .await;
        signal.notify_one();
        let second = writer
            .write_message_while(&blob(1_000_000), &admit_always)
            .await;
        (first, second, writer)
    });
    awaited("the first frame being written", first_written.notified()).await;
    awaited(
        "the write deadline of the second frame",
        harness.deadlines.fire_when_armed(DeadlineKind::Write),
    )
    .await;
    let (first, second, writer) = awaited("the write that was cut", writing)
        .await
        .expect("the write task ended");
    assert!(matches!(first, Ok(true)), "the first frame was not written");
    assert!(
        matches!(second, Err(TransportError::Deadline(DeadlineKind::Write))),
        "the write was not cut by the write deadline: {second:?}"
    );
    assert!(
        reader.is_revoked(),
        "the half that reads did not see the stream revoked"
    );
    assert_eq!(
        harness.registry.budget().queued_bytes(),
        0,
        "a write that was cut kept its queue space"
    );
    drop((reader, writer));
    assert_eq!(reset_code(&mut recv).await, u64::from(STREAM_REVOKED));

    harness.finish().await;
}

/// A host that refuses to let a write go.
fn refuse(_attempt: &mut dyn FnMut()) -> bool {
    false
}

/// Ending a stream by revoking its handle ends a write that waits for the device. The write fails
/// as a revoked stream's does, never with a refusal, and the stream is reset when it is dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoking_a_stream_ends_a_write_the_device_does_not_read() {
    let mut harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Forward).await;
    let header = attachment_header(harness.authorised.connection_id, 1);
    let (_send, mut recv) = harness.raw(&header).await;
    let stream = harness.next().await;
    let handle = stream.handle();
    let (reader, mut writer) = stream.split();

    let first_written = Arc::new(Notify::new());
    let signal = Arc::clone(&first_written);
    let writing = tokio::spawn(async move {
        let first = writer
            .write_message_while(&blob(1_000_000), &admit_always)
            .await;
        signal.notify_one();
        let second = writer
            .write_message_while(&blob(1_000_000), &admit_always)
            .await;
        (first, second, writer)
    });
    awaited("the first frame being written", first_written.notified()).await;
    // The second frame holds its queue space for as long as it is being written, and the device
    // reads nothing, so it is still in the write when the stream is revoked.
    awaited("the second frame being written", async {
        while harness.registry.budget().queued_bytes() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    handle.revoke();
    let (first, second, writer) = awaited("the write that was ended", writing)
        .await
        .expect("the write task ended");
    assert!(matches!(first, Ok(true)), "the first frame was not written");
    assert!(
        matches!(second, Err(TransportError::ControlLost)),
        "a revoked stream's write did not fail as one: {second:?}"
    );
    assert!(reader.is_revoked());
    assert_eq!(harness.registry.budget().queued_bytes(), 0);
    drop((reader, writer));
    assert_eq!(reset_code(&mut recv).await, u64::from(STREAM_REVOKED));

    harness.finish().await;
}

/// Reads one whole frame from a stream a device holds, and returns its payload's length.
async fn whole_frame(recv: &mut RecvStream) -> usize {
    let mut prefix = [0u8; 4];
    awaited("a frame's length", recv.read_exact(&mut prefix))
        .await
        .expect("a frame's length");
    let length = u32::from_be_bytes(prefix) as usize;
    let mut payload = vec![0u8; length];
    awaited("a frame's payload", recv.read_exact(&mut payload))
        .await
        .expect("a frame's payload");
    length
}

/// A frame is not written past the moment its stream is revoked. A write hands a frame to the
/// stream in attempts, a length and then the payload, and the stream's revoked state is asked at
/// each of them, in the same poll, so a revocation that arrives between two attempts of one poll,
/// which a race against the revocation cannot tell from one that arrives just after the write,
/// ends the write there. Here the host's check revokes the stream while it admits the first
/// attempt, with the stream still writable: its check is not asked again, the second attempt is
/// not made, the write fails as a revoked stream's does and the device reads a reset, never the
/// frame. The same write with no revocation arrives whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_is_not_written_once_the_stream_is_revoked() {
    let mut harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Forward).await;
    let header = attachment_header(harness.authorised.connection_id, 1);
    let (_send, mut recv) = harness.raw(&header).await;
    let stream = harness.next().await;
    let handle = stream.handle();
    let (reader, mut writer) = stream.split();

    // The control: with nothing revoked the frame arrives whole.
    let written = writer
        .write_message_while(&blob(100), &admit_always)
        .await
        .expect("a write that nothing ends");
    assert!(
        written,
        "a frame nothing refused was reported as not written"
    );
    assert!(whole_frame(&mut recv).await >= 100);

    let asked = AtomicUsize::new(0);
    let revoke_at_the_first_attempt = |attempt: &mut dyn FnMut()| {
        if asked.fetch_add(1, Ordering::SeqCst) == 0 {
            attempt();
            handle.revoke();
            true
        } else {
            false
        }
    };
    let outcome = writer
        .write_message_while(&blob(100), &revoke_at_the_first_attempt)
        .await;
    assert!(
        matches!(outcome, Err(TransportError::ControlLost)),
        "a write that was revoked part way did not fail as a revoked stream's does: {outcome:?}"
    );
    assert_eq!(
        asked.load(Ordering::SeqCst),
        1,
        "the host's check was asked again after the stream was revoked"
    );
    assert!(reader.is_revoked());
    drop((reader, writer));
    let (code, received) = reset_after_bytes(&mut recv).await;
    assert_eq!(code, u64::from(STREAM_REVOKED));
    assert!(
        received <= kr_protocol::frame::FRAME_LENGTH_PREFIX_LEN,
        "{received} bytes reached the device, so part of the frame went after the revocation"
    );

    harness.finish().await;
}

/// A revocation that lands while the host's check is running stops the attempt it was running for.
/// The check may wait for a lock before it hands bytes over, and the stream's revoked state is
/// asked again inside the attempt, once the check holds what it holds: here the check revokes the
/// stream and then makes the attempt for the payload, which is not made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_while_the_hosts_check_runs_stops_the_attempt() {
    let mut harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Forward).await;
    let header = attachment_header(harness.authorised.connection_id, 1);
    let (_send, mut recv) = harness.raw(&header).await;
    let stream = harness.next().await;
    let handle = stream.handle();
    let (reader, mut writer) = stream.split();

    let asked = AtomicUsize::new(0);
    let revoke_before_the_second_attempt = |attempt: &mut dyn FnMut()| {
        if asked.fetch_add(1, Ordering::SeqCst) == 1 {
            handle.revoke();
        }
        attempt();
        true
    };
    let outcome = writer
        .write_message_while(&blob(100), &revoke_before_the_second_attempt)
        .await;
    assert!(
        matches!(outcome, Err(TransportError::ControlLost)),
        "a write whose stream was revoked as its attempt began did not fail as one: {outcome:?}"
    );
    assert!(reader.is_revoked());
    drop((reader, writer));
    let (code, received) = reset_after_bytes(&mut recv).await;
    assert_eq!(code, u64::from(STREAM_REVOKED));
    assert!(
        received <= kr_protocol::frame::FRAME_LENGTH_PREFIX_LEN,
        "{received} bytes reached the device, so the payload went after the revocation"
    );

    harness.finish().await;
}

/// A write the host's own check refuses leaves the stream reset, and the half that reads stops with
/// it: the host has withdrawn what it asked, so there is nothing more to take from the stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_the_hosts_check_refuses_resets_the_stream_and_stops_the_reader() {
    let mut harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Forward).await;
    let header = attachment_header(harness.authorised.connection_id, 1);
    let (_send, mut recv) = harness.raw(&header).await;
    let (reader, mut writer) = harness.next().await.split();

    let written = writer
        .write_message_while(&blob(100), &refuse)
        .await
        .expect("a refusal by the host's own check is not an error");
    assert!(!written, "a refused frame was reported as written");
    assert!(
        reader.is_revoked(),
        "the half that reads kept reading a stream whose write was refused"
    );
    drop((reader, writer));
    assert_eq!(reset_code(&mut recv).await, u64::from(STREAM_REVOKED));

    harness.finish().await;
}

/// A read the host drops before it ends has consumed part of a frame, or waited for one, and the
/// stream can carry nothing more: dropping it revokes the stream, so the other half stops too and
/// the device sees a reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_dropped_before_it_ends_revokes_the_stream() {
    let mut harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Forward).await;
    let header = attachment_header(harness.authorised.connection_id, 1);
    let (_send, mut recv) = harness.raw(&header).await;
    let mut stream = harness.next().await;

    // Nothing has been sent, so the read waits, and dropping it is a host giving up on it.
    assert!(stream.read_payload().now_or_never().is_none());
    assert!(
        stream.is_revoked(),
        "a stream whose read was dropped part way was left usable"
    );
    drop(stream);
    assert_eq!(reset_code(&mut recv).await, u64::from(STREAM_REVOKED));

    harness.finish().await;
}

/// Lets a held lookup go when a case ends, however it ends: a case that fails while the host's
/// lookup is held would otherwise leave a runtime thread blocked in it.
struct LetGoWhenDropped(Arc<LookupHold>);

impl Drop for LetGoWhenDropped {
    fn drop(&mut self) {
        self.0.let_go();
    }
}

/// KR-REQ-23.19: a connection that is not authorised yet has room for one stream, the one the
/// handshake runs on. While the host's lookup of the device is held, a second stream the device
/// opens finds no credit; once the host has authorised the connection and raised the limit, the
/// same open completes and the stream is taken as a data stream is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_stream_waits_until_the_connection_is_authorised() {
    let hold = Arc::new(LookupHold::default());
    let _let_go = LetGoWhenDropped(Arc::clone(&hold));
    let listening = Harness::listen(
        &[StreamKind::AttachmentChunks],
        Taking::Forward,
        Some(Arc::clone(&hold)),
    )
    .await;

    // The device's offer is sent on the connection's first stream and the host's lookup of the
    // device is reached. The connection has been granted nothing yet.
    let mut handshaking = Box::pin(handshake::connect(
        &listening.connection,
        &listening.client.identity,
        &listening.host_side.record,
    ));
    tokio::select! {
        outcome = &mut handshaking => {
            panic!("the handshake ended while the host's lookup was held: {:?}", outcome.map(|_| ()))
        }
        () = awaited("the host's lookup of the device", hold.reached()) => {}
    }
    let mut second = Box::pin(listening.connection.open_bi());
    assert!(
        futures::poll!(&mut second).is_pending(),
        "a connection that is not authorised yet had room for a second stream"
    );

    hold.let_go();
    let authorised = awaited("the handshake", handshaking)
        .await
        .expect("an authorised connection");
    let (mut send, _recv) = awaited(
        "the second stream, once the connection is authorised",
        second,
    )
    .await
    .expect("a second stream");
    let mut harness = listening.with(authorised).await;
    let header = attachment_header(harness.authorised.connection_id, 1);
    write_header(&mut send, &header, None).await;
    assert_eq!(harness.next().await.header(), &header);

    harness.finish().await;
}

/// A host that takes no data streams leaves its connections at room for one stream.
/// A second stream the device opens finds no credit: the host has been told the device is blocked,
/// reports that it granted nothing, and the open ends only with the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_takes_no_data_streams_leaves_a_device_one_stream() {
    let harness = Harness::start(&[], Taking::Forward).await;

    let mut second = Box::pin(harness.connection.open_bi());
    assert!(
        futures::poll!(&mut second).is_pending(),
        "a device had room for a second stream on a host that takes none"
    );
    awaited("the host being told the device is blocked", async {
        while harness
            .host_connection
            .stats()
            .frame_rx
            .streams_blocked_bidi
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(
        harness.host_connection.stats().frame_tx.max_streams_bidi,
        0,
        "the host granted a device more streams though it takes none"
    );
    assert!(futures::poll!(&mut second).is_pending());
    harness.connection.close(0u32.into(), b"done");
    let outcome = awaited("the open that waited", second).await;
    assert!(
        outcome.is_err(),
        "the second stream was opened on a host that takes no data streams"
    );

    harness.finish().await;
}

/// A host opens no stream to a device: a client's endpoint allows none, so a stream the host tries
/// to open finds no credit, and a client that waits to accept one waits for the end of the
/// connection. The device has been told the host is blocked, so a packet has crossed since its
/// accept began, and the accept is still waiting and the host's open still has no credit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_opens_no_stream_to_a_device() {
    let harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Forward).await;

    let device = Arc::clone(&harness.device);
    let connection = harness.connection.clone();
    let accepting = tokio::spawn(async move { device.accept(&connection).await.map(|_| ()) });
    let mut from_the_host = Box::pin(harness.host_connection.open_bi());
    assert!(
        futures::poll!(&mut from_the_host).is_pending(),
        "a device's endpoint had room for a stream the host opens"
    );
    awaited("the device being told the host is blocked", async {
        while harness.connection.stats().frame_rx.streams_blocked_bidi == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(!accepting.is_finished(), "a device's accept ended at once");
    assert!(futures::poll!(&mut from_the_host).is_pending());
    harness.host_connection.close(0u32.into(), b"done");
    let accepted = awaited("the device's accept ending with the connection", accepting)
        .await
        .expect("the accept task ended");
    assert!(
        accepted.is_err(),
        "a device accepted a stream the host cannot open"
    );
    drop(from_the_host);

    harness.finish().await;
}

/// A host that has not taken streams yet leaves its device one stream: the stream limit is raised
/// when the host first reads, and not when it authorises the connection. The host is serving and
/// has not polled its receiver, so a second open finds no credit, the host reports it granted
/// nothing, and when the host starts reading the same open completes and its stream is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_has_not_taken_streams_leaves_a_device_one_stream_until_it_does() {
    let mut harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::NotYet).await;

    let mut second = Box::pin(harness.connection.open_bi());
    assert!(
        futures::poll!(&mut second).is_pending(),
        "a device had room for a second stream before the host took any"
    );
    awaited("the host being told the device is blocked", async {
        while harness
            .host_connection
            .stats()
            .frame_rx
            .streams_blocked_bidi
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(
        harness.host_connection.stats().frame_tx.max_streams_bidi,
        0,
        "the host granted credit before it read its first stream"
    );

    harness.host.gate.add_permits(1);
    let (mut send, _recv) = awaited("the second stream, once the host reads", second)
        .await
        .expect("a second stream");
    let header = attachment_header(harness.authorised.connection_id, 1);
    write_header(&mut send, &header, None).await;
    assert_eq!(harness.next().await.header(), &header);

    harness.finish().await;
}

/// A host that drops its queue while the listener is reading a stream's header ends that read:
/// the stream is reset at once, not when its header deadline passes, and nothing the listener held
/// for it is kept. The header deadline here is never fired.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_drops_its_queue_releases_a_header_being_read() {
    let harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::DropAfterTheGate).await;
    let header = attachment_header(harness.authorised.connection_id, 1);
    let (mut half_send, mut half_recv) = awaited("a stream's credit", harness.connection.open_bi())
        .await
        .expect("a stream");
    write_header(&mut half_send, &header, Some(12)).await;
    awaited(
        "the listener reading the header",
        harness.deadlines.wait_armed(DeadlineKind::Header),
    )
    .await;

    harness.host.gate.add_permits(1);
    assert_eq!(reset_code(&mut half_recv).await, u64::from(STREAM_REVOKED));
    assert!(harness.registry.is_empty());
    assert_eq!(harness.registry.budget().open_bulk_streams(), 0);

    harness.finish().await;
}

/// A stream that was revoked while it waited in the queue is reset and skipped, and never handed to
/// the host: the host keeps a transfer's stream where it could replace the device's live one. The
/// case waits until the stream is in the queue, revokes the connection's streams, and only then
/// lets the receiver meet it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_revoked_while_queued_is_reset_and_not_handed_over() {
    let harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Stash).await;
    let (_send, mut recv) = harness
        .raw(&attachment_header(harness.authorised.connection_id, 1))
        .await;
    let queued = || {
        harness
            .host
            .stash
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map_or(0, DataStreams::queued)
    };
    awaited("the stream being queued", async {
        while queued() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    harness.registry.revoke_all();

    let mut receiver = harness
        .host
        .stash
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .expect("the host kept its receiver");
    let handed_over = awaited("the receiver meeting the stream", receiver.recv()).await;
    assert!(
        handed_over.is_none(),
        "a stream that was revoked in the queue was handed to the host"
    );
    assert_eq!(reset_code(&mut recv).await, u64::from(STREAM_REVOKED));

    harness.finish().await;
}

/// A receiver that the host moved to another task ends when the connection ends, whichever way the
/// listener's accept task ended. Here the host moves the receiver away and returns from serving
/// at once, on a runtime with one thread, so the connection's cleanup aborts the accept task before
/// it has run at all: the end of the streams is announced by what the accept task owned, not by
/// anything its body did. The order rests on the runtime: the connection's task reaches the abort
/// in the poll that spawned the accept task, with the runtime's per-poll budget of cooperative
/// work (128 operations) not yet spent, as the end of a handshake spends only a few. A task that
/// reached its `select!` with no budget left would yield first, the accept task would run, and
/// the case would pass without testing the guard. The case cannot set that budget, which belongs to
/// the listener's task.
#[tokio::test(flavor = "current_thread")]
async fn a_receiver_held_elsewhere_ends_when_the_accept_task_never_ran() {
    let listening = Harness::listen(&[StreamKind::AttachmentChunks], Taking::MoveAway, None).await;
    // The host's cleanup closes the connection as soon as the host has the session, which can cut
    // what the device reads last: how the device's handshake ends is not what this case is about.
    let _ = handshake::connect(
        &listening.connection,
        &listening.client.identity,
        &listening.host_side.record,
    )
    .await;
    awaited(
        "the receiver held elsewhere seeing the streams end",
        until_set(&listening.host.receiver_ended, &listening.host.ended),
    )
    .await;

    listening.connection.close(0u32.into(), b"done");
    listening.listener.shutdown().await;
}

/// A receiver reads `None` when its connection ends: the host keeps reading on a task of its own,
/// and the end of the streams reaches it without anything else waking it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receiver_ends_when_its_connection_does() {
    let harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::KeepReading).await;
    assert!(
        !harness.host.receiver_ended.load(Ordering::Acquire),
        "the receiver ended while its connection stood"
    );

    harness.connection.close(0u32.into(), b"done");
    awaited(
        "the receiver seeing the streams end",
        until_set(&harness.host.receiver_ended, &harness.host.ended),
    )
    .await;

    harness.finish().await;
}

/// A host that drops its receiver gives the device no more credit to open streams. The credit
/// already sent stays, so the device can use it, and every stream it opens is reset; but the
/// freeing of those streams, which would grant a stream each, grants nothing: the limit went back
/// to the control stream's one with the receiver. The device opens the streams its credit allows
/// and the host resets each; the next open still finds no credit, and the device has told the host
/// it is blocked. (The host's count of the credit frames it has sent is not asserted: a frame whose
/// acknowledgement comes late is sent again, with nothing new in it.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_drops_its_receiver_gives_no_more_credit() {
    let mut harness =
        Harness::start(&[StreamKind::AttachmentChunks], Taking::DropAfterTheGate).await;
    // The streams the connection allows beside its control stream: the bulk streams, the places
    // for streams waiting for their headers, and one more.
    let granted = u8::try_from(
        SendLimits::default().max_bulk_streams + kr_transport::streams::MAX_PENDING_HEADERS + 1,
    )
    .expect("a small credit");

    // The credit the host's first read gave: a stream for each, opened and not yet used.
    let mut held = Vec::new();
    for _ in 0..granted {
        held.push(
            awaited(
                "the credit the first read gave",
                harness.connection.open_bi(),
            )
            .await
            .expect("a stream"),
        );
    }

    harness.host.gate.add_permits(1);
    awaited(
        "the host dropping its receiver",
        until_set(&harness.host.receiver_dropped, &harness.host.dropped),
    )
    .await;
    for (send, recv) in &mut held {
        // A byte is what announces the stream to the host. The host resets it without reading a
        // header, so a later write of the device's can find the stream stopped.
        let _ = send.write_all(&[0u8]).await;
        assert_eq!(reset_code(recv).await, u64::from(STREAM_REVOKED));
        // The device ends its half too, so the host's stream is free on both sides and the
        // library would hand its place on as credit.
        let _ = send.reset(0u32.into());
    }

    // Without the withdrawal, each stream the host frees would add a stream's credit, and the
    // library would send it once two are free. So the first look comes after the host has received
    // the reset of every stream, and after one round trip on the control stream: the device's
    // frame carries its acknowledgements of the host's resets, which free the streams on the host,
    // and the host's answer cannot overtake the credit those frees would have queued.
    awaited("the host receiving the reset of each stream", async {
        while harness.host_connection.stats().frame_rx.reset_stream < u64::from(granted) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    harness
        .authorised
        .control_writer
        .write_message(&ControlFrame::Event(ControlEvent::Keepalive))
        .await
        .expect("the device writes to the control stream");
    awaited(
        "the host's answer on the control stream",
        harness
            .authorised
            .control_reader
            .read_message::<ControlFrame>(),
    )
    .await
    .expect("the control stream is readable")
    .expect("the host answers");

    let mut next = Box::pin(harness.connection.open_bi());
    assert!(
        futures::poll!(&mut next).is_pending(),
        "a device was given credit for a stream after the host dropped its receiver"
    );
    awaited("the host being told the device is blocked", async {
        while harness
            .host_connection
            .stats()
            .frame_rx
            .streams_blocked_bidi
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        futures::poll!(&mut next).is_pending(),
        "a device was given credit for a stream after the host dropped its receiver"
    );
    drop(next);

    harness.finish().await;
}

/// A connection takes no datagram from either side. The product reads none, and the library keeps
/// the unread ones of every connection up to a stream's window, the connections that are not
/// authorised yet among them. A side that takes none leaves the datagram parameter out of what it
/// tells its peer, so the peer finds no size a datagram may have.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_takes_no_datagram_from_either_side() {
    let harness = Harness::start(&[], Taking::Forward).await;

    assert_eq!(
        harness.connection.max_datagram_size(),
        None,
        "the host takes datagrams from a device"
    );
    assert_eq!(
        harness.host_connection.max_datagram_size(),
        None,
        "a device takes datagrams from the host"
    );

    harness.finish().await;
}

/// KR-PERF-005 and KR-REQ-23.21: a stream the listener hands over is scheduled as a transfer is, on
/// the host's side and on the device's, so its answers go behind control and receipts. Frames pass
/// both ways, and the stream stays counted against its connection until both halves are dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_the_listener_hands_over_is_scheduled_as_bulk() {
    let mut harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Forward).await;
    let header = attachment_header(harness.authorised.connection_id, 1);
    let mut device_side = harness
        .device
        .open(&harness.connection, header.clone())
        .await
        .expect("a stream");
    let mut host_side = harness.next().await;

    assert_eq!(device_side.priority(), Some(PRIORITY_BULK));
    assert_eq!(
        host_side.priority(),
        Some(PRIORITY_BULK),
        "the connection does not use the bulk priority for a stream the listener handed over"
    );

    // A frame in, and an answer out, as a chunk and its receipt travel.
    let chunk = blob(1_000);
    device_side
        .write_message(&chunk)
        .await
        .expect("the device's frame");
    let read = awaited(
        "the device's frame",
        host_side.read_message::<ParamsValue>(),
    )
    .await
    .expect("a readable frame")
    .expect("a frame, not an end");
    assert_eq!(read, chunk);
    let (reader, mut writer) = host_side.split();
    assert!(
        writer
            .write_message_while(&read, &admit_always)
            .await
            .expect("the answer"),
        "the answer was not admitted"
    );
    let answer = awaited(
        "the host's answer",
        device_side.read_message::<ParamsValue>(),
    )
    .await
    .expect("a readable answer")
    .expect("an answer, not an end");
    assert_eq!(answer, chunk);

    // The stream is one stream, counted until the last half goes.
    assert_eq!(harness.registry.len(), 1);
    assert_eq!(harness.registry.budget().open_bulk_streams(), 1);
    drop(reader);
    assert_eq!(harness.registry.len(), 1, "the writing half was still held");
    assert_eq!(harness.registry.budget().open_bulk_streams(), 1);
    drop(writer);
    assert_eq!(harness.registry.len(), 0);
    assert_eq!(harness.registry.budget().open_bulk_streams(), 0);

    harness.finish().await;
}

/// A host that waits for one stream, tells the case, and then writes to the control stream until the
/// write fails, checking at that moment whether the stream was revoked.
#[derive(Debug)]
struct LossHost {
    client: PairedPeer,
    admitted: std::sync::Mutex<Option<oneshot::Sender<()>>>,
    verdict: std::sync::Mutex<Option<oneshot::Sender<bool>>>,
}

impl PairedDirectory for LossHost {
    fn paired_peer(&self, endpoint_id: &EndpointKey) -> Option<PairedPeer> {
        (endpoint_id == &self.client.endpoint_id).then_some(self.client)
    }
}

impl HostHandler for LossHost {
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
            let stream = session
                .data_streams
                .recv()
                .await
                .expect("a stream was admitted");
            if let Some(sent) = self
                .admitted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                let _ = sent.send(());
            }
            // The device has stopped reading its control stream, which the host learns when a
            // write to it fails. The write that fails declares the control stream lost, and the
            // data streams are revoked by the time it returns: nothing else has run since.
            let sender = session.control.sender();
            let keepalive = kr_protocol::envelope::ControlFrame::Event(
                kr_protocol::envelope::ControlEvent::Keepalive,
            );
            while sender.send(&keepalive).await.is_ok() {
                tokio::task::yield_now().await;
            }
            let revoked = stream.is_revoked();
            if let Some(verdict) = self
                .verdict
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                let _ = verdict.send(revoked);
            }
            while session.control.recv().await.is_some() {}
        })
    }
}

/// KR-REQ-23.18: the data streams are revoked where the loss of the control stream is declared, and
/// not when the connection's supervisor next runs. A host that learns of the loss from a failed
/// write finds a stream it was handed already revoked when the write returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_control_write_revokes_the_data_streams_before_it_returns() {
    let (host_side, client) = paired_pair().await;
    let (admitted_tx, admitted_rx) = oneshot::channel();
    let (verdict_tx, verdict_rx) = oneshot::channel();
    let host = Arc::new(LossHost {
        client: client.record,
        admitted: std::sync::Mutex::new(Some(admitted_tx)),
        verdict: std::sync::Mutex::new(Some(verdict_tx)),
    });
    let config = ListenerConfig {
        accepted_kinds: vec![StreamKind::AttachmentChunks],
        deadlines: ManualDeadlines::new(),
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
        Arc::clone(&host_side.identity),
        &host_side.keys.transport,
        host,
    )
    .await
    .expect("a listener");
    let mut addr = iroh::EndpointAddr::new(listener.endpoint().id());
    for socket in listener.endpoint().bound_sockets() {
        addr = addr.with_ip_addr(socket);
    }
    let connection = client
        .endpoint
        .connect(addr, ALPN)
        .await
        .expect("a connection");
    let mut authorised = handshake::connect(&connection, &client.identity, &host_side.record)
        .await
        .expect("an authorised connection");
    let (mut send, _recv) = awaited("a stream's credit", connection.open_bi())
        .await
        .expect("a stream");
    write_header(
        &mut send,
        &attachment_header(authorised.connection_id, 1),
        None,
    )
    .await;
    awaited("the host being handed the stream", admitted_rx)
        .await
        .expect("the host reported the stream");

    // The device stops reading its control stream, and the host's next writes to it fail.
    authorised.control_reader.stop();
    let revoked = awaited("the failed control write", verdict_rx)
        .await
        .expect("the host reported");
    assert!(
        revoked,
        "a data stream was not revoked when the control write that failed returned"
    );

    drop(authorised);
    connection.close(0u32.into(), b"done");
    listener.shutdown().await;
}
