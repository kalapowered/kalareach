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
use std::time::Duration;

use futures::future::select_all;
use iroh::endpoint::{Connection, ReadError, RecvStream, SendStream, WriteError};
use kr_cbor::CanonicalValue;
use kr_crypto::connect::PairedPeer;
use kr_protocol::envelope::ParamsValue;
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
    AuthorisedSession, BoxFuture, DATA_STREAM_QUEUE_DEPTH, HostHandler, ListenerConfig,
    NetworkListener, register,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Taking {
    /// Forwards each one to the case.
    Forward,
    /// Holds the receiver without reading it until the case opens the gate, and then forwards.
    AfterTheGate,
    /// Drops the receiver as soon as it has the session.
    Never,
}

/// A host that forwards the data streams it is handed to the case and otherwise only holds the
/// connection.
#[derive(Debug)]
struct ChunkHost {
    client: PairedPeer,
    taking: Taking,
    /// Opened by the case when [`Taking::AfterTheGate`] may start reading.
    gate: Semaphore,
    /// Where each stream the host takes is forwarded.
    forwarded: mpsc::UnboundedSender<DataStream>,
    /// The connection's registry, sent to the case once the host has the session.
    registry: std::sync::Mutex<Option<oneshot::Sender<Arc<StreamRegistry>>>>,
    /// Said once the host has dropped the receiver, for [`Taking::Never`].
    dropped: Notify,
    receiver_dropped: std::sync::atomic::AtomicBool,
}

impl PairedDirectory for ChunkHost {
    fn paired_peer(&self, endpoint_id: &EndpointKey) -> Option<PairedPeer> {
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

    fn serve(self: Arc<Self>, mut session: AuthorisedSession) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            if let Some(sender) = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                let _ = sender.send(Arc::clone(&session.streams));
            }
            match self.taking {
                Taking::Never => {
                    drop(session.data_streams);
                    self.receiver_dropped
                        .store(true, std::sync::atomic::Ordering::Release);
                    self.dropped.notify_waiters();
                    while session.control.recv().await.is_some() {}
                }
                Taking::Forward | Taking::AfterTheGate => {
                    let mut admitted = session.data_streams;
                    let host = Arc::clone(&self);
                    let forwarding = tokio::spawn(async move {
                        if host.taking == Taking::AfterTheGate {
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
    /// The host's registry for the connection.
    registry: Arc<StreamRegistry>,
    /// The device's own registry, which opens streams with a proper header.
    device: Arc<StreamRegistry>,
    _sides: (Side, Side),
}

impl Harness {
    async fn start(accepted: &[StreamKind], taking: Taking) -> Self {
        let (host_side, client) = paired_pair().await;
        let (forwarded, admitted) = mpsc::unbounded_channel();
        let (registry_tx, registry_rx) = oneshot::channel();
        let host = Arc::new(ChunkHost {
            client: client.record,
            taking,
            gate: Semaphore::new(0),
            forwarded,
            registry: std::sync::Mutex::new(Some(registry_tx)),
            dropped: Notify::new(),
            receiver_dropped: std::sync::atomic::AtomicBool::new(false),
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
        let authorised = handshake::connect(&connection, &client.identity, &host_side.record)
            .await
            .expect("an authorised connection");
        let registry = awaited("the host's session", registry_rx)
            .await
            .expect("the host sent its registry");
        let device = Arc::new(StreamRegistry::with_limits(
            authorised.connection_id,
            Arc::new(StreamBudget::new(SendLimits::default())),
            None,
            authorised.selection.limits,
        ));
        Self {
            listener,
            connection,
            authorised,
            deadlines,
            host,
            admitted,
            registry,
            device,
            _sides: (host_side, client),
        }
    }

    /// Opens a stream the way a device does, header first, and returns its two raw halves.
    async fn raw(&self, header: &StreamHeader) -> (SendStream, RecvStream) {
        let (mut send, recv) = self.connection.open_bi().await.expect("a stream");
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

/// Writes the header's length and the first `bytes` of its encoding, or all of it.
async fn write_header(send: &mut SendStream, header: &StreamHeader, bytes: Option<usize>) {
    let encoded = header.encode().expect("an encoded header");
    let length = u32::try_from(encoded.len()).expect("a header fits a length");
    send.write_all(&length.to_be_bytes())
        .await
        .expect("a header length");
    let sent = bytes.map_or(encoded.len(), |bytes| bytes.min(encoded.len()));
    send.write_all(&encoded[..sent])
        .await
        .expect("the header's bytes");
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
    let mut byte = [0u8; 4096];
    loop {
        match awaited("the host's reset of the stream", recv.read(&mut byte)).await {
            Err(ReadError::Reset(code)) => return code.into_inner(),
            Ok(Some(_)) => {}
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

/// KR-REQ-23.12: a stream whose header is half sent holds no one back. The listener reads each
/// header on a task of its own, so the stream behind it is taken and handed to the host while the
/// first still waits, and when the header deadline passes the first is reset with nothing admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_with_half_a_header_does_not_hold_back_the_next_one() {
    let mut harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Forward).await;
    let connection_id = harness.authorised.connection_id;

    // The first stream names a header and sends half of it, and stays open.
    let (mut half_send, mut half_recv) = harness.connection.open_bi().await.expect("a stream");
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

/// KR-REQ-23.12: a stream the host does not take is reset, and the next one is taken as usual: a
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

/// KR-REQ-23.12: a host that is not taking streams costs nothing. A stream that finds the queue full
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

/// KR-REQ-23.12: a host that is gone from its queue costs nothing either: the stream is reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_for_a_host_that_dropped_its_receiver_is_reset() {
    let harness = Harness::start(&[StreamKind::AttachmentChunks], Taking::Never).await;
    awaited("the host dropping its receiver", async {
        while !harness
            .host
            .receiver_dropped
            .load(std::sync::atomic::Ordering::Acquire)
        {
            harness.host.dropped.notified().await;
        }
    })
    .await;

    let (_send, mut recv) = harness
        .raw(&attachment_header(harness.authorised.connection_id, 1))
        .await;
    assert_eq!(reset_code(&mut recv).await, u64::from(STREAM_REVOKED));
    assert_eq!(
        harness.registry.len(),
        0,
        "a stream nobody took stayed registered"
    );
    assert_eq!(harness.registry.budget().open_bulk_streams(), 0);

    harness.finish().await;
}

/// KR-REQ-23.12: a frame that stops arriving is cut by the stall deadline. The device sends a
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
    assert!(
        matches!(
            send.write_all(&[0u8; 8]).await,
            Err(WriteError::Stopped(code)) if code.into_inner() == u64::from(STREAM_REVOKED)
        ),
        "the device could still write to a stream the host cut"
    );

    harness.finish().await;
}

/// KR-REQ-23.12: a stream that is quiet between frames is cut by the idle deadline, and the device
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

/// KR-REQ-23.12: a device that never reads its answers cannot hold the stream. A write that waits
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
                tokio::time::sleep(Duration::from_millis(5)).await;
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
    let (mut send, _recv) = connection.open_bi().await.expect("a stream");
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
