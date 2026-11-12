//! An upload's chunks on a paired host's data stream, against a scripted host over a real
//! connection.
//!
//! The host here plays the host's side of the form and nothing else: it answers `transfer.streams`,
//! `upload.begin`, `upload.status` and `upload.finish` on the control stream and
//! takes `attachment_chunks` streams, answering each chunk as its script says. What the cases check
//! is the client's half: it asks before it reserves, it sends nothing on a stream before the host
//! has said it takes one, every chunk goes on a stream with the connection's window and a request
//! identifier of the session's counter, and a lane that fails, is refused or is cut at the client's
//! own bound is replaced after a read of `upload.status`, which alone decides what is sent next.

use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr};
use kr_client::chunks::ChunkRoute;
use kr_client::error::ClientError;
use kr_client::session::Session;
use kr_client::transport::{ControlTransport, NetworkTransport, StreamOpener, TransportFuture};
use kr_client::uploads::{self, Held, Progress, Stage, Subject, Upload};
use kr_crypto::connect::{ChallengeLedger, PairedPeer};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::{
    ActionTarget, ControlEvent, ControlFrame, Outcome, ParamsValue, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{StreamHeader, StreamKind};
use kr_protocol::hello::{ActionWindow, ReceiveLimits};
use kr_protocol::ids::{
    ActionWindowId, BootEpoch, BuildId, ClockEpoch, ConnectionId, DeviceId, DeviceKeyRevision,
    EnvironmentId, RequestId, TransferId,
};
use kr_protocol::limits::UPLOAD_CHUNK_LEN;
use kr_protocol::method::{Method, MethodName};
use kr_protocol::scalars::{
    Bytes, Digest256, DurationMs, EndpointKey, Nullable, TimestampMs, U64, Uuid,
};
use kr_protocol::transfer::{
    AttachmentHandle, ChunkBitmap, ChunkLayout, TransferStreamsResult, UploadBeginParams,
    UploadBeginResult, UploadChunkParams, UploadChunkResult, UploadFinishParams,
    UploadFinishResult, UploadState, UploadStatusParams, UploadStatusResult,
};
use kr_transport::TransportError;
use kr_transport::clock::{ContinuousClock, ManualClock};
use kr_transport::config::EndpointConfig;
use kr_transport::deadlines::{DeadlineKind, ManualDeadlines};
use kr_transport::handshake::{self, Admitted, HostEpochs, LocalIdentity, PairedDirectory};
use kr_transport::scheduler::{SendLimits, StreamBudget};
use kr_transport::streams::{DataStream, StreamRegistry};
use kr_transport::window::{ActionWindowIssuer, MAX_WINDOW_VALIDITY};

/// How long a case waits for the host to see something that must happen: it fails a wait that
/// never ends, and is not a measurement.
const LIVENESS: Duration = Duration::from_secs(60);

const TTL: DurationMs = DurationMs::new(60_000);

/// A file of two full chunks and a remainder.
const THREE_CHUNKS: usize = 2 * UPLOAD_CHUNK_LEN + 100;

fn environment() -> EnvironmentId {
    EnvironmentId::new(Uuid::from_bytes([7; 16]))
}

fn target() -> ActionTarget {
    ActionTarget::environment(environment())
}

fn window_id(name: &str) -> ActionWindowId {
    ActionWindowId::new(name).expect("a window identifier")
}

fn bytes_of(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from((index * 7 + index / UPLOAD_CHUNK_LEN) % 251).unwrap_or(0))
        .collect()
}

/// Waits for `future`, which a case fails if it never ends: a wait that never ends measures nothing.
async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIVENESS, future)
        .await
        .expect("the call ended in time")
}

/// Polls a call once and says whether it is still waiting. A lane's call chooses its window before
/// it does anything else on the network, so one poll takes it to the wait for a window when the
/// host has issued none it can carry, and the case then knows where the lane stands without waiting
/// for it.
async fn waits<F: std::future::Future>(call: &mut std::pin::Pin<&mut F>) -> bool {
    std::future::poll_fn(|cx| std::task::Poll::Ready(call.as_mut().poll(cx).is_pending())).await
}

/// A progress channel nobody watches.
fn unwatched() -> tokio::sync::watch::Sender<Progress> {
    tokio::sync::watch::channel(Progress::default()).0
}

fn subject() -> Subject {
    Subject {
        environment_id: environment(),
        session_id: None,
        device_id: None,
        declared_media_type: "application/octet-stream".to_owned(),
        original_file_name: "capture.bin".to_owned(),
    }
}

fn plan(len: usize) -> Upload {
    Upload::new(subject(), Box::new(Held::new(bytes_of(len))))
}

/* ---------------------------------------------------------------------------------------- */
/* Two endpoints                                                                             */
/* ---------------------------------------------------------------------------------------- */

struct Side {
    identity: Arc<LocalIdentity>,
    endpoint: Endpoint,
    record: PairedPeer,
}

#[derive(Debug)]
struct OneDevice {
    endpoint_id: EndpointKey,
    record: PairedPeer,
}

impl PairedDirectory for OneDevice {
    fn paired_peer(&self, endpoint_id: &EndpointKey) -> Option<PairedPeer> {
        (endpoint_id == &self.endpoint_id).then_some(self.record)
    }
}

async fn side(device_byte: u8, listening: bool) -> Side {
    let config = EndpointConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
        ..EndpointConfig::default()
    };
    let keys = DeviceKeys::generate().expect("device keys");
    let endpoint = if listening {
        kr_transport::endpoint::bind_listener(&config, &keys.transport)
            .await
            .expect("a listening endpoint")
    } else {
        kr_transport::endpoint::bind_dialer(&config, &keys.transport)
            .await
            .expect("a dialling endpoint")
    };
    let device_id = DeviceId::new(Uuid::from_bytes([device_byte; 16]));
    let record = PairedPeer {
        device_id,
        device_key_revision: DeviceKeyRevision::new(1),
        authorisation: *keys.authorisation.public(),
        endpoint_id: *keys.transport.public(),
    };
    let identity = Arc::new(LocalIdentity::new(
        device_id,
        DeviceKeyRevision::new(1),
        *keys.transport.public(),
        keys.authorisation.clone(),
        BuildId::new("kr/0.1.0+test").expect("a build identity"),
    ));
    Side {
        identity,
        endpoint,
        record,
    }
}

fn direct_addr(side: &Side) -> EndpointAddr {
    let mut addr = EndpointAddr::new(side.endpoint.id());
    for socket in side.endpoint.bound_sockets() {
        addr = addr.with_ip_addr(socket);
    }
    addr
}

/* ---------------------------------------------------------------------------------------- */
/* The scripted host                                                                          */
/* ---------------------------------------------------------------------------------------- */

/// What the host does with the next chunk it reads.
enum Chunk {
    /// Stores it and answers.
    Answer,
    /// Answers with this refusal and stores nothing.
    Refuse(ErrorCode),
    /// Answers that it cannot say what became of the chunk, having stored it or not.
    Unknown { stored: bool },
    /// Reads it and never answers.
    Hold,
}

/// One chunk the host read.
#[derive(Clone, Debug)]
struct SeenChunk {
    stream: u64,
    index: u64,
    window: String,
    request_id: RequestId,
}

#[derive(Default)]
struct Seen {
    /// Streams whose header the host read, and each header.
    headers: Vec<StreamHeader>,
    /// Streams of those whose host side has ended, however it ended: the client finished it or
    /// reset it, or the host's idle bound reset it.
    ended_streams: u64,
    chunks: Vec<SeenChunk>,
    stored: BTreeSet<u64>,
    begins: u64,
    finishes: u64,
    status_reads: u64,
    /// The request identifiers of every request and mutation read on the control stream.
    control_ids: Vec<RequestId>,
    /// Chunks read on the control stream, which must be none.
    control_chunks: u64,
    transfer: Option<TransferId>,
    layout: Option<ChunkLayout>,
}

/// What the host answers, and what it saw.
struct Script {
    /// Whether the host raises the connection's stream limit, which is the credit a device needs to
    /// open a stream.
    grants_credit: bool,
    streams: Mutex<Result<Vec<StreamKind>, ProtocolError>>,
    /// The state `upload.status` reports.
    state: Mutex<UploadState>,
    /// Resets every stream after reading its header.
    refuses_streams: AtomicBool,
    /// Answers the next `upload.finish` that the outcome is not known, though it publishes: once.
    finish_unknown_once: AtomicBool,
    chunks: Mutex<VecDeque<Chunk>>,
    /// A chunk under this window is refused as one that has expired.
    ended_window: Mutex<Option<ActionWindowId>>,
    seen: Mutex<Seen>,
    changed: tokio::sync::Notify,
    /// Counts the times the host's idle bound has passed: a stream that stands idle at one is reset.
    idle: tokio::sync::watch::Sender<u64>,
    renewals: tokio::sync::mpsc::UnboundedSender<ActionWindow>,
    pending_renewals: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<ActionWindow>>>,
}

impl Script {
    fn new(grants_credit: bool) -> Arc<Self> {
        let (renewals, pending) = tokio::sync::mpsc::unbounded_channel();
        Arc::new(Self {
            grants_credit,
            streams: Mutex::new(Ok(vec![StreamKind::AttachmentChunks])),
            state: Mutex::new(UploadState::Receiving),
            refuses_streams: AtomicBool::new(false),
            finish_unknown_once: AtomicBool::new(false),
            chunks: Mutex::new(VecDeque::new()),
            ended_window: Mutex::new(None),
            seen: Mutex::new(Seen::default()),
            changed: tokio::sync::Notify::new(),
            idle: tokio::sync::watch::channel(0).0,
            renewals,
            pending_renewals: Mutex::new(Some(pending)),
        })
    }

    fn seen<T>(&self, read: impl FnOnce(&Seen) -> T) -> T {
        read(&self.seen.lock().expect("what the host saw"))
    }

    fn record(&self, write: impl FnOnce(&mut Seen)) {
        write(&mut self.seen.lock().expect("what the host saw"));
        self.changed.notify_waiters();
    }

    /// Waits until what the host saw satisfies `condition`, which is a condition of the host's
    /// state and never of a time.
    async fn until(&self, what: &str, condition: impl Fn(&Seen) -> bool) {
        tokio::time::timeout(LIVENESS, async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.seen(&condition) {
                    return;
                }
                changed.await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the host never saw {what}"));
    }

    /// Waits until the host side of every stream whose header it read has ended. After the idle
    /// bound has passed, that is the host's acknowledgement that it reset each stream that stood
    /// idle, so a case that renews a window next knows the reset came first.
    async fn until_every_stream_has_ended(&self) {
        self.until("the end of every stream the host read", |seen| {
            seen.ended_streams == seen.headers.len() as u64
        })
        .await;
    }

    /// The host's idle bound passes: every stream that waits for a frame at this moment is reset, as
    /// the host resets a stream that has stood idle for too long. The case says when it passes, by
    /// what the host has done and never by how long, so that no case waits for a time.
    fn idle_bound_passes(&self) {
        self.idle.send_modify(|passes| *passes += 1);
    }

    /// Makes the host take chunks of a file of `len` bytes, as it does once it has reserved one.
    fn reserved(&self, len: usize) {
        self.record(|seen| seen.layout = Some(ChunkLayout::for_length(len as u64)));
    }

    fn will(&self, next: Chunk) {
        self.chunks.lock().expect("the script").push_back(next);
    }

    fn renew_to(&self, id: &str, connection_id: ConnectionId) {
        let _ = self.renewals.send(ActionWindow {
            action_window_id: window_id(id),
            connection_id,
            boot_epoch: BootEpoch::new(1),
            issued_at_ms: TimestampMs::new(0),
            valid_for_ms: DurationMs::new(300_000),
        });
    }

    fn bitmap(&self) -> Bytes {
        let layout = self.seen(|seen| seen.layout).expect("a reserved upload");
        let mut bitmap = ChunkBitmap::empty(layout.chunk_count.get());
        for index in self.seen(|seen| seen.stored.clone()) {
            bitmap.insert(index);
        }
        bitmap.encode()
    }
}

fn typed<T: serde::Serialize>(value: &T) -> Result<ParamsValue, ProtocolError> {
    ParamsValue::from_typed(value)
        .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))
}

fn answer(request_id: RequestId, outcome: Result<ParamsValue, ProtocolError>) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: match outcome {
            Ok(value) => Outcome::Ok(value),
            Err(error) => Outcome::Error(error),
        },
    })
}

/// Serves connections: the control stream, and the data streams of each.
fn spawn_host(
    host: &Side,
    client_record: PairedPeer,
    script: Arc<Script>,
) -> tokio::task::JoinHandle<()> {
    let endpoint = host.endpoint.clone();
    let identity = Arc::clone(&host.identity);
    let directory: Arc<dyn PairedDirectory> = Arc::new(OneDevice {
        endpoint_id: client_record.endpoint_id,
        record: client_record,
    });
    tokio::spawn(async move {
        loop {
            let Some(incoming) = endpoint.accept().await else {
                return;
            };
            let Ok(connection) = incoming.await else {
                continue;
            };
            let identity = Arc::clone(&identity);
            let directory = Arc::clone(&directory);
            let script = Arc::clone(&script);
            tokio::spawn(async move {
                let clock: Arc<dyn ContinuousClock> = Arc::new(ManualClock::new());
                let issuer = Arc::new(ActionWindowIssuer::new(clock, MAX_WINDOW_VALIDITY));
                let challenges = Arc::new(std::sync::Mutex::new(ChallengeLedger::with_limit(16)));
                let Ok(Admitted::Authorised(authorised)) = handshake::accept(
                    &connection,
                    &identity,
                    HostEpochs {
                        boot_epoch: BootEpoch::new(1),
                        clock_epoch: ClockEpoch::new(1),
                    },
                    directory.as_ref(),
                    &challenges,
                    &issuer,
                )
                .await
                else {
                    return;
                };
                // A host that takes streams from a device gives it the credit to open them; one
                // that does not leaves the connection at the control stream alone.
                if script.grants_credit {
                    connection.set_max_concurrent_bi_streams(iroh::endpoint::VarInt::from_u32(16));
                    let streams = StreamRegistry::new(
                        authorised.connection_id,
                        Arc::new(StreamBudget::new(SendLimits::default())),
                        None,
                    );
                    let accepting = Arc::clone(&script);
                    let taken = connection.clone();
                    tokio::spawn(async move {
                        let mut number = 0_u64;
                        while let Ok(pending) = streams.accept_pending(&taken).await {
                            number += 1;
                            let script = Arc::clone(&accepting);
                            tokio::spawn(serve_stream(script, pending, number));
                        }
                    });
                }
                let mut reader = authorised.control_reader;
                let writer = Arc::new(tokio::sync::Mutex::new(authorised.control_writer));
                if let Some(mut renewals) =
                    script.pending_renewals.lock().expect("the script").take()
                {
                    let writer = Arc::clone(&writer);
                    tokio::spawn(async move {
                        while let Some(window) = renewals.recv().await {
                            let frame =
                                ControlFrame::Event(ControlEvent::ActionWindowRenewed(window));
                            if writer.lock().await.write_message(&frame).await.is_err() {
                                return;
                            }
                        }
                    });
                }
                loop {
                    let frame = match reader.read_message::<ControlFrame>().await {
                        Ok(Some(frame)) => frame,
                        _ => return,
                    };
                    let reply = control_reply(&script, frame);
                    if let Some(reply) = reply
                        && writer.lock().await.write_message(&reply).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    })
}

/// What the host says to one frame of the control stream.
fn control_reply(script: &Arc<Script>, frame: ControlFrame) -> Option<ControlFrame> {
    match frame {
        ControlFrame::Request(request) => {
            script.record(|seen| seen.control_ids.push(request.request_id));
            let outcome = match request.method.method() {
                Some(Method::TransferStreams) => match &*script.streams.lock().expect("the script")
                {
                    Ok(kinds) => typed(&TransferStreamsResult {
                        accepted_streams: kinds.clone(),
                    }),
                    Err(error) => Err(error.clone()),
                },
                Some(Method::UploadStatus) => {
                    script.record(|seen| seen.status_reads += 1);
                    let params: UploadStatusParams = request.params.to_typed().ok()?;
                    let state = *script.state.lock().expect("the script");
                    let layout = script.seen(|seen| seen.layout)?;
                    typed(&UploadStatusResult {
                        transfer_id: params.transfer_id,
                        environment_id: environment(),
                        state,
                        layout,
                        received_chunks: script.bitmap(),
                        received_byte_len: U64::new(0),
                        expires_at_ms: TimestampMs::new(1),
                        handle: Nullable::null(),
                        invalid_reason: Nullable::null(),
                    })
                }
                _ => Err(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    kr_transport::actor::METHOD_NOT_AVAILABLE,
                )),
            };
            Some(answer(request.request_id, outcome))
        }
        ControlFrame::Mutation(mutation) => {
            script.record(|seen| seen.control_ids.push(mutation.request_id));
            let outcome = match mutation.method.method() {
                Some(Method::UploadBegin) => {
                    let params: UploadBeginParams = mutation.params.to_typed().ok()?;
                    let transfer_id = TransferId::new(kr_ipc::new_uuid());
                    let layout = ChunkLayout::for_length(params.declared_byte_len.get());
                    script.record(|seen| {
                        seen.begins += 1;
                        seen.transfer = Some(transfer_id);
                        seen.layout = Some(layout);
                    });
                    typed(&UploadBeginResult {
                        transfer_id,
                        environment_id: environment(),
                        layout,
                        received_chunks: ChunkBitmap::empty(layout.chunk_count.get()).encode(),
                        expires_at_ms: TimestampMs::new(1),
                        staged_byte_len: U64::new(0),
                        staged_byte_limit: U64::new(1 << 30),
                    })
                }
                Some(Method::UploadFinish) => {
                    let params: UploadFinishParams = mutation.params.to_typed().ok()?;
                    let transfer_id = script.seen(|seen| seen.transfer)?;
                    script.record(|seen| seen.finishes += 1);
                    if script.finish_unknown_once.swap(false, Ordering::AcqRel) {
                        return Some(answer(
                            mutation.request_id,
                            Err(ProtocolError::new(
                                ErrorCode::OutcomeUnknown,
                                "the host cannot say what became of the finish",
                            )),
                        ));
                    }
                    typed(&UploadFinishResult {
                        handle: AttachmentHandle {
                            environment_id: environment(),
                            transfer_id,
                            session_id: Nullable::null(),
                            byte_len: params.declared_byte_len,
                            content_digest: params.declared_digest,
                            declared_media_type: "application/octet-stream".to_owned(),
                            original_file_name: "capture.bin".to_owned(),
                            preview: Nullable::null(),
                            presented_as_image: false,
                            published_at_ms: TimestampMs::new(1),
                            expires_at_ms: TimestampMs::new(2),
                            submitted: false,
                        },
                        already_published: false,
                        preview_unavailable: Nullable::null(),
                    })
                }
                Some(Method::UploadChunk) => {
                    script.record(|seen| seen.control_chunks += 1);
                    Err(ProtocolError::new(
                        ErrorCode::InvalidArgument,
                        "a chunk does not go on the control stream",
                    ))
                }
                _ => Err(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    kr_transport::actor::METHOD_NOT_AVAILABLE,
                )),
            };
            Some(answer(mutation.request_id, outcome))
        }
        _ => None,
    }
}

/// Takes one data stream: its header, and then a chunk at a time.
/// Records that the host's side of a stream whose header it read has ended, however it ended.
struct Ends(Arc<Script>);

impl Drop for Ends {
    fn drop(&mut self) {
        self.0.record(|seen| seen.ended_streams += 1);
    }
}

async fn serve_stream(
    script: Arc<Script>,
    pending: kr_transport::streams::PendingStream,
    number: u64,
) {
    let Ok(mut stream) = pending.open(&[StreamKind::AttachmentChunks]).await else {
        return;
    };
    // Watched before the header is recorded, so that a case that has seen the header and then lets
    // the idle bound pass is never missed.
    let mut idle = script.idle.subscribe();
    script.record(|seen| seen.headers.push(stream.header().clone()));
    let _ends = Ends(Arc::clone(&script));
    if script.refuses_streams.load(Ordering::Acquire) {
        stream.reset();
        return;
    }
    loop {
        let read = tokio::select! {
            read = stream.read_message::<ControlFrame>() => read,
            Ok(()) = idle.changed() => {
                stream.reset();
                return;
            }
        };
        let Ok(Some(ControlFrame::Mutation(mutation))) = read else {
            return;
        };
        let Ok(chunk) = mutation.params.to_typed::<UploadChunkParams>() else {
            return;
        };
        let index = chunk.chunk.index.get();
        script.record(|seen| {
            seen.chunks.push(SeenChunk {
                stream: number,
                index,
                window: mutation.action_window_id.to_string(),
                request_id: mutation.request_id,
            });
        });
        let ended = script
            .ended_window
            .lock()
            .expect("the script")
            .clone()
            .is_some_and(|ended| ended == mutation.action_window_id);
        let next = if ended {
            Chunk::Refuse(ErrorCode::PermissionDenied)
        } else {
            script
                .chunks
                .lock()
                .expect("the script")
                .pop_front()
                .unwrap_or(Chunk::Answer)
        };
        let outcome = match next {
            Chunk::Hold => {
                // Held until the client ends the stream, as a host that reads and does not answer
                // is: its side of the stream goes when the peer's reset reaches it.
                let _ = stream.read_message::<ControlFrame>().await;
                return;
            }
            Chunk::Refuse(code) => Err(ProtocolError::new(code, "refused")),
            Chunk::Unknown { stored } => {
                if stored {
                    script.record(|seen| {
                        seen.stored.insert(index);
                    });
                }
                Err(ProtocolError::new(
                    ErrorCode::OutcomeUnknown,
                    "the host cannot say what became of the chunk",
                ))
            }
            Chunk::Answer => {
                script.record(|seen| {
                    seen.stored.insert(index);
                });
                typed(&UploadChunkResult {
                    transfer_id: chunk.transfer_id,
                    index: chunk.chunk.index,
                    duplicate: false,
                    received_chunks: script.bitmap(),
                    received_byte_len: U64::new(0),
                })
            }
        };
        if stream
            .write_message(&answer(mutation.request_id, outcome))
            .await
            .is_err()
        {
            return;
        }
        // A pass of the idle bound counts only while the stream waits for a frame: one that came
        // while the host was busy with this chunk is not one.
        idle.borrow_and_update();
    }
}

/* ---------------------------------------------------------------------------------------- */
/* The client                                                                                 */
/* ---------------------------------------------------------------------------------------- */

/// A client with an authorised session, and the host it is connected to.
struct Pair {
    session: Session,
    script: Arc<Script>,
    _host: Side,
    _client: Side,
    serving: tokio::task::JoinHandle<()>,
}

impl Drop for Pair {
    fn drop(&mut self) {
        self.session.close();
        self.serving.abort();
    }
}

async fn pair(script: Arc<Script>) -> Pair {
    let (session, host, client, serving) = pair_over(script.clone(), |transport| {
        Ok(Arc::new(transport) as Arc<dyn ControlTransport>)
    })
    .await;
    Pair {
        session,
        script,
        _host: host,
        _client: client,
        serving,
    }
}

/// Connects a client to a scripted host, with the transport as `wrap` makes it.
async fn pair_over(
    script: Arc<Script>,
    wrap: impl FnOnce(NetworkTransport) -> Result<Arc<dyn ControlTransport>, ClientError>,
) -> (Session, Side, Side, tokio::task::JoinHandle<()>) {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let serving = spawn_host(&host, client.record, script);
    let transport = NetworkTransport::connect(
        &client.endpoint,
        direct_addr(&host),
        &client.identity,
        &host.record,
        SendLimits::default(),
    )
    .await
    .expect("an authorised connection");
    let transport = wrap(transport).expect("a transport");
    let session = Session::start(transport).expect("a session");
    (session, host, client, serving)
}

impl Pair {
    fn connection_id(&self) -> ConnectionId {
        self.session.transport().connection_id()
    }

    /// The chunks the host read, as (stream, index) in the order it read them.
    fn read_order(&self) -> Vec<(u64, u64)> {
        self.script
            .seen(|seen| seen.chunks.iter().map(|c| (c.stream, c.index)).collect())
    }
}

/// The reason a lane's open or call failed, as the error a caller reads.
fn deadline_of(error: &ClientError) -> Option<DeadlineKind> {
    match error {
        ClientError::Transport(TransportError::Deadline(kind)) => Some(*kind),
        _ => None,
    }
}

/* ---------------------------------------------------------------------------------------- */
/* Asking before anything is reserved                                                        */
/* ---------------------------------------------------------------------------------------- */

/// KR-REQ-23.21: a host that takes the stream is asked first, and then a whole upload goes on a
/// data stream of the connection: every chunk, none on the control stream, under request
/// identifiers that no control request shares and a header that names the connection and the
/// transfer.
#[tokio::test]
async fn an_upload_goes_on_a_stream_after_the_host_said_it_takes_one() {
    let pair = pair(Script::new(true)).await;
    let route = ChunkRoute::network(&pair.session, environment())
        .await
        .expect("a host that takes the stream gives a route");
    assert_eq!(
        pair.script.seen(|seen| seen.begins),
        0,
        "the probe reserves nothing"
    );
    let mut upload = plan(THREE_CHUNKS);
    let progress = unwatched();
    let handle = within(uploads::send(
        &pair.session,
        &route,
        &target(),
        &mut upload,
        TTL,
        &progress,
    ))
    .await
    .expect("the upload reaches a handle");
    assert_eq!(handle.byte_len.get(), THREE_CHUNKS as u64);

    let transfer = pair.script.seen(|seen| seen.transfer).expect("a transfer");
    pair.script.seen(|seen| {
        assert_eq!(
            seen.control_chunks, 0,
            "no chunk went on the control stream"
        );
        assert_eq!(seen.headers.len(), 1, "one stream carried the transfer");
        let header = &seen.headers[0];
        assert_eq!(header.kind, StreamKind::AttachmentChunks);
        assert_eq!(header.connection_id, pair.connection_id());
        assert_eq!(header.resource.environment_id, environment());
        assert_eq!(header.resource.transfer_id.0, Some(transfer));
        let order: Vec<u64> = seen.chunks.iter().map(|chunk| chunk.index).collect();
        assert_eq!(order, vec![0, 1, 2]);
        let mut ids: BTreeSet<RequestId> = seen.control_ids.iter().copied().collect();
        for chunk in &seen.chunks {
            assert!(
                ids.insert(chunk.request_id),
                "a chunk's request identifier is one the connection used before"
            );
        }
    });
    let told = *progress.borrow();
    assert_eq!(told.stage, Stage::Published);
    assert_eq!((told.acknowledged_chunks, told.chunks), (3, 3));
}

/// A host of an earlier build refuses `transfer.streams` as any method it does not list, and is
/// told to be updated; no reservation is made, no stream is opened, and the refusal raises nothing,
/// because a host too old for the method did not withdraw the connection.
#[tokio::test]
async fn a_host_of_an_earlier_build_is_told_to_update_before_anything_is_reserved() {
    let script = Script::new(true);
    *script.streams.lock().expect("the script") = Err(ProtocolError::new(
        ErrorCode::PermissionDenied,
        kr_transport::actor::METHOD_NOT_AVAILABLE,
    ));
    let pair = pair(script).await;
    let refused = ChunkRoute::network(&pair.session, environment())
        .await
        .err()
        .expect("the route is refused");
    assert_eq!(refused.code(), ErrorCode::UnsupportedCapability);
    assert!(refused.to_string().contains("update it"), "{refused}");
    pair.script.seen(|seen| {
        assert_eq!(seen.begins, 0);
        assert!(seen.headers.is_empty());
    });
    assert!(
        tokio::time::timeout(Duration::ZERO, pair.session.denied())
            .await
            .is_err(),
        "a host too old for the method did not withdraw the connection"
    );
}

/// An answer that lacks the stream is the same refusal; a refusal that is not the host's age is
/// returned as it is, and so is a permission refusal that does not say the method is unlisted.
#[tokio::test]
async fn only_an_answer_that_lacks_the_stream_or_an_unlisted_method_reads_as_the_hosts_age() {
    let script = Script::new(true);
    *script.streams.lock().expect("the script") = Ok(Vec::new());
    let pair = pair(Arc::clone(&script)).await;
    let refused = ChunkRoute::network(&pair.session, environment())
        .await
        .err()
        .expect("the route is refused");
    assert_eq!(refused.code(), ErrorCode::UnsupportedCapability);

    for (code, message) in [
        (ErrorCode::InvalidArgument, "the host does not take that"),
        (ErrorCode::PermissionDenied, "this device may not do that"),
    ] {
        *script.streams.lock().expect("the script") = Err(ProtocolError::new(code, message));
        let refused = ChunkRoute::network(&pair.session, environment())
            .await
            .err()
            .expect("the route is refused");
        assert_eq!(refused.code(), code, "{refused}");
        assert!(!refused.to_string().contains("update it"), "{refused}");
    }
    assert_eq!(pair.script.seen(|seen| seen.begins), 0);
}

/// A transport with no data streams, such as one to a host on this machine, is refused before the
/// host is asked anything, so its refusal never reads "update the host".
#[tokio::test]
async fn a_transport_with_no_data_streams_is_refused_before_the_probe() {
    #[derive(Debug)]
    struct Streamless(Arc<Mutex<u64>>);

    impl ControlTransport for Streamless {
        fn connection_id(&self) -> ConnectionId {
            ConnectionId::new(Uuid::from_bytes([9; 16]))
        }
        fn limits(&self) -> ReceiveLimits {
            ReceiveLimits::default()
        }
        fn initial_action_window(&self) -> ActionWindow {
            ActionWindow {
                action_window_id: window_id("window-1"),
                connection_id: self.connection_id(),
                boot_epoch: BootEpoch::new(1),
                issued_at_ms: TimestampMs::new(0),
                valid_for_ms: DurationMs::new(60_000),
            }
        }
        fn ended_by_this_device(&self) -> Option<ProtocolError> {
            None
        }
        fn send<'a>(&'a self, _: &'a ControlFrame) -> TransportFuture<'a, ()> {
            *self.0.lock().expect("the count") += 1;
            Box::pin(async { Ok(()) })
        }
        fn claim_receiver(&self) -> kr_client::Result<()> {
            Ok(())
        }
        fn stream_opener(&self) -> Option<Arc<dyn StreamOpener>> {
            None
        }
        fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
            Box::pin(std::future::pending())
        }
        fn revoke_streams(&self) {}
        fn close(&self) {}
    }

    let sent = Arc::new(Mutex::new(0));
    let session = Session::start(Arc::new(Streamless(Arc::clone(&sent)))).expect("a session");
    let refused = ChunkRoute::network(&session, environment())
        .await
        .err()
        .expect("the route is refused");
    assert_eq!(refused.code(), ErrorCode::InvalidArgument);
    assert!(!refused.to_string().contains("update"), "{refused}");
    assert_eq!(*sent.lock().expect("the count"), 0, "nothing was asked");
    session.close();
}

/* ---------------------------------------------------------------------------------------- */
/* A lane that fails                                                                          */
/* ---------------------------------------------------------------------------------------- */

/// KR-REQ-23.21: the client ends a stream after chunk 1. The driver reads `upload.status` and sends
/// exactly the rest, on a new stream, under the one transfer.
#[tokio::test]
async fn a_stream_the_client_reset_is_replaced_and_only_the_rest_is_sent() {
    let pair = pair(Script::new(true)).await;
    let route = ChunkRoute::network(&pair.session, environment())
        .await
        .expect("a route")
        .resetting_first_lane_after(1);
    let mut upload = plan(THREE_CHUNKS);
    let handle = within(uploads::send(
        &pair.session,
        &route,
        &target(),
        &mut upload,
        TTL,
        &unwatched(),
    ))
    .await
    .expect("the upload reaches a handle");
    assert_eq!(handle.byte_len.get(), THREE_CHUNKS as u64);
    assert_eq!(
        pair.read_order(),
        vec![(1, 0), (2, 1), (2, 2)],
        "the first stream carried chunk 0 and the second exactly the rest"
    );
    pair.script.seen(|seen| {
        assert_eq!(seen.begins, 1, "one transfer");
        assert_eq!(
            seen.status_reads, 1,
            "the host's record decided what was sent"
        );
        let transfers: BTreeSet<_> = seen
            .headers
            .iter()
            .map(|header| header.resource.transfer_id.0)
            .collect();
        assert_eq!(transfers.len(), 1, "both streams name the one transfer");
    });
}

/// The host refused a chunk's window before its replacement reached the client: the host issues the
/// replacement right after, and the chunk goes again under it and not under the refused one.
#[tokio::test]
async fn a_window_the_host_refused_is_replaced_by_one_it_issued_since() {
    let script = Script::new(true);
    let pair = pair(Arc::clone(&script)).await;
    let refused = pair.session.action_window().await.action_window_id;
    *script.ended_window.lock().expect("the script") = Some(refused.clone());
    let route = ChunkRoute::network(&pair.session, environment())
        .await
        .expect("a route");
    let mut upload = plan(THREE_CHUNKS);
    let at = target();
    let progress = unwatched();
    let sending = uploads::send(&pair.session, &route, &at, &mut upload, TTL, &progress);
    let renewing = async {
        script
            .until("a chunk under the first window", |seen| {
                !seen.chunks.is_empty()
            })
            .await;
        script.renew_to("replacement", pair.connection_id());
    };
    let (sent, ()) = tokio::join!(within(sending), renewing);
    sent.expect("the upload reaches a handle");
    script.seen(|seen| {
        let under_refused = seen
            .chunks
            .iter()
            .filter(|chunk| chunk.window == refused.as_str())
            .count();
        assert_eq!(under_refused, 1, "the refused window was carried once");
        assert!(
            seen.chunks[1..]
                .iter()
                .all(|chunk| chunk.window == "replacement")
        );
        assert_eq!(seen.stored, BTreeSet::from([0, 1, 2]));
    });
}

/// KR-REQ-23.21: the refused window's marker survives the lane's replacement. The host refuses a
/// window and the driver drops the lane; the replacement lane, with the same window still the
/// newest and the host's next one withheld, does not send it again: it waits, and carries the
/// window the host issues once the case lets it.
#[tokio::test]
async fn the_refused_windows_marker_survives_the_lanes_replacement() {
    let script = Script::new(true);
    script.reserved(64);
    let pair = pair(Arc::clone(&script)).await;
    let refused = pair.session.action_window().await.action_window_id;
    *script.ended_window.lock().expect("the script") = Some(refused.clone());
    let route = ChunkRoute::network(&pair.session, environment())
        .await
        .expect("a route");
    let transfer = TransferId::new(Uuid::from_bytes([8; 16]));
    let chunk = some_chunk(transfer);
    let at = target();
    let mut first = within(route.open(transfer)).await.expect("a lane");
    let turned_down = within(first.send_chunk(&at, &chunk, TTL))
        .await
        .expect_err("the host refuses the window");
    assert_eq!(turned_down.code(), ErrorCode::PermissionDenied);
    drop(first);

    // The replacement lane has the refused window newest and has been told the host turned it
    // down. One poll takes its call as far as it goes: if the lane did not wait for another
    // window it would have chosen the refused one by now.
    let mut second = within(route.open(transfer)).await.expect("a lane");
    let mut sending = std::pin::pin!(second.send_chunk(&at, &chunk, TTL));
    assert!(
        waits(&mut sending).await,
        "the replacement lane waits for a window the host has not issued"
    );
    script.renew_to("replacement", pair.connection_id());
    within(sending)
        .await
        .expect("the replacement window is carried");
    script.seen(|seen| {
        let windows: Vec<&str> = seen
            .chunks
            .iter()
            .map(|chunk| chunk.window.as_str())
            .collect();
        assert_eq!(windows, vec![refused.as_str(), "replacement"]);
    });
}

/// KR-REQ-23.21: a lane that waits for a window holds no stream. The wait can last as long as a
/// window's validity, and the host resets a stream that stands idle for a much shorter time, so a
/// stream opened before the wait is dead when the chunk goes on it and the chunk costs a retry. The
/// lane has its window first and opens its stream for the chunk. The case lets the host's idle
/// bound pass during the wait, once the host has read the header of every stream the client has
/// opened, and renews the window once the host has ended every stream it read, so that a stream
/// the lane held would be reset by then; the chunk goes on a stream the bound did not reach.
#[tokio::test]
async fn a_lane_that_waits_for_a_window_holds_no_stream_for_the_host_to_reset() {
    let script = Script::new(true);
    script.reserved(64);
    let opened = Arc::new(AtomicU64::new(0));
    let count = Arc::clone(&opened);
    let (session, _host, _client, serving) = pair_over(Arc::clone(&script), move |transport| {
        Ok(Arc::new(Counted {
            inner: Arc::new(transport),
            opened: count,
        }) as Arc<dyn ControlTransport>)
    })
    .await;
    let refused = session.action_window().await.action_window_id;
    *script.ended_window.lock().expect("the script") = Some(refused.clone());
    let route = ChunkRoute::network(&session, environment())
        .await
        .expect("a route");
    let transfer = TransferId::new(Uuid::from_bytes([9; 16]));
    let chunk = some_chunk(transfer);
    let at = target();
    let mut first = within(route.open(transfer)).await.expect("a lane");
    let turned_down = within(first.send_chunk(&at, &chunk, TTL))
        .await
        .expect_err("the host refuses the window");
    assert_eq!(turned_down.code(), ErrorCode::PermissionDenied);
    drop(first);

    let mut second = within(route.open(transfer)).await.expect("a lane");
    let mut sending = std::pin::pin!(second.send_chunk(&at, &chunk, TTL));
    assert!(
        waits(&mut sending).await,
        "the replacement lane waits for a window the host has not issued"
    );
    script
        .until("the header of every stream the client opened", |seen| {
            seen.headers.len() as u64 == opened.load(Ordering::Acquire)
        })
        .await;
    script.idle_bound_passes();
    script.until_every_stream_has_ended().await;
    script.renew_to("replacement", session.transport().connection_id());
    within(sending)
        .await
        .expect("the chunk goes under the new window, on a stream the bound did not reach");
    script.seen(|seen| {
        let windows: Vec<&str> = seen
            .chunks
            .iter()
            .map(|chunk| chunk.window.as_str())
            .collect();
        assert_eq!(windows, vec![refused.as_str(), "replacement"]);
        assert_eq!(seen.stored, BTreeSet::from([0]));
    });
    session.close();
    serving.abort();
}

/// KR-REQ-23.21: a lane that has carried a chunk gives up its stream before it waits for its next
/// window. Two uploads share one route and so one window: the first lane carries a chunk and holds
/// its stream; the second lane is refused the shared window; the first lane's next call then waits
/// for a window the host has not issued. The host's idle bound passes during the wait, and the
/// case goes on once the host has ended every stream it read, so a stream the lane still held
/// would be dead. The chunk goes on a new stream, under the new window, with nothing retried.
#[tokio::test]
async fn a_lane_that_carried_a_chunk_gives_up_its_stream_before_it_waits_for_a_window() {
    let script = Script::new(true);
    script.reserved(64);
    let opened = Arc::new(AtomicU64::new(0));
    let count = Arc::clone(&opened);
    let (session, _host, _client, serving) = pair_over(Arc::clone(&script), move |transport| {
        Ok(Arc::new(Counted {
            inner: Arc::new(transport),
            opened: count,
        }) as Arc<dyn ControlTransport>)
    })
    .await;
    let shared = session.action_window().await.action_window_id;
    let route = ChunkRoute::network(&session, environment())
        .await
        .expect("a route");
    let first_transfer = TransferId::new(Uuid::from_bytes([10; 16]));
    let second_transfer = TransferId::new(Uuid::from_bytes([11; 16]));
    let at = target();

    let mut first = within(route.open(first_transfer)).await.expect("a lane");
    within(first.send_chunk(&at, &some_chunk(first_transfer), TTL))
        .await
        .expect("the first lane carries a chunk and holds its stream");
    *script.ended_window.lock().expect("the script") = Some(shared.clone());
    let mut second = within(route.open(second_transfer)).await.expect("a lane");
    let turned_down = within(second.send_chunk(&at, &some_chunk(second_transfer), TTL))
        .await
        .expect_err("the host refuses the shared window");
    assert_eq!(turned_down.code(), ErrorCode::PermissionDenied);
    drop(second);

    let chunk = some_chunk(first_transfer);
    let mut next = std::pin::pin!(first.send_chunk(&at, &chunk, TTL));
    assert!(
        waits(&mut next).await,
        "the first lane waits for a window the host has not issued"
    );
    script
        .until("the header of every stream the client opened", |seen| {
            seen.headers.len() as u64 == opened.load(Ordering::Acquire)
        })
        .await;
    script.idle_bound_passes();
    script.until_every_stream_has_ended().await;
    script.renew_to("replacement", session.transport().connection_id());
    within(next)
        .await
        .expect("the chunk goes under the new window, on a stream the bound did not reach");
    assert_eq!(
        opened.load(Ordering::Acquire),
        3,
        "the first lane opened a second stream for its second chunk"
    );
    script.seen(|seen| {
        let windows: Vec<&str> = seen
            .chunks
            .iter()
            .map(|chunk| chunk.window.as_str())
            .collect();
        assert_eq!(
            windows,
            vec![shared.as_str(), shared.as_str(), "replacement"]
        );
        assert_ne!(
            seen.chunks[0].stream, seen.chunks[2].stream,
            "the second chunk of the first lane is on a new stream"
        );
    });
    session.close();
    serving.abort();
}

/// The host takes a chunk and never answers: the lane ends at the client's own bound, which the
/// case fires by what the lane waits for, and the driver reads `upload.status` and sends the chunk
/// again on a new stream.
#[tokio::test]
async fn a_host_that_holds_a_chunk_ends_the_lane_at_the_clients_bound() {
    let script = Script::new(true);
    script.will(Chunk::Hold);
    let pair = pair(Arc::clone(&script)).await;
    let bounds = ManualDeadlines::new();
    let route = ChunkRoute::network(&pair.session, environment())
        .await
        .expect("a route")
        .bounded_by(bounds.clone());
    let mut upload = plan(UPLOAD_CHUNK_LEN);
    let at = target();
    let progress = unwatched();
    let sending = uploads::send(&pair.session, &route, &at, &mut upload, TTL, &progress);
    // The wait for the answer is cut once the host holds the chunk: a chunk the host has not read
    // yet is not one it holds.
    let cutting = async {
        script
            .until("the held chunk", |seen| !seen.chunks.is_empty())
            .await;
        bounds.fire_when_armed(DeadlineKind::Idle).await;
    };
    let (sent, ()) = tokio::time::timeout(LIVENESS, async { tokio::join!(sending, cutting) })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the upload never ended: the host read {:?} on {} streams, {} status reads",
                pair.read_order(),
                pair.script.seen(|seen| seen.headers.len()),
                pair.script.seen(|seen| seen.status_reads)
            )
        });
    sent.expect("the chunk goes again on a new stream and the upload reaches a handle");
    assert_eq!(pair.read_order(), vec![(1, 0), (2, 0)]);
    assert!(pair.script.seen(|seen| seen.status_reads) >= 1);
}

/// A host that gives no stream credit ends the open, which is a lane's first call, at the client's
/// own bound, and the bulk slot the open held comes back: the fifth open, past the connection's four
/// slots, is cut by its bound too and is not refused for want of a slot.
#[tokio::test]
async fn a_host_that_gives_no_stream_credit_ends_the_open_and_returns_its_slot() {
    let pair = pair(Script::new(false)).await;
    let bounds = ManualDeadlines::new();
    let route = ChunkRoute::network(&pair.session, environment())
        .await
        .expect("a route")
        .bounded_by(bounds.clone());
    let transfer = TransferId::new(Uuid::from_bytes([3; 16]));
    let chunk = some_chunk(transfer);
    let at = target();
    for attempt in 1..=5 {
        let mut lane = within(route.open(transfer)).await.expect("a lane");
        let opening = lane.send_chunk(&at, &chunk, TTL);
        let cutting = bounds.fire_when_armed(DeadlineKind::Header);
        let (opened, ()) = within(async { tokio::join!(opening, cutting) }).await;
        let error = opened.expect_err("the open is cut");
        assert_eq!(
            deadline_of(&error),
            Some(DeadlineKind::Header),
            "attempt {attempt}: {error}"
        );
        assert_eq!(error.code(), ErrorCode::ResourceUnavailable);
    }
}

/// A chunk for a lane, of a transfer the scripted host does not check.
fn some_chunk(transfer: TransferId) -> UploadChunkParams {
    let bytes = bytes_of(64);
    UploadChunkParams {
        transfer_id: transfer,
        chunk: kr_protocol::transfer::ChunkDescriptor {
            index: U64::new(0),
            byte_len: U64::new(bytes.len() as u64),
            digest: Digest256::from_bytes(kr_cbor::sha256(&bytes)),
        },
        bytes: Bytes::new(bytes),
    }
}

/// A lane the client's bound ended gives its stream and its bulk slot back at once, though the
/// caller keeps the lane: five lanes in a row end at the bound and are all kept, and the fifth open,
/// past the connection's four slots, is not refused for want of one.
#[tokio::test]
async fn a_lane_the_bound_ended_gives_its_slot_back_while_the_caller_keeps_it() {
    let script = Script::new(true);
    let pair = pair(Arc::clone(&script)).await;
    let bounds = ManualDeadlines::new();
    let route = ChunkRoute::network(&pair.session, environment())
        .await
        .expect("a route")
        .bounded_by(bounds.clone());
    let transfer = TransferId::new(Uuid::from_bytes([4; 16]));
    let chunk = some_chunk(transfer);
    let at = target();
    let mut kept = Vec::new();
    for attempt in 1..=5 {
        script.will(Chunk::Hold);
        let mut lane = within(route.open(transfer))
            .await
            .unwrap_or_else(|error| panic!("attempt {attempt}: the open was refused: {error}"));
        let sending = lane.send_chunk(&at, &chunk, TTL);
        let cutting = async {
            script
                .until("the held chunk", |seen| seen.chunks.len() == attempt)
                .await;
            bounds.fire_when_armed(DeadlineKind::Idle).await;
        };
        let (sent, ()) = within(async { tokio::join!(sending, cutting) }).await;
        let error = sent.expect_err("the held chunk is cut");
        assert_eq!(deadline_of(&error), Some(DeadlineKind::Idle), "{error}");
        kept.push(lane);
    }
    assert_eq!(kept.len(), 5);
}

/// A connection lost while a lane waits for a window ends the wait. The lane's one window was
/// refused and no other will come, so without the connection's end the wait would run to the
/// window's expiry.
#[tokio::test]
async fn a_lost_connection_ends_the_wait_for_a_window() {
    let script = Script::new(true);
    let pair = pair(Arc::clone(&script)).await;
    let refused = pair.session.action_window().await.action_window_id;
    *script.ended_window.lock().expect("the script") = Some(refused);
    let route = ChunkRoute::network(&pair.session, environment())
        .await
        .expect("a route");
    let transfer = TransferId::new(Uuid::from_bytes([5; 16]));
    let chunk = some_chunk(transfer);
    let at = target();
    let mut lane = within(route.open(transfer)).await.expect("a lane");
    let first = within(lane.send_chunk(&at, &chunk, TTL))
        .await
        .expect_err("the host refuses the window");
    assert_eq!(first.code(), ErrorCode::PermissionDenied);

    // The lane now waits: the window it holds is the one the host turned down.
    let waiting = lane.send_chunk(&at, &chunk, TTL);
    let closing = async {
        script
            .until("the first chunk", |seen| seen.chunks.len() == 1)
            .await;
        tokio::task::yield_now().await;
        pair.session.close();
    };
    let (second, ()) = within(async { tokio::join!(waiting, closing) }).await;
    let ended = second.expect_err("the wait ends with the connection");
    assert_eq!(ended.code(), ErrorCode::ResourceUnavailable, "{ended}");
    assert_eq!(
        script.seen(|seen| seen.chunks.len()),
        1,
        "the refused window was not carried again"
    );
}

/// A connection lost while a lane that has not opened its stream waits for a window ends the wait
/// as well: the lane has no stream to see revoked, and it learns of the loss from the connection.
#[tokio::test]
async fn a_lost_connection_ends_the_wait_of_a_lane_that_has_no_stream_yet() {
    let script = Script::new(true);
    let pair = pair(Arc::clone(&script)).await;
    let refused = pair.session.action_window().await.action_window_id;
    *script.ended_window.lock().expect("the script") = Some(refused);
    let route = ChunkRoute::network(&pair.session, environment())
        .await
        .expect("a route");
    let transfer = TransferId::new(Uuid::from_bytes([10; 16]));
    let chunk = some_chunk(transfer);
    let at = target();
    let mut first = within(route.open(transfer)).await.expect("a lane");
    let turned_down = within(first.send_chunk(&at, &chunk, TTL))
        .await
        .expect_err("the host refuses the window");
    assert_eq!(turned_down.code(), ErrorCode::PermissionDenied);
    drop(first);

    let mut second = within(route.open(transfer)).await.expect("a lane");
    let mut waiting = std::pin::pin!(second.send_chunk(&at, &chunk, TTL));
    assert!(
        waits(&mut waiting).await,
        "the replacement lane waits for a window the host has not issued"
    );
    pair.session.close();
    let ended = within(waiting)
        .await
        .expect_err("the wait ends with the connection");
    assert_eq!(ended.code(), ErrorCode::ResourceUnavailable, "{ended}");
    assert_eq!(
        script.seen(|seen| seen.chunks.len()),
        1,
        "the refused window was not carried again"
    );
}

/// A host that ended the upload while its lookup waited refuses the stream after its header. The
/// client reads that as a lane that failed: it reads `upload.status`, which says the upload expired,
/// and the upload ends with that, with no second stream opened.
#[tokio::test]
async fn a_stream_the_host_refuses_ends_in_the_status_and_is_not_opened_again() {
    let script = Script::new(true);
    script.refuses_streams.store(true, Ordering::Release);
    *script.state.lock().expect("the script") = UploadState::Expired;
    let pair = pair(Arc::clone(&script)).await;
    let route = ChunkRoute::network(&pair.session, environment())
        .await
        .expect("a route");
    let mut upload = plan(UPLOAD_CHUNK_LEN);
    let ended = within(uploads::send(
        &pair.session,
        &route,
        &target(),
        &mut upload,
        TTL,
        &unwatched(),
    ))
    .await
    .expect_err("an upload the host ended cannot go on");
    assert!(ended.to_string().contains("expired"), "{ended}");
    pair.script.seen(|seen| {
        assert_eq!(seen.headers.len(), 1, "the header was not sent again");
        assert_eq!(seen.status_reads, 1);
        assert!(seen.chunks.is_empty());
    });
}

/// A chunk the host cannot say what became of is neither sent nor unsent: the driver reads the
/// status and sends what the bitmap lacks. Where the host had stored it the chunk is not sent
/// again, and where it had not it is.
#[tokio::test]
async fn a_chunk_with_an_unknown_outcome_is_decided_by_the_status_alone() {
    for stored in [false, true] {
        let script = Script::new(true);
        script.will(Chunk::Unknown { stored });
        let pair = pair(Arc::clone(&script)).await;
        let route = ChunkRoute::network(&pair.session, environment())
            .await
            .expect("a route");
        let mut upload = plan(THREE_CHUNKS);
        within(uploads::send(
            &pair.session,
            &route,
            &target(),
            &mut upload,
            TTL,
            &unwatched(),
        ))
        .await
        .expect("the upload reaches a handle");
        let sent: Vec<u64> = pair
            .script
            .seen(|seen| seen.chunks.iter().map(|c| c.index).collect());
        let expected = if stored {
            vec![0, 1, 2]
        } else {
            vec![0, 0, 1, 2]
        };
        assert_eq!(sent, expected, "stored by the host: {stored}");
        assert_eq!(pair.script.seen(|seen| seen.status_reads), 1);
    }
}

/// A transport that counts the data streams opened through it, each once its header is written.
#[derive(Debug)]
struct Counted {
    inner: Arc<dyn ControlTransport>,
    opened: Arc<AtomicU64>,
}

#[derive(Debug)]
struct CountingOpener {
    inner: Arc<dyn StreamOpener>,
    opened: Arc<AtomicU64>,
}

impl StreamOpener for CountingOpener {
    fn open(&self, header: StreamHeader) -> TransportFuture<'_, DataStream> {
        Box::pin(async move {
            let stream = self.inner.open(header).await?;
            self.opened.fetch_add(1, Ordering::AcqRel);
            Ok(stream)
        })
    }

    fn revoked(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        self.inner.revoked()
    }
}

impl ControlTransport for Counted {
    fn connection_id(&self) -> ConnectionId {
        self.inner.connection_id()
    }
    fn limits(&self) -> ReceiveLimits {
        self.inner.limits()
    }
    fn initial_action_window(&self) -> ActionWindow {
        self.inner.initial_action_window()
    }
    fn ended_by_this_device(&self) -> Option<ProtocolError> {
        self.inner.ended_by_this_device()
    }
    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
        self.inner.send(frame)
    }
    fn claim_receiver(&self) -> kr_client::Result<()> {
        self.inner.claim_receiver()
    }
    fn stream_opener(&self) -> Option<Arc<dyn StreamOpener>> {
        Some(Arc::new(CountingOpener {
            inner: self.inner.stream_opener()?,
            opened: Arc::clone(&self.opened),
        }))
    }
    fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
        self.inner.recv()
    }
    fn revoke_streams(&self) {
        self.inner.revoke_streams();
    }
    fn close(&self) {
        self.inner.close();
    }
}

/// A transport whose account can be signed out: once the flag is set it says why this device ended
/// the connection, under the code the case chooses, and sends nothing more, as the companion's
/// bound transport does.
#[derive(Debug)]
struct Ending {
    inner: Arc<dyn ControlTransport>,
    ended: Arc<AtomicBool>,
    code: ErrorCode,
    /// The opener the transport gives out instead of the inner transport's, when a case sets one.
    opener: Option<Arc<dyn StreamOpener>>,
    /// The connection breaks as the client sends a request or a mutation of this method, in the
    /// way the case chooses; that send fails with the connection ended, and so does every later one.
    breaks_at: Option<(Method, Break)>,
    /// Set once the network has ended the connection.
    lost: AtomicBool,
    /// The `upload.status` reads the client tried to send, whether or not they went.
    status_sends: Arc<AtomicU64>,
}

/// How a connection breaks.
#[derive(Clone, Copy, Debug)]
enum Break {
    /// The account signs out: the reason is recorded, as a watcher that closes the connection does.
    SignOut,
    /// The network ends the connection: no reason of this device's is recorded.
    Loss,
}

impl ControlTransport for Ending {
    fn connection_id(&self) -> ConnectionId {
        self.inner.connection_id()
    }
    fn limits(&self) -> ReceiveLimits {
        self.inner.limits()
    }
    fn initial_action_window(&self) -> ActionWindow {
        self.inner.initial_action_window()
    }
    fn ended_by_this_device(&self) -> Option<ProtocolError> {
        self.ended
            .load(Ordering::Acquire)
            .then(|| ProtocolError::new(self.code, "the account signed out"))
    }
    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
        let called = match frame {
            ControlFrame::Request(request) => Some(&request.method),
            ControlFrame::Mutation(mutation) => Some(&mutation.method),
            _ => None,
        };
        if called == Some(&MethodName::from(Method::UploadStatus)) {
            self.status_sends.fetch_add(1, Ordering::AcqRel);
        }
        if let (Some(called), Some((method, kind))) = (called, self.breaks_at)
            && *called == MethodName::from(method)
        {
            match kind {
                Break::SignOut => self.ended.store(true, Ordering::Release),
                Break::Loss => self.lost.store(true, Ordering::Release),
            }
        }
        if self.lost.load(Ordering::Acquire) || self.ended.load(Ordering::Acquire) {
            return Box::pin(async { Err(ClientError::ConnectionEnded) });
        }
        self.inner.send(frame)
    }
    fn claim_receiver(&self) -> kr_client::Result<()> {
        self.inner.claim_receiver()
    }
    fn stream_opener(&self) -> Option<Arc<dyn StreamOpener>> {
        self.opener.clone().or_else(|| self.inner.stream_opener())
    }
    fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
        self.inner.recv()
    }
    fn revoke_streams(&self) {
        self.inner.revoke_streams();
    }
    fn close(&self) {
        self.inner.close();
    }
}

/// An opener whose open waits until a case lets it go and then fails, as an open does that a
/// sign-out cuts.
#[derive(Debug)]
struct CutOpener {
    gate: Arc<tokio::sync::Notify>,
}

impl StreamOpener for CutOpener {
    fn open(&self, _header: StreamHeader) -> TransportFuture<'_, DataStream> {
        Box::pin(async move {
            self.gate.notified().await;
            Err(ClientError::ConnectionEnded)
        })
    }

    fn revoked(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}

/// The lane asks the transport whether this device ended the connection before each chunk, so a
/// sign-in that ended after the lane opened stops the next chunk with the recorded reason.
#[tokio::test]
async fn a_lane_stops_when_the_transport_says_this_device_ended_the_connection() {
    let script = Script::new(true);
    let ended = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ended);
    let (session, _host, _client, serving) = pair_over(Arc::clone(&script), move |transport| {
        Ok(Arc::new(Ending {
            inner: Arc::new(transport),
            ended: flag,
            code: ErrorCode::LeaseLost,
            opener: None,
            breaks_at: None,
            lost: AtomicBool::new(false),
            status_sends: Arc::new(AtomicU64::new(0)),
        }) as Arc<dyn ControlTransport>)
    })
    .await;
    let route = ChunkRoute::network(&session, environment())
        .await
        .expect("a route");
    let mut upload = plan(THREE_CHUNKS);
    // Reserved by the driver's own first step, so the lane has a transfer to carry.
    let begun = session
        .mutate(
            Method::UploadBegin,
            target(),
            None,
            &serde_json::json!({}),
            &UploadBeginParams {
                environment_id: environment(),
                session_id: Nullable::null(),
                device_id: Nullable::null(),
                declared_byte_len: U64::new(THREE_CHUNKS as u64),
                declared_digest: Digest256::from_bytes(kr_cbor::sha256(&bytes_of(THREE_CHUNKS))),
                declared_media_type: "application/octet-stream".to_owned(),
                original_file_name: "capture.bin".to_owned(),
            },
            TTL,
        )
        .await
        .expect("the reservation");
    let begun: UploadBeginResult = begun.to_typed().expect("a reservation");
    upload
        .accept(uploads::Answer::Begun(Box::new(begun.clone())))
        .expect("the plan takes the reservation");
    let uploads::Step::Chunk(first) = upload.next().expect("a step") else {
        panic!("the first step is a chunk");
    };
    let mut lane = route.open(begun.transfer_id).await.expect("a lane");
    lane.send_chunk(&target(), &first, TTL)
        .await
        .expect("the first chunk goes");

    // The account watcher records the reason and closes the connection, which revokes its streams:
    // the lane is told the reason, and not that a stream was revoked.
    ended.store(true, Ordering::Release);
    session.transport().revoke_streams();
    upload
        .accept(uploads::Answer::Chunked(Box::new(UploadChunkResult {
            transfer_id: begun.transfer_id,
            index: first.chunk.index,
            duplicate: false,
            received_chunks: script.bitmap(),
            received_byte_len: U64::new(0),
        })))
        .expect("the plan takes the answer");
    let uploads::Step::Chunk(second) = upload.next().expect("a step") else {
        panic!("the next step is a chunk");
    };
    let stopped = lane
        .send_chunk(&target(), &second, TTL)
        .await
        .expect_err("the lane stops");
    assert_eq!(stopped.code(), ErrorCode::LeaseLost, "{stopped}");
    assert_eq!(
        script.seen(|seen| seen.chunks.len()),
        1,
        "the second chunk was never sent"
    );
    session.close();
    serving.abort();
}

/// A sign-out after the lane began to wait for a window: the account's watcher records the reason
/// and closes the connection, which revokes the lane's streams, and the lane is told the reason and
/// not that a stream was revoked.
#[tokio::test]
async fn a_sign_out_during_the_wait_for_a_window_is_told_with_its_reason() {
    let script = Script::new(true);
    let ended = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ended);
    let (session, _host, _client, serving) = pair_over(Arc::clone(&script), move |transport| {
        Ok(Arc::new(Ending {
            inner: Arc::new(transport),
            ended: flag,
            code: ErrorCode::LeaseLost,
            opener: None,
            breaks_at: None,
            lost: AtomicBool::new(false),
            status_sends: Arc::new(AtomicU64::new(0)),
        }) as Arc<dyn ControlTransport>)
    })
    .await;
    let refused = session.action_window().await.action_window_id;
    *script.ended_window.lock().expect("the script") = Some(refused);
    let route = ChunkRoute::network(&session, environment())
        .await
        .expect("a route");
    let transfer = TransferId::new(Uuid::from_bytes([6; 16]));
    let chunk = some_chunk(transfer);
    let at = target();
    let mut lane = within(route.open(transfer)).await.expect("a lane");
    let first = within(lane.send_chunk(&at, &chunk, TTL))
        .await
        .expect_err("the host refuses the window");
    assert_eq!(first.code(), ErrorCode::PermissionDenied);

    let waiting = lane.send_chunk(&at, &chunk, TTL);
    let signing_out = async {
        script
            .until("the first chunk", |seen| seen.chunks.len() == 1)
            .await;
        tokio::task::yield_now().await;
        ended.store(true, Ordering::Release);
        session.transport().revoke_streams();
    };
    let (second, ()) = within(async { tokio::join!(waiting, signing_out) }).await;
    let told = second.expect_err("the wait ends with the sign-out");
    assert_eq!(told.code(), ErrorCode::LeaseLost, "{told}");
    session.close();
    serving.abort();
}

/// A sign-out that ends the connection while the driver's lane waits for a window reaches the
/// caller of `uploads::send` as its reason. The companion's sign-out reasons carry the code a host
/// refuses an expired window with, so the driver must not read that code as a refused window: it
/// would retry, read the status on the connection that has ended, and tell the caller the
/// connection ended. Another upload's lane has the shared window refused first, so the driver's
/// first lane waits for a window the host has not issued.
#[tokio::test]
async fn a_sign_out_that_reads_as_a_refused_window_reaches_the_caller_of_send_as_its_reason() {
    let script = Script::new(true);
    let ended = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ended);
    let (session, _host, _client, serving) = pair_over(Arc::clone(&script), move |transport| {
        Ok(Arc::new(Ending {
            inner: Arc::new(transport),
            ended: flag,
            code: ErrorCode::PermissionDenied,
            opener: None,
            breaks_at: None,
            lost: AtomicBool::new(false),
            status_sends: Arc::new(AtomicU64::new(0)),
        }) as Arc<dyn ControlTransport>)
    })
    .await;
    let shared = session.action_window().await.action_window_id;
    *script.ended_window.lock().expect("the script") = Some(shared);
    let route = ChunkRoute::network(&session, environment())
        .await
        .expect("a route");
    let other = TransferId::new(Uuid::from_bytes([12; 16]));
    let at = target();
    let mut lane = within(route.open(other)).await.expect("a lane");
    let refused = within(lane.send_chunk(&at, &some_chunk(other), TTL))
        .await
        .expect_err("the host refuses the shared window");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    drop(lane);

    let mut upload = plan(THREE_CHUNKS);
    let progress = unwatched();
    let sending = uploads::send(&session, &route, &at, &mut upload, TTL, &progress);
    let signing_out = async {
        script
            .until("the reservation", |seen| seen.begins == 1)
            .await;
        ended.store(true, Ordering::Release);
        session.transport().revoke_streams();
    };
    let (sent, ()) = within(async { tokio::join!(sending, signing_out) }).await;
    let told = sent.expect_err("the upload ends with the sign-out");
    assert!(
        matches!(told, ClientError::Host(_)),
        "the caller is told the account's reason and not that the connection ended: {told}"
    );
    assert_eq!(told.code(), ErrorCode::PermissionDenied);
    session.close();
    serving.abort();
}

/// A sign-out that cuts the open of a lane's stream: the open fails with whatever the transport saw,
/// and the lane tells the caller the reason the account's watcher recorded, as it does for any other
/// way out.
#[tokio::test]
async fn a_sign_out_that_cuts_the_open_of_the_stream_is_told_with_its_reason() {
    let script = Script::new(true);
    let ended = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ended);
    let gate = Arc::new(tokio::sync::Notify::new());
    let cut = Arc::clone(&gate);
    let (session, _host, _client, serving) = pair_over(Arc::clone(&script), move |transport| {
        Ok(Arc::new(Ending {
            inner: Arc::new(transport),
            ended: flag,
            code: ErrorCode::LeaseLost,
            opener: Some(Arc::new(CutOpener { gate: cut })),
            breaks_at: None,
            lost: AtomicBool::new(false),
            status_sends: Arc::new(AtomicU64::new(0)),
        }) as Arc<dyn ControlTransport>)
    })
    .await;
    let route = ChunkRoute::network(&session, environment())
        .await
        .expect("a route");
    let transfer = TransferId::new(Uuid::from_bytes([13; 16]));
    let chunk = some_chunk(transfer);
    let at = target();
    let mut lane = within(route.open(transfer)).await.expect("a lane");
    let mut sending = std::pin::pin!(lane.send_chunk(&at, &chunk, TTL));
    assert!(
        waits(&mut sending).await,
        "the lane has its window and waits for the open"
    );
    ended.store(true, Ordering::Release);
    gate.notify_one();
    let told = within(sending).await.expect_err("the open is cut");
    assert_eq!(told.code(), ErrorCode::LeaseLost, "{told}");
    assert_eq!(script.seen(|seen| seen.chunks.len()), 0, "nothing was sent");
    session.close();
    serving.abort();
}

/// A network lane whose window ran out, because the host turned it down and issued none before it
/// would have expired, has ended: it says so, and the next call on it is refused as a call on an
/// ended lane. The lane's own reading of time is put past the window's validity, so the case waits for
/// no time.
#[tokio::test]
async fn a_window_that_runs_out_while_a_lane_waits_ends_the_lane() {
    let script = Script::new(true);
    script.reserved(64);
    let pair = pair(Arc::clone(&script)).await;
    let refused = pair.session.action_window().await.action_window_id;
    *script.ended_window.lock().expect("the script") = Some(refused);
    let route = ChunkRoute::network(&pair.session, environment())
        .await
        .expect("a route");
    let transfer = TransferId::new(Uuid::from_bytes([14; 16]));
    let chunk = some_chunk(transfer);
    let at = target();
    let mut first = within(route.open(transfer)).await.expect("a lane");
    let turned_down = within(first.send_chunk(&at, &chunk, TTL))
        .await
        .expect_err("the host refuses the window");
    assert_eq!(turned_down.code(), ErrorCode::PermissionDenied);
    drop(first);

    let mut second = within(route.open(transfer)).await.expect("a lane");
    second.hold_clock_at(Duration::from_secs(1_000));
    let ran_out = within(second.send_chunk(&at, &chunk, TTL))
        .await
        .expect_err("the window ran out before another came");
    assert!(matches!(ran_out, ClientError::NoActionWindow), "{ran_out}");
    let ended = within(second.send_chunk(&at, &chunk, TTL))
        .await
        .expect_err("the lane has ended");
    assert!(matches!(ended, ClientError::ConnectionEnded), "{ended}");
    assert_eq!(
        script.seen(|seen| seen.chunks.len()),
        1,
        "only the refused chunk was ever sent"
    );
}

/// A sign-out that lands after the driver has asked the transport once, between a lane's usual failure
/// and the status read that follows it, still reaches the caller of `uploads::send` as its reason and
/// not as a connection that ended. The host answers the first chunk that the outcome is not known,
/// which the driver reads as a failure to retry; the account signs out as the driver's status read is
/// sent.
#[tokio::test]
async fn a_sign_out_between_a_lane_failure_and_the_status_read_reaches_the_caller_of_send() {
    let script = Script::new(true);
    script.will(Chunk::Unknown { stored: false });
    let ended = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ended);
    let (session, _host, _client, serving) = pair_over(Arc::clone(&script), move |transport| {
        Ok(Arc::new(Ending {
            inner: Arc::new(transport),
            ended: flag,
            code: ErrorCode::LeaseLost,
            opener: None,
            breaks_at: Some((Method::UploadStatus, Break::SignOut)),
            lost: AtomicBool::new(false),
            status_sends: Arc::new(AtomicU64::new(0)),
        }) as Arc<dyn ControlTransport>)
    })
    .await;
    let route = ChunkRoute::network(&session, environment())
        .await
        .expect("a route");
    let mut upload = plan(THREE_CHUNKS);
    let told = within(uploads::send(
        &session,
        &route,
        &target(),
        &mut upload,
        TTL,
        &unwatched(),
    ))
    .await
    .expect_err("the upload ends with the sign-out");
    assert!(
        ended.load(Ordering::Acquire),
        "the sign-out came with the status read"
    );
    assert!(
        matches!(told, ClientError::Host(_)),
        "the caller is told the account's reason and not that the connection ended: {told}"
    );
    assert_eq!(told.code(), ErrorCode::LeaseLost);
    session.close();
    serving.abort();
}

/// A finish the host answers that the outcome is not known is read from the status once. Where the
/// status does not say the upload is published, the answer stands: the send ends with it after one
/// finish and one status read, and sends no second finish by itself. The caller's next send reads the
/// status again and finishes, and the handle comes back.
#[tokio::test]
async fn a_finish_the_status_does_not_show_published_ends_the_send_with_the_hosts_answer() {
    let script = Script::new(true);
    script.finish_unknown_once.store(true, Ordering::Release);
    *script.state.lock().expect("the script") = UploadState::Publishing;
    let pair = pair(Arc::clone(&script)).await;
    let route = ChunkRoute::network(&pair.session, environment())
        .await
        .expect("a route");
    let mut upload = plan(THREE_CHUNKS);
    let at = target();
    let progress = unwatched();

    let told = within(uploads::send(
        &pair.session,
        &route,
        &at,
        &mut upload,
        TTL,
        &progress,
    ))
    .await
    .expect_err("the host cannot say what became of the finish, and the status shows no handle");
    assert_eq!(told.code(), ErrorCode::OutcomeUnknown, "{told}");
    script.seen(|seen| {
        assert_eq!(seen.finishes, 1, "no second finish went by itself");
        assert_eq!(seen.status_reads, 1, "the status was read once");
    });

    let handle = within(uploads::send(
        &pair.session,
        &route,
        &at,
        &mut upload,
        TTL,
        &progress,
    ))
    .await
    .expect("the next send reads the status, finishes and returns the handle");
    assert_eq!(Some(handle.transfer_id), upload.transfer_id().copied());
    script.seen(|seen| {
        assert_eq!(seen.finishes, 2);
        assert_eq!(seen.status_reads, 2);
    });
}

/// A finish that was sent and not answered, because the account signed out as it went, is
/// `SubmissionUncertain` with its action and not the sign-out's refusal: the host may have
/// published, and nothing is read on a connection that has gone.
#[tokio::test]
async fn a_finish_that_a_sign_out_leaves_unanswered_is_submission_uncertain() {
    let script = Script::new(true);
    let ended = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ended);
    let status_sends = Arc::new(AtomicU64::new(0));
    let counting = Arc::clone(&status_sends);
    let (session, _host, _client, serving) = pair_over(Arc::clone(&script), move |transport| {
        Ok(Arc::new(Ending {
            inner: Arc::new(transport),
            ended: flag,
            code: ErrorCode::PermissionDenied,
            opener: None,
            breaks_at: Some((Method::UploadFinish, Break::SignOut)),
            lost: AtomicBool::new(false),
            status_sends: counting,
        }) as Arc<dyn ControlTransport>)
    })
    .await;
    let route = ChunkRoute::network(&session, environment())
        .await
        .expect("a route");
    let mut upload = plan(THREE_CHUNKS);
    let told = within(uploads::send(
        &session,
        &route,
        &target(),
        &mut upload,
        TTL,
        &unwatched(),
    ))
    .await
    .expect_err("the finish is not answered");
    assert!(
        ended.load(Ordering::Acquire),
        "the sign-out came with the finish"
    );
    assert!(
        matches!(told, ClientError::SubmissionUncertain { .. }),
        "the caller is told the finish's outcome is unknown, with its action, and not the sign-out's refusal: {told:?}"
    );
    assert_eq!(
        status_sends.load(Ordering::Acquire),
        0,
        "no read of the status was tried after it"
    );
    session.close();
    serving.abort();
}

/// A finish that was sent and not answered, because the network ended the connection as it went, is
/// `SubmissionUncertain` with its action and not a connection that ended: it is the same call
/// whatever ended the connection.
#[tokio::test]
async fn a_finish_that_a_lost_connection_leaves_unanswered_is_submission_uncertain() {
    let script = Script::new(true);
    let ended = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ended);
    let status_sends = Arc::new(AtomicU64::new(0));
    let counting = Arc::clone(&status_sends);
    let (session, _host, _client, serving) = pair_over(Arc::clone(&script), move |transport| {
        Ok(Arc::new(Ending {
            inner: Arc::new(transport),
            ended: flag,
            code: ErrorCode::PermissionDenied,
            opener: None,
            breaks_at: Some((Method::UploadFinish, Break::Loss)),
            lost: AtomicBool::new(false),
            status_sends: counting,
        }) as Arc<dyn ControlTransport>)
    })
    .await;
    let route = ChunkRoute::network(&session, environment())
        .await
        .expect("a route");
    let mut upload = plan(THREE_CHUNKS);
    let told = within(uploads::send(
        &session,
        &route,
        &target(),
        &mut upload,
        TTL,
        &unwatched(),
    ))
    .await
    .expect_err("the finish is not answered");
    assert!(
        !ended.load(Ordering::Acquire),
        "this device recorded no reason: the network ended the connection"
    );
    assert!(
        matches!(told, ClientError::SubmissionUncertain { .. }),
        "the caller is told the finish's outcome is unknown, with its action: {told:?}"
    );
    assert_eq!(
        status_sends.load(Ordering::Acquire),
        0,
        "no read of the status was tried after it"
    );
    session.close();
    serving.abort();
}

/// The host answers the finish that it does not know what became of it, and the account signs out as
/// the status read that follows is sent. The status read has failed, so the send ends with the host's
/// own answer to the finish and not with the sign-out's refusal or the read's failure.
#[tokio::test]
async fn a_status_read_that_a_sign_out_stops_after_an_unknown_finish_leaves_the_hosts_answer() {
    let script = Script::new(true);
    script.finish_unknown_once.store(true, Ordering::Release);
    let ended = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ended);
    let (session, _host, _client, serving) = pair_over(Arc::clone(&script), move |transport| {
        Ok(Arc::new(Ending {
            inner: Arc::new(transport),
            ended: flag,
            code: ErrorCode::PermissionDenied,
            opener: None,
            breaks_at: Some((Method::UploadStatus, Break::SignOut)),
            lost: AtomicBool::new(false),
            status_sends: Arc::new(AtomicU64::new(0)),
        }) as Arc<dyn ControlTransport>)
    })
    .await;
    let route = ChunkRoute::network(&session, environment())
        .await
        .expect("a route");
    let mut upload = plan(THREE_CHUNKS);
    let told = within(uploads::send(
        &session,
        &route,
        &target(),
        &mut upload,
        TTL,
        &unwatched(),
    ))
    .await
    .expect_err("the host cannot say what became of the finish, and the status read is stopped");
    assert!(
        ended.load(Ordering::Acquire),
        "the sign-out came with the status read"
    );
    assert!(
        matches!(told, ClientError::OutcomeUnknown { .. }),
        "the caller is told the host's answer to the finish: {told:?}"
    );
    assert_eq!(
        script.seen(|seen| seen.finishes),
        1,
        "the finish was sent once"
    );
    session.close();
    serving.abort();
}
