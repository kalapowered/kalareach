//! An attachment's typing on the input lane, against a scripted host over a real connection.
//!
//! The host here plays the host's side of the stream and nothing else. It answers
//! `transfer.streams`, takes `terminal_input` streams, records every frame it reads, and writes
//! exactly the words a case tells it to: the window, an acceptance, a refusal, the launch marker,
//! the notice that an epoch ended, a reset. What the cases check is the client's half: the lane owns
//! the sequence, keeps within the host's window and its own bound, matches the host's words in order,
//! counts every frame in one of four sets, and never writes a held key after the hold ended.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr};
use kr_client::error::ClientError;
use kr_client::input::{
    Count, EndCause, EpochKnown, InputEvent, InputEvents, InputLane, InputRefusal, InputTarget,
    NotReached, Over, Sets,
};
use kr_client::session::Session;
use kr_client::transport::{ControlTransport, NetworkTransport, StreamOpener, TransportFuture};
use kr_crypto::connect::{ChallengeLedger, PairedPeer};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{StreamHeader, StreamKind};
use kr_protocol::hello::{ActionWindow, ReceiveLimits};
use kr_protocol::ids::{
    AttachmentId, BootEpoch, BuildId, ClockEpoch, ConnectionId, DeviceId, DeviceKeyRevision,
    EnvironmentId, InputLeaseEpoch, InputSequence, RequestId, SessionId,
};
use kr_protocol::input::{InputAck, InputFrame, InputWindow};
use kr_protocol::method::Method;
use kr_protocol::scalars::{EndpointKey, Nullable, U64, Uuid};
use kr_protocol::transfer::{TransferStreamsParams, TransferStreamsResult};
use kr_transport::clock::{ContinuousClock, ManualClock};
use kr_transport::config::EndpointConfig;
use kr_transport::deadlines::{DeadlineKind, ManualDeadlines};
use kr_transport::handshake::{self, Admitted, HostEpochs, LocalIdentity, PairedDirectory};
use kr_transport::scheduler::{SendLimits, StreamBudget, StreamClass};
use kr_transport::streams::{PendingStream, StreamRegistry};
use kr_transport::window::{ActionWindowIssuer, MAX_WINDOW_VALIDITY};

/// How long a case waits for the host to see something that must happen: it fails a wait that never
/// ends, and is not a measurement.
const LIVENESS: Duration = Duration::from_secs(60);

/// The most key bytes a frame holds at the floor of the negotiated limit, 1,024.
const FLOOR_FRAME: usize = 977;

/// A launch number that no case uses: the marker that comes back last tells that every word the host
/// wrote before it has been applied.
const SYNC: u32 = 4_000_000_000;

const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";

fn environment() -> EnvironmentId {
    EnvironmentId::new(Uuid::from_bytes([7; 16]))
}

fn session_id() -> SessionId {
    SessionId::new(Uuid::from_bytes([8; 16]))
}

fn attachment() -> AttachmentId {
    AttachmentId::new(Uuid::from_bytes([9; 16]))
}

fn epoch(number: u64) -> InputLeaseEpoch {
    InputLeaseEpoch::new(number)
}

fn sequence(number: u64) -> InputSequence {
    InputSequence::new(number)
}

fn window(frames: u32) -> InputWindow {
    InputWindow {
        frames,
        bytes: U64::new(512 * 1024),
    }
}

/// A distinct five-byte key for each number, so that an order can be told from a count.
fn key(number: u64) -> Vec<u8> {
    format!("k{number:04}").into_bytes()
}

async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIVENESS, future)
        .await
        .expect("the call ended in time")
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

/// A frame the host read.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SeenFrame {
    epoch: u64,
    sequence: u64,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct Seen {
    headers: Vec<StreamHeader>,
    frames: Vec<SeenFrame>,
    ended_streams: u64,
    /// Streams whose end the host read as a clean finish, not a reset.
    finished_streams: u64,
    /// Streams whose end the host read as a reset or a failure.
    reset_streams: u64,
    methods: Vec<String>,
}

/// What the host writes next on the stream.
enum Out {
    Ack(InputAck),
    /// Resets the stream, as a host does that ends it.
    Reset,
    /// Finishes the host's side of the stream, as a host does that has nothing more to say.
    Finish,
}

struct Script {
    streams: Mutex<Vec<StreamKind>>,
    window: Mutex<InputWindow>,
    seen: Mutex<Seen>,
    changed: tokio::sync::Notify,
    out: Mutex<Option<tokio::sync::mpsc::UnboundedSender<Out>>>,
    /// Frames the host writes on the control stream, as the host's own words to the connection.
    control_out: tokio::sync::mpsc::UnboundedSender<ControlFrame>,
    pending_control: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<ControlFrame>>>,
}

impl Script {
    fn new(window: InputWindow, streams: Vec<StreamKind>) -> Arc<Self> {
        let (control_out, pending) = tokio::sync::mpsc::unbounded_channel();
        Arc::new(Self {
            streams: Mutex::new(streams),
            window: Mutex::new(window),
            seen: Mutex::new(Seen::default()),
            changed: tokio::sync::Notify::new(),
            out: Mutex::new(None),
            control_out,
            pending_control: Mutex::new(Some(pending)),
        })
    }

    fn seen<T>(&self, read: impl FnOnce(&Seen) -> T) -> T {
        read(&self.seen.lock().expect("what the host saw"))
    }

    fn record(&self, write: impl FnOnce(&mut Seen)) {
        write(&mut self.seen.lock().expect("what the host saw"));
        self.changed.notify_waiters();
    }

    /// Waits until what the host saw satisfies `condition`: a condition of the host's state, never
    /// of a time.
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

    fn frames(&self) -> Vec<SeenFrame> {
        self.seen(|seen| seen.frames.clone())
    }

    fn say(&self, out: Out) {
        self.out
            .lock()
            .expect("the stream's writer")
            .as_ref()
            .expect("a stream is open")
            .send(out)
            .expect("the stream's writer is alive");
    }

    fn accept(&self, epoch_number: u64, through: u64) {
        self.say(Out::Ack(InputAck::Accepted {
            epoch: epoch(epoch_number),
            through: sequence(through),
        }));
    }

    fn refuse(
        &self,
        epoch_number: u64,
        first: u64,
        accepted_through: Option<u64>,
        code: ErrorCode,
    ) {
        self.say(Out::Ack(InputAck::Refused {
            epoch: epoch(epoch_number),
            sequence: sequence(first),
            accepted_through: Nullable::from(accepted_through.map(sequence)),
            error: ProtocolError::new(code, "refused"),
        }));
    }

    fn marker(&self, launch: u32) {
        self.say(Out::Ack(InputAck::LaunchReserved { launch }));
    }

    fn epoch_ended(&self, epoch_number: u64, fenced_bytes: u64) {
        self.say(Out::Ack(InputAck::EpochEnded {
            epoch: epoch(epoch_number),
            fenced_bytes: U64::new(fenced_bytes),
        }));
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

/// Serves connections: the control stream, and the input streams of each.
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
                connection.set_max_concurrent_bi_streams(iroh::endpoint::VarInt::from_u32(16));
                let streams = StreamRegistry::new(
                    authorised.connection_id,
                    Arc::new(kr_transport::scheduler::StreamBudget::new(
                        SendLimits::default(),
                    )),
                    None,
                );
                let accepting = Arc::clone(&script);
                let taken = connection.clone();
                tokio::spawn(async move {
                    while let Ok(pending) = streams.accept_pending(&taken).await {
                        tokio::spawn(serve_stream(Arc::clone(&accepting), pending));
                    }
                });
                let mut reader = authorised.control_reader;
                let writer = Arc::new(tokio::sync::Mutex::new(authorised.control_writer));
                if let Some(mut words) = script.pending_control.lock().expect("the script").take() {
                    let writer = Arc::clone(&writer);
                    tokio::spawn(async move {
                        while let Some(frame) = words.recv().await {
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
                    if let Some(reply) = control_reply(&script, frame)
                        && writer.lock().await.write_message(&reply).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    })
}

fn control_reply(script: &Arc<Script>, frame: ControlFrame) -> Option<ControlFrame> {
    let ControlFrame::Request(request) = frame else {
        return None;
    };
    script.record(|seen| {
        seen.methods.push(
            request
                .method
                .method()
                .map_or_else(String::new, |m| format!("{m:?}")),
        );
    });
    let outcome = match request.method.method() {
        Some(Method::TransferStreams) => {
            let _: TransferStreamsParams = request.params.to_typed().ok()?;
            typed(&TransferStreamsResult {
                accepted_streams: script.streams.lock().expect("the script").clone(),
            })
        }
        _ => Err(ProtocolError::new(
            ErrorCode::PermissionDenied,
            kr_transport::actor::METHOD_NOT_AVAILABLE,
        )),
    };
    Some(answer(request.request_id, outcome))
}

/// Records that the host's side of a stream has ended.
struct Ends(Arc<Script>);

impl Drop for Ends {
    fn drop(&mut self) {
        self.0.record(|seen| seen.ended_streams += 1);
    }
}

/// Takes one input stream: its header, the window it says, every frame read, and the words the
/// case writes.
async fn serve_stream(script: Arc<Script>, pending: PendingStream) {
    let Ok(stream) = pending.open(&[StreamKind::TerminalInput]).await else {
        return;
    };
    script.record(|seen| seen.headers.push(stream.header().clone()));
    let ends = Arc::new(Ends(Arc::clone(&script)));
    let (mut reader, mut writer) = stream.split();
    let handle = reader.handle();
    let (words, mut queued) = tokio::sync::mpsc::unbounded_channel();
    *script.out.lock().expect("the stream's writer") = Some(words);
    let ready = *script.window.lock().expect("the window");
    if writer
        .write_message(&InputAck::Ready { window: ready })
        .await
        .is_err()
    {
        return;
    }
    let reading = Arc::clone(&script);
    let reading_ends = Arc::clone(&ends);
    tokio::spawn(async move {
        let _ends = reading_ends;
        loop {
            match reader.read_message::<InputFrame>().await {
                Ok(Some(frame)) => reading.record(|seen| {
                    seen.frames.push(SeenFrame {
                        epoch: frame.epoch.get(),
                        sequence: frame.sequence.get(),
                        bytes: frame.bytes.into_vec(),
                    });
                }),
                Ok(None) => {
                    reading.record(|seen| seen.finished_streams += 1);
                    break;
                }
                Err(_) => {
                    reading.record(|seen| seen.reset_streams += 1);
                    break;
                }
            }
        }
    });
    while let Some(out) = queued.recv().await {
        match out {
            Out::Ack(ack) => {
                if writer.write_message(&ack).await.is_err() {
                    return;
                }
            }
            Out::Reset => {
                handle.revoke();
                return;
            }
            Out::Finish => {
                drop(writer);
                return;
            }
        }
    }
}

/* ---------------------------------------------------------------------------------------- */
/* The rig                                                                                    */
/* ---------------------------------------------------------------------------------------- */

/// A transport that reports another input frame limit than the one the connection negotiated, so
/// that a case can run the lane at the floor of 1,024 over the real stream.
#[derive(Debug)]
struct Floored {
    inner: Arc<dyn ControlTransport>,
    limit: u64,
}

impl ControlTransport for Floored {
    fn connection_id(&self) -> ConnectionId {
        self.inner.connection_id()
    }
    fn limits(&self) -> ReceiveLimits {
        ReceiveLimits {
            max_input_frame_len: U64::new(self.limit),
            ..self.inner.limits()
        }
    }
    fn initial_action_window(&self) -> ActionWindow {
        self.inner.initial_action_window()
    }
    fn ended_by_this_device(&self) -> Option<kr_client::transport::DeviceEnd> {
        self.inner.ended_by_this_device()
    }
    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
        self.inner.send(frame)
    }
    fn claim_receiver(&self) -> kr_client::Result<()> {
        self.inner.claim_receiver()
    }
    fn stream_opener(&self) -> Option<Arc<dyn StreamOpener>> {
        self.inner.stream_opener()
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

struct Rig {
    session: Session,
    script: Arc<Script>,
    lane: InputLane,
    events: InputEvents,
    deadlines: Arc<ManualDeadlines>,
    budget: Arc<StreamBudget>,
    _host: Side,
    _client: Side,
    serving: tokio::task::JoinHandle<()>,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.session.close();
        self.serving.abort();
    }
}

async fn connect(
    script: Arc<Script>,
    limit: Option<u64>,
) -> (
    Session,
    Side,
    Side,
    tokio::task::JoinHandle<()>,
    Arc<StreamBudget>,
) {
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
    let transport: Arc<dyn ControlTransport> = match limit {
        Some(limit) => Arc::new(Floored {
            inner: Arc::new(transport),
            limit,
        }),
        None => Arc::new(transport),
    };
    let budget = transport
        .stream_opener()
        .and_then(|opener| opener.budget())
        .expect("the connection's send budget");
    let session = Session::start(transport).expect("a session");
    (session, host, client, serving, budget)
}

fn target(deadlines: &Arc<ManualDeadlines>) -> InputTarget {
    InputTarget::new(environment(), session_id(), attachment()).bounded_by(deadlines.clone())
}

/// A lane on a scripted host that says `window`, at the negotiated limit or at `limit`.
async fn rig_at(window: InputWindow, limit: Option<u64>) -> Rig {
    let script = Script::new(window, vec![StreamKind::TerminalInput]);
    let (session, host, client, serving, budget) = connect(Arc::clone(&script), limit).await;
    let deadlines = ManualDeadlines::new();
    let lane = within(session.input_lane(target(&deadlines)))
        .await
        .expect("a lane");
    let events = lane.events().expect("the lane's events");
    Rig {
        session,
        script,
        lane,
        events,
        deadlines,
        budget,
        _host: host,
        _client: client,
        serving,
    }
}

async fn rig(frames: u32) -> Rig {
    rig_at(window(frames), None).await
}

/// A lane at the floor of the negotiated limit, 1,024.
async fn floor_rig() -> Rig {
    rig_at(window(32), Some(1_024)).await
}

impl Rig {
    async fn event(&mut self) -> InputEvent {
        within(self.events.recv())
            .await
            .expect("the lane has another event")
    }

    /// Reads events until `want` picks one, and fails on none of them.
    async fn event_where(&mut self, want: impl Fn(&InputEvent) -> bool) -> InputEvent {
        loop {
            let event = self.event().await;
            if want(&event) {
                return event;
            }
        }
    }

    /// Returns once the lane has applied every word the host wrote before this call: the words are
    /// read in order, so the one that comes back last was read last.
    async fn settled(&mut self) -> Vec<InputEvent> {
        self.script.marker(SYNC);
        let mut passed = Vec::new();
        loop {
            let event = self.event().await;
            if matches!(&event, InputEvent::LaunchReserved { launch, .. } if *launch == SYNC) {
                return passed;
            }
            // An ended lane reads no marker: say so here and not by waiting for it.
            assert!(
                !matches!(&event, InputEvent::Ended { .. }),
                "the lane ended before the host's marker was applied: {event:?} after {passed:?}"
            );
            passed.push(event);
        }
    }

    /// The event that ends the lane for a word of the host's that breaks the stream's contract. A
    /// marker follows the word, so a lane that takes the word and goes on says so by an event of its
    /// own, and the case fails by its assertion and not by waiting.
    async fn ended_by_breach(&mut self) -> InputEvent {
        self.script.marker(SYNC);
        let mut passed = Vec::new();
        loop {
            let event = self.event().await;
            match &event {
                InputEvent::Ended { .. } => return event,
                InputEvent::LaunchReserved { launch, .. } if *launch == SYNC => {
                    panic!("the lane took the host's word and went on: {passed:?}")
                }
                _ => passed.push(event),
            }
        }
    }

    /// Accepts every frame the host has read so far, once the lane has written `total` of them.
    async fn accept_all(&mut self, epoch_number: u64, total: usize) {
        let mut accepted = 0;
        while accepted < total {
            self.script
                .until("a frame to accept", |seen| seen.frames.len() > accepted)
                .await;
            let seen = self.script.seen(|seen| seen.frames.len());
            self.script.accept(epoch_number, seen as u64 - 1);
            accepted = seen;
        }
        self.settled().await;
    }

    fn sets(&self) -> Sets {
        self.lane.sets().expect("an epoch has begun")
    }

    /// Takes the send room the connection has left, so that the lane's next write meets the queue's
    /// limit. The room comes back when the returned value is dropped.
    async fn take_the_room(&self) -> impl Sized + use<> {
        let budget = Arc::clone(&self.budget);
        within(async move {
            loop {
                let released = budget.released();
                let free = budget.limits().max_queued_bytes - budget.queued_bytes();
                if let Ok(taken) = budget.reserve(StreamClass::Interactive, free) {
                    return taken;
                }
                released.await;
            }
        })
        .await
    }
}

fn count(frames: u64, bytes: u64) -> Count {
    Count { frames, bytes }
}

/* ---------------------------------------------------------------------------------------- */
/* Opening                                                                                    */
/* ---------------------------------------------------------------------------------------- */

/// The lane opens one stream under the attachment's own header and keeps it.
#[tokio::test]
async fn the_lane_opens_one_stream_with_the_attachments_header() {
    let rig = rig(4).await;
    let headers = rig.script.seen(|seen| seen.headers.clone());
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].kind, StreamKind::TerminalInput);
    assert_eq!(headers[0].resource.environment_id, environment());
    assert_eq!(headers[0].resource.session_id, Nullable::some(session_id()));
    assert_eq!(
        headers[0].resource.attachment_id,
        Nullable::some(attachment())
    );
    assert_eq!(
        headers[0].connection_id,
        rig.session.transport().connection_id()
    );
}

/// A host that does not list the stream gets no stream, and the person is told in the host's own
/// terms.
#[tokio::test]
async fn a_host_that_takes_no_input_stream_is_refused_before_any_stream_opens() {
    let script = Script::new(window(4), Vec::new());
    let (session, _host, _client, serving, _budget) = connect(Arc::clone(&script), None).await;
    let deadlines = ManualDeadlines::new();
    let refused = within(session.input_lane(target(&deadlines)))
        .await
        .expect_err("no lane");
    assert_eq!(refused.code(), ErrorCode::UnsupportedCapability);
    assert!(
        script.seen(|seen| seen.headers.is_empty()),
        "no stream opened"
    );
    session.close();
    serving.abort();
}

/// A host that says something other than its window first has not opened the stream.
#[tokio::test]
async fn a_window_that_holds_no_whole_frame_is_refused() {
    let script = Script::new(
        InputWindow {
            frames: 4,
            bytes: U64::new(100),
        },
        vec![StreamKind::TerminalInput],
    );
    let (session, _host, _client, serving, _budget) = connect(Arc::clone(&script), None).await;
    let deadlines = ManualDeadlines::new();
    let refused = within(session.input_lane(target(&deadlines)))
        .await
        .expect_err("no lane");
    assert!(matches!(refused, ClientError::Host(_)), "{refused}");
    session.close();
    serving.abort();
}

/* ---------------------------------------------------------------------------------------- */
/* The bound                                                                                  */
/* ---------------------------------------------------------------------------------------- */

/// The lane never has more frames written and not yet accepted than the host's window allows; the
/// rest wait in its queue, and are written in order as acceptances make room.
#[tokio::test]
async fn the_lane_keeps_within_the_hosts_window_and_writes_in_order() {
    let mut rig = rig(3).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..10 {
        let writing = rig.lane.try_send(&key(number)).expect("admitted");
        assert_eq!(writing.sequence, Some(sequence(number)));
    }
    rig.script
        .until("the window's three frames", |seen| seen.frames.len() >= 3)
        .await;
    rig.settled().await;
    assert_eq!(rig.script.frames().len(), 3, "no frame past the window");
    assert_eq!(rig.sets().uncertain, count(3, 15));
    assert_eq!(rig.sets().unsent, count(7, 35));
    rig.script.accept(5, 1);
    rig.script
        .until("two more", |seen| seen.frames.len() >= 5)
        .await;
    rig.settled().await;
    assert_eq!(rig.script.frames().len(), 5, "no frame past the window");
    assert_eq!(rig.sets().accepted, count(2, 10));
    rig.accept_all(5, 10).await;
    let frames = rig.script.frames();
    assert_eq!(frames.len(), 10);
    for (number, frame) in frames.iter().enumerate() {
        assert_eq!(frame.epoch, 5);
        assert_eq!(frame.sequence, number as u64);
        assert_eq!(frame.bytes, key(number as u64));
    }
}

/// At the lane's own bound nothing is admitted and no sequence is taken: the frame admitted once
/// room is free continues the sequence where the last admitted frame left it.
#[tokio::test]
async fn the_frame_bound_refuses_without_taking_a_sequence() {
    let mut rig = rig(32).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..1_024_u64 {
        let writing = rig.lane.try_send(b"x").expect("admitted");
        assert_eq!(writing.sequence, Some(sequence(number)));
    }
    for _ in 0..3 {
        assert_eq!(rig.lane.try_send(b"x"), Err(InputRefusal::Full));
    }
    let before = rig.sets();
    assert_eq!(before.uncertain.frames + before.unsent.frames, 1_024);
    rig.script
        .until("the window", |seen| seen.frames.len() >= 32)
        .await;
    rig.script.accept(5, 31);
    rig.settled().await;
    let writing = rig.lane.try_send(b"y").expect("room again");
    assert_eq!(
        writing.sequence,
        Some(sequence(1_024)),
        "the refusals took no sequence"
    );
}

/// The bound counts encoded bytes at their widest, so frames of the widest key size reach it long
/// before the frame bound.
#[tokio::test]
async fn the_byte_bound_refuses_the_frame_that_would_pass_it() {
    let rig = rig(32).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    // At the negotiated 64 KiB a frame holds 65,489 key bytes and costs 65,536 encoded.
    let widest = vec![b'w'; 65_489];
    for _ in 0..4 {
        rig.lane.try_send(&widest).expect("within 256 KiB");
    }
    assert_eq!(rig.lane.try_send(b"x"), Err(InputRefusal::Full));
    assert_eq!(
        rig.lane.try_send(&vec![b'w'; 65_490]),
        Err(InputRefusal::TooLarge),
        "more than a frame holds"
    );
}

/// An epoch's frames never go out under an epoch that ended: queued frames of the old epoch are not
/// written once a new epoch begins.
#[tokio::test]
async fn frames_of_an_old_epoch_are_not_written_under_a_new_one() {
    let mut rig = rig(1).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..6 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.script
        .until("the first frame", |seen| !seen.frames.is_empty())
        .await;
    let ended = rig.lane.begin_epoch(epoch(6)).expect("a new epoch");
    let ended = ended.expect("the old epoch ended");
    assert_eq!(ended.uncertain, count(1, 5));
    assert_eq!(ended.unsent, count(5, 25));
    rig.lane
        .try_send(&key(100))
        .expect("admitted under epoch 6");
    rig.script.accept(5, 0);
    rig.settled().await;
    rig.script
        .until("the new epoch's frame", |seen| {
            seen.frames.iter().any(|frame| frame.epoch == 6)
        })
        .await;
    let frames = rig.script.frames();
    assert_eq!(frames.iter().filter(|frame| frame.epoch == 5).count(), 1);
    let new: Vec<_> = frames.iter().filter(|frame| frame.epoch == 6).collect();
    assert_eq!(new.len(), 1);
    assert_eq!(new[0].sequence, 0, "sequences start again in a new epoch");
}

/* ---------------------------------------------------------------------------------------- */
/* What the host says                                                                          */
/* ---------------------------------------------------------------------------------------- */

/// An acceptance is cumulative, and the four sets are exact while the host's words are stalled and
/// after each of them.
#[tokio::test]
async fn an_acceptance_moves_the_sets_and_reaches_the_barrier() {
    let mut rig = rig(4).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..6 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.script
        .until("the window", |seen| seen.frames.len() >= 4)
        .await;
    // Stalled: nothing is accepted yet.
    assert_eq!(rig.sets().accepted, count(0, 0));
    assert_eq!(rig.sets().uncertain, count(4, 20));
    assert_eq!(rig.sets().unsent, count(2, 10));
    let barrier = rig.lane.mark(None).expect("a barrier");
    assert_eq!(barrier.count.get(), 6);
    rig.script.accept(5, 2);
    let event = rig.event().await;
    assert_eq!(
        event,
        InputEvent::Accepted {
            epoch: epoch(5),
            through: sequence(2),
            frames: 3,
            bytes: 15,
        }
    );
    assert_eq!(rig.sets().accepted, count(3, 15));
    rig.script.accept(5, 5);
    rig.script
        .until("all six", |seen| seen.frames.len() >= 6)
        .await;
    let event = rig.event().await;
    assert!(
        matches!(event, InputEvent::Accepted { frames: 3, .. }),
        "{event:?}"
    );
    assert_eq!(rig.event().await, InputEvent::Reached(barrier));
    assert_eq!(
        rig.sets(),
        Sets {
            accepted: count(6, 30),
            ..Sets::default()
        }
    );
}

/// A refusal ends the epoch: the accepted prefix is counted, the first refused frame and every later
/// frame, written or not, are refused, and nothing is written after it.
#[tokio::test]
async fn a_refusal_ends_the_epoch_with_exact_sets() {
    let mut rig = rig(4).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..7 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.script
        .until("the window", |seen| seen.frames.len() >= 4)
        .await;
    let barrier = rig.lane.mark(None).expect("a barrier");
    rig.script.refuse(5, 2, Some(1), ErrorCode::LeaseLost);
    let accepted = rig.event().await;
    assert!(
        matches!(accepted, InputEvent::Accepted { frames: 2, .. }),
        "{accepted:?}"
    );
    let refused = rig.event().await;
    let InputEvent::Refused {
        epoch: ended,
        sequence: first,
        accepted_through,
        error,
        sets,
    } = refused
    else {
        panic!("a refusal, not {refused:?}");
    };
    assert_eq!(ended, epoch(5));
    assert_eq!(first, sequence(2));
    assert_eq!(accepted_through, Some(sequence(1)));
    assert_eq!(error.code, ErrorCode::LeaseLost);
    assert_eq!(
        sets,
        Sets {
            accepted: count(2, 10),
            refused: count(5, 25),
            uncertain: count(0, 0),
            unsent: count(0, 0),
        }
    );
    assert_eq!(
        rig.event().await,
        InputEvent::NotReached {
            barrier,
            reason: NotReached::Refused,
        }
    );
    assert_eq!(
        rig.lane.try_send(&key(9)),
        Err(InputRefusal::Over(Over::Refused))
    );
    rig.settled().await;
    assert_eq!(
        rig.script.frames().len(),
        4,
        "nothing written after the refusal"
    );
}

/// A refusal that starts the epoch refuses the first frame with no accepted prefix.
#[tokio::test]
async fn a_refusal_of_the_first_frame_has_no_prefix() {
    let mut rig = rig(4).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    rig.lane.try_send(&key(0)).expect("admitted");
    rig.script
        .until("the frame", |seen| !seen.frames.is_empty())
        .await;
    rig.script.refuse(5, 0, None, ErrorCode::LeaseLost);
    let refused = rig
        .event_where(|event| matches!(event, InputEvent::Refused { .. }))
        .await;
    assert!(
        matches!(
            refused,
            InputEvent::Refused {
                accepted_through: None,
                sets: Sets {
                    accepted: Count { frames: 0, .. },
                    refused: Count { frames: 1, .. },
                    ..
                },
                ..
            }
        ),
        "{refused:?}"
    );
}

/// The host's notice that an epoch ended is told with its sets and the discarded count, even when
/// the view has nothing outstanding.
#[tokio::test]
async fn the_notice_that_an_epoch_ended_carries_the_sets_and_the_fenced_count() {
    let mut rig = rig(2).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..5 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.script
        .until("the window", |seen| seen.frames.len() >= 2)
        .await;
    rig.script.accept(5, 0);
    rig.script
        .until("a third", |seen| seen.frames.len() >= 3)
        .await;
    rig.script.epoch_ended(5, 1234);
    let event = rig
        .event_where(|event| matches!(event, InputEvent::EpochEnded { .. }))
        .await;
    assert_eq!(
        event,
        InputEvent::EpochEnded {
            epoch: epoch(5),
            fenced_bytes: 1234,
            sets: Some(Sets {
                accepted: count(1, 5),
                refused: count(0, 0),
                uncertain: count(2, 10),
                unsent: count(2, 10),
            }),
            known: EpochKnown::Typing,
        }
    );
    assert_eq!(
        rig.lane.try_send(&key(9)),
        Err(InputRefusal::Over(Over::LeaseEnded))
    );
    // A new epoch goes on over the same stream, from sequence 0.
    assert_eq!(rig.lane.begin_epoch(epoch(6)), Ok(None));
    let writing = rig.lane.try_send(&key(20)).expect("admitted");
    assert_eq!(writing.sequence, Some(sequence(0)));
}

/// A notice for an epoch the view has not yet begun is kept: the view that acquired the epoch and
/// lost it before it began it learns of the end when it begins it.
#[tokio::test]
async fn a_notice_that_comes_before_the_epoch_begins_is_told_when_it_begins() {
    let mut rig = rig(2).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    rig.script.epoch_ended(6, 7);
    rig.settled().await;
    assert_eq!(rig.lane.begin_epoch(epoch(6)), Ok(Some(Sets::default())));
    let event = rig
        .event_where(|event| matches!(event, InputEvent::EpochEnded { .. }))
        .await;
    assert!(
        matches!(event, InputEvent::EpochEnded { epoch: e, fenced_bytes: 7, .. } if e == epoch(6)),
        "{event:?}"
    );
    assert_eq!(
        rig.lane.try_send(&key(1)),
        Err(InputRefusal::Over(Over::LeaseEnded))
    );
}

/// The lane suppresses no notice: after the view marked its own release it tells the host's notice
/// once, with what it knew, and the holder leaves the words out when its answer carried the count.
#[tokio::test]
async fn the_notice_for_an_epoch_the_view_marked_to_end_is_told_with_what_the_lane_knew() {
    let mut rig = rig(2).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    rig.lane.try_send(&key(0)).expect("admitted");
    let barrier = rig.lane.mark(None).expect("a barrier");
    rig.script
        .until("the frame", |seen| !seen.frames.is_empty())
        .await;
    rig.script.accept(5, 0);
    rig.script.epoch_ended(5, 40);
    let mut told = rig.settled().await;
    while let Some(event) = rig.events.try_recv() {
        told.push(event);
    }
    assert!(told.contains(&InputEvent::Reached(barrier)), "{told:?}");
    let notices: Vec<_> = told
        .iter()
        .filter(|event| matches!(event, InputEvent::EpochEnded { .. }))
        .collect();
    assert_eq!(
        notices,
        [&InputEvent::EpochEnded {
            epoch: epoch(5),
            fenced_bytes: 40,
            sets: Some(Sets {
                accepted: count(1, 5),
                ..Sets::default()
            }),
            known: EpochKnown::Ending,
        }],
        "{told:?}"
    );
}

/// A refusal ends the epoch and tells its sets; the worker's drop of accepted typing is told after
/// it, by the host's notice, with the count and without the sets again.
#[tokio::test]
async fn a_notice_after_a_refusal_is_told_with_its_count() {
    let mut rig = rig(4).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..3 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.script
        .until("three frames", |seen| seen.frames.len() >= 3)
        .await;
    rig.script
        .refuse(5, 1, Some(0), ErrorCode::PermissionDenied);
    rig.script.epoch_ended(5, 321);
    let notice = rig
        .event_where(|event| matches!(event, InputEvent::EpochEnded { .. }))
        .await;
    assert_eq!(
        notice,
        InputEvent::EpochEnded {
            epoch: epoch(5),
            fenced_bytes: 321,
            sets: None,
            known: EpochKnown::Refused,
        }
    );
}

/// A notice for an epoch that a later one has replaced is still told, without sets: the host's
/// answer to the later acquire can come first.
#[tokio::test]
async fn a_notice_for_an_older_epoch_is_told_without_sets() {
    let mut rig = rig(4).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    rig.lane.try_send(&key(0)).expect("admitted");
    rig.lane.begin_epoch(epoch(6)).expect("a later epoch");
    rig.script.epoch_ended(5, 9);
    let notice = rig
        .event_where(|event| matches!(event, InputEvent::EpochEnded { .. }))
        .await;
    assert_eq!(
        notice,
        InputEvent::EpochEnded {
            epoch: epoch(5),
            fenced_bytes: 9,
            sets: None,
            known: EpochKnown::Older,
        }
    );
}

/// A notice is told when everything the view typed was accepted: the worker can still have dropped
/// accepted batches, and the count is the only word of it.
#[tokio::test]
async fn a_notice_is_told_when_every_frame_was_accepted() {
    let mut rig = rig(4).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..2 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.accept_all(5, 2).await;
    rig.script.epoch_ended(5, 10);
    let notice = rig
        .event_where(|event| matches!(event, InputEvent::EpochEnded { .. }))
        .await;
    assert_eq!(
        notice,
        InputEvent::EpochEnded {
            epoch: epoch(5),
            fenced_bytes: 10,
            sets: Some(Sets {
                accepted: count(2, 10),
                ..Sets::default()
            }),
            known: EpochKnown::Typing,
        }
    );
}

/// The stream's end tells what is known: the written frames may not have arrived and the queued
/// ones were never sent.
#[tokio::test]
async fn the_streams_reset_tells_what_is_known() {
    let mut rig = rig(2).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..5 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.script
        .until("the window", |seen| seen.frames.len() >= 2)
        .await;
    rig.script.accept(5, 0);
    rig.script
        .until("a third", |seen| seen.frames.len() >= 3)
        .await;
    rig.settled().await;
    rig.script.say(Out::Reset);
    let event = rig
        .event_where(|event| matches!(event, InputEvent::Ended { .. }))
        .await;
    assert_eq!(
        event,
        InputEvent::Ended {
            epoch: Some(epoch(5)),
            cause: EndCause::Reset,
            sets: Some(Sets {
                accepted: count(1, 5),
                refused: count(0, 0),
                uncertain: count(2, 10),
                unsent: count(2, 10),
            }),
        }
    );
    assert_eq!(
        rig.lane.try_send(&key(9)),
        Err(InputRefusal::Over(Over::StreamEnded))
    );
    assert_eq!(
        rig.lane.begin_epoch(epoch(6)),
        Err(InputRefusal::Over(Over::StreamEnded))
    );
}

/// A host that has withdrawn the connection says so in the one way a host can on a connection it
/// keeps open: it refuses the connection itself. The lane ends with that refusal, so that the
/// typing that the session had accepted may also have been discarded can be said.
#[tokio::test]
async fn a_connection_the_host_withdrew_ends_the_lane_with_the_refusal() {
    let mut rig = rig(2).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..4 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.script
        .until("the window", |seen| seen.frames.len() >= 2)
        .await;
    rig.script.accept(5, 0);
    rig.script
        .until("a third frame", |seen| seen.frames.len() >= 3)
        .await;
    rig.settled().await;
    rig.script
        .control_out
        .send(answer(
            RequestId::new(0),
            Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "the connection was withdrawn",
            )),
        ))
        .expect("the control stream's writer");
    let event = rig
        .event_where(|event| matches!(event, InputEvent::Ended { .. }))
        .await;
    let InputEvent::Ended { cause, sets, .. } = event else {
        unreachable!();
    };
    let sets = sets.expect("the event froze the epoch");
    let EndCause::Connection {
        refusal: Some(refusal),
    } = cause
    else {
        panic!("the host's refusal, not {cause:?}");
    };
    assert_eq!(refusal.code, ErrorCode::PermissionDenied);
    assert_eq!(sets.accepted, count(1, 5));
    assert_eq!(sets.uncertain, count(2, 10));
    assert_eq!(sets.unsent, count(1, 5));
}

/// Words that break the stream's contract end the lane and are never counted: an acceptance that
/// goes back, one for a frame never written, a refusal that lies in the accepted prefix, one for a
/// frame never written, one whose prefix cannot be, and an acceptance past a refused frame. Each
/// word is followed by a marker, so a lane that took it and went on fails by its assertion.
#[tokio::test]
async fn words_that_break_the_contract_end_the_lane_and_are_not_counted() {
    fn breach(event: &InputEvent) -> bool {
        matches!(
            event,
            InputEvent::Ended {
                cause: EndCause::Breach(_),
                ..
            }
        )
    }
    // An acceptance that goes back.
    let mut rig = rig(4).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..3 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.script
        .until("three frames", |seen| seen.frames.len() >= 3)
        .await;
    rig.script.accept(5, 1);
    rig.script.accept(5, 0);
    let ended = rig.ended_by_breach().await;
    assert!(breach(&ended), "{ended:?}");
    drop(rig);

    // An acceptance of a frame the lane never wrote.
    let mut rig = rig_at(window(4), None).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    rig.lane.try_send(&key(0)).expect("admitted");
    rig.script.accept(5, 3);
    let ended = rig.ended_by_breach().await;
    assert!(breach(&ended), "{ended:?}");
    drop(rig);

    // A refusal of a frame inside the accepted prefix.
    let mut rig = rig_at(window(4), None).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..3 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.script
        .until("three frames", |seen| seen.frames.len() >= 3)
        .await;
    rig.script.accept(5, 1);
    rig.script.refuse(5, 1, Some(1), ErrorCode::LeaseLost);
    let ended = rig.ended_by_breach().await;
    assert!(breach(&ended), "{ended:?}");
    drop(rig);

    // A refusal of a frame the lane never wrote.
    let mut rig = rig_at(window(4), None).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..2 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.script
        .until("two frames", |seen| seen.frames.len() >= 2)
        .await;
    rig.script.refuse(5, 5, Some(1), ErrorCode::LeaseLost);
    let ended = rig.ended_by_breach().await;
    assert!(breach(&ended), "{ended:?}");
    drop(rig);

    // A refusal whose accepted prefix cannot be: one more than the largest sequence is no number.
    let mut rig = rig_at(window(4), None).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    rig.lane.try_send(&key(0)).expect("admitted");
    rig.script
        .until("the frame", |seen| !seen.frames.is_empty())
        .await;
    rig.script
        .refuse(5, 0, Some(u64::MAX), ErrorCode::LeaseLost);
    let ended = rig.ended_by_breach().await;
    assert!(breach(&ended), "{ended:?}");
    drop(rig);

    // An acceptance past a refused frame: the refusal told its sets, and nothing is counted after it.
    let mut rig = rig_at(window(4), None).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..3 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.script
        .until("three frames", |seen| seen.frames.len() >= 3)
        .await;
    rig.script.refuse(5, 1, Some(0), ErrorCode::LeaseLost);
    rig.script.accept(5, 2);
    let refused = rig
        .event_where(|event| matches!(event, InputEvent::Refused { .. }))
        .await;
    let InputEvent::Refused { sets, .. } = refused else {
        unreachable!();
    };
    assert_eq!(
        sets.accepted,
        count(1, 5),
        "nothing counted past the refusal"
    );
    assert_eq!(sets.refused, count(2, 10));
    let ended = rig.ended_by_breach().await;
    assert!(
        matches!(
            &ended,
            InputEvent::Ended {
                cause: EndCause::Breach(_),
                sets: None,
                ..
            }
        ),
        "an epoch that was already over gives no sets again: {ended:?}"
    );
}

/// The host can refuse a frame while the frames before it still await the worker. The refusal is
/// valid: the frames between the accepted prefix and the refused one are uncertain, the refused one
/// and every later frame are refused, and the lane ends the epoch in the refusal's own words.
#[tokio::test]
async fn a_refusal_above_the_accepted_prefix_leaves_the_frames_between_uncertain() {
    let mut rig = rig(8).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..5 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.script
        .until("five frames", |seen| seen.frames.len() >= 5)
        .await;
    rig.script.accept(5, 0);
    rig.script.refuse(5, 3, Some(0), ErrorCode::LeaseLost);
    let refused = rig
        .event_where(|event| matches!(event, InputEvent::Refused { .. }))
        .await;
    let InputEvent::Refused {
        sequence: first,
        accepted_through,
        sets,
        ..
    } = refused
    else {
        unreachable!();
    };
    assert_eq!(first, sequence(3));
    assert_eq!(accepted_through, Some(sequence(0)));
    assert_eq!(
        sets,
        Sets {
            accepted: count(1, 5),
            refused: count(2, 10),
            uncertain: count(2, 10),
            unsent: count(0, 0),
        }
    );
    assert_eq!(
        rig.lane.try_send(&key(9)),
        Err(InputRefusal::Over(Over::Refused))
    );
}

/* ---------------------------------------------------------------------------------------- */
/* Paste                                                                                      */
/* ---------------------------------------------------------------------------------------- */

fn text_of(len: usize) -> Vec<u8> {
    // Printable bytes only, so that no delimiter appears by chance.
    (0..len)
        .map(|index| b'a' + u8::try_from(index % 23).unwrap_or(0))
        .collect()
}

fn bracketed(text: &[u8]) -> Vec<u8> {
    let mut paste = PASTE_START.to_vec();
    paste.extend_from_slice(text);
    paste.extend_from_slice(PASTE_END);
    paste
}

/// A paste of 190 KiB is admitted whole at the floor, cut into frames within the negotiated limit
/// with its delimiters whole, and delivered in order.
#[tokio::test]
async fn a_paste_of_190_kib_is_admitted_whole_at_the_floor_and_delivered_in_order() {
    let mut rig = floor_rig().await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    let paste = bracketed(&text_of(190 * 1024));
    let written = rig.lane.try_send_paste(&paste).expect("admitted whole");
    for (number, writing) in written.iter().enumerate() {
        assert_eq!(writing.sequence, Some(sequence(number as u64)));
        assert!(writing.bytes <= FLOOR_FRAME);
    }
    assert_eq!(
        written.iter().map(|writing| writing.bytes).sum::<usize>(),
        paste.len()
    );
    rig.accept_all(5, written.len()).await;
    let frames = rig.script.frames();
    let delivered: Vec<u8> = frames
        .iter()
        .flat_map(|frame| frame.bytes.clone())
        .collect();
    assert_eq!(delivered, paste, "the paste arrives in order and whole");
    assert!(frames.iter().all(|frame| frame.bytes.len() <= FLOOR_FRAME));
    assert!(frames[0].bytes.starts_with(PASTE_START));
    assert!(frames[frames.len() - 1].bytes.ends_with(PASTE_END));
}

/// A cut never falls inside a delimiter: the frame ends before a delimiter that would straddle it.
#[tokio::test]
async fn a_cut_never_falls_inside_a_paste_delimiter() {
    let mut rig = floor_rig().await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    // The end delimiter begins three bytes before a frame's limit.
    let mut paste = vec![b'a'; FLOOR_FRAME - 3];
    paste.extend_from_slice(PASTE_END);
    paste.extend_from_slice(&[b'b'; 20]);
    let written = rig.lane.try_send_paste(&paste).expect("admitted");
    assert_eq!(
        written[0].bytes,
        FLOOR_FRAME - 3,
        "the cut moved before the delimiter"
    );
    rig.accept_all(5, written.len()).await;
    let frames = rig.script.frames();
    assert!(frames[1].bytes.starts_with(PASTE_END));
}

/// What an empty lane admits is derived from the lane's own bound, and a paste above it is refused
/// as too large with no sequence taken, whatever else is queued.
#[tokio::test]
async fn a_paste_above_what_an_empty_lane_admits_is_too_large() {
    let rig = floor_rig().await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    let capacity = rig.lane.paste_capacity();
    // A paste of 192 KiB with its delimiters is admitted by an empty lane at the floor.
    assert!(
        capacity >= 192 * 1024 + PASTE_START.len() + PASTE_END.len(),
        "capacity {capacity}"
    );
    let too_large = text_of(capacity + 1_000);
    assert_eq!(
        rig.lane.try_send_paste(&too_large),
        Err(InputRefusal::TooLarge)
    );
    assert_eq!(
        rig.lane.try_send_paste(&text_of(600 * 1024)),
        Err(InputRefusal::TooLarge)
    );
    assert_eq!(
        rig.sets(),
        Sets::default(),
        "nothing admitted, nothing sequenced"
    );
    let writing = rig.lane.try_send(&key(0)).expect("admitted");
    assert_eq!(writing.sequence, Some(sequence(0)));
    // A paste of exactly the capacity fits an empty lane.
    let rig = floor_rig().await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    let whole = text_of(rig.lane.paste_capacity());
    assert!(rig.lane.try_send_paste(&whole).is_ok());
}

/// A paste that would fit an empty lane but not the room that is free is refused for now, takes no
/// sequence, and is admitted once the room is free.
#[tokio::test]
async fn a_paste_that_fits_an_empty_lane_but_not_the_free_room_waits() {
    let mut rig = floor_rig().await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    let first = rig
        .lane
        .try_send_paste(&text_of(150 * 1024))
        .expect("admitted");
    let second = text_of(150 * 1024);
    assert_eq!(rig.lane.try_send_paste(&second), Err(InputRefusal::NotNow));
    rig.accept_all(5, first.len()).await;
    let written = rig.lane.try_send_paste(&second).expect("room is free");
    assert_eq!(
        written[0].sequence,
        Some(sequence(first.len() as u64)),
        "the refusal took no sequence"
    );
}

/* ---------------------------------------------------------------------------------------- */
/* The stream's window, and the send queue                                                     */
/* ---------------------------------------------------------------------------------------- */

/// The window is the stream's: a new epoch does not clear the charge of the frames the host has
/// not answered, so the new epoch's first frame waits behind them, and the one writer never writes
/// an older epoch's frame after a newer one. The older epoch's answer lifts the charge and is not
/// told again: the sets that the lane gave when it ended that epoch do not change.
async fn the_window_outlives_the_epoch(answer: impl FnOnce(&Script)) {
    let mut rig = rig(1).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    rig.lane.try_send(&key(0)).expect("admitted");
    rig.script
        .until("the frame", |seen| !seen.frames.is_empty())
        .await;
    let ended = rig
        .lane
        .begin_epoch(epoch(6))
        .expect("a new epoch")
        .expect("epoch 5 ended");
    assert_eq!(ended.uncertain, count(1, 5));
    rig.lane
        .try_send(&key(100))
        .expect("admitted under epoch 6");
    rig.settled().await;
    assert_eq!(
        rig.sets().unsent,
        count(1, 5),
        "the one-frame window is still charged, so the new frame waits"
    );
    assert_eq!(rig.script.frames().len(), 1);
    answer(&rig.script);
    rig.script
        .until("the new epoch's frame", |seen| seen.frames.len() >= 2)
        .await;
    let frames = rig.script.frames();
    assert_eq!(
        (frames[1].epoch, frames[1].sequence, frames[1].bytes.clone()),
        (6, 0, key(100))
    );
    let mut told = rig.settled().await;
    while let Some(event) = rig.events.try_recv() {
        told.push(event);
    }
    assert!(
        !told.iter().any(|event| matches!(
            event,
            InputEvent::Accepted { epoch: e, .. } | InputEvent::Refused { epoch: e, .. }
                if *e == epoch(5)
        )),
        "an older epoch's answer is read for the charge alone: {told:?}"
    );
}

#[tokio::test]
async fn an_older_epochs_acceptance_lifts_its_charge_from_the_window() {
    the_window_outlives_the_epoch(|script| script.accept(5, 0)).await;
}

#[tokio::test]
async fn an_older_epochs_refusal_lifts_its_charge_from_the_window() {
    the_window_outlives_the_epoch(|script| script.refuse(5, 0, None, ErrorCode::LeaseLost)).await;
}

/// The window has a byte half: frames the frame count allows still wait when their bytes would pass
/// what the host said.
#[tokio::test]
async fn the_byte_half_of_the_window_holds_the_lane_back() {
    let window = InputWindow {
        frames: 100,
        bytes: U64::new(2 * 1_024),
    };
    let mut rig = rig_at(window, Some(1_024)).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for _ in 0..4 {
        rig.lane.try_send(&[b'x'; FLOOR_FRAME]).expect("admitted");
    }
    rig.script
        .until("two frames", |seen| seen.frames.len() >= 2)
        .await;
    rig.settled().await;
    let two = 2 * FLOOR_FRAME as u64;
    assert_eq!(
        rig.sets().uncertain,
        count(2, two),
        "two frames fill the bytes"
    );
    assert_eq!(rig.sets().unsent, count(2, two));
    rig.script.accept(5, 0);
    rig.script
        .until("a third frame", |seen| seen.frames.len() >= 3)
        .await;
    rig.settled().await;
    assert_eq!(rig.sets().uncertain, count(2, two));
    assert_eq!(rig.sets().unsent, count(1, FLOOR_FRAME as u64));
}

/// A frame costs its encoded size in the lane's bound: at the floor a frame of the most key bytes is
/// 1,024 encoded bytes, so exactly 256 of them fill 256 KiB.
#[tokio::test]
async fn a_frame_costs_its_encoded_size_in_the_bound() {
    let rig = floor_rig().await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for _ in 0..256 {
        rig.lane.try_send(&[b'x'; FLOOR_FRAME]).expect("admitted");
    }
    assert_eq!(
        rig.lane.try_send(b"x"),
        Err(InputRefusal::Full),
        "256 frames of 1,024 bytes leave no room"
    );
}

/// A write that finds no room in the connection's send queue waits for room and goes on: the frames
/// are unsent while it waits, they are written in order once room comes back, and the lane has not
/// ended.
#[tokio::test]
async fn a_write_that_finds_no_room_in_the_send_queue_waits_for_room() {
    let mut rig = rig(4).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    let room = rig.take_the_room().await;
    for number in 0..3 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.settled().await;
    assert_eq!(
        rig.sets().uncertain,
        count(0, 0),
        "a frame the transport refused before a byte went out was never written"
    );
    assert_eq!(rig.sets().unsent, count(3, 15));
    rig.lane
        .try_send(&key(3))
        .expect("the lane waits for room: it has not ended");
    drop(room);
    rig.script
        .until("the four frames", |seen| seen.frames.len() >= 4)
        .await;
    for (number, frame) in rig.script.frames().iter().enumerate() {
        assert_eq!(
            (frame.epoch, frame.sequence, frame.bytes.clone()),
            (5, number as u64, key(number as u64))
        );
    }
    rig.script.accept(5, 3);
    let accepted = rig.event().await;
    assert!(
        matches!(accepted, InputEvent::Accepted { frames: 4, .. }),
        "{accepted:?}"
    );
}

enum EndsBy {
    /// A new epoch begins while the writer waits.
    Superseded,
    /// The host's notice ends the epoch while the writer waits.
    Notice,
}

/// A frame whose epoch ended while the writer waited for room is not written once room comes back:
/// the check is made before each attempt, the one after the wait included.
async fn an_epoch_ends_while_the_writer_waits_for_room(how: EndsBy) {
    let mut rig = rig(4).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    let room = rig.take_the_room().await;
    rig.lane.try_send(&key(0)).expect("admitted");
    rig.settled().await;
    match how {
        EndsBy::Superseded => {
            rig.lane.begin_epoch(epoch(6)).expect("a new epoch");
            rig.lane
                .try_send(&key(100))
                .expect("admitted under epoch 6");
            drop(room);
            rig.settled().await;
        }
        EndsBy::Notice => {
            rig.script.epoch_ended(5, 0);
            rig.event_where(|event| matches!(event, InputEvent::EpochEnded { .. }))
                .await;
            drop(room);
            rig.settled().await;
            rig.lane.begin_epoch(epoch(6)).expect("a new epoch");
            rig.lane
                .try_send(&key(100))
                .expect("admitted under epoch 6");
        }
    }
    rig.script
        .until("the new epoch's frame", |seen| {
            seen.frames.iter().any(|frame| frame.epoch == 6)
        })
        .await;
    assert_eq!(
        rig.script.frames(),
        vec![SeenFrame {
            epoch: 6,
            sequence: 0,
            bytes: key(100),
        }],
        "the frame of the epoch that ended is never written"
    );
}

#[tokio::test]
async fn a_new_epoch_while_the_writer_waits_for_room_leaves_the_old_frame_unwritten() {
    an_epoch_ends_while_the_writer_waits_for_room(EndsBy::Superseded).await;
}

#[tokio::test]
async fn a_notice_while_the_writer_waits_for_room_leaves_the_frame_unwritten() {
    an_epoch_ends_while_the_writer_waits_for_room(EndsBy::Notice).await;
}

/// The stream ends as the host finishes its side of it, and the lane says so, apart from a reset.
#[tokio::test]
async fn the_host_finishing_its_side_ends_the_lane_as_finished() {
    let mut rig = rig(2).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..3 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.script
        .until("the window", |seen| seen.frames.len() >= 2)
        .await;
    rig.script.accept(5, 0);
    rig.script
        .until("a third frame", |seen| seen.frames.len() >= 3)
        .await;
    rig.settled().await;
    rig.script.say(Out::Finish);
    let event = rig
        .event_where(|event| matches!(event, InputEvent::Ended { .. }))
        .await;
    assert_eq!(
        event,
        InputEvent::Ended {
            epoch: Some(epoch(5)),
            cause: EndCause::Finished,
            sets: Some(Sets {
                accepted: count(1, 5),
                refused: count(0, 0),
                uncertain: count(2, 10),
                unsent: count(0, 0),
            }),
        }
    );
    assert_eq!(
        rig.lane.try_send(&key(9)),
        Err(InputRefusal::Over(Over::StreamEnded))
    );
}

/// A connection that ends with no refusal ends the lane as a connection that was lost, not as a
/// stream that was reset: the person is told of a lost connection.
#[tokio::test]
async fn a_connection_that_ends_with_no_refusal_ends_the_lane_as_a_connection() {
    let mut rig = rig(2).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..3 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.script
        .until("the window", |seen| seen.frames.len() >= 2)
        .await;
    rig.script.accept(5, 0);
    rig.script
        .until("a third frame", |seen| seen.frames.len() >= 3)
        .await;
    rig.settled().await;
    rig.session.close();
    let event = rig
        .event_where(|event| matches!(event, InputEvent::Ended { .. }))
        .await;
    assert_eq!(
        event,
        InputEvent::Ended {
            epoch: Some(epoch(5)),
            cause: EndCause::Connection { refusal: None },
            sets: Some(Sets {
                accepted: count(1, 5),
                refused: count(0, 0),
                uncertain: count(2, 10),
                unsent: count(0, 0),
            }),
        }
    );
}

/// The holder finishes the lane: it takes nothing more, every frame admitted is written, and the
/// stream ends as a finish the host reads, not as a reset that discards what it has not read.
#[tokio::test]
async fn finishing_the_lane_writes_every_frame_and_finishes_the_stream() {
    let rig = rig(2).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..5 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    rig.lane.finish();
    assert_eq!(
        rig.lane.try_send(&key(9)),
        Err(InputRefusal::Over(Over::StreamEnded)),
        "a finished lane takes nothing more"
    );
    assert_eq!(
        rig.lane.begin_epoch(epoch(6)),
        Err(InputRefusal::Over(Over::StreamEnded))
    );
    let mut accepted = 0;
    while accepted < 5 {
        rig.script
            .until("a frame to accept", |seen| seen.frames.len() > accepted)
            .await;
        rig.script.accept(5, accepted as u64);
        accepted += 1;
    }
    rig.script
        .until("the stream's end", |seen| {
            seen.finished_streams + seen.reset_streams >= 1
        })
        .await;
    assert_eq!(
        rig.script.seen(|seen| seen.finished_streams),
        1,
        "the host read a finish, not a reset"
    );
    assert_eq!(rig.script.frames().len(), 5, "every frame was written");
}

/* ---------------------------------------------------------------------------------------- */
/* Barriers                                                                                   */
/* ---------------------------------------------------------------------------------------- */

/// A barrier names every admitted frame, the queued ones included, and an empty one is reached at
/// once. A barrier the host does not reach in time is told as not reached.
#[tokio::test]
async fn a_barrier_is_reached_by_acceptance_and_times_out_by_its_own_bound() {
    let mut rig = rig(2).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    let empty = rig.lane.mark(Some(1)).expect("a barrier");
    assert_eq!(empty.count.get(), 0);
    assert_eq!(empty.launch, Nullable::some(1));
    assert_eq!(rig.event().await, InputEvent::Reached(empty));
    assert_eq!(rig.lane.discard_held(), Count::default());
    for number in 0..4 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    let barrier = rig.lane.mark(Some(2)).expect("a barrier");
    assert_eq!(
        barrier.count.get(),
        4,
        "the queued frames are in the prefix"
    );
    assert_eq!(barrier.attachment_id, attachment());
    assert_eq!(barrier.epoch, epoch(5));
    // The host accepts two of the four, and the lane's wait for the rest passes.
    rig.script
        .until("the window", |seen| seen.frames.len() >= 2)
        .await;
    rig.script.accept(5, 1);
    rig.script
        .until("two more", |seen| seen.frames.len() >= 4)
        .await;
    rig.event_where(|event| matches!(event, InputEvent::Accepted { .. }))
        .await;
    rig.deadlines.fire(DeadlineKind::Admission);
    assert_eq!(
        rig.event().await,
        InputEvent::NotReached {
            barrier: barrier.clone(),
            reason: NotReached::Timeout,
        }
    );
    // A later acceptance of the rest does not reach a barrier that was given up.
    rig.script.accept(5, 3);
    let mut told = rig.settled().await;
    while let Some(event) = rig.events.try_recv() {
        told.push(event);
    }
    assert!(!told.contains(&InputEvent::Reached(barrier)), "{told:?}");
}

/// A barrier is told as not reached when the epoch ends or the stream does, so that no wait is left
/// for ever.
#[tokio::test]
async fn a_barrier_is_not_reached_when_the_epoch_or_the_stream_ends() {
    let mut rig = rig(1).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..3 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    let barrier = rig.lane.mark(Some(1)).expect("a barrier");
    rig.script.epoch_ended(5, 0);
    let notice = rig
        .event_where(|event| matches!(event, InputEvent::EpochEnded { .. }))
        .await;
    assert!(matches!(notice, InputEvent::EpochEnded { .. }));
    assert_eq!(
        rig.event().await,
        InputEvent::NotReached {
            barrier,
            reason: NotReached::EpochEnded,
        }
    );
    rig.lane.begin_epoch(epoch(6)).expect("an epoch");
    rig.lane.try_send(&key(5)).expect("admitted");
    let barrier = rig.lane.mark(None).expect("a barrier");
    rig.script.say(Out::Reset);
    rig.event_where(|event| matches!(event, InputEvent::Ended { .. }))
        .await;
    assert_eq!(
        rig.event().await,
        InputEvent::NotReached {
            barrier,
            reason: NotReached::StreamEnded,
        }
    );
}

/* ---------------------------------------------------------------------------------------- */
/* The hold                                                                                   */
/* ---------------------------------------------------------------------------------------- */

/// A launch holds later typing without a sequence, counts it against the bound, and releases it in
/// order at the worker's marker for that launch. A marker for another launch releases nothing, and a
/// second launch while one waits is refused.
#[tokio::test]
async fn a_launch_holds_later_typing_until_its_own_marker() {
    let mut rig = rig(8).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    rig.lane.try_send(&key(0)).expect("admitted");
    let barrier = rig.lane.mark(Some(7)).expect("a barrier");
    assert_eq!(barrier.count.get(), 1);
    assert_eq!(
        rig.lane.mark(Some(8)),
        Err(InputRefusal::LaunchWaiting),
        "a launch is already waiting"
    );
    let held = rig.lane.try_send(&key(1)).expect("held");
    assert_eq!(held.sequence, None, "a held frame has no sequence");
    let pasted = rig.lane.try_send_paste(&bracketed(b"hi")).expect("held");
    assert!(pasted.iter().all(|writing| writing.sequence.is_none()));
    rig.script
        .until("the frame before the launch", |seen| {
            !seen.frames.is_empty()
        })
        .await;
    rig.script.accept(5, 0);
    rig.script.marker(6);
    let event = rig
        .event_where(|event| matches!(event, InputEvent::LaunchReserved { .. }))
        .await;
    assert_eq!(
        event,
        InputEvent::LaunchReserved {
            launch: 6,
            released: Count::default(),
        },
        "the marker of another launch releases nothing"
    );
    rig.settled().await;
    assert_eq!(rig.script.frames().len(), 1, "nothing was released");
    rig.script.marker(7);
    let event = rig
        .event_where(|event| matches!(event, InputEvent::LaunchReserved { launch: 7, .. }))
        .await;
    assert_eq!(
        event,
        InputEvent::LaunchReserved {
            launch: 7,
            released: count(2, 5 + 14),
        }
    );
    rig.script
        .until("the released frames", |seen| {
            seen.frames.len() >= 1 + 1 + pasted.len()
        })
        .await;
    let frames = rig.script.frames();
    let sequences: Vec<u64> = frames.iter().map(|frame| frame.sequence).collect();
    assert_eq!(sequences, (0..frames.len() as u64).collect::<Vec<_>>());
    assert_eq!(
        frames[1].bytes,
        key(1),
        "released in the order they were admitted"
    );
    // The hold is over: the next launch may be asked for and later typing is sequenced at once.
    let after = rig.lane.try_send(&key(2)).expect("admitted");
    assert_eq!(after.sequence, Some(sequence(frames.len() as u64)));
}

/// The caller's own end of the hold, the launch's definite answer, releases the held frames once;
/// a second call does nothing.
#[tokio::test]
async fn the_callers_release_gives_the_held_frames_their_sequences_once() {
    let mut rig = rig(8).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    rig.lane.mark(Some(1)).expect("a barrier");
    rig.lane.try_send(&key(0)).expect("held");
    rig.lane.try_send(&key(1)).expect("held");
    assert_eq!(rig.sets().unsent, count(2, 10), "held frames are unsent");
    assert_eq!(rig.lane.release_hold(1), count(2, 10));
    assert_eq!(rig.lane.release_hold(1), Count::default());
    rig.script
        .until("both frames", |seen| seen.frames.len() >= 2)
        .await;
    rig.accept_all(5, 2).await;
    let frames = rig.script.frames();
    assert_eq!((frames[0].sequence, frames[1].sequence), (0, 1));
}

/// A discard drops the unsequenced frames and ends the hold: the bytes are counted once, the next
/// key takes the next sequence with no gap, and the epoch goes on.
#[tokio::test]
async fn a_discard_counts_its_bytes_once_and_leaves_no_gap() {
    let mut rig = rig(8).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    rig.lane.try_send(&key(0)).expect("admitted");
    rig.lane.mark(Some(1)).expect("a barrier");
    rig.script
        .until("the frame before the launch", |seen| {
            !seen.frames.is_empty()
        })
        .await;
    for number in 1..4 {
        rig.lane.try_send(&key(number)).expect("held");
    }
    assert_eq!(rig.lane.discard_held(), count(3, 15));
    assert_eq!(rig.lane.discard_held(), Count::default(), "counted once");
    assert_eq!(rig.sets().unsent, Count::default(), "not counted again");
    let writing = rig.lane.try_send(&key(4)).expect("admitted");
    assert_eq!(writing.sequence, Some(sequence(1)), "no gap");
    rig.script.marker(1);
    rig.settled().await;
    rig.script
        .until("both frames", |seen| seen.frames.len() >= 2)
        .await;
    let frames = rig.script.frames();
    assert_eq!(frames[1].bytes, key(4));
    assert_eq!(frames[1].sequence, 1);
    // The epoch was kept: the host accepts the frames as they stand.
    rig.accept_all(5, 2).await;
    assert_eq!(rig.sets().accepted, count(2, 10));
}

/// The hold is bounded with everything else: held frames count against the lane's bound.
#[tokio::test]
async fn held_frames_count_against_the_bound() {
    let rig = rig(8).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    rig.lane.mark(Some(1)).expect("a barrier");
    for _ in 0..1_024 {
        rig.lane.try_send(b"x").expect("held");
    }
    assert_eq!(rig.lane.try_send(b"x"), Err(InputRefusal::Full));
    assert_eq!(rig.lane.discard_held(), count(1_024, 1_024));
    assert!(
        rig.lane.try_send(b"x").is_ok(),
        "room is back after the discard"
    );
}

/// A launch's answer can come after the next launch's hold began: the caller's release acts on the
/// hold of the launch it names, and leaves another launch's hold alone.
#[tokio::test]
async fn the_callers_release_acts_on_the_hold_of_its_own_launch() {
    let mut rig = rig(8).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    rig.lane.try_send(&key(0)).expect("admitted");
    rig.lane.mark(Some(1)).expect("a barrier");
    rig.lane.try_send(&key(1)).expect("held");
    rig.script.marker(1);
    rig.event_where(|event| matches!(event, InputEvent::LaunchReserved { launch: 1, .. }))
        .await;
    rig.script.accept(5, 1);
    rig.lane.mark(Some(2)).expect("a second launch");
    rig.lane
        .try_send(&key(2))
        .expect("held for the second launch");
    assert_eq!(
        rig.lane.release_hold(1),
        Count::default(),
        "the first launch's answer does not end the second launch's hold"
    );
    assert_eq!(rig.sets().unsent, count(1, 5), "the key is still held");
    assert_eq!(rig.lane.release_hold(2), count(1, 5));
}

/// A barrier that is given up leaves the hold as it is: the keys held for the launch go on being
/// held until the launch's marker, the caller's release or a discard.
#[tokio::test]
async fn a_barrier_that_times_out_leaves_the_hold_in_place() {
    let mut rig = rig(2).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    rig.lane.try_send(&key(0)).expect("admitted");
    let barrier = rig.lane.mark(Some(7)).expect("a barrier");
    rig.lane.try_send(&key(1)).expect("held");
    rig.script
        .until("the frame", |seen| !seen.frames.is_empty())
        .await;
    rig.deadlines.fire(DeadlineKind::Admission);
    assert_eq!(
        rig.event().await,
        InputEvent::NotReached {
            barrier,
            reason: NotReached::Timeout,
        }
    );
    let later = rig.lane.try_send(&key(2)).expect("still held");
    assert_eq!(later.sequence, None, "the hold stands after the timeout");
    assert_eq!(rig.sets().unsent, count(2, 10));
    rig.script.marker(7);
    let released = rig
        .event_where(|event| matches!(event, InputEvent::LaunchReserved { launch: 7, .. }))
        .await;
    assert_eq!(
        released,
        InputEvent::LaunchReserved {
            launch: 7,
            released: count(2, 10),
        }
    );
}

/// A new epoch ends a barrier that is waiting: it is told as not reached, at once.
#[tokio::test]
async fn a_barrier_is_not_reached_when_a_new_epoch_begins() {
    let mut rig = rig(1).await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    for number in 0..2 {
        rig.lane.try_send(&key(number)).expect("admitted");
    }
    let barrier = rig.lane.mark(Some(1)).expect("a barrier");
    rig.lane.begin_epoch(epoch(6)).expect("a new epoch");
    assert_eq!(
        rig.events.try_recv(),
        Some(InputEvent::NotReached {
            barrier,
            reason: NotReached::Superseded,
        })
    );
}

/// A discard gives back the room that the held frames took, the bytes as well as the frames.
#[tokio::test]
async fn a_discard_gives_back_the_bytes_of_the_held_frames() {
    let rig = floor_rig().await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    rig.lane.mark(Some(1)).expect("a barrier");
    let paste = text_of(rig.lane.paste_capacity());
    rig.lane.try_send_paste(&paste).expect("held");
    assert_eq!(
        rig.lane.try_send_paste(&paste),
        Err(InputRefusal::NotNow),
        "the held paste took the room"
    );
    rig.lane.discard_held();
    assert!(
        rig.lane.try_send_paste(&paste).is_ok(),
        "the room is back after the discard"
    );
}

/// A cut never falls inside the start delimiter either.
#[tokio::test]
async fn a_cut_never_falls_inside_the_start_delimiter() {
    let mut rig = floor_rig().await;
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    let mut paste = vec![b'a'; FLOOR_FRAME - 3];
    paste.extend_from_slice(PASTE_START);
    paste.extend_from_slice(&[b'b'; 20]);
    let written = rig.lane.try_send_paste(&paste).expect("admitted");
    assert_eq!(
        written[0].bytes,
        FLOOR_FRAME - 3,
        "the cut moved before the delimiter"
    );
    rig.accept_all(5, written.len()).await;
    assert!(rig.script.frames()[1].bytes.starts_with(PASTE_START));
}

/// What a hold's end counts and what nothing releases afterwards, four ways, each with the two
/// sequences that make the fault visible. After any ending, neither the caller's release nor the
/// launch's late marker writes a key that was held, whatever epoch is current.
mod the_hold_ends {
    use super::*;

    /// A hold of two keys under epoch 5, a launch numbered 3, and one key already written.
    async fn holding() -> Rig {
        let mut rig = rig(8).await;
        rig.lane.begin_epoch(epoch(5)).expect("an epoch");
        rig.lane.try_send(&key(0)).expect("admitted");
        rig.lane.mark(Some(3)).expect("a barrier");
        rig.lane.try_send(&key(1)).expect("held");
        rig.lane.try_send(&key(2)).expect("held");
        rig.script
            .until("the key before the launch", |seen| !seen.frames.is_empty())
            .await;
        rig.settled().await;
        rig
    }

    /// Nothing but what the case expects was written, and neither the caller's release nor a marker
    /// for the hold's launch changes that.
    async fn nothing_held_is_written(rig: &mut Rig, written: usize) {
        assert_eq!(
            rig.lane.release_hold(3),
            Count::default(),
            "the release does nothing"
        );
        rig.script.marker(3);
        rig.settled().await;
        assert_eq!(
            rig.script.frames().len(),
            written,
            "the held keys were never written: {:?}",
            rig.script.frames()
        );
    }

    /// The host's notice that the epoch ended ends the hold. Sequence 1: another view types and the
    /// view takes the lease again under a later epoch, then the stale marker and release arrive:
    /// the held keys are not written under the later epoch.
    #[tokio::test]
    async fn the_notice_that_the_epoch_ended() {
        let mut rig = holding().await;
        rig.script.epoch_ended(5, 0);
        let event = rig
            .event_where(|event| matches!(event, InputEvent::EpochEnded { .. }))
            .await;
        let InputEvent::EpochEnded { sets, .. } = event else {
            unreachable!();
        };
        let sets = sets.expect("the event froze the epoch");
        assert_eq!(
            sets.unsent,
            count(2, 10),
            "the held keys are counted unsent"
        );
        assert_eq!(sets.uncertain, count(1, 5));
        assert_eq!(
            rig.lane.release_hold(3),
            Count::default(),
            "the notice ended the hold, whatever epoch comes next"
        );
        rig.lane.begin_epoch(epoch(7)).expect("a later epoch");
        rig.lane
            .try_send(&key(9))
            .expect("admitted under the later epoch");
        rig.script
            .until("the later epoch's key", |seen| seen.frames.len() >= 2)
            .await;
        nothing_held_is_written(&mut rig, 2).await;
        let frames = rig.script.frames();
        assert_eq!((frames[1].epoch, frames[1].sequence), (7, 0));
        assert_eq!(frames[1].bytes, key(9));
    }

    /// A new epoch ends the hold. Sequence 1: the later epoch's keys carry its own sequences from 0.
    /// Sequence 2: the stale release and marker write nothing.
    #[tokio::test]
    async fn a_new_epoch() {
        let mut rig = holding().await;
        let ended = rig.lane.begin_epoch(epoch(6)).expect("a new epoch");
        let ended = ended.expect("the old epoch ended");
        assert_eq!(
            ended.unsent,
            count(2, 10),
            "the held keys are counted unsent"
        );
        assert_eq!(ended.uncertain, count(1, 5));
        rig.lane.try_send(&key(9)).expect("admitted");
        rig.script
            .until("the new epoch's key", |seen| seen.frames.len() >= 2)
            .await;
        nothing_held_is_written(&mut rig, 2).await;
        let frames = rig.script.frames();
        assert_eq!((frames[1].epoch, frames[1].sequence), (6, 0));
    }

    /// The stream's end ends the hold. Sequence 2: the lane takes nothing more, and a release writes
    /// nothing.
    #[tokio::test]
    async fn the_streams_end() {
        let mut rig = holding().await;
        rig.script.say(Out::Reset);
        let event = rig
            .event_where(|event| matches!(event, InputEvent::Ended { .. }))
            .await;
        let InputEvent::Ended { sets, .. } = event else {
            unreachable!();
        };
        let sets = sets.expect("the event froze the epoch");
        assert_eq!(
            sets.unsent,
            count(2, 10),
            "the held keys are counted unsent"
        );
        assert_eq!(rig.lane.release_hold(3), Count::default());
        assert_eq!(
            rig.lane.try_send(&key(9)),
            Err(InputRefusal::Over(Over::StreamEnded))
        );
        assert_eq!(rig.script.frames().len(), 1);
    }

    /// The mark of a release or a detach ends the hold. Sequence 2, the review's: keys that were
    /// held when the person released control are not written after the release's barrier, not by the
    /// caller's release and not by a late marker, and typing after the barrier is refused.
    #[tokio::test]
    async fn the_mark_of_a_release_or_a_detach() {
        let mut rig = holding().await;
        let barrier = rig.lane.mark(None).expect("the release's barrier");
        assert_eq!(
            barrier.count.get(),
            1,
            "the barrier names the sequenced prefix only"
        );
        assert_eq!(
            rig.sets().unsent,
            count(2, 10),
            "the held keys are counted unsent"
        );
        assert_eq!(rig.lane.try_send(&key(9)), Err(InputRefusal::Ending));
        assert_eq!(rig.lane.mark(None), Err(InputRefusal::Ending));
        rig.script.accept(5, 0);
        rig.event_where(|event| matches!(event, InputEvent::Reached(_)))
            .await;
        nothing_held_is_written(&mut rig, 1).await;
        assert_eq!(rig.sets().accepted, count(1, 5));
        assert_eq!(rig.sets().unsent, count(2, 10));
    }
}

/// A launch that is asked for when no epoch has begun, or that has ended, is refused.
#[tokio::test]
async fn nothing_is_marked_without_a_live_epoch() {
    let rig = rig(2).await;
    assert_eq!(rig.lane.mark(Some(1)), Err(InputRefusal::NoEpoch));
    assert_eq!(rig.lane.try_send(&key(0)), Err(InputRefusal::NoEpoch));
    rig.lane.begin_epoch(epoch(5)).expect("an epoch");
    assert_eq!(
        rig.lane.begin_epoch(epoch(5)),
        Err(InputRefusal::EpochNotNew)
    );
    assert_eq!(rig.lane.try_send(&[]), Err(InputRefusal::Empty));
}

/* ---------------------------------------------------------------------------------------- */
/* The local carrier                                                                          */
/* ---------------------------------------------------------------------------------------- */

mod local {
    use super::*;
    use kr_protocol::input::{InputContent, InputWriteParams, InputWriteResult};

    /// What the scripted local host did, in the order it did it.
    #[derive(Default)]
    struct Ledger {
        order: Vec<String>,
        writes: Vec<(u64, u64, Vec<u8>)>,
    }

    /// A transport to a host on this machine: no data streams, one connection, requests answered by
    /// the case.
    #[derive(Debug)]
    struct Socket {
        sent: Mutex<VecDeque<ControlFrame>>,
        changed: tokio::sync::Notify,
        words: tokio::sync::mpsc::UnboundedSender<ControlFrame>,
        incoming: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<ControlFrame>>>,
        claimed: AtomicBool,
    }

    impl Socket {
        fn new() -> Arc<Self> {
            let (words, incoming) = tokio::sync::mpsc::unbounded_channel();
            Arc::new(Self {
                sent: Mutex::new(VecDeque::new()),
                changed: tokio::sync::Notify::new(),
                words,
                incoming: Mutex::new(Some(incoming)),
                claimed: AtomicBool::new(false),
            })
        }

        /// Waits for the next request the client wrote, as the host reads it.
        async fn next_write(&self) -> (RequestId, InputWriteParams) {
            tokio::time::timeout(LIVENESS, async {
                loop {
                    let changed = self.changed.notified();
                    tokio::pin!(changed);
                    changed.as_mut().enable();
                    if let Some(ControlFrame::Request(request)) =
                        self.sent.lock().expect("sent").pop_front()
                    {
                        let params = request.params.to_typed().expect("input.write's params");
                        return (request.request_id, params);
                    }
                    changed.await;
                }
            })
            .await
            .expect("the client wrote a request")
        }

        fn accept(&self, request_id: RequestId) {
            let result = InputWriteResult {
                sequence: sequence(0),
                forwarded_bytes: U64::new(0),
                held_prefix_bytes: U64::new(0),
            };
            self.words
                .send(answer(request_id, typed(&result)))
                .expect("the reader");
        }

        fn refuse(&self, request_id: RequestId, error: ProtocolError) {
            self.words
                .send(answer(request_id, Err(error)))
                .expect("the reader");
        }

        /// The host's word on the connection itself: it refuses the connection, and every call that
        /// waits is answered with the same refusal.
        fn withdraw(&self, error: ProtocolError) {
            self.refuse(RequestId::new(0), error);
        }
    }

    impl ControlTransport for Socket {
        fn connection_id(&self) -> ConnectionId {
            ConnectionId::new(Uuid::from_bytes([5; 16]))
        }
        fn limits(&self) -> ReceiveLimits {
            ReceiveLimits::default()
        }
        fn initial_action_window(&self) -> ActionWindow {
            ActionWindow {
                action_window_id: kr_protocol::ids::ActionWindowId::new("window-1").expect("id"),
                connection_id: self.connection_id(),
                boot_epoch: BootEpoch::new(1),
                issued_at_ms: kr_protocol::scalars::TimestampMs::new(0),
                valid_for_ms: kr_protocol::scalars::DurationMs::new(60_000),
            }
        }
        fn ended_by_this_device(&self) -> Option<kr_client::transport::DeviceEnd> {
            None
        }
        fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
            self.sent.lock().expect("sent").push_back(frame.clone());
            self.changed.notify_waiters();
            Box::pin(async { Ok(()) })
        }
        fn claim_receiver(&self) -> kr_client::Result<()> {
            if self.claimed.swap(true, Ordering::AcqRel) {
                return Err(ClientError::ConnectionEnded);
            }
            Ok(())
        }
        fn stream_opener(&self) -> Option<Arc<dyn StreamOpener>> {
            None
        }
        fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
            let mut incoming = self
                .incoming
                .lock()
                .expect("incoming")
                .take()
                .expect("one reader");
            Box::pin(async move {
                let frame = incoming.recv().await;
                *self.incoming.lock().expect("incoming") = Some(incoming);
                Ok(frame)
            })
        }
        fn revoke_streams(&self) {}
        fn close(&self) {}
    }

    async fn local_lane(states_input_lane: bool) -> (Arc<Socket>, Session, InputLane, InputEvents) {
        let socket = Socket::new();
        let session =
            Session::start(Arc::clone(&socket) as Arc<dyn ControlTransport>).expect("a session");
        let target = InputTarget::new(environment(), session_id(), attachment())
            .worker_states_input_lane(states_input_lane);
        let lane = within(session.input_lane(target)).await.expect("a lane");
        let events = lane.events().expect("events");
        (socket, session, lane, events)
    }

    async fn event(events: &mut InputEvents) -> InputEvent {
        within(events.recv()).await.expect("an event")
    }

    /// Typing goes as ordered `input.write` requests, one at a time, each answered before the next
    /// is written, and each answer is an acceptance.
    #[tokio::test]
    async fn typing_goes_as_ordered_requests_one_at_a_time() {
        let (socket, session, lane, mut events) = local_lane(false).await;
        lane.begin_epoch(epoch(5)).expect("an epoch");
        for number in 0..3 {
            lane.try_send(&key(number)).expect("admitted");
        }
        let (first, params) = socket.next_write().await;
        assert_eq!((params.epoch, params.sequence), (epoch(5), sequence(0)));
        assert!(
            socket.sent.lock().expect("sent").is_empty(),
            "the second is not written until the first is answered"
        );
        socket.accept(first);
        for number in 0..3_u64 {
            if number > 0 {
                let (request, params) = socket.next_write().await;
                assert_eq!(params.sequence, sequence(number));
                assert!(
                    matches!(&params.input, InputContent::Bytes { bytes } if bytes.as_slice() == key(number)),
                    "bytes in order"
                );
                socket.accept(request);
            }
            let accepted = event(&mut events).await;
            assert!(
                matches!(accepted, InputEvent::Accepted { through, frames: 1, .. } if through == sequence(number)),
                "{accepted:?}"
            );
        }
        assert!(!lane.fenced_report());
        session.close();
    }

    /// A request that must follow the typing runs once every earlier key is answered and before any
    /// later one is written.
    #[tokio::test]
    async fn ordered_work_runs_behind_earlier_keys_and_ahead_of_later_ones() {
        let (socket, session, lane, mut events) = local_lane(true).await;
        assert!(lane.fenced_report(), "the worker states the input lane");
        lane.begin_epoch(epoch(5)).expect("an epoch");
        let ledger = Arc::new(Mutex::new(Ledger::default()));
        lane.try_send(&key(0)).expect("admitted");
        let note = Arc::clone(&ledger);
        let answer = lane
            .after_keys(move |sent| async move {
                note.lock().expect("ledger").order.push("launch".to_owned());
                sent.sent();
                7_u32
            })
            .expect("queued");
        lane.try_send(&key(1)).expect("admitted");
        let barrier = lane.mark(Some(1)).expect("a barrier");
        assert_eq!(barrier.count.get(), 2, "a local launch holds nothing");
        let later = lane.try_send(&key(2)).expect("admitted");
        assert_eq!(
            later.sequence,
            Some(sequence(2)),
            "later typing is sequenced at once"
        );
        for number in 0..3_u64 {
            let (request, params) = socket.next_write().await;
            ledger.lock().expect("ledger").writes.push((
                params.sequence.get(),
                number,
                params.input_bytes(),
            ));
            ledger
                .lock()
                .expect("ledger")
                .order
                .push(format!("key{}", params.sequence.get()));
            socket.accept(request);
            event(&mut events).await;
        }
        let order = ledger.lock().expect("ledger").order.clone();
        assert_eq!(order, ["key0", "launch", "key1", "key2"]);
        assert_eq!(
            within(answer).await,
            Ok(7),
            "the answer comes back on a channel"
        );
        session.close();
    }

    /// A definite refusal ends the epoch and is a refusal; an answer that does not say whether the
    /// write was accepted ends the lane with the frame uncertain.
    #[tokio::test]
    async fn refusals_are_classed_as_a_stream_adapter_classes_them() {
        let (socket, session, lane, mut events) = local_lane(false).await;
        lane.begin_epoch(epoch(5)).expect("an epoch");
        lane.try_send(&key(0)).expect("admitted");
        let (request, _) = socket.next_write().await;
        socket.refuse(request, ProtocolError::new(ErrorCode::LeaseLost, "lost"));
        let refused = event(&mut events).await;
        assert!(
            matches!(
                refused,
                InputEvent::Refused {
                    sets: Sets {
                        refused: Count { frames: 1, .. },
                        ..
                    },
                    ..
                }
            ),
            "{refused:?}"
        );
        lane.begin_epoch(epoch(6)).expect("an epoch");
        lane.try_send(&key(1)).expect("admitted");
        let (request, _) = socket.next_write().await;
        let mut marked = ProtocolError::new(ErrorCode::PermissionDenied, "fenced");
        marked.link_fenced = true;
        socket.refuse(request, marked);
        let ended = event(&mut events).await;
        assert!(
            matches!(
                ended,
                InputEvent::Ended {
                    cause: EndCause::Uncertain(_),
                    sets: Some(Sets {
                        uncertain: Count { frames: 1, .. },
                        ..
                    }),
                    ..
                }
            ),
            "{ended:?}"
        );
        session.close();
    }

    /// What the lane tells of one frame that the local host answers with `error`.
    async fn told_of_a_refusal(error: ProtocolError) -> InputEvent {
        let (socket, session, lane, mut events) = local_lane(false).await;
        lane.begin_epoch(epoch(5)).expect("an epoch");
        lane.try_send(&key(0)).expect("admitted");
        let (request, _) = socket.next_write().await;
        socket.refuse(request, error);
        let told = event(&mut events).await;
        session.close();
        told
    }

    /// Every code that a stream adapter classes as a refusal before acceptance is a refusal; the
    /// marked form of `PermissionDenied` and every other code leave the frame uncertain.
    #[tokio::test]
    async fn every_class_of_refusal_is_told_as_the_stream_adapter_tells_it() {
        for code in [
            ErrorCode::LeaseLost,
            ErrorCode::InvalidArgument,
            ErrorCode::SessionClosed,
            ErrorCode::ResourceUnavailable,
            ErrorCode::PermissionDenied,
        ] {
            let told = told_of_a_refusal(ProtocolError::new(code, "refused")).await;
            assert!(
                matches!(told, InputEvent::Refused { .. }),
                "{code:?} is a refusal: {told:?}"
            );
        }
        let told =
            told_of_a_refusal(ProtocolError::new(ErrorCode::UnsupportedCapability, "no")).await;
        assert!(
            matches!(
                told,
                InputEvent::Ended {
                    cause: EndCause::Uncertain(_),
                    ..
                }
            ),
            "{told:?}"
        );
    }

    /// The host refused the connection: the pending write is answered with that refusal, which says
    /// nothing of the frame. The lane ends with the refusal and counts the frame uncertain, not refused.
    #[tokio::test]
    async fn a_connections_refusal_is_read_before_a_pending_answer_counts_as_a_frames() {
        let (socket, session, lane, mut events) = local_lane(false).await;
        lane.begin_epoch(epoch(5)).expect("an epoch");
        lane.try_send(&key(0)).expect("admitted");
        socket.next_write().await;
        socket.withdraw(ProtocolError::new(
            ErrorCode::PermissionDenied,
            "the connection was withdrawn",
        ));
        let told = event(&mut events).await;
        let InputEvent::Ended { cause, sets, .. } = told else {
            panic!("the lane ends with the connection's refusal, not {told:?}");
        };
        assert!(
            matches!(cause, EndCause::Connection { refusal: Some(_) }),
            "{cause:?}"
        );
        let sets = sets.expect("the end froze the epoch");
        assert_eq!(sets.uncertain, count(1, 5));
        assert_eq!(sets.refused, count(0, 0));
        session.close();
    }

    /// Ordered requests are not typing: one that is queued behind a key that the host then refuses is
    /// still sent, and a request can still be queued after the refusal.
    #[tokio::test]
    async fn a_queued_request_outlives_a_refused_key() {
        let (socket, session, lane, mut events) = local_lane(false).await;
        lane.begin_epoch(epoch(5)).expect("an epoch");
        lane.try_send(&key(0)).expect("admitted");
        let ran = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        let first = lane
            .after_keys(move |sent| async move {
                flag.store(true, Ordering::SeqCst);
                sent.sent();
            })
            .expect("queued");
        let (request, _) = socket.next_write().await;
        socket.refuse(request, ProtocolError::new(ErrorCode::LeaseLost, "lost"));
        let refused = event(&mut events).await;
        assert!(matches!(refused, InputEvent::Refused { .. }), "{refused:?}");
        within(first).await.expect("the request ran");
        assert!(ran.load(Ordering::SeqCst));
        let second = lane
            .after_keys(|sent| async move {
                sent.sent();
            })
            .expect("a request can be queued after the refusal");
        within(second).await.expect("the second request ran");
        session.close();
    }

    /// A request that is on the connection lets the next key go: a launch holds no later typing
    /// while it waits for its answer.
    #[tokio::test]
    async fn a_request_that_is_sent_holds_no_later_key_for_its_answer() {
        let (socket, session, lane, mut events) = local_lane(false).await;
        lane.begin_epoch(epoch(5)).expect("an epoch");
        let (finish, finished) = tokio::sync::oneshot::channel::<u32>();
        let answer = lane
            .after_keys(move |sent| async move {
                sent.sent();
                finished.await.unwrap_or(0)
            })
            .expect("queued");
        lane.try_send(&key(0)).expect("admitted");
        let (request, params) = socket.next_write().await;
        assert_eq!(
            params.input_bytes(),
            key(0),
            "the key is written while the request waits for its answer"
        );
        socket.accept(request);
        let accepted = event(&mut events).await;
        assert!(
            matches!(accepted, InputEvent::Accepted { .. }),
            "{accepted:?}"
        );
        finish.send(9).expect("the request waits");
        assert_eq!(within(answer).await, Ok(9));
        session.close();
    }

    /// Ordered work belongs to a local lane.
    #[tokio::test]
    async fn a_network_lane_takes_no_ordered_work() {
        let rig = rig(2).await;
        rig.lane.begin_epoch(epoch(5)).expect("an epoch");
        assert_eq!(
            rig.lane.after_keys(|_| async {}).err(),
            Some(InputRefusal::NotLocal)
        );
        assert!(!rig.lane.fenced_report(), "a paired host sets it itself");
    }

    trait InputBytes {
        fn input_bytes(&self) -> Vec<u8>;
    }

    impl InputBytes for InputWriteParams {
        fn input_bytes(&self) -> Vec<u8> {
            match &self.input {
                InputContent::Bytes { bytes } => bytes.as_slice().to_vec(),
                InputContent::ConsoleKeys { .. } => Vec::new(),
            }
        }
    }
}
