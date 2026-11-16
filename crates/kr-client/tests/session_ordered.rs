//! A session started for an ordered delivery, the whole write of a close, and what a dropped call
//! leaves, over a connection that this test scripts frame by frame.
//!
//! The stand-in connection is read by the session's one reader: the test feeds it frames, failures
//! and an end, counts what the reader took, and holds a write where a case needs a call to stop
//! inside it.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_client::error::ClientError;
use kr_client::input::{InputEvent, InputTarget};
use kr_client::ordered::{Ended, Ordered, OrderedEvents};
use kr_client::session::{ComposedMutation, Session};
use kr_client::transport::{ControlTransport, StreamOpener, TransportFuture};
use kr_protocol::envelope::{
    ActionTarget, ControlFrame, Notification, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::hello::{ActionWindow, ReceiveLimits};
use kr_protocol::ids::{
    ActionId, ActionWindowId, AttachmentId, BootEpoch, ConnectionId, EnvironmentId, EventSequence,
    EventType, InputLeaseEpoch, InputSequence, RequestId, SessionId, StreamId,
};
use kr_protocol::input::InputWriteResult;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{DurationMs, TimestampMs, U64, Uuid};
use tokio::sync::{Notify, mpsc};

/// How long a case waits for something that must happen before it takes the call for hung.
const LIVENESS: Duration = Duration::from_secs(5);

/// How long a case lets a reader that must stay still show that it did.
const STILL: Duration = Duration::from_millis(300);

async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIVENESS, future)
        .await
        .expect("the step ended in time")
}

#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SessionList {
    count: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct Empty {}

/* ---------------------------------------------------------------------------------------- */
/* The stand-in connection                                                                    */
/* ---------------------------------------------------------------------------------------- */

enum Incoming {
    Frame(ControlFrame),
    Fail(ClientError),
    End,
}

struct Scripted {
    feed: mpsc::UnboundedSender<Incoming>,
    incoming: tokio::sync::Mutex<mpsc::UnboundedReceiver<Incoming>>,
    /// Frames the session's reader has taken from the connection.
    read: AtomicUsize,
    /// Frames the client wrote whole.
    sent: Mutex<Vec<ControlFrame>>,
    changed: Notify,
    /// What happened to the connection, in order: "sent" for each frame written whole, "closed".
    log: Mutex<Vec<&'static str>>,
    /// While set, a write stops before it writes anything.
    park_writes: AtomicBool,
    entered: Notify,
    freed: Notify,
    closed: AtomicBool,
    claimed: AtomicBool,
    /// What runs once, inside the read that returns the next scripted failure, just before that
    /// read returns: the owner's close that follows a failure the read already has.
    after_a_failed_read: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl std::fmt::Debug for Scripted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Scripted").finish_non_exhaustive()
    }
}

impl Scripted {
    fn new() -> Arc<Self> {
        let (feed, incoming) = mpsc::unbounded_channel();
        Arc::new(Self {
            feed,
            incoming: tokio::sync::Mutex::new(incoming),
            read: AtomicUsize::new(0),
            sent: Mutex::new(Vec::new()),
            changed: Notify::new(),
            log: Mutex::new(Vec::new()),
            park_writes: AtomicBool::new(false),
            entered: Notify::new(),
            freed: Notify::new(),
            closed: AtomicBool::new(false),
            claimed: AtomicBool::new(false),
            after_a_failed_read: Mutex::new(None),
        })
    }

    /// Runs `hook` inside the read that returns the next scripted failure, right before it returns.
    fn after_a_failed_read(&self, hook: impl FnOnce() + Send + 'static) {
        *self.after_a_failed_read.lock().expect("hook") = Some(Box::new(hook));
    }

    fn feed(&self, frame: ControlFrame) {
        self.feed.send(Incoming::Frame(frame)).expect("the reader");
    }

    fn fail(&self, error: ClientError) {
        self.feed.send(Incoming::Fail(error)).expect("the reader");
    }

    fn finish(&self) {
        self.feed.send(Incoming::End).expect("the reader");
    }

    fn read_count(&self) -> usize {
        self.read.load(Ordering::Acquire)
    }

    fn log(&self) -> Vec<&'static str> {
        self.log.lock().expect("log").clone()
    }

    fn written(&self) -> usize {
        self.sent.lock().expect("sent").len()
    }

    /// The next writes stop before they write.
    fn park(&self) {
        self.park_writes.store(true, Ordering::Release);
    }

    /// Lets the parked writes go.
    fn unpark(&self) {
        self.park_writes.store(false, Ordering::Release);
        self.freed.notify_waiters();
    }

    /// Waits until a write has reached the stop.
    async fn write_entered(&self) {
        within(self.entered.notified()).await;
    }

    /// Waits until `count` frames were written whole, and returns the identifier of the last.
    async fn written_at_least(&self, count: usize) -> RequestId {
        within(async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                {
                    let sent = self.sent.lock().expect("sent");
                    if sent.len() >= count {
                        return request_id_of(sent.last().expect("a frame"));
                    }
                }
                changed.await;
            }
        })
        .await
    }
}

fn request_id_of(frame: &ControlFrame) -> RequestId {
    match frame {
        ControlFrame::Request(request) => request.request_id,
        ControlFrame::Mutation(request) => request.request_id,
        _ => panic!("the client wrote a frame that is no request"),
    }
}

impl ControlTransport for Scripted {
    fn connection_id(&self) -> ConnectionId {
        ConnectionId::new(Uuid::from_bytes([5; 16]))
    }

    fn limits(&self) -> ReceiveLimits {
        ReceiveLimits::default()
    }

    fn initial_action_window(&self) -> ActionWindow {
        ActionWindow {
            action_window_id: ActionWindowId::new("window-1").expect("a window"),
            connection_id: self.connection_id(),
            boot_epoch: BootEpoch::new(1),
            issued_at_ms: TimestampMs::new(0),
            valid_for_ms: DurationMs::new(60_000),
        }
    }

    fn ended_by_this_device(&self) -> Option<kr_client::transport::DeviceEnd> {
        None
    }

    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
        Box::pin(async move {
            if self.closed.load(Ordering::Acquire) {
                return Err(ClientError::ConnectionEnded);
            }
            if self.park_writes.load(Ordering::Acquire) {
                let freed = self.freed.notified();
                tokio::pin!(freed);
                freed.as_mut().enable();
                self.entered.notify_one();
                freed.await;
            }
            self.sent.lock().expect("sent").push(frame.clone());
            self.log.lock().expect("log").push("sent");
            self.changed.notify_waiters();
            Ok(())
        })
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
        Box::pin(async move {
            let mut incoming = self.incoming.lock().await;
            match incoming.recv().await {
                Some(Incoming::Frame(frame)) => {
                    self.read.fetch_add(1, Ordering::AcqRel);
                    Ok(Some(frame))
                }
                Some(Incoming::Fail(error)) => {
                    let hook = self.after_a_failed_read.lock().expect("hook").take();
                    if let Some(hook) = hook {
                        hook();
                    }
                    Err(error)
                }
                Some(Incoming::End) | None => Ok(None),
            }
        })
    }

    fn revoke_streams(&self) {}

    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.log.lock().expect("log").push("closed");
        }
        let _ = self.feed.send(Incoming::End);
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/* ---------------------------------------------------------------------------------------- */
/* Frames                                                                                     */
/* ---------------------------------------------------------------------------------------- */

fn stream(name: &str) -> StreamId {
    StreamId::new(name).expect("a stream identifier")
}

fn notice(name: &str, sequence: u64) -> ControlFrame {
    ControlFrame::Notification(Notification {
        stream_id: stream(name),
        sequence: EventSequence::new(sequence),
        event_type: EventType::new("terminal.output").expect("an event type"),
        payload: ParamsValue::empty(),
    })
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

fn typed<T: serde::Serialize>(value: &T) -> ParamsValue {
    ParamsValue::from_typed(value).expect("encodes")
}

fn environment() -> EnvironmentId {
    EnvironmentId::new(Uuid::from_bytes([7; 16]))
}

fn session_id() -> SessionId {
    SessionId::new(Uuid::from_bytes([8; 16]))
}

fn attachment() -> AttachmentId {
    AttachmentId::new(Uuid::from_bytes([9; 16]))
}

/// A real mutation composed on this session, as a release, a detach or a launch is.
async fn composed(session: &Session, number: u8) -> ComposedMutation {
    session
        .compose(
            Method::SessionCreate,
            ActionId::new(Uuid::from_bytes([number; 16])),
            ActionTarget::environment(environment()),
            None,
            &Empty {},
            &Empty {},
            DurationMs::new(120_000),
        )
        .await
        .expect("a composed mutation")
}

/* ---------------------------------------------------------------------------------------- */
/* What the owner reads                                                                       */
/* ---------------------------------------------------------------------------------------- */

/// The next item, which must be a notification: its stream and its sequence.
async fn next_notice(events: &mut OrderedEvents) -> (StreamId, u64) {
    let item = tokio::time::timeout(LIVENESS, events.recv()).await;
    assert!(item.is_ok(), "a notification was due and never came");
    match item.ok().flatten() {
        Some(Ordered::Notification(notification)) => {
            (notification.stream_id, notification.sequence.get())
        }
        Some(Ordered::Ended(_)) => panic!("the session ended where a notification was due"),
        None => panic!("the channel closed where a notification was due"),
    }
}

/// The channel's end, which comes right after the session's end.
async fn the_channel_ends(events: &mut OrderedEvents) {
    let item = tokio::time::timeout(LIVENESS, events.recv()).await;
    assert!(item.is_ok(), "the channel stayed open after the end");
    assert!(item.ok().flatten().is_none(), "an item came after the end");
}

/// Waits until the session's reader has taken `count` frames from the connection.
async fn reader_has_taken(transport: &Scripted, count: usize) {
    within(async {
        while transport.read_count() < count {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

async fn next_end(events: &mut OrderedEvents) -> Ended {
    let item = tokio::time::timeout(LIVENESS, events.recv()).await;
    assert!(item.is_ok(), "the end never came");
    match item.ok().flatten() {
        Some(Ordered::Ended(ended)) => ended,
        Some(Ordered::Notification(_)) => panic!("a notification came where the end was due"),
        None => panic!("the channel closed where the end was due"),
    }
}

fn ordered(capacity: usize) -> (Arc<Scripted>, Arc<Session>, OrderedEvents) {
    let transport = Scripted::new();
    let (session, events) = Session::start_ordered(
        Arc::clone(&transport) as Arc<dyn ControlTransport>,
        capacity,
    )
    .expect("an ordered session");
    (transport, Arc::new(session), events)
}

fn plain() -> (Arc<Scripted>, Arc<Session>) {
    let transport = Scripted::new();
    let session =
        Session::start(Arc::clone(&transport) as Arc<dyn ControlTransport>).expect("a session");
    (transport, Arc::new(session))
}

/* ---------------------------------------------------------------------------------------- */
/* The ordered delivery                                                                       */
/* ---------------------------------------------------------------------------------------- */

#[tokio::test]
async fn notifications_of_two_streams_arrive_in_the_order_the_host_sent_them() {
    let (transport, _session, mut events) = ordered(8);
    let wire = [("a", 0), ("b", 0), ("a", 1), ("b", 1), ("a", 2)];
    for (name, sequence) in wire {
        transport.feed(notice(name, sequence));
    }
    for (name, sequence) in wire {
        assert_eq!(next_notice(&mut events).await, (stream(name), sequence));
    }
}

#[tokio::test]
async fn a_delivery_that_starts_again_at_zero_reaches_the_owner_whole() {
    let (transport, _session, mut events) = ordered(16);
    let wire = [0, 1, 2, 3, 0, 1];
    for sequence in wire {
        transport.feed(notice("session.output", sequence));
    }
    for sequence in wire {
        assert_eq!(
            next_notice(&mut events).await,
            (stream("session.output"), sequence)
        );
    }
}

/// The rule the ordered delivery goes around, pinned where it stands: the cursors of a session
/// drop a sequence that goes back, so another consumer of a session reads a resubscription's first
/// frames as duplicates.
#[tokio::test]
async fn a_session_that_is_not_ordered_still_drops_a_delivery_that_starts_again() {
    let (transport, session) = plain();
    let mut broadcast = session.events();
    for sequence in [0, 1, 2, 3, 0, 1] {
        transport.feed(notice("session.output", sequence));
    }
    transport.feed(notice("sentinel", 0));
    let mut seen = Vec::new();
    loop {
        let notification = within(broadcast.recv()).await.expect("an event");
        if notification.stream_id == stream("sentinel") {
            break;
        }
        seen.push(notification.sequence.get());
    }
    assert_eq!(seen, [0, 1, 2, 3]);
}

#[tokio::test]
async fn a_frame_that_is_ready_when_the_session_starts_is_delivered_first() {
    let transport = Scripted::new();
    transport.feed(notice("session.output", 0));
    transport.feed(notice("session.output", 1));
    let (_session, mut events) =
        Session::start_ordered(Arc::clone(&transport) as Arc<dyn ControlTransport>, 4)
            .expect("an ordered session");
    assert_eq!(
        next_notice(&mut events).await,
        (stream("session.output"), 0)
    );
    assert_eq!(
        next_notice(&mut events).await,
        (stream("session.output"), 1)
    );
}

#[derive(Debug)]
struct Called(tokio::task::JoinHandle<Result<SessionList, ClientError>>);

fn ask_for_the_list(session: &Arc<Session>) -> Called {
    let session = Arc::clone(session);
    Called(tokio::spawn(async move {
        session
            .read::<_, SessionList>(Method::SessionList, &Empty {})
            .await
    }))
}

#[tokio::test]
async fn a_slow_owner_loses_nothing_and_the_reader_waits_for_room() {
    const CAPACITY: usize = 2;
    const NOTICES: u64 = 20;
    let (transport, session, mut events) = ordered(CAPACITY);
    // A call whose answer is behind every notification on the connection.
    let call = ask_for_the_list(&session);
    let request_id = transport.written_at_least(1).await;
    for sequence in 0..NOTICES {
        transport.feed(notice("session.output", sequence));
    }
    transport.feed(answer(request_id, Ok(typed(&SessionList { count: 2 }))));

    // The channel holds CAPACITY items and the reader holds one more, waiting: it takes no
    // frame beyond that while the owner reads nothing.
    within(async {
        while transport.read_count() < CAPACITY + 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    tokio::time::sleep(STILL).await;
    assert_eq!(
        transport.read_count(),
        CAPACITY + 1,
        "the reader took frames the owner had no room for"
    );
    assert!(
        !call.0.is_finished(),
        "an answer behind the notifications came before them"
    );

    // Reading makes room, and every notification arrives once, in order, and then the answer.
    for sequence in 0..NOTICES {
        assert_eq!(
            next_notice(&mut events).await,
            (stream("session.output"), sequence)
        );
    }
    let listing = within(call.0)
        .await
        .expect("the call ran")
        .expect("a listing");
    assert_eq!(listing, SessionList { count: 2 });
}

/// An owner that drops its end is not waited for, not even by a reader that is already waiting
/// for room in its channel: the reader goes on, answers still arrive, and the session ends.
#[tokio::test]
async fn an_owner_that_drops_its_end_does_not_stop_the_reader() {
    const CAPACITY: usize = 2;
    const NOTICES: u64 = 5;
    let (transport, session, events) = ordered(CAPACITY);
    let call = ask_for_the_list(&session);
    let request_id = transport.written_at_least(1).await;
    for sequence in 0..NOTICES {
        transport.feed(notice("session.output", sequence));
    }
    transport.feed(answer(request_id, Ok(typed(&SessionList { count: 5 }))));

    // The reader is held by the full channel: it holds the channel's items and one more.
    within(async {
        while transport.read_count() < CAPACITY + 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    tokio::time::sleep(STILL).await;
    assert_eq!(
        transport.read_count(),
        CAPACITY + 1,
        "the reader was not held by the full channel, which this case needs"
    );

    // The owner goes away while the reader waits for room.
    drop(events);
    let every_frame = usize::try_from(NOTICES).expect("a small count") + 1;
    let went_on = tokio::time::timeout(LIVENESS, async {
        while transport.read_count() < every_frame {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        went_on.is_ok(),
        "the reader stopped at {} of {every_frame} frames when the owner dropped its end",
        transport.read_count()
    );
    let answered = tokio::time::timeout(LIVENESS, call.0).await;
    assert!(
        answered.is_ok(),
        "a request got no answer after the owner dropped its end"
    );

    // Later frames are read and answered as well, and the end of the connection ends the session.
    let second = ask_for_the_list(&session);
    let second_id = transport.written_at_least(2).await;
    transport.feed(notice("session.output", NOTICES));
    transport.feed(answer(second_id, Ok(typed(&SessionList { count: 6 }))));
    let answered = tokio::time::timeout(LIVENESS, second.0).await;
    assert!(
        answered.is_ok(),
        "a later request got no answer after the owner dropped its end"
    );
    assert_eq!(
        answered
            .expect("an answer")
            .expect("the call ran")
            .expect("a listing"),
        SessionList { count: 6 }
    );
    transport.finish();
    let closed = tokio::time::timeout(LIVENESS, session.closed()).await;
    assert!(
        closed.is_ok(),
        "the session did not end when the connection did"
    );
}

#[tokio::test]
async fn the_end_of_a_connection_the_host_finished_comes_after_every_earlier_notification() {
    let (transport, _session, mut events) = ordered(8);
    transport.feed(notice("session.output", 0));
    transport.feed(notice("session.output", 1));
    transport.finish();
    assert_eq!(next_notice(&mut events).await.1, 0);
    assert_eq!(next_notice(&mut events).await.1, 1);
    assert!(matches!(next_end(&mut events).await, Ended::Finished));
}

#[tokio::test]
async fn the_end_of_a_failed_read_comes_with_the_transports_text() {
    let (transport, _session, mut events) = ordered(8);
    transport.feed(notice("session.output", 0));
    transport.fail(ClientError::Host(ProtocolError::new(
        ErrorCode::ResourceUnavailable,
        "the stream was reset by the peer",
    )));
    assert_eq!(next_notice(&mut events).await.1, 0);
    match next_end(&mut events).await {
        Ended::Failed(ClientError::Host(error)) => {
            assert_eq!(error.message, "the stream was reset by the peer");
        }
        _ => panic!("the end did not carry the transport's failure"),
    }
}

#[tokio::test]
async fn the_end_the_host_refused_comes_with_the_refusal() {
    let (transport, session, mut events) = ordered(8);
    let refusal = ProtocolError::new(ErrorCode::ResourceUnavailable, "no more connections");
    transport.feed(notice("session.output", 0));
    transport.feed(answer(RequestId::new(0), Err(refusal.clone())));
    assert_eq!(next_notice(&mut events).await.1, 0);
    match next_end(&mut events).await {
        Ended::Refused(held) => assert_eq!(held, refusal),
        _ => panic!("the end did not carry the host's refusal"),
    }
    assert_eq!(session.connection_refusal(), Some(refusal));
}

#[tokio::test]
async fn the_end_a_frame_the_client_may_not_receive_caused_says_so() {
    let (transport, _session, mut events) = ordered(8);
    transport.feed(notice("session.output", 0));
    transport.feed(ControlFrame::Request(Request {
        request_id: RequestId::new(1),
        method: Method::SessionList.into(),
        method_version: MethodVersion::V1,
        params: ParamsValue::empty(),
    }));
    assert_eq!(next_notice(&mut events).await.1, 0);
    assert!(matches!(next_end(&mut events).await, Ended::Unexpected));
}

#[tokio::test]
async fn the_end_waits_behind_notifications_a_slow_owner_has_not_read() {
    let (transport, _session, mut events) = ordered(1);
    for sequence in 0..6 {
        transport.feed(notice("session.output", sequence));
    }
    transport.finish();
    tokio::time::sleep(STILL).await;
    for sequence in 0..6 {
        assert_eq!(next_notice(&mut events).await.1, sequence);
    }
    assert!(matches!(next_end(&mut events).await, Ended::Finished));
}

/* ---------------------------------------------------------------------------------------- */
/* The owner's close                                                                          */
/* ---------------------------------------------------------------------------------------- */

/// What the reader has taken from the connection is the owner's, whatever the owner does next: the
/// channel holds the first notification and the reader holds the second, waiting for room, when
/// the owner closes. Both arrive, in order, then the end, then the channel's end. The third frame
/// was not read, since the close stopped the reading.
#[tokio::test]
async fn a_close_keeps_every_notification_the_reader_had_taken_and_the_end_follows() {
    let (transport, session, mut events) = ordered(1);
    for sequence in 0..3 {
        transport.feed(notice("session.output", sequence));
    }
    reader_has_taken(&transport, 2).await;
    tokio::time::sleep(STILL).await;
    assert_eq!(
        transport.read_count(),
        2,
        "the reader was not held by the full channel, which this case needs"
    );
    session.close();
    assert_eq!(next_notice(&mut events).await.1, 0);
    assert_eq!(next_notice(&mut events).await.1, 1);
    assert!(matches!(next_end(&mut events).await, Ended::Finished));
    the_channel_ends(&mut events).await;
}

/// The end of a failed read is as much the reader's as a notification is: a close that comes while
/// the reader holds it, waiting for room, does not lose it or its text.
#[tokio::test]
async fn a_close_after_a_failed_read_keeps_the_failures_end() {
    let (transport, session, mut events) = ordered(1);
    transport.feed(notice("session.output", 0));
    transport.fail(ClientError::Host(ProtocolError::new(
        ErrorCode::ResourceUnavailable,
        "the stream was reset by the peer",
    )));
    // The session has ended on the failure; the channel is full, so the reader holds the end.
    within(session.closed()).await;
    tokio::time::sleep(STILL).await;
    session.close();
    assert_eq!(next_notice(&mut events).await.1, 0);
    match next_end(&mut events).await {
        Ended::Failed(ClientError::Host(error)) => {
            assert_eq!(error.message, "the stream was reset by the peer");
        }
        _ => panic!("the end after a close did not carry the failure that was read"),
    }
    the_channel_ends(&mut events).await;
}

#[tokio::test]
async fn a_close_with_nothing_read_ends_the_session_and_the_channel_at_once() {
    let (_transport, session, mut events) = ordered(4);
    session.close();
    assert!(matches!(next_end(&mut events).await, Ended::Finished));
    the_channel_ends(&mut events).await;
}

/// A read's end is what the transport returned. A failure that the read has already returned is a
/// cause that the owner's close, which comes right after it, does not take away: the close raises
/// the stop before the reader looks at the result.
#[tokio::test]
async fn a_failure_the_read_returned_keeps_its_cause_when_the_owner_closes_right_after_it() {
    let (transport, session, mut events) = ordered(4);
    transport.after_a_failed_read({
        let session = Arc::clone(&session);
        move || session.close()
    });
    transport.fail(ClientError::Host(ProtocolError::new(
        ErrorCode::ResourceUnavailable,
        "the stream was reset by the peer",
    )));
    match next_end(&mut events).await {
        Ended::Failed(ClientError::Host(error)) => {
            assert_eq!(error.message, "the stream was reset by the peer");
        }
        Ended::Finished => {
            panic!("a close right after a failed read replaced the failure with the clean end")
        }
        _ => panic!("the end did not carry the failure that was read"),
    }
    the_channel_ends(&mut events).await;
}

/// The other order: the owner closes, and the read that the close ends is the clean end, since a
/// transport returns the clean end for this side's own close.
#[tokio::test]
async fn a_close_while_the_reader_waits_for_a_frame_ends_cleanly() {
    let (transport, session, mut events) = ordered(4);
    transport.feed(notice("session.output", 0));
    assert_eq!(next_notice(&mut events).await.1, 0);
    // The reader has taken the frame and now waits for the next one.
    session.close();
    assert!(matches!(next_end(&mut events).await, Ended::Finished));
    the_channel_ends(&mut events).await;
}

/// A lane holds the session's state for as long as it lives, and the channel's end does not wait
/// for it: the session is dropped with the lane alive and a notification still held by the reader.
#[tokio::test]
async fn a_dropped_session_ends_the_channel_while_a_lane_lives() {
    let (transport, session, mut events) = ordered(1);
    let lane =
        within(session.input_lane(InputTarget::new(environment(), session_id(), attachment())))
            .await
            .expect("a lane");
    transport.feed(notice("session.output", 0));
    transport.feed(notice("session.output", 1));
    reader_has_taken(&transport, 2).await;
    tokio::time::sleep(STILL).await;
    drop(session);
    assert_eq!(next_notice(&mut events).await.1, 0);
    assert_eq!(next_notice(&mut events).await.1, 1);
    assert!(matches!(next_end(&mut events).await, Ended::Finished));
    the_channel_ends(&mut events).await;
    drop(lane);
}

/// The same for an answer that is still awaited: it holds the session's state, the channel's end
/// does not wait for it, and the answer itself ends with the session's end and not with silence.
#[tokio::test]
async fn a_dropped_session_ends_the_channel_while_an_answer_is_awaited() {
    let (transport, session, mut events) = ordered(4);
    let detach = composed(&session, 6).await;
    let answering = within(session.send_whole(&detach))
        .await
        .expect("the frame was written");
    transport.feed(notice("session.output", 0));
    reader_has_taken(&transport, 1).await;
    drop(session);
    assert_eq!(next_notice(&mut events).await.1, 0);
    assert!(matches!(next_end(&mut events).await, Ended::Finished));
    the_channel_ends(&mut events).await;
    match within(answering).await {
        Err(ClientError::SubmissionUncertain { action_id }) => {
            assert_eq!(action_id, ActionId::new(Uuid::from_bytes([6; 16])));
        }
        _ => panic!("the written request ended with silence or another word"),
    }
}

/// The broadcast and the cursors work on an ordered session as on any other: a holder of
/// `events()` gets what the cursors let through, a duplicate is not one of them, and the owner of
/// the ordered delivery gets all four.
#[tokio::test]
async fn an_ordered_session_keeps_the_broadcast_and_the_cursors_as_they_are() {
    let (transport, session, mut events) = ordered(8);
    let mut broadcast = session.events();
    for sequence in [0, 1, 1, 5] {
        transport.feed(notice("session.output", sequence));
    }
    for sequence in [0, 1, 1, 5] {
        assert_eq!(next_notice(&mut events).await.1, sequence);
    }
    // The broadcast's copy is made before the owner's, so it is there once the owner has read.
    let mut seen = Vec::new();
    while let Ok(notification) = broadcast.try_recv() {
        seen.push(notification.sequence.get());
    }
    assert_eq!(
        seen,
        [0, 1, 5],
        "the broadcast did not get what the cursors let through, once each"
    );
}

/// What a lane stands on: on an ordered session a lane sends, and its event is seen, while the
/// owner's notifications keep coming. The lane's own answers are the session's, and never ride the
/// owner's channel.
#[tokio::test]
async fn a_lane_on_an_ordered_session_sends_and_its_event_is_seen() {
    let (transport, session, mut events) = ordered(4);
    let lane =
        within(session.input_lane(InputTarget::new(environment(), session_id(), attachment())))
            .await
            .expect("a lane");
    let mut lane_events = lane.events().expect("the lane's events");
    lane.begin_epoch(InputLeaseEpoch::new(1)).expect("an epoch");
    lane.try_send(b"a").expect("the lane takes a key");
    let request_id = transport.written_at_least(1).await;
    transport.feed(notice("session.output", 0));
    transport.feed(answer(
        request_id,
        Ok(typed(&InputWriteResult {
            sequence: InputSequence::new(0),
            forwarded_bytes: U64::new(1),
            held_prefix_bytes: U64::new(0),
        })),
    ));
    assert_eq!(
        next_notice(&mut events).await,
        (stream("session.output"), 0)
    );
    match within(lane_events.recv()).await.expect("a lane event") {
        InputEvent::Accepted { epoch, through, .. } => {
            assert_eq!(epoch, InputLeaseEpoch::new(1));
            assert_eq!(through, InputSequence::new(0));
        }
        _ => panic!("the lane's first event was not the key's acceptance"),
    }
}

/* ---------------------------------------------------------------------------------------- */
/* A close                                                                                    */
/* ---------------------------------------------------------------------------------------- */

#[tokio::test]
async fn a_request_is_on_the_connection_whole_before_the_connection_ends() {
    let (transport, session, _events) = ordered(4);
    let detach = composed(&session, 1).await;
    transport.park();
    let writing = {
        let session = Arc::clone(&session);
        tokio::spawn(async move { session.send_whole(&detach).await.map(|_| ()) })
    };
    transport.write_entered().await;
    tokio::time::sleep(STILL).await;
    assert!(
        !writing.is_finished(),
        "the call returned before the frame was written"
    );
    assert!(transport.log().is_empty());
    transport.unpark();
    within(writing)
        .await
        .expect("the call ran")
        .expect("the frame was written");
    // The owner closes only now.
    session.close();
    assert_eq!(transport.log(), ["sent", "closed"]);
}

#[tokio::test]
async fn a_request_still_waiting_at_a_close_ends_with_the_sessions_end() {
    let (transport, session, _events) = ordered(4);
    let detach = composed(&session, 2).await;
    let answering = within(session.send_whole(&detach))
        .await
        .expect("the frame was written");
    let call = ask_for_the_list(&session);
    transport.written_at_least(2).await;
    session.close();
    match within(answering).await {
        Err(ClientError::SubmissionUncertain { action_id }) => {
            assert_eq!(action_id, ActionId::new(Uuid::from_bytes([2; 16])));
        }
        _ => panic!("the written request ended with silence or another word"),
    }
    assert!(matches!(
        within(call.0).await.expect("the call ran"),
        Err(ClientError::ConnectionEnded)
    ));
}

/* ---------------------------------------------------------------------------------------- */
/* A dropped call                                                                             */
/* ---------------------------------------------------------------------------------------- */

#[tokio::test]
async fn a_read_dropped_inside_its_write_leaves_no_waiter() {
    let (transport, session, _events) = ordered(4);
    transport.park();
    let call = ask_for_the_list(&session);
    transport.write_entered().await;
    assert_eq!(session.waiting_requests(), 1);
    call.0.abort();
    let _ = call.0.await;
    assert_eq!(session.waiting_requests(), 0);
    assert_eq!(transport.written(), 0);
}

#[tokio::test]
async fn a_read_dropped_while_it_waits_for_its_answer_leaves_no_waiter_and_its_answer_is_ignored() {
    let (transport, session, _events) = ordered(4);
    let call = ask_for_the_list(&session);
    let request_id = transport.written_at_least(1).await;
    assert_eq!(session.waiting_requests(), 1);
    call.0.abort();
    let _ = call.0.await;
    assert_eq!(session.waiting_requests(), 0);
    // The answer comes later and is ignored; the session goes on.
    transport.feed(answer(request_id, Ok(typed(&SessionList { count: 9 }))));
    let second = ask_for_the_list(&session);
    let second_id = transport.written_at_least(2).await;
    transport.feed(answer(second_id, Ok(typed(&SessionList { count: 3 }))));
    let listing = within(second.0)
        .await
        .expect("the call ran")
        .expect("a listing");
    assert_eq!(listing, SessionList { count: 3 });
}

#[tokio::test(start_paused = true)]
async fn a_read_dropped_while_it_waits_to_try_again_sends_no_second_request() {
    let (transport, session, _events) = ordered(4);
    let call = ask_for_the_list(&session);
    let request_id = transport.written_at_least(1).await;
    // A transient refusal of an idempotent read: the library waits, and then sends it again.
    transport.feed(answer(
        request_id,
        Err(ProtocolError::new(
            ErrorCode::ResourceUnavailable,
            "try again",
        )),
    ));
    within(async {
        while session.waiting_requests() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    tokio::task::yield_now().await;
    assert!(!call.0.is_finished(), "the call did not wait to try again");
    call.0.abort();
    let _ = call.0.await;
    tokio::time::advance(Duration::from_secs(120)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        transport.written(),
        1,
        "a dropped call sent its request again"
    );
    assert_eq!(session.waiting_requests(), 0);
}

#[tokio::test]
async fn a_mutation_dropped_inside_its_write_leaves_its_action_on_the_book_and_no_waiter() {
    let (transport, session, _events) = ordered(4);
    let mutation = composed(&session, 3).await;
    transport.park();
    let writing = {
        let session = Arc::clone(&session);
        tokio::spawn(async move { session.send(&mutation).await.map(|_| ()) })
    };
    transport.write_entered().await;
    writing.abort();
    let _ = writing.await;
    assert_eq!(session.waiting_requests(), 0);
    assert_eq!(transport.written(), 0);
    assert_eq!(
        session.submitted_actions().await.len(),
        1,
        "the action was not left on the book"
    );
}

#[tokio::test]
async fn a_mutation_dropped_while_it_waits_for_its_answer_stays_on_the_book_until_its_owner_settles_it()
 {
    let (transport, session, _events) = ordered(4);
    let mutation = composed(&session, 4).await;
    let waiting = {
        let session = Arc::clone(&session);
        tokio::spawn(async move { session.send(&mutation).await.map(|_| ()) })
    };
    let request_id = transport.written_at_least(1).await;
    assert_eq!(session.waiting_requests(), 1);
    waiting.abort();
    let _ = waiting.await;
    assert_eq!(session.waiting_requests(), 0);
    assert_eq!(session.submitted_actions().await.len(), 1);
    // The host's definite answer does not clear it: the action is held until its owner settles it.
    transport.feed(answer(request_id, Ok(typed(&Empty {}))));
    tokio::time::sleep(STILL).await;
    assert_eq!(session.submitted_actions().await.len(), 1);
    session
        .settle(ActionId::new(Uuid::from_bytes([4; 16])))
        .await;
    assert!(session.submitted_actions().await.is_empty());
}

#[tokio::test]
async fn a_dropped_whole_write_answer_leaves_its_action_held_until_its_owner_settles_it() {
    let (transport, session, _events) = ordered(4);
    let mutation = composed(&session, 5).await;
    let answering = within(session.send_whole(&mutation))
        .await
        .expect("the frame was written");
    let request_id = transport.written_at_least(1).await;
    assert_eq!(session.waiting_requests(), 1);
    drop(answering);
    assert_eq!(session.waiting_requests(), 0);
    assert_eq!(session.submitted_actions().await.len(), 1);
    // The host's definite answer does not clear it: the action is held until its owner settles it.
    transport.feed(answer(request_id, Ok(typed(&Empty {}))));
    tokio::time::sleep(STILL).await;
    assert_eq!(session.submitted_actions().await.len(), 1);
    session
        .settle(ActionId::new(Uuid::from_bytes([5; 16])))
        .await;
    assert!(session.submitted_actions().await.is_empty());
}

#[tokio::test]
async fn a_mutate_dropped_while_it_waits_for_its_answer_is_settled_by_the_hosts_late_answer() {
    let (transport, session, _events) = ordered(4);
    let waiting = {
        let session = Arc::clone(&session);
        tokio::spawn(async move {
            session
                .mutate(
                    Method::SessionCreate,
                    ActionTarget::environment(environment()),
                    None,
                    &Empty {},
                    &Empty {},
                    DurationMs::new(120_000),
                )
                .await
                .map(|_| ())
        })
    };
    let request_id = transport.written_at_least(1).await;
    assert_eq!(session.waiting_requests(), 1);
    waiting.abort();
    let _ = waiting.await;
    assert_eq!(session.waiting_requests(), 0);
    assert_eq!(
        session.submitted_actions().await.len(),
        1,
        "the action was not left on the book"
    );
    // The host's definite answer comes with no one waiting, and the session settles the action.
    transport.feed(answer(request_id, Ok(typed(&Empty {}))));
    let settled = tokio::time::timeout(LIVENESS, async {
        while !session.submitted_actions().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        settled.is_ok(),
        "a late definite answer left the action of a dropped mutate on the book"
    );
}
