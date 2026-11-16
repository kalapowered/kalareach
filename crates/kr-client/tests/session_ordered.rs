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
        })
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

    fn ended_by_this_device(&self) -> Option<ProtocolError> {
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
                Some(Incoming::Fail(error)) => Err(error),
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
    match within(events.recv()).await {
        Some(Ordered::Notification(notification)) => {
            (notification.stream_id, notification.sequence.get())
        }
        Some(Ordered::Ended(_)) => panic!("the session ended where a notification was due"),
        None => panic!("the channel closed where a notification was due"),
    }
}

async fn next_end(events: &mut OrderedEvents) -> Ended {
    match within(events.recv()).await {
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
    let mut seen = Vec::new();
    for _ in 0..3 {
        let notification = within(broadcast.recv()).await.expect("an event");
        seen.push(notification.sequence.get());
    }
    assert_eq!(seen, [0, 1, 5], "the duplicate reached the broadcast");
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
