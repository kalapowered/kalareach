//! Cases of the side channel's adapter over a real WebSocket stream, on a connection that the test
//! controls: the provider's end is the library's own server, and the writes of the adapter's end
//! pass, stay pending, or fail as the test says. Nothing here waits for time to pass.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker, ready};

use futures_util::{FutureExt, SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio_websockets::{ClientBuilder, Message, ServerBuilder, WebSocketStream};

use super::*;

/// What a write on the adapter's end of the connection does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Writes {
    /// It goes through.
    Pass,
    /// It never finishes, and keeps no waker.
    Hold,
    /// It fails, as a write on a connection the other end reset does.
    Fail,
    /// It waits and keeps the waker of the task that made it: the next mode that is set wakes that
    /// waker, and no other.
    Park,
    /// The first write waits, keeping no waker, and every write after it fails.
    HoldThenFail,
}

crate::debug_as_name!(Writes);

/// What the completion of a flush on the adapter's end of the connection does, whatever the writes
/// do.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Flushes {
    /// A flush goes through, waits or fails as the writes do.
    Follow,
    /// A write that passes is kept by the wire and reaches the other end only when a flush
    /// completes; a flush waits and keeps the waker of the task that made it, and the next mode that
    /// is set wakes that waker, and no other.
    Park,
}

struct GateState {
    writes: Writes,
    flushes: Flushes,
    write_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    /// How many writes and flushes were left waiting.
    waits: usize,
    /// How many times the call polled its read of the adapter.
    read_polls: usize,
}

/// The test's hold on what the writes and the flushes of one connection do.
#[derive(Clone)]
struct Gate(Arc<Mutex<GateState>>);

impl Gate {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(GateState {
            writes: Writes::Pass,
            flushes: Flushes::Follow,
            write_waker: None,
            flush_waker: None,
            waits: 0,
            read_polls: 0,
        })))
    }

    fn state(&self) -> MutexGuard<'_, GateState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sets what writes do, and wakes the task a parked write kept.
    fn set(&self, mode: Writes) {
        let waker = {
            let mut state = self.state();
            state.writes = mode;
            state.write_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Sets what flushes do, and wakes the task a parked flush kept.
    fn set_flushes(&self, flushes: Flushes) {
        let waker = {
            let mut state = self.state();
            state.flushes = flushes;
            state.flush_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn mode(&self) -> Writes {
        self.state().writes
    }

    fn waits(&self) -> usize {
        self.state().waits
    }

    fn read_polls(&self) -> usize {
        self.state().read_polls
    }

    fn note_read_poll(&self) {
        self.state().read_polls += 1;
    }

    fn parks_flushes(&self) -> bool {
        self.state().flushes == Flushes::Park
    }

    /// What a write is told: `Some` when it is decided, `None` when it waits.
    fn write(&self, waker: &Waker) -> Option<io::Result<()>> {
        let mut state = self.state();
        match state.writes {
            Writes::Pass => Some(Ok(())),
            Writes::Fail => Some(Err(io::ErrorKind::BrokenPipe.into())),
            Writes::Hold => {
                state.waits += 1;
                None
            }
            Writes::Park => {
                state.waits += 1;
                state.write_waker = Some(waker.clone());
                None
            }
            Writes::HoldThenFail => {
                state.writes = Writes::Fail;
                state.waits += 1;
                None
            }
        }
    }

    /// What a flush is told: `Some` when it is decided, `None` when it waits.
    fn flush(&self, waker: &Waker) -> Option<io::Result<()>> {
        let mut state = self.state();
        match (state.writes, state.flushes) {
            (Writes::Pass, Flushes::Follow) => Some(Ok(())),
            (Writes::Fail, _) => Some(Err(io::ErrorKind::BrokenPipe.into())),
            (Writes::Park, _) => {
                state.waits += 1;
                state.write_waker = Some(waker.clone());
                None
            }
            (Writes::Pass, Flushes::Park) => {
                state.waits += 1;
                state.flush_waker = Some(waker.clone());
                None
            }
            (Writes::Hold | Writes::HoldThenFail, _) => {
                state.waits += 1;
                None
            }
        }
    }
}

/// A task's waker that counts how often it is woken.
struct Wakes(AtomicUsize);

impl Wakes {
    fn new() -> Arc<Self> {
        Arc::new(Self(AtomicUsize::new(0)))
    }

    fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Polls a future once, as the task that owns `wakes` does.
fn poll_once<T>(future: &mut TransportFuture<'_, T>, wakes: &Arc<Wakes>) -> Poll<T> {
    let waker = Waker::from(Arc::clone(wakes));
    future.as_mut().poll(&mut Context::from_waker(&waker))
}

/// The adapter's end of an in-memory connection, with writes under a [`Gate`]. It takes writes as
/// the library offers them, in one buffer or in several, as `vectored` says.
struct Wire {
    inner: DuplexStream,
    gate: Gate,
    vectored: bool,
    /// What writes took while flushes are parked: it reaches the other end when a flush completes.
    staged: Vec<u8>,
}

impl AsyncRead for Wire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Wire {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.gate.write(cx.waker()) {
            Some(Ok(())) => {}
            Some(Err(error)) => return Poll::Ready(Err(error)),
            None => return Poll::Pending,
        }
        let this = &mut *self;
        if !this.staged.is_empty() || this.gate.parks_flushes() {
            this.staged.extend_from_slice(buf);
            return Poll::Ready(Ok(buf.len()));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn is_write_vectored(&self) -> bool {
        self.vectored
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.gate.flush(cx.waker()) {
            Some(Ok(())) => {}
            Some(Err(error)) => return Poll::Ready(Err(error)),
            None => return Poll::Pending,
        }
        let this = &mut *self;
        while !this.staged.is_empty() {
            let taken = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.staged))?;
            this.staged.drain(..taken);
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The adapter on a connection to the library's server, with that server's end and the gate of
/// the adapter's writes.
async fn connected() -> (WebSocketSideband<Wire>, WebSocketStream<DuplexStream>, Gate) {
    connected_over(false).await
}

/// [`connected`], on a connection whose writes take several buffers at once.
async fn connected_vectored() -> (WebSocketSideband<Wire>, WebSocketStream<DuplexStream>, Gate) {
    connected_over(true).await
}

async fn connected_over(
    vectored: bool,
) -> (WebSocketSideband<Wire>, WebSocketStream<DuplexStream>, Gate) {
    let (near, far) = tokio::io::duplex(1 << 20);
    let gate = Gate::new();
    let wire = Wire {
        inner: near,
        gate: gate.clone(),
        vectored,
        staged: Vec::new(),
    };
    let client = ClientBuilder::new()
        .uri("ws://stand-in.invalid/side")
        .expect("an address");
    let server = ServerBuilder::new();
    let (opened, accepted) =
        tokio::join!(client.connect_on(HoldWrites::new(wire)), server.accept(far));
    let (socket, _) = opened.expect("the client's upgrade");
    let (_, provider) = accepted.expect("the server's upgrade");
    (WebSocketSideband::new(socket), provider, gate)
}

fn usage() -> String {
    json!({ "type": "session.usage.updated" }).to_string()
}

fn closure() -> String {
    closed_event("expired", None).to_string()
}

/// A usage event that is told from the others by its number.
fn event(n: usize) -> String {
    json!({ "type": "session.usage.updated", "n": n }).to_string()
}

/// The provider says each of these, one after the other, before the adapter reads any.
async fn said(provider: &mut WebSocketStream<DuplexStream>, texts: &[String]) {
    for text in texts {
        provider
            .send(Message::text(text.clone()))
            .await
            .expect("the provider writes");
    }
}

/// The provider pings the adapter, which owes a Pong for it.
async fn pinged(provider: &mut WebSocketStream<DuplexStream>) {
    provider
        .send(Message::ping("keep-alive"))
        .await
        .expect("the provider pings");
}

/// Whether what the provider read, without waiting, is a Pong.
fn is_pong(read: Option<Option<std::result::Result<Message, tokio_websockets::Error>>>) -> bool {
    matches!(read, Some(Some(Ok(message))) if message.is_pong())
}

/// Lets the call's task run, without moving the clock.
async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

/// A side channel for a call: the stand-in's own, which answers the call's readiness and records
/// its commands, with reads from `adapter` as well, and writes that go through `adapter` first. A
/// write that is cancelled leaves the connection failing. The gate counts the polls of the read.
struct Bridge {
    stand: Box<dyn SidebandSocket>,
    adapter: WebSocketSideband<Wire>,
    gate: Gate,
}

/// Makes every later write on a connection fail, unless it is disarmed first.
struct FailOnDrop {
    gate: Gate,
    armed: bool,
}

impl Drop for FailOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.gate.set(Writes::Fail);
        }
    }
}

impl SidebandSocket for Bridge {
    fn send(&mut self, text: String) -> TransportFuture<'_, bool> {
        Box::pin(async move {
            let mut cancelled = FailOnDrop {
                gate: self.gate.clone(),
                armed: true,
            };
            let written = self.adapter.send(text.clone()).await;
            cancelled.armed = false;
            written && self.stand.send(text).await
        })
    }

    fn next(&mut self) -> TransportFuture<'_, SocketRead> {
        Box::pin(async move {
            let gate = self.gate.clone();
            let mut adapter = self.adapter.next();
            let adapter = std::future::poll_fn(move |cx| {
                gate.note_read_poll();
                adapter.as_mut().poll(cx)
            });
            tokio::select! {
                biased;
                read = self.stand.next() => read,
                read = adapter => read,
            }
        })
    }
}

/// A started call whose side channel is a [`Bridge`] over a connection to the library's server.
async fn bridged() -> (World, OwnSession, WebSocketStream<DuplexStream>, Gate) {
    let world = fresh();
    let (adapter, provider, gate) = connected().await;
    let held = gate.clone();
    world.stand_in.wrap_next_attach(move |stand| {
        Box::new(Bridge {
            stand,
            adapter,
            gate: held,
        })
    });
    let own = started(&world).await;
    (world, own, provider, gate)
}

fn thinking() -> VoiceContextFrame {
    VoiceContextFrame::new("w-1", VoiceCommand::Thinking, None, Some("x".to_owned()))
        .expect("frame")
}

/// A usage event and a valid closure come together and the adapter reads the event; the next
/// write fails. The closure is still read, and then the socket is closed.
#[tokio::test]
async fn a_closure_buffered_beside_an_event_is_read_after_a_write_that_fails() {
    let (mut sideband, mut provider, gate) = connected().await;
    said(&mut provider, &[usage(), closure()]).await;
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(usage()))
    );
    gate.set(Writes::Fail);
    assert!(!sideband.send("{}".to_owned()).await, "the write failed");
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(closure())),
        "the closure that was buffered when the write began is read"
    );
    assert_eq!(sideband.next().now_or_never(), Some(SocketRead::Closed));
}

/// A write that never finishes is cancelled with its frame queued in the library, and the
/// connection then fails: the closure buffered beside an event is still read.
#[tokio::test]
async fn a_closure_buffered_beside_an_event_is_read_after_a_write_is_cancelled() {
    let (mut sideband, mut provider, gate) = connected().await;
    said(&mut provider, &[usage(), closure()]).await;
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(usage()))
    );
    gate.set(Writes::Hold);
    assert!(
        sideband.send("{}".to_owned()).now_or_never().is_none(),
        "the write is held"
    );
    gate.set(Writes::Fail);
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(closure())),
        "the closure that was buffered when the write began is read"
    );
    assert_eq!(sideband.next().now_or_never(), Some(SocketRead::Closed));
}

/// An event is read, and a valid closure then comes before a write that fails: the closure is
/// read, and then the socket is closed.
#[tokio::test]
async fn a_closure_that_came_after_the_last_read_is_read_after_a_write_that_fails() {
    let (mut sideband, mut provider, gate) = connected().await;
    said(&mut provider, &[usage()]).await;
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(usage()))
    );
    said(&mut provider, &[closure()]).await;
    gate.set(Writes::Fail);
    assert!(!sideband.send("{}".to_owned()).await, "the write failed");
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(closure())),
        "the closure that was on the socket when the write began is read"
    );
    assert_eq!(sideband.next().now_or_never(), Some(SocketRead::Closed));
}

/// The same for a write that never finishes and is cancelled with its frame queued, and a
/// connection that then fails.
#[tokio::test]
async fn a_closure_that_came_after_the_last_read_is_read_after_a_write_is_cancelled() {
    let (mut sideband, mut provider, gate) = connected().await;
    said(&mut provider, &[usage()]).await;
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(usage()))
    );
    said(&mut provider, &[closure()]).await;
    gate.set(Writes::Hold);
    assert!(
        sideband.send("{}".to_owned()).now_or_never().is_none(),
        "the write is held"
    );
    gate.set(Writes::Fail);
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(closure())),
        "the closure that was on the socket when the write began is read"
    );
    assert_eq!(sideband.next().now_or_never(), Some(SocketRead::Closed));
}

/// The read ahead stops after 256 messages: a closure behind more of them is not read after a
/// write that fails, and the read ahead keeps their order.
#[tokio::test]
async fn a_closure_behind_more_messages_than_a_write_reads_ahead_is_not_read_after_it_fails() {
    let (mut sideband, mut provider, gate) = connected().await;
    let mut texts: Vec<String> = (0..300).map(event).collect();
    texts.push(closure());
    said(&mut provider, &texts).await;
    gate.set(Writes::Fail);
    assert!(!sideband.send("{}".to_owned()).await, "the write failed");
    for n in 0..256 {
        assert_eq!(
            sideband.next().now_or_never(),
            Some(SocketRead::Text(event(n))),
            "message {n} was read ahead, in the order it came"
        );
    }
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Closed),
        "what is behind the messages read ahead went with the failed write"
    );
}

/// A usage event and a valid closure are on the connection when a write fails before either is
/// read: the call ends as the provider's, nothing is hung up, and no row stands.
#[tokio::test(start_paused = true)]
async fn a_call_whose_write_fails_beside_a_closure_on_the_socket_ends_as_the_providers() {
    let (world, own, mut provider, gate) = bridged().await;
    let control = world.provider.host_control(&own.call_id).expect("control");
    // A hangup would be answered by an empty 404 and leave the row unresolved.
    world
        .stand_in
        .script_hangup(HangupScript::Answer(404, None));
    said(&mut provider, &[usage(), closure()]).await;
    gate.set(Writes::Fail);
    assert_eq!(
        control.write(control.revision(), thinking()).await,
        Err(WriteRefusal::Lost),
        "the write is refused as lost"
    );
    settle().await;
    assert_eq!(
        control.state(),
        SidebandState::Closed(SidebandEnd::ProviderClosed),
        "the closure that was on the socket when the write began was read"
    );
    assert!(
        world.stand_in.recorded().hangups.is_empty(),
        "a closure the provider told is not hung up"
    );
    assert!(world.ledger.rows().expect("rows").is_empty());
}

/// A usage event and a valid closure are on the connection when a write is cancelled at its
/// bound, and the connection fails before the next read: the call ends as the provider's, nothing
/// is hung up, and no row stands.
#[tokio::test(start_paused = true)]
async fn a_call_whose_write_is_cancelled_beside_a_closure_on_the_socket_ends_as_the_providers() {
    let (world, own, mut provider, gate) = bridged().await;
    let control = world.provider.host_control(&own.call_id).expect("control");
    world
        .stand_in
        .script_hangup(HangupScript::Answer(404, None));
    said(&mut provider, &[usage(), closure()]).await;
    gate.set(Writes::Hold);
    let writing = control.write(control.revision(), thinking());
    let passing = async {
        settle().await;
        assert_eq!(gate.mode(), Writes::Hold, "the write is held");
        tokio::time::advance(DRAIN_BOUND).await;
        settle().await;
    };
    let (written, ()) = tokio::join!(writing, passing);
    assert_eq!(
        written,
        Err(WriteRefusal::Lost),
        "the write that never finished is refused as lost"
    );
    assert_eq!(
        gate.mode(),
        Writes::Fail,
        "the write was cancelled, and the connection failed with it"
    );
    assert_eq!(
        control.state(),
        SidebandState::Closed(SidebandEnd::ProviderClosed),
        "the closure that was on the socket when the write began was read"
    );
    assert!(
        world.stand_in.recorded().hangups.is_empty(),
        "a closure the provider told is not hung up"
    );
    assert!(world.ledger.rows().expect("rows").is_empty());
}

/// A Ping and a valid closure are on the connection when a write fails, after the adapter read an
/// event: the Pong the Ping owes waits while they are read, and the closure is read.
#[tokio::test]
async fn a_closure_behind_a_ping_is_read_after_a_write_that_fails() {
    let (mut sideband, mut provider, gate) = connected().await;
    said(&mut provider, &[usage()]).await;
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(usage()))
    );
    pinged(&mut provider).await;
    said(&mut provider, &[closure()]).await;
    gate.set(Writes::Fail);
    assert!(!sideband.send("{}".to_owned()).await, "the write failed");
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(closure())),
        "the closure behind the Ping, which was on the connection when the write began, is read"
    );
    assert_eq!(sideband.next().now_or_never(), Some(SocketRead::Closed));
}

/// The same, on a connection whose writes take several buffers at once.
#[tokio::test]
async fn a_closure_behind_a_ping_is_read_after_a_write_that_fails_on_vectored_writes() {
    let (mut sideband, mut provider, gate) = connected_vectored().await;
    said(&mut provider, &[usage()]).await;
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(usage()))
    );
    pinged(&mut provider).await;
    said(&mut provider, &[closure()]).await;
    gate.set(Writes::Fail);
    assert!(!sideband.send("{}".to_owned()).await, "the write failed");
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(closure())),
        "the closure behind the Ping, which was on the connection when the write began, is read"
    );
    assert_eq!(sideband.next().now_or_never(), Some(SocketRead::Closed));
}

/// A read that waits is cancelled with the Pong of a Ping queued in the library, and a closure
/// comes before the next write, which fails: the closure is read.
#[tokio::test]
async fn a_closure_after_a_cancelled_read_that_left_a_pong_queued_is_read_after_a_write_that_fails()
{
    let (mut sideband, mut provider, gate) = connected().await;
    gate.set(Writes::Hold);
    pinged(&mut provider).await;
    assert!(
        sideband.next().now_or_never().is_none(),
        "the read waits, with the Pong it owes held"
    );
    said(&mut provider, &[closure()]).await;
    gate.set(Writes::Fail);
    assert!(!sideband.send("{}".to_owned()).await, "the write failed");
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(closure())),
        "the closure that came before the write is read"
    );
    assert_eq!(sideband.next().now_or_never(), Some(SocketRead::Closed));
}

/// An event, a Ping and a valid closure are on the connection when writes already fail, and no
/// write is made: reads alone give the event, the closure, and then the end.
#[tokio::test]
async fn a_closure_behind_a_ping_is_read_by_reads_alone_while_writes_fail() {
    let (mut sideband, mut provider, gate) = connected().await;
    said(&mut provider, &[usage()]).await;
    pinged(&mut provider).await;
    said(&mut provider, &[closure()]).await;
    gate.set(Writes::Fail);
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(usage()))
    );
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(closure())),
        "the closure behind the Ping is read"
    );
    assert_eq!(sideband.next().now_or_never(), Some(SocketRead::Closed));
}

/// A read that finds a Ping and an event answers the Ping at once, with no write made.
#[tokio::test]
async fn a_ping_read_with_an_event_is_answered_before_any_write() {
    let (mut sideband, mut provider, _gate) = connected().await;
    pinged(&mut provider).await;
    said(&mut provider, &[usage()]).await;
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(usage()))
    );
    assert!(
        is_pong(provider.next().now_or_never()),
        "the Pong went out with the read"
    );
}

/// A write that reads a Ping ahead lets the Pong go with its own text.
#[tokio::test]
async fn a_ping_read_ahead_by_a_write_is_answered_with_the_write() {
    let (mut sideband, mut provider, _gate) = connected().await;
    pinged(&mut provider).await;
    assert_eq!(
        sideband.send("{}".to_owned()).now_or_never(),
        Some(true),
        "the write finished"
    );
    assert!(
        is_pong(provider.next().now_or_never()),
        "the Pong came first"
    );
    let text = provider.next().now_or_never();
    assert!(
        matches!(text, Some(Some(Ok(ref message))) if message.as_text() == Some("{}")),
        "the text came after it"
    );
}

/// The provider sends distinct events, a valid closure and a closing frame before the adapter
/// writes: the write is refused, and what was read ahead is handed on in the order it came, with
/// the end last.
#[tokio::test]
async fn events_a_closure_and_a_closing_frame_read_ahead_are_handed_on_in_order() {
    let (mut sideband, mut provider, _gate) = connected().await;
    let mut texts: Vec<String> = (0..3).map(event).collect();
    texts.push(closure());
    said(&mut provider, &texts).await;
    provider
        .send(Message::close(None, ""))
        .await
        .expect("the provider closes");
    assert!(
        !sideband.send("{}".to_owned()).await,
        "a socket the provider closed takes no write"
    );
    for (n, text) in texts.iter().enumerate() {
        assert_eq!(
            sideband.next().now_or_never(),
            Some(SocketRead::Text(text.clone())),
            "message {n}, in the order it came"
        );
    }
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Closed),
        "the closing frame is the last"
    );
}

/// Events come before a write that passes, and others after it: all are handed on in the order
/// they came.
#[tokio::test]
async fn events_before_and_after_a_write_that_passes_are_handed_on_in_order() {
    let (mut sideband, mut provider, _gate) = connected().await;
    said(&mut provider, &[event(0), event(1)]).await;
    assert!(sideband.send("{}".to_owned()).await, "the write passed");
    said(&mut provider, &[event(2), event(3)]).await;
    for n in 0..4 {
        assert_eq!(
            sideband.next().now_or_never(),
            Some(SocketRead::Text(event(n))),
            "message {n}, in the order it came"
        );
    }
}

/// An event, a Ping and a valid closure are on the connection when a write fails before any is
/// read: the call ends as the provider's, nothing is hung up, and no row stands.
#[tokio::test(start_paused = true)]
async fn a_call_whose_write_fails_beside_a_ping_and_a_closure_on_the_socket_ends_as_the_providers()
{
    let (world, own, mut provider, gate) = bridged().await;
    let control = world.provider.host_control(&own.call_id).expect("control");
    world
        .stand_in
        .script_hangup(HangupScript::Answer(404, None));
    said(&mut provider, &[usage()]).await;
    pinged(&mut provider).await;
    said(&mut provider, &[closure()]).await;
    gate.set(Writes::Fail);
    assert_eq!(
        control.write(control.revision(), thinking()).await,
        Err(WriteRefusal::Lost),
        "the write is refused as lost"
    );
    settle().await;
    assert_eq!(
        control.state(),
        SidebandState::Closed(SidebandEnd::ProviderClosed),
        "the closure behind the Ping was read"
    );
    assert!(
        world.stand_in.recorded().hangups.is_empty(),
        "a closure the provider told is not hung up"
    );
    assert!(world.ledger.rows().expect("rows").is_empty());
}

/// A Ping is read while writes are held and a closure comes before the next write, which fails:
/// the call ends as the provider's, nothing is hung up, and no row stands.
#[tokio::test(start_paused = true)]
async fn a_call_whose_read_left_a_pong_held_and_whose_write_fails_beside_a_closure_ends_as_the_providers()
 {
    let (world, own, mut provider, gate) = bridged().await;
    let control = world.provider.host_control(&own.call_id).expect("control");
    world
        .stand_in
        .script_hangup(HangupScript::Answer(404, None));
    gate.set(Writes::Hold);
    pinged(&mut provider).await;
    settle().await;
    said(&mut provider, &[closure()]).await;
    gate.set(Writes::Fail);
    assert_eq!(
        control.write(control.revision(), thinking()).await,
        Err(WriteRefusal::Lost),
        "the write is refused as lost"
    );
    settle().await;
    assert_eq!(
        control.state(),
        SidebandState::Closed(SidebandEnd::ProviderClosed),
        "the closure that came after the Ping was read"
    );
    assert!(
        world.stand_in.recorded().hangups.is_empty(),
        "a closure the provider told is not hung up"
    );
    assert!(world.ledger.rows().expect("rows").is_empty());
}

/// A read waits. A Ping and a valid closure then come, and writes fail: the same read, polled
/// again, gives the closure, and a read after it gives the end.
#[tokio::test]
async fn a_closure_behind_a_ping_that_comes_while_a_read_waits_is_read_when_writes_fail() {
    let (mut sideband, mut provider, gate) = connected().await;
    let task = Wakes::new();
    {
        let mut read = sideband.next();
        assert_eq!(poll_once(&mut read, &task), Poll::Pending, "the read waits");
        pinged(&mut provider).await;
        said(&mut provider, &[closure()]).await;
        gate.set(Writes::Fail);
        assert_eq!(
            poll_once(&mut read, &task),
            Poll::Ready(SocketRead::Text(closure())),
            "the read that was waiting gives the closure behind the Ping"
        );
    }
    assert_eq!(sideband.next().now_or_never(), Some(SocketRead::Closed));
}

/// The Pong a Ping owes waits for the stream, which takes no write. A closure then comes and writes
/// fail while the same read waits: that read gives the closure.
#[tokio::test]
async fn a_closure_that_comes_while_a_read_waits_behind_a_pong_whose_write_waits_is_read_when_writes_fail()
 {
    let (mut sideband, mut provider, gate) = connected().await;
    let task = Wakes::new();
    gate.set(Writes::Hold);
    {
        let mut read = sideband.next();
        assert_eq!(poll_once(&mut read, &task), Poll::Pending, "the read waits");
        pinged(&mut provider).await;
        assert_eq!(
            poll_once(&mut read, &task),
            Poll::Pending,
            "the read waits again, after the Ping"
        );
        assert!(gate.waits() > 0, "the Pong's write reached the stream");
        assert!(
            provider.next().now_or_never().is_none(),
            "the Pong has not gone out"
        );
        said(&mut provider, &[closure()]).await;
        gate.set(Writes::Fail);
        assert_eq!(
            poll_once(&mut read, &task),
            Poll::Ready(SocketRead::Text(closure())),
            "the read that was waiting gives the closure"
        );
    }
    assert_eq!(sideband.next().now_or_never(), Some(SocketRead::Closed));
}

/// A Ping is the only thing a read finds, and the Pong's write waits. When the stream lets that
/// write go it wakes the task that polled the read, which then sends the Pong, with no other input,
/// no write and no poll in between.
#[tokio::test]
async fn a_ping_read_with_no_other_input_sends_its_pong_when_the_write_that_waited_is_woken() {
    let (mut sideband, mut provider, gate) = connected().await;
    let task = Wakes::new();
    gate.set(Writes::Park);
    pinged(&mut provider).await;
    let mut read = sideband.next();
    assert_eq!(
        poll_once(&mut read, &task),
        Poll::Pending,
        "the read waits, with the Pong it owes"
    );
    assert!(gate.waits() > 0, "the Pong's write waits");
    gate.set(Writes::Pass);
    assert_eq!(task.count(), 1, "the write that waited woke the task");
    assert_eq!(
        poll_once(&mut read, &task),
        Poll::Pending,
        "the read has nothing to give"
    );
    assert!(is_pong(provider.next().now_or_never()), "the Pong went out");
}

/// The stream takes the bytes of a Pong and its flush waits, beside an event that the read gives.
/// When only the flush is woken, the next read flushes again and the Pong goes out.
#[tokio::test]
async fn a_pong_the_stream_took_and_did_not_flush_is_flushed_when_its_flush_is_woken() {
    let (mut sideband, mut provider, gate) = connected().await;
    let task = Wakes::new();
    gate.set_flushes(Flushes::Park);
    {
        let mut read = sideband.next();
        assert_eq!(poll_once(&mut read, &task), Poll::Pending, "the read waits");
        pinged(&mut provider).await;
        said(&mut provider, &[event(1)]).await;
        assert_eq!(
            poll_once(&mut read, &task),
            Poll::Ready(SocketRead::Text(event(1))),
            "the read gives the event"
        );
    }
    assert!(
        provider.next().now_or_never().is_none(),
        "the Pong's bytes are with the stream and have not gone out"
    );
    let woken = task.count();
    gate.set_flushes(Flushes::Follow);
    assert_eq!(
        task.count(),
        woken + 1,
        "the flush that waited woke the task"
    );
    let mut read = sideband.next();
    assert_eq!(
        poll_once(&mut read, &task),
        Poll::Pending,
        "the read has nothing to give"
    );
    assert!(
        is_pong(provider.next().now_or_never()),
        "the flush was tried again, and the Pong went out"
    );
}

/// The provider's closing frame is read, and so are the reads after it: each gives the end.
#[tokio::test]
async fn reads_after_the_providers_closing_frame_all_give_the_end() {
    let (mut sideband, mut provider, _gate) = connected().await;
    provider
        .send(Message::close(None, ""))
        .await
        .expect("the provider closes");
    for n in 0..3 {
        assert_eq!(
            sideband.next().now_or_never(),
            Some(SocketRead::Closed),
            "read {n} after the provider's closing frame gives the end"
        );
    }
}

/// More Pings than a read ahead takes come before a closure, and the stream's first write waits and
/// the rest fail: one read gives the closure.
#[tokio::test]
async fn a_closure_behind_more_pings_than_a_read_ahead_takes_is_read_when_the_first_write_waits() {
    let (mut sideband, mut provider, gate) = connected().await;
    for _ in 0..READ_AHEAD_MESSAGES {
        pinged(&mut provider).await;
    }
    said(&mut provider, &[closure()]).await;
    gate.set(Writes::HoldThenFail);
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(closure())),
        "the closure behind the Pings is read while their Pongs wait"
    );
    assert_eq!(sideband.next().now_or_never(), Some(SocketRead::Closed));
}

/// A write waits for the stream. A valid closure comes, and the write then fails: the closure is
/// read, and then the socket is closed.
#[tokio::test]
async fn a_closure_that_comes_while_a_write_waits_is_read_when_the_write_then_fails() {
    let (mut sideband, mut provider, gate) = connected().await;
    let task = Wakes::new();
    gate.set(Writes::Park);
    {
        let mut sending = sideband.send("{}".to_owned());
        assert_eq!(
            poll_once(&mut sending, &task),
            Poll::Pending,
            "the write waits"
        );
        said(&mut provider, &[closure()]).await;
        gate.set(Writes::Fail);
        assert_eq!(
            poll_once(&mut sending, &task),
            Poll::Ready(false),
            "the write failed"
        );
    }
    assert_eq!(
        sideband.next().now_or_never(),
        Some(SocketRead::Text(closure())),
        "the closure that came while the write waited is read"
    );
    assert_eq!(sideband.next().now_or_never(), Some(SocketRead::Closed));
}

/// A call waits in its read when a Ping and a valid closure come and writes fail: the call ends as
/// the provider's, nothing is hung up, and no row stands.
#[tokio::test(start_paused = true)]
async fn a_call_whose_read_waits_when_a_ping_and_a_closure_come_and_writes_fail_ends_as_the_providers()
 {
    let (world, own, mut provider, gate) = bridged().await;
    let control = world.provider.host_control(&own.call_id).expect("control");
    world
        .stand_in
        .script_hangup(HangupScript::Answer(404, None));
    settle().await;
    assert!(
        gate.read_polls() > 0,
        "the call has polled its read of the channel, and it waits"
    );
    assert_eq!(control.state(), SidebandState::Ready, "the call is open");
    pinged(&mut provider).await;
    said(&mut provider, &[closure()]).await;
    gate.set(Writes::Fail);
    settle().await;
    assert_eq!(
        control.state(),
        SidebandState::Closed(SidebandEnd::ProviderClosed),
        "the read that was waiting gave the closure behind the Ping"
    );
    assert!(
        world.stand_in.recorded().hangups.is_empty(),
        "a closure the provider told is not hung up"
    );
    assert!(world.ledger.rows().expect("rows").is_empty());
}

/// A call's write waits for the stream, a valid closure comes, and the write then fails: the call
/// ends as the provider's, nothing is hung up, and no row stands.
#[tokio::test(start_paused = true)]
async fn a_call_whose_write_waits_while_the_provider_closes_and_then_fails_ends_as_the_providers() {
    let (world, own, mut provider, gate) = bridged().await;
    let control = world.provider.host_control(&own.call_id).expect("control");
    world
        .stand_in
        .script_hangup(HangupScript::Answer(404, None));
    gate.set(Writes::Park);
    let writing = control.write(control.revision(), thinking());
    let passing = async {
        settle().await;
        assert!(gate.waits() > 0, "the write waits");
        said(&mut provider, &[closure()]).await;
        gate.set(Writes::Fail);
        settle().await;
    };
    let (written, ()) = tokio::join!(writing, passing);
    assert_eq!(
        written,
        Err(WriteRefusal::Lost),
        "the write is refused as lost"
    );
    assert_eq!(
        control.state(),
        SidebandState::Closed(SidebandEnd::ProviderClosed),
        "the closure that came while the write waited was read"
    );
    assert!(
        world.stand_in.recorded().hangups.is_empty(),
        "a closure the provider told is not hung up"
    );
    assert!(world.ledger.rows().expect("rows").is_empty());
}

/// A read is cancelled with a Pong queued in the library and its write waiting. A new read, with
/// another task's waker, is the one the stream's write wakes, and it sends the Pong.
#[tokio::test]
async fn a_new_read_after_a_cancelled_one_that_left_a_pong_queued_is_woken_by_the_write() {
    let (mut sideband, mut provider, gate) = connected().await;
    let (first, second) = (Wakes::new(), Wakes::new());
    gate.set(Writes::Park);
    pinged(&mut provider).await;
    {
        let mut read = sideband.next();
        assert_eq!(
            poll_once(&mut read, &first),
            Poll::Pending,
            "the read waits"
        );
        assert!(gate.waits() > 0, "the Pong's write waits");
    }
    let mut read = sideband.next();
    assert_eq!(
        poll_once(&mut read, &second),
        Poll::Pending,
        "the new read waits"
    );
    gate.set(Writes::Pass);
    assert_eq!(
        (first.count(), second.count()),
        (0, 1),
        "the write woke the task of the new read and no other"
    );
    assert_eq!(poll_once(&mut read, &second), Poll::Pending);
    assert!(is_pong(provider.next().now_or_never()), "the Pong went out");
}

/// A read is cancelled after the stream took the bytes of a Pong and its flush waits, with nothing
/// left queued in the library. A new read, with another task's waker, is the one the flush wakes,
/// and it flushes again.
#[tokio::test]
async fn a_new_read_after_a_cancelled_one_that_left_a_flush_waiting_is_woken_by_the_flush() {
    let (mut sideband, mut provider, gate) = connected().await;
    let (first, second) = (Wakes::new(), Wakes::new());
    gate.set_flushes(Flushes::Park);
    pinged(&mut provider).await;
    {
        let mut read = sideband.next();
        assert_eq!(
            poll_once(&mut read, &first),
            Poll::Pending,
            "the read waits"
        );
        assert!(gate.waits() > 0, "the Pong's flush waits");
    }
    let mut read = sideband.next();
    assert_eq!(
        poll_once(&mut read, &second),
        Poll::Pending,
        "the new read waits"
    );
    gate.set_flushes(Flushes::Follow);
    assert_eq!(
        (first.count(), second.count()),
        (0, 1),
        "the flush woke the task of the new read and no other"
    );
    assert_eq!(poll_once(&mut read, &second), Poll::Pending);
    assert!(is_pong(provider.next().now_or_never()), "the Pong went out");
}

/// A read is cancelled with a Pong queued in the library and its write waiting. A write, with
/// another task's waker, is the one the stream's write wakes, and the Pong goes out before its text.
#[tokio::test]
async fn a_write_after_a_cancelled_read_that_left_a_pong_queued_is_woken_by_the_write() {
    let (mut sideband, mut provider, gate) = connected().await;
    let (first, second) = (Wakes::new(), Wakes::new());
    gate.set(Writes::Park);
    pinged(&mut provider).await;
    {
        let mut read = sideband.next();
        assert_eq!(
            poll_once(&mut read, &first),
            Poll::Pending,
            "the read waits"
        );
    }
    let mut sending = sideband.send("{}".to_owned());
    assert_eq!(
        poll_once(&mut sending, &second),
        Poll::Pending,
        "the write waits"
    );
    gate.set(Writes::Pass);
    assert_eq!(
        (first.count(), second.count()),
        (0, 1),
        "the write woke the task of the new write and no other"
    );
    assert_eq!(
        poll_once(&mut sending, &second),
        Poll::Ready(true),
        "the write finished"
    );
    assert!(
        is_pong(provider.next().now_or_never()),
        "the Pong came first"
    );
    let text = provider.next().now_or_never();
    assert!(
        matches!(text, Some(Some(Ok(ref message))) if message.as_text() == Some("{}")),
        "the text came after it"
    );
}

/// A read is cancelled after the stream took the bytes of a Pong and its flush waits, with nothing
/// left queued in the library. A write, with another task's waker, is the one the flush wakes, and
/// the Pong goes out before its text.
#[tokio::test]
async fn a_write_after_a_cancelled_read_that_left_a_flush_waiting_is_woken_by_the_flush() {
    let (mut sideband, mut provider, gate) = connected().await;
    let (first, second) = (Wakes::new(), Wakes::new());
    gate.set_flushes(Flushes::Park);
    pinged(&mut provider).await;
    {
        let mut read = sideband.next();
        assert_eq!(
            poll_once(&mut read, &first),
            Poll::Pending,
            "the read waits"
        );
    }
    let mut sending = sideband.send("{}".to_owned());
    assert_eq!(
        poll_once(&mut sending, &second),
        Poll::Pending,
        "the write waits"
    );
    gate.set_flushes(Flushes::Follow);
    assert_eq!(
        (first.count(), second.count()),
        (0, 1),
        "the flush woke the task of the write and no other"
    );
    assert_eq!(
        poll_once(&mut sending, &second),
        Poll::Ready(true),
        "the write finished"
    );
    assert!(
        is_pong(provider.next().now_or_never()),
        "the Pong came first"
    );
    let text = provider.next().now_or_never();
    assert!(
        matches!(text, Some(Some(Ok(ref message))) if message.as_text() == Some("{}")),
        "the text came after it"
    );
}
