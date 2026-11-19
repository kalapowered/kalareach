//! Cases of the side channel's adapter over a real WebSocket stream, on a connection that the test
//! controls: the provider's end is the library's own server, and the writes of the adapter's end
//! pass, stay pending, or fail as the test says. Nothing here waits for time to pass.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use futures_util::{FutureExt, SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio_websockets::{ClientBuilder, Message, ServerBuilder, WebSocketStream};

use super::*;

/// What a write on the adapter's end of the connection does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Writes {
    /// It goes through.
    Pass,
    /// It never finishes.
    Hold,
    /// It fails, as a write on a connection the other end reset does.
    Fail,
}

crate::debug_as_name!(Writes);

/// The test's hold on what the writes of one connection do.
#[derive(Clone)]
struct Gate(Arc<Mutex<Writes>>);

impl Gate {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Writes::Pass)))
    }

    fn set(&self, mode: Writes) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = mode;
    }

    fn mode(&self) -> Writes {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The adapter's end of an in-memory connection, with writes under a [`Gate`]. It takes writes as
/// the library offers them, in one buffer or in several, as `vectored` says.
struct Wire {
    inner: DuplexStream,
    gate: Gate,
    vectored: bool,
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
        match self.gate.mode() {
            Writes::Pass => Pin::new(&mut self.inner).poll_write(cx, buf),
            Writes::Hold => Poll::Pending,
            Writes::Fail => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.vectored
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.gate.mode() {
            Writes::Pass => Pin::new(&mut self.inner).poll_flush(cx),
            Writes::Hold => Poll::Pending,
            Writes::Fail => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
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
/// write that is cancelled leaves the connection failing.
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
            tokio::select! {
                biased;
                read = self.stand.next() => read,
                read = self.adapter.next() => read,
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
