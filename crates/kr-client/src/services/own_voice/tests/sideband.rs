//! Cases of the side channel's adapter over a real WebSocket stream, on a connection that the test
//! controls: the provider's end is the library's own server, and the writes of the adapter's end
//! pass, stay pending, or fail as the test says. Nothing here waits for time to pass.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use futures_util::{FutureExt, SinkExt};
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

/// The adapter's end of an in-memory connection, with writes under a [`Gate`].
struct Wire {
    inner: DuplexStream,
    gate: Gate,
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
    let (near, far) = tokio::io::duplex(1 << 20);
    let gate = Gate::new();
    let wire = Wire {
        inner: near,
        gate: gate.clone(),
    };
    let client = ClientBuilder::new()
        .uri("ws://stand-in.invalid/side")
        .expect("an address");
    let server = ServerBuilder::new();
    let (opened, accepted) = tokio::join!(client.connect_on(wire), server.accept(far));
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

/// The provider says each of these, one after the other, before the adapter reads any.
async fn said(provider: &mut WebSocketStream<DuplexStream>, texts: &[String]) {
    for text in texts {
        provider
            .send(Message::text(text.clone()))
            .await
            .expect("the provider writes");
    }
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
    assert_eq!(sideband.next().await, SocketRead::Text(usage()));
    gate.set(Writes::Fail);
    assert!(!sideband.send("{}".to_owned()).await, "the write failed");
    assert_eq!(
        sideband.next().await,
        SocketRead::Text(closure()),
        "the closure that was buffered when the write began is read"
    );
    assert_eq!(sideband.next().await, SocketRead::Closed);
}

/// A write that never finishes is cancelled with its frame queued in the library, and the
/// connection then fails: the closure buffered beside an event is still read.
#[tokio::test]
async fn a_closure_buffered_beside_an_event_is_read_after_a_write_is_cancelled() {
    let (mut sideband, mut provider, gate) = connected().await;
    said(&mut provider, &[usage(), closure()]).await;
    assert_eq!(sideband.next().await, SocketRead::Text(usage()));
    gate.set(Writes::Hold);
    assert!(
        sideband.send("{}".to_owned()).now_or_never().is_none(),
        "the write is held"
    );
    gate.set(Writes::Fail);
    assert_eq!(
        sideband.next().await,
        SocketRead::Text(closure()),
        "the closure that was buffered when the write began is read"
    );
    assert_eq!(sideband.next().await, SocketRead::Closed);
}

/// The read ahead stops after 256 messages: a closure behind more of them is not read after a
/// write that fails, and the read ahead keeps their order.
#[tokio::test]
async fn a_closure_behind_more_messages_than_a_write_reads_ahead_is_not_read_after_it_fails() {
    let (mut sideband, mut provider, gate) = connected().await;
    let mut texts = vec![usage(); 300];
    texts.push(closure());
    said(&mut provider, &texts).await;
    gate.set(Writes::Fail);
    assert!(!sideband.send("{}".to_owned()).await, "the write failed");
    for n in 0..256 {
        assert_eq!(
            sideband.next().await,
            SocketRead::Text(usage()),
            "message {n} was read ahead"
        );
    }
    assert_eq!(
        sideband.next().await,
        SocketRead::Closed,
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
        "the write was made before the closure was read"
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
        "the write was made before the closure was read"
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
