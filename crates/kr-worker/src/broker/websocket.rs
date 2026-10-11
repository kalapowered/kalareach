//! The WebSocket leg between a native terminal and the worker's gateway.
//!
//! A terminal started with `--remote unix://...` upgrades its connection to a WebSocket and sends
//! one JSON-RPC message in each text message. The gateway reads and writes one JSON document per
//! line, so this module is the adapter between the two: [`accept`] reads and vets the terminal's
//! upgrade request and completes the handshake, and what it returns reads each text message as one
//! line and writes each line it is given as one text message.
//!
//! **The request is vetted before anything answers it.** It is read under a bound and a deadline,
//! it must be a `GET` over HTTP/1.1, and none of its header lines may be one a browser adds (a page
//! that guessed the address cannot speak to this listener). Every line is looked at, a repeated
//! name included. The bytes that were read are then given to the WebSocket library as the start of
//! the connection, so the library parses the request this module vetted and no other. No
//! subprotocol is selected: the response names none, whatever the request offers.
//!
//! **A message is a line.** Only text messages are carried, and only one document each: a message
//! with a line break inside would be read as two frames, so it ends the connection, as does a binary
//! message and a message above the connection's frame bound.
//!
//! **A close that cannot be sent at once is sent when it can.** When the gateway ends a connection
//! the terminal is sent a close, so that it reads an end and not a reset. A terminal that has not
//! read the answers to its pings leaves them in the socket, and the close has no room behind
//! them. Dropping the connection hands the close to a task of its own, which waits for the room for
//! [`CLOSE_DEADLINE`] and then lets the socket go.
//!
//! **A flush is the library's own send.** The adapter implements reading and writing directly over
//! the WebSocket stream, so a flush returns when the library has written what it queued and not
//! before. The gateway's write deadline keeps its meaning: a terminal that has stopped reading
//! leaves the flush pending until the deadline ends the connection, and nothing sits in a buffer
//! this host cannot see.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio_websockets::{CloseCode, Limits, Message, ServerBuilder, WebSocketStream};

use crate::broker::error::{BrokerError, Result};
use crate::broker::framing::Framing;
use crate::broker::listener::reject_browser_origin;

/// The most bytes an upgrade request may have before its header block ends.
pub const MAX_REQUEST_HEAD_BYTES: usize = 16 * 1024;

/// The most header lines an upgrade request may carry.
pub const MAX_REQUEST_HEADERS: usize = 64;

/// How many ping and pong messages the gateway reads from a terminal in one window before it ends
/// the connection.
///
/// The library queues an answer to every ping it reads, and sends them while the terminal reads.
/// A terminal that pings and reads nothing would have them held without end, so the rate of them
/// has a bound. A keepalive, which sends a ping every few seconds at the most, is far below it.
pub const MAX_CONTROL_MESSAGES_PER_WINDOW: usize = 256;

/// How long one window of ping and pong messages is.
pub const CONTROL_WINDOW: Duration = Duration::from_secs(60);

/// How long a terminal has to send its upgrade request and have it answered.
pub const UPGRADE_DEADLINE: Duration = Duration::from_secs(5);

/// How long a close that the socket had no room for waits for room, once the gateway has let go of
/// the connection. A terminal that reads nothing for this long is gone.
pub const CLOSE_DEADLINE: Duration = Duration::from_secs(5);

/// A connection the gateway can carry a terminal's upgrade over, and hand to a task of its own.
pub trait Carrier: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Carrier for S {}

/// A connection's start: the bytes already read off it, then the rest of it.
#[derive(Debug)]
pub struct Replayed<S> {
    start: Vec<u8>,
    at: usize,
    rest: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Replayed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.at < self.start.len() {
            let take = (self.start.len() - self.at).min(buffer.remaining());
            let from = self.at;
            buffer.put_slice(&self.start[from..from + take]);
            self.at += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.rest).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replayed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.rest).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.rest).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.rest).poll_shutdown(cx)
    }
}

/// A terminal's connection after the upgrade, read and written as lines.
pub type Terminal<S> = TextLines<Replayed<S>>;

/// Reads the terminal's upgrade request from `stream`, refuses it or completes the handshake, and
/// returns the connection as lines.
///
/// The whole of it, the response included, has [`UPGRADE_DEADLINE`]. `framing` says how many bytes
/// a message may have.
///
/// # Errors
///
/// Returns [`BrokerError::PermissionDenied`] for a request that carries a header a browser adds,
/// and [`BrokerError::InvalidArgument`] for one that is not a `GET` over HTTP/1.1, that is larger
/// than [`MAX_REQUEST_HEAD_BYTES`] or has more than [`MAX_REQUEST_HEADERS`] header lines, that the
/// library does not accept as an upgrade, that ends before it is complete, or that does not arrive
/// within the deadline. A request that was read and refused is answered with a status before the
/// connection is closed.
pub async fn accept<S>(stream: S, framing: Framing) -> Result<Terminal<S>>
where
    S: Carrier,
{
    tokio::time::timeout(UPGRADE_DEADLINE, upgrade(stream, framing))
        .await
        .map_err(|_| {
            BrokerError::invalid("the terminal's upgrade request did not complete in time")
        })?
}

async fn upgrade<S>(mut stream: S, framing: Framing) -> Result<Terminal<S>>
where
    S: Carrier,
{
    let head = match read_head(&mut stream).await {
        Ok(head) => head,
        Err(refusal) => return Err(refuse(&mut stream, "400 Bad Request", refusal).await),
    };
    if let Err(refusal) = vet(&head) {
        let status = match refusal {
            BrokerError::PermissionDenied { .. } => "403 Forbidden",
            _ => "400 Bad Request",
        };
        return Err(refuse(&mut stream, status, refusal).await);
    }
    let replayed = Replayed {
        start: head,
        at: 0,
        rest: stream,
    };
    let (_request, socket) = ServerBuilder::new()
        .limits(Limits::default().max_payload_len(Some(framing.limit())))
        .accept(replayed)
        .await
        .map_err(|error| {
            BrokerError::invalid(format!(
                "the terminal's upgrade request was not accepted: {error}"
            ))
        })?;
    Ok(TextLines::new(socket, framing))
}

/// Answers a refused request with a status and closes the connection, and returns why.
async fn refuse<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: &str,
    why: BrokerError,
) -> BrokerError {
    let response = format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
    why
}

/// Reads until the request's header block ends, and returns every byte read.
///
/// The bytes after the block are the start of what the terminal sends next, and they stay with the
/// request so the library reads them where it expects them.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.map_err(|error| {
            BrokerError::invalid(format!(
                "the terminal's upgrade request could not be read: {error}"
            ))
        })?;
        if read == 0 {
            return Err(BrokerError::invalid(
                "the connection ended before the terminal's upgrade request did",
            ));
        }
        head.extend_from_slice(&chunk[..read]);
        let ended = head.windows(4).position(|window| window == b"\r\n\r\n");
        match ended {
            Some(end) if end + 4 > MAX_REQUEST_HEAD_BYTES => {}
            Some(_) => return Ok(head),
            None if head.len() <= MAX_REQUEST_HEAD_BYTES => continue,
            None => {}
        }
        return Err(BrokerError::invalid(format!(
            "the terminal's upgrade request is more than {MAX_REQUEST_HEAD_BYTES} bytes before its \
             headers end"
        )));
    }
}

/// Refuses a request that is not a plain upgrade from a native terminal.
fn vet(head: &[u8]) -> Result<()> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_REQUEST_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => {
            return Err(BrokerError::invalid(
                "the terminal's upgrade request ends before its headers do",
            ));
        }
        Err(error) => {
            return Err(BrokerError::invalid(format!(
                "the terminal's upgrade request is not readable: {error}"
            )));
        }
    }
    if request.method != Some("GET") {
        return Err(BrokerError::invalid(
            "the terminal's upgrade request is not a GET",
        ));
    }
    if request.version != Some(1) {
        return Err(BrokerError::invalid(
            "the terminal's upgrade request is not HTTP/1.1",
        ));
    }
    reject_browser_origin(request.headers.iter().map(|header| {
        (
            header.name,
            std::str::from_utf8(header.value).unwrap_or("(not text)"),
        )
    }))
}

/// A WebSocket connection read and written as lines of JSON.
///
/// When it is dropped, the gateway has ended the connection: the terminal is sent a close with the
/// reason the gateway had, if it had one, so that it reads an end and not a reset.
#[derive(Debug)]
pub struct TextLines<S: Carrier> {
    /// Held until the connection is dropped, which hands it to the close.
    socket: Option<WebSocketStream<S>>,
    /// Why the gateway ended the connection, when it did so for a message it refused.
    closing: Option<CloseCode>,
    /// When the window the ping and pong messages are counted in began, and how many have been
    /// read in it.
    control_window: Option<(tokio::time::Instant, usize)>,
    /// Whether the terminal has sent a close, after which anything that goes wrong is its leaving.
    peer_closed: bool,
    /// The most bytes a message that is read may have.
    read_limit: usize,
    /// The most bytes a message that is written may have.
    write_limit: usize,
    /// The message being read, line end included, and how much of it has been taken.
    reading: Vec<u8>,
    taken: usize,
    /// What has been written and is not yet a whole line.
    writing: Vec<u8>,
}

impl<S: Carrier> TextLines<S> {
    fn new(socket: WebSocketStream<S>, framing: Framing) -> Self {
        Self {
            socket: Some(socket),
            closing: None,
            control_window: None,
            peer_closed: false,
            read_limit: framing.limit(),
            write_limit: framing.largest_body(),
            reading: Vec::new(),
            taken: 0,
            writing: Vec::new(),
        }
    }
}

fn refused(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.to_owned())
}

fn failed(error: tokio_websockets::Error) -> io::Error {
    match error {
        tokio_websockets::Error::Io(error) => error,
        other => io::Error::other(other),
    }
}

impl<S> TextLines<S>
where
    S: Carrier,
{
    /// The socket, which is there until the connection is dropped.
    fn socket(&mut self) -> Pin<&mut WebSocketStream<S>> {
        Pin::new(
            self.socket
                .as_mut()
                .expect("the socket is held until the connection is dropped"),
        )
    }

    /// Hands the socket every whole line written so far, each as one text message.
    ///
    /// A line is taken off only when the socket is ready for it, so a socket that is not taking
    /// them leaves them here, counted against the bound, and this returns pending.
    fn send_lines(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(end) = self.writing.iter().position(|byte| *byte == b'\n') {
            if end > self.write_limit {
                return Poll::Ready(Err(refused(
                    "a frame is larger than the connection carries",
                )));
            }
            ready!(self.socket().poll_ready(cx)).map_err(failed)?;
            let line: Vec<u8> = self.writing.drain(..=end).take(end).collect();
            let text = String::from_utf8(line).map_err(|_| refused("a frame is not text"))?;
            self.socket()
                .start_send(Message::text(text))
                .map_err(failed)?;
        }
        Poll::Ready(Ok(()))
    }

    /// Notes why the connection is ending, for the close the terminal is sent, and returns the
    /// error that says so.
    fn end(&mut self, code: CloseCode, why: &str) -> io::Error {
        self.closing = Some(code);
        refused(why)
    }

    /// How many bytes of a line that has not ended are held.
    fn partial_line(&self) -> usize {
        self.writing
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(self.writing.len(), |end| self.writing.len() - end - 1)
    }
}

impl<S> AsyncRead for TextLines<S>
where
    S: Carrier,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.taken < self.reading.len() {
                let take = (self.reading.len() - self.taken).min(buffer.remaining());
                let from = self.taken;
                buffer.put_slice(&self.reading[from..from + take]);
                self.taken += take;
                return Poll::Ready(Ok(()));
            }
            let this = &mut *self;
            let message = match ready!(this.socket().poll_next(cx)) {
                None => return Poll::Ready(Ok(())),
                // A terminal that closed and then went away before the answer reached it has left,
                // and that is how a person quitting looks.
                Some(Err(_)) if this.peer_closed => return Poll::Ready(Ok(())),
                Some(Err(tokio_websockets::Error::PayloadTooLong { len, max_len })) => {
                    return Poll::Ready(Err(this.end(
                        CloseCode::MESSAGE_TOO_BIG,
                        &format!("a message of {len} bytes is more than the {max_len} carried"),
                    )));
                }
                Some(Err(error)) => return Poll::Ready(Err(failed(error))),
                Some(Ok(message)) => message,
            };
            // A close, and the answer to a ping, are the library's to send: it sends them from
            // the next poll, with the waker of whichever task is writing, and a flush started
            // here would take that waker away from a writer that is waiting on the socket. A
            // close is read to its end, so that the answer to it goes out before this reads one.
            if message.is_close() {
                this.peer_closed = true;
                continue;
            }
            if message.is_ping() || message.is_pong() {
                let now = tokio::time::Instant::now();
                let (since, counted) = this.control_window.get_or_insert((now, 0));
                if now.duration_since(*since) >= CONTROL_WINDOW {
                    (*since, *counted) = (now, 0);
                }
                *counted += 1;
                if *counted > MAX_CONTROL_MESSAGES_PER_WINDOW {
                    return Poll::Ready(Err(
                        this.end(CloseCode::POLICY_VIOLATION, "too many control messages")
                    ));
                }
                continue;
            }
            let Some(text) = message.as_text() else {
                return Poll::Ready(Err(this.end(
                    CloseCode::UNSUPPORTED_DATA,
                    "only text messages are carried",
                )));
            };
            if text.len() > this.read_limit {
                return Poll::Ready(Err(this.end(
                    CloseCode::MESSAGE_TOO_BIG,
                    "a message is larger than the connection carries",
                )));
            }
            if text.bytes().any(|byte| byte == b'\n') {
                return Poll::Ready(Err(
                    this.end(CloseCode::POLICY_VIOLATION, "a message holds a line break")
                ));
            }
            this.reading.clear();
            this.reading.extend_from_slice(text.as_bytes());
            this.reading.push(b'\n');
            this.taken = 0;
        }
    }
}

impl<S> AsyncWrite for TextLines<S>
where
    S: Carrier,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // The lines already written go first, so a socket that is not taking them holds this
        // write and nothing grows behind it.
        ready!(this.send_lines(cx))?;
        this.writing.extend_from_slice(buffer);
        // What this write completed is handed over if the socket is ready and kept if it is not:
        // the bytes are taken either way, and a flush is what waits for the socket to send them.
        if let Poll::Ready(Err(error)) = this.send_lines(cx) {
            return Poll::Ready(Err(error));
        }
        if this.partial_line() > this.write_limit {
            return Poll::Ready(Err(refused(
                "a frame is larger than the connection carries",
            )));
        }
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.send_lines(cx))?;
        this.socket().poll_flush(cx).map_err(failed)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.send_lines(cx))?;
        this.socket().poll_close(cx).map_err(failed)
    }
}

impl<S: Carrier> Drop for TextLines<S> {
    /// Sends the terminal a close, now if there is room for it in the socket and when there is
    /// otherwise.
    ///
    /// A close the connection has already sent is not sent again. Anything the library queued
    /// before this, a reply to the terminal's own close among it, goes out ahead of the close. What
    /// the socket will not take at once is left to a task that waits for the room for
    /// [`CLOSE_DEADLINE`]: the gateway has ended the connection and has no task of its own left to
    /// wait in. Where there is no runtime to run the task, what the socket takes now is all that is
    /// sent.
    fn drop(&mut self) {
        let Some(mut socket) = self.socket.take() else {
            return;
        };
        let code = self.closing.unwrap_or(CloseCode::NORMAL_CLOSURE);
        let _ = Pin::new(&mut socket).start_send(Message::close(Some(code), ""));
        let mut context = Context::from_waker(std::task::Waker::noop());
        if Pin::new(&mut socket).poll_flush(&mut context).is_ready() {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = tokio::time::timeout(
                    CLOSE_DEADLINE,
                    std::future::poll_fn(|cx| Pin::new(&mut socket).poll_flush(cx)),
                )
                .await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::gateway::NativeFraming;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    /// A ping a terminal sends, which carries nothing and is masked, as a client's frames are.
    const PING: [u8; 6] = [0x89, 0x80, 0, 0, 0, 0];

    /// Gives the reading task the turns it needs to read what was written to it.
    async fn settle() {
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
    }

    /// Upgrades a terminal's connection over an in-memory pipe that holds `room` bytes in each
    /// direction, and returns the terminal's end and the gateway's lines.
    async fn upgraded(room: usize) -> (tokio::io::DuplexStream, Terminal<tokio::io::DuplexStream>) {
        let (mut terminal, gateway) = tokio::io::duplex(room);
        let upgrading = tokio::spawn(accept(gateway, Framing::new(NativeFraming::JsonLines)));
        terminal
            .write_all(
                b"GET /rpc HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
                  Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                  Sec-WebSocket-Version: 13\r\n\r\n",
            )
            .await
            .expect("the request is written");
        let mut response = Vec::new();
        let mut chunk = [0_u8; 256];
        while !response.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = terminal.read(&mut chunk).await.expect("the response");
            assert_ne!(read, 0, "the connection ended before the upgrade");
            response.extend_from_slice(&chunk[..read]);
        }
        let lines = upgrading
            .await
            .expect("the upgrade ends")
            .expect("the terminal is accepted");
        (terminal, lines)
    }

    /// KR-REQ-11.32: the pings of a terminal are bounded by their rate and not by their number, so
    /// a keepalive that goes on for as long as a session does is not cut off, and a flood is.
    #[tokio::test(start_paused = true)]
    async fn kr_req_11_32_a_slow_keepalive_is_not_cut_off_and_a_flood_is() {
        let (mut terminal, mut lines) = upgraded(1 << 16).await;
        let mut reading = tokio::spawn(async move {
            let mut buffer = [0_u8; 16];
            lines.read(&mut buffer).await
        });

        // A bound's worth of pings, then a window later as many again: a keepalive, not a flood.
        for _ in 0..MAX_CONTROL_MESSAGES_PER_WINDOW {
            terminal.write_all(&PING).await.expect("a ping");
        }
        settle().await;
        assert!(
            !reading.is_finished(),
            "a bound's worth of pings is not cut off"
        );
        tokio::time::advance(CONTROL_WINDOW + Duration::from_secs(1)).await;
        for _ in 0..MAX_CONTROL_MESSAGES_PER_WINDOW {
            terminal.write_all(&PING).await.expect("a ping");
        }
        settle().await;
        assert!(
            !reading.is_finished(),
            "a keepalive that goes on is not cut off"
        );

        // More than the bound inside one window is a flood.
        terminal.write_all(&PING).await.expect("a ping");
        settle().await;
        let ended = (&mut reading).await.expect("the reader is joined");
        assert!(ended.is_err(), "the flood ended the connection: {ended:?}");
    }

    /// KR-REQ-11.32: a connection the gateway ends is closed to the terminal even when the pipe
    /// to it is full of the answers to the terminal's own pings, which a terminal that has not
    /// read them leaves there. The close waits for room and is sent when the terminal reads.
    #[tokio::test]
    async fn kr_req_11_32_a_close_the_socket_had_no_room_for_is_sent_when_the_terminal_reads() {
        // The pipe holds the answers to 32 pings, so the answers to the flood outgrow it.
        let (mut terminal, mut lines) = upgraded(64).await;
        let reading = tokio::spawn(async move {
            let mut buffer = [0_u8; 16];
            lines.read(&mut buffer).await
        });
        for _ in 0..=MAX_CONTROL_MESSAGES_PER_WINDOW {
            terminal.write_all(&PING).await.expect("a ping");
        }
        let ended = reading.await.expect("the reader is joined");
        assert!(ended.is_err(), "the flood ended the connection: {ended:?}");

        // The terminal reads only now: the answers, then the close and the end of the connection.
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(30), terminal.read_to_end(&mut received))
            .await
            .expect("the connection ends")
            .expect("it is readable");
        let policy_violation = [0x88, 0x02, 0x03, 0xF0];
        assert!(
            received.ends_with(&policy_violation),
            "the terminal was not sent the close that ended its connection"
        );
        assert!(
            received[..received.len() - policy_violation.len()]
                .chunks(2)
                .all(|answer| answer == [0x8A, 0x00]),
            "only the answers to its pings came before the close"
        );
    }
}
