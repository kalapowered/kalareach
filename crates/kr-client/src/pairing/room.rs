//! The rendezvous room socket, for a host and for a candidate.
//!
//! A short-code invitation's room is a WebSocket at `wss://<origin>/api/pair/room/<locator>/<role>`,
//! opened on a TLS stream verified against the platform's trust store as the managed services'
//! requests are. The two roles differ in one thing: a host proves its reservation with the control
//! token in `KR-Pair-Control-Token`, and a candidate presents nothing, because the room serves it
//! the record of the locator it asked for and no more. Everything else is one implementation, so
//! the bounds on the upgrade, on the room's pings and on each direction's queue are the same for
//! both.
//!
//! Once open, one task carries the socket's frames to and from its caller: it reads the socket
//! only while no frame it read waits for the caller, so neither direction can hold the other up,
//! and a frame it cannot read ends the socket.
//!
//! # What a failure is
//!
//! [`RoomError`] says how far the socket got, and nothing more: the caller decides what that means
//! for a person. A host treats every kind but [`RoomError::Configuration`] as the service being
//! unavailable. A candidate tells an origin that serves no room (a page or a redirect where the
//! upgrade should be, a route the origin does not have) apart from a service that could not serve
//! this socket now, which is why a refused upgrade keeps its status.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use kr_crypto::secret::SymmetricKey;
use kr_protocol::pairing::{Locator, RendezvousOrigin};
use kr_protocol::rendezvous::{
    CONTROL_TOKEN_HEADER, ClientFrame, MAX_FRAME_BYTES, ServiceFrame, decode_service_frame,
    encode_frame,
};
use kr_protocol::scalars::to_base64url;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_websockets::{ClientBuilder, Limits, Message, WebSocketStream};

/// How long opening a room socket may take: the name, the connection, TLS and the upgrade.
pub const OPEN_DEADLINE: Duration = Duration::from_secs(10);

/// How many frames wait in each direction between a room socket and its caller.
const ROOM_QUEUE: usize = 16;

/// How long a socket may take to close once its pump is done with it.
const CLOSE_DEADLINE: Duration = Duration::from_secs(1);

/// The most of a room's answer to the upgrade that is read before its head is complete.
///
/// A real answer's head is a few hundred bytes.
pub const MAX_UPGRADE_ANSWER_BYTES: usize = 16 * 1024;

/// How many of the room's pings may arrive while the socket cannot take the answers to them.
///
/// The WebSocket library answers every ping itself and holds the answer until the socket takes
/// it, so a room that stops reading and keeps pinging would otherwise grow that queue without
/// bound.
pub const MAX_UNANSWERED_PINGS: u32 = 32;

/// One socket attached to a room, as frames in each direction.
///
/// Whoever opened the socket pumps it: an outgoing frame is sent on it, and every frame that
/// arrives is handed over here. `incoming` ends when the socket does, and dropping both ends the
/// socket.
#[derive(Debug)]
pub struct RoomSocket {
    /// Frames to send to the room.
    pub outgoing: mpsc::Sender<ClientFrame>,
    /// Frames the room sent.
    pub incoming: mpsc::Receiver<ServiceFrame>,
}

/// Which side of a room a socket is.
#[derive(Clone, Copy)]
pub enum RoomRole<'a> {
    /// The host that reserved the locator, proving the reservation with its control token.
    Host(&'a SymmetricKey),
    /// A candidate, which presents nothing.
    Candidate,
}

impl RoomRole<'_> {
    /// The last segment of the room's path for this role.
    const fn path(&self) -> &'static str {
        match self {
            Self::Host(_) => "host",
            Self::Candidate => "candidate",
        }
    }
}

impl std::fmt::Debug for RoomRole<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The control token is the reservation's whole authority, so it is never printed.
        formatter.write_str(self.path())
    }
}

/// How far opening a room socket got.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RoomError {
    /// The origin is not one this client can address, or a request to it cannot be written.
    #[error("the room at {origin} cannot be addressed: {reason}")]
    Configuration {
        /// The origin.
        origin: String,
        /// What is wrong.
        reason: String,
    },
    /// The name, the connection or TLS failed, or the socket did not open in time.
    #[error("the room at {origin} could not be reached: {reason}")]
    Unreachable {
        /// The origin.
        origin: String,
        /// What failed.
        reason: String,
    },
    /// The upgrade was answered with a status other than switching protocols.
    #[error("the room at {origin} answered the upgrade with status {status}")]
    Refused {
        /// The origin.
        origin: String,
        /// The status it answered with.
        status: u16,
    },
    /// The answer was not a WebSocket upgrade, or not one this client accepts.
    #[error("the room at {origin} did not answer with an upgrade: {reason}")]
    NotAnUpgrade {
        /// The origin.
        origin: String,
        /// What was wrong with the answer.
        reason: String,
    },
}

/// Opens room sockets with one TLS configuration.
#[derive(Clone, Debug)]
pub struct RoomConnector {
    tls: Arc<ClientConfig>,
}

impl RoomConnector {
    /// A connector that verifies rooms against the platform's trust store.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::Configuration`] when the platform's verifier cannot be set up.
    pub fn platform() -> Result<Self, RoomError> {
        let tls = ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .and_then(BuilderVerifierExt::with_platform_verifier)
        .map_err(|error| RoomError::Configuration {
            origin: "every origin".to_owned(),
            reason: format!("the platform's certificate verifier cannot be set up: {error}"),
        })?
        .with_no_client_auth();
        Ok(Self::with_tls(tls))
    }

    /// A connector that verifies rooms with `tls`, for a service whose certificates come from an
    /// authority the platform does not hold.
    #[must_use]
    pub fn with_tls(mut tls: ClientConfig) -> Self {
        // The upgrade is an HTTP/1.1 request, so that is the one protocol offered.
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self { tls: Arc::new(tls) }
    }

    /// Opens a socket in the room of `locator` at `origin`, as `role`.
    ///
    /// # Errors
    ///
    /// Returns a [`RoomError`] saying how far the socket got. The whole attempt is bounded by
    /// [`OPEN_DEADLINE`].
    pub async fn open(
        &self,
        origin: &RendezvousOrigin,
        locator: &Locator,
        role: RoomRole<'_>,
    ) -> Result<RoomSocket, RoomError> {
        let token = match role {
            RoomRole::Host(token) => Some(to_base64url(token.expose())),
            RoomRole::Candidate => None,
        };
        let opened = tokio::time::timeout(
            OPEN_DEADLINE,
            open_socket(
                Arc::clone(&self.tls),
                origin,
                locator,
                role.path(),
                token.as_deref(),
            ),
        )
        .await
        .map_err(|_| RoomError::Unreachable {
            origin: origin.as_str().to_owned(),
            reason: format!(
                "the socket did not open within {} seconds",
                OPEN_DEADLINE.as_secs()
            ),
        })??;
        Ok(pump(opened))
    }
}

/// Opens one socket: the connection, TLS verified for the origin's host, and the upgrade, with the
/// control token when the role has one.
async fn open_socket(
    tls: Arc<ClientConfig>,
    origin: &RendezvousOrigin,
    locator: &Locator,
    role: &str,
    token: Option<&str>,
) -> Result<WebSocketStream<UpgradeGuard<tokio_rustls::client::TlsStream<TcpStream>>>, RoomError> {
    let configuration = |reason: String| RoomError::Configuration {
        origin: origin.as_str().to_owned(),
        reason,
    };
    let unreachable = |what: &str, error: &dyn std::fmt::Display| RoomError::Unreachable {
        origin: origin.as_str().to_owned(),
        reason: format!("{what}: {error}"),
    };
    let authority = origin
        .as_str()
        .strip_prefix("https://")
        .ok_or_else(|| configuration("a rendezvous origin is an https origin".to_owned()))?;
    let (host, port) = host_and_port(authority).map_err(configuration)?;
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| configuration(format!("{host} is not a name TLS can verify")))?;
    let connection = TcpStream::connect((host, port))
        .await
        .map_err(|error| unreachable("the connection failed", &error))?;
    let stream = TlsConnector::from(tls)
        .connect(server_name, connection)
        .await
        .map_err(|error| unreachable("the TLS handshake failed", &error))?;
    let address = format!(
        "wss://{authority}/api/pair/room/{}/{role}",
        locator.as_str()
    );
    let mut builder = ClientBuilder::new()
        .uri(&address)
        .map_err(|error| configuration(format!("{address} is not an address: {error}")))?;
    if let Some(token) = token {
        builder = builder
            .add_header(
                CONTROL_TOKEN_HEADER.parse().map_err(|_| {
                    configuration("the control token header cannot be sent".to_owned())
                })?,
                token
                    .parse()
                    .map_err(|_| configuration("the control token cannot be sent".to_owned()))?,
            )
            .map_err(|_| configuration("the control token header cannot be sent".to_owned()))?;
    }
    let (socket, _) = builder
        .limits(Limits::default().max_payload_len(Some(MAX_FRAME_BYTES)))
        .connect_on(UpgradeGuard::new(stream))
        .await
        .map_err(|error| upgrade_failed(origin, error))?;
    Ok(socket)
}

/// Says how far an upgrade that failed got.
///
/// A status other than switching protocols is the room's answer, whatever it is. An answer that
/// is not an upgrade, or that the guard refused, is not one either. Anything else is the
/// connection failing part way through.
fn upgrade_failed(origin: &RendezvousOrigin, error: tokio_websockets::Error) -> RoomError {
    let origin = origin.as_str().to_owned();
    match error {
        tokio_websockets::Error::Upgrade(
            tokio_websockets::upgrade::Error::DidNotSwitchProtocols(status),
        ) => RoomError::Refused { origin, status },
        tokio_websockets::Error::Upgrade(error) => RoomError::NotAnUpgrade {
            origin,
            reason: error.to_string(),
        },
        tokio_websockets::Error::Io(error) if error.kind() == io::ErrorKind::InvalidData => {
            RoomError::NotAnUpgrade {
                origin,
                reason: error.to_string(),
            }
        }
        error => RoomError::Unreachable {
            origin,
            reason: format!("the upgrade did not finish: {error}"),
        },
    }
}

/// A room socket's stream, which holds the room's answer to the upgrade back until it is whole and
/// safe to parse.
///
/// The WebSocket library reads an answer's head for as long as it is incomplete, however long it
/// grows, and decodes `Sec-WebSocket-Accept` into a digest's twenty bytes on the assumption that
/// the value fits. So the answer is read here first, into a buffer of at most
/// [`MAX_UPGRADE_ANSWER_BYTES`], and handed on only once its head is complete and every accept
/// value in it is one SHA-1 digest in base64; anything else is an error of the stream, which ends
/// the attempt. The answer must begin with its status line: the library skips blank lines in
/// front of one, and they would put the end of a head where this guard looks for it. After the
/// head, reads and writes go straight to the stream.
struct UpgradeGuard<S> {
    stream: S,
    answer: Answered,
}

/// How far the room's answer to the upgrade has come.
enum Answered {
    /// Its head is still arriving.
    Reading(Vec<u8>),
    /// Its head was whole and acceptable: what was read is being handed on, from `at`.
    Handing { read: Vec<u8>, at: usize },
    /// Everything read ahead has been handed on.
    Through,
}

impl<S> UpgradeGuard<S> {
    const fn new(stream: S) -> Self {
        Self {
            stream,
            answer: Answered::Reading(Vec::new()),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for UpgradeGuard<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.answer {
                Answered::Through => return Pin::new(&mut this.stream).poll_read(cx, buf),
                Answered::Handing { read, at } => {
                    let count = (read.len() - *at).min(buf.remaining());
                    buf.put_slice(&read[*at..*at + count]);
                    *at += count;
                    if *at == read.len() {
                        this.answer = Answered::Through;
                    }
                    return Poll::Ready(Ok(()));
                }
                Answered::Reading(head) => {
                    let mut chunk = [0; 1024];
                    let room = (MAX_UPGRADE_ANSWER_BYTES - head.len()).min(chunk.len());
                    let mut into = ReadBuf::new(&mut chunk[..room]);
                    ready!(Pin::new(&mut this.stream).poll_read(cx, &mut into))?;
                    if into.filled().is_empty() {
                        // The room ended the stream part way through its answer, which the
                        // library reads as the end it is.
                        return Poll::Ready(Ok(()));
                    }
                    head.extend_from_slice(into.filled());
                    let start = head.len().min(STATUS_LINE_START.len());
                    if head[..start] != STATUS_LINE_START[..start] {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "the room's answer to the upgrade does not begin with a status line",
                        )));
                    }
                    if let Some(end) = head.windows(4).position(|window| window == b"\r\n\r\n") {
                        check_upgrade_head(&head[..end + 4])?;
                        let read = std::mem::take(head);
                        this.answer = Answered::Handing { read, at: 0 };
                    } else if head.len() >= MAX_UPGRADE_ANSWER_BYTES {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "the room's answer to the upgrade is longer than an answer may be",
                        )));
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for UpgradeGuard<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

/// How an answer to the upgrade begins: its status line.
const STATUS_LINE_START: &[u8] = b"HTTP/";

/// Refuses an answer carrying a `Sec-WebSocket-Accept` that is anything but one SHA-1 digest in
/// padded base64, on whichever line it appears: the value is decoded into twenty bytes, and a
/// longer one does not fit. A value is trimmed exactly as the library's parser trims it (spaces
/// and tabs in front, spaces, tabs and line ends behind), so what is checked here is what the
/// library decodes.
fn check_upgrade_head(head: &[u8]) -> io::Result<()> {
    for line in head.split(|byte| *byte == b'\n') {
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        if !line[..colon]
            .trim_ascii()
            .eq_ignore_ascii_case(b"sec-websocket-accept")
        {
            continue;
        }
        let value = &line[colon + 1..];
        let start = value
            .iter()
            .position(|byte| !matches!(byte, b' ' | b'\t'))
            .unwrap_or(value.len());
        let end = value
            .iter()
            .rposition(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
            .map_or(start, |last| last + 1)
            .max(start);
        let value = &value[start..end];
        let digest = value.len() == 28
            && value[27] == b'='
            && value[..27]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'));
        if !digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the room's answer to the upgrade carries an accept value that is no SHA-1 digest",
            ));
        }
    }
    Ok(())
}

/// Splits an origin's authority into its host, without an IPv6 literal's brackets, and its port.
fn host_and_port(authority: &str) -> Result<(&str, u16), String> {
    let (host, port) = match authority.strip_prefix('[') {
        Some(bracketed) => {
            let (host, rest) = bracketed
                .split_once(']')
                .ok_or_else(|| "an IPv6 origin closes its brackets".to_owned())?;
            (host, rest.strip_prefix(':'))
        }
        None => match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    let port = match port {
        Some(port) => port.parse().map_err(|_| format!("{port} is not a port"))?,
        None => 443,
    };
    Ok((host, port))
}

/// Starts the task that carries one room socket's frames, and returns the caller's ends of it.
fn pump<S>(socket: WebSocketStream<S>) -> RoomSocket
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (to_caller, incoming) = mpsc::channel(ROOM_QUEUE);
    let (outgoing, from_caller) = mpsc::channel(ROOM_QUEUE);
    tokio::spawn(carry(socket, to_caller, from_caller));
    RoomSocket { outgoing, incoming }
}

/// A frame the room sent, and the wait for the caller to have room for it.
type Delivery = (
    ServiceFrame,
    Pin<
        Box<
            dyn Future<Output = Result<mpsc::OwnedPermit<ServiceFrame>, mpsc::error::SendError<()>>>
                + Send,
        >,
    >,
);

/// Carries frames between one room socket and its caller until either lets go.
///
/// Both directions move in the one task, each as far as it can: the room's frames are read and
/// delivered while the caller's wait to be written, and the caller's are taken and written while
/// the room's wait for the caller. A frame the room sent waits here until the caller has room for
/// it, and the socket is read no further meanwhile, which is the room's backpressure; the socket
/// takes the caller's next frame only when it can accept one, which is the caller's. A frame of the
/// room's that this client cannot read ends the socket.
async fn carry<S>(
    mut socket: WebSocketStream<S>,
    to_caller: mpsc::Sender<ServiceFrame>,
    mut from_caller: mpsc::Receiver<ClientFrame>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let caller_gone = to_caller.closed();
    tokio::pin!(caller_gone);
    let mut delivering: Option<Delivery> = None;
    let mut unflushed = false;
    // Pings read since the socket last took everything queued for it, answers included.
    let mut unanswered_pings = 0_u32;
    std::future::poll_fn(|cx| {
        loop {
            if caller_gone.as_mut().poll(cx).is_ready() {
                return Poll::Ready(());
            }
            let mut moved = false;
            if let Some((_, room)) = &mut delivering {
                match room.as_mut().poll(cx) {
                    Poll::Ready(Ok(permit)) => {
                        if let Some((frame, _)) = delivering.take() {
                            permit.send(frame);
                        }
                        moved = true;
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(()),
                    Poll::Pending => {}
                }
            }
            if delivering.is_none() {
                match socket.poll_next_unpin(cx) {
                    Poll::Ready(Some(Ok(message))) if message.is_binary() => {
                        let Ok(frame) = decode_service_frame(message.as_payload()) else {
                            return Poll::Ready(());
                        };
                        delivering = Some((frame, Box::pin(to_caller.clone().reserve_owned())));
                        moved = true;
                    }
                    // The library answers a ping itself, and the answer waits in its queue until a
                    // flush takes it; a room that pings without reading gets only so many.
                    Poll::Ready(Some(Ok(message))) if message.is_ping() => {
                        unanswered_pings += 1;
                        if unanswered_pings > MAX_UNANSWERED_PINGS {
                            return Poll::Ready(());
                        }
                        unflushed = true;
                        moved = true;
                    }
                    Poll::Ready(Some(Ok(message))) if message.is_pong() => moved = true,
                    // Text is no frame of the room's, and a close, an error or the end ends it.
                    Poll::Ready(_) => return Poll::Ready(()),
                    Poll::Pending => {}
                }
            }
            match socket.poll_ready_unpin(cx) {
                Poll::Ready(Ok(())) => match from_caller.poll_recv(cx) {
                    Poll::Ready(Some(frame)) => {
                        let Ok(bytes) = encode_frame(&frame) else {
                            return Poll::Ready(());
                        };
                        if socket.start_send_unpin(Message::binary(bytes)).is_err() {
                            return Poll::Ready(());
                        }
                        unflushed = true;
                        moved = true;
                    }
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => {}
                },
                Poll::Ready(Err(_)) => return Poll::Ready(()),
                Poll::Pending => {}
            }
            if unflushed {
                match socket.poll_flush_unpin(cx) {
                    Poll::Ready(Ok(())) => {
                        unflushed = false;
                        unanswered_pings = 0;
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(()),
                    Poll::Pending => {}
                }
            }
            if !moved {
                return Poll::Pending;
            }
        }
    })
    .await;
    if let Some((frame, _)) = delivering {
        let _ = tokio::time::timeout(CLOSE_DEADLINE, to_caller.send(frame)).await;
    }
    let _ = tokio::time::timeout(CLOSE_DEADLINE, socket.close()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard trims an accept value as the library's parser does, so a correct digest with
    /// optional whitespace around it passes, and anything that is not one digest does not.
    #[test]
    fn an_accept_value_is_checked_as_the_library_reads_it() {
        let head = |value: &str| {
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Sec-WebSocket-Accept:{value}\r\n\r\n"
            )
        };
        let digest = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        for passes in [
            format!(" {digest}"),
            digest.to_owned(),
            format!(" \t{digest} \t"),
            format!("{digest}\t"),
        ] {
            assert!(
                check_upgrade_head(head(&passes).as_bytes()).is_ok(),
                "{passes:?}"
            );
        }
        for refused in [
            format!(" {digest}A"),
            " AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            " s3pPLMBiTxaQ9kYGzzhZRbK+xOoA".to_owned(),
            " s3pPLMBiTxaQ 9kYGzzhZRbK+xO=".to_owned(),
            String::new(),
        ] {
            assert!(
                check_upgrade_head(head(&refused).as_bytes()).is_err(),
                "{refused:?}"
            );
        }
    }

    /// An origin's authority splits into the host TLS verifies and the port, with an IPv6 literal's
    /// brackets removed and 443 when none is named.
    #[test]
    fn an_authority_splits_into_its_host_and_port() {
        assert_eq!(host_and_port("reach.kala.to"), Ok(("reach.kala.to", 443)));
        assert_eq!(host_and_port("127.0.0.1:8443"), Ok(("127.0.0.1", 8443)));
        assert_eq!(host_and_port("[::1]:8443"), Ok(("::1", 8443)));
        assert_eq!(host_and_port("[::1]"), Ok(("::1", 443)));
        assert!(host_and_port("[::1:8443").is_err());
        assert!(host_and_port("pair.example.org:port").is_err());
    }

    /// A control token never reaches a rendering of the role that carries it.
    #[test]
    fn a_role_never_prints_its_token() {
        let token = SymmetricKey::from_bytes([0x41; 32]);
        let rendered = format!("{:?}", RoomRole::Host(&token));
        assert_eq!(rendered, "host");
        assert!(!rendered.contains(&to_base64url(token.expose())));
    }
}
