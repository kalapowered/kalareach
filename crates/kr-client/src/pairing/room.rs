//! The rendezvous room socket, for a host and for a candidate.
//!
//! A short-code invitation's room is a WebSocket at `wss://<origin>/api/pair/room/<locator>/<role>`,
//! opened on a TLS stream verified against the platform's trust as the managed services' requests
//! are ([`crate::services::http::platform_tls`]). The connection is the room's own, or, for a host
//! whose configuration selects a proxy, a `CONNECT` tunnel through that proxy; a candidate has no
//! such selection and connects directly. The two roles differ in one thing: a host proves its
//! reservation with the control token in `KR-Pair-Control-Token`, and a candidate presents
//! nothing, because the room serves it the record of the locator it asked for and no more.
//! Everything else is one implementation, so the bounds on the upgrade, on the room's pings and on
//! each direction's queue are the same for both.
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
use std::net::IpAddr;
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
use kr_transport::config::ProxyUrl;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_websockets::{ClientBuilder, Limits, Message, WebSocketStream};

use crate::shown::{Said, Shown};

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

/// The most of a proxy's answer to a tunnel request that is read before its head is complete.
///
/// A real answer is a status line and a few headers.
pub const MAX_TUNNEL_ANSWER_BYTES: usize = 16 * 1024;

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
///
/// What it says is its stage, the origin as a diagnostic names an address, the status a room
/// answered with, and a reason when the reason is one this client gives. A reason is otherwise
/// text somebody else wrote, and it is replaced.
#[derive(Clone, PartialEq, Eq)]
pub enum RoomError {
    /// The origin is not one this client can address, or a request to it cannot be written.
    Configuration {
        /// The origin.
        origin: String,
        /// What is wrong.
        reason: String,
    },
    /// The name, the connection, the proxy or TLS failed, or the socket did not open in time.
    Unreachable {
        /// The origin.
        origin: String,
        /// What failed.
        reason: String,
    },
    /// The upgrade was answered with a status other than switching protocols.
    Refused {
        /// The origin.
        origin: String,
        /// The status it answered with.
        status: u16,
    },
    /// The answer was not a WebSocket upgrade, or not one this client accepts.
    NotAnUpgrade {
        /// The origin.
        origin: String,
        /// What was wrong with the answer.
        reason: String,
    },
}

impl Said for RoomError {
    fn said(&self) -> Shown {
        match self {
            Self::Configuration { origin, reason } => crate::shown!(
                "the room at {} cannot be addressed: {}",
                room_origin(origin),
                room_reason(reason)
            ),
            Self::Unreachable { origin, reason } => crate::shown!(
                "the room at {} could not be reached: {}",
                room_origin(origin),
                room_reason(reason)
            ),
            Self::Refused { origin, status } => crate::shown!(
                "the room at {} answered the upgrade with status {}",
                room_origin(origin),
                *status
            ),
            Self::NotAnUpgrade { origin, reason } => crate::shown!(
                "the room at {} did not answer with an upgrade: {}",
                room_origin(origin),
                room_reason(reason)
            ),
        }
    }
}

crate::display_as_said!(RoomError);
crate::debug_as_display!(RoomError);

impl std::error::Error for RoomError {}

/// What a failure that concerns no origin in particular names as its origin.
const EVERY_ORIGIN: &str = "every origin";

/// The platform's certificate verifier could not be set up.
const NO_VERIFIER: &str = "the platform's certificate verifier cannot be set up";
/// The origin is not an https origin.
const NOT_HTTPS: &str = "a rendezvous origin is an https origin";
/// An IPv6 origin's brackets do not close.
const OPEN_BRACKETS: &str = "an IPv6 origin closes its brackets";
/// The origin's port is not a number a port can be.
const NOT_A_PORT: &str = "the origin's port is not a port number";
/// The origin's host is not a name TLS can verify.
const NOT_A_TLS_NAME: &str = "the origin's host is not a name TLS can verify";
/// The room's address cannot be written as a request.
const NOT_AN_ADDRESS: &str = "the room's address cannot be written as a request";
/// The control token's header cannot be sent.
const NO_TOKEN_HEADER: &str = "the control token header cannot be sent";
/// The control token cannot be sent.
const NO_TOKEN: &str = "the control token cannot be sent";
/// The socket did not open within [`OPEN_DEADLINE`].
const TOO_SLOW: &str = "the socket did not open within its deadline";
/// The connection to the origin's host failed.
const NO_CONNECTION: &str = "the connection failed";
/// The TLS handshake failed.
const NO_TLS: &str = "the TLS handshake failed";
/// The upgrade did not finish.
const UNFINISHED: &str = "the upgrade did not finish";
/// The answer does not begin with a status line.
const NO_STATUS_LINE: &str = "the room's answer to the upgrade does not begin with a status line";
/// The answer is longer than [`MAX_UPGRADE_ANSWER_BYTES`].
const TOO_LONG: &str = "the room's answer to the upgrade is longer than an answer may be";
/// The answer carries an accept value that is not one SHA-1 digest.
const NOT_A_DIGEST: &str =
    "the room's answer to the upgrade carries an accept value that is no SHA-1 digest";
/// The answer lacks a header an upgrade needs.
const MISSING_HEADER: &str = "the answer lacks a header an upgrade needs";
/// The answer's `Upgrade` header is not `websocket`.
const NOT_WEBSOCKET: &str = "the answer upgrades to another protocol than WebSocket";
/// The answer's `Connection` header does not upgrade.
const NO_UPGRADE: &str = "the answer's connection header does not upgrade";
/// The answer names a WebSocket version this client does not speak.
const OTHER_VERSION: &str = "the answer names a WebSocket version this client does not speak";
/// The answer is not a response that can be read.
const UNPARSED: &str = "the answer is not a response this client can read";
/// The answer's accept value is not the one the key this client sent asks for.
const WRONG_ACCEPT: &str = "the answer's accept value does not match the key this client sent";
/// Any other answer that is not an upgrade.
const NOT_ACCEPTED: &str = "the answer is not an upgrade this client accepts";

/// The proxy's address names no port.
const PROXY_NO_PORT: &str = "the proxy's address names no port";
/// The proxy's address names no host.
const PROXY_NO_HOST: &str = "the proxy's address names no host";
/// The connection to the proxy failed.
const PROXY_UNREACHABLE: &str = "the proxy could not be reached";
/// The proxy's host is not a name TLS can verify.
const PROXY_NOT_A_TLS_NAME: &str = "the proxy's host is not a name TLS can verify";
/// The TLS handshake with the proxy failed.
const PROXY_NO_TLS: &str = "the TLS handshake with the proxy failed";
/// The tunnel request could not be sent to the proxy.
const PROXY_REQUEST_FAILED: &str = "the tunnel request to the proxy failed";
/// The proxy's answer is longer than [`MAX_TUNNEL_ANSWER_BYTES`].
const PROXY_ANSWER_TOO_LONG: &str =
    "the proxy's answer to the tunnel request is longer than an answer may be";
/// The proxy ended the connection before its answer's head was complete.
const PROXY_ENDED: &str = "the proxy ended the connection before it answered";
/// The proxy's answer does not begin with a status line.
const PROXY_NO_STATUS_LINE: &str = "the proxy did not answer the tunnel request with a status line";
/// The proxy answered the tunnel request with a status other than 2xx, which follows these words.
const PROXY_REFUSED: &str = "the proxy refused the tunnel with status";

/// The reasons this client gives a room failure, which are the only reasons a failure says.
const ROOM_REASONS: [&str; 31] = [
    NO_VERIFIER,
    NOT_HTTPS,
    OPEN_BRACKETS,
    NOT_A_PORT,
    NOT_A_TLS_NAME,
    NOT_AN_ADDRESS,
    NO_TOKEN_HEADER,
    NO_TOKEN,
    TOO_SLOW,
    NO_CONNECTION,
    NO_TLS,
    UNFINISHED,
    NO_STATUS_LINE,
    TOO_LONG,
    NOT_A_DIGEST,
    MISSING_HEADER,
    NOT_WEBSOCKET,
    NO_UPGRADE,
    OTHER_VERSION,
    UNPARSED,
    WRONG_ACCEPT,
    NOT_ACCEPTED,
    PROXY_NO_PORT,
    PROXY_NO_HOST,
    PROXY_UNREACHABLE,
    PROXY_NOT_A_TLS_NAME,
    PROXY_NO_TLS,
    PROXY_REQUEST_FAILED,
    PROXY_ANSWER_TOO_LONG,
    PROXY_ENDED,
    PROXY_NO_STATUS_LINE,
];

/// What a room failure says of its origin: the address as a diagnostic names one, or that it
/// concerns every origin.
fn room_origin(origin: &str) -> Shown {
    if origin == EVERY_ORIGIN {
        Shown::said(EVERY_ORIGIN)
    } else {
        Shown::address(origin)
    }
}

/// What a room failure says of its reason: the reason when this client gives it, a proxy's refusal
/// by its three-digit status, and a placeholder for any other.
fn room_reason(reason: &str) -> Shown {
    let refused = reason
        .strip_prefix(PROXY_REFUSED)
        .and_then(|rest| rest.strip_prefix(' '))
        .filter(|status| status.len() == 3 && status.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|status| status.parse::<u16>().ok());
    if let Some(status) = refused {
        return crate::shown!("{} {}", PROXY_REFUSED, status);
    }
    ROOM_REASONS
        .iter()
        .find(|known| **known == reason)
        .map_or_else(
            || Shown::said("[a reason this client does not give]"),
            |known| Shown::said(known),
        )
}

/// Opens room sockets with one TLS configuration, directly or through one proxy.
#[derive(Clone, Debug)]
pub struct RoomConnector {
    tls: Arc<ClientConfig>,
    proxy: Option<ProxyUrl>,
}

impl RoomConnector {
    /// A connector that verifies rooms against the platform's trust
    /// ([`crate::services::http::platform_tls`]) and opens them directly.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::Configuration`] when the platform's verifier cannot be set up.
    pub fn platform() -> Result<Self, RoomError> {
        let tls =
            crate::services::http::platform_tls(&[]).map_err(|_| RoomError::Configuration {
                origin: EVERY_ORIGIN.to_owned(),
                reason: NO_VERIFIER.to_owned(),
            })?;
        Ok(Self::with_tls(tls))
    }

    /// A connector that verifies rooms with `tls`, for a service whose certificates come from an
    /// authority the platform does not hold, and opens them directly.
    #[must_use]
    pub fn with_tls(mut tls: ClientConfig) -> Self {
        // The upgrade is an HTTP/1.1 request, so that is the one protocol offered.
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            tls: Arc::new(tls),
            proxy: None,
        }
    }

    /// The same connector, opening its sockets through `proxy`, or directly when that is `None`.
    ///
    /// A host names the proxy its configuration document selects, and a candidate has no such
    /// document and names none; nothing is read from the environment. Through a proxy, a socket
    /// is an HTTP `CONNECT` tunnel to the room, and the room's TLS runs inside it, so the proxy
    /// sees where the socket goes and nothing that travels on it. A proxy that cannot be reached
    /// or refuses the tunnel ends the attempt: nothing goes around it.
    #[must_use]
    pub fn through(mut self, proxy: Option<ProxyUrl>) -> Self {
        self.proxy = proxy;
        self
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
                self.proxy.as_ref(),
                origin,
                locator,
                role.path(),
                token.as_deref(),
            ),
        )
        .await
        .map_err(|_| RoomError::Unreachable {
            origin: origin.as_str().to_owned(),
            reason: TOO_SLOW.to_owned(),
        })??;
        Ok(pump(opened))
    }
}

/// Opens one socket: the connection, directly or through `proxy`, TLS verified for the origin's
/// host, and the upgrade, with the control token when the role has one.
async fn open_socket(
    tls: Arc<ClientConfig>,
    proxy: Option<&ProxyUrl>,
    origin: &RendezvousOrigin,
    locator: &Locator,
    role: &str,
    token: Option<&str>,
) -> Result<WebSocketStream<UpgradeGuard<tokio_rustls::client::TlsStream<Carrier>>>, RoomError> {
    let configuration = |reason: &'static str| RoomError::Configuration {
        origin: origin.as_str().to_owned(),
        reason: reason.to_owned(),
    };
    let unreachable = |reason: &'static str| RoomError::Unreachable {
        origin: origin.as_str().to_owned(),
        reason: reason.to_owned(),
    };
    let authority = origin
        .as_str()
        .strip_prefix("https://")
        .ok_or_else(|| configuration(NOT_HTTPS))?;
    let (host, port) = host_and_port(authority).map_err(configuration)?;
    let server_name =
        ServerName::try_from(host.to_owned()).map_err(|_| configuration(NOT_A_TLS_NAME))?;
    let connection = match proxy {
        None => Carrier::Plain(
            TcpStream::connect((host, port))
                .await
                .map_err(|_| unreachable(NO_CONNECTION))?,
        ),
        Some(proxy) => {
            tunnel(proxy, host, port, &tls)
                .await
                .map_err(|failure| RoomError::Unreachable {
                    origin: origin.as_str().to_owned(),
                    reason: failure.reason(),
                })?
        }
    };
    let stream = TlsConnector::from(tls)
        .connect(server_name, connection)
        .await
        .map_err(|_| unreachable(NO_TLS))?;
    let address = format!(
        "wss://{authority}/api/pair/room/{}/{role}",
        locator.as_str()
    );
    let mut builder = ClientBuilder::new()
        .uri(&address)
        .map_err(|_| configuration(NOT_AN_ADDRESS))?;
    if let Some(token) = token {
        builder = builder
            .add_header(
                CONTROL_TOKEN_HEADER
                    .parse()
                    .map_err(|_| configuration(NO_TOKEN_HEADER))?,
                token.parse().map_err(|_| configuration(NO_TOKEN))?,
            )
            .map_err(|_| configuration(NO_TOKEN_HEADER))?;
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
/// connection failing part way through, TLS included: its failures after the handshake reach this
/// as input errors of the same kind the guard's do, so the guard's are told apart by their own
/// type rather than by their kind.
fn upgrade_failed(origin: &RendezvousOrigin, error: tokio_websockets::Error) -> RoomError {
    use tokio_websockets::upgrade;

    let origin = origin.as_str().to_owned();
    match error {
        tokio_websockets::Error::Upgrade(upgrade::Error::DidNotSwitchProtocols(status)) => {
            RoomError::Refused { origin, status }
        }
        tokio_websockets::Error::Upgrade(error) => RoomError::NotAnUpgrade {
            origin,
            reason: match error {
                upgrade::Error::MissingHeader(_) => MISSING_HEADER,
                upgrade::Error::UpgradeNotWebSocket => NOT_WEBSOCKET,
                upgrade::Error::ConnectionNotUpgrade => NO_UPGRADE,
                upgrade::Error::UnsupportedWebSocketVersion => OTHER_VERSION,
                upgrade::Error::Parsing(_) => UNPARSED,
                upgrade::Error::WrongWebSocketAccept => WRONG_ACCEPT,
                _ => NOT_ACCEPTED,
            }
            .to_owned(),
        },
        tokio_websockets::Error::Io(error) => match GuardRefusal::of(&error) {
            Some(refusal) => RoomError::NotAnUpgrade {
                origin,
                reason: refusal.to_owned(),
            },
            None => RoomError::Unreachable {
                origin,
                reason: UNFINISHED.to_owned(),
            },
        },
        _ => RoomError::Unreachable {
            origin,
            reason: UNFINISHED.to_owned(),
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

/// The guard refusing the room's answer to the upgrade.
///
/// It travels inside an input error, the only kind of error a stream can return, and is its own
/// type so that a refusal of the answer is never confused with the stream failing underneath: TLS
/// reports a corrupt record after the handshake with the same error kind.
struct GuardRefusal(&'static str);

impl GuardRefusal {
    /// Returns the input error that carries this refusal.
    fn error(reason: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, Self(reason))
    }

    /// The reason the guard gave, when `error` carries the guard's refusal.
    fn of(error: &io::Error) -> Option<&'static str> {
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<Self>())
            .map(|refusal| refusal.0)
    }
}

impl Said for GuardRefusal {
    fn said(&self) -> Shown {
        Shown::said(self.0)
    }
}

crate::display_as_said!(GuardRefusal);
crate::debug_as_display!(GuardRefusal);

impl std::error::Error for GuardRefusal {}

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
                        return Poll::Ready(Err(GuardRefusal::error(NO_STATUS_LINE)));
                    }
                    if let Some(end) = head.windows(4).position(|window| window == b"\r\n\r\n") {
                        check_upgrade_head(&head[..end + 4])?;
                        let read = std::mem::take(head);
                        this.answer = Answered::Handing { read, at: 0 };
                    } else if head.len() >= MAX_UPGRADE_ANSWER_BYTES {
                        return Poll::Ready(Err(GuardRefusal::error(TOO_LONG)));
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
            return Err(GuardRefusal::error(NOT_A_DIGEST));
        }
    }
    Ok(())
}

/// Splits an origin's authority into its host, without an IPv6 literal's brackets, and its port.
fn host_and_port(authority: &str) -> Result<(&str, u16), &'static str> {
    let (host, port) = match authority.strip_prefix('[') {
        Some(bracketed) => {
            let (host, rest) = bracketed.split_once(']').ok_or(OPEN_BRACKETS)?;
            (host, rest.strip_prefix(':'))
        }
        None => match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    let port = match port {
        Some(port) => port.parse().map_err(|_| NOT_A_PORT)?,
        None => 443,
    };
    Ok((host, port))
}

/// The connection a room's TLS runs over: the room's own, or a tunnel through a proxy, which is
/// itself TLS when the proxy's address is an `https` one.
enum Carrier {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Carrier {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Carrier {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Why a tunnel through a proxy did not open: one of this client's reasons, or the proxy's refusal
/// with the status it answered. Nothing the proxy wrote beside its status is kept, and neither is
/// the proxy's address, which its owner configured and a failure does not repeat.
enum TunnelFailure {
    Reason(&'static str),
    Refused(u16),
}

impl TunnelFailure {
    /// The reason a room failure carries: this client's words, and for a refusal the status after
    /// them, which [`room_reason`] says again.
    fn reason(&self) -> String {
        match self {
            Self::Reason(reason) => (*reason).to_owned(),
            Self::Refused(status) => format!("{PROXY_REFUSED} {status}"),
        }
    }
}

/// Opens a tunnel to `host:port` through `proxy` with HTTP `CONNECT`, and returns it once the
/// proxy has agreed.
///
/// The proxy's own address is reached directly, over TLS verified like a room's when it is an
/// `https` address. Any 2xx answer is the proxy agreeing (RFC 9110, section 9.3.6); anything else,
/// and an answer whose head has not ended within [`MAX_TUNNEL_ANSWER_BYTES`], ends the attempt.
/// The head is read one byte at a time, so nothing that follows it is taken from the room's TLS.
async fn tunnel(
    proxy: &ProxyUrl,
    host: &str,
    port: u16,
    tls: &Arc<ClientConfig>,
) -> Result<Carrier, TunnelFailure> {
    let address = proxy.as_url();
    let proxy_port = address
        .port_or_known_default()
        .ok_or(TunnelFailure::Reason(PROXY_NO_PORT))?;
    let (connection, name) = match address.host() {
        Some(url::Host::Domain(name)) => (
            TcpStream::connect((name, proxy_port)).await,
            ServerName::try_from(name.to_owned()).ok(),
        ),
        Some(url::Host::Ipv4(ip)) => (
            TcpStream::connect((ip, proxy_port)).await,
            Some(ServerName::from(IpAddr::V4(ip))),
        ),
        Some(url::Host::Ipv6(ip)) => (
            TcpStream::connect((ip, proxy_port)).await,
            Some(ServerName::from(IpAddr::V6(ip))),
        ),
        None => return Err(TunnelFailure::Reason(PROXY_NO_HOST)),
    };
    let connection = connection.map_err(|_| TunnelFailure::Reason(PROXY_UNREACHABLE))?;
    let mut carrier = if address.scheme() == "https" {
        let name = name.ok_or(TunnelFailure::Reason(PROXY_NOT_A_TLS_NAME))?;
        let stream = TlsConnector::from(Arc::clone(tls))
            .connect(name, connection)
            .await
            .map_err(|_| TunnelFailure::Reason(PROXY_NO_TLS))?;
        Carrier::Tls(Box::new(stream))
    } else {
        Carrier::Plain(connection)
    };

    let target = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    carrier
        .write_all(request.as_bytes())
        .await
        .map_err(|_| TunnelFailure::Reason(PROXY_REQUEST_FAILED))?;
    carrier
        .flush()
        .await
        .map_err(|_| TunnelFailure::Reason(PROXY_REQUEST_FAILED))?;

    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_TUNNEL_ANSWER_BYTES {
            return Err(TunnelFailure::Reason(PROXY_ANSWER_TOO_LONG));
        }
        let byte = carrier
            .read_u8()
            .await
            .map_err(|_| TunnelFailure::Reason(PROXY_ENDED))?;
        head.push(byte);
    }
    match tunnel_status(&head) {
        Some(status) if (200..300).contains(&status) => Ok(carrier),
        Some(status) => Err(TunnelFailure::Refused(status)),
        None => Err(TunnelFailure::Reason(PROXY_NO_STATUS_LINE)),
    }
}

/// The status code of an HTTP/1.x answer's head: the three digits after its version.
fn tunnel_status(head: &[u8]) -> Option<u16> {
    let line = head.split(|&byte| byte == b'\r').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let (version, rest) = line.split_once(' ')?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return None;
    }
    let code = rest.get(..3)?;
    let ends = rest.len() == 3 || rest.as_bytes()[3] == b' ';
    (ends && code.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| code.parse().ok())
        .flatten()
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

    /// A proxy's answer to a tunnel request is read by its status line, and only a status line of
    /// HTTP/1.x with three digits is one.
    #[test]
    fn a_tunnel_answer_is_read_by_its_status_line() {
        assert_eq!(
            tunnel_status(b"HTTP/1.1 200 Connection established\r\n\r\n"),
            Some(200)
        );
        assert_eq!(tunnel_status(b"HTTP/1.0 200\r\n\r\n"), Some(200));
        assert_eq!(
            tunnel_status(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"),
            Some(407)
        );
        for refused in [
            &b"HTTP/2 200\r\n\r\n"[..],
            b"HTTP/1.1 2000 OK\r\n\r\n",
            b"HTTP/1.1 20a OK\r\n\r\n",
            b"HTTP/1.1  200 OK\r\n\r\n",
            b"\r\n\r\n",
        ] {
            assert_eq!(
                tunnel_status(refused),
                None,
                "{}",
                String::from_utf8_lossy(refused)
            );
        }
    }

    /// A control token never reaches a rendering of the role that carries it.
    #[test]
    fn a_role_never_prints_its_token() {
        let token = SymmetricKey::from_bytes([0x41; 32]);
        let rendered = format!("{:?}", RoomRole::Host(&token));
        assert_eq!(rendered, "host");
        assert!(!rendered.contains(&to_base64url(token.expose())));
    }

    /// A room failure says its stage, the origin as a diagnostic names an address, the status and a
    /// reason this client gives, and nothing else: not an origin's credentials, and not a reason
    /// anything else wrote.
    #[test]
    fn a_room_failure_says_its_stage_its_origin_and_only_a_reason_of_its_own() {
        use crate::shown::marker::{MARKER, NEUTRAL, assert_unmarked, failure_renderings};

        let origin = format!("https://{MARKER}:{MARKER}@rendezvous.example");
        for error in [
            RoomError::Configuration {
                origin: origin.clone(),
                reason: MARKER.to_owned(),
            },
            RoomError::Unreachable {
                origin: origin.clone(),
                reason: MARKER.to_owned(),
            },
            RoomError::Refused {
                origin: origin.clone(),
                status: 404,
            },
            RoomError::NotAnUpgrade {
                origin: origin.clone(),
                reason: MARKER.to_owned(),
            },
        ] {
            assert_unmarked("a room failure", &failure_renderings(error));
        }
        // The neutral controls: an origin without credentials, a status and a reason this client
        // gives are said; a reason it does not give is replaced.
        assert_eq!(
            RoomError::Unreachable {
                origin: "https://rendezvous.example:8443".to_owned(),
                reason: NO_TLS.to_owned(),
            }
            .to_string(),
            "the room at https://rendezvous.example:8443 could not be reached: the TLS handshake \
             failed"
        );
        assert_eq!(
            RoomError::Refused {
                origin: "https://rendezvous.example".to_owned(),
                status: 404,
            }
            .to_string(),
            "the room at https://rendezvous.example answered the upgrade with status 404"
        );
        assert_eq!(
            RoomError::NotAnUpgrade {
                origin: "https://rendezvous.example".to_owned(),
                reason: NEUTRAL.to_owned(),
            }
            .to_string(),
            "the room at https://rendezvous.example did not answer with an upgrade: [a reason this \
             client does not give]"
        );
        assert_eq!(
            format!(
                "{:?}",
                RoomError::Configuration {
                    origin: EVERY_ORIGIN.to_owned(),
                    reason: NO_VERIFIER.to_owned(),
                }
            ),
            "RoomError(\"the room at every origin cannot be addressed: the platform's certificate \
             verifier cannot be set up\")"
        );
    }
}
