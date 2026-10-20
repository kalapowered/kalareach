//! The WebSocket both of this client's service sockets open.
//!
//! The rendezvous room and a managed voice call's control socket are each a WebSocket at
//! `wss://<origin><path>`, opened on a TLS stream verified against a configuration the caller
//! holds (the platform's trust, as the managed services' requests are, through
//! [`crate::services::http::platform_tls`]). The connection is the socket's own, or, for a caller
//! that names a proxy, a `CONNECT` tunnel through that proxy. A caller that allows it may also open
//! a plain `ws://` socket to a loopback address, which is what a development deployment serves on
//! and the one place a credential travels without TLS.
//!
//! What the two share is everything between the first byte and the first frame: the name, the
//! connection, TLS, the upgrade request with the headers the caller adds, and a guard on the
//! answer. What each does with the frames after that is its own.
//!
//! # What a failure is
//!
//! [`Failure`] says how far the socket got and nothing more: the caller decides what that means
//! for a person. A status other than switching protocols is kept, because an address that serves
//! no such socket (a page, a redirect, a route the origin does not have) and one that refused this
//! caller are told apart by it.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use kr_transport::config::ProxyUrl;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_websockets::{ClientBuilder, Limits, WebSocketStream};

use crate::shown::{Said, Shown};
use crate::tunnel::{self, Carrier};

/// How long opening a socket may take: the name, the connection, TLS and the upgrade.
pub(crate) const OPEN_DEADLINE: Duration = Duration::from_secs(10);

/// The most of an answer to the upgrade that is read before its head is complete.
///
/// A real answer's head is a few hundred bytes.
pub(crate) const MAX_UPGRADE_ANSWER_BYTES: usize = 16 * 1024;

/// The origin is not one the socket can be addressed at.
pub(crate) const NOT_HTTPS: &str = "a socket's origin is an https origin";
/// An IPv6 origin's brackets do not close.
pub(crate) const OPEN_BRACKETS: &str = "an IPv6 origin closes its brackets";
/// The origin's port is not a number a port can be.
pub(crate) const NOT_A_PORT: &str = "the origin's port is not a port number";
/// The origin's host is not a name TLS can verify.
pub(crate) const NOT_A_TLS_NAME: &str = "the origin's host is not a name TLS can verify";
/// The socket's address cannot be written as a request.
pub(crate) const NOT_AN_ADDRESS: &str = "the socket's address cannot be written as a request";
/// A header the upgrade carries cannot be sent.
pub(crate) const NO_TOKEN_HEADER: &str = "the control token header cannot be sent";
/// A header's value cannot be sent.
pub(crate) const NO_TOKEN: &str = "the control token cannot be sent";
/// The socket did not open within [`OPEN_DEADLINE`].
pub(crate) const TOO_SLOW: &str = "the socket did not open within its deadline";
/// The connection to the origin's host failed.
pub(crate) const NO_CONNECTION: &str = "the connection failed";
/// The TLS handshake failed.
pub(crate) const NO_TLS: &str = "the TLS handshake failed";
/// The upgrade did not finish.
pub(crate) const UNFINISHED: &str = "the upgrade did not finish";
/// The answer does not begin with a status line.
pub(crate) const NO_STATUS_LINE: &str =
    "the answer to the upgrade does not begin with a status line";
/// The answer is longer than [`MAX_UPGRADE_ANSWER_BYTES`].
pub(crate) const TOO_LONG: &str = "the answer to the upgrade is longer than an answer may be";
/// The answer carries an accept value that is not one SHA-1 digest.
pub(crate) const NOT_A_DIGEST: &str =
    "the answer to the upgrade carries an accept value that is no SHA-1 digest";
/// The answer lacks a header an upgrade needs.
pub(crate) const MISSING_HEADER: &str = "the answer lacks a header an upgrade needs";
/// The answer's `Upgrade` header is not `websocket`.
pub(crate) const NOT_WEBSOCKET: &str = "the answer upgrades to another protocol than WebSocket";
/// The answer's `Connection` header does not upgrade.
pub(crate) const NO_UPGRADE: &str = "the answer's connection header does not upgrade";
/// The answer names a WebSocket version this client does not speak.
pub(crate) const OTHER_VERSION: &str =
    "the answer names a WebSocket version this client does not speak";
/// The answer is not a response that can be read.
pub(crate) const UNPARSED: &str = "the answer is not a response this client can read";
/// The answer's accept value is not the one the key this client sent asks for.
pub(crate) const WRONG_ACCEPT: &str =
    "the answer's accept value does not match the key this client sent";
/// Any other answer that is not an upgrade.
pub(crate) const NOT_ACCEPTED: &str = "the answer is not an upgrade this client accepts";

/// The reasons opening a socket gives, which are the only reasons a failure of it says.
pub(crate) const REASONS: [&str; 21] = [
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
];

/// How far opening a socket got.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The origin is not one the socket can be addressed at, or a request to it cannot be written.
    Configuration(&'static str),
    /// The name, the connection, the proxy or TLS failed, or the socket did not open in time.
    Unreachable(String),
    /// The upgrade was answered with a status other than switching protocols, and with the wait
    /// before trying again that the answer named, when it named one.
    Refused {
        /// The status.
        status: u16,
        /// The wait, from a `Retry-After` of whole seconds.
        retry_after: Option<Duration>,
    },
    /// The answer was not a WebSocket upgrade, or not one this client accepts.
    NotAnUpgrade(&'static str),
}

/// What a caller asks to be opened.
pub(crate) struct Upgrade<'a> {
    /// The origin: `https://<host>[:<port>]`, or `http://<loopback host>[:<port>]` where
    /// [`Self::loopback_plain`] allows it.
    pub origin: &'a str,
    /// The path of the socket, beginning with `/`.
    pub path: &'a str,
    /// Headers to send with the upgrade, as name and value.
    pub headers: &'a [(&'a str, &'a str)],
    /// The largest frame the socket reads.
    pub max_payload: usize,
    /// The proxy to tunnel through, or nothing to connect directly.
    pub proxy: Option<&'a ProxyUrl>,
    /// Whether an `http` origin on a loopback address opens a plain socket.
    pub loopback_plain: bool,
}

/// A stream a socket runs on: TLS to the origin, or plain TCP to a loopback address.
pub(crate) enum Wire {
    /// TLS over a direct connection or a tunnel.
    Tls(Box<tokio_rustls::client::TlsStream<Carrier>>),
    /// A plain connection to a loopback address.
    Plain(TcpStream),
}

impl AsyncRead for Wire {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Wire {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Plain(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tls(stream) => stream.is_write_vectored(),
            Self::Plain(stream) => stream.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// An open socket.
pub(crate) type Socket = WebSocketStream<UpgradeGuard<Wire>>;

/// `tls` set up to offer the one protocol an upgrade is made in.
///
/// The upgrade is an HTTP/1.1 request, so that is the one protocol offered.
pub(crate) fn for_upgrade(mut tls: ClientConfig) -> Arc<ClientConfig> {
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(tls)
}

/// Opens one socket: the connection, directly or through a proxy, TLS verified for the origin's
/// host, and the upgrade with the caller's headers. The whole attempt is bounded by
/// [`OPEN_DEADLINE`].
///
/// # Errors
///
/// Returns a [`Failure`] saying how far the socket got.
pub(crate) async fn open(
    tls: &Arc<ClientConfig>,
    upgrade: &Upgrade<'_>,
) -> Result<Socket, Failure> {
    tokio::time::timeout(OPEN_DEADLINE, open_now(tls, upgrade))
        .await
        .map_err(|_| Failure::Unreachable(TOO_SLOW.to_owned()))?
}

/// Opens one socket without a deadline of its own.
async fn open_now(tls: &Arc<ClientConfig>, upgrade: &Upgrade<'_>) -> Result<Socket, Failure> {
    let (secure, authority) = if let Some(authority) = upgrade.origin.strip_prefix("https://") {
        (true, authority)
    } else if let Some(authority) = upgrade
        .origin
        .strip_prefix("http://")
        .filter(|_| upgrade.loopback_plain)
    {
        (false, authority)
    } else {
        return Err(Failure::Configuration(NOT_HTTPS));
    };
    let (host, port) =
        host_and_port(authority, if secure { 443 } else { 80 }).map_err(Failure::Configuration)?;
    let unreachable = |reason: &'static str| Failure::Unreachable(reason.to_owned());
    let wire = if secure {
        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|_| Failure::Configuration(NOT_A_TLS_NAME))?;
        let connection = match upgrade.proxy {
            None => Carrier::Plain(
                TcpStream::connect((host, port))
                    .await
                    .map_err(|_| unreachable(NO_CONNECTION))?,
            ),
            Some(proxy) => tunnel::through(proxy, host, port, tls)
                .await
                .map_err(|failure| Failure::Unreachable(failure.reason()))?,
        };
        let stream = TlsConnector::from(Arc::clone(tls))
            .connect(server_name, connection)
            .await
            .map_err(|_| unreachable(NO_TLS))?;
        Wire::Tls(Box::new(stream))
    } else {
        if !is_loopback(host) {
            return Err(Failure::Configuration(NOT_HTTPS));
        }
        Wire::Plain(
            TcpStream::connect((host, port))
                .await
                .map_err(|_| unreachable(NO_CONNECTION))?,
        )
    };
    let address = format!(
        "{}://{authority}{}",
        if secure { "wss" } else { "ws" },
        upgrade.path
    );
    let mut builder = ClientBuilder::new()
        .uri(&address)
        .map_err(|_| Failure::Configuration(NOT_AN_ADDRESS))?;
    for (name, value) in upgrade.headers {
        builder = builder
            .add_header(
                name.parse()
                    .map_err(|_| Failure::Configuration(NO_TOKEN_HEADER))?,
                value
                    .parse()
                    .map_err(|_| Failure::Configuration(NO_TOKEN))?,
            )
            .map_err(|_| Failure::Configuration(NO_TOKEN_HEADER))?;
    }
    let retry_after = Arc::new(OnceLock::new());
    let (socket, _) = builder
        .limits(Limits::default().max_payload_len(Some(upgrade.max_payload)))
        .connect_on(UpgradeGuard::new(wire, Arc::clone(&retry_after)))
        .await
        .map_err(|error| upgrade_failed(error, retry_after.get().copied()))?;
    Ok(socket)
}

/// Whether a host names the loopback interface: the name `localhost` or a loopback address.
fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Says how far an upgrade that failed got.
///
/// A status other than switching protocols is the answer, whatever it is. An answer that is not an
/// upgrade, or that the guard refused, is not one either. Anything else is the connection failing
/// part way through, TLS included: its failures after the handshake reach this as input errors of
/// the same kind the guard's do, so the guard's are told apart by their own type rather than by
/// their kind.
fn upgrade_failed(error: tokio_websockets::Error, retry_after: Option<Duration>) -> Failure {
    use tokio_websockets::upgrade;

    match error {
        tokio_websockets::Error::Upgrade(upgrade::Error::DidNotSwitchProtocols(status)) => {
            Failure::Refused {
                status,
                retry_after,
            }
        }
        tokio_websockets::Error::Upgrade(error) => Failure::NotAnUpgrade(match error {
            upgrade::Error::MissingHeader(_) => MISSING_HEADER,
            upgrade::Error::UpgradeNotWebSocket => NOT_WEBSOCKET,
            upgrade::Error::ConnectionNotUpgrade => NO_UPGRADE,
            upgrade::Error::UnsupportedWebSocketVersion => OTHER_VERSION,
            upgrade::Error::Parsing(_) => UNPARSED,
            upgrade::Error::WrongWebSocketAccept => WRONG_ACCEPT,
            _ => NOT_ACCEPTED,
        }),
        tokio_websockets::Error::Io(error) => match GuardRefusal::of(&error) {
            Some(refusal) => Failure::NotAnUpgrade(refusal),
            None => Failure::Unreachable(UNFINISHED.to_owned()),
        },
        _ => Failure::Unreachable(UNFINISHED.to_owned()),
    }
}

/// A socket's stream, which holds the answer to the upgrade back until it is whole and safe to
/// parse.
///
/// The WebSocket library reads an answer's head for as long as it is incomplete, however long it
/// grows, and decodes `Sec-WebSocket-Accept` into a digest's twenty bytes on the assumption that
/// the value fits. So the answer is read here first, into a buffer of at most
/// [`MAX_UPGRADE_ANSWER_BYTES`], and handed on only once its head is complete and every accept
/// value in it is one SHA-1 digest in base64; anything else is an error of the stream, which ends
/// the attempt. The answer must begin with its status line: the library skips blank lines in
/// front of one, and they would put the end of a head where this guard looks for it. After the
/// head, reads and writes go straight to the stream.
pub(crate) struct UpgradeGuard<S> {
    stream: S,
    answer: Answered,
    /// The wait the answer's `Retry-After` named, once its head is whole. The library reports a
    /// refused upgrade by its status alone, so a refusal's wait is kept here for the caller.
    retry_after: Arc<OnceLock<Duration>>,
}

/// The guard refusing the answer to the upgrade.
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

/// How far the answer to the upgrade has come.
enum Answered {
    /// Its head is still arriving.
    Reading(Vec<u8>),
    /// Its head was whole and acceptable: what was read is being handed on, from `at`.
    Handing { read: Vec<u8>, at: usize },
    /// Everything read ahead has been handed on.
    Through,
}

impl<S> UpgradeGuard<S> {
    const fn new(stream: S, retry_after: Arc<OnceLock<Duration>>) -> Self {
        Self {
            stream,
            answer: Answered::Reading(Vec::new()),
            retry_after,
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
                        // The far end ended the stream part way through its answer, which the
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
                        if let Some(wait) = retry_after_of(&head[..end + 4]) {
                            let _ = this.retry_after.set(wait);
                        }
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

/// The wait a head names in `Retry-After`, when it names one as whole seconds.
///
/// A date, a fraction, a sign and a figure too large to count name none: a caller that waits as it
/// was told reads only what it can count.
fn retry_after_of(head: &[u8]) -> Option<Duration> {
    head.split(|byte| *byte == b'\n').find_map(|line| {
        let colon = line.iter().position(|byte| *byte == b':')?;
        if !line[..colon]
            .trim_ascii()
            .eq_ignore_ascii_case(b"retry-after")
        {
            return None;
        }
        let value = line[colon + 1..].trim_ascii();
        if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let seconds = std::str::from_utf8(value).ok()?.parse().ok()?;
        Some(Duration::from_secs(seconds))
    })
}

/// Splits an origin's authority into its host, without an IPv6 literal's brackets, and its port,
/// which is `default_port` when the authority names none.
fn host_and_port(authority: &str, default_port: u16) -> Result<(&str, u16), &'static str> {
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
        None => default_port,
    };
    Ok((host, port))
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
    /// brackets removed and the scheme's own port when none is named.
    #[test]
    fn an_authority_splits_into_its_host_and_port() {
        assert_eq!(
            host_and_port("reach.kala.to", 443),
            Ok(("reach.kala.to", 443))
        );
        assert_eq!(
            host_and_port("127.0.0.1:8443", 443),
            Ok(("127.0.0.1", 8443))
        );
        assert_eq!(host_and_port("[::1]:8443", 443), Ok(("::1", 8443)));
        assert_eq!(host_and_port("[::1]", 443), Ok(("::1", 443)));
        assert_eq!(host_and_port("localhost", 80), Ok(("localhost", 80)));
        assert!(host_and_port("[::1:8443", 443).is_err());
        assert!(host_and_port("pair.example.org:port", 443).is_err());
    }

    /// Plain sockets are for the loopback interface and nothing else.
    #[test]
    fn only_the_loopback_interface_is_a_plain_socket_host() {
        for loopback in ["localhost", "LOCALHOST", "127.0.0.1", "127.9.9.9", "::1"] {
            assert!(is_loopback(loopback), "{loopback}");
        }
        for elsewhere in [
            "reach.kala.to",
            "10.0.2.2",
            "192.168.1.5",
            "localhost.example",
            "0.0.0.0",
            "",
        ] {
            assert!(!is_loopback(elsewhere), "{elsewhere}");
        }
    }
}
