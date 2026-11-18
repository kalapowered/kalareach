//! An HTTP `CONNECT` tunnel through the proxy a host's configuration document selects.
//!
//! A host that selects a proxy reaches the services it names through it, and a connection that is
//! not HTTP itself, such as the rendezvous room's TLS or a mail submission's, goes as a tunnel: the
//! proxy is asked for `CONNECT host:port`, and once it agrees the connection's own TLS runs inside
//! the tunnel, so the proxy sees where the connection goes and, once TLS has started, nothing that
//! travels on it. A proxy that cannot be reached or refuses the tunnel ends the attempt: nothing
//! goes around it.
//!
//! [`Carrier`] is the connection TLS runs over, directly or through a tunnel, and [`through`]
//! opens a tunnel. A failure ([`TunnelFailure`]) is said in this client's words and the proxy's
//! status, and never in anything the proxy wrote or in the proxy's own address, which its owner
//! configured and a failure does not repeat.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::future::BoxFuture;
use kr_crypto::secret::SecretVec;
use kr_transport::config::ProxyUrl;
use kr_transport::front::{Tunnel, TunnelOpener, TunnelRefusal};
use kr_transport::proxy::{ProxyLoginKind, StopKind};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::shown::{Said, Shown};

/// The most of a proxy's answer to a tunnel request that is read before its head is complete.
///
/// A real answer is a status line and a few headers.
pub const MAX_ANSWER_BYTES: usize = 16 * 1024;

/// The proxy's address names no port.
const NO_PORT: &str = "the proxy's address names no port";
/// The proxy's address names no host.
const NO_HOST: &str = "the proxy's address names no host";
/// The connection to the proxy failed.
pub(crate) const UNREACHABLE: &str = "the proxy could not be reached";
/// The proxy's host is not a name TLS can verify.
const NOT_A_TLS_NAME: &str = "the proxy's host is not a name TLS can verify";
/// The TLS handshake with the proxy failed.
const NO_TLS: &str = "the TLS handshake with the proxy failed";
/// The tunnel request could not be sent to the proxy.
const REQUEST_FAILED: &str = "the tunnel request to the proxy failed";
/// The proxy's answer is longer than [`MAX_ANSWER_BYTES`].
pub(crate) const ANSWER_TOO_LONG: &str =
    "the proxy's answer to the tunnel request is longer than an answer may be";
/// The proxy ended the connection before its answer's head was complete.
pub(crate) const ENDED: &str = "the proxy ended the connection before it answered";
/// The proxy's answer does not begin with a status line.
pub(crate) const NO_STATUS_LINE: &str =
    "the proxy did not answer the tunnel request with a status line";
/// The proxy answered the tunnel request with a status other than 2xx, which follows these words.
pub(crate) const REFUSED: &str = "the proxy refused the tunnel with status";

/// The reasons a tunnel failure gives besides a refusal's status, which are the only words of the
/// proxy's part that a failure says.
pub(crate) const REASONS: [&str; 9] = [
    NO_PORT,
    NO_HOST,
    UNREACHABLE,
    NOT_A_TLS_NAME,
    NO_TLS,
    REQUEST_FAILED,
    ANSWER_TOO_LONG,
    ENDED,
    NO_STATUS_LINE,
];

/// The words of each kind of login failure, which a failure that composes a tunnel's reason says
/// whole.
pub(crate) const LOGIN_REASONS: [&str; 4] = [
    ProxyLoginKind::Needed.clause(),
    ProxyLoginKind::Refused.clause(),
    ProxyLoginKind::Unsupported.clause(),
    ProxyLoginKind::ClearTextTarget.clause(),
];

/// The connection a TLS session runs over: the server's own, or a tunnel through a proxy, which is
/// itself TLS when the proxy's address is an `https` one.
///
/// It has no `Debug`, because a socket prints the address of its peer, and a proxy's address is its
/// owner's configuration.
///
/// A failure of the TLS to the proxy, once it was established, is the proxy's and not the server's:
/// it reaches the TLS inside the tunnel as an input error that names no certificate, so a caller
/// never reads it as one the server presented.
pub enum Carrier {
    /// A connection in the clear: the server's own, or a tunnel through an `http` proxy.
    Plain(TcpStream),
    /// A tunnel through an `https` proxy, inside the TLS to the proxy.
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
            Self::Tls(stream) => Pin::new(stream.as_mut())
                .poll_read(cx, buf)
                .map_err(of_the_proxy),
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
            Self::Tls(stream) => Pin::new(stream.as_mut())
                .poll_write(cx, buf)
                .map_err(of_the_proxy),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut())
                .poll_flush(cx)
                .map_err(of_the_proxy),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut())
                .poll_shutdown(cx)
                .map_err(of_the_proxy),
        }
    }
}

/// The TLS to the proxy failed after it was established.
struct ProxyTlsFailed;

impl Said for ProxyTlsFailed {
    fn said(&self) -> Shown {
        Shown::said("the TLS to the proxy failed")
    }
}

crate::display_as_said!(ProxyTlsFailed);
crate::debug_as_display!(ProxyTlsFailed);

impl std::error::Error for ProxyTlsFailed {}

/// An error of the TLS to the proxy, with what TLS says of a certificate or a record taken out of
/// it: the TLS inside the tunnel reads that as the server's failure, and it is not.
fn of_the_proxy(error: io::Error) -> io::Error {
    if error
        .get_ref()
        .is_some_and(|inner| inner.is::<tokio_rustls::rustls::Error>())
    {
        io::Error::new(error.kind(), ProxyTlsFailed)
    } else {
        error
    }
}

/// Why a tunnel through a proxy did not open: one of this client's reasons, or the proxy's refusal
/// with the status it answered. Nothing the proxy wrote beside its status is kept, and neither is
/// the proxy's address, which its owner configured and a failure does not repeat.
#[derive(Debug)]
pub enum TunnelFailure {
    /// One of this client's reasons.
    Reason(&'static str),
    /// The proxy answered the request with a status other than 2xx.
    Refused(u16),
    /// The proxy's login: it asked for one this host does not hold, it refused the one this host
    /// sent, or it asked for a sign-in method this host does not send. A refusal of the login sets
    /// the login's verdict before this is returned, and once the verdict is set no tunnel sends the
    /// login again.
    Login(ProxyLoginKind),
}

impl TunnelFailure {
    /// The words that say why the tunnel did not open: this client's reason, or for a refusal the
    /// status after the words that name it, or for a login the kind's clause.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Reason(reason) => (*reason).to_owned(),
            Self::Refused(status) => format!("{REFUSED} {status}"),
            Self::Login(kind) => kind.clause().to_owned(),
        }
    }
}

/// Opens a tunnel to `host:port` through `proxy` with HTTP `CONNECT`, and returns it once the
/// proxy has agreed.
///
/// The proxy's own address is reached directly, over TLS verified with `tls` when it is an `https`
/// address. Any 2xx answer is the proxy agreeing (RFC 9110, section 9.3.6); anything else, and an
/// answer whose head has not ended within [`MAX_ANSWER_BYTES`], ends the attempt. The head is read
/// one byte at a time, so nothing that follows it is taken from the TLS that runs inside the
/// tunnel. The caller bounds how long all of it may take.
///
/// This is the one writer of a proxy's login. A proxy that holds one gets it in the `CONNECT`'s
/// `Proxy-Authorization`, written only after TLS to an `https` proxy is up. The verdict on the
/// login is read when this is called and again right before the write, with nothing that waits
/// between the read and the write, so once the verdict is set no call writes the login except one
/// that has passed its second read. A `407` to a login that was sent sets the verdict.
///
/// # Errors
///
/// Returns why the tunnel did not open. Nothing has been sent to `host` when this fails.
pub async fn through(
    proxy: &ProxyUrl,
    host: &str,
    port: u16,
    tls: &Arc<ClientConfig>,
) -> Result<Carrier, TunnelFailure> {
    let login = proxy.login();
    if let Some(stop) = login.and_then(|login| login.stopped()) {
        return Err(TunnelFailure::Login(stop.as_login_kind()));
    }
    let address = proxy.as_url();
    let proxy_port = address
        .port_or_known_default()
        .ok_or(TunnelFailure::Reason(NO_PORT))?;
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
        None => return Err(TunnelFailure::Reason(NO_HOST)),
    };
    let connection = connection.map_err(|_| TunnelFailure::Reason(UNREACHABLE))?;
    let mut carrier = if address.scheme() == "https" {
        let name = name.ok_or(TunnelFailure::Reason(NOT_A_TLS_NAME))?;
        let stream = TlsConnector::from(Arc::clone(tls))
            .connect(name, connection)
            .await
            .map_err(|_| TunnelFailure::Reason(NO_TLS))?;
        Carrier::Tls(Box::new(stream))
    } else {
        Carrier::Plain(connection)
    };

    let target = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n").into_bytes();
    if let Some(login) = login {
        request.extend_from_slice(b"Proxy-Authorization: ");
        request.extend_from_slice(login.authorization().as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    let request = SecretVec::new(request);
    // The second read of the verdict. Nothing awaits between it and the first poll of the write.
    if let Some(stop) = login.and_then(|login| login.stopped()) {
        return Err(TunnelFailure::Login(stop.as_login_kind()));
    }
    carrier
        .write_all(request.expose())
        .await
        .map_err(|_| TunnelFailure::Reason(REQUEST_FAILED))?;
    carrier
        .flush()
        .await
        .map_err(|_| TunnelFailure::Reason(REQUEST_FAILED))?;

    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_ANSWER_BYTES {
            return Err(TunnelFailure::Reason(ANSWER_TOO_LONG));
        }
        let byte = carrier
            .read_u8()
            .await
            .map_err(|_| TunnelFailure::Reason(ENDED))?;
        head.push(byte);
    }
    match status(&head) {
        Some(status) if (200..300).contains(&status) => Ok(carrier),
        Some(407) => Err(TunnelFailure::Login(the_login_was_refused(proxy, &head))),
        Some(status) => Err(TunnelFailure::Refused(status)),
        None => Err(TunnelFailure::Reason(NO_STATUS_LINE)),
    }
}

/// What a `407` to a `CONNECT` means, and the verdict when a login was sent.
///
/// A proxy that offers challenges and none of them Basic asks for a method this host does not send,
/// whether or not a login was sent. Otherwise the login that was sent was refused, or none was sent
/// and one is needed. Nothing the proxy wrote is kept.
fn the_login_was_refused(proxy: &ProxyUrl, head: &[u8]) -> ProxyLoginKind {
    let kind = if offers_basic(head) {
        if proxy.login().is_some() {
            ProxyLoginKind::Refused
        } else {
            ProxyLoginKind::Needed
        }
    } else {
        ProxyLoginKind::Unsupported
    };
    if let Some(login) = proxy.login() {
        login.refuse(match kind {
            ProxyLoginKind::Unsupported => StopKind::Unsupported,
            _ => StopKind::Refused,
        });
    }
    kind
}

/// Whether a `407`'s head leaves Basic open: `false` only when it offered challenges and none was
/// Basic.
///
/// A header name is case-insensitive and may repeat, and its value is a list of challenges. A
/// challenge is a scheme token followed by a token68 or by a comma-separated list of parameters,
/// each `token BWS "=" BWS (token | quoted-string)`. The value splits at commas outside quoted
/// strings, and a backslash inside one escapes the next character. A token that is followed by
/// optional blanks and `=` is a parameter of the challenge before it and never a scheme. A head
/// with no challenge, or none that can be read, leaves Basic open.
fn offers_basic(head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(head);
    let mut offered = false;
    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("proxy-authenticate") {
            continue;
        }
        for element in split_outside_quotes(value) {
            let element = element.trim_matches([' ', '\t']);
            let scheme_end = element.find([' ', '\t', '=']).unwrap_or(element.len());
            if element.is_empty() || scheme_end == 0 {
                continue;
            }
            if element[scheme_end..]
                .trim_start_matches([' ', '\t'])
                .starts_with('=')
            {
                // `name=value`, or `name = value`: a parameter, never a scheme.
                continue;
            }
            offered = true;
            if element[..scheme_end].eq_ignore_ascii_case("basic") {
                return true;
            }
        }
    }
    !offered
}

/// Splits a header value at its commas that are outside quoted strings.
fn split_outside_quotes(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (index, character) in value.char_indices() {
        match (quoted, escaped, character) {
            (true, true, _) => escaped = false,
            (true, false, '\\') => escaped = true,
            (true, false, '"') => quoted = false,
            (false, _, '"') => quoted = true,
            (false, _, ',') => {
                parts.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&value[start..]);
    parts
}

/// The tunnels through one proxy, as the front of a login-holding endpoint opens them: each is
/// [`through`], so the front never writes the login itself.
pub struct ProxyTunnels {
    proxy: ProxyUrl,
    tls: Arc<ClientConfig>,
}

impl ProxyTunnels {
    /// The tunnels through `proxy`, whose TLS is verified with `tls`.
    #[must_use]
    pub const fn new(proxy: ProxyUrl, tls: Arc<ClientConfig>) -> Self {
        Self { proxy, tls }
    }
}

impl std::fmt::Debug for ProxyTunnels {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProxyTunnels")
    }
}

impl TunnelOpener for ProxyTunnels {
    fn open<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, Result<Tunnel, TunnelRefusal>> {
        Box::pin(async move {
            match through(&self.proxy, host, port, &self.tls).await {
                Ok(carrier) => Ok(Tunnel::new(carrier)),
                Err(TunnelFailure::Login(kind)) if kind.stops_until_restart() => {
                    Err(TunnelRefusal::Stopped)
                }
                Err(_) => Err(TunnelRefusal::Failed),
            }
        })
    }
}

/// The status code of an HTTP/1.x answer's head: the three digits after its version.
fn status(head: &[u8]) -> Option<u16> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The challenge reader leaves Basic open unless the head offers challenges and none is Basic:
    /// a scheme is found by its place in the list, never inside a quoted string, a parameter or a
    /// token68, and a head with nothing readable leaves Basic open.
    ///
    /// Covers KR-REQ-10.02.
    #[test]
    fn the_challenge_reader_takes_basic_and_nothing_inside_a_realm() {
        let head = |lines: &[&str]| {
            let mut head = String::from("HTTP/1.1 407 Proxy Authentication Required\r\n");
            for line in lines {
                head.push_str(line);
                head.push_str("\r\n");
            }
            head.push_str("\r\n");
            head.into_bytes()
        };
        // (the Proxy-Authenticate lines, whether Basic stays open)
        let table: [(&[&str], bool); 21] = [
            (&["Proxy-Authenticate: Negotiate"], false),
            (&["Proxy-Authenticate: NTLM"], false),
            (&["Proxy-Authenticate: Negotiate, NTLM"], false),
            (&["Proxy-Authenticate: Digest realm=\"x\""], false),
            (&["Proxy-Authenticate: Bearer"], false),
            (&["Proxy-Authenticate: Negotiate YII="], false),
            (&["Proxy-Authenticate: Negotiate YII/AA=="], false),
            (&["Proxy-Authenticate:"], true),
            (&[], true),
            (
                &[
                    "Proxy-Authenticate: NTLM",
                    "proxy-authenticate: Basic realm=\"x\"",
                ],
                true,
            ),
            (&["PROXY-AUTHENTICATE: bAsIc realm=\"x\""], true),
            (&["Proxy-Authenticate: Basic realm=\"NTLM\""], true),
            (&["Proxy-Authenticate: Basic, NTLM"], true),
            (&["Proxy-Authenticate: Digest realm=\"a, Basic\""], false),
            (
                &["Proxy-Authenticate: Digest realm=\"x\", Basic = \"parameter\""],
                false,
            ),
            (
                &["Proxy-Authenticate: Digest realm=\"a\\\",Basic,b\""],
                false,
            ),
            (
                &["Proxy-Authenticate: Digest realm=\"a\\\"b\", Basic"],
                true,
            ),
            (&["Proxy-Authenticate: Basic YII="], true),
            (&["Proxy-Authenticate: NTLM,, Basic"], true),
            (
                &["Proxy-Authenticate: Digest realm\t=\t\"x\",\tBasic"],
                true,
            ),
            (&["Proxy-Authenticate: ,"], true),
        ];
        for (lines, basic) in table {
            assert_eq!(offers_basic(&head(lines)), basic, "{lines:?}");
        }
    }

    /// A proxy's answer to a tunnel request is read by its status line, and only a status line of
    /// HTTP/1.x with three digits is one.
    #[test]
    fn a_tunnel_answer_is_read_by_its_status_line() {
        assert_eq!(
            status(b"HTTP/1.1 200 Connection established\r\n\r\n"),
            Some(200)
        );
        assert_eq!(status(b"HTTP/1.0 200\r\n\r\n"), Some(200));
        assert_eq!(
            status(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"),
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
                status(refused),
                None,
                "{}",
                String::from_utf8_lossy(refused)
            );
        }
    }
}
