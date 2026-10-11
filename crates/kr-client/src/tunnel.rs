//! An HTTP `CONNECT` tunnel through the proxy a host's configuration document selects.
//!
//! A host that selects a proxy reaches every outbound connection through it, and a connection that
//! is not HTTP itself, such as the rendezvous room's TLS or a mail submission's, goes as a
//! tunnel: the proxy is asked for `CONNECT host:port`, and once it agrees the connection's own TLS
//! runs inside the tunnel, so the proxy sees where the connection goes and nothing that travels on
//! it. A proxy that cannot be reached or refuses the tunnel ends the attempt: nothing goes around
//! it.
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

use kr_transport::config::ProxyUrl;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

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

/// The connection a TLS session runs over: the server's own, or a tunnel through a proxy, which is
/// itself TLS when the proxy's address is an `https` one.
///
/// It has no `Debug`, because a socket prints the address of its peer, and a proxy's address is its
/// owner's configuration.
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
#[derive(Debug)]
pub enum TunnelFailure {
    /// One of this client's reasons.
    Reason(&'static str),
    /// The proxy answered the request with a status other than 2xx.
    Refused(u16),
}

impl TunnelFailure {
    /// The words that say why the tunnel did not open: this client's reason, or for a refusal the
    /// status after the words that name it.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Reason(reason) => (*reason).to_owned(),
            Self::Refused(status) => format!("{REFUSED} {status}"),
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
/// # Errors
///
/// Returns why the tunnel did not open. Nothing has been sent to `host` when this fails.
pub async fn through(
    proxy: &ProxyUrl,
    host: &str,
    port: u16,
    tls: &Arc<ClientConfig>,
) -> Result<Carrier, TunnelFailure> {
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
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    carrier
        .write_all(request.as_bytes())
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
        Some(status) => Err(TunnelFailure::Refused(status)),
        None => Err(TunnelFailure::Reason(NO_STATUS_LINE)),
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
