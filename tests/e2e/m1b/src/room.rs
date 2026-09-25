//! A candidate's socket in a rendezvous room at the deployed site.
//!
//! The host reserves a locator at the origin and attaches to its room as the host; a candidate
//! reaches the same room at `wss://<origin>/api/pair/room/<locator>/candidate` and is served the
//! record the host reserved, or nothing at all when the locator names none. Every frame either side
//! sends is the room's own vocabulary, encoded and decoded by the host's own codecs, so a frame the
//! deployed service could not read would fail here as it would for a real device.
//!
//! The socket is opened with TLS verified against the platform's trust store for the origin's
//! host, as the host's own room socket is.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use kr_protocol::pairing::{Locator, RendezvousOrigin};
use kr_protocol::rendezvous::{
    ClientFrame, CloseReason, MAX_FRAME_BYTES, ServiceFrame, decode_service_frame, encode_frame,
};
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_websockets::{ClientBuilder, Limits, Message, WebSocketStream};

/// How long opening a room socket may take: the name, the connection, TLS and the upgrade.
pub const OPEN_DEADLINE: Duration = Duration::from_secs(15);

/// How long closing a room socket from this side may take.
pub const CLOSE_DEADLINE: Duration = Duration::from_secs(2);

/// How long a candidate waits for the room's next frame.
///
/// The room ends every candidate socket ten seconds after it opened, so a frame that has not come
/// by then is not coming.
pub const FRAME_DEADLINE: Duration = Duration::from_secs(12);

/// Why a socket stopped giving frames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stopped {
    /// The room said it was closing the socket, and why.
    Closed(CloseReason),
    /// The socket ended without the room's closing frame.
    Ended(String),
    /// Nothing arrived within the bound.
    Silent,
}

impl std::fmt::Display for Stopped {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed(reason) => write!(formatter, "the room closed the socket ({reason:?})"),
            Self::Ended(why) => write!(formatter, "the socket ended: {why}"),
            Self::Silent => write!(formatter, "the room sent nothing within {FRAME_DEADLINE:?}"),
        }
    }
}

/// One candidate socket.
pub struct CandidateSocket {
    socket: WebSocketStream<TlsStream<TcpStream>>,
}

impl std::fmt::Debug for CandidateSocket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CandidateSocket")
            .finish_non_exhaustive()
    }
}

impl CandidateSocket {
    /// Opens a candidate socket in the room of `locator` at `origin`.
    ///
    /// # Errors
    ///
    /// Returns why the room could not be reached.
    pub async fn open(origin: &RendezvousOrigin, locator: &Locator) -> Result<Self, String> {
        tokio::time::timeout(OPEN_DEADLINE, Self::open_now(origin, locator))
            .await
            .map_err(|_| format!("the room was not reached within {OPEN_DEADLINE:?}"))?
    }

    async fn open_now(origin: &RendezvousOrigin, locator: &Locator) -> Result<Self, String> {
        let authority = origin
            .as_str()
            .strip_prefix("https://")
            .ok_or("a rendezvous origin is an https origin")?;
        let (host, port) = host_and_port(authority)?;
        let mut tls = ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .and_then(BuilderVerifierExt::with_platform_verifier)
        .map_err(|error| format!("the platform's certificate verifier: {error}"))?
        .with_no_client_auth();
        // The upgrade is an HTTP/1.1 request, so that is the one protocol offered.
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = ServerName::try_from(host.to_owned())
            .map_err(|_| format!("{host} is not a name TLS can verify"))?;
        let connection = TcpStream::connect((host, port))
            .await
            .map_err(|error| format!("the room could not be reached: {error}"))?;
        let stream = TlsConnector::from(Arc::new(tls))
            .connect(name, connection)
            .await
            .map_err(|error| format!("the room's TLS handshake failed: {error}"))?;
        let address = format!(
            "wss://{authority}/api/pair/room/{}/candidate",
            locator.as_str()
        );
        let (socket, _) = ClientBuilder::new()
            .uri(&address)
            .map_err(|error| format!("{address} is not an address: {error}"))?
            .limits(Limits::default().max_payload_len(Some(MAX_FRAME_BYTES)))
            .connect_on(stream)
            .await
            .map_err(|error| format!("the room did not accept the candidate: {error}"))?;
        Ok(Self { socket })
    }

    /// Sends one frame.
    ///
    /// # Errors
    ///
    /// Returns why it could not be sent.
    pub async fn send(&mut self, frame: &ClientFrame) -> Result<(), String> {
        let bytes = encode_frame(frame)?;
        self.socket
            .send(Message::binary(bytes))
            .await
            .map_err(|error| format!("the room did not take the frame: {error}"))
    }

    /// Waits for the room's next frame, within `within`.
    ///
    /// # Errors
    ///
    /// Returns how the socket stopped when the next thing it gives is not a frame.
    pub async fn next(&mut self, within: Duration) -> Result<ServiceFrame, Stopped> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let message = match tokio::time::timeout_at(deadline, self.socket.next()).await {
                Err(_) => return Err(Stopped::Silent),
                Ok(None) => return Err(Stopped::Ended("the room ended the socket".to_owned())),
                Ok(Some(Err(error))) => return Err(Stopped::Ended(error.to_string())),
                Ok(Some(Ok(message))) => message,
            };
            if message.is_close() {
                return Err(Stopped::Ended("the room closed the socket".to_owned()));
            }
            if !message.is_binary() {
                // Pings are answered by the library; nothing else the room sends is text.
                continue;
            }
            let frame = decode_service_frame(message.as_payload())
                .map_err(|error| Stopped::Ended(format!("a frame the room sent: {error}")))?;
            if let ServiceFrame::Closed { reason } = frame {
                return Err(Stopped::Closed(reason));
            }
            return Ok(frame);
        }
    }

    /// Closes the socket from this side, within [`CLOSE_DEADLINE`].
    pub async fn close(mut self) {
        let _ = tokio::time::timeout(CLOSE_DEADLINE, self.socket.close()).await;
    }
}

/// Whether the room of `locator` still serves a record, as a new candidate finds it.
///
/// A served candidate is sent the record as the first thing on its socket, before the upgrade is
/// answered; a locator with no record, a released one and an expired one are all held without a
/// frame until the room's deadline. So a socket that is sent nothing within `within` of opening is
/// one the room served nothing to. The socket is closed from this side either way.
///
/// # Errors
///
/// Returns why the room could not be asked.
pub async fn serves_record(
    origin: &RendezvousOrigin,
    locator: &Locator,
    within: Duration,
) -> Result<bool, String> {
    let mut socket = CandidateSocket::open(origin, locator).await?;
    let answer = match socket.next(within).await {
        Ok(ServiceFrame::Record { .. }) => Ok(true),
        Ok(other) => Err(format!("the room sent a new candidate {other:?}")),
        Err(Stopped::Silent | Stopped::Closed(CloseReason::Deadline)) => Ok(false),
        Err(stopped) => Err(stopped.to_string()),
    };
    socket.close().await;
    answer
}

/// Splits an origin's authority into its host and port.
fn host_and_port(authority: &str) -> Result<(&str, u16), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or("an IPv6 origin closes its bracket")?;
        let port = match after.strip_prefix(':') {
            Some(port) => port.parse().map_err(|_| "the origin's port is a number")?,
            None => 443,
        };
        return Ok((host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Ok((
            host,
            port.parse().map_err(|_| "the origin's port is a number")?,
        )),
        None => Ok((authority, 443)),
    }
}

/// Asks the room of `locator` again until a new candidate is served no record, and returns how long
/// after the first question the question that found it serving none concluded; `None` when the room
/// still served the record to every question that concluded within `within`.
///
/// Each question is [`serves_record`] with `probe`: a served candidate learns so at once, and one
/// that is served nothing learns it only when `probe` has passed. Everything here runs against one
/// deadline, `within` after the call: a question starts only when all of it (opening the socket,
/// the probe and closing the socket) fits before the deadline, it is cut short at the deadline,
/// an answer counts only when it came before the deadline, and the pause between two questions
/// ends at the deadline at the latest. So nothing here runs past `within`.
///
/// # Errors
///
/// Returns why the room could not be asked.
pub async fn stops_serving(
    origin: &RendezvousOrigin,
    locator: &Locator,
    probe: Duration,
    within: Duration,
) -> Result<Option<Duration>, String> {
    let started = tokio::time::Instant::now();
    let deadline = started + within;
    let question = OPEN_DEADLINE + probe + CLOSE_DEADLINE;
    loop {
        if tokio::time::Instant::now() + question > deadline {
            return Ok(None);
        }
        let Ok(served) =
            tokio::time::timeout_at(deadline, serves_record(origin, locator, probe)).await
        else {
            return Ok(None);
        };
        let served = served?;
        let answered = tokio::time::Instant::now();
        if answered > deadline {
            return Ok(None);
        }
        if !served {
            return Ok(Some(answered - started));
        }
        tokio::time::sleep_until((answered + Duration::from_secs(1)).min(deadline)).await;
    }
}
