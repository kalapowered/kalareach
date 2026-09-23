//! The rendezvous service a deployed host reaches over the network.
//!
//! Reserving and releasing a locator are JSON requests over HTTPS to the service's pairing routes,
//! made through the managed-service transport, [`HttpService`]: certificate and host name
//! verification, finite deadlines, a bounded answer and no redirects. Each request goes to the
//! origin the invitation names, so the service the owner chose is the one contacted.
//!
//! The host's room socket is a WebSocket at `wss://<origin>/api/pair/room/<locator>/host`, opened
//! on a TLS stream verified against the platform's trust store as the transport's are, and proven
//! with the reservation's control token in `KR-Pair-Control-Token`. One task carries its frames to
//! and from the relay (see [`super::rendezvous::serve_room`]): it reads the socket only while no
//! frame it read waits for the relay, so neither direction can hold the other up, and a frame it
//! cannot read ends the socket, which the relay answers by attaching again.
//!
//! # What a failure is
//!
//! Section 10 has the owner told a rendezvous origin that is configured wrongly apart from a
//! service that cannot be reached, and neither costs the invitation a guess. So a configuration
//! error is reported only where the answer shows the origin serves no rendezvous, and everything
//! else is the service being unavailable. An exchange is read in this order:
//!
//! 1. An origin the transport will not address is a configuration error.
//! 2. A failure to reach the service or to finish the exchange (the name, the connection, TLS, a
//!    deadline) is the service being unavailable.
//! 3. The service's own envelope decides next. `NOT_CONFIGURED`, `NOT_FOUND` and
//!    `METHOD_NOT_ALLOWED` say the origin serves no rendezvous there: a configuration error.
//!    `RATE_LIMITED` and every other code are the service being unavailable.
//! 4. An answer without the envelope: a redirect, 404 and 405 say the same as those codes, and
//!    anything else, such as a 429 or a 5xx page from something in front of the service, is the
//!    service being unavailable.
//! 5. A success that is not the answer to the operation asked is a configuration error: whatever
//!    answered does not speak this contract.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use kr_client::error::ClientError;
use kr_client::services::http::{HttpDeadlines, HttpService, ResponseLimits};
use kr_client::services::relay::{ServiceHttp, ServiceHttpAnswer};
use kr_crypto::secret::SymmetricKey;
use kr_pairing::PairingError;
use kr_pairing::platform::RendezvousHost;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::InvitationId;
use kr_protocol::pairing::{Locator, RendezvousOrigin};
use kr_protocol::scalars::{Digest256, TimestampMs, to_base64url};
use kr_protocol::service::GatewayOrigin;
use kr_transport::listener::BoxFuture;
use rustls_platform_verifier::BuilderVerifierExt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_websockets::{ClientBuilder, Limits, Message, WebSocketStream};

use super::rendezvous::{
    CONTROL_TOKEN_HEADER, ClientFrame, MAX_FRAME_BYTES, Rendezvous, RoomSocket, ServiceFrame,
    decode_service_frame, encode_frame,
};

/// Where a host reserves a locator for an invitation.
pub const RESERVE_PATH: &str = "/api/pair/locator/reserve";

/// Where a host releases a reservation, proving possession of its control token.
pub const RELEASE_PATH: &str = "/api/pair/locator/release";

/// How long a reservation or a release may take.
///
/// A reservation runs while the owner waits for the invitation and while the invitation's lock is
/// held, so the whole exchange is bounded well inside the transport's own defaults.
pub const CONTROL_DEADLINES: HttpDeadlines = HttpDeadlines {
    connect: Duration::from_secs(5),
    read: Duration::from_secs(5),
    total: Duration::from_secs(10),
};

/// How long attaching to a room may take: the name, the connection, TLS and the upgrade.
pub const ATTACH_DEADLINE: Duration = Duration::from_secs(10);

/// How many frames wait in each direction between a room socket and its relay.
const ROOM_QUEUE: usize = 16;

/// How long a socket may take to close once its pump is done with it.
const CLOSE_DEADLINE: Duration = Duration::from_secs(1);

/// The most of a room's answer to the upgrade that is read before its head is complete.
///
/// A real answer's head is a few hundred bytes.
pub const MAX_UPGRADE_ANSWER_BYTES: usize = 16 * 1024;

/// The rendezvous service a deployed host reaches over HTTPS.
///
/// kr-pairing asks for a reservation and a release synchronously, on the blocking thread a pairing
/// step runs on, so each request runs on the daemon's runtime and that thread waits for it.
#[derive(Clone, Debug)]
pub struct HttpsRendezvous {
    runtime: tokio::runtime::Handle,
    /// What a room socket's TLS is opened with.
    tls: Arc<ClientConfig>,
}

impl HttpsRendezvous {
    /// Builds the client on the runtime of the calling task, which runs its requests, with room
    /// sockets verified against the platform's trust store.
    ///
    /// # Errors
    ///
    /// Returns a reason when called outside a runtime, or when the platform's verifier cannot be
    /// set up.
    pub fn new() -> Result<Self, String> {
        let tls = ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .and_then(BuilderVerifierExt::with_platform_verifier)
        .map_err(|error| format!("the platform's certificate verifier cannot be set up: {error}"))?
        .with_no_client_auth();
        Self::with_tls(tls)
    }

    /// Builds the client with the TLS configuration its room sockets are opened with.
    fn with_tls(mut tls: ClientConfig) -> Result<Self, String> {
        // The upgrade is an HTTP/1.1 request, so that is the one protocol offered.
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "the rendezvous client runs its requests on the daemon's runtime")?;
        Ok(Self {
            runtime,
            tls: Arc::new(tls),
        })
    }

    /// Reserves `locator` at `origin` for `invitation_id`. False when the locator is taken.
    ///
    /// Only the locator travels, never the six secret characters of the code, and the control
    /// token only as its hash.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::RendezvousConfiguration`] or
    /// [`PairingError::RendezvousUnavailable`], as this module's note describes.
    pub async fn reserve(
        &self,
        origin: &RendezvousOrigin,
        locator: &Locator,
        invitation_id: InvitationId,
        advertised_expires_at_ms: TimestampMs,
        control_token_hash: Digest256,
    ) -> kr_pairing::Result<bool> {
        let body = reserve_body(
            locator,
            invitation_id,
            advertised_expires_at_ms,
            control_token_hash,
        )?;
        let answer: ReserveAnswer = control(origin, RESERVE_PATH, &body).await?;
        Ok(answer.reserved)
    }

    /// Releases the reservation of `locator` at `origin`.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::RendezvousConfiguration`] or
    /// [`PairingError::RendezvousUnavailable`], as this module's note describes. A record that is
    /// already gone is refused like a token that does not match, which is the service being
    /// unavailable to this release.
    pub async fn release(
        &self,
        origin: &RendezvousOrigin,
        locator: &Locator,
        control_token: &SymmetricKey,
    ) -> kr_pairing::Result<()> {
        let body = release_body(locator, control_token)?;
        let _: ReleaseAnswer = control(origin, RELEASE_PATH, &body).await?;
        Ok(())
    }
}

impl Rendezvous for HttpsRendezvous {
    fn attach(
        &self,
        origin: &RendezvousOrigin,
        locator: &Locator,
        control_token: &SymmetricKey,
    ) -> BoxFuture<'static, kr_pairing::Result<RoomSocket>> {
        let tls = Arc::clone(&self.tls);
        let origin = origin.clone();
        let locator = locator.clone();
        let token = to_base64url(control_token.expose());
        Box::pin(async move {
            let socket =
                tokio::time::timeout(ATTACH_DEADLINE, open_room(tls, &origin, &locator, &token))
                    .await
                    .map_err(|_| PairingError::RendezvousUnavailable {
                        reason: format!(
                            "attaching to the room at {} took longer than {} seconds",
                            origin.as_str(),
                            ATTACH_DEADLINE.as_secs()
                        ),
                    })??;
            Ok(pump(socket))
        })
    }
}

/// Opens the host's socket in the room of `locator`: the connection, TLS verified for the
/// origin's host, and the upgrade presenting the control token.
async fn open_room(
    tls: Arc<ClientConfig>,
    origin: &RendezvousOrigin,
    locator: &Locator,
    token: &str,
) -> kr_pairing::Result<WebSocketStream<UpgradeGuard<tokio_rustls::client::TlsStream<TcpStream>>>> {
    let authority = origin
        .as_str()
        .strip_prefix("https://")
        .ok_or_else(|| configuration("a rendezvous origin is an https origin"))?;
    let (host, port) = host_and_port(authority)?;
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| configuration(format!("{host} is not a name TLS can verify")))?;
    let unreachable =
        |what: &str, error: &dyn std::fmt::Display| PairingError::RendezvousUnavailable {
            reason: format!("the room at {} {what}: {error}", origin.as_str()),
        };
    let connection = TcpStream::connect((host, port))
        .await
        .map_err(|error| unreachable("could not be reached", &error))?;
    let stream = TlsConnector::from(tls)
        .connect(server_name, connection)
        .await
        .map_err(|error| unreachable("failed its TLS handshake", &error))?;
    let address = format!("wss://{authority}/api/pair/room/{}/host", locator.as_str());
    let builder = ClientBuilder::new()
        .uri(&address)
        .map_err(|error| configuration(format!("{address} is not an address: {error}")))?
        .add_header(
            CONTROL_TOKEN_HEADER
                .parse()
                .map_err(|_| configuration("the control token header cannot be sent"))?,
            token
                .parse()
                .map_err(|_| configuration("the control token cannot be sent"))?,
        )
        .map_err(|_| configuration("the control token header cannot be sent"))?
        .limits(Limits::default().max_payload_len(Some(MAX_FRAME_BYTES)));
    let (socket, _) = builder
        .connect_on(UpgradeGuard::new(stream))
        .await
        .map_err(|error| unreachable("did not accept the host", &error))?;
    Ok(socket)
}

/// A room socket's stream, which holds the room's answer to the upgrade back until it is whole and
/// safe to parse.
///
/// The WebSocket library reads an answer's head for as long as it is incomplete, however long it
/// grows, and decodes `Sec-WebSocket-Accept` into a digest's twenty bytes on the assumption that
/// the value fits. So the answer is read here first, into a buffer of at most
/// [`MAX_UPGRADE_ANSWER_BYTES`], and handed on only once its head is complete and every accept
/// value in it is one SHA-1 digest in base64; anything else is an error of the stream, which ends
/// the attachment. After the head, reads and writes go straight to the stream.
pub struct UpgradeGuard<S> {
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

/// Refuses an answer carrying a `Sec-WebSocket-Accept` that is anything but one SHA-1 digest in
/// padded base64, on whichever line it appears: the value is decoded into twenty bytes, and a
/// longer one does not fit. A value is measured from after its leading spaces to the end of its
/// line, so one the library would read shorter is measured at least as long here.
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
        let value = line[colon + 1..].trim_ascii_start();
        let value = value.strip_suffix(b"\r").unwrap_or(value);
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
fn host_and_port(authority: &str) -> kr_pairing::Result<(&str, u16)> {
    let (host, port) = match authority.strip_prefix('[') {
        Some(bracketed) => {
            let (host, rest) = bracketed
                .split_once(']')
                .ok_or_else(|| configuration("an IPv6 origin closes its brackets"))?;
            (host, rest.strip_prefix(':'))
        }
        None => match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    let port = match port {
        Some(port) => port
            .parse()
            .map_err(|_| configuration(format!("{port} is not a port")))?,
        None => 443,
    };
    Ok((host, port))
}

/// Starts the task that carries one room socket's frames, and returns the relay's ends of it.
fn pump<S>(socket: WebSocketStream<S>) -> RoomSocket
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (to_relay, incoming) = mpsc::channel(ROOM_QUEUE);
    let (outgoing, from_relay) = mpsc::channel(ROOM_QUEUE);
    tokio::spawn(carry(socket, to_relay, from_relay));
    RoomSocket { outgoing, incoming }
}

/// A frame the room sent, and the wait for the relay to have room for it.
type Delivery = (
    ServiceFrame,
    Pin<
        Box<
            dyn Future<Output = Result<mpsc::OwnedPermit<ServiceFrame>, mpsc::error::SendError<()>>>
                + Send,
        >,
    >,
);

/// Carries frames between one room socket and its relay until either lets go.
///
/// Both directions move in the one task, each as far as it can: the room's frames are read and
/// delivered while the relay's wait to be written, and the relay's are taken and written while
/// the room's wait for the relay. A frame the room sent waits here until the relay has room for
/// it, and the socket is read no further meanwhile, which is the room's backpressure; the socket
/// takes the relay's next frame only when it can accept one, which is the relay's. A frame of the
/// room's that this host cannot read ends the socket.
async fn carry<S>(
    mut socket: WebSocketStream<S>,
    to_relay: mpsc::Sender<ServiceFrame>,
    mut from_relay: mpsc::Receiver<ClientFrame>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let relay_gone = to_relay.closed();
    tokio::pin!(relay_gone);
    let mut delivering: Option<Delivery> = None;
    let mut unflushed = false;
    std::future::poll_fn(|cx| {
        loop {
            if relay_gone.as_mut().poll(cx).is_ready() {
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
                        delivering = Some((frame, Box::pin(to_relay.clone().reserve_owned())));
                        moved = true;
                    }
                    // The library answers a ping itself.
                    Poll::Ready(Some(Ok(message))) if message.is_ping() || message.is_pong() => {
                        moved = true;
                    }
                    // Text is no frame of the room's, and a close, an error or the end ends it.
                    Poll::Ready(_) => return Poll::Ready(()),
                    Poll::Pending => {}
                }
            }
            match socket.poll_ready_unpin(cx) {
                Poll::Ready(Ok(())) => match from_relay.poll_recv(cx) {
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
                    Poll::Ready(Ok(())) => unflushed = false,
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
        let _ = tokio::time::timeout(CLOSE_DEADLINE, to_relay.send(frame)).await;
    }
    let _ = tokio::time::timeout(CLOSE_DEADLINE, socket.close()).await;
}

impl RendezvousHost for HttpsRendezvous {
    fn reserve_locator(
        &self,
        origin: &RendezvousOrigin,
        locator: &Locator,
        invitation_id: InvitationId,
        advertised_expires_at_ms: TimestampMs,
        control_token_hash: Digest256,
    ) -> kr_pairing::Result<bool> {
        self.runtime.block_on(self.reserve(
            origin,
            locator,
            invitation_id,
            advertised_expires_at_ms,
            control_token_hash,
        ))
    }

    fn release_locator(
        &self,
        origin: &RendezvousOrigin,
        locator: &Locator,
        control_token: &SymmetricKey,
    ) -> kr_pairing::Result<()> {
        self.runtime
            .block_on(self.release(origin, locator, control_token))
    }
}

/// The body of a reservation, in the service's JSON representation.
#[derive(Serialize)]
struct ReserveRequest<'a> {
    locator: &'a str,
    invitation_id: String,
    advertised_expires_at_ms: String,
    control_token_hash: String,
}

/// The body of a release.
#[derive(Serialize)]
struct ReleaseRequest<'a> {
    locator: &'a str,
    control_token: String,
}

/// A reservation's answer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReserveAnswer {
    reserved: bool,
    /// The expiry the service stored, after clamping. The host's own deadline is authoritative,
    /// so it is read only to check that it is a decimal counter. Absent is not `null`.
    #[serde(default, deserialize_with = "text")]
    advertised_expires_at_ms: Option<String>,
}

/// Reads a member that is text when it is present: an explicit `null` is not the member being
/// absent.
fn text<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

/// A release's answer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseAnswer {
    released: bool,
}

/// What each operation's answer must be, beyond its shape.
trait Answer: DeserializeOwned {
    fn is_answer(&self) -> bool;
}

impl Answer for ReserveAnswer {
    fn is_answer(&self) -> bool {
        match &self.advertised_expires_at_ms {
            Some(expiry) => self.reserved && is_decimal_counter(expiry),
            None => !self.reserved,
        }
    }
}

impl Answer for ReleaseAnswer {
    fn is_answer(&self) -> bool {
        self.released
    }
}

/// True for a decimal counter the service writes: no sign, no leading zero, at most 2^53 - 1.
fn is_decimal_counter(text: &str) -> bool {
    const MAX: u64 = (1 << 53) - 1;
    let canonical = text == "0" || (!text.starts_with('0') && !text.is_empty());
    canonical
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && text.parse::<u64>().is_ok_and(|value| value <= MAX)
}

fn reserve_body(
    locator: &Locator,
    invitation_id: InvitationId,
    advertised_expires_at_ms: TimestampMs,
    control_token_hash: Digest256,
) -> kr_pairing::Result<Vec<u8>> {
    json(&ReserveRequest {
        locator: locator.as_str(),
        invitation_id: invitation_id.to_string(),
        advertised_expires_at_ms: advertised_expires_at_ms.get().to_string(),
        control_token_hash: to_base64url(control_token_hash.as_bytes()),
    })
}

fn release_body(locator: &Locator, control_token: &SymmetricKey) -> kr_pairing::Result<Vec<u8>> {
    json(&ReleaseRequest {
        locator: locator.as_str(),
        control_token: to_base64url(control_token.expose()),
    })
}

fn json<T: Serialize>(body: &T) -> kr_pairing::Result<Vec<u8>> {
    serde_json::to_vec(body).map_err(|error| PairingError::RendezvousUnavailable {
        reason: format!("the request could not be written: {error}"),
    })
}

/// Sends one control request to `origin` and reads its answer.
async fn control<T: Answer>(
    origin: &RendezvousOrigin,
    path: &str,
    body: &[u8],
) -> kr_pairing::Result<T> {
    let gateway = GatewayOrigin::new(origin.as_str()).map_err(configuration)?;
    let transport = HttpService::with(gateway, CONTROL_DEADLINES, ResponseLimits::default())
        .map_err(|error| failed(&error))?;
    let address = format!("{}{path}", origin.as_str());
    let answer = transport
        .post_json(&address, body, &[])
        .await
        .map_err(|error| failed(&error))?;
    read_answer(&address, &answer)
}

/// What a failed exchange means: a request the transport refused to send was never going to reach
/// a rendezvous, and every other failure is the service not being reached or not answering.
fn failed(error: &ClientError) -> PairingError {
    match error {
        ClientError::Host(ProtocolError {
            code: ErrorCode::InvalidArgument,
            message,
            ..
        }) => configuration(message),
        other => PairingError::RendezvousUnavailable {
            reason: other.to_string(),
        },
    }
}

/// The service's envelope, when an answer carries it.
enum Envelope {
    /// `{"ok": true, "data": ...}`.
    Answered(serde_json::Value),
    /// `{"ok": false, "error": {"code": ...}}`.
    Refused(String),
}

/// Reads the envelope out of a body, or nothing when the body is not one.
fn envelope(body: &[u8]) -> Option<Envelope> {
    let serde_json::Value::Object(mut members) = serde_json::from_slice(body).ok()? else {
        return None;
    };
    match (members.remove("ok"), members.len()) {
        (Some(serde_json::Value::Bool(true)), 1) => members.remove("data").map(Envelope::Answered),
        (Some(serde_json::Value::Bool(false)), 1) => {
            let code = members.remove("error")?.get("code")?.as_str()?.to_owned();
            Some(Envelope::Refused(code))
        }
        _ => None,
    }
}

/// Reads one exchange's answer as this module's note describes.
fn read_answer<T: Answer>(address: &str, answer: &ServiceHttpAnswer) -> kr_pairing::Result<T> {
    let status = answer.status;
    match envelope(&answer.body) {
        Some(Envelope::Refused(code)) => Err(match code.as_str() {
            "NOT_CONFIGURED" | "NOT_FOUND" | "METHOD_NOT_ALLOWED" => configuration(format!(
                "{address} answered {code}: that origin serves no rendezvous"
            )),
            _ => PairingError::RendezvousUnavailable {
                reason: format!("{address} answered {code}"),
            },
        }),
        Some(Envelope::Answered(data)) if (200..300).contains(&status) => {
            serde_json::from_value::<T>(data)
                .ok()
                .filter(Answer::is_answer)
                .ok_or_else(|| {
                    configuration(format!(
                        "{address} answered {status} with something other than this operation's \
                         answer: that origin does not serve this rendezvous"
                    ))
                })
        }
        Some(Envelope::Answered(_)) => Err(configuration(format!(
            "{address} answered {status} with a success: that origin does not serve this \
             rendezvous"
        ))),
        None => Err(match status {
            200..=299 | 300..=399 | 404 | 405 => configuration(format!(
                "{address} answered {status} without the rendezvous service's envelope: that \
                 origin serves no rendezvous"
            )),
            _ => PairingError::RendezvousUnavailable {
                reason: format!("{address} answered {status} without the service's envelope"),
            },
        }),
    }
}

fn configuration(reason: impl std::fmt::Display) -> PairingError {
    PairingError::RendezvousConfiguration {
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Instant;

    use kr_protocol::ids::AttemptId;
    use kr_protocol::invitation::RendezvousMessage;
    use kr_protocol::scalars::{Bytes, Nonce256, Uuid};
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::watch;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::crypto::ring;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::{RootCertStore, ServerConfig};
    use tokio_websockets::ServerBuilder;

    use crate::service::net::rendezvous::{
        RoomHost, RoomOffer, RoomTicket, decode_client_frame, encode_message, serve_room,
    };

    /// How long a test waits for something before it fails as stuck.
    const WATCHDOG: Duration = Duration::from_secs(20);

    const ADDRESS: &str = "https://rendezvous.example/api/pair/locator/reserve";

    fn answered(status: u16, body: &str) -> ServiceHttpAnswer {
        ServiceHttpAnswer {
            status,
            body: body.as_bytes().to_vec(),
        }
    }

    fn reserved(status: u16, body: &str) -> kr_pairing::Result<bool> {
        read_answer::<ReserveAnswer>(ADDRESS, &answered(status, body)).map(|answer| answer.reserved)
    }

    fn released(status: u16, body: &str) -> kr_pairing::Result<()> {
        read_answer::<ReleaseAnswer>(ADDRESS, &answered(status, body)).map(|_| ())
    }

    fn code(result: kr_pairing::Result<impl std::fmt::Debug>) -> ErrorCode {
        result.expect_err("a failure").code()
    }

    /// The bodies are the service's JSON representation: the invitation as a hyphenated
    /// lower-case identity, the expiry as a decimal string, the token and its hash as unpadded
    /// base64url. Nothing else travels, and never the code's six secret characters.
    #[test]
    fn a_request_is_the_body_the_service_reads() {
        let locator = Locator::new("abcd").expect("a locator");
        let invitation_id = InvitationId::new(Uuid::from_bytes([0xab; 16]));
        let body = reserve_body(
            &locator,
            invitation_id,
            TimestampMs::new(1_764_003_600_000),
            Digest256::from_bytes([0xfb; 32]),
        )
        .expect("a body");
        assert_eq!(
            String::from_utf8(body).expect("text"),
            concat!(
                r#"{"locator":"abcd","#,
                r#""invitation_id":"abababab-abab-abab-abab-abababababab","#,
                r#""advertised_expires_at_ms":"1764003600000","#,
                r#""control_token_hash":"-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s"}"#
            )
        );
        let token = SymmetricKey::from_bytes([0x3e; 32]);
        let body = release_body(&locator, &token).expect("a body");
        assert_eq!(
            String::from_utf8(body).expect("text"),
            r#"{"locator":"abcd","control_token":"Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4"}"#
        );
    }

    /// KR-REQ-10.19: a successful reservation, a taken locator and a successful release are read
    /// from the service's envelope.
    #[test]
    fn the_services_answers_are_read() {
        assert!(
            reserved(
                200,
                r#"{"ok":true,"data":{"reserved":true,"advertised_expires_at_ms":"1764003600000"}}"#
            )
            .expect("an answer"),
            "reserved"
        );
        assert!(
            !reserved(200, r#"{"ok":true,"data":{"reserved":false}}"#).expect("an answer"),
            "taken"
        );
        released(200, r#"{"ok":true,"data":{"released":true}}"#).expect("released");
    }

    /// KR-REQ-10.19: an origin that answers but serves no rendezvous there is the owner's
    /// configuration to fix: the service saying it is not configured, a route it does not have,
    /// a redirect elsewhere, and a success that is not this operation's answer.
    #[test]
    fn an_origin_that_serves_no_rendezvous_is_a_configuration_error() {
        for (status, body) in [
            (
                501,
                r#"{"ok":false,"error":{"code":"NOT_CONFIGURED","message":"No.","missing":["PAIRING_ROOM"]}}"#,
            ),
            (
                404,
                r#"{"ok":false,"error":{"code":"NOT_FOUND","message":"No such route."}}"#,
            ),
            (
                405,
                r#"{"ok":false,"error":{"code":"METHOD_NOT_ALLOWED","message":"POST."}}"#,
            ),
            (404, "<html>Not Found</html>"),
            (405, ""),
            (302, ""),
            (200, "<html>a landing page</html>"),
            (200, r#"{"ok":true,"data":{"reserved":"yes"}}"#),
            (200, r#"{"ok":true,"data":{"reserved":true}}"#),
            (
                200,
                r#"{"ok":true,"data":{"reserved":true,"advertised_expires_at_ms":"017"}}"#,
            ),
            (
                200,
                r#"{"ok":true,"data":{"reserved":false,"advertised_expires_at_ms":"17"}}"#,
            ),
            (
                200,
                r#"{"ok":true,"data":{"reserved":true,"advertised_expires_at_ms":"1","more":1}}"#,
            ),
            (200, r#"{"ok":true,"data":{"released":true}}"#),
            (
                200,
                r#"{"ok":true,"data":{"reserved":false,"advertised_expires_at_ms":null}}"#,
            ),
            (503, r#"{"ok":true,"data":{"reserved":false}}"#),
        ] {
            assert_eq!(
                code(reserved(status, body)),
                ErrorCode::RendezvousConfigError,
                "{status} {body}"
            );
        }
        assert_eq!(
            code(released(200, r#"{"ok":true,"data":{"released":false}}"#)),
            ErrorCode::RendezvousConfigError
        );
    }

    /// KR-REQ-10.19: a service that is there but cannot serve now is unavailable, never a
    /// configuration error and never an authentication result: a rate limit with or without the
    /// envelope, a 5xx page from something in front of the service, and a refusal the contract
    /// does not make about the origin.
    #[test]
    fn a_service_that_cannot_serve_now_is_unavailable() {
        for (status, body) in [
            (503, "<html>Service Temporarily Unavailable</html>"),
            (502, ""),
            (
                429,
                r#"{"ok":false,"error":{"code":"RATE_LIMITED","message":"Slow down.","retryAfterSeconds":3}}"#,
            ),
            (429, "Too Many Requests"),
            (
                503,
                r#"{"ok":false,"error":{"code":"SERVICE_UNAVAILABLE","message":"Later."}}"#,
            ),
            (
                403,
                r#"{"ok":false,"error":{"code":"FORBIDDEN","message":"Not proven."}}"#,
            ),
            (403, "<html>Forbidden</html>"),
            (
                500,
                r#"{"ok":false,"error":{"code":"INTERNAL","message":"Oops."}}"#,
            ),
        ] {
            assert_eq!(
                code(reserved(status, body)),
                ErrorCode::RendezvousUnavailable,
                "{status} {body}"
            );
        }
        assert_eq!(
            code(released(
                403,
                r#"{"ok":false,"error":{"code":"FORBIDDEN","message":"Not proven."}}"#
            )),
            ErrorCode::RendezvousUnavailable
        );
    }

    /// KR-REQ-10.19: a service whose certificate this host cannot verify is unavailable: the
    /// handshake is refused before a byte of the request is written.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_service_whose_certificate_is_not_trusted_is_unavailable() {
        let key = KeyPair::generate().expect("a key pair");
        let certificate = CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .expect("certificate parameters")
            .self_signed(&key)
            .expect("a certificate");
        let config = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("a server configuration");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("an address").port();
        let handshakes = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("a connection");
            acceptor.accept(stream).await.is_err()
        });

        let origin = RendezvousOrigin::new(format!("https://127.0.0.1:{port}")).expect("an origin");
        let refused = HttpsRendezvous::new()
            .expect("a client")
            .reserve(
                &origin,
                &Locator::new("abcd").expect("a locator"),
                InvitationId::new(Uuid::from_bytes([1; 16])),
                TimestampMs::new(1_764_003_600_000),
                Digest256::from_bytes([2; 32]),
            )
            .await
            .expect_err("the certificate is not trusted");
        assert_eq!(
            refused.code(),
            ErrorCode::RendezvousUnavailable,
            "{refused}"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(20), handshakes)
                .await
                .expect("the server saw the attempt")
                .expect("the server ran"),
            "the handshake did not complete"
        );
    }

    /// KR-REQ-10.19: a service nobody answers for is unavailable, through the synchronous side a
    /// pairing step calls on its blocking thread.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_service_nobody_answers_for_is_unavailable() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("an address").port();
        drop(listener);
        let origin = RendezvousOrigin::new(format!("https://127.0.0.1:{port}")).expect("an origin");
        let rendezvous = HttpsRendezvous::new().expect("a client");
        let released = tokio::task::spawn_blocking(move || {
            rendezvous.release_locator(
                &origin,
                &Locator::new("abcd").expect("a locator"),
                &SymmetricKey::from_bytes([3; 32]),
            )
        })
        .await
        .expect("the step ran");
        assert_eq!(
            released.expect_err("nobody answers").code(),
            ErrorCode::RendezvousUnavailable
        );
    }

    /// A certificate authority a test trusts, or does not.
    struct Authority {
        der: CertificateDer<'static>,
        issuer: Issuer<'static, KeyPair>,
    }

    impl Authority {
        fn new(name: &str) -> Self {
            let mut params = CertificateParams::new(Vec::new()).expect("certificate parameters");
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            params
                .distinguished_name
                .push(DnType::CommonName, name.to_owned());
            let key = KeyPair::generate().expect("a key pair");
            let certificate = params.self_signed(&key).expect("a certificate");
            Self {
                der: certificate.der().clone(),
                issuer: Issuer::new(params, key),
            }
        }

        /// A client whose room sockets trust this authority and nothing else.
        fn trusted_by(&self) -> HttpsRendezvous {
            let mut roots = RootCertStore::empty();
            roots.add(self.der.clone()).expect("a root");
            let tls = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            HttpsRendezvous::with_tls(tls).expect("a client")
        }

        /// TLS presenting a certificate for 127.0.0.1 that this authority issued.
        fn acceptor(&self) -> TlsAcceptor {
            let key = KeyPair::generate().expect("a key pair");
            let leaf = CertificateParams::new(vec!["127.0.0.1".to_owned()])
                .expect("certificate parameters")
                .signed_by(&key, &self.issuer)
                .expect("a certificate");
            let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("protocol versions")
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf.der().clone(), self.der.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .expect("a server configuration");
            TlsAcceptor::from(Arc::new(config))
        }
    }

    /// The room's end of a host socket.
    type RoomEnd = WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>;

    /// A room on loopback, under a certificate a test's authority issued.
    struct LoopbackRoom {
        origin: RendezvousOrigin,
        listener: TcpListener,
        acceptor: TlsAcceptor,
    }

    impl LoopbackRoom {
        async fn start(authority: &Authority) -> Self {
            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("a loopback port");
            let port = listener.local_addr().expect("an address").port();
            Self {
                origin: RendezvousOrigin::new(format!("https://127.0.0.1:{port}"))
                    .expect("an origin"),
                listener,
                acceptor: authority.acceptor(),
            }
        }

        /// Takes the next host socket: the path it asked for, the token it presented, and the
        /// room's end.
        async fn attached(&self) -> (String, Option<String>, RoomEnd) {
            let (stream, _) = self.listener.accept().await.expect("a connection");
            let stream = self.acceptor.accept(stream).await.expect("TLS");
            let (request, socket) = ServerBuilder::new()
                .accept(stream)
                .await
                .expect("an upgrade");
            let token = request
                .headers()
                .get(CONTROL_TOKEN_HEADER)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            (request.uri().path().to_owned(), token, socket)
        }
    }

    fn locator() -> Locator {
        Locator::new("abcd").expect("a locator")
    }

    async fn send(end: &mut RoomEnd, frame: &ServiceFrame) {
        end.send(Message::binary(encode_frame(frame).expect("a frame")))
            .await
            .expect("sent");
    }

    async fn received(end: &mut RoomEnd) -> ClientFrame {
        let message = tokio::time::timeout(WATCHDOG, end.next())
            .await
            .expect("the host sends")
            .expect("a message")
            .expect("readable");
        decode_client_frame(message.as_payload()).expect("a frame of the room's vocabulary")
    }

    /// The host attaches at its locator's host path, presenting the control token, over TLS
    /// verified against the roots it trusts; the room's frames reach the relay and the relay's
    /// reach the room; and the room closing the socket ends it for the relay.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_host_attaches_with_its_token_and_frames_travel_both_ways() {
        let authority = Authority::new("rendezvous test authority");
        let room = LoopbackRoom::start(&authority).await;
        let client = authority.trusted_by();
        let token = SymmetricKey::from_bytes([5; 32]);
        let (attached, (path, presented, mut end)) = tokio::time::timeout(WATCHDOG, async {
            tokio::join!(
                client.attach(&room.origin, &locator(), &token),
                room.attached()
            )
        })
        .await
        .expect("the host attaches");
        let mut socket = attached.expect("attached");
        assert_eq!(path, "/api/pair/room/abcd/host");
        assert_eq!(presented, Some(to_base64url(token.expose())));

        let attempt_id = AttemptId::new(Uuid::from_bytes([7; 16]));
        for frame in [
            ServiceFrame::Attached {
                invitation_id: InvitationId::new(Uuid::from_bytes([6; 16])),
                expires_at_ms: 1_764_003_600_000,
            },
            ServiceFrame::Relay {
                attempt_id,
                payload: Bytes::new(vec![1, 2, 3]),
            },
        ] {
            send(&mut end, &frame).await;
            let delivered = tokio::time::timeout(WATCHDOG, socket.incoming.recv())
                .await
                .expect("the pump delivers");
            assert_eq!(delivered, Some(frame));
        }
        let reply = ClientFrame::CloseAttempt { attempt_id };
        socket
            .outgoing
            .send(reply.clone())
            .await
            .expect("the pump takes it");
        assert_eq!(received(&mut end).await, reply);

        end.close().await.expect("closed");
        let ended = tokio::time::timeout(WATCHDOG, socket.incoming.recv())
            .await
            .expect("the pump ends");
        assert_eq!(ended, None, "the room closing the socket ends it");
    }

    /// KR-REQ-10.19: a room whose certificate this host cannot verify is not attached to: the
    /// handshake is refused, and the failure is the service being unavailable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_room_whose_certificate_is_not_trusted_is_not_attached() {
        let trusted = Authority::new("trusted authority");
        let other = Authority::new("another authority");
        let room = LoopbackRoom::start(&other).await;
        let client = trusted.trusted_by();
        let (attached, handshake_failed) = tokio::time::timeout(WATCHDOG, async {
            tokio::join!(
                client.attach(&room.origin, &locator(), &SymmetricKey::from_bytes([5; 32])),
                async {
                    let (stream, _) = room.listener.accept().await.expect("a connection");
                    room.acceptor.accept(stream).await.is_err()
                }
            )
        })
        .await
        .expect("the attempt ends");
        assert_eq!(
            attached.expect_err("not trusted").code(),
            ErrorCode::RendezvousUnavailable
        );
        assert!(handshake_failed, "the handshake did not complete");
    }

    /// A room that refuses the control token, as one whose record is gone does, is not attached
    /// to, and the relay's answer to that is to try again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_room_that_refuses_the_token_is_not_attached() {
        let authority = Authority::new("rendezvous test authority");
        let room = LoopbackRoom::start(&authority).await;
        let client = authority.trusted_by();
        let (attached, ()) = tokio::time::timeout(WATCHDOG, async {
            tokio::join!(
                client.attach(&room.origin, &locator(), &SymmetricKey::from_bytes([5; 32])),
                async {
                    let (stream, _) = room.listener.accept().await.expect("a connection");
                    let mut stream = room.acceptor.accept(stream).await.expect("TLS");
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        head.push(stream.read_u8().await.expect("the request"));
                    }
                    let body =
                        r#"{"ok":false,"error":{"code":"FORBIDDEN","message":"Not proven."}}"#;
                    let answer = format!(
                        "HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(answer.as_bytes()).await.expect("answered");
                    let _ = stream.shutdown().await;
                }
            )
        })
        .await
        .expect("the attempt ends");
        assert_eq!(
            attached.expect_err("refused").code(),
            ErrorCode::RendezvousUnavailable
        );
    }

    /// Takes the next connection's TLS, reads the host's upgrade request, and answers it with
    /// `answer`, as a room that does not speak the upgrade properly would.
    async fn answer_upgrade(room: &LoopbackRoom, answer: Vec<u8>) {
        let (stream, _) = room.listener.accept().await.expect("a connection");
        let mut stream = room.acceptor.accept(stream).await.expect("TLS");
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.expect("the request"));
        }
        // The host may stop reading part way through, which ends this write.
        let _ = stream.write_all(&answer).await;
        let _ = stream.flush().await;
        // Held open, so the host's side of the answer is decided by what it read.
        let _ = tokio::time::timeout(WATCHDOG, stream.read_u8()).await;
    }

    /// An answer to the upgrade whose head never ends is refused once it reaches its bound, well
    /// before the attachment's deadline, rather than held for as long as it keeps arriving.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_answer_to_the_upgrade_that_never_ends_is_refused_at_its_bound() {
        let authority = Authority::new("rendezvous test authority");
        let room = LoopbackRoom::start(&authority).await;
        let client = authority.trusted_by();
        let mut answer = b"HTTP/1.1 101 Switching Protocols\r\nX-Padding: ".to_vec();
        answer.resize(answer.len() + 1024 * 1024, b'a');
        let attempted = Instant::now();
        let (attached, ()) = tokio::time::timeout(WATCHDOG, async {
            tokio::join!(
                client.attach(&room.origin, &locator(), &SymmetricKey::from_bytes([5; 32])),
                answer_upgrade(&room, answer)
            )
        })
        .await
        .expect("the attempt ends");
        assert_eq!(
            attached.expect_err("an answer that never ends").code(),
            ErrorCode::RendezvousUnavailable
        );
        let took = attempted.elapsed();
        assert!(
            took < ATTACH_DEADLINE / 2,
            "refused {took:?} after the attempt began, at the bound rather than the deadline"
        );
    }

    /// An answer whose accept value is longer than a SHA-1 digest is refused as an error, and the
    /// relay that asked goes on, rather than the WebSocket library failing on it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_accept_value_longer_than_a_digest_is_refused() {
        let authority = Authority::new("rendezvous test authority");
        let room = LoopbackRoom::start(&authority).await;
        let client = authority.trusted_by();
        let answer = concat!(
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n",
            "\r\n"
        );
        let (attached, ()) = tokio::time::timeout(WATCHDOG, async {
            tokio::join!(
                client.attach(&room.origin, &locator(), &SymmetricKey::from_bytes([5; 32])),
                answer_upgrade(&room, answer.as_bytes().to_vec())
            )
        })
        .await
        .expect("the attempt ends");
        assert_eq!(
            attached.expect_err("no digest").code(),
            ErrorCode::RendezvousUnavailable
        );
    }

    /// While the socket can take no more of the relay's frames, the room's frames still reach the
    /// relay: neither direction waits for the other.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_rooms_frames_reach_the_relay_while_the_socket_can_take_no_more() {
        let authority = Authority::new("rendezvous test authority");
        let room = LoopbackRoom::start(&authority).await;
        let client = authority.trusted_by();
        let (attached, (_, _, mut end)) = tokio::time::timeout(WATCHDOG, async {
            tokio::join!(
                client.attach(&room.origin, &locator(), &SymmetricKey::from_bytes([5; 32])),
                room.attached()
            )
        })
        .await
        .expect("the host attaches");
        let mut socket = attached.expect("attached");
        let attempt_id = AttemptId::new(Uuid::from_bytes([7; 16]));

        // The room reads nothing, and the relay sends until the socket takes no more.
        let large = ClientFrame::Relay {
            attempt_id,
            payload: Bytes::new(vec![0; super::super::rendezvous::MAX_FRAME_PAYLOAD_BYTES]),
        };
        tokio::time::timeout(WATCHDOG, async {
            loop {
                match socket.outgoing.try_send(large.clone()) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        if socket.outgoing.capacity() == 0 {
                            return;
                        }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => panic!("the pump ended"),
                }
            }
        })
        .await
        .expect("the socket fills");

        let opened = ServiceFrame::AttemptOpened { attempt_id };
        send(&mut end, &opened).await;
        let delivered = tokio::time::timeout(Duration::from_secs(5), socket.incoming.recv())
            .await
            .expect("delivered while the relay's frames wait");
        assert_eq!(delivered, Some(opened));
    }

    /// A frame of the room's that this host cannot read ends the socket, rather than being passed
    /// on or skipped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_frame_the_host_cannot_read_ends_its_socket() {
        let authority = Authority::new("rendezvous test authority");
        let room = LoopbackRoom::start(&authority).await;
        let client = authority.trusted_by();
        let (attached, (_, _, mut end)) = tokio::time::timeout(WATCHDOG, async {
            tokio::join!(
                client.attach(&room.origin, &locator(), &SymmetricKey::from_bytes([5; 32])),
                room.attached()
            )
        })
        .await
        .expect("the host attaches");
        let mut socket = attached.expect("attached");
        end.send(Message::binary(vec![0xff, 0x00]))
            .await
            .expect("sent");
        let ended = tokio::time::timeout(WATCHDOG, socket.incoming.recv())
            .await
            .expect("the pump ends");
        assert_eq!(ended, None);
        let closing = tokio::time::timeout(WATCHDOG, end.next())
            .await
            .expect("the host lets go");
        assert!(
            !matches!(closing, Some(Ok(ref message)) if message.is_binary()),
            "nothing follows the unreadable frame but the socket's end"
        );
    }

    /// A host that answers every message with the same frame, on offer until the test stops it.
    struct Answering {
        answer: ClientFrame,
    }

    impl RoomHost for Answering {
        fn room_step(
            &self,
            _invitation_id: InvitationId,
            _attempt_id: AttemptId,
            _message: RendezvousMessage,
        ) -> Vec<ClientFrame> {
            vec![self.answer.clone()]
        }

        fn room_abort(&self, _invitation_id: InvitationId, _attempt_id: AttemptId) {}

        fn room_offer(&self, _invitation_id: InvitationId) -> RoomOffer {
            RoomOffer::Open
        }
    }

    /// KR-REQ-10.19: the relay attaches through this client and carries a candidate's message to
    /// the host and the host's answer back through the room, and the owner's stop ends it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relay_attached_through_the_service_carries_a_candidates_message() {
        let authority = Authority::new("rendezvous test authority");
        let room = LoopbackRoom::start(&authority).await;
        let attempt_id = AttemptId::new(Uuid::from_bytes([7; 16]));
        let host = Arc::new(Answering {
            answer: ClientFrame::Relay {
                attempt_id,
                payload: Bytes::new(vec![4, 5, 6]),
            },
        });
        let token = SymmetricKey::from_bytes([5; 32]);
        let (stop, stopped) = watch::channel(false);
        let relay = tokio::spawn(serve_room(
            Arc::downgrade(&host),
            Arc::new(authority.trusted_by()) as Arc<dyn Rendezvous>,
            RoomTicket {
                invitation_id: InvitationId::new(Uuid::from_bytes([6; 16])),
                origin: room.origin.clone(),
                locator: locator(),
                control_token: token.clone(),
            },
            stopped,
        ));
        let (path, presented, mut end) = tokio::time::timeout(WATCHDOG, room.attached())
            .await
            .expect("the relay attaches");
        assert_eq!(path, "/api/pair/room/abcd/host");
        assert_eq!(presented, Some(to_base64url(token.expose())));

        send(&mut end, &ServiceFrame::AttemptOpened { attempt_id }).await;
        send(
            &mut end,
            &ServiceFrame::Relay {
                attempt_id,
                payload: encode_message(&RendezvousMessage::Admit {
                    client_nonce: Nonce256::from_bytes([3; 32]),
                })
                .expect("a message"),
            },
        )
        .await;
        assert_eq!(received(&mut end).await, host.answer);

        stop.send(true).expect("the relay listens");
        tokio::time::timeout(WATCHDOG, relay)
            .await
            .expect("the relay ends")
            .expect("cleanly");
    }
}
