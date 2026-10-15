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
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
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
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_rustls::rustls::ClientConfig;
use tokio_websockets::{Message, WebSocketStream};

use crate::shown::{Said, Shown};
use crate::tunnel;
use crate::wss::{self, Failure, Upgrade};

/// How many frames wait in each direction between a room socket and its caller.
const ROOM_QUEUE: usize = 16;

/// How long a socket may take to close once its pump is done with it.
const CLOSE_DEADLINE: Duration = Duration::from_secs(1);

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
        let path: &'static str = self.path();
        formatter.write_str(path)
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
        .strip_prefix(tunnel::REFUSED)
        .and_then(|rest| rest.strip_prefix(' '))
        .filter(|status| status.len() == 3 && status.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|status| status.parse::<u16>().ok());
    if let Some(status) = refused {
        return crate::shown!("{} {}", tunnel::REFUSED, status);
    }
    wss::REASONS
        .iter()
        .chain(std::iter::once(&NO_VERIFIER))
        .chain(tunnel::REASONS.iter())
        .find(|known| **known == reason)
        .map_or_else(
            || Shown::said("[a reason this client does not give]"),
            |known| Shown::said(known),
        )
}

/// Opens room sockets with one TLS configuration, directly or through one proxy.
#[derive(Clone)]
pub struct RoomConnector {
    tls: Arc<ClientConfig>,
    proxy: Option<ProxyUrl>,
}

impl std::fmt::Debug for RoomConnector {
    /// Whether a proxy carries its sockets. Never the proxy's address, which can carry a user name
    /// and a password, and never the TLS configuration.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoomConnector")
            .field("proxied", &self.proxy.is_some())
            .finish_non_exhaustive()
    }
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
    pub fn with_tls(tls: ClientConfig) -> Self {
        Self {
            tls: wss::for_upgrade(tls),
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
    /// [`wss::OPEN_DEADLINE`].
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
        let path = format!("/api/pair/room/{}/{}", locator.as_str(), role.path());
        let headers = token
            .as_deref()
            .map(|token| [(CONTROL_TOKEN_HEADER, token)]);
        let opened = wss::open(
            &self.tls,
            &Upgrade {
                origin: origin.as_str(),
                path: &path,
                headers: headers.as_ref().map_or(&[], |headers| headers.as_slice()),
                max_payload: MAX_FRAME_BYTES,
                proxy: self.proxy.as_ref(),
                loopback_plain: false,
            },
        )
        .await
        .map_err(|failure| room_failure(origin, failure))?;
        Ok(pump(opened))
    }
}

/// What a room failure says for a socket that did not open at `origin`.
fn room_failure(origin: &RendezvousOrigin, failure: Failure) -> RoomError {
    let origin = origin.as_str().to_owned();
    match failure {
        Failure::Configuration(reason) => RoomError::Configuration {
            origin,
            reason: reason.to_owned(),
        },
        Failure::Unreachable(reason) => RoomError::Unreachable { origin, reason },
        Failure::Refused(status) => RoomError::Refused { origin, status },
        Failure::NotAnUpgrade(reason) => RoomError::NotAnUpgrade {
            origin,
            reason: reason.to_owned(),
        },
    }
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

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
                reason: wss::NO_TLS.to_owned(),
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

    /// A proxy that does not open the tunnel is said by the proxy's part in this client's words, and
    /// by the status when it refused: nothing the proxy wrote, not its reason phrase, a header or an
    /// answer that is not one, and not the proxy's address. A refusal's status in any shape but
    /// three digits is a reason this client does not give.
    #[tokio::test]
    async fn a_proxy_that_does_not_open_the_tunnel_is_said_in_this_clients_words() {
        use crate::shown::marker::{MARKER, NEUTRAL, assert_unmarked, failure_renderings};
        use tokio::net::TcpListener;

        /// A proxy that reads one tunnel request, writes `answer` and closes.
        async fn answering(answer: Vec<u8>) -> ProxyUrl {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
            let port = listener.local_addr().expect("its address").port();
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("the tunnel request");
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let Ok(byte) = stream.read_u8().await else {
                        return;
                    };
                    head.push(byte);
                }
                let _ = stream.write_all(&answer).await;
                let _ = stream.shutdown().await;
            });
            format!("http://127.0.0.1:{port}")
                .parse()
                .expect("a proxy address")
        }

        let tls = ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("the protocol versions")
        .with_root_certificates(tokio_rustls::rustls::RootCertStore::empty())
        .with_no_client_auth();
        let origin = RendezvousOrigin::new("https://rendezvous.example").expect("an origin");
        let locator = Locator::new("abcd").expect("a locator");
        let marked = MARKER.as_bytes();

        for (answer, said) in [
            (
                format!("HTTP/1.1 407 {MARKER}\r\nProxy-Authenticate: {MARKER}\r\n\r\n")
                    .into_bytes(),
                "the proxy refused the tunnel with status 407",
            ),
            (
                format!("{MARKER}\r\n\r\n").into_bytes(),
                tunnel::NO_STATUS_LINE,
            ),
            (
                marked
                    .iter()
                    .copied()
                    .cycle()
                    .take(tunnel::MAX_ANSWER_BYTES + 1)
                    .collect(),
                tunnel::ANSWER_TOO_LONG,
            ),
            (marked.to_vec(), tunnel::ENDED),
        ] {
            // The negative control: what the proxy writes holds the marker.
            assert!(answer.windows(marked.len()).any(|window| window == marked));
            let failed = RoomConnector::with_tls(tls.clone())
                .through(Some(answering(answer).await))
                .open(&origin, &locator, RoomRole::Candidate)
                .await
                .map(|_| ())
                .expect_err("the tunnel does not open");
            // The neutral control: the stage, the room's origin and the proxy's part.
            assert_eq!(
                failed.to_string(),
                format!("the room at https://rendezvous.example could not be reached: {said}")
            );
            assert_unmarked(said, &failure_renderings(failed));
        }

        for reason in [
            format!("{} {MARKER}", tunnel::REFUSED),
            format!("{} 4031", tunnel::REFUSED),
            format!("{}  407", tunnel::REFUSED),
            format!("{} {NEUTRAL}", tunnel::REFUSED),
        ] {
            let failed = RoomError::Unreachable {
                origin: "https://rendezvous.example".to_owned(),
                reason,
            };
            assert_eq!(
                failed.to_string(),
                "the room at https://rendezvous.example could not be reached: [a reason this client \
                 does not give]"
            );
            assert_unmarked("a status in another shape", &failure_renderings(failed));
        }
    }
}
