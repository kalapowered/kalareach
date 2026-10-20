//! The rendezvous service a deployed host reaches over the network.
//!
//! Reserving and releasing a locator are JSON requests over HTTPS to the service's pairing routes,
//! made through the managed-service transport, [`HttpService`]: certificate and host name
//! verification, finite deadlines, a bounded answer and no redirects. Each request goes to the
//! origin the invitation names, so the service the owner chose is the one contacted, and it goes
//! through the proxy this host's configuration document selects when it selects one.
//!
//! The host's room socket is kr-client's room socket in the host's role
//! ([`kr_client::pairing::room::RoomConnector`]): a WebSocket at
//! `wss://<origin>/api/pair/room/<locator>/host`, verified against the platform's trust, opened
//! through the same proxy as a `CONNECT` tunnel when one is selected, and proven with the
//! reservation's control token in `KR-Pair-Control-Token`. The relay (see
//! [`super::rendezvous::serve_room`]) reads it, and a socket that ends is answered by attaching
//! again. A socket that did not open is the service being unavailable, except an origin that
//! cannot be addressed at all, which is a configuration error; that is what the host has always
//! reported, and a candidate reading the same failures tells more of them apart.
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
//!
//! # What is sent again
//!
//! The service answers a reservation or a release that its room could not carry out with 503,
//! `SERVICE_UNAVAILABLE` and a `retryAfterSeconds` that it also serves as `Retry-After`: a deploy
//! resets every room, and a request that arrives meanwhile is told to come back. A room that threw
//! is answered at once, and one that is held up is answered when the service's eight seconds for it
//! have passed, which [`CONTROL_DEADLINES`] waits for. That is the only
//! answer sent again, and only once it names a wait. A 500, a rate limit, a refusal and a 503 from
//! something in front of the service are not. A request is made at most [`MAX_ATTEMPTS`] times and
//! never past [`RETRY_BUDGET`] from the first, a reservation never past the invitation's own life,
//! and no request is made past the time the caller allows the whole call, which is what the
//! mutation it is made for has left; a request that runs out of any of them is reported as the
//! service being unavailable, with the answer it ended on. A repeat finds what the first did: a reservation the room made is answered
//! as taken, which makes the host draw another locator, and a release it made is answered
//! `FORBIDDEN`, which a release has always been reported as.

use std::time::Duration;

use tokio::time::Instant;

use kr_client::error::ClientError;
use kr_client::pairing::room::{RoomConnector, RoomError, RoomRole, RoomSocket};
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
use kr_transport::config::ProxyUrl;
use kr_transport::listener::BoxFuture;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::rendezvous::{NotAttached, OWNER_RELEASE, Rendezvous};

/// Where a host reserves a locator for an invitation.
pub const RESERVE_PATH: &str = "/api/pair/locator/reserve";

/// Where a host releases a reservation, proving possession of its control token.
pub const RELEASE_PATH: &str = "/api/pair/locator/release";

/// How long a reservation or a release may take.
///
/// A reservation runs while the owner waits for the invitation and while the invitation's lock is
/// held, so the whole exchange is bounded well inside the transport's own defaults.
///
/// The answer may begin as late as the service's own refusal of a room that is held up: the
/// service gives a room eight seconds from the moment it has read the request and then answers
/// `SERVICE_UNAVAILABLE` with a wait. The host waits ten, as the transport does by default, which
/// leaves two for the connection, the network and the service's own start. A shorter wait would end
/// the call before that refusal could arrive, and only a room that throws would be sent again.
pub const CONTROL_DEADLINES: HttpDeadlines = HttpDeadlines {
    connect: Duration::from_secs(5),
    read: Duration::from_secs(10),
    total: Duration::from_secs(10),
};

/// How many times a reservation or a release is made in all, the first time included, when the
/// service answers that it should be sent again.
pub const MAX_ATTEMPTS: u32 = 4;

/// How long a reservation or a release, sent again, may take from its first attempt to the end of
/// its last.
///
/// It is well inside the five minutes an invitation lives and the time a mutation is given, and a
/// request is sent again only when its wait and the whole of another attempt still fit.
pub const RETRY_BUDGET: Duration = Duration::from_secs(30);

// A release made while an owner waits is one exchange: no wait and a whole attempt fit in its time.
const _: () = assert!(OWNER_RELEASE.as_millis() == CONTROL_DEADLINES.total.as_millis());

/// The rendezvous service a deployed host reaches over HTTPS.
///
/// kr-pairing asks for a reservation and a release synchronously, on the blocking thread a pairing
/// step runs on, so each request runs on the daemon's runtime and that thread waits for it.
#[derive(Clone, Debug)]
pub struct HttpsRendezvous {
    runtime: tokio::runtime::Handle,
    /// What the host's room sockets are opened with.
    room: RoomConnector,
    /// The proxy every request and room socket goes through, or none.
    proxy: Option<ProxyUrl>,
}

impl HttpsRendezvous {
    /// Builds the client on the runtime of the calling task, which runs its requests, with room
    /// sockets verified against the platform's trust.
    ///
    /// `proxy` is the one this host's configuration document selects: the reservations, the
    /// releases and the room sockets all go through it, and with none they all go directly.
    ///
    /// # Errors
    ///
    /// Returns a reason when called outside a runtime, or when the platform's verifier cannot be
    /// set up.
    pub fn new(proxy: Option<ProxyUrl>) -> Result<Self, String> {
        let room = RoomConnector::platform()
            .map_err(|error| error.to_string())?
            .through(proxy.clone());
        Self::with_connector(room, proxy)
    }

    /// Builds the client with the connector its room sockets are opened with, and the proxy its
    /// requests go through.
    fn with_connector(room: RoomConnector, proxy: Option<ProxyUrl>) -> Result<Self, String> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "the rendezvous client runs its requests on the daemon's runtime")?;
        Ok(Self {
            runtime,
            room,
            proxy,
        })
    }

    /// Reserves `locator` at `origin` for `invitation_id`. False when the locator is taken.
    ///
    /// Only the locator travels, never the six secret characters of the code, and the control
    /// token only as its hash. The whole call, any request sent again included, takes no longer
    /// than `within` once its first request is made.
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
        within: Duration,
    ) -> kr_pairing::Result<bool> {
        let gateway = GatewayOrigin::new(origin.as_str()).map_err(configuration)?;
        self.reserve_at(
            &gateway,
            locator,
            invitation_id,
            advertised_expires_at_ms,
            control_token_hash,
            within,
        )
        .await
    }

    /// As [`Self::reserve`], at the gateway the origin names.
    ///
    /// A reservation is sent again only while the invitation it is for is still on offer, which
    /// is until the expiry it advertises.
    async fn reserve_at(
        &self,
        gateway: &GatewayOrigin,
        locator: &Locator,
        invitation_id: InvitationId,
        advertised_expires_at_ms: TimestampMs,
        control_token_hash: Digest256,
        within: Duration,
    ) -> kr_pairing::Result<bool> {
        let body = reserve_body(
            locator,
            invitation_id,
            advertised_expires_at_ms,
            control_token_hash,
        )?;
        let life = Duration::from_millis(
            advertised_expires_at_ms
                .get()
                .saturating_sub(kr_ipc::now_ms().get()),
        );
        let until = Instant::now() + life.min(RETRY_BUDGET).min(within);
        let answer: ReserveAnswer =
            control(gateway, RESERVE_PATH, &body, self.proxy.as_ref(), until).await?;
        Ok(answer.reserved)
    }

    /// Releases the reservation of `locator` at `origin`, taking no longer than `within` in all
    /// once the first request is made.
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
        within: Duration,
    ) -> kr_pairing::Result<()> {
        let gateway = GatewayOrigin::new(origin.as_str()).map_err(configuration)?;
        self.release_at(&gateway, locator, control_token, within)
            .await
    }

    /// As [`Self::release`], at the gateway the origin names.
    async fn release_at(
        &self,
        gateway: &GatewayOrigin,
        locator: &Locator,
        control_token: &SymmetricKey,
        within: Duration,
    ) -> kr_pairing::Result<()> {
        let body = release_body(locator, control_token)?;
        let until = Instant::now() + RETRY_BUDGET.min(within);
        let _: ReleaseAnswer =
            control(gateway, RELEASE_PATH, &body, self.proxy.as_ref(), until).await?;
        Ok(())
    }
}

impl Rendezvous for HttpsRendezvous {
    fn attach(
        &self,
        origin: &RendezvousOrigin,
        locator: &Locator,
        control_token: &SymmetricKey,
    ) -> BoxFuture<'static, Result<RoomSocket, NotAttached>> {
        let room = self.room.clone();
        let origin = origin.clone();
        let locator = locator.clone();
        let token = control_token.clone();
        Box::pin(async move {
            room.open(&origin, &locator, RoomRole::Host(&token))
                .await
                .map_err(not_attached)
        })
    }

    fn reserve_within(
        &self,
        origin: &RendezvousOrigin,
        locator: &Locator,
        invitation_id: InvitationId,
        advertised_expires_at_ms: TimestampMs,
        control_token_hash: Digest256,
        within: Duration,
    ) -> kr_pairing::Result<bool> {
        self.runtime.block_on(self.reserve(
            origin,
            locator,
            invitation_id,
            advertised_expires_at_ms,
            control_token_hash,
            within,
        ))
    }

    fn release_within(
        &self,
        origin: &RendezvousOrigin,
        locator: &Locator,
        control_token: &SymmetricKey,
        within: Duration,
    ) -> kr_pairing::Result<()> {
        self.runtime
            .block_on(self.release(origin, locator, control_token, within))
    }
}

/// A room socket that did not open, with the wait the room named before another attempt.
fn not_attached(error: RoomError) -> NotAttached {
    let retry_after = match &error {
        RoomError::Refused { retry_after, .. } => *retry_after,
        RoomError::Configuration { .. }
        | RoomError::Unreachable { .. }
        | RoomError::NotAnUpgrade { .. } => None,
    };
    NotAttached {
        error: room_failure(error),
        retry_after,
    }
}

/// What a room socket that did not open means for the host.
///
/// An origin the socket cannot address is the owner's configuration to fix. Everything else,
/// whatever the room answered, is the service being unavailable to this attachment, which the
/// relay answers by attaching again while the invitation is on offer.
fn room_failure(error: RoomError) -> PairingError {
    match error {
        RoomError::Configuration { .. } => configuration(&error),
        RoomError::Unreachable { .. }
        | RoomError::Refused { .. }
        | RoomError::NotAnUpgrade { .. } => PairingError::RendezvousUnavailable {
            reason: error.to_string(),
        },
    }
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
        self.reserve_within(
            origin,
            locator,
            invitation_id,
            advertised_expires_at_ms,
            control_token_hash,
            RETRY_BUDGET,
        )
    }

    fn release_locator(
        &self,
        origin: &RendezvousOrigin,
        locator: &Locator,
        control_token: &SymmetricKey,
    ) -> kr_pairing::Result<()> {
        self.release_within(origin, locator, control_token, RETRY_BUDGET)
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

/// Sends one control request to `gateway`, through `proxy` when there is one, and reads its answer.
///
/// A request the service answers that it should be sent again is sent again, after the wait the
/// answer names, as this module's note describes. `until` is the last instant an attempt after the
/// first may end at. Such an attempt is started only when a whole one fits before it, which is
/// asked again after its wait, and its exchange is stopped at it. Its transport is made before the
/// wait, so what making it costs is spent from the time the second question reads. The first
/// attempt is the one request a host always made.
async fn control<T: Answer>(
    gateway: &GatewayOrigin,
    path: &str,
    body: &[u8],
    proxy: Option<&ProxyUrl>,
    until: Instant,
) -> kr_pairing::Result<T> {
    let mut transport = transport_to(gateway, proxy)?;
    let mut attempt = 1;
    let mut result = exchange(&transport, path, body).await;
    loop {
        let failure = match result {
            Ok(answer) => return Ok(answer),
            Err(failure) => failure,
        };
        let Some(wait) = failure.send_again_after else {
            return Err(failure.error);
        };
        if attempt == MAX_ATTEMPTS || !fits(until, wait) {
            return Err(failure.error);
        }
        attempt += 1;
        let Ok(next) = transport_to(gateway, proxy) else {
            return Err(failure.error);
        };
        transport = next;
        tokio::time::sleep(wait).await;
        // The wait can end later than it was set for, and another attempt is made only if all of
        // it still fits.
        if !fits(until, Duration::ZERO) {
            return Err(failure.error);
        }
        result = match tokio::time::timeout_at(until, exchange(&transport, path, body)).await {
            Ok(result) => result,
            Err(_) => return Err(failure.error),
        };
    }
}

/// Whether a wait of `wait` and a whole attempt after it end by `until`.
///
/// The wait is the service's figure, which can be any number, so it is compared with the time left
/// and never added to an instant.
fn fits(until: Instant, wait: Duration) -> bool {
    wait.saturating_add(CONTROL_DEADLINES.total) <= until.saturating_duration_since(Instant::now())
}

/// An exchange that did not give the answer asked for, and whether the service said to send the
/// request again.
struct Unanswered {
    error: PairingError,
    send_again_after: Option<Duration>,
}

impl From<PairingError> for Unanswered {
    fn from(error: PairingError) -> Self {
        Self {
            error,
            send_again_after: None,
        }
    }
}

/// The transport one attempt at a control request is made over.
fn transport_to(
    gateway: &GatewayOrigin,
    proxy: Option<&ProxyUrl>,
) -> kr_pairing::Result<HttpService> {
    HttpService::through(
        gateway.clone(),
        CONTROL_DEADLINES,
        ResponseLimits::default(),
        proxy,
    )
    .map_err(|error| failed(&error))
}

/// One attempt at a control request, over `transport`.
async fn exchange<T: Answer>(
    transport: &HttpService,
    path: &str,
    body: &[u8],
) -> Result<T, Unanswered> {
    let address = format!("{}{path}", transport.origin().as_str());
    let answer = transport
        .post_json(&address, body, &[])
        .await
        .map_err(|error| failed(&error))?;
    read_answer(&address, &answer).map_err(|error| Unanswered {
        error,
        send_again_after: send_again_after(&answer),
    })
}

/// The wait the service named, when it answered that the request should be sent again: 503,
/// `SERVICE_UNAVAILABLE`, and the seconds to wait that it also serves as `Retry-After`.
fn send_again_after(answer: &ServiceHttpAnswer) -> Option<Duration> {
    match envelope(&answer.body)? {
        Envelope::Refused {
            code,
            retry_after_seconds: Some(seconds),
        } if answer.status == 503 && code == "SERVICE_UNAVAILABLE" => {
            Some(Duration::from_secs(seconds))
        }
        Envelope::Refused { .. } | Envelope::Answered(_) => None,
    }
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
    /// `{"ok": false, "error": {"code": ...}}`, with the seconds to wait when it names them.
    Refused {
        code: String,
        retry_after_seconds: Option<u64>,
    },
}

/// Reads the envelope out of a body, or nothing when the body is not one.
///
/// The body is read through the client's one reader, so a text that names a member twice, in the
/// envelope or anywhere inside it, is not the service's envelope.
fn envelope(body: &[u8]) -> Option<Envelope> {
    let mut members: serde_json::Map<String, serde_json::Value> =
        kr_client::services::json::read(body).ok()?;
    match (members.remove("ok"), members.len()) {
        (Some(serde_json::Value::Bool(true)), 1) => members.remove("data").map(Envelope::Answered),
        (Some(serde_json::Value::Bool(false)), 1) => {
            let error = members.remove("error")?;
            Some(Envelope::Refused {
                code: error.get("code")?.as_str()?.to_owned(),
                retry_after_seconds: error
                    .get("retryAfterSeconds")
                    .and_then(serde_json::Value::as_u64),
            })
        }
        _ => None,
    }
}

/// Reads one exchange's answer as this module's note describes.
fn read_answer<T: Answer>(address: &str, answer: &ServiceHttpAnswer) -> kr_pairing::Result<T> {
    let status = answer.status;
    match envelope(&answer.body) {
        Some(Envelope::Refused { code, .. }) => Err(match code.as_str() {
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
    use std::sync::Arc;

    use futures_util::{SinkExt, StreamExt};
    use kr_ipc::testing::UNANSWERED;
    use kr_protocol::ids::AttemptId;
    use kr_protocol::invitation::RendezvousMessage;
    use kr_protocol::rendezvous::{
        CONTROL_TOKEN_HEADER, ClientFrame, ServiceFrame, decode_client_frame, encode_frame,
        encode_message,
    };
    use kr_protocol::scalars::{Bytes, Nonce256, Uuid};
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::watch;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::crypto::ring;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio_websockets::{Message, ServerBuilder, WebSocketStream};

    use crate::service::net::rendezvous::{RoomHost, RoomOffer, RoomTicket, serve_room};

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

    /// KR-REQ-04.19: an answer that names a member twice is not the service's envelope, whatever
    /// else it says, so the status decides what it is, as it does for any answer without the
    /// envelope: a success is an origin that serves no rendezvous, and a fault is the service
    /// being unavailable.
    #[test]
    fn an_answer_that_names_a_member_twice_is_not_the_services_envelope() {
        // One reader would take the first for a taken locator and another for a reservation, and
        // the refusal for a rate limit or for an origin that is configured wrongly.
        for (status, body, expected) in [
            (
                200,
                r#"{"ok":true,"data":{"reserved":false,"reserved":true,"advertised_expires_at_ms":"1764003600000"}}"#,
                ErrorCode::RendezvousConfigError,
            ),
            (
                503,
                r#"{"ok":false,"error":{"code":"RATE_LIMITED","code":"NOT_CONFIGURED","message":"No."}}"#,
                ErrorCode::RendezvousUnavailable,
            ),
        ] {
            assert_eq!(code(reserved(status, body)), expected, "{status} {body}");
        }
        assert_eq!(
            code(released(
                200,
                r#"{"ok":true,"data":{"released":false},"data":{"released":true}}"#
            )),
            ErrorCode::RendezvousConfigError
        );

        // The controls: each answer naming its members once reads as itself.
        assert!(
            reserved(
                200,
                r#"{"ok":true,"data":{"reserved":true,"advertised_expires_at_ms":"1764003600000"}}"#
            )
            .expect("an answer")
        );
        assert!(!reserved(200, r#"{"ok":true,"data":{"reserved":false}}"#).expect("an answer"));
        released(200, r#"{"ok":true,"data":{"released":true}}"#).expect("released");
        assert_eq!(
            code(reserved(
                503,
                r#"{"ok":false,"error":{"code":"NOT_CONFIGURED","message":"No."}}"#
            )),
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
        let refused = HttpsRendezvous::new(None)
            .expect("a client")
            .reserve(
                &origin,
                &Locator::new("abcd").expect("a locator"),
                InvitationId::new(Uuid::from_bytes([1; 16])),
                TimestampMs::new(1_764_003_600_000),
                Digest256::from_bytes([2; 32]),
                ENOUGH,
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
        // An address nothing answers at: a port this test freed could be handed to another test
        // before the connection is made, and that test's server would answer.
        let origin = RendezvousOrigin::new(format!("https://{UNANSWERED}")).expect("an origin");
        let rendezvous = HttpsRendezvous::new(None).expect("a client");
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

    /// The service's answer to a request its room could not carry out: send it again, with no wait.
    const BUSY_NOW: &str = r#"{"ok":false,"error":{"code":"SERVICE_UNAVAILABLE","message":"Later.","retryAfterSeconds":0}}"#;

    const RESERVED: &str =
        r#"{"ok":true,"data":{"reserved":true,"advertised_expires_at_ms":"1764003600000"}}"#;

    const RELEASED: &str = r#"{"ok":true,"data":{"released":true}}"#;

    /// A rendezvous service on loopback that answers its requests as `answers` say, in order and
    /// the last one for every request after them, and counts the requests it read.
    struct Scripted {
        gateway: GatewayOrigin,
        seen: Arc<std::sync::atomic::AtomicUsize>,
        /// When each request was accepted.
        arrivals: Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
        /// How many requests the service has read to their end.
        read: Arc<watch::Sender<usize>>,
        /// What the first answer waits for, when the service holds it.
        gate: Arc<tokio::sync::Semaphore>,
        serving: tokio::task::JoinHandle<()>,
    }

    impl Scripted {
        async fn answering(answers: &[(u16, &str)]) -> Self {
            Self::serving(answers, false).await
        }

        /// As [`Self::answering`], with the first answer held back until [`Self::let_go`], as a room
        /// that is held up holds it.
        async fn holding_the_first(answers: &[(u16, &str)]) -> Self {
            Self::serving(answers, true).await
        }

        async fn serving(answers: &[(u16, &str)], holding: bool) -> Self {
            let answers: Vec<(u16, String)> = answers
                .iter()
                .map(|(status, body)| (*status, (*body).to_owned()))
                .collect();
            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("a loopback port");
            let port = listener.local_addr().expect("an address").port();
            let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counted = Arc::clone(&seen);
            let arrivals = Arc::new(std::sync::Mutex::new(Vec::new()));
            let arrived = Arc::clone(&arrivals);
            let read = Arc::new(watch::channel(0).0);
            let gate = Arc::new(tokio::sync::Semaphore::new(0));
            let (reading, gated) = (Arc::clone(&read), Arc::clone(&gate));
            let serving = tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    arrived
                        .lock()
                        .expect("arrivals")
                        .push(std::time::Instant::now());
                    let nth = counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let (status, body) = answers[nth.min(answers.len() - 1)].clone();
                    let (reading, gated) = (Arc::clone(&reading), Arc::clone(&gated));
                    tokio::spawn(async move {
                        // The request is read to the end of its head and its body, so the client
                        // has finished writing before it is answered.
                        let mut head = Vec::new();
                        let mut byte = [0_u8; 1];
                        while !head.ends_with(b"\r\n\r\n") {
                            if stream.read_exact(&mut byte).await.is_err() {
                                return;
                            }
                            head.push(byte[0]);
                        }
                        let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
                        let length = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .and_then(|value| value.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        let mut request = vec![0_u8; length];
                        if stream.read_exact(&mut request).await.is_err() {
                            return;
                        }
                        reading.send_modify(|read| *read += 1);
                        if holding && nth == 0 {
                            match gated.acquire().await {
                                Ok(permit) => permit.forget(),
                                Err(_) => return,
                            }
                        }
                        let answer = format!(
                            "HTTP/1.1 {status} Answer\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(answer.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
            });
            Self {
                gateway: GatewayOrigin::new(format!("http://127.0.0.1:{port}"))
                    .expect("a loopback origin"),
                seen,
                arrivals,
                read,
                gate,
                serving,
            }
        }

        /// Lets the held first answer go.
        fn let_go(&self) {
            self.gate.add_permits(1);
        }

        /// Waits until the service has read `count` requests to their end.
        async fn until_read(&self, count: usize) {
            self.read
                .subscribe()
                .wait_for(|read| *read >= count)
                .await
                .expect("the service runs");
        }

        fn requests(&self) -> usize {
            self.seen.load(std::sync::atomic::Ordering::SeqCst)
        }

        /// How long after the first request the second one was accepted. A wait never ends early,
        /// so this is at least the wait that was asked for, whatever the machine's load.
        fn gap_before_the_second(&self) -> Duration {
            let arrivals = self.arrivals.lock().expect("arrivals");
            arrivals[1].duration_since(arrivals[0])
        }
    }

    impl Drop for Scripted {
        fn drop(&mut self) {
            self.serving.abort();
        }
    }

    /// More time than any of these cases spends: what a caller that is in no hurry allows.
    const ENOUGH: Duration = Duration::from_secs(300);

    /// A reservation for an invitation that has `life` left.
    async fn reserve_for(service: &Scripted, life: Duration) -> kr_pairing::Result<bool> {
        reserve_within_for(service, life, ENOUGH).await
    }

    /// A reservation for an invitation that has `life` left, for a caller that allows the whole
    /// call `within`.
    async fn reserve_within_for(
        service: &Scripted,
        life: Duration,
        within: Duration,
    ) -> kr_pairing::Result<bool> {
        let expires = kr_ipc::now_ms().get() + u64::try_from(life.as_millis()).expect("a life");
        tokio::time::timeout(
            WATCHDOG,
            HttpsRendezvous::new(None).expect("a client").reserve_at(
                &service.gateway,
                &Locator::new("abcd").expect("a locator"),
                InvitationId::new(Uuid::from_bytes([1; 16])),
                TimestampMs::new(expires),
                Digest256::from_bytes([2; 32]),
                within,
            ),
        )
        .await
        .expect("the reservation ends")
    }

    /// A release for a caller that allows the whole call `within`.
    async fn release_within_for(service: &Scripted, within: Duration) -> kr_pairing::Result<()> {
        tokio::time::timeout(
            WATCHDOG,
            HttpsRendezvous::new(None).expect("a client").release_at(
                &service.gateway,
                &Locator::new("abcd").expect("a locator"),
                &SymmetricKey::from_bytes([3; 32]),
                within,
            ),
        )
        .await
        .expect("the release ends")
    }

    /// KR-REQ-10.19: a reservation the service answers 503 for, naming a wait, is made again after
    /// that wait, and the second answer is the reservation's. A deploy resets every room, and the
    /// pairing that began during it must not fail.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reservation_the_service_said_to_send_again_is_sent_again() {
        let service = Scripted::answering(&[(503, BUSY_NOW), (200, RESERVED)]).await;

        let reserved = reserve_for(&service, Duration::from_secs(300)).await;

        assert!(reserved.expect("the second attempt is answered"));
        assert_eq!(service.requests(), 2);
    }

    /// KR-REQ-10.19: a room that is held up answers only when the route's own deadline passes,
    /// after the time the host once waited, and the host reads that refusal and sends the request
    /// again. The clock is moved by hand, to a moment past the time the host once waited and inside
    /// the time it waits now, while the service holds the answer.
    #[tokio::test]
    async fn the_refusal_of_a_room_that_is_held_up_is_read_and_the_request_is_sent_again() {
        /// Longer than the five seconds the host once waited for an answer to begin, and shorter
        /// than the route's own eight.
        const HELD_UP_FOR: Duration = Duration::from_secs(6);

        let service = Scripted::holding_the_first(&[(503, BUSY_NOW), (200, RESERVED)]).await;
        let call = reserve_for(&service, Duration::from_secs(300));
        tokio::pin!(call);

        // Under the ordinary clock until the service has the whole request, so that what the host
        // gives up on is an answer it is waiting for.
        tokio::select! {
            biased;
            () = service.until_read(1) => {}
            outcome = &mut call => panic!("the host gave up before the service had the request: {outcome:?}"),
        }
        tokio::time::pause();
        tokio::time::advance(HELD_UP_FOR).await;
        tokio::time::resume();
        service.let_go();

        let reserved = call.await;

        assert!(
            reserved.expect("the held-up room's refusal is read and the second attempt answered")
        );
        assert_eq!(service.requests(), 2);
    }

    /// KR-REQ-10.19: a request is sent again after the wait the service named, and not before it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_is_sent_again_after_the_wait_the_service_named() {
        let wait = r#"{"ok":false,"error":{"code":"SERVICE_UNAVAILABLE","message":"Later.","retryAfterSeconds":1}}"#;
        let service = Scripted::answering(&[(503, wait), (200, RESERVED)]).await;

        let reserved = reserve_for(&service, Duration::from_secs(300)).await;

        assert!(reserved.expect("the second attempt is answered"));
        assert!(service.gap_before_the_second() >= Duration::from_secs(1));
    }

    /// KR-REQ-10.19: a release is sent again the same way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_release_the_service_said_to_send_again_is_sent_again() {
        let service = Scripted::answering(&[(503, BUSY_NOW), (200, RELEASED)]).await;

        let released = release_within_for(&service, ENOUGH).await;

        released.expect("the second attempt is answered");
        assert_eq!(service.requests(), 2);
    }

    /// KR-REQ-10.19: a service that keeps answering 503 is asked a bounded number of times, and
    /// is then reported as unavailable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_service_that_keeps_saying_to_send_again_is_reported_unavailable() {
        let service = Scripted::answering(&[(503, BUSY_NOW)]).await;

        let reserved = reserve_for(&service, Duration::from_secs(300)).await;

        assert_eq!(code(reserved), ErrorCode::RendezvousUnavailable);
        assert_eq!(
            service.requests(),
            usize::try_from(MAX_ATTEMPTS).expect("a count")
        );
    }

    /// KR-REQ-10.19: only a 503 that names a wait and says `SERVICE_UNAVAILABLE` is sent again. A
    /// 500 is a failure, and so is a 503 from something in front of the service, one that names no
    /// wait and one that says something else.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_the_answer_that_says_to_send_again_is_sent_again() {
        for (status, body) in [
            (
                500,
                r#"{"ok":false,"error":{"code":"INTERNAL","message":"Oops.","retryAfterSeconds":0}}"#,
            ),
            (
                503,
                r#"{"ok":false,"error":{"code":"SERVICE_UNAVAILABLE","message":"Later."}}"#,
            ),
            (503, "<html>Service Temporarily Unavailable</html>"),
            (
                500,
                r#"{"ok":false,"error":{"code":"SERVICE_UNAVAILABLE","message":"Later.","retryAfterSeconds":0}}"#,
            ),
            (
                503,
                r#"{"ok":false,"error":{"code":"RATE_LIMITED","message":"Slow down.","retryAfterSeconds":0}}"#,
            ),
            (
                429,
                r#"{"ok":false,"error":{"code":"RATE_LIMITED","message":"Slow down.","retryAfterSeconds":0}}"#,
            ),
        ] {
            let service = Scripted::answering(&[(status, body), (200, RESERVED)]).await;

            let reserved = reserve_for(&service, Duration::from_secs(300)).await;

            assert_eq!(
                code(reserved),
                ErrorCode::RendezvousUnavailable,
                "{status} {body}"
            );
            assert_eq!(service.requests(), 1, "{status} {body}");
        }
    }

    /// A mutation is given a time to live, and a request sent again for it must not be sent past
    /// it: a caller that allows less than a wait and a whole attempt takes one request, and one
    /// that allows enough takes the second. A reservation's invitation has plenty of life left in
    /// every case here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reservation_is_not_sent_again_past_the_time_its_caller_allows() {
        let wait = r#"{"ok":false,"error":{"code":"SERVICE_UNAVAILABLE","message":"Later.","retryAfterSeconds":1}}"#;
        let tight = Scripted::answering(&[(503, wait), (200, RESERVED)]).await;

        // The wait and a whole attempt do not fit in five seconds.
        let short =
            reserve_within_for(&tight, Duration::from_secs(300), Duration::from_secs(5)).await;

        assert_eq!(code(short), ErrorCode::RendezvousUnavailable);
        assert_eq!(tight.requests(), 1);

        // The same answers, to a caller that allows the second request, which is made.
        let roomy = Scripted::answering(&[(503, wait), (200, RESERVED)]).await;

        let long = reserve_within_for(&roomy, Duration::from_secs(300), ENOUGH).await;

        assert!(long.expect("the second request is answered"));
        assert_eq!(roomy.requests(), 2);
    }

    /// A release made while an owner waits for its answer is made once, and one nobody waits for is
    /// sent again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_release_an_owner_waits_for_is_made_once() {
        let owner_waits = Scripted::answering(&[(503, BUSY_NOW), (200, RELEASED)]).await;

        let once = release_within_for(&owner_waits, OWNER_RELEASE).await;

        assert_eq!(code(once), ErrorCode::RendezvousUnavailable);
        assert_eq!(owner_waits.requests(), 1);

        let nobody_waits = Scripted::answering(&[(503, BUSY_NOW), (200, RELEASED)]).await;

        let again = release_within_for(&nobody_waits, RETRY_BUDGET).await;

        again.expect("the second request is answered");
        assert_eq!(nobody_waits.requests(), 2);
    }

    /// KR-REQ-10.19: a reservation is not sent again once its invitation is over, and not after a
    /// wait that the time allowed does not hold.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_is_not_sent_again_when_the_time_allowed_cannot_hold_it() {
        let over = Scripted::answering(&[(503, BUSY_NOW), (200, RESERVED)]).await;
        let reserved = reserve_for(&over, Duration::ZERO).await;
        assert_eq!(code(reserved), ErrorCode::RendezvousUnavailable);
        assert_eq!(over.requests(), 1);

        // A wait the budget cannot hold, one it could hold if the attempt after it took no time,
        // and a figure no instant can have added to it.
        for seconds in [3600, 25, u64::MAX] {
            let wait = format!(
                r#"{{"ok":false,"error":{{"code":"SERVICE_UNAVAILABLE","message":"Later.","retryAfterSeconds":{seconds}}}}}"#
            );
            let slow = Scripted::answering(&[(503, &wait), (200, RESERVED)]).await;
            let reserved = reserve_for(&slow, Duration::from_secs(300)).await;
            assert_eq!(
                code(reserved),
                ErrorCode::RendezvousUnavailable,
                "{seconds}"
            );
            assert_eq!(slow.requests(), 1, "{seconds}");
        }
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
            HttpsRendezvous::with_connector(RoomConnector::with_tls(tls), None).expect("a client")
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
            attached.expect_err("not trusted").error.code(),
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
            attached.expect_err("refused").error.code(),
            ErrorCode::RendezvousUnavailable
        );
    }

    /// KR-REQ-10.19: a room socket that did not open is the service being unavailable to the
    /// host, whatever the room answered, and only an origin the socket cannot address is the
    /// owner's configuration to fix.
    #[test]
    fn a_room_that_did_not_open_is_unavailable_unless_its_origin_cannot_be_addressed() {
        let origin = "https://rendezvous.example".to_owned();
        assert_eq!(
            room_failure(RoomError::Configuration {
                origin: origin.clone(),
                reason: "no".to_owned(),
            })
            .code(),
            ErrorCode::RendezvousConfigError
        );
        for failure in [
            RoomError::Unreachable {
                origin: origin.clone(),
                reason: "no".to_owned(),
            },
            RoomError::Refused {
                origin: origin.clone(),
                status: 404,
                retry_after: None,
            },
            RoomError::Refused {
                origin: origin.clone(),
                status: 200,
                retry_after: None,
            },
            RoomError::NotAnUpgrade {
                origin,
                reason: "no".to_owned(),
            },
        ] {
            assert_eq!(
                room_failure(failure.clone()).code(),
                ErrorCode::RendezvousUnavailable,
                "{failure:?}"
            );
        }
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
