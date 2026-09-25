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

use std::time::Duration;

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

use super::rendezvous::Rendezvous;

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
        let answer: ReserveAnswer =
            control(origin, RESERVE_PATH, &body, self.proxy.as_ref()).await?;
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
        let _: ReleaseAnswer = control(origin, RELEASE_PATH, &body, self.proxy.as_ref()).await?;
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
        let room = self.room.clone();
        let origin = origin.clone();
        let locator = locator.clone();
        let token = control_token.clone();
        Box::pin(async move {
            room.open(&origin, &locator, RoomRole::Host(&token))
                .await
                .map_err(room_failure)
        })
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

/// Sends one control request to `origin`, through `proxy` when there is one, and reads its answer.
async fn control<T: Answer>(
    origin: &RendezvousOrigin,
    path: &str,
    body: &[u8],
    proxy: Option<&ProxyUrl>,
) -> kr_pairing::Result<T> {
    let gateway = GatewayOrigin::new(origin.as_str()).map_err(configuration)?;
    let transport =
        HttpService::through(gateway, CONTROL_DEADLINES, ResponseLimits::default(), proxy)
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
///
/// The body is read through the client's one reader, so a text that names a member twice, in the
/// envelope or anywhere inside it, is not the service's envelope.
fn envelope(body: &[u8]) -> Option<Envelope> {
    let mut members: serde_json::Map<String, serde_json::Value> =
        kr_client::services::json::read(body).ok()?;
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
    use std::sync::Arc;

    use futures_util::{SinkExt, StreamExt};
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
            },
            RoomError::Refused {
                origin: origin.clone(),
                status: 200,
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
