//! What a short-code attempt says when it ends before the host's word can be trusted.
//!
//! Section 10 asks for an unreachable service and a known local configuration error to be told
//! apart, for an authentication failure to stay ambiguous, and for nothing to answer cheaply
//! whether a locator exists. So the evidence decides: reaching the room, the room holding the
//! socket before any host has spoken, and a host that has spoken but whose confirmation tag has not
//! verified are three phases, and each claims only what its evidence supports. A scripted room on
//! loopback, behind TLS a test issues, plays each ending.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use kr_client::pairing::candidate::{AttemptState, Candidate, Pairing};
use kr_client::pairing::clock::DeviceClock;
use kr_client::pairing::failure::FailureKind;
use kr_client::pairing::link::{EndpointPool, IrohLink};
use kr_client::pairing::paired::PairedHosts;
use kr_client::pairing::room::RoomConnector;
use kr_crypto::keys::DeviceKeys;
use kr_pairing::code::{CodeSecret, EnteredCode};
use kr_pairing::platform::TestClientBudgetStore;
use kr_pairing::spake::{Role, SpakeState};
use kr_protocol::ids::{BuildId, InvitationId};
use kr_protocol::invitation::RendezvousMessage;
use kr_protocol::pairing::{DeviceName, DevicePlatform, Locator, PairingContext, RendezvousOrigin};
use kr_protocol::rendezvous::{
    ClientFrame, CloseReason, ServiceFrame, decode_client_frame, decode_message, encode_frame,
    encode_message,
};
use kr_protocol::scalars::{Bytes, Nonce256, Uuid};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tokio_websockets::{Message, ServerBuilder, WebSocketStream};

/// How long a test waits for an attempt before it fails as stuck.
const WATCHDOG: Duration = Duration::from_secs(40);

/// The code every attempt here enters: locator `aB3x`, secret `Yz79Qw`.
const CODE: &str = "aB3x-Yz7-9Qw";

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

    fn connector(&self) -> RoomConnector {
        let mut roots = RootCertStore::empty();
        roots.add(self.der.clone()).expect("a root");
        RoomConnector::with_tls(
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    fn acceptor(&self) -> TlsAcceptor {
        let key = KeyPair::generate().expect("a key pair");
        let leaf = CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .expect("certificate parameters")
            .signed_by(&key, &self.issuer)
            .expect("a certificate");
        TlsAcceptor::from(Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("protocol versions")
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf.der().clone(), self.der.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .expect("a server configuration"),
        ))
    }
}

type RoomEnd = WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>;

/// What the scripted room does with the one socket it is sent.
#[derive(Clone, Copy)]
enum Script {
    /// Answers the upgrade with this status and body instead.
    Status(u16, &'static str),
    /// Holds the socket, serves nothing, and closes it at its deadline: an unknown locator.
    Unknown,
    /// Serves the record, and closes the socket at the first relayed frame: no host attached.
    NoHost,
    /// Serves the record, answers the admission with a genuine host PAKE message, and then says
    /// nothing more: a host that fell silent after it spoke.
    SilentAfterSpeaking,
}

/// A room on loopback that plays one script, and the origin it answers at.
async fn scripted(authority: &Authority, script: Script) -> RendezvousOrigin {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("an address").port();
    let origin = RendezvousOrigin::new(format!("https://127.0.0.1:{port}")).expect("an origin");
    let acceptor = authority.acceptor();
    let served = origin.clone();
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut stream) = acceptor.accept(stream).await else {
            return;
        };
        if let Script::Status(status, body) = script {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let Ok(byte) = stream.read_u8().await else {
                    return;
                };
                head.push(byte);
            }
            let answer = format!(
                "HTTP/1.1 {status} Scripted\r\ncontent-type: text/html\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(answer.as_bytes()).await;
            let _ = stream.flush().await;
            let _ = tokio::time::timeout(WATCHDOG, stream.read_u8()).await;
            return;
        }
        let Ok((_, mut end)) = ServerBuilder::new().accept(stream).await else {
            return;
        };
        play(&mut end, script, &served).await;
        // Held open: the attempt's side decides how it ends.
        let _ = tokio::time::timeout(WATCHDOG, async { while end.next().await.is_some() {} }).await;
    });
    origin
}

async fn send(end: &mut RoomEnd, frame: &ServiceFrame) {
    let _ = end
        .send(Message::binary(encode_frame(frame).expect("a frame")))
        .await;
}

async fn next_frame(end: &mut RoomEnd) -> Option<ClientFrame> {
    let message = end.next().await?.ok()?;
    decode_client_frame(message.as_payload()).ok()
}

async fn play(end: &mut RoomEnd, script: Script, origin: &RendezvousOrigin) {
    let invitation_id = InvitationId::new(Uuid::from_bytes([6; 16]));
    let record = ServiceFrame::Record {
        invitation_id,
        expires_at_ms: kr_ipc::now_ms().get() + 300_000,
    };
    match script {
        Script::Status(..) => {}
        Script::Unknown => {
            // The service's own deadline, shortened: nothing is served, then the socket closes.
            tokio::time::sleep(Duration::from_millis(300)).await;
            send(
                end,
                &ServiceFrame::Closed {
                    reason: CloseReason::Deadline,
                },
            )
            .await;
        }
        Script::NoHost => {
            send(end, &record).await;
            while let Some(frame) = next_frame(end).await {
                if matches!(frame, ClientFrame::Relay { .. }) {
                    send(
                        end,
                        &ServiceFrame::Closed {
                            reason: CloseReason::HostGone,
                        },
                    )
                    .await;
                    return;
                }
            }
        }
        Script::SilentAfterSpeaking => {
            send(end, &record).await;
            let Some(ClientFrame::Attempt { attempt_id }) = next_frame(end).await else {
                return;
            };
            let Some(ClientFrame::Relay { payload, .. }) = next_frame(end).await else {
                return;
            };
            let Ok(RendezvousMessage::Admit { client_nonce }) = decode_message(payload.as_slice())
            else {
                return;
            };
            let host_nonce = Nonce256::from_bytes([9; 32]);
            let context = PairingContext {
                rendezvous_origin: origin.clone(),
                locator: Locator::new("aB3x").expect("a locator"),
                invitation_id,
                attempt_id,
                host_nonce,
                client_nonce,
            };
            let host = SpakeState::start(
                Role::Host,
                &context,
                &CodeSecret::new("Yz79Qw").expect("the secret"),
            );
            send(
                end,
                &ServiceFrame::Relay {
                    attempt_id,
                    payload: encode_message(&RendezvousMessage::HostPake {
                        host_nonce,
                        message: Bytes::new(host.message().to_vec()),
                    })
                    .expect("a message"),
                },
            )
            .await;
        }
    }
}

/// A device that pairs through `room`.
fn pairing(room: RoomConnector) -> (Pairing, tempfile::TempDir) {
    let keys = DeviceKeys::generate().expect("keys");
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let pool = EndpointPool::new(keys.transport.clone())
        .bound_to("127.0.0.1:0".parse().expect("loopback"));
    let pairing = Pairing {
        candidate: Candidate::new(
            keys,
            DeviceName::new("A test computer").expect("a name"),
            DevicePlatform::Macos,
            BuildId::new("kr-test/0").expect("a build"),
        ),
        budget: Arc::new(TestClientBudgetStore::new().expect("a budget")),
        clock: Arc::new(DeviceClock::current().expect("a clock")),
        room: Arc::new(room),
        link: Arc::new(IrohLink::new(Arc::new(pool))),
        hosts: Arc::new(PairedHosts::open(directory.path().join("pairing")).expect("a store")),
    };
    (pairing, directory)
}

/// Runs one attempt against `origin` and returns what a person is shown at its end.
async fn ending(room: RoomConnector, origin: &RendezvousOrigin) -> AttemptState {
    let (pairing, _directory) = pairing(room);
    let (progress, shown) = watch::channel(AttemptState::Idle);
    let code = EnteredCode::parse(CODE).expect("a code");
    let outcome = tokio::time::timeout(WATCHDOG, pairing.pair_by_code(origin, &code, &progress))
        .await
        .expect("the attempt ends");
    assert!(outcome.is_err(), "no host paired");
    shown.borrow().clone()
}

fn kind_of(state: &AttemptState) -> (FailureKind, Option<u32>) {
    let AttemptState::Ended { failure } = state else {
        panic!("the attempt ended, and shows how: {state:?}");
    };
    (failure.kind, failure.tries_left)
}

/// KR-REQ-10.19: a room this device cannot verify, or one that answers with a failure in front
/// of the service, could not be reached; the try was charged, and the person is told how many are
/// left.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_that_cannot_serve_now_is_unreachable() {
    let authority = Authority::new("rendezvous test authority");
    let untrusted = Authority::new("another authority");
    let origin = scripted(&untrusted, Script::Unknown).await;
    assert_eq!(
        kind_of(&ending(authority.connector(), &origin).await),
        (FailureKind::ServiceUnreachable, Some(4))
    );
    let origin = scripted(&authority, Script::Status(503, "<html>Later</html>")).await;
    assert_eq!(
        kind_of(&ending(authority.connector(), &origin).await),
        (FailureKind::ServiceUnreachable, Some(4))
    );
}

/// KR-REQ-10.19: an origin that answers with a page or a missing route where the room's upgrade
/// should be does not serve pairing, which is this device's configuration to fix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_origin_that_serves_no_room_is_the_devices_configuration() {
    let authority = Authority::new("rendezvous test authority");
    for (status, body) in [
        (
            404,
            r#"{"ok":false,"error":{"code":"NOT_FOUND","message":"No."}}"#,
        ),
        (200, "<html><body>a landing page</body></html>"),
    ] {
        let origin = scripted(&authority, Script::Status(status, body)).await;
        assert_eq!(
            kind_of(&ending(authority.connector(), &origin).await),
            (FailureKind::ServiceNotPairing, Some(4)),
            "{status}"
        );
    }
}

/// KR-REQ-10.19: an unknown locator and a known one with no host attached end the same way to a
/// person, because nothing the room did before a host spoke is evidence about the invitation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_room_no_host_spoke_in_says_the_same_whether_or_not_the_locator_exists() {
    let authority = Authority::new("rendezvous test authority");
    let unknown = scripted(&authority, Script::Unknown).await;
    let unknown = ending(authority.connector(), &unknown).await;
    let hostless = scripted(&authority, Script::NoHost).await;
    let hostless = ending(authority.connector(), &hostless).await;
    assert_eq!(kind_of(&unknown), (FailureKind::NoHostAnswered, Some(4)));
    // What an interface is sent is the state's serialised form; a failure's detail is for a log.
    assert_eq!(
        serde_json::to_value(&unknown).expect("serialises"),
        serde_json::to_value(&hostless).expect("serialises"),
        "one page-visible ending for both"
    );
}

/// KR-REQ-10.19: a host that spoke and then fell silent leaves the attempt timed out, never
/// expired: the attempt ran out of time, and the invitation may still be open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_that_falls_silent_after_it_spoke_times_the_attempt_out() {
    let authority = Authority::new("rendezvous test authority");
    let origin = scripted(&authority, Script::SilentAfterSpeaking).await;
    assert_eq!(
        kind_of(&ending(authority.connector(), &origin).await),
        (FailureKind::TimedOut, Some(4))
    );
}
