//! A rendezvous room on loopback, behind TLS a test issues.
//!
//! The candidate's failure suite (kr-client `tests/pairing_failures.rs`) and the host's pairing
//! suite (kr-controller `tests/pairing_client.rs`) serve their rooms through this one harness: the
//! same certificate authority, TLS acceptor, upgrade and room path, whether what answers in the
//! room is a script that ends the attempt or a host that pairs. A device reaches it through the
//! product's own `RoomConnector`, trusting this authority alone.
//!
//! Suites in other crates include this module by its path rather than keep a copy of their own.

#![allow(
    dead_code,
    reason = "each suite that includes this module uses the part of it that it needs"
)]

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use kr_client::pairing::room::{RoomConnector, RoomSocket};
use kr_protocol::pairing::RendezvousOrigin;
use kr_protocol::rendezvous::{decode_client_frame, encode_frame};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_websockets::{Message, ServerBuilder, WebSocketStream};

/// How long the room holds a connection whose ending is the device's to decide.
pub const HOLD: Duration = Duration::from_secs(40);

/// One connection to the room, once TLS is established.
pub type Stream = tokio_rustls::server::TlsStream<TcpStream>;

/// The room's end of an upgraded socket.
pub type RoomEnd = WebSocketStream<Stream>;

/// A certificate authority a test trusts, which issues the room's certificate.
pub struct Authority {
    der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

impl Authority {
    /// A new authority named `name`.
    pub fn new(name: &str) -> Self {
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

    /// The product's room connector, trusting this authority alone.
    pub fn connector(&self) -> RoomConnector {
        let mut roots = RootCertStore::empty();
        roots.add(self.der.clone()).expect("a root");
        RoomConnector::with_tls(
            ClientConfig::builder_with_provider(Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }

    /// A TLS acceptor presenting a certificate this authority issued for the loopback address.
    fn acceptor(&self) -> TlsAcceptor {
        let key = KeyPair::generate().expect("a key pair");
        let leaf = CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .expect("certificate parameters")
            .signed_by(&key, &self.issuer)
            .expect("a certificate");
        TlsAcceptor::from(Arc::new(
            ServerConfig::builder_with_provider(Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))
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

/// Serves every connection to a new loopback origin with `serve`, once TLS from `authority` is
/// established, and returns the origin. `serve` is also given the origin, which a room that plays
/// a host needs for the pairing context.
pub async fn serve<F, Served>(authority: &Authority, serve: F) -> RendezvousOrigin
where
    F: Fn(Stream, RendezvousOrigin) -> Served + Send + Sync + 'static,
    Served: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("an address").port();
    let origin = RendezvousOrigin::new(format!("https://127.0.0.1:{port}")).expect("an origin");
    let acceptor = authority.acceptor();
    let served = origin.clone();
    let serve = Arc::new(serve);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (acceptor, origin, serve) = (acceptor.clone(), served.clone(), Arc::clone(&serve));
            tokio::spawn(async move {
                if let Ok(stream) = acceptor.accept(stream).await {
                    serve(stream, origin).await;
                }
            });
        }
    });
    origin
}

/// Answers the request on `stream` with `status` and `body` where the upgrade should be, and holds
/// the connection until the device closes it.
pub async fn answer(mut stream: Stream, status: u16, body: &str) {
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
    let _ = tokio::time::timeout(HOLD, stream.read_u8()).await;
}

/// Accepts the WebSocket upgrade on `stream`. Returns the locator and the role the room path
/// `/api/pair/room/<locator>/<role>` names, and the room's end of the socket.
pub async fn upgrade(stream: Stream) -> Option<(String, String, RoomEnd)> {
    let (request, end) = ServerBuilder::new().accept(stream).await.ok()?;
    let (locator, role) = request
        .uri()
        .path()
        .strip_prefix("/api/pair/room/")?
        .split_once('/')?;
    Some((locator.to_owned(), role.to_owned(), end))
}

/// Carries every frame between the room's end of an upgraded socket and `socket`, the socket of a
/// room a test runs, until either side ends.
pub async fn carry(end: RoomEnd, socket: RoomSocket) {
    let (mut to_device, mut from_device) = end.split();
    let RoomSocket {
        outgoing,
        mut incoming,
    } = socket;
    let down = async move {
        while let Some(frame) = incoming.recv().await {
            let frame = Message::binary(encode_frame(&frame).expect("a frame"));
            if to_device.send(frame).await.is_err() {
                return;
            }
        }
        let _ = to_device.close().await;
    };
    let up = async move {
        while let Some(Ok(message)) = from_device.next().await {
            if message.is_close() {
                return;
            }
            if !message.is_binary() {
                continue;
            }
            let Ok(frame) = decode_client_frame(message.as_payload()) else {
                return;
            };
            if outgoing.send(frame).await.is_err() {
                return;
            }
        }
    };
    tokio::join!(down, up);
}
