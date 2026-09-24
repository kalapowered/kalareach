//! The rendezvous room socket, against a room on loopback under certificates a test issues.
//!
//! One socket serves both roles. A host attaches at its locator's `host` path with the
//! reservation's control token; a candidate opens the `candidate` path and presents nothing. Both
//! are verified TLS, bounded while the room answers the upgrade, and bounded in how much of the
//! room's traffic can wait for them once they are open.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use kr_client::pairing::room::{
    MAX_UNANSWERED_PINGS, OPEN_DEADLINE, RoomConnector, RoomError, RoomRole, RoomSocket,
};
use kr_crypto::secret::SymmetricKey;
use kr_protocol::ids::{AttemptId, InvitationId};
use kr_protocol::pairing::{Locator, RendezvousOrigin};
use kr_protocol::rendezvous::{
    CONTROL_TOKEN_HEADER, ClientFrame, MAX_FRAME_BYTES, MAX_FRAME_PAYLOAD_BYTES, ServiceFrame,
    decode_client_frame, encode_frame,
};
use kr_protocol::scalars::{Bytes, Uuid, to_base64url};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_websockets::{Message, ServerBuilder, WebSocketStream};

/// How long a test waits for something before it fails as stuck.
const WATCHDOG: Duration = Duration::from_secs(20);

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

    /// A connector whose room sockets trust this authority and nothing else.
    fn trusted_by(&self) -> RoomConnector {
        let mut roots = RootCertStore::empty();
        roots.add(self.der.clone()).expect("a root");
        let tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
        RoomConnector::with_tls(tls)
    }

    /// TLS presenting a certificate for `name` that this authority issued.
    fn acceptor_for(&self, name: &str) -> TlsAcceptor {
        let key = KeyPair::generate().expect("a key pair");
        let leaf = CertificateParams::new(vec![name.to_owned()])
            .expect("certificate parameters")
            .signed_by(&key, &self.issuer)
            .expect("a certificate");
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
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

/// The room's end of one socket.
type RoomEnd = WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>;

/// A room on loopback, under a certificate a test's authority issued.
struct LoopbackRoom {
    origin: RendezvousOrigin,
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl LoopbackRoom {
    /// A room whose certificate names the address it answers on.
    async fn start(authority: &Authority) -> Self {
        Self::start_as(authority, "127.0.0.1").await
    }

    /// A room whose certificate names `name`, whatever address it answers on.
    async fn start_as(authority: &Authority, name: &str) -> Self {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("an address").port();
        Self {
            origin: RendezvousOrigin::new(format!("https://127.0.0.1:{port}")).expect("an origin"),
            listener,
            acceptor: authority.acceptor_for(name),
        }
    }

    /// Takes the next socket: the path it asked for, the token it presented, and the room's end.
    async fn opened(&self) -> (String, Option<String>, RoomEnd) {
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

    /// Takes the next connection's TLS, reads the upgrade request, and answers it with each of
    /// `pieces` in turn, as a room that does not speak the upgrade properly would.
    async fn answer_in_pieces(&self, pieces: Vec<Vec<u8>>) {
        let (stream, _) = self.listener.accept().await.expect("a connection");
        let mut stream = self.acceptor.accept(stream).await.expect("TLS");
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.expect("the request"));
        }
        for piece in pieces {
            // The client may stop reading part way through, which ends this write.
            if stream.write_all(&piece).await.is_err() || stream.flush().await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Held open, so the client's side of the answer is decided by what it read.
        let _ = tokio::time::timeout(WATCHDOG, stream.read_u8()).await;
    }
}

fn locator() -> Locator {
    Locator::new("abcd").expect("a locator")
}

fn token() -> SymmetricKey {
    SymmetricKey::from_bytes([5; 32])
}

async fn send(end: &mut RoomEnd, frame: &ServiceFrame) {
    end.send(Message::binary(encode_frame(frame).expect("a frame")))
        .await
        .expect("sent");
}

async fn received(end: &mut RoomEnd) -> ClientFrame {
    let message = tokio::time::timeout(WATCHDOG, end.next())
        .await
        .expect("the client sends")
        .expect("a message")
        .expect("readable");
    decode_client_frame(message.as_payload()).expect("a frame of the room's vocabulary")
}

/// Opens a socket in `role` while the room takes it.
async fn open_while(
    connector: &RoomConnector,
    room: &LoopbackRoom,
    role: RoomRole<'_>,
) -> (RoomSocket, String, Option<String>, RoomEnd) {
    let locator = locator();
    let (opened, (path, presented, end)) = tokio::time::timeout(WATCHDOG, async {
        tokio::join!(connector.open(&room.origin, &locator, role), room.opened())
    })
    .await
    .expect("the socket opens");
    (opened.expect("opened"), path, presented, end)
}

/// Opens a socket while the room answers the upgrade with `pieces`, and returns the refusal.
async fn refusal_of(
    connector: &RoomConnector,
    room: &LoopbackRoom,
    pieces: Vec<Vec<u8>>,
) -> RoomError {
    let locator = locator();
    let (opened, ()) = tokio::time::timeout(WATCHDOG, async {
        tokio::join!(
            connector.open(&room.origin, &locator, RoomRole::Candidate),
            room.answer_in_pieces(pieces)
        )
    })
    .await
    .expect("the attempt ends");
    opened.expect_err("refused")
}

/// KR-REQ-10.27: a candidate opens its locator's candidate path over verified TLS and presents
/// no control token; the room's record reaches it first, its attempt reaches the room, and the
/// room closing the socket ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_candidate_opens_its_room_without_a_token_and_frames_travel_both_ways() {
    let authority = Authority::new("rendezvous test authority");
    let room = LoopbackRoom::start(&authority).await;
    let (mut socket, path, presented, mut end) =
        open_while(&authority.trusted_by(), &room, RoomRole::Candidate).await;
    assert_eq!(path, "/api/pair/room/abcd/candidate");
    assert_eq!(presented, None, "a candidate holds no control token");

    let record = ServiceFrame::Record {
        invitation_id: InvitationId::new(Uuid::from_bytes([6; 16])),
        expires_at_ms: 1_764_003_600_000,
    };
    send(&mut end, &record).await;
    let delivered = tokio::time::timeout(WATCHDOG, socket.incoming.recv())
        .await
        .expect("the pump delivers");
    assert_eq!(delivered, Some(record));

    let attempt = ClientFrame::Attempt {
        attempt_id: AttemptId::new(Uuid::from_bytes([7; 16])),
    };
    socket
        .outgoing
        .send(attempt.clone())
        .await
        .expect("the pump takes it");
    assert_eq!(received(&mut end).await, attempt);

    end.close().await.expect("closed");
    let ended = tokio::time::timeout(WATCHDOG, socket.incoming.recv())
        .await
        .expect("the pump ends");
    assert_eq!(ended, None, "the room closing the socket ends it");
}

/// A host attaches at its locator's host path, presenting the control token as unpadded
/// base64url, and frames travel both ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_presents_its_token_at_the_host_path() {
    let authority = Authority::new("rendezvous test authority");
    let room = LoopbackRoom::start(&authority).await;
    let token = token();
    let (mut socket, path, presented, mut end) =
        open_while(&authority.trusted_by(), &room, RoomRole::Host(&token)).await;
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
}

/// KR-REQ-10.27: a room whose certificate a trusted authority issued for another host name is
/// not opened: the name the origin gives is the name TLS verifies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_certificate_for_another_host_name_is_refused() {
    let authority = Authority::new("rendezvous test authority");
    let room = LoopbackRoom::start_as(&authority, "room.elsewhere.test").await;
    let connector = authority.trusted_by();
    let locator = locator();
    let (opened, handshake_failed) = tokio::time::timeout(WATCHDOG, async {
        tokio::join!(
            connector.open(&room.origin, &locator, RoomRole::Candidate),
            async {
                let (stream, _) = room.listener.accept().await.expect("a connection");
                room.acceptor.accept(stream).await.is_err()
            }
        )
    })
    .await
    .expect("the attempt ends");
    assert!(
        matches!(opened, Err(RoomError::Unreachable { .. })),
        "{opened:?}"
    );
    assert!(handshake_failed, "the handshake did not complete");
}

/// A room whose certificate no trusted authority issued is not opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_room_whose_certificate_is_not_trusted_is_refused() {
    let trusted = Authority::new("trusted authority");
    let other = Authority::new("another authority");
    let room = LoopbackRoom::start(&other).await;
    let connector = trusted.trusted_by();
    let (locator, token) = (locator(), token());
    let (opened, handshake_failed) = tokio::time::timeout(WATCHDOG, async {
        tokio::join!(
            connector.open(&room.origin, &locator, RoomRole::Host(&token)),
            async {
                let (stream, _) = room.listener.accept().await.expect("a connection");
                room.acceptor.accept(stream).await.is_err()
            }
        )
    })
    .await
    .expect("the attempt ends");
    assert!(
        matches!(opened, Err(RoomError::Unreachable { .. })),
        "{opened:?}"
    );
    assert!(handshake_failed, "the handshake did not complete");
}

/// A room nobody answers for is unreachable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_room_nobody_answers_for_is_unreachable() {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("an address").port();
    drop(listener);
    let origin = RendezvousOrigin::new(format!("https://127.0.0.1:{port}")).expect("an origin");
    let opened = tokio::time::timeout(
        WATCHDOG,
        Authority::new("rendezvous test authority")
            .trusted_by()
            .open(&origin, &locator(), RoomRole::Candidate),
    )
    .await
    .expect("the attempt ends");
    assert!(
        matches!(opened, Err(RoomError::Unreachable { .. })),
        "{opened:?}"
    );
}

/// An upgrade answered with any other status is refused with that status, whatever the body:
/// a route the origin does not have, a plain page, a refusal and a failure in front of the
/// service. What the status means for a person is the caller's to decide.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_upgrade_reports_its_status() {
    let authority = Authority::new("rendezvous test authority");
    let connector = authority.trusted_by();
    for (status, reason, body) in [
        (
            404,
            "Not Found",
            r#"{"ok":false,"error":{"code":"NOT_FOUND","message":"No."}}"#,
        ),
        (200, "OK", "<html><body>a landing page</body></html>"),
        (403, "Forbidden", "<html>Forbidden</html>"),
        (503, "Service Unavailable", "<html>Later</html>"),
    ] {
        let room = LoopbackRoom::start(&authority).await;
        let answer = format!(
            "HTTP/1.1 {status} {reason}\r\ncontent-type: text/html\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        let refused = refusal_of(&connector, &room, vec![answer.into_bytes()]).await;
        assert!(
            matches!(refused, RoomError::Refused { status: got, .. } if got == status),
            "{status}: {refused:?}"
        );
    }
}

/// An answer to the upgrade whose head never ends is refused once it reaches its bound, well
/// before the open deadline, rather than held for as long as it keeps arriving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_to_the_upgrade_that_never_ends_is_refused_at_its_bound() {
    let authority = Authority::new("rendezvous test authority");
    let room = LoopbackRoom::start(&authority).await;
    let mut answer = b"HTTP/1.1 101 Switching Protocols\r\nX-Padding: ".to_vec();
    answer.resize(answer.len() + 1024 * 1024, b'a');
    let attempted = Instant::now();
    let refused = refusal_of(&authority.trusted_by(), &room, vec![answer]).await;
    assert!(
        matches!(refused, RoomError::NotAnUpgrade { .. }),
        "{refused:?}"
    );
    let took = attempted.elapsed();
    assert!(
        took < OPEN_DEADLINE / 2,
        "refused {took:?} after the attempt began, at the bound rather than the deadline"
    );
}

/// An answer whose accept value is longer than a SHA-1 digest is refused as not an upgrade,
/// rather than the WebSocket library failing on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_accept_value_longer_than_a_digest_is_refused() {
    let authority = Authority::new("rendezvous test authority");
    let room = LoopbackRoom::start(&authority).await;
    let answer = concat!(
        "HTTP/1.1 101 Switching Protocols\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n",
        "\r\n"
    );
    let refused = refusal_of(
        &authority.trusted_by(),
        &room,
        vec![answer.as_bytes().to_vec()],
    )
    .await;
    assert!(
        matches!(refused, RoomError::NotAnUpgrade { .. }),
        "{refused:?}"
    );
}

/// Splits `answer` into pieces of `size` bytes.
fn pieces(answer: &[u8], size: usize) -> Vec<Vec<u8>> {
    answer.chunks(size).map(<[u8]>::to_vec).collect()
}

/// Blank lines in front of the status line, which the library's parser skips, do not let an
/// answer past the guard: an answer that never ends and one whose accept value is too long are
/// both refused, however their bytes arrive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blank_lines_in_front_of_an_answer_do_not_let_it_past() {
    let authority = Authority::new("rendezvous test authority");
    let mut endless = b"\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nX-Padding: ".to_vec();
    endless.resize(endless.len() + 256 * 1024, b'a');
    let long_accept = concat!(
        "\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n",
        "\r\n"
    )
    .as_bytes()
    .to_vec();
    for answer in [
        pieces(&endless, 1500),
        pieces(&long_accept, 3),
        vec![long_accept],
    ] {
        let room = LoopbackRoom::start(&authority).await;
        let attempted = Instant::now();
        let refused = refusal_of(&authority.trusted_by(), &room, answer).await;
        assert!(
            matches!(refused, RoomError::NotAnUpgrade { .. }),
            "{refused:?}"
        );
        let took = attempted.elapsed();
        assert!(
            took < OPEN_DEADLINE / 2,
            "refused {took:?} after the attempt began"
        );
    }
}

/// Sends frames until the socket takes no more, the room reading nothing.
async fn fill(socket: &mut RoomSocket) {
    let large = ClientFrame::Relay {
        attempt_id: AttemptId::new(Uuid::from_bytes([7; 16])),
        payload: Bytes::new(vec![0; MAX_FRAME_PAYLOAD_BYTES]),
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
}

/// A room that stops reading and keeps pinging ends its socket once the answers it has not taken
/// reach their bound, rather than growing the queue they wait in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_room_that_pings_without_reading_loses_its_socket() {
    let authority = Authority::new("rendezvous test authority");
    let room = LoopbackRoom::start(&authority).await;
    let (mut socket, _, _, mut end) =
        open_while(&authority.trusted_by(), &room, RoomRole::Host(&token())).await;
    fill(&mut socket).await;

    tokio::time::timeout(WATCHDOG, async {
        for _ in 0..=MAX_UNANSWERED_PINGS {
            end.send(Message::ping(vec![1, 2, 3]))
                .await
                .expect("a ping");
        }
    })
    .await
    .expect("the pings are sent");
    let ended = tokio::time::timeout(WATCHDOG, socket.incoming.recv())
        .await
        .expect("the socket ends");
    assert_eq!(ended, None, "the socket ended at the bound");
}

/// While the socket can take no more of the caller's frames, the room's frames still reach the
/// caller: neither direction waits for the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_rooms_frames_arrive_while_the_socket_can_take_no_more() {
    let authority = Authority::new("rendezvous test authority");
    let room = LoopbackRoom::start(&authority).await;
    let (mut socket, _, _, mut end) =
        open_while(&authority.trusted_by(), &room, RoomRole::Host(&token())).await;
    let attempt_id = AttemptId::new(Uuid::from_bytes([7; 16]));
    fill(&mut socket).await;

    let opened = ServiceFrame::AttemptOpened { attempt_id };
    send(&mut end, &opened).await;
    let delivered = tokio::time::timeout(Duration::from_secs(5), socket.incoming.recv())
        .await
        .expect("delivered while the caller's frames wait");
    assert_eq!(delivered, Some(opened));
}

/// A frame of the room's that the client cannot read ends the socket, rather than being passed on
/// or skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_frame_the_client_cannot_read_ends_its_socket() {
    let authority = Authority::new("rendezvous test authority");
    let room = LoopbackRoom::start(&authority).await;
    let (mut socket, _, _, mut end) =
        open_while(&authority.trusted_by(), &room, RoomRole::Candidate).await;
    end.send(Message::binary(vec![0xff, 0x00]))
        .await
        .expect("sent");
    let ended = tokio::time::timeout(WATCHDOG, socket.incoming.recv())
        .await
        .expect("the pump ends");
    assert_eq!(ended, None);
    let closing = tokio::time::timeout(WATCHDOG, end.next())
        .await
        .expect("the client lets go");
    assert!(
        !matches!(closing, Some(Ok(ref message)) if message.is_binary()),
        "nothing follows the unreadable frame but the socket's end"
    );
}

/// KR-REQ-10.27: a frame larger than a room frame may be ends the socket as soon as its header
/// declares the length, before any of its body arrives: the room here sends the header of an
/// oversized frame and nothing more, and keeps the connection open, so only the limit can end it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_frame_ends_the_socket_at_its_header() {
    let authority = Authority::new("rendezvous test authority");
    let room = LoopbackRoom::start(&authority).await;
    let (mut socket, _, _, mut end) =
        open_while(&authority.trusted_by(), &room, RoomRole::Candidate).await;
    // A final binary frame, unmasked as a server's are, whose 64-bit length is one byte more than
    // a room frame may be.
    let declared = u64::try_from(MAX_FRAME_BYTES + 1).expect("a frame length");
    let mut header = vec![0x82, 127];
    header.extend_from_slice(&declared.to_be_bytes());
    let stream = end.get_mut();
    stream
        .write_all(&header)
        .await
        .expect("the header is written");
    stream.flush().await.expect("the header is sent");
    let ended = tokio::time::timeout(Duration::from_secs(5), socket.incoming.recv())
        .await
        .expect("the socket ends at the header, without waiting for a body that never comes");
    assert_eq!(ended, None, "an oversized frame ends the socket");
}

/// A TLS failure after the handshake, while the room answers the upgrade, is the room being
/// unreachable, not an answer that is not an upgrade: the stream failing underneath says nothing
/// about what the origin serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tls_failure_during_the_upgrade_is_unreachable() {
    let authority = Authority::new("rendezvous test authority");
    let room = LoopbackRoom::start(&authority).await;
    let connector = authority.trusted_by();
    let locator = locator();
    let (opened, ()) = tokio::time::timeout(WATCHDOG, async {
        tokio::join!(
            connector.open(&room.origin, &locator, RoomRole::Candidate),
            async {
                let (stream, _) = room.listener.accept().await.expect("a connection");
                let mut stream = room.acceptor.accept(stream).await.expect("TLS");
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(stream.read_u8().await.expect("the request"));
                }
                // Bytes written past TLS, straight onto the connection: to the client they are a
                // record that fails TLS's own checks.
                let (connection, _) = stream.get_mut();
                connection
                    .write_all(b"this is not a TLS record")
                    .await
                    .expect("written");
                connection.flush().await.expect("sent");
                let _ = tokio::time::timeout(WATCHDOG, connection.read_u8()).await;
            }
        )
    })
    .await
    .expect("the attempt ends");
    assert!(
        matches!(opened, Err(RoomError::Unreachable { .. })),
        "{opened:?}"
    );
}
