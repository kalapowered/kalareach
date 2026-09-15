//! Two endpoints, one connection, and the rules section 23 puts on it.
//!
//! These tests run both sides in one process over loopback iroh, with relaying disabled in most of
//! them and a relay server running in the same process in the one that needs it. Nothing here
//! stubs the transport: every assertion is about what actually crossed a QUIC connection.

mod support;

use std::sync::Arc;
use std::time::Duration;

use iroh::Endpoint;
use iroh::endpoint::Connection;
use kr_cbor::CanonicalValue;
use kr_crypto::connect::PairedPeer;
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Request, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{StreamHeader, StreamKind, StreamResource};
use kr_protocol::hello::{
    ALPN, ClientOffer, ConnectProof, ConnectReply, HelloReply, PROTOCOL_VERSION, ProtocolVersion,
    ReceiveLimits,
};
use kr_protocol::ids::{
    AttachmentId, BuildId, ConnectionId, ControllerGeneration, EnvironmentId, RequestId, SessionId,
    TransferId,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{CanonicalSet, EndpointKey, Nullable, Uuid};
use kr_transport::clock::ManualClock;
use kr_transport::codec::{FrameReader, FrameWriter};
use kr_transport::config::EndpointConfig;
use kr_transport::error::TransportError;
use kr_transport::handshake::{self, Admitted, PairedDirectory};
use kr_transport::preauth::{self, PairingMethod, PairingSurface, PreAuthLimits};
use kr_transport::random::fresh_nonce;
use kr_transport::scheduler::{SendLimits, StreamBudget, StreamClass};
use kr_transport::streams::StreamRegistry;
use support::{
    NoDevices, OneDevice, Side, direct_addr, epochs, ledger, paired_pair, side, windows,
};
use tokio::task::JoinHandle;

/// Accepts one connection on the host and runs the handshake against a directory.
///
/// The endpoint is cloned rather than moved, so the caller's host outlives the task. An endpoint
/// that goes away mid-handshake takes the connection with it, which would make every assertion
/// below a test of drop order rather than of the protocol.
fn spawn_accept(
    host: &Side,
    directory: Arc<dyn PairedDirectory>,
    clock: ManualClock,
) -> JoinHandle<(Connection, kr_transport::Result<Admitted>)> {
    let endpoint = host.endpoint.clone();
    let identity = Arc::clone(&host.identity);
    tokio::spawn(async move {
        let connection = accept_connection(&endpoint).await;
        let challenges = ledger();
        let issuer = windows(&clock);
        let admitted = handshake::accept(
            &connection,
            &identity,
            epochs(),
            directory.as_ref(),
            &challenges,
            &issuer,
        )
        .await;
        (connection, admitted)
    })
}

async fn accept_connection(endpoint: &Endpoint) -> Connection {
    endpoint
        .accept()
        .await
        .expect("an incoming connection")
        .await
        .expect("a connection")
}

#[tokio::test]
async fn a_paired_pair_completes_the_handshake_over_loopback() {
    let (host, client) = paired_pair().await;
    let accepting = spawn_accept(&host, one_device(&client), ManualClock::new());

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");

    let (_host_connection, admitted) = accepting.await.expect("the host task");
    let Admitted::Authorised(host_side) = admitted.expect("an admitted connection") else {
        panic!("a paired endpoint is authorised");
    };

    assert_eq!(host_side.connection_id, authorised.connection_id);
    assert_eq!(host_side.transcript_digest, authorised.transcript_digest);
    assert_eq!(host_side.peer_device_id, client.record.device_id);
    assert_eq!(authorised.peer_device_id, host.record.device_id);
    assert_eq!(authorised.version(), ProtocolVersion::new(1, 0));
    assert_eq!(
        authorised.action_window.connection_id,
        authorised.connection_id
    );
    assert_eq!(authorised.action_window.valid_for_ms.get(), 300_000);
    assert_eq!(
        authorised.limits().max_control_frame_len,
        ReceiveLimits::default().max_control_frame_len
    );
}

#[tokio::test]
async fn a_connection_completes_through_a_relay_in_the_same_process() {
    let relay = support::LocalRelay::spawn().await;
    let config = EndpointConfig {
        relay_urls: vec![relay.url.clone()],
        relay_ca_roots: relay.ca_roots.clone(),
        bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
        ..EndpointConfig::default()
    };
    assert_eq!(config.relay_map().len(), 1);

    let host = side(&config, 1, true).await;
    let client = side(&config, 2, false).await;
    // Both endpoints have to reach the relay before either can be dialled through it.
    tokio::time::timeout(Duration::from_secs(20), host.endpoint.online())
        .await
        .expect("the host reached its home relay");
    tokio::time::timeout(Duration::from_secs(20), client.endpoint.online())
        .await
        .expect("the client reached its home relay");

    let accepting = spawn_accept(&host, one_device(&client), ManualClock::new());

    // Dial by relay only: the address carries no direct addresses, so a completed handshake proves
    // the relay carried it.
    let relay = host
        .endpoint
        .addr()
        .relay_urls()
        .next()
        .cloned()
        .expect("the host has a home relay");
    let host_addr = iroh::EndpointAddr::new(host.endpoint.id()).with_relay_url(relay);

    let connection = client
        .endpoint
        .connect(host_addr, ALPN)
        .await
        .expect("a connection");
    let authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");
    assert_eq!(authorised.version(), ProtocolVersion::new(1, 0));

    let (_connection, admitted) = accepting.await.expect("the host task");
    assert!(matches!(
        admitted.expect("an admitted connection"),
        Admitted::Authorised(_)
    ));
}

#[tokio::test]
async fn an_offer_with_no_shared_major_is_refused_as_an_unsupported_schema() {
    let (host, mut client) = paired_pair().await;
    Arc::get_mut(&mut client.identity)
        .expect("the identity is not shared yet")
        .supported_versions = vec![ProtocolVersion::new(2, 0)];
    let accepting = spawn_accept(&host, one_device(&client), ManualClock::new());

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let error = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect_err("a refusal");
    let TransportError::Handshake(error) = error else {
        panic!("a version mismatch is a handshake refusal, not {error}");
    };
    assert_eq!(error.code, ErrorCode::UnsupportedSchema);

    let (_connection, admitted) = accepting.await.expect("the host task");
    assert!(admitted.is_err(), "the host refused too");
}

#[tokio::test]
async fn a_send_queue_too_small_for_a_transfer_is_refused_at_hello() {
    // A connection that could never be handed an attachment frame is not established. Both sides
    // reach that conclusion: the host refuses the offer and the client refuses the selection.
    let (host, mut client) = paired_pair().await;
    Arc::get_mut(&mut client.identity)
        .expect("the identity is not shared yet")
        .max_receive = ReceiveLimits {
        max_send_queue_bytes: kr_protocol::scalars::U64::new(
            kr_transport::scheduler::MIN_SEND_QUEUE_BYTES as u64 - 1,
        ),
        ..ReceiveLimits::default()
    };
    let accepting = spawn_accept(&host, one_device(&client), ManualClock::new());

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let error = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect_err("a refusal");
    let TransportError::Handshake(error) = error else {
        panic!("an unusable send queue is a handshake refusal, not {error}");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);

    let (_connection, admitted) = accepting.await.expect("the host task");
    assert!(admitted.is_err(), "the host refused too");
}

#[tokio::test]
async fn a_peer_that_cannot_prove_the_paired_key_is_refused() {
    let (host, client) = paired_pair().await;
    // The right endpoint, another device's authorisation key: a stale or substituted record.
    let impostor = kr_crypto::keys::DeviceKeys::generate().expect("device keys");
    let directory: Arc<dyn PairedDirectory> = Arc::new(OneDevice {
        endpoint_id: client.record.endpoint_id,
        record: PairedPeer {
            authorisation: *impostor.authorisation.public(),
            ..client.record
        },
    });
    let accepting = spawn_accept(&host, directory, ManualClock::new());

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let error = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect_err("a refusal");
    let TransportError::Handshake(error) = error else {
        panic!("a failed proof is a handshake refusal, not {error}");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);

    let (_connection, admitted) = accepting.await.expect("the host task");
    assert!(admitted.is_err(), "the host refused the proof");
}

#[tokio::test]
async fn a_replayed_proof_is_refused_on_a_second_connection() {
    let (host, client) = paired_pair().await;
    let directory = one_device(&client);
    let clock = ManualClock::new();
    let challenges = ledger();
    let issuer = windows(&clock);
    let endpoint = host.endpoint.clone();
    let identity = Arc::clone(&host.identity);

    // One challenge ledger across both connections, which is how a host holds them.
    let accepting = tokio::spawn(async move {
        let mut outcomes = Vec::new();
        // The connections are kept: dropping one closes it, and the client is still reading the
        // reply the host just wrote.
        let mut held = Vec::new();
        for _ in 0..2u8 {
            let connection = accept_connection(&endpoint).await;
            let admitted = handshake::accept(
                &connection,
                &identity,
                epochs(),
                directory.as_ref(),
                &challenges,
                &issuer,
            )
            .await;
            outcomes.push(admitted.is_ok());
            held.push((connection, admitted));
        }
        (outcomes, held)
    });

    // The first connection is a complete handshake, run by hand so the proof can be kept.
    let first = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let host_endpoint_id = EndpointKey::from_bytes(*first.remote_id().as_bytes());
    let (mut writer, mut reader) = control_streams(&first).await;
    let client_offer = offer(&client);
    writer.write_message(&client_offer).await.expect("sent");
    let HelloReply::Selected(selection) = read_frame::<HelloReply>(&mut reader).await else {
        panic!("the first offer is selected");
    };
    let proof = ConnectProof {
        signature: kr_crypto::connect::sign_connect(
            &client.keys.authorisation,
            &client_offer,
            &selection,
            &client.record.endpoint_id,
            &host_endpoint_id,
        )
        .expect("a proof"),
    };
    writer.write_message(&proof).await.expect("sent");
    assert!(matches!(
        read_frame::<ConnectReply>(&mut reader).await,
        ConnectReply::Accepted(_)
    ));

    // The second connection replays the exact offer and the exact proof. The host answers with a
    // fresh challenge, so the replayed signature covers a transcript that is not this connection's.
    let second = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let (mut writer, mut reader) = control_streams(&second).await;
    writer.write_message(&client_offer).await.expect("sent");
    let HelloReply::Selected(fresh) = read_frame::<HelloReply>(&mut reader).await else {
        panic!("the replayed offer is still selected");
    };
    assert_ne!(
        fresh.host_nonce, selection.host_nonce,
        "every connection issues its own challenge"
    );
    writer.write_message(&proof).await.expect("sent");
    let ConnectReply::Refused(error) = read_frame::<ConnectReply>(&mut reader).await else {
        panic!("a replayed proof is refused");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);

    let (outcomes, _held) = accepting.await.expect("the host task");
    assert_eq!(outcomes, vec![true, false]);
}

/// A pairing surface that records what it was asked and answers nothing else.
///
/// A real host drives `kr-pairing`'s invitation state machines from here, passing the peer straight
/// through as their `LivePeer`. This records what the transport handed it, which is the part the
/// transport owes the ceremony.
#[derive(Debug, Default)]
struct RecordingSurface {
    calls: std::sync::Mutex<Vec<PairingMethod>>,
    peers: std::sync::Mutex<Vec<(EndpointKey, bool)>>,
}

impl RecordingSurface {
    fn calls(&self) -> Vec<PairingMethod> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn peers(&self) -> Vec<(EndpointKey, bool)> {
        self.peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl PairingSurface for RecordingSurface {
    fn call(
        &self,
        method: PairingMethod,
        peer: &kr_transport::preauth::ConnectionPeer,
        _params: &ParamsValue,
    ) -> Result<ParamsValue, ProtocolError> {
        // The pairing crate's own rule, applied through its own contract: no pairing mutation in
        // early data. A real host passes the peer straight to its invitation state machine.
        if kr_pairing::platform::require_completed_handshake(peer).is_err()
            && method != PairingMethod::Status
        {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "no mutation is accepted in 0-RTT",
            ));
        }
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(method);
        self.peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((
                kr_pairing::platform::LivePeer::live_endpoint(peer).expect("an authenticated peer"),
                kr_pairing::platform::LivePeer::arrived_in_early_data(peer),
            ));
        Ok(ParamsValue::empty())
    }
}

/// Serves the pre-authorisation surface for one unpaired connection.
fn spawn_preauth(
    host: &Side,
    surface: Arc<RecordingSurface>,
    limits: PreAuthLimits,
    clock: ManualClock,
) -> JoinHandle<()> {
    let endpoint = host.endpoint.clone();
    let identity = Arc::clone(&host.identity);
    tokio::spawn(async move {
        let connection = accept_connection(&endpoint).await;
        let challenges = ledger();
        let issuer = windows(&clock);
        let admitted = handshake::accept(
            &connection,
            &identity,
            epochs(),
            &NoDevices,
            &challenges,
            &issuer,
        )
        .await
        .expect("an admitted connection");
        let Admitted::Unpaired(mut unpaired) = admitted else {
            panic!("an unknown endpoint is unpaired");
        };
        let _ = preauth::serve(
            &mut unpaired,
            surface.as_ref(),
            limits,
            &clock,
            ControllerGeneration::new(1),
        )
        .await;
        // The exchange is over, but the connection stays until the peer goes away: dropping it
        // here would discard the answer the client has not read yet.
        let _ = connection.closed().await;
    })
}

#[tokio::test]
async fn an_unpaired_endpoint_reaches_only_the_pairing_surface() {
    let (host, client) = paired_pair().await;
    let surface = Arc::new(RecordingSurface::default());
    let serving = spawn_preauth(
        &host,
        Arc::clone(&surface),
        PreAuthLimits::default(),
        ManualClock::new(),
    );

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let (mut writer, mut reader) = control_streams(&connection).await;

    // hello is answered: an unpaired peer still negotiates framing and version.
    writer.write_message(&offer(&client)).await.expect("sent");
    assert!(matches!(
        read_frame::<HelloReply>(&mut reader).await,
        HelloReply::Selected(_)
    ));

    // A pairing read is served.
    writer
        .write_message(&request(Method::PairStatus, 1))
        .await
        .expect("sent");
    let response = read_frame::<Response>(&mut reader).await;
    assert!(matches!(response.outcome, Outcome::Ok(_)));

    // An ordinary session method is not.
    writer
        .write_message(&request(Method::SessionList, 2))
        .await
        .expect("sent");
    let response = read_frame::<Response>(&mut reader).await;
    let Outcome::Error(error) = response.outcome else {
        panic!("session.list is not reachable before pairing");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);

    assert_eq!(
        surface.calls(),
        vec![PairingMethod::Status],
        "only the pairing read reached the surface"
    );
    // What the transport owes the pairing ceremony: the authenticated endpoint on the other end of
    // this connection, and whether the step arrived as early data. The ceremony checks the live
    // peer against the authenticated bundle and refuses a mutation in 0-RTT from these two answers.
    assert_eq!(
        surface.peers(),
        vec![(client.record.endpoint_id, false)],
        "the surface saw the authenticated peer this connection belongs to"
    );

    connection.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(Duration::from_secs(5), serving).await;
}

#[tokio::test]
async fn an_unpaired_connection_runs_out_of_pairing_requests() {
    let (host, client) = paired_pair().await;
    let limits = PreAuthLimits {
        max_requests: 2,
        max_requests_per_window: 2,
        window: Duration::from_secs(10),
        max_frame_len: preauth::MAX_PREAUTH_FRAME_LEN,
    };
    let serving = spawn_preauth(
        &host,
        Arc::new(RecordingSurface::default()),
        limits,
        ManualClock::new(),
    );

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let (mut writer, mut reader) = control_streams(&connection).await;
    writer.write_message(&offer(&client)).await.expect("sent");
    let _ = read_frame::<HelloReply>(&mut reader).await;

    let mut codes = Vec::new();
    for index in 0..3u64 {
        writer
            .write_message(&request(Method::PairStatus, index + 1))
            .await
            .expect("sent");
        codes.push(match read_frame::<Response>(&mut reader).await.outcome {
            Outcome::Ok(_) => None,
            Outcome::Error(error) => Some(error.code),
        });
    }
    assert_eq!(codes[0], None);
    assert_eq!(codes[1], None);
    assert_eq!(
        codes[2],
        Some(ErrorCode::RateLimited),
        "the third request is past the budget"
    );

    connection.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(Duration::from_secs(5), serving).await;
}

#[tokio::test]
async fn a_data_stream_does_not_survive_the_control_stream() {
    let (host, client) = paired_pair().await;
    let accepting = spawn_accept(&host, one_device(&client), ManualClock::new());

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");
    let client_registry = registry(authorised.connection_id, SendLimits::default());
    let mut client_stream = client_registry
        .open(&connection, terminal_header(authorised.connection_id))
        .await
        .expect("a data stream");

    let (host_connection, admitted) = accepting.await.expect("the host task");
    let Admitted::Authorised(host_side) = admitted.expect("an admitted connection") else {
        panic!("a paired endpoint is authorised");
    };
    let host_registry = registry(host_side.connection_id, SendLimits::default());
    let mut host_stream = host_registry
        .accept(&host_connection)
        .await
        .expect("a data stream");
    assert_eq!(host_stream.kind(), StreamKind::TerminalOutput);
    assert!(!host_stream.is_revoked());

    // A read that is already waiting on the host's side of the stream must wake as soon as the
    // stream is revoked, not when a peer that will never send finally sends.
    let waiting_handle = host_stream.handle();
    let waiting = tokio::spawn(async move {
        let outcome = host_stream.read_payload().await;
        (host_stream, outcome)
    });
    tokio::task::yield_now().await;

    // The control stream ends, and with it every data stream it authorised. Nothing else is done
    // to the stream: revocation alone has to be enough.
    drop(host_side);
    host_registry.revoke_all();
    assert!(waiting_handle.is_revoked());

    let (host_stream, outcome) = tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("the waiting read woke")
        .expect("the task finished");
    assert!(
        matches!(outcome, Err(TransportError::ControlLost)),
        "a revoked stream stops carrying data"
    );
    // Dropping the revoked stream resets it, so the peer sees that it was taken away rather than a
    // clean end of data.
    drop(host_stream);
    assert!(host_registry.is_empty());

    match tokio::time::timeout(Duration::from_secs(10), client_stream.read_payload()).await {
        Ok(Ok(None)) | Ok(Err(_)) => {}
        Ok(Ok(Some(_))) => panic!("a revoked stream delivered a frame"),
        Err(_) => panic!("a revoked stream left the peer waiting"),
    }
}

#[tokio::test]
async fn a_connection_admits_no_more_bulk_streams_than_it_allows() {
    let (host, client) = paired_pair().await;
    let accepting = spawn_accept(&host, one_device(&client), ManualClock::new());

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");
    let registry = registry(
        authorised.connection_id,
        SendLimits {
            max_bulk_streams: 2,
            max_bulk_queued_bytes: 1024,
            max_queued_bytes: 4096,
        },
    );

    let first = registry
        .open(&connection, attachment_header(authorised.connection_id, 1))
        .await
        .expect("the first transfer");
    let _second = registry
        .open(&connection, attachment_header(authorised.connection_id, 2))
        .await
        .expect("the second transfer");
    let error = registry
        .open(&connection, attachment_header(authorised.connection_id, 3))
        .await
        .expect_err("the third is refused");
    assert!(matches!(
        error,
        TransportError::LimitExceeded {
            what: "concurrent bulk streams",
            limit: 2
        }
    ));

    // An interactive stream is not a bulk stream and is not held to the bulk ceiling.
    let _terminal = registry
        .open(&connection, terminal_header(authorised.connection_id))
        .await
        .expect("a terminal stream");

    // Ending a transfer frees its slot.
    drop(first);
    let _third = registry
        .open(&connection, attachment_header(authorised.connection_id, 3))
        .await
        .expect("a freed slot is reusable");

    let _ = accepting.await.expect("the host task");
}

#[tokio::test]
async fn an_empty_frame_is_refused_before_it_damages_the_stream() {
    // A zero length is what the peer's decoder reads as a malformed frame, so a caller that asks
    // for an empty frame gets a local error and the stream carries on.
    let (host, client) = paired_pair().await;
    let accepting = spawn_accept(&host, one_device(&client), ManualClock::new());

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");
    let client_registry = registry(authorised.connection_id, SendLimits::default());
    let mut client_stream = client_registry
        .open(&connection, terminal_header(authorised.connection_id))
        .await
        .expect("a data stream");

    let (host_connection, admitted) = accepting.await.expect("the host task");
    let Admitted::Authorised(host_side) = admitted.expect("an admitted connection") else {
        panic!("a paired endpoint is authorised");
    };
    let host_registry = registry(host_side.connection_id, SendLimits::default());
    let mut host_stream = host_registry
        .accept(&host_connection)
        .await
        .expect("a data stream");

    let error = client_stream
        .write_payload(&[])
        .await
        .expect_err("an empty frame is refused");
    assert!(
        matches!(
            error,
            TransportError::Frame(kr_protocol::frame::FrameError::EmptyPayload)
        ),
        "an empty frame is a framing error, not a stream failure: {error:?}"
    );

    // Nothing reached the connection, so the next frame is read as itself.
    client_stream
        .write_payload(b"still usable")
        .await
        .expect("the stream was not damaged");
    let delivered = tokio::time::timeout(Duration::from_secs(10), host_stream.read_payload())
        .await
        .expect("the frame arrived")
        .expect("a frame")
        .expect("the stream did not end");
    assert_eq!(delivered, b"still usable");
    drop(host_side);
}

#[tokio::test]
async fn every_stream_class_is_charged_against_the_connection_send_budget() {
    // A terminal stream is interactive, not bulk, and it is still held to what the peer said it
    // would accept: a write past the whole-connection ceiling is refused before anything is sent.
    let (host, client) = paired_pair().await;
    let accepting = spawn_accept(&host, one_device(&client), ManualClock::new());

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");
    let registry = registry(
        authorised.connection_id,
        SendLimits {
            max_bulk_streams: 4,
            max_bulk_queued_bytes: 1024,
            max_queued_bytes: 2048,
        },
    );
    let mut stream = registry
        .open(&connection, terminal_header(authorised.connection_id))
        .await
        .expect("a terminal stream");

    let error = stream
        .write_payload(&vec![0u8; 4096])
        .await
        .expect_err("a write past the connection ceiling is refused");
    assert!(
        matches!(
            error,
            TransportError::LimitExceeded {
                what: "queued bytes",
                limit: 2048
            }
        ),
        "{error:?}"
    );
    // The refusal charged nothing, so a write inside the ceiling still goes out.
    assert_eq!(registry.budget().queued_bytes(), 0);
    stream
        .write_payload(b"inside the ceiling")
        .await
        .expect("a write inside the ceiling");
    assert_eq!(registry.budget().queued_bytes(), 0);

    let _ = accepting.await.expect("the host task");
}

#[tokio::test]
async fn a_message_is_bounded_by_the_ceiling_it_will_be_charged_against() {
    // A message is encoded under the smallest bound that applies, so a frame the budget would
    // always refuse never reaches the connection; and a message that does fit is admitted on what
    // it actually encodes to, not on what its stream kind allows.
    let (host, client) = paired_pair().await;
    let accepting = spawn_accept(&host, one_device(&client), ManualClock::new());

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");
    let registry = registry(
        authorised.connection_id,
        SendLimits {
            max_bulk_streams: 4,
            max_bulk_queued_bytes: 1024,
            max_queued_bytes: 2048,
        },
    );
    let mut stream = registry
        .open(&connection, terminal_header(authorised.connection_id))
        .await
        .expect("a terminal stream");

    // The stream kind allows a 1 MiB frame; this connection would never admit one.
    let error = stream
        .write_message(&ParamsValue::new(CanonicalValue::bytes(vec![0u8; 4096])))
        .await
        .expect_err("a frame the budget could never admit is refused");
    assert!(
        matches!(error, TransportError::Frame(_)),
        "an unadmittable frame is refused as too large rather than sent: {error:?}"
    );
    assert_eq!(registry.budget().queued_bytes(), 0);

    // A small message is charged for what it encodes to, so it goes out even with most of the
    // ceiling already spoken for.
    let held = registry
        .budget()
        .reserve(StreamClass::Live, 2000)
        .expect("another write holding most of the ceiling");
    stream
        .write_message(&ParamsValue::new(CanonicalValue::bytes(b"hi".to_vec())))
        .await
        .expect("a small message fits what is left");
    drop(held);
    assert_eq!(registry.budget().queued_bytes(), 0);

    let _ = accepting.await.expect("the host task");
}

#[tokio::test]
async fn a_stream_header_from_another_connection_is_refused() {
    let (host, client) = paired_pair().await;
    let accepting = spawn_accept(&host, one_device(&client), ManualClock::new());

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let _authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");

    let (host_connection, admitted) = accepting.await.expect("the host task");
    let Admitted::Authorised(host_side) = admitted.expect("an admitted connection") else {
        panic!("a paired endpoint is authorised");
    };
    let host_registry = registry(host_side.connection_id, SendLimits::default());

    // A header that names a connection identity the host never allocated.
    let forged = ConnectionId::new(Uuid::from_bytes([0xaa; 16]));
    let (send, _recv) = connection.open_bi().await.expect("a stream");
    let mut writer = FrameWriter::new(send, StreamKind::TerminalOutput);
    writer
        .write_header(&terminal_header(forged))
        .await
        .expect("the header was sent");

    let error = host_registry
        .accept(&host_connection)
        .await
        .expect_err("a header for another connection is refused");
    assert!(matches!(error, TransportError::Handshake(_)));
}

#[tokio::test]
async fn no_mutation_is_admitted_before_the_connection_is_authorised() {
    // KR-ACC-026: version 1 accepts no application mutation in QUIC 0-RTT. The host never enters
    // iroh's 0-RTT acceptance path, so nothing a client sends as early data reaches the
    // application until the QUIC handshake has completed and the peer's endpoint identity is
    // authenticated. On top of that, the only frame the host will read between `hello` and
    // authorisation is the connection proof: a mutation sent in that window is refused and the
    // connection is never authorised.
    let (host, client) = paired_pair().await;
    let first = spawn_accept(&host, one_device(&client), ManualClock::new());

    // A complete connection first, so the client holds a TLS ticket and can offer 0-RTT.
    let warm = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let _authorised = handshake::connect(&warm, &client.identity, &host.record)
        .await
        .expect("an authorised connection");
    let _ = first.await.expect("the host task");
    warm.close(0u32.into(), b"done");

    let second = spawn_accept(&host, one_device(&client), ManualClock::new());
    let connecting = client
        .endpoint
        .connect_with_opts(
            direct_addr(&host),
            ALPN,
            iroh::endpoint::ConnectOptions::new(),
        )
        .await
        .expect("a connection attempt");

    // Offer 0-RTT where the session allows it, and fall back to an ordinary connection otherwise.
    // Either way the frames below are sent as early as this client can send them.
    let (mut writer, mut reader) = match connecting.into_0rtt() {
        Ok(zero_rtt) => {
            let streams = control_streams(&zero_rtt).await;
            let _ = zero_rtt.handshake_completed().await;
            streams
        }
        Err(connecting) => {
            let connection = connecting.await.expect("a connection");
            control_streams(&connection).await
        }
    };

    writer.write_message(&offer(&client)).await.expect("sent");
    assert!(matches!(
        read_frame::<HelloReply>(&mut reader).await,
        HelloReply::Selected(_)
    ));

    // A mutation in place of the connection proof. The host is not authorised to run it and has
    // not asked for it.
    writer
        .write_message(&mutation(Method::SessionCreate))
        .await
        .expect("sent");

    let (_connection, admitted) = second.await.expect("the host task");
    assert!(
        admitted.is_err(),
        "a mutation never authorises a connection"
    );
}

#[tokio::test]
async fn a_control_frame_carries_every_shape_the_stream_uses() {
    // The control stream's union is closed, so a receiver never has to guess. This checks the
    // round trip through the canonical encoding, which is where a new variant would break first.
    let frame = ControlFrame::Request(request(Method::SessionList, 1));
    let bytes = kr_cbor::to_canonical_vec(&frame).expect("canonical bytes");
    let decoded: ControlFrame =
        kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("a frame");
    assert_eq!(decoded, frame);
}

fn one_device(client: &Side) -> Arc<dyn PairedDirectory> {
    Arc::new(OneDevice {
        endpoint_id: client.record.endpoint_id,
        record: client.record,
    })
}

fn registry(connection_id: ConnectionId, limits: SendLimits) -> Arc<StreamRegistry> {
    Arc::new(StreamRegistry::new(
        connection_id,
        Arc::new(StreamBudget::new(limits)),
        None,
    ))
}

async fn control_streams<S: iroh::endpoint::ConnectionState>(
    connection: &iroh::endpoint::Connection<S>,
) -> (FrameWriter, FrameReader) {
    let (send, recv) = connection.open_bi().await.expect("a stream");
    (
        FrameWriter::new(send, StreamKind::Control),
        FrameReader::new(recv, StreamKind::Control),
    )
}

async fn read_frame<T: serde::de::DeserializeOwned + serde::Serialize>(
    reader: &mut FrameReader,
) -> T {
    reader
        .read_message()
        .await
        .expect("a frame")
        .expect("the stream did not end")
}

fn offer(client: &Side) -> ClientOffer {
    ClientOffer {
        offered_versions: vec![PROTOCOL_VERSION],
        build_id: BuildId::new("kr/0.1.0+test").expect("a build identity"),
        device_id: client.record.device_id,
        device_key_revision: client.record.device_key_revision,
        capabilities: CanonicalSet::new(),
        max_receive: ReceiveLimits::default(),
        client_nonce: fresh_nonce().expect("a nonce"),
    }
}

fn mutation(method: Method) -> kr_protocol::envelope::MutationRequest {
    kr_protocol::envelope::MutationRequest {
        request_id: RequestId::new(99),
        method: method.into(),
        method_version: MethodVersion::V1,
        action_id: kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x11; 16])),
        grant_id: Nullable::null(),
        target: kr_protocol::envelope::ActionTarget::environment(EnvironmentId::new(
            Uuid::from_bytes([9; 16]),
        )),
        expected: ParamsValue::empty(),
        action_window_id: kr_protocol::ids::ActionWindowId::new("forged").expect("an identifier"),
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(120_000),
        params: ParamsValue::empty(),
    }
}

fn request(method: Method, id: u64) -> Request {
    Request {
        request_id: RequestId::new(id),
        method: method.into(),
        method_version: MethodVersion::V1,
        params: ParamsValue::empty(),
    }
}

fn terminal_header(connection_id: ConnectionId) -> StreamHeader {
    StreamHeader {
        kind: StreamKind::TerminalOutput,
        connection_id,
        stream_id: Nullable::null(),
        resource: StreamResource {
            environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
            session_id: Nullable::some(SessionId::new(Uuid::from_bytes([8; 16]))),
            attachment_id: Nullable::some(AttachmentId::new(Uuid::from_bytes([7; 16]))),
            transfer_id: Nullable::null(),
        },
    }
}

fn attachment_header(connection_id: ConnectionId, transfer: u8) -> StreamHeader {
    StreamHeader {
        kind: StreamKind::AttachmentChunks,
        connection_id,
        stream_id: Nullable::null(),
        resource: StreamResource {
            environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
            session_id: Nullable::null(),
            attachment_id: Nullable::null(),
            transfer_id: Nullable::some(TransferId::new(Uuid::from_bytes([transfer; 16]))),
        },
    }
}
