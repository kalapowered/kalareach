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
use kr_crypto::connect::{PairedPeer, sign_connect};
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Request, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::extension::{
    self, ExtensionDefinition, ExtensionId, ExtensionOffers, MemberBlock,
};
use kr_protocol::frame::{StreamHeader, StreamKind, StreamResource};
use kr_protocol::hello::{
    ALPN, ActionWindow, ClientOffer, ConnectAccepted, ConnectProof, ConnectReply, HelloReply,
    HostSelection, PROTOCOL_VERSION, ProtocolVersion, ReceiveLimits,
};
use kr_protocol::ids::{
    ActionWindowId, AttachmentId, BuildId, ConnectionId, ControllerGeneration, EnvironmentId,
    RequestId, SessionId, TransferId,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{CanonicalSet, DurationMs, EndpointKey, Nullable, TimestampMs, Uuid};
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

/// KR-REQ-23.09, KR-REQ-23.13: over the stable `kalareach` ALPN the first bidirectional stream
/// carries hello and device authorisation, and hello carries its full contents in both directions.
#[tokio::test]
async fn a_paired_pair_completes_the_handshake_over_loopback() {
    // KR-REQ-04.06: the transport is iroh: two endpoints complete an authenticated, encrypted
    // connection over a direct path.
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

    // hello, in both directions. The host received the client's complete offer, and the client
    // received the host's complete selection.
    assert_eq!(host_side.offer, authorised.offer);
    assert_eq!(host_side.selection, authorised.selection);
    let offer = &authorised.offer;
    assert_eq!(offer.offered_versions, client.identity.supported_versions);
    assert_eq!(offer.build_id, client.identity.build_id);
    assert_eq!(offer.device_id, client.record.device_id);
    assert_eq!(offer.device_key_revision, client.record.device_key_revision);
    assert_eq!(offer.capabilities, client.identity.capabilities);
    assert_eq!(offer.max_receive, client.identity.max_receive);
    let selection = &authorised.selection;
    assert_eq!(
        selection.client_nonce, offer.client_nonce,
        "the selection answers this offer"
    );
    assert_ne!(
        selection.host_nonce, offer.client_nonce,
        "the host brings a nonce of its own"
    );
    assert_eq!(selection.connection_id, authorised.connection_id);
    assert_eq!(selection.selected_version, ProtocolVersion::new(1, 0));
    assert_eq!(selection.limits, authorised.limits());
    assert_eq!(selection.endpoint_id, host.record.endpoint_id);
    assert_eq!(selection.device_id, host.record.device_id);
    assert_eq!(
        selection.device_key_revision,
        host.record.device_key_revision
    );
    assert_eq!(selection.boot_epoch, epochs().boot_epoch);
    assert_eq!(selection.clock_epoch, epochs().clock_epoch);
}

/// KR-REQ-10.02: the relay path works through a relay whose certificate chains to an explicitly
/// added trust anchor, dialled by relay alone.
#[tokio::test]
async fn a_connection_completes_through_a_relay_in_the_same_process() {
    // KR-REQ-04.06: iroh's relay transport carries the same authorised connection.
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

/// KR-REQ-10.02: altered certificate trust is refused. Two clients dial one host through one relay
/// that the host accepts every connection from: the client that trusts the relay's own anchor
/// reaches it and connects, and the client that trusts only the public roots never reaches the
/// relay and is carried nowhere, in a window longer than the trusting client needed. Dialled with
/// each client's own TLS configuration, the relay's handshake fails certificate validation for the
/// second and completes for the first, so the certificate is what refuses it.
#[tokio::test]
async fn a_relay_whose_certificate_nothing_trusts_is_never_used() {
    let relay = support::LocalRelay::spawn().await;
    let loopback = Some("127.0.0.1:0".parse().expect("a loopback address"));
    let trusting = EndpointConfig {
        relay_urls: vec![relay.url.clone()],
        relay_ca_roots: relay.ca_roots.clone(),
        bind_addr: loopback,
        ..EndpointConfig::default()
    };
    let untrusting = EndpointConfig {
        relay_urls: vec![relay.url.clone()],
        bind_addr: loopback,
        ..EndpointConfig::default()
    };
    let host = side(&trusting, 1, true).await;
    let trusted = side(&trusting, 2, false).await;
    let untrusted = side(&untrusting, 3, false).await;
    tokio::time::timeout(Duration::from_secs(20), host.endpoint.online())
        .await
        .expect("the host reached the relay it trusts");
    tokio::time::timeout(Duration::from_secs(20), trusted.endpoint.online())
        .await
        .expect("a client that trusts the relay's anchor reaches it");

    // The host takes every connection that reaches it, so a connection that is missing below was
    // never carried rather than refused by the host.
    let endpoint = host.endpoint.clone();
    let arrivals = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = Arc::clone(&arrivals);
    let accepting = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(incoming) = endpoint.accept().await {
            let Ok(connection) = incoming.await else {
                continue;
            };
            recorded
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(connection.remote_id());
            held.push(connection);
        }
    });

    let relay_url = host
        .endpoint
        .addr()
        .relay_urls()
        .next()
        .cloned()
        .expect("the host has a home relay");
    let host_addr = iroh::EndpointAddr::new(host.endpoint.id()).with_relay_url(relay_url);
    let _trusted_connection = tokio::time::timeout(
        Duration::from_secs(20),
        trusted.endpoint.connect(host_addr.clone(), ALPN),
    )
    .await
    .expect("the trusting client connects in time")
    .expect("the trusting client connects through the relay");

    let (online, attempt) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(20), untrusted.endpoint.online()),
        tokio::time::timeout(
            Duration::from_secs(20),
            untrusted.endpoint.connect(host_addr, ALPN)
        ),
    );
    assert!(
        online.is_err(),
        "a client that does not trust the relay's certificate never reaches it"
    );
    assert!(
        !matches!(attempt, Ok(Ok(_))),
        "nothing is carried through a relay the client does not trust"
    );
    let arrived = arrivals
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(
        arrived,
        vec![trusted.endpoint.id()],
        "only the trusting client's connection reached the host"
    );
    accepting.abort();

    // The TLS configuration each endpoint dials relays with, used for one relay handshake each.
    let dial = |endpoint: &iroh::Endpoint| {
        iroh_relay::client::ClientBuilder::new(
            relay.url.clone(),
            iroh::SecretKey::generate(),
            iroh::dns::DnsResolver::new(),
        )
        .tls_client_config(endpoint.tls_config().clone())
    };
    let completed = dial(&trusted.endpoint).connect().await;
    assert!(
        completed.is_ok(),
        "the trusting configuration completes the relay handshake: {:?}",
        completed.err()
    );
    let Err(refusal) = dial(&untrusted.endpoint).connect().await else {
        panic!("the relay handshake completed without its anchor");
    };
    let iroh_relay::client::ConnectError::Tls { source, .. } = &refusal else {
        panic!("the relay handshake failed for another reason: {refusal:?}");
    };
    let reason = source
        .get_ref()
        .map(ToString::to_string)
        .unwrap_or_default();
    assert!(
        reason.contains("invalid peer certificate") && reason.contains("UnknownIssuer"),
        "the relay handshake failed certificate validation: {reason}"
    );
}

/// KR-REQ-23.13: a major mismatch is refused as UNSUPPORTED_SCHEMA before any session data.
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
    let TransportError::Refused(error) = error else {
        panic!("a version mismatch is the host's refusal, not {error}");
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
    let TransportError::Refused(error) = error else {
        panic!("an unusable send queue is the host's refusal, not {error}");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);

    let (_connection, admitted) = accepting.await.expect("the host task");
    assert!(admitted.is_err(), "the host refused too");
}

/// KR-REQ-23.16: a stale or substituted paired key cannot complete the connection proof.
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
    let TransportError::Refused(error) = error else {
        panic!("a failed proof is the host's refusal, not {error}");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);

    let (_connection, admitted) = accepting.await.expect("the host task");
    assert!(admitted.is_err(), "the host refused the proof");
}

/// KR-REQ-23.16: a proof replayed on another connection answers a challenge that connection never
/// issued, and is refused.
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

/// KR-REQ-23.16: a proof signed over a transcript the host did not issue, here its selection with
/// the limits lowered as a party in the middle would present them, is refused, and the connection
/// is never authorised.
#[tokio::test]
async fn a_proof_over_a_downgraded_selection_is_refused() {
    let (host, client) = paired_pair().await;
    let accepting = spawn_accept(&host, one_device(&client), ManualClock::new());

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let host_endpoint_id = EndpointKey::from_bytes(*connection.remote_id().as_bytes());
    let (mut writer, mut reader) = control_streams(&connection).await;
    let client_offer = offer(&client);
    writer.write_message(&client_offer).await.expect("sent");
    let HelloReply::Selected(selection) = read_frame::<HelloReply>(&mut reader).await else {
        panic!("the offer is selected");
    };

    let mut downgraded = (*selection).clone();
    downgraded.limits.max_control_frame_len = kr_protocol::scalars::U64::new(1024);
    let proof = ConnectProof {
        signature: kr_crypto::connect::sign_connect(
            &client.keys.authorisation,
            &client_offer,
            &downgraded,
            &client.record.endpoint_id,
            &host_endpoint_id,
        )
        .expect("a proof"),
    };
    writer.write_message(&proof).await.expect("sent");
    let ConnectReply::Refused(error) = read_frame::<ConnectReply>(&mut reader).await else {
        panic!("a proof over a downgraded transcript is refused");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);

    let (_connection, admitted) = accepting.await.expect("the host task");
    assert!(admitted.is_err(), "the connection was never authorised");
}

/// KR-REQ-23.22: a reconnect is a new connection. The host gives a second connection from the
/// same client a new connection identity, new nonces, a new action window and a new transcript.
#[tokio::test]
async fn a_reconnect_is_a_new_connection_identity() {
    let (host, client) = paired_pair().await;
    let mut authorised = Vec::new();
    for _ in 0..2 {
        let accepting = spawn_accept(&host, one_device(&client), ManualClock::new());
        let connection = client
            .endpoint
            .connect(direct_addr(&host), ALPN)
            .await
            .expect("a connection");
        authorised.push(
            handshake::connect(&connection, &client.identity, &host.record)
                .await
                .expect("an authorised connection"),
        );
        let _ = accepting.await.expect("the host task");
        connection.close(0u32.into(), b"reconnecting");
    }
    let (first, second) = (&authorised[0], &authorised[1]);
    assert_ne!(first.connection_id, second.connection_id);
    assert_ne!(first.offer.client_nonce, second.offer.client_nonce);
    assert_ne!(first.selection.host_nonce, second.selection.host_nonce);
    assert_ne!(
        first.action_window.action_window_id,
        second.action_window.action_window_id
    );
    assert_ne!(first.transcript_digest, second.transcript_digest);
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

/// KR-REQ-23.19, KR-REQ-10.39: an unpaired connection negotiates hello and reaches only the pairing
/// surface; an ordinary method is refused.
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

/// KR-REQ-10.39: the pre-authorisation surface is rate limited per connection.
/// KR-REQ-23.19: the unpaired surface is bounded by a per-connection request budget.
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

/// KR-REQ-10.39: the pre-authorisation surface bounds every request. One larger than its frame
/// bound is refused from its length prefix, the exchange ends there, and nothing reaches the
/// pairing surface.
/// KR-REQ-23.19: the unpaired surface bounds every message it reads.
#[tokio::test]
async fn an_oversized_pairing_request_never_reaches_the_surface() {
    let (host, client) = paired_pair().await;
    let surface = Arc::new(RecordingSurface::default());
    let recording = Arc::clone(&surface);
    let endpoint = host.endpoint.clone();
    let identity = Arc::clone(&host.identity);
    let serving = tokio::spawn(async move {
        let connection = accept_connection(&endpoint).await;
        let clock = ManualClock::new();
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
        let outcome = preauth::serve(
            &mut unpaired,
            recording.as_ref(),
            PreAuthLimits::default(),
            &clock,
            ControllerGeneration::new(1),
        )
        .await;
        (connection, outcome)
    });

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let (mut writer, mut reader) = control_streams(&connection).await;
    writer.write_message(&offer(&client)).await.expect("sent");
    let _ = read_frame::<HelloReply>(&mut reader).await;

    let oversized = Request {
        request_id: RequestId::new(1),
        method: Method::PairStatus.into(),
        method_version: MethodVersion::V1,
        params: ParamsValue::new(CanonicalValue::bytes(vec![
            0u8;
            preauth::MAX_PREAUTH_FRAME_LEN
        ])),
    };
    writer.write_message(&oversized).await.expect("sent");

    let (_connection, outcome) = tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("the host stopped serving")
        .expect("the host task");
    assert!(
        matches!(outcome, Err(TransportError::Frame(_))),
        "an oversized request ends the exchange: {outcome:?}"
    );
    assert!(
        surface.calls().is_empty(),
        "nothing reached the pairing surface"
    );
}

/// KR-REQ-23.18: losing the control stream revokes every data stream it authorised.
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

/// KR-REQ-23.11: a stream header is validated against the established control connection.
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

/// KR-REQ-23.09: between hello and device authorisation the first stream takes nothing but the
/// connection proof; a mutation sent there is refused and the connection is never authorised.
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

/// KR-REQ-09.02: a `hello` offer that carries a field its schema does not declare is refused by the
/// host's frame reader before the typed decoder runs, and the refusal answers
/// `UNSUPPORTED_SCHEMA`.
#[tokio::test]
async fn an_offer_with_a_field_its_schema_does_not_declare_is_refused_before_it_is_decoded() {
    let (host, client) = paired_pair().await;
    let accepting = spawn_accept(&host, one_device(&client), ManualClock::new());

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let (send, _recv) = connection.open_bi().await.expect("a stream");
    let mut writer = FrameWriter::new(send, StreamKind::Control);
    let CanonicalValue::Map(fields) =
        kr_cbor::to_canonical_value(&offer(&client)).expect("an offer")
    else {
        unreachable!("an offer is a map");
    };
    let mut entries = fields.into_entries();
    entries.push(("zz_unknown".to_owned(), CanonicalValue::Bool(true)));
    let extended = kr_cbor::encode(&CanonicalValue::Map(
        kr_cbor::CanonicalMap::from_entries(entries).expect("distinct keys"),
    ));
    writer.write_payload(&extended).await.expect("sent");

    let (_connection, admitted) = accepting.await.expect("the host task");
    let error = admitted.expect_err("the host refused the offer");
    let TransportError::Frame(kr_protocol::frame::FrameError::Cbor(cbor)) = &error else {
        panic!("an undeclared field is a frame refusal, not {error}");
    };
    assert_eq!(cbor.rule(), "unknown_field", "{error}");
    assert_eq!(error.to_protocol_error().code, ErrorCode::UnsupportedSchema);
}

/// A test extension that adds a member of type `B` to a `host.info` result. Two member types give
/// two schemas, and so two hashes, under one identifier.
fn thermal<B: kr_protocol::wire::WireMessage>() -> ExtensionDefinition {
    ExtensionDefinition::new(
        ExtensionId::new("org.example.thermal").expect("an identifier"),
        [MemberBlock::of::<B>("HostInfoResult")],
    )
    .expect("a definition")
}

/// KR-REQ-23.14: an extension both sides implement with the same schema is negotiated in `hello`
/// by identifier and schema hash, and the transcript both proofs sign covers it. One the host does
/// not implement, or holds another schema for, is left out and the connection completes without it.
#[tokio::test]
async fn an_extension_is_negotiated_by_identifier_and_schema_hash() {
    let offered = extension::offer(&[thermal::<ProtocolVersion>()]);
    for (host_extensions, selected) in [
        (vec![thermal::<ProtocolVersion>()], offered.clone()),
        (Vec::new(), ExtensionOffers::new()),
        (vec![thermal::<ReceiveLimits>()], ExtensionOffers::new()),
    ] {
        let (mut host, mut client) = paired_pair().await;
        Arc::get_mut(&mut client.identity)
            .expect("the identity is not shared yet")
            .extensions = vec![thermal::<ProtocolVersion>()];
        Arc::get_mut(&mut host.identity)
            .expect("the identity is not shared yet")
            .extensions = host_extensions;
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

        assert_eq!(authorised.offer.extensions, offered);
        assert_eq!(authorised.selection.extensions, selected);
        assert_eq!(host_side.selection.extensions, selected);
        assert_eq!(host_side.transcript_digest, authorised.transcript_digest);
    }
}

/// Answers the first offer on a connection with a selection naming `org.example.thermal`, whatever
/// the offer said, and holds the connection until the client lets it go.
fn spawn_selecting_unoffered(host: &Side) -> JoinHandle<()> {
    let endpoint = host.endpoint.clone();
    let record = host.record;
    tokio::spawn(async move {
        let connection = accept_connection(&endpoint).await;
        let (send, recv) = connection.accept_bi().await.expect("a stream");
        let mut reader = FrameReader::new(recv, StreamKind::Control);
        let mut writer = FrameWriter::new(send, StreamKind::Control);
        let offer: ClientOffer = reader
            .read_message()
            .await
            .expect("a frame")
            .expect("an offer");
        let selection = HostSelection {
            host_nonce: fresh_nonce().expect("a nonce"),
            client_nonce: offer.client_nonce,
            connection_id: ConnectionId::new(Uuid::from_bytes([7; 16])),
            selected_version: PROTOCOL_VERSION,
            capabilities: CanonicalSet::new(),
            limits: ReceiveLimits::default(),
            endpoint_id: record.endpoint_id,
            device_id: record.device_id,
            device_key_revision: record.device_key_revision,
            boot_epoch: epochs().boot_epoch,
            clock_epoch: epochs().clock_epoch,
            extensions: extension::offer(&[thermal::<ProtocolVersion>()]),
        };
        writer
            .write_message(&HelloReply::Selected(Box::new(selection)))
            .await
            .expect("the selection is sent");
        connection.closed().await;
    })
}

/// KR-REQ-23.14: a client refuses a selection that names an extension it did not offer, on the
/// paired path and on the candidate path to the pairing surface alike, before anything is used under
/// that selection.
#[tokio::test]
async fn a_selection_naming_an_extension_the_client_did_not_offer_is_refused() {
    for candidate in [false, true] {
        let (host, client) = paired_pair().await;
        let answering = spawn_selecting_unoffered(&host);
        let connection = client
            .endpoint
            .connect(direct_addr(&host), ALPN)
            .await
            .expect("a connection");
        let error = if candidate {
            handshake::connect_unpaired(&connection, &client.identity)
                .await
                .expect_err("refused")
        } else {
            handshake::connect(&connection, &client.identity, &host.record)
                .await
                .expect_err("refused")
        };
        let TransportError::Handshake(error) = error else {
            panic!("an unoffered extension is a handshake refusal, not {error}");
        };
        assert_eq!(
            error.code,
            ErrorCode::UnsupportedSchema,
            "{}",
            error.message
        );
        drop(connection);
        answering.abort();
    }
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

async fn read_frame<T: kr_protocol::wire::WireMessage>(reader: &mut FrameReader) -> T {
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
        extensions: kr_protocol::extension::ExtensionOffers::new(),
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

/// What a scripted host does on a client's first stream, once it has read the offer.
#[derive(Clone)]
enum HostScript {
    /// Ends the stream without a reply.
    NoReply,
    /// Refuses the offer with this error.
    RefuseOffer(ProtocolError),
    /// Selects limits the client cannot work within.
    SelectUnusableLimits,
    /// Selects, reads the connection proof, and ends the stream without a reply.
    NoProofReply,
    /// Selects, reads the connection proof, and refuses it with this error.
    RefuseProof(ProtocolError),
    /// Selects, reads the connection proof, and accepts it with a valid proof of its own and an
    /// action window bound to another connection.
    AcceptForAnotherConnection,
    /// Selects for a candidate, reads its first call, and answers it with this error.
    AnswerWithError(ProtocolError),
    /// Selects for a candidate, reads its first call, and answers another request.
    AnswerAnotherRequest,
    /// Selects for a candidate, reads its first call, and ends the stream without an answer.
    AnswerNothing,
}

/// Runs `script` as the host on the first connection `host` accepts, and holds the connection
/// until the client lets it go.
fn spawn_scripted(host: &Side, script: HostScript) -> JoinHandle<()> {
    let endpoint = host.endpoint.clone();
    let record = host.record;
    let keys = host.keys.clone();
    tokio::spawn(async move {
        let connection = accept_connection(&endpoint).await;
        let (send, recv) = connection.accept_bi().await.expect("a stream");
        let mut reader = FrameReader::new(recv, StreamKind::Control);
        let mut writer = FrameWriter::new(send, StreamKind::Control);
        let offer: ClientOffer = reader
            .read_message()
            .await
            .expect("a frame")
            .expect("an offer");
        let mut selection = HostSelection {
            host_nonce: fresh_nonce().expect("a nonce"),
            client_nonce: offer.client_nonce,
            connection_id: ConnectionId::new(Uuid::from_bytes([7; 16])),
            selected_version: PROTOCOL_VERSION,
            capabilities: CanonicalSet::new(),
            limits: ReceiveLimits::default(),
            endpoint_id: record.endpoint_id,
            device_id: record.device_id,
            device_key_revision: record.device_key_revision,
            boot_epoch: epochs().boot_epoch,
            clock_epoch: epochs().clock_epoch,
            extensions: extension::select(&offer.extensions, &[]),
        };
        match script {
            HostScript::NoReply => {
                writer.finish_and_flush(Duration::from_secs(1)).await;
            }
            HostScript::RefuseOffer(error) => {
                writer
                    .write_message(&HelloReply::Refused(error))
                    .await
                    .expect("the refusal is sent");
            }
            HostScript::SelectUnusableLimits => {
                selection.limits.max_send_queue_bytes = kr_protocol::scalars::U64::new(
                    kr_transport::scheduler::MIN_SEND_QUEUE_BYTES as u64 - 1,
                );
                writer
                    .write_message(&HelloReply::Selected(Box::new(selection.clone())))
                    .await
                    .expect("the selection is sent");
            }
            HostScript::NoProofReply
            | HostScript::RefuseProof(_)
            | HostScript::AcceptForAnotherConnection => {
                writer
                    .write_message(&HelloReply::Selected(Box::new(selection.clone())))
                    .await
                    .expect("the selection is sent");
                let _: ConnectProof = reader
                    .read_message()
                    .await
                    .expect("a frame")
                    .expect("a proof");
                match script {
                    HostScript::RefuseProof(error) => writer
                        .write_message(&ConnectReply::Refused(error))
                        .await
                        .expect("the refusal is sent"),
                    HostScript::AcceptForAnotherConnection => {
                        let signature = sign_connect(
                            &keys.authorisation,
                            &offer,
                            &selection,
                            &EndpointKey::from_bytes(*connection.remote_id().as_bytes()),
                            &record.endpoint_id,
                        )
                        .expect("the host's proof");
                        let accepted = ConnectAccepted {
                            host_proof: ConnectProof { signature },
                            action_window: ActionWindow {
                                action_window_id: ActionWindowId::new(
                                    "a-window-of-another-connection",
                                )
                                .expect("a window identifier"),
                                connection_id: ConnectionId::new(Uuid::from_bytes([9; 16])),
                                boot_epoch: selection.boot_epoch,
                                issued_at_ms: TimestampMs::new(1),
                                valid_for_ms: DurationMs::new(60_000),
                            },
                        };
                        writer
                            .write_message(&ConnectReply::Accepted(Box::new(accepted)))
                            .await
                            .expect("the acceptance is sent");
                    }
                    _ => writer.finish_and_flush(Duration::from_secs(1)).await,
                }
            }
            HostScript::AnswerWithError(_)
            | HostScript::AnswerAnotherRequest
            | HostScript::AnswerNothing => {
                writer
                    .write_message(&HelloReply::Selected(Box::new(selection.clone())))
                    .await
                    .expect("the selection is sent");
                let request: Request = reader
                    .read_message()
                    .await
                    .expect("a frame")
                    .expect("a call");
                match script {
                    HostScript::AnswerWithError(error) => writer
                        .write_message(&Response {
                            request_id: request.request_id,
                            outcome: Outcome::Error(error),
                        })
                        .await
                        .expect("the answer is sent"),
                    HostScript::AnswerAnotherRequest => writer
                        .write_message(&Response {
                            request_id: RequestId::new(request.request_id.get() + 1),
                            outcome: Outcome::Error(ProtocolError::new(
                                ErrorCode::PairingAuthFailed,
                                "an answer to a request nobody made",
                            )),
                        })
                        .await
                        .expect("the answer is sent"),
                    _ => writer.finish_and_flush(Duration::from_secs(1)).await,
                }
            }
        }
        connection.closed().await;
    })
}

/// The error the paired handshake ends with against a host that plays `script`.
async fn paired_ending(script: HostScript) -> TransportError {
    let (host, client) = paired_pair().await;
    let answering = spawn_scripted(&host, script);
    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let error = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect_err("the handshake ends");
    drop(connection);
    answering.abort();
    error
}

/// The error a candidate's surface ends with against a host that plays `script`: in its offer,
/// or in its first call.
async fn candidate_ending(script: HostScript) -> TransportError {
    let (host, client) = paired_pair().await;
    let answering = spawn_scripted(&host, script);
    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let error = match handshake::connect_unpaired(&connection, &client.identity).await {
        Err(error) => error,
        Ok(mut surface) => surface
            .call::<_, kr_protocol::preauth::PairStatusResult>(
                Method::PairStatus,
                &kr_protocol::preauth::PairStatusParams {
                    invitation_id: kr_protocol::ids::InvitationId::new(Uuid::from_bytes([3; 16])),
                },
            )
            .await
            .expect_err("the call ends"),
    };
    drop(connection);
    answering.abort();
    error
}

fn refused(error: TransportError) -> ProtocolError {
    let TransportError::Refused(error) = error else {
        panic!("the host's own answer is a refusal, not {error}");
    };
    error
}

fn concluded(error: TransportError) -> ProtocolError {
    let TransportError::Handshake(error) = error else {
        panic!("what this side concluded is a handshake failure, not {error}");
    };
    error
}

/// An error the host sends in reply to the offer is the host's refusal, whatever its code; a reply
/// that never came, and a selection the client cannot work within, are the client's own
/// conclusions, and stay handshake failures.
#[tokio::test]
async fn a_refused_offer_is_told_apart_from_what_the_client_concluded() {
    let sent = ProtocolError::new(ErrorCode::RateLimited, "later");
    assert_eq!(
        refused(paired_ending(HostScript::RefuseOffer(sent.clone())).await),
        sent
    );
    assert_eq!(
        concluded(paired_ending(HostScript::NoReply).await).code,
        ErrorCode::ResourceUnavailable
    );
    assert_eq!(
        concluded(paired_ending(HostScript::SelectUnusableLimits).await).code,
        ErrorCode::InvalidArgument
    );
}

/// An error the host sends in reply to the connection proof is the host's refusal; a reply that
/// never came, and an acceptance bound to another connection, are the client's own conclusions.
#[tokio::test]
async fn a_refused_proof_is_told_apart_from_what_the_client_concluded() {
    let sent = ProtocolError::new(ErrorCode::PermissionDenied, "not this key");
    assert_eq!(
        refused(paired_ending(HostScript::RefuseProof(sent.clone())).await),
        sent
    );
    assert_eq!(
        concluded(paired_ending(HostScript::NoProofReply).await).code,
        ErrorCode::PermissionDenied
    );
    let unbound = concluded(paired_ending(HostScript::AcceptForAnotherConnection).await);
    assert_eq!(unbound.code, ErrorCode::PermissionDenied);
    assert!(
        unbound.message.contains("action window"),
        "{}",
        unbound.message
    );
}

/// A candidate tells the host's refusal of its offer, and the host's error answer to its call,
/// apart from what it concluded itself: no reply to the offer, no answer to the call, and an
/// answer to another request, whatever code that answer carried.
#[tokio::test]
async fn a_candidates_refusals_are_told_apart_from_what_it_concluded() {
    let sent = ProtocolError::new(ErrorCode::UnsupportedSchema, "no version in common");
    assert_eq!(
        refused(candidate_ending(HostScript::RefuseOffer(sent.clone())).await),
        sent
    );
    assert_eq!(
        concluded(candidate_ending(HostScript::NoReply).await).code,
        ErrorCode::ResourceUnavailable
    );
    let answered = ProtocolError::new(ErrorCode::InvalidArgument, "not a status question");
    assert_eq!(
        refused(candidate_ending(HostScript::AnswerWithError(answered.clone())).await),
        answered
    );
    assert_eq!(
        concluded(candidate_ending(HostScript::AnswerNothing).await).code,
        ErrorCode::ResourceUnavailable
    );
    assert_eq!(
        concluded(candidate_ending(HostScript::AnswerAnotherRequest).await).code,
        ErrorCode::InvalidArgument
    );
}
