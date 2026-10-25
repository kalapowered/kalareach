//! What a device says when the host it dialled answers its offer with a selection it cannot use.
//!
//! A direct invitation pins the host's endpoint. The device dials that endpoint over a real
//! connection and offers on it, and the host's selection is the first thing it answers with. A
//! selection that names another endpoint than the one that answered, or that does not answer the
//! offer, is not a host that could not be reached: the host answered. A scripted host on loopback
//! plays the selection and watches whether the device goes on to ask it anything, and the device
//! is the product's own pairing client over the product's own link.

use std::sync::Arc;
use std::time::Duration;

use kr_client::pairing::candidate::{AttemptState, Candidate, Pairing};
use kr_client::pairing::clock::DeviceClock;
use kr_client::pairing::failure::FailureKind;
use kr_client::pairing::link::{EndpointPool, IrohLink};
use kr_client::pairing::paired::PairedHosts;
use kr_crypto::keys::DeviceKeys;
use kr_pairing::platform::TestClientBudgetStore;
use kr_protocol::envelope::Request;
use kr_protocol::extension;
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ClientOffer, HelloReply, HostSelection, PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::ids::{BootEpoch, BuildId, ClockEpoch, ConnectionId, DeviceId, DeviceKeyRevision};
use kr_protocol::pairing::{
    DeviceName, DevicePlatform, DirectQrPayload, NetworkConfig, NetworkHint, QrPayload,
};
use kr_protocol::scalars::{CanonicalSet, EndpointKey, TimestampMs, Uuid};
use kr_transport::codec::{FrameReader, FrameWriter};
use kr_transport::config::EndpointConfig;
use kr_transport::random::fresh_nonce;
use room_tls::Authority;
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[path = "support/room_tls.rs"]
mod room_tls;

/// How long a test waits for an attempt before it fails as stuck.
const WATCHDOG: Duration = Duration::from_secs(40);

/// How long the scripted host waits for the device to ask it something after the selection.
const ASKING: Duration = Duration::from_secs(5);

/// What the scripted host selects.
#[derive(Clone, Copy)]
enum Selects {
    /// Exactly what the offer asked for, under the endpoint that answers.
    Correctly,
    /// The same, naming another endpoint than the one that answers.
    AnotherEndpoint,
    /// The same, with a client nonce other than the one the offer carried.
    AnotherNonce,
}

/// A direct invitation pinning a host that plays `selects` on loopback, and what the host saw: the
/// host task ends with whether the device asked it anything after its selection.
async fn scripted_host(selects: Selects) -> (DirectQrPayload, JoinHandle<bool>) {
    let keys = DeviceKeys::generate().expect("keys");
    let config = EndpointConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
        ..EndpointConfig::default()
    };
    let endpoint = kr_transport::endpoint::bind_listener(&config, &keys.transport)
        .await
        .expect("a listening endpoint");

    let document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/pairing/codes.json"),
        )
        .expect("the fixture"),
    )
    .expect("JSON");
    let text = document
        .pointer("/qr/direct/text")
        .and_then(serde_json::Value::as_str)
        .expect("the published direct payload");
    let QrPayload::Direct(mut payload) = QrPayload::from_text(text).expect("the vector") else {
        panic!("the direct vector is a direct payload");
    };
    payload.endpoint_id = *keys.transport.public();
    payload.network_config = NetworkConfig {
        direct_addresses: endpoint
            .bound_sockets()
            .into_iter()
            .map(|socket| NetworkHint::new(socket.to_string()).expect("a hint"))
            .collect(),
        ..NetworkConfig::empty()
    };
    payload.expires_at_ms = TimestampMs::new(kr_ipc::now_ms().get() + 300_000);

    let host = tokio::spawn(async move {
        let connection = endpoint
            .accept()
            .await
            .expect("an incoming connection")
            .await
            .expect("a connection");
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
            endpoint_id: *keys.transport.public(),
            device_id: DeviceId::new(Uuid::from_bytes([1; 16])),
            device_key_revision: DeviceKeyRevision::new(1),
            boot_epoch: BootEpoch::new(1),
            clock_epoch: ClockEpoch::new(1),
            extensions: extension::select(&offer.extensions, &[]),
        };
        match selects {
            Selects::Correctly => {}
            Selects::AnotherEndpoint => {
                selection.endpoint_id = EndpointKey::from_bytes([9; 32]);
            }
            Selects::AnotherNonce => {
                selection.client_nonce = fresh_nonce().expect("a nonce");
            }
        }
        writer
            .write_message(&HelloReply::Selected(Box::new(selection)))
            .await
            .expect("the selection is sent");
        let asked = matches!(
            tokio::time::timeout(ASKING, reader.read_message::<Request>()).await,
            Ok(Ok(Some(_)))
        );
        // Nothing is answered: the stream ends, and the connection is let go.
        writer.finish_and_flush(Duration::from_secs(1)).await;
        asked
    });
    (*payload, host)
}

/// A device that pairs through the product's link.
fn pairing() -> (Pairing, tempfile::TempDir) {
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
        room: Arc::new(Authority::new("a room no direct attempt opens").connector()),
        link: Arc::new(IrohLink::new(Arc::new(pool))),
        hosts: Arc::new(PairedHosts::open(directory.path().join("pairing")).expect("a store")),
    };
    (pairing, directory)
}

/// How a direct attempt against a host that plays `selects` ends, and whether the device asked the
/// host anything after the selection.
async fn ending(selects: Selects) -> (FailureKind, bool) {
    let (payload, host) = scripted_host(selects).await;
    let (pairing, _directory) = pairing();
    let (progress, _shown) = watch::channel(AttemptState::Idle);
    let failure = tokio::time::timeout(WATCHDOG, pairing.pair_directly(&payload, &progress))
        .await
        .expect("the attempt ends")
        .expect_err("no host paired");
    (failure.kind, host.await.expect("the host task"))
}

/// KR-REQ-10.19: a host that answers under another endpoint's identity is not the host the
/// invitation names. The device says so, and asks it nothing; it does not tell the person to check
/// the network.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_selection_naming_another_endpoint_is_a_host_that_did_not_match() {
    assert_eq!(
        ending(Selects::AnotherEndpoint).await,
        (FailureKind::HostMismatch, false)
    );
}

/// KR-REQ-10.19: a selection that does not answer the offer ends the attempt as one that did not
/// finish, with nothing asked of the host, and not as a host that could not be reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_selection_that_does_not_answer_the_offer_is_not_an_unreachable_host() {
    assert_eq!(
        ending(Selects::AnotherNonce).await,
        (FailureKind::DidNotFinish, false)
    );
}

/// KR-REQ-10.19: the control for both. A selection that answers the offer under the endpoint that
/// answers is accepted, and the device goes on to ask the host for its challenge; the host then
/// answers nothing, which is a host that could not be reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_selection_that_answers_the_offer_is_asked_for_a_challenge() {
    assert_eq!(
        ending(Selects::Correctly).await,
        (FailureKind::HostUnreachable, true)
    );
}
