//! A relay that turns an endpoint away, and what a new connection makes of it.
//!
//! Every relay here is a real `iroh-relay` server in this process, with an admission check that
//! refuses the endpoints a test names, with the reason the test gives, as a managed relay refuses
//! an endpoint whose allowance is spent. Every endpoint is a real iroh endpoint on the loopback.
//! What is checked is the dialling side: that a connection a refusing relay stood in the way of
//! fails as that refusal, with the relay's kind of refusal and its words, and only when the
//! refusing relay is on the connection's route.

mod support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::{EndpointAddr, EndpointId, RelayUrl, Watcher as _};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::error::ErrorCode;
use kr_transport::config::EndpointConfig;
use kr_transport::error::{RelayRefusalKind, RouteAlternative};
use kr_transport::{ALPN, TransportError};
use support::Side;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// How long anything the machine has to do may take before the test calls it a failure.
const PATIENCE: Duration = Duration::from_secs(60);

/// How soon an endpoint with nothing but refusing relays learns that it cannot connect.
///
/// A third of the attempt's own 30-second deadline: a failure inside it was decided by the
/// refusal, not by the attempt running out.
const AT_ONCE: Duration = Duration::from_secs(10);

/// The endpoints a relay turns away, each with the reason it gives.
#[derive(Debug, Clone, Default)]
struct Gate(Arc<Mutex<BTreeMap<EndpointId, String>>>);

impl iroh_relay::server::AccessControl for Gate {
    async fn on_connect(
        &self,
        request: &iroh_relay::server::ClientRequest,
    ) -> iroh_relay::server::Access {
        match self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&request.endpoint_id())
        {
            Some(reason) => iroh_relay::server::Access::Deny {
                reason: Some(reason.clone()),
            },
            None => iroh_relay::server::Access::Allow,
        }
    }
}

/// A relay server in this process that admits everyone except the endpoints it is told to refuse.
struct RefusingRelay {
    url: RelayUrl,
    ca_roots: Vec<Vec<u8>>,
    gate: Gate,
    _server: iroh_relay::server::Server,
}

impl RefusingRelay {
    async fn spawn() -> Self {
        use std::net::Ipv4Addr;

        use iroh_relay::server::{
            CertConfig, QuicConfig, RelayConfig as RelayServerConfig, Server, ServerConfig,
            TlsConfig,
        };

        let (certs, server_config) =
            iroh_relay::server::testing::self_signed_tls_certs_and_config();
        let tls = TlsConfig::new(
            (Ipv4Addr::LOCALHOST, 0),
            CertConfig::Manual { server_config },
        );
        let gate = Gate::default();
        let mut relay = RelayServerConfig::new((Ipv4Addr::LOCALHOST, 0));
        relay.tls = Some(tls);
        relay.key_cache_capacity = Some(1024);
        relay.access = Arc::new(gate.clone());

        let mut config = ServerConfig::default();
        config.relay = Some(relay);
        config.quic = Some(QuicConfig::new((Ipv4Addr::LOCALHOST, 0)));

        let server = Server::spawn(config).await.expect("a relay server");
        let url: RelayUrl = format!("https://{}", server.https_addr().expect("configured"))
            .parse()
            .expect("a relay URL");
        Self {
            url,
            ca_roots: certs.into_iter().map(|cert| cert.to_vec()).collect(),
            gate,
            _server: server,
        }
    }

    /// Turns `endpoint` away from now on, saying `reason`.
    fn refuse(&self, endpoint: EndpointId, reason: &str) {
        self.gate
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(endpoint, reason.to_owned());
    }
}

/// An endpoint whose only transport is `relay`, trusting the certificates in `anchors`.
fn relay_only(relay: &RefusingRelay, anchors: &[&RefusingRelay]) -> EndpointConfig {
    EndpointConfig {
        relay_urls: vec![relay.url.clone()],
        relay_ca_roots: anchors
            .iter()
            .flat_map(|anchor| anchor.ca_roots.iter().cloned())
            .collect(),
        relay_only: true,
        ..EndpointConfig::default()
    }
}

/// An endpoint with a direct path on the loopback as well as `relay`.
fn with_direct(relay: &RefusingRelay) -> EndpointConfig {
    EndpointConfig {
        relay_urls: vec![relay.url.clone()],
        relay_ca_roots: relay.ca_roots.clone(),
        bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
        ..EndpointConfig::default()
    }
}

fn endpoint_id(keys: &DeviceKeys) -> EndpointId {
    EndpointId::from_bytes(keys.transport.public().as_bytes()).expect("an endpoint identity")
}

/// A host on `config` that is on its relay and accepting.
async fn host(config: &EndpointConfig) -> Side {
    let host = support::side(config, 1, true).await;
    tokio::time::timeout(PATIENCE, host.endpoint.online())
        .await
        .expect("the host reaches its relay");
    host
}

/// Accepts one connection on the host.
fn accept_one(host: &Side) -> JoinHandle<Connection> {
    let endpoint = host.endpoint.clone();
    tokio::spawn(async move {
        endpoint
            .accept()
            .await
            .expect("an incoming connection")
            .await
            .expect("a connection")
    })
}

/// A device on `config` that `refusing` turns away with `reason` from the moment it exists.
async fn refused_device(config: &EndpointConfig, refusing: &RefusingRelay, reason: &str) -> Side {
    let keys = DeviceKeys::generate().expect("device keys");
    refusing.refuse(endpoint_id(&keys), reason);
    support::side_with(config, keys, 2, false).await
}

/// Waits until the device's home relay `relay` has refused it with `reason`.
async fn until_refused(device: &Side, relay: &RelayUrl, reason: &str) {
    let deadline = Instant::now() + PATIENCE;
    let mut statuses = device.endpoint.home_relay_status();
    while !statuses
        .get()
        .iter()
        .any(|status| status.url() == relay && status.auth_denied_reason() == Some(reason))
    {
        assert!(
            Instant::now() < deadline,
            "the relay never refused the device: {:?}",
            statuses.get()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Dials `peer` from `device` and returns the outcome and how long it took.
async fn dial(device: &Side, peer: EndpointAddr) -> (Duration, kr_transport::Result<Connection>) {
    let started = Instant::now();
    let outcome = tokio::time::timeout(
        PATIENCE,
        kr_transport::endpoint::connect(&device.endpoint, peer, ALPN),
    )
    .await
    .expect("the attempt ends by itself");
    (started.elapsed(), outcome)
}

/// KR-REQ-17.40: a device whose only path is a relay, and whom that relay turns away, is told so
/// at once and in the relay's own terms. Each kind of refusal a relay names is read from the token
/// its reason starts with and carries its own code: a spent allowance is `QUOTA_EXCEEDED`, a
/// stopping relay is `SERVICE_CAPACITY`, and a reason with no known token, which is what an older
/// relay or another operator's relay sends, is kept whole under the code of any other failed
/// connection. None of them waits for the attempt's deadline, and none looks like a peer that went
/// away.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_kind_of_refusal_ends_a_relay_only_attempt_at_once_as_itself() {
    let cases = [
        (
            "allowance_spent: the reserved bytes for this endpoint are spent; 900000 ms of grace \
             remain for connections already open",
            RelayRefusalKind::AllowanceSpent,
            ErrorCode::QuotaExceeded,
            "the reserved bytes for this endpoint are spent; 900000 ms of grace remain for \
             connections already open",
            vec![
                RouteAlternative::AnotherRelay,
                RouteAlternative::RestoredAllowance,
            ],
        ),
        (
            "stopping: this relay is stopping",
            RelayRefusalKind::Stopping,
            ErrorCode::ServiceCapacity,
            "this relay is stopping",
            vec![RouteAlternative::AnotherRelay],
        ),
        (
            "the relay allowance for this period is used up",
            RelayRefusalKind::Unknown,
            ErrorCode::ResourceUnavailable,
            "the relay allowance for this period is used up",
            vec![RouteAlternative::AnotherRelay],
        ),
    ];
    for (said, kind, code, text, alternatives) in cases {
        let relay = RefusingRelay::spawn().await;
        let host = host(&relay_only(&relay, &[&relay])).await;
        let device = refused_device(&relay_only(&relay, &[&relay]), &relay, said).await;

        let (took, outcome) = dial(
            &device,
            EndpointAddr::new(host.endpoint.id()).with_relay_url(relay.url.clone()),
        )
        .await;
        let error = outcome.expect_err("a relay that refuses carries nothing");
        let TransportError::RelayRefused(refusal) = &error else {
            panic!("the failure is the relay's refusal, not a peer that did not answer: {error}");
        };
        assert_eq!(refusal.relay, relay.url, "{said}: the relay that refused");
        assert_eq!(refusal.kind, kind, "{said}: the kind the relay named");
        assert_eq!(refusal.reason, text, "{said}: what the relay said");
        assert_eq!(
            refusal.alternatives, alternatives,
            "{said}: a relay-only device is offered no direct path"
        );
        assert_eq!(error.to_protocol_error().code, code, "{said}: the code");
        assert!(
            took < AT_ONCE,
            "{said}: a device with nothing but the refusing relay is told within {AT_ONCE:?}, \
             not at the attempt's deadline: it took {took:?}"
        );

        device.endpoint.close().await;
        host.endpoint.close().await;
    }
}

/// KR-REQ-17.40: a device that has a direct transport of its own is not cut off by a relay's
/// refusal while a direct path could still open. With nothing but the refusing relay to reach the
/// host by, its attempt runs to its own end and then fails as the refusal, offering the direct
/// alternatives as well as the relay ones.
///
/// The refusal is the reason only while the status shows it. By the end of the attempt iroh dials
/// the refusing relay again only after five seconds or more, and each dial shows no refusal for the
/// few milliseconds it takes, so an attempt that ends inside one is a plain timeout. When the first
/// attempt runs to its end and times out, the device dials once more, and the second attempt has to
/// fail as the refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_with_a_direct_transport_is_told_of_the_refusal_when_its_attempt_ends() {
    const SPENT: &str = "allowance_spent: the reserved bytes for this endpoint are spent";
    let relay = RefusingRelay::spawn().await;
    let host = host(&relay_only(&relay, &[&relay])).await;
    let device = refused_device(&with_direct(&relay), &relay, SPENT).await;
    until_refused(&device, &relay.url, SPENT).await;

    let route = EndpointAddr::new(host.endpoint.id()).with_relay_url(relay.url.clone());
    let (mut took, mut outcome) = dial(&device, route.clone()).await;
    let timed_out =
        matches!(&outcome, Err(TransportError::Connect(message)) if message == "timed out");
    if took >= AT_ONCE && timed_out {
        eprintln!(
            "the first attempt timed out after {took:?}, possibly while iroh was dialling the \
             relay again; dialling once more"
        );
        (took, outcome) = dial(&device, route).await;
    }
    let error = outcome.expect_err("the host can be reached only through the refusing relay");
    let TransportError::RelayRefused(refusal) = &error else {
        panic!("the failure is the relay's refusal, not a peer that did not answer: {error}");
    };
    assert_eq!(refusal.relay, relay.url);
    assert_eq!(refusal.kind, RelayRefusalKind::AllowanceSpent);
    assert_eq!(
        refusal.alternatives,
        vec![
            RouteAlternative::AddressHints,
            RouteAlternative::LocalDiscovery,
            RouteAlternative::AnotherRelay,
            RouteAlternative::RestoredAllowance,
        ]
    );
    assert!(
        took >= AT_ONCE,
        "the attempt of a device that can take a direct path runs on after the refusal: it \
         ended after {took:?}"
    );

    device.endpoint.close().await;
    host.endpoint.close().await;
}

/// KR-REQ-17.40: already-reachable direct paths are unaffected. The same device the relay turns
/// away reaches the host when the host's direct address is on the route, and the refusal plays no
/// part in the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_device_still_reaches_the_host_by_a_direct_address() {
    const SPENT: &str = "allowance_spent: the reserved bytes for this endpoint are spent";
    let relay = RefusingRelay::spawn().await;
    let host = host(&with_direct(&relay)).await;
    let device = refused_device(&with_direct(&relay), &relay, SPENT).await;
    until_refused(&device, &relay.url, SPENT).await;

    let accepting = accept_one(&host);
    let mut route = EndpointAddr::new(host.endpoint.id()).with_relay_url(relay.url.clone());
    for socket in host.endpoint.bound_sockets() {
        route = route.with_ip_addr(socket);
    }
    let (_, outcome) = dial(&device, route).await;
    let connection = outcome.expect("a direct path reaches the host despite the refusal");
    let accepted = accepting.await.expect("the host task");
    assert_eq!(accepted.remote_id(), device.endpoint.id());

    drop(connection);
    device.endpoint.close().await;
    host.endpoint.close().await;
}

/// KR-REQ-17.40: a refusal explains only a failure in which nothing answered. A device its relay
/// turns away dials a host whose direct address is on the route, in a protocol the host does not
/// speak: the host answers and refuses the handshake, and that refusal, not the relay's, is the
/// failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_answered_and_refused_is_not_reported_as_the_relays_refusal() {
    const SPENT: &str = "allowance_spent: the reserved bytes for this endpoint are spent";
    let relay = RefusingRelay::spawn().await;
    let host = host(&with_direct(&relay)).await;
    let device = refused_device(&with_direct(&relay), &relay, SPENT).await;
    until_refused(&device, &relay.url, SPENT).await;

    // The host takes the attempt up, so its refusal is an answer rather than silence.
    let endpoint = host.endpoint.clone();
    let answering = tokio::spawn(async move {
        if let Some(incoming) = endpoint.accept().await {
            let _ = incoming.await;
        }
    });
    let mut route = EndpointAddr::new(host.endpoint.id()).with_relay_url(relay.url.clone());
    for socket in host.endpoint.bound_sockets() {
        route = route.with_ip_addr(socket);
    }
    let outcome = tokio::time::timeout(
        PATIENCE,
        kr_transport::endpoint::connect(&device.endpoint, route, b"kalareach-unspoken"),
    )
    .await
    .expect("the attempt ends by itself");
    let error = outcome.expect_err("the host refuses a protocol it does not speak");
    assert!(
        matches!(error, TransportError::Connect(_)),
        "the host's refusal is the failure, not the relay's: {error}"
    );

    answering.abort();
    device.endpoint.close().await;
    host.endpoint.close().await;
}

/// KR-REQ-17.40: a request the endpoint cannot make fails as itself, even for a device every relay
/// on its route has refused. Dialling itself and naming no protocol are refused before any path is
/// tried, so no relay has anything to do with them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_that_cannot_be_made_is_not_reported_as_the_relays_refusal() {
    const SPENT: &str = "allowance_spent: the reserved bytes for this endpoint are spent";
    let relay = RefusingRelay::spawn().await;
    let host = host(&relay_only(&relay, &[&relay])).await;
    let device = refused_device(&relay_only(&relay, &[&relay]), &relay, SPENT).await;
    until_refused(&device, &relay.url, SPENT).await;

    let itself = EndpointAddr::new(device.endpoint.id()).with_relay_url(relay.url.clone());
    let (_, outcome) = dial(&device, itself).await;
    let error = outcome.expect_err("an endpoint does not dial itself");
    assert!(
        matches!(error, TransportError::Connect(_)),
        "dialling itself fails as itself: {error}"
    );

    let host_route = EndpointAddr::new(host.endpoint.id()).with_relay_url(relay.url.clone());
    let outcome = tokio::time::timeout(
        PATIENCE,
        kr_transport::endpoint::connect(&device.endpoint, host_route, b""),
    )
    .await
    .expect("the attempt ends by itself");
    let error = outcome.expect_err("a connection names a protocol");
    assert!(
        matches!(error, TransportError::Connect(_)),
        "naming no protocol fails as itself: {error}"
    );

    device.endpoint.close().await;
    host.endpoint.close().await;
}

/// KR-REQ-17.40: a refusal is the reason for a connection only when the refusing relay is on its
/// route. A device whose own home relay turns it away dials a host through another relay, which
/// admits it, and connects: neither at once nor at the end is the home relay's refusal taken for
/// this connection's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_home_relay_refusal_off_the_route_is_not_the_connections_reason() {
    const SPENT: &str = "allowance_spent: the reserved bytes for this endpoint are spent";
    let home = RefusingRelay::spawn().await;
    let other = RefusingRelay::spawn().await;
    let host = host(&relay_only(&other, &[&other])).await;
    let device = refused_device(&relay_only(&home, &[&home, &other]), &home, SPENT).await;
    until_refused(&device, &home.url, SPENT).await;

    let accepting = accept_one(&host);
    let (_, outcome) = dial(
        &device,
        EndpointAddr::new(host.endpoint.id()).with_relay_url(other.url.clone()),
    )
    .await;
    let connection = outcome.expect("the relay on the route admits the device");
    let accepted = accepting.await.expect("the host task");
    assert_eq!(accepted.remote_id(), device.endpoint.id());

    drop(connection);
    device.endpoint.close().await;
    host.endpoint.close().await;
}
