//! A relay-only endpoint behind a real proxy that intercepts TLS: the squid that
//! `scripts/real-proxy.sh` runs in its `bump` mode, with a certificate authority made for the run.
//!
//! It is the real-proxy twin of the intercepting-proxy and blocked-upgrade cases of
//! `restricted_networks.rs`. The proxy answers for the relay with a certificate its own authority
//! issued, and one of its ports answers a request to upgrade to a WebSocket with 403. Each case runs
//! only against a proxy the environment names; see `support/real_proxy.rs`.

mod support;

#[path = "support/real_proxy.rs"]
#[allow(dead_code)]
mod real_proxy;

use std::time::{Duration, Instant};

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr};
use kr_protocol::error::ErrorCode;
use kr_transport::config::EndpointConfig;
use kr_transport::{ALPN, TransportError};
use real_proxy::{Login, RealProxy};
use support::{LocalRelay, Side};
use tokio::task::JoinHandle;

/// How long anything the machine has to do may take before the test calls it a failure.
const PATIENCE: Duration = Duration::from_secs(60);

/// How soon an endpoint with nothing but a relay it cannot use learns that it cannot connect.
const AT_ONCE: Duration = Duration::from_secs(10);

/// An endpoint whose only transport is `relay`, trusting `ca_roots` for it.
fn relay_only(relay: &iroh::RelayUrl, ca_roots: &[Vec<u8>]) -> EndpointConfig {
    EndpointConfig {
        relay_urls: vec![relay.clone()],
        relay_ca_roots: ca_roots.to_vec(),
        relay_only: true,
        ..EndpointConfig::default()
    }
}

/// The relay's `host:port`.
fn address_of(relay: &iroh::RelayUrl) -> String {
    format!(
        "{}:{}",
        relay.host_str().expect("a host"),
        relay.port_or_known_default().expect("a port")
    )
}

async fn online(side: &Side, what: &str) {
    tokio::time::timeout(PATIENCE, side.endpoint.online())
        .await
        .unwrap_or_else(|_| panic!("{what}"));
}

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

async fn dial(side: &Side, peer: EndpointAddr) -> kr_transport::Result<Connection> {
    tokio::time::timeout(
        PATIENCE,
        kr_transport::endpoint::connect(&side.endpoint, peer, ALPN),
    )
    .await
    .expect("the attempt ends by itself")
}

/// KR-REQ-10.02: a real proxy that intercepts TLS and refuses the WebSocket upgrade. A relay-only
/// client that trusts the proxy's authority is told within moments that the network refused the
/// upgrade with status 403, as `RESOURCE_UNAVAILABLE`, and the proxy's log shows the request it
/// refused. The same client reaches the host through the proxy's other port, which lets the upgrade
/// through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "runs only against a proxy this machine runs that intercepts TLS, named by KR_REAL_PROXY_BUMP, KR_REAL_PROXY_BUMP_BLOCKING, KR_REAL_PROXY_BUMP_CA_FILE and KR_REAL_PROXY_BUMP_ACCESS_LOG"]
async fn a_relay_only_attempt_through_a_real_proxy_that_refuses_the_upgrade_says_so() {
    let (proxy, blocking, authority) = RealProxy::bump();
    let relay = LocalRelay::spawn().await;
    let host = support::side(&relay_only(&relay.url, &relay.ca_roots), 1, true).await;
    online(&host, "the host reaches its relay").await;
    let trusted = [relay.ca_roots.clone(), vec![authority]].concat();
    let peer = EndpointAddr::new(host.endpoint.id()).with_relay_url(relay.url.clone());

    let refused = EndpointConfig {
        proxy_url: Some(blocking.parse().expect("the proxy's origin")),
        ..relay_only(&relay.url, &trusted)
    };
    let client = support::side(&refused, 2, false).await;
    let started = Instant::now();
    let error = dial(&client, peer.clone())
        .await
        .expect_err("no path reaches the host");
    let took = started.elapsed();
    let TransportError::Connect(message) = &error else {
        panic!("a refused upgrade is a connection that could not be established: {error}");
    };
    assert_eq!(
        *message,
        format!(
            "the network refused the WebSocket upgrade to the relay {} with HTTP status 403",
            relay.url
        )
    );
    assert_eq!(
        error.to_protocol_error().code,
        ErrorCode::ResourceUnavailable
    );
    assert!(
        took < AT_ONCE,
        "a client with nothing but the blocked relay is told within {AT_ONCE:?}: it took {took:?}"
    );
    let lines = proxy
        .wait_until_naming(&address_of(&relay.url), "a refused upgrade", |lines| {
            lines
                .iter()
                .any(|line| line.status == 403 && line.result == "TCP_DENIED")
        })
        .await;
    assert!(
        lines
            .iter()
            .any(|line| line.method == "GET" && line.target.ends_with("/relay")),
        "the refused request was the relay's: {lines:?}"
    );
    client.endpoint.close().await;

    let passing = EndpointConfig {
        proxy_url: Some(proxy.url(Login::None)),
        ..relay_only(&relay.url, &trusted)
    };
    let unblocked = support::side(&passing, 3, false).await;
    let accepting = accept_one(&host);
    let connection = dial(&unblocked, peer)
        .await
        .expect("with the upgrade let through the relay carries the connection");
    let accepted = accepting.await.expect("the host task");
    assert_eq!(accepted.remote_id(), unblocked.endpoint.id());

    drop(connection);
    unblocked.endpoint.close().await;
    host.endpoint.close().await;
}

/// KR-REQ-10.02: a real proxy that intercepts TLS answers for the relay with a certificate its own
/// authority issued. A client that trusts only the relay's own anchor refuses it, and never gets
/// onto the relay. With the proxy's authority named among its trust anchors, the same kind of
/// client reaches the relay through the proxy and connects to the host, and the proxy's log shows
/// the tunnel it opened to the relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "runs only against a proxy this machine runs that intercepts TLS, named by KR_REAL_PROXY_BUMP, KR_REAL_PROXY_BUMP_BLOCKING, KR_REAL_PROXY_BUMP_CA_FILE and KR_REAL_PROXY_BUMP_ACCESS_LOG"]
async fn a_real_intercepting_proxy_is_trusted_only_when_its_authority_is_named() {
    let (proxy, _, authority) = RealProxy::bump();
    let relay = LocalRelay::spawn().await;
    let host = support::side(&relay_only(&relay.url, &relay.ca_roots), 1, true).await;
    online(&host, "the host reaches its relay").await;
    let proxy_url = proxy.url(Login::None);
    let through_proxy = |ca_roots: Vec<Vec<u8>>| EndpointConfig {
        proxy_url: Some(proxy_url.clone()),
        ..relay_only(&relay.url, &ca_roots)
    };
    // One relay handshake through the proxy, with the TLS configuration `endpoint` uses for relays.
    let handshake = |endpoint: &Endpoint| {
        iroh_relay::client::ClientBuilder::new(
            relay.url.clone(),
            iroh::SecretKey::generate(),
            iroh::dns::DnsResolver::new(),
        )
        .tls_client_config(endpoint.tls_config().clone())
        .proxy_url(proxy_url.as_url().clone())
    };

    let untrusting = support::side(&through_proxy(relay.ca_roots.clone()), 2, false).await;
    let Err(refusal) = handshake(&untrusting.endpoint).connect().await else {
        panic!("the relay handshake completed with a certificate nothing trusts");
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
    assert!(
        tokio::time::timeout(AT_ONCE, untrusting.endpoint.online())
            .await
            .is_err(),
        "a client that does not trust the proxy's authority never gets onto the relay"
    );
    untrusting.endpoint.close().await;

    let trusting = support::side(
        &through_proxy([relay.ca_roots.clone(), vec![authority]].concat()),
        3,
        false,
    )
    .await;
    handshake(&trusting.endpoint)
        .connect()
        .await
        .expect("with the proxy's authority named, the relay handshake completes");
    online(
        &trusting,
        "the trusting client reaches its relay through the proxy",
    )
    .await;
    let accepting = accept_one(&host);
    let connection = dial(
        &trusting,
        EndpointAddr::new(host.endpoint.id()).with_relay_url(relay.url.clone()),
    )
    .await
    .expect("the relay carries the connection through the intercepting proxy");
    let accepted = accepting.await.expect("the host task");
    assert_eq!(accepted.remote_id(), trusting.endpoint.id());

    drop(connection);
    trusting.endpoint.close().await;
    host.endpoint.close().await;
    let lines = proxy.wait_for(&address_of(&relay.url), 1).await;
    assert!(
        lines
            .iter()
            .all(|line| line.method == "CONNECT" && line.status == 200),
        "{lines:?}"
    );
}
