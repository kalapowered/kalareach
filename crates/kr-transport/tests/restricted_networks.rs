//! Networks that require a proxy, block the WebSocket upgrade or alter certificate trust.
//!
//! Section 10 names these three kinds of network as the ones the relay path must be tested
//! against, and section 17 qualifies the endpoint's proxy support against them. Each is built here
//! on loopback: a proxy an endpoint has to go through, a front that will not let the relay's
//! WebSocket upgrade through, and a proxy that intercepts TLS with an authority of its own.
//!
//! The relay-only endpoints also stand in for a network that blocks UDP. They have no IP transport
//! at all, so the relay's HTTPS path, and whatever stands in its way, is the only path they have.

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use futures::StreamExt as _;
use iroh::address_lookup::{AddressLookup as _, PkarrResolver};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use kr_transport::ALPN;
use kr_transport::config::{DiscoveryConfig, EndpointConfig, PublishedAddresses, PublisherPolicy};
use support::front::RelayFront;
use support::pkarr::PkarrRelay;
use support::proxy::{HttpProxy, authority};
use support::{LocalRelay, Side};
use tokio::task::JoinHandle;

/// How long anything the machine has to do may take before the test calls it a failure.
const PATIENCE: Duration = Duration::from_secs(60);

fn loopback() -> Option<SocketAddr> {
    Some("127.0.0.1:0".parse().expect("a loopback address"))
}

/// An endpoint whose only transport is `relay`, trusting `ca_roots` for it.
fn relay_only(relay: &RelayUrl, ca_roots: &[Vec<u8>]) -> EndpointConfig {
    EndpointConfig {
        relay_urls: vec![relay.clone()],
        relay_ca_roots: ca_roots.to_vec(),
        relay_only: true,
        ..EndpointConfig::default()
    }
}

/// Waits until `side` is on its home relay.
async fn online(side: &Side, what: &str) {
    tokio::time::timeout(PATIENCE, side.endpoint.online())
        .await
        .unwrap_or_else(|_| panic!("{what}"));
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

/// Dials `peer` from `side` and waits for the attempt to end by itself.
async fn dial(side: &Side, peer: EndpointAddr) -> kr_transport::Result<Connection> {
    tokio::time::timeout(
        PATIENCE,
        kr_transport::endpoint::connect(&side.endpoint, peer, ALPN),
    )
    .await
    .expect("the attempt ends by itself")
}

/// KR-REQ-10.02: a network that requires a proxy. A relay-only host and client each select the
/// proxy, reach the relay through it and connect to each other. Every tunnel the proxy opened was
/// to the relay's own address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_only_pair_connects_through_the_proxy_it_selected() {
    let relay = LocalRelay::spawn().await;
    let proxy = HttpProxy::forwarding();
    let config = EndpointConfig {
        proxy_url: Some(proxy.url.clone()),
        ..relay_only(&relay.url, &relay.ca_roots)
    };
    let host = support::side(&config, 1, true).await;
    let client = support::side(&config, 2, false).await;
    online(&host, "the host reaches its relay through the proxy").await;
    online(&client, "the client reaches its relay through the proxy").await;

    let accepting = accept_one(&host);
    let connection = dial(
        &client,
        EndpointAddr::new(host.endpoint.id()).with_relay_url(relay.url.clone()),
    )
    .await
    .expect("the relay carries the connection");
    let accepted = accepting.await.expect("the host task");
    assert_eq!(accepted.remote_id(), client.endpoint.id());

    let relay_address = authority(&relay.url);
    let tunnels = proxy.tunnels();
    assert!(
        tunnels
            .iter()
            .filter(|tunnel| **tunnel == relay_address)
            .count()
            >= 2,
        "both endpoints tunnelled to the relay through the proxy: {tunnels:?}"
    );
    assert!(
        tunnels.iter().all(|tunnel| *tunnel == relay_address),
        "and to nowhere else: {tunnels:?}"
    );

    drop(connection);
    client.endpoint.close().await;
    host.endpoint.close().await;
}

/// KR-REQ-10.02: a selected proxy is the only way to the relay. With the proxy stopped, a
/// relay-only client's attempt to reach a host through the relay fails and nothing reaches the
/// relay: the client does not go around its proxy. The same client without a proxy reaches the
/// relay and the host, so the relay was there to be reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_whose_proxy_is_stopped_never_reaches_the_relay() {
    let relay = LocalRelay::spawn().await;
    // The host is on the relay directly. The clients are given the front's address for it, so a
    // connection that reaches the relay from a client is one the front counted.
    let front = RelayFront::passing(&relay);
    let host = support::side(&relay_only(&relay.url, &relay.ca_roots), 1, true).await;
    online(&host, "the host reaches its relay").await;
    let route = EndpointAddr::new(host.endpoint.id()).with_relay_url(front.url.clone());

    let mut proxy = HttpProxy::forwarding();
    let stopped = proxy.url.clone();
    proxy.stop();
    let client = support::side(
        &EndpointConfig {
            proxy_url: Some(stopped),
            ..relay_only(&front.url, &front.ca_roots)
        },
        2,
        false,
    )
    .await;
    let outcome = dial(&client, route.clone()).await;
    assert!(
        outcome.is_err(),
        "no path reaches the host while the proxy is stopped"
    );
    assert_eq!(
        front.accepted(),
        0,
        "and the relay was never reached around the proxy"
    );
    client.endpoint.close().await;

    let unproxied = support::side(&relay_only(&front.url, &front.ca_roots), 3, false).await;
    let accepting = accept_one(&host);
    let connection = dial(&unproxied, route)
        .await
        .expect("without a proxy the relay carries the connection");
    let accepted = accepting.await.expect("the host task");
    assert_eq!(accepted.remote_id(), unproxied.endpoint.id());
    assert!(front.accepted() > 0, "through the front");

    drop(connection);
    unproxied.endpoint.close().await;
    host.endpoint.close().await;
}

/// Everything the endpoint's lookup services found for `id`, once each has answered.
async fn found(endpoint: &Endpoint, id: EndpointId) -> Vec<iroh::address_lookup::Item> {
    let services = endpoint.address_lookup().expect("the lookup services");
    let answers = services.resolve(id).collect::<Vec<_>>();
    tokio::time::timeout(PATIENCE, answers)
        .await
        .expect("every selected service answers in time")
        .into_iter()
        .filter_map(|answer| answer.ok()?.ok())
        .collect()
}

/// Resolves `id` through `endpoint` until an answer satisfies `wanted`, and returns it.
///
/// An endpoint publishes whenever its addresses change, so its first record can predate the
/// address a test looks for.
async fn found_until(
    endpoint: &Endpoint,
    id: EndpointId,
    wanted: impl Fn(&iroh::address_lookup::Item) -> bool,
) -> iroh::address_lookup::Item {
    let deadline = Instant::now() + PATIENCE;
    loop {
        if let Some(item) = found(endpoint, id).await.into_iter().find(&wanted) {
            return item;
        }
        assert!(Instant::now() < deadline, "no record as wanted resolved");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Waits until `check` holds, or fails the test saying what did not happen.
async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !check() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The child half of [`no_proxy_variable_moves_a_request_of_the_endpoint`].
///
/// It is ignored in an ordinary run because it means nothing without the environment the other
/// test builds around it, and that test runs it by name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "no_proxy_variable_moves_a_request_of_the_endpoint runs this one"]
async fn the_child_of_the_proxy_variable_test() {
    let pkarr = PkarrRelay::spawn();

    // The control: iroh's own Pkarr resolver, the one the endpoint does not use, reads the proxy
    // variables and asks the address they name, which refuses it. That is what makes what follows
    // about the endpoint rather than about an environment nothing reads. A control that ran out of
    // time would prove nothing, so it has to be answered.
    let probe = support::side(
        &EndpointConfig {
            bind_addr: loopback(),
            ..EndpointConfig::default()
        },
        9,
        false,
    )
    .await;
    let control =
        PkarrResolver::builder(pkarr.url.clone()).build(probe.endpoint.tls_config().clone());
    let answer = tokio::time::timeout(PATIENCE, async {
        control
            .resolve(probe.endpoint.id())
            .expect("a lookup")
            .next()
            .await
    })
    .await
    .expect("the control is refused rather than left to wait");
    assert!(
        matches!(answer, Some(Err(_))),
        "the control went to the address the variables name: {answer:?}"
    );
    assert_eq!(pkarr.lookups(&probe.endpoint.id()), 0);
    probe.endpoint.close().await;

    // With no proxy selected, the endpoint's publisher and resolver reach the Pkarr relay directly.
    let direct = EndpointConfig {
        discovery: DiscoveryConfig {
            pkarr_publisher_url: Some(pkarr.url.clone()),
            pkarr_resolver_url: Some(pkarr.url.clone()),
            publisher: PublisherPolicy {
                published_addresses: PublishedAddresses::RelayAndDirect,
                ..PublisherPolicy::default()
            },
            ..DiscoveryConfig::default()
        },
        bind_addr: loopback(),
        ..EndpointConfig::default()
    };
    let host = support::side(&direct, 1, true).await;
    let host_id = host.endpoint.id();
    eventually("the host publishes to the Pkarr relay directly", || {
        pkarr.publications(&host_id) > 0
    })
    .await;
    let peer = support::side(&direct, 2, false).await;
    let item = found_until(&peer.endpoint, host_id, |item| {
        item.ip_addrs().next().is_some()
    })
    .await;
    assert_eq!(item.provenance(), "pkarr");
    assert!(pkarr.lookups(&host_id) > 0, "resolved from the Pkarr relay");
    peer.endpoint.close().await;
    host.endpoint.close().await;

    // With a proxy selected, every client of the endpoint uses that proxy: the relay connection
    // and the relay probes, which tunnel to the relay through it, and the publisher and resolver,
    // whose requests it forwards. None of them uses the one the variables name.
    let relay = LocalRelay::spawn().await;
    let selected = HttpProxy::forwarding();
    let proxied = EndpointConfig {
        discovery: DiscoveryConfig {
            pkarr_publisher_url: Some(pkarr.url.clone()),
            pkarr_resolver_url: Some(pkarr.url.clone()),
            ..DiscoveryConfig::default()
        },
        proxy_url: Some(selected.url.clone()),
        ..relay_only(&relay.url, &relay.ca_roots)
    };
    let host = support::side(&proxied, 3, true).await;
    let host_id = host.endpoint.id();
    online(
        &host,
        "the host reaches its relay through the selected proxy",
    )
    .await;
    let peer = support::side(&proxied, 4, false).await;
    found_until(&peer.endpoint, host_id, |item| {
        item.relay_urls().any(|url| *url == relay.url)
    })
    .await;
    let record = format!("{}/{}", pkarr.url, host_id.to_z32());
    let asked = selected.asked();
    for (method, target) in [
        ("CONNECT", authority(&relay.url)),
        ("PUT", record.clone()),
        ("GET", record),
    ] {
        assert!(
            asked
                .iter()
                .any(|asked| asked.method == method && asked.target == target),
            "{method} {target} went through the selected proxy: {asked:?}"
        );
    }
    peer.endpoint.close().await;
    host.endpoint.close().await;
}

/// KR-REQ-10.02, KR-REQ-26.14: the proxy variables other programs follow move no request of the
/// endpoint's. In a process whose `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` name an address that
/// counts each connection and drops it, the endpoint's Pkarr publisher and resolver go to their
/// server directly, and with a proxy selected every client of the endpoint uses that proxy. The
/// address the variables name is reached once, by the control: iroh's own Pkarr resolver, built
/// the ordinary way, which is what the endpoint would otherwise have used.
#[tokio::test]
async fn no_proxy_variable_moves_a_request_of_the_endpoint() {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("an address").port();
    let reached = Arc::new(Mutex::new(0_usize));
    let counted = Arc::clone(&reached);
    let listening = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            *counted.lock().unwrap_or_else(PoisonError::into_inner) += 1;
            drop(stream);
        }
    });

    // The environment belongs to a process, so the case is exercised in one of its own.
    let proxy = format!("http://127.0.0.1:{port}");
    let binary = std::env::current_exe().expect("this test binary");
    let ran = tokio::task::spawn_blocking(move || {
        std::process::Command::new(binary)
            .args([
                "--exact",
                "--ignored",
                "--nocapture",
                "the_child_of_the_proxy_variable_test",
            ])
            .env("HTTP_PROXY", &proxy)
            .env("HTTPS_PROXY", &proxy)
            .env("ALL_PROXY", &proxy)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .current_dir(std::env::temp_dir())
            .output()
            .expect("the child")
    })
    .await
    .expect("the child");
    listening.abort();

    assert!(
        ran.status.success(),
        "{}{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("1 passed"),
        "the child ran: {}",
        String::from_utf8_lossy(&ran.stdout)
    );
    assert_eq!(
        *reached.lock().unwrap_or_else(PoisonError::into_inner),
        1,
        "the control went to the address the variables name, and nothing of the endpoint's did"
    );
}
