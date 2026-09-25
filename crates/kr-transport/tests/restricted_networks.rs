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
use iroh::endpoint::RelayStatus;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, TransportAddr, Watcher as _};
use kr_protocol::error::ErrorCode;
use kr_transport::config::{DiscoveryConfig, EndpointConfig, PublishedAddresses, PublisherPolicy};
use kr_transport::{ALPN, TransportError};
use support::front::RelayFront;
use support::pkarr::PkarrRelay;
use support::proxy::{HttpProxy, authority};
use support::{LocalRelay, Side};
use tokio::task::JoinHandle;

/// How long anything the machine has to do may take before the test calls it a failure.
const PATIENCE: Duration = Duration::from_secs(60);

/// How soon an endpoint with nothing but relays it cannot use learns that it cannot connect.
///
/// A third of the attempt's own 30-second deadline: a failure inside it was decided by what the
/// relay status said, not by the attempt running out.
const AT_ONCE: Duration = Duration::from_secs(10);

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

/// Whether `error`, or anything it wraps, is a connection the other side refused.
fn refused_connection(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::ConnectionRefused)
        {
            return true;
        }
        current = error.source();
    }
    false
}

/// Waits until `side` is off its home relay `relay` and its latest attempt to reach the relay again
/// ended at a refused connection, other than `seen`, and returns the status that said so.
async fn until_refused_again(
    side: &Side,
    relay: &RelayUrl,
    seen: Option<&RelayStatus>,
) -> RelayStatus {
    let deadline = Instant::now() + PATIENCE;
    let mut statuses = side.endpoint.home_relay_status();
    loop {
        let refused = statuses.get().into_iter().find(|status| {
            status.url() == relay
                && !status.is_connected()
                && status
                    .last_error()
                    .is_some_and(|error| refused_connection(error))
                && Some(status) != seen
        });
        if let Some(status) = refused {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "the relay status never recorded a refused connection: {:?}",
            statuses.get()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// KR-REQ-10.02: a network that requires a proxy. A relay-only host and client each select the
/// proxy, reach the relay through it and connect to each other, and every tunnel the proxy opened
/// was to the relay's own address. Both relay sessions ran through the proxy: stopping it takes
/// each endpoint off the relay, and its next attempt to reach the relay is refused at the proxy's
/// closed port.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_only_pair_connects_through_the_proxy_it_selected() {
    let relay = LocalRelay::spawn().await;
    let mut proxy = HttpProxy::forwarding();
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
        tunnels.contains(&relay_address),
        "the proxy was asked for the relay: {tunnels:?}"
    );
    assert!(
        tunnels.iter().all(|tunnel| *tunnel == relay_address),
        "and for nothing else: {tunnels:?}"
    );

    proxy.stop();
    for side in [&host, &client] {
        until_refused_again(side, &relay.url, None).await;
    }

    drop(connection);
    client.endpoint.close().await;
    host.endpoint.close().await;
}

/// KR-REQ-10.02: a selected proxy is the only way to the relay, and nothing falls back to a direct
/// connection when it stops. A relay-only client reaches its relay through the proxy, and the
/// proxy reaches the relay through a front that counts every connection, so a connection to the
/// relay from anywhere is one the front counted. Once the proxy stops, the client's relay status
/// records its connection to the proxy refused, attempt after attempt, and no connection reaches
/// the front meanwhile: the client never goes around its proxy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_whose_proxy_stops_never_goes_around_it() {
    let relay = LocalRelay::spawn().await;
    let front = RelayFront::passing(&relay);
    let host = support::side(&relay_only(&relay.url, &relay.ca_roots), 1, true).await;
    online(&host, "the host reaches its relay").await;

    let mut proxy = HttpProxy::forwarding();
    let client = support::side(
        &EndpointConfig {
            proxy_url: Some(proxy.url.clone()),
            ..relay_only(&front.url, &front.ca_roots)
        },
        2,
        false,
    )
    .await;
    online(&client, "the client reaches its relay through the proxy").await;
    let accepting = accept_one(&host);
    let connection = dial(
        &client,
        EndpointAddr::new(host.endpoint.id()).with_relay_url(front.url.clone()),
    )
    .await
    .expect("the relay carries the connection through the proxy");
    let accepted = accepting.await.expect("the host task");
    assert_eq!(accepted.remote_id(), client.endpoint.id());
    assert!(
        proxy.tunnels().contains(&authority(&front.url)),
        "{:?}",
        proxy.tunnels()
    );

    proxy.stop();
    let refused = until_refused_again(&client, &front.url, None).await;
    let reached = front.accepted();
    // The client keeps trying to reach its relay, each time at the proxy.
    until_refused_again(&client, &front.url, Some(&refused)).await;
    assert_eq!(
        front.accepted(),
        reached,
        "no connection reached the relay around the stopped proxy"
    );

    drop(connection);
    client.endpoint.close().await;
    host.endpoint.close().await;
}

/// KR-REQ-10.02: a network that blocks the WebSocket upgrade does not stand in the way of a direct
/// path. The relay's front passes ordinary requests to the relay and answers the relay connection's
/// upgrade with 403, so neither endpoint gets onto the relay; the client still reaches the host at
/// the host's direct address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_upgrade_leaves_a_direct_path_open() {
    let relay = LocalRelay::spawn().await;
    let front = RelayFront::refusing_upgrades(&relay, 403);
    let config = EndpointConfig {
        relay_urls: vec![front.url.clone()],
        relay_ca_roots: front.ca_roots.clone(),
        bind_addr: loopback(),
        ..EndpointConfig::default()
    };
    let host = support::side(&config, 1, true).await;
    let client = support::side(&config, 2, false).await;
    eventually("the relay connection's upgrade is refused", || {
        front.refused_upgrades() > 0
    })
    .await;

    let accepting = accept_one(&host);
    let mut route = EndpointAddr::new(host.endpoint.id()).with_relay_url(front.url.clone());
    for socket in host.endpoint.bound_sockets() {
        route = route.with_ip_addr(socket);
    }
    let connection = dial(&client, route)
        .await
        .expect("the direct path carries the connection");
    let accepted = accepting.await.expect("the host task");
    assert_eq!(accepted.remote_id(), client.endpoint.id());
    assert!(
        connection
            .paths()
            .iter()
            .any(|path| matches!(path.remote_addr(), TransportAddr::Ip(_))),
        "the connection runs on a direct path"
    );

    drop(connection);
    client.endpoint.close().await;
    host.endpoint.close().await;
}

/// KR-REQ-10.02: a network that blocks the WebSocket upgrade, for an endpoint whose only path is
/// the relay. The relay-only client stands for a network that blocks UDP as well. The front passes
/// the relay latency probe, so the client makes the relay its home and tries to connect to it, and
/// answers the upgrade with 403. The attempt to reach the host ends at once rather than at its
/// deadline, in a connection failure that names the relay and says the network refused the upgrade
/// with status 403: `RESOURCE_UNAVAILABLE` on the wire, and never the relay's own refusal, because
/// the relay never answered. The same client reaches the host through a front that lets the
/// upgrade through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_only_attempt_whose_upgrade_is_refused_says_so() {
    let relay = LocalRelay::spawn().await;
    let host = support::side(&relay_only(&relay.url, &relay.ca_roots), 1, true).await;
    online(&host, "the host reaches its relay").await;

    let blocking = RelayFront::refusing_upgrades(&relay, 403);
    let client = support::side(&relay_only(&blocking.url, &blocking.ca_roots), 2, false).await;
    let started = Instant::now();
    let error = dial(
        &client,
        EndpointAddr::new(host.endpoint.id()).with_relay_url(blocking.url.clone()),
    )
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
            blocking.url
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
    assert!(blocking.refused_upgrades() > 0);
    client.endpoint.close().await;

    let passing = RelayFront::passing(&relay);
    let unblocked = support::side(&relay_only(&passing.url, &passing.ca_roots), 3, false).await;
    let accepting = accept_one(&host);
    let connection = dial(
        &unblocked,
        EndpointAddr::new(host.endpoint.id()).with_relay_url(passing.url.clone()),
    )
    .await
    .expect("with the upgrade let through the relay carries the connection");
    let accepted = accepting.await.expect("the host task");
    assert_eq!(accepted.remote_id(), unblocked.endpoint.id());

    drop(connection);
    unblocked.endpoint.close().await;
    host.endpoint.close().await;
}

/// KR-REQ-10.02: a network that alters certificate trust. A proxy that intercepts TLS answers for
/// the relay with a certificate its own authority issued. A client that trusts only the relay's
/// own anchor refuses it: the relay handshake its TLS configuration makes through the proxy fails
/// certificate validation as `UnknownIssuer`, and the client never gets onto the relay. With the
/// proxy's authority named among its trust anchors, as an owner names one in
/// `network.relay_trust_anchors`, the same kind of client reaches the relay through the proxy and
/// connects to the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_intercepting_proxy_is_trusted_only_when_its_authority_is_named() {
    let relay = LocalRelay::spawn().await;
    let host = support::side(&relay_only(&relay.url, &relay.ca_roots), 1, true).await;
    online(&host, "the host reaches its relay").await;
    let proxy = HttpProxy::intercepting(&relay.ca_roots);
    let through_proxy = |ca_roots: Vec<Vec<u8>>| EndpointConfig {
        proxy_url: Some(proxy.url.clone()),
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
        .proxy_url(proxy.url.as_url().clone())
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
    // The trusting client below is on the relay through the same proxy within a second or two.
    assert!(
        tokio::time::timeout(AT_ONCE, untrusting.endpoint.online())
            .await
            .is_err(),
        "a client that does not trust the proxy's authority never gets onto the relay"
    );
    untrusting.endpoint.close().await;

    let trusting = support::side(
        &through_proxy([relay.ca_roots.clone(), proxy.ca_roots.clone()].concat()),
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
    assert!(
        proxy.tunnels().contains(&authority(&relay.url)),
        "{:?}",
        proxy.tunnels()
    );

    drop(connection);
    trusting.endpoint.close().await;
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
            // With it set, as in a CGI program, every proxy variable is ignored.
            .env_remove("REQUEST_METHOD")
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
