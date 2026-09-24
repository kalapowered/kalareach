//! Discovery and relay selection, against relay servers and a Pkarr relay in this process.
//!
//! Section 17 puts three rules on how an endpoint is found. It reaches exactly the services its
//! configuration selects and inherits nothing from a preset or a public default. Its public record
//! names its relay and never its direct addresses, which travel through pairing and over the
//! authenticated connection instead. And an address hint a device holds from pairing is not a
//! permanent route: when the host has moved, the device resolves the identity it pinned again.
//!
//! Everything here is real iroh on loopback, with endpoints this crate builds from a configuration
//! the way a host and a device build theirs.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt as _;
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, TransportAddr};
use kr_protocol::hello::ALPN;
use kr_transport::clock::ManualClock;
use kr_transport::config::{DiscoveryConfig, EndpointConfig, PublishedAddresses};
use kr_transport::handshake::{self, Admitted};
use support::pkarr::PkarrRelay;
use support::{LocalRelay, OneDevice, Side, side, side_with};
use tokio::task::JoinHandle;

/// How long a test waits for something the machine has to do before it calls it a failure.
const PATIENCE: Duration = Duration::from_secs(20);

fn loopback() -> Option<SocketAddr> {
    Some("127.0.0.1:0".parse().expect("a loopback address"))
}

/// Waits until `check` holds, or fails the test saying what did not happen.
async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !check() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// One answer a resolution produced: the service that gave it and the addresses it named.
#[derive(Debug)]
struct Answer {
    service: &'static str,
    relays: Vec<RelayUrl>,
    direct: Vec<SocketAddr>,
}

/// Everything an endpoint's selected services answer about one identity, until each has answered.
///
/// A service that finds nothing is a failure in the stream rather than an absence from it, so the
/// failures are the evidence of which services were asked as much as the answers are.
async fn resolve(endpoint: &Endpoint, id: EndpointId) -> (Vec<Answer>, Vec<String>) {
    let mut answers = Vec::new();
    let mut failures = Vec::new();
    let services = endpoint.address_lookup().expect("the lookup services");
    let mut stream = std::pin::pin!(services.resolve(id));
    let collecting = async {
        while let Some(answer) = stream.next().await {
            match answer {
                Ok(Ok(item)) => answers.push(Answer {
                    service: item.provenance(),
                    relays: item.relay_urls().cloned().collect(),
                    direct: item.ip_addrs().copied().collect(),
                }),
                Ok(Err(failure)) => failures.push(failure.to_string()),
                Err(nothing) => failures.push(nothing.to_string()),
            }
        }
    };
    tokio::time::timeout(PATIENCE, collecting)
        .await
        .expect("every selected service answers in time");
    (answers, failures)
}

/// Resolves `id` through `endpoint` until the record names `relay`, and returns that answer.
///
/// An endpoint publishes whenever its addresses change, and its first record can predate its home
/// relay, so the record is read again until it names the relay or the patience runs out.
async fn resolve_naming(endpoint: &Endpoint, id: EndpointId, relay: &RelayUrl) -> Answer {
    let deadline = Instant::now() + PATIENCE;
    loop {
        let (answers, failures) = resolve(endpoint, id).await;
        if let Some(answer) = answers
            .into_iter()
            .find(|answer| answer.relays.contains(relay))
        {
            return answer;
        }
        assert!(
            Instant::now() < deadline,
            "no record naming {relay} could be resolved: {failures:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Accepts one connection on the host and authorises it against the one device it paired.
fn accept_paired(
    host: &Side,
    device: &Side,
) -> JoinHandle<(Connection, kr_transport::Result<Admitted>)> {
    let endpoint = host.endpoint.clone();
    let identity = Arc::clone(&host.identity);
    let directory = OneDevice {
        endpoint_id: device.record.endpoint_id,
        record: device.record,
    };
    tokio::spawn(async move {
        let connection = endpoint
            .accept()
            .await
            .expect("an incoming connection")
            .await
            .expect("a connection");
        let challenges = support::ledger();
        let issuer = support::windows(&ManualClock::new());
        let admitted = handshake::accept(
            &connection,
            &identity,
            support::epochs(),
            &directory,
            &challenges,
            &issuer,
        )
        .await;
        (connection, admitted)
    })
}

/// KR-REQ-17.43: an endpoint is built from the minimal preset with the selected relay map, Pkarr
/// publisher, Pkarr resolver and DNS lookup added by name, and nothing else. Its home relay is the
/// selected relay and no public relay is in its map; its signed record reaches the selected Pkarr
/// relay; a peer with the same selection resolves it through the selected Pkarr relay and asks the
/// DNS lookup under the selected origin, and no other service answers; and no public publisher or
/// resolver, local discovery or Mainline DHT is among its services.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_endpoint_reaches_exactly_the_relay_pkarr_and_dns_services_it_selected() {
    const ORIGIN: &str = "discovery.kalareach.test";
    let relay = LocalRelay::spawn().await;
    let pkarr = PkarrRelay::spawn();
    let selection = EndpointConfig {
        relay_urls: vec![relay.url.clone()],
        discovery: DiscoveryConfig {
            pkarr_publisher_url: Some(pkarr.url.clone()),
            pkarr_resolver_url: Some(pkarr.url.clone()),
            dns_origin: Some(ORIGIN.to_owned()),
            ..DiscoveryConfig::default()
        },
        bind_addr: loopback(),
        relay_ca_roots: relay.ca_roots.clone(),
        ..EndpointConfig::default()
    };
    assert!(
        !selection.discovery.local_discovery && !selection.discovery.mainline_dht,
        "neither local discovery nor the Mainline DHT is selected"
    );
    let host = side(&selection, 1, true).await;
    let peer = side(&selection, 2, false).await;

    // Three services, and they are the three this selection names: a publisher, a resolver and a
    // DNS lookup. The minimal preset brings none of its own, and there is no local discovery and
    // no DHT because neither was selected.
    for endpoint in [&host.endpoint, &peer.endpoint] {
        assert_eq!(
            endpoint
                .address_lookup()
                .expect("the lookup services")
                .len(),
            3
        );
    }

    // The relay map: the home relay is the selected relay.
    tokio::time::timeout(PATIENCE, host.endpoint.online())
        .await
        .expect("the host reaches the relay it selected");
    assert_eq!(
        host.endpoint
            .addr()
            .relay_urls()
            .cloned()
            .collect::<Vec<_>>(),
        vec![relay.url.clone()],
        "the home relay is the selected one"
    );

    // The publisher: the signed record reaches the selected Pkarr relay.
    eventually("the record reaches the selected Pkarr relay", || {
        pkarr.holds(&host.endpoint.id())
    })
    .await;
    let reader = side(
        &EndpointConfig {
            discovery: DiscoveryConfig {
                pkarr_resolver_url: Some(pkarr.url.clone()),
                ..DiscoveryConfig::default()
            },
            bind_addr: loopback(),
            ..EndpointConfig::default()
        },
        3,
        false,
    )
    .await;
    resolve_naming(&reader.endpoint, host.endpoint.id(), &relay.url).await;

    // The resolvers: everything the peer's services say about the host. The Pkarr resolver answers
    // from the selected relay with the host's record, the DNS lookup is asked and finds nothing
    // because the test's origin is served by no name server, and nothing else is asked at all.
    let (answers, failures) = resolve(&peer.endpoint, host.endpoint.id()).await;
    assert_eq!(answers.len(), 1, "one service found the host: {answers:?}");
    assert_eq!(answers[0].service, "pkarr");
    assert_eq!(answers[0].relays, vec![relay.url.clone()]);
    assert_eq!(
        failures,
        vec!["Service 'dns' failed".to_owned()],
        "the only other service asked is the DNS lookup"
    );

    // The DNS lookup asks the machine's own name servers, which a test cannot point at a server of
    // its own, so its origin is read from the service itself. Nothing among the services names the
    // public n0 infrastructure, whose DNS origin, Pkarr relay and relays all sit under iroh.link.
    let described = format!(
        "{:?}",
        host.endpoint.address_lookup().expect("the lookup services")
    );
    assert!(
        described.contains(&format!("origin_domain: {ORIGIN:?}")),
        "the DNS lookup asks under the selected origin: {described}"
    );
    assert!(
        !described.contains("iroh.link"),
        "no public discovery service is configured: {described}"
    );

    // No public relay is in the map. Removing a relay returns its configuration when it was there,
    // which the selected relay shows last.
    for public in [
        iroh::defaults::prod::default_relay_map(),
        iroh::defaults::staging::default_relay_map(),
    ] {
        for url in public.urls::<Vec<_>>() {
            assert!(
                host.endpoint.remove_relay(&url).await.is_none(),
                "the public relay {url} is not in the map"
            );
        }
    }
    assert!(
        host.endpoint.remove_relay(&relay.url).await.is_some(),
        "the selected relay is"
    );

    reader.endpoint.close().await;
    peer.endpoint.close().await;
    host.endpoint.close().await;
}

/// KR-REQ-17.45: a host's direct addresses stay out of its public record and reach a device over
/// the authenticated connection instead. The host has direct addresses and selects a relay and a
/// Pkarr publisher under the default publication rules. The signed record anybody can read from the
/// Pkarr relay names the relay and none of the direct addresses; a device that knows only the
/// host's identity resolves that record, connects through the relay, and the connection then opens
/// a direct path to the host that the record never carried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_public_record_names_the_relay_and_never_a_direct_address() {
    let relay = LocalRelay::spawn().await;
    let pkarr = PkarrRelay::spawn();
    let selection = EndpointConfig {
        relay_urls: vec![relay.url.clone()],
        discovery: DiscoveryConfig {
            pkarr_publisher_url: Some(pkarr.url.clone()),
            pkarr_resolver_url: Some(pkarr.url.clone()),
            ..DiscoveryConfig::default()
        },
        bind_addr: loopback(),
        relay_ca_roots: relay.ca_roots.clone(),
        ..EndpointConfig::default()
    };
    assert_eq!(
        selection.discovery.publisher.published_addresses,
        PublishedAddresses::RelayOnly
    );
    let host = side(&selection, 1, true).await;
    let direct = host.endpoint.bound_sockets();
    assert!(!direct.is_empty(), "the host has direct addresses to keep");
    tokio::time::timeout(PATIENCE, host.endpoint.online())
        .await
        .expect("the host reaches its relay");

    let device = side(&selection, 2, false).await;
    let record = resolve_naming(&device.endpoint, host.endpoint.id(), &relay.url).await;
    assert_eq!(record.relays, vec![relay.url.clone()]);
    assert!(
        record.direct.is_empty(),
        "the public record carries no direct address: {:?}",
        record.direct
    );

    // The device dials the identity alone. What it knows of the host is the record it resolved,
    // which names the relay; the handshake then authenticates the host it reached.
    let accepting = accept_paired(&host, &device);
    let connection = tokio::time::timeout(
        PATIENCE,
        device
            .endpoint
            .connect(EndpointAddr::new(host.endpoint.id()), ALPN),
    )
    .await
    .expect("the device reaches the host in time")
    .expect("a connection");
    handshake::connect(&connection, &device.identity, &host.record)
        .await
        .expect("the host is the one the device paired with");
    let (_host_side, admitted) = accepting.await.expect("the host task");
    assert!(matches!(
        admitted.expect("an admitted connection"),
        Admitted::Authorised(_)
    ));

    // The connection learns a direct path to the host from the host itself, inside the encrypted
    // connection: none of the host's direct addresses was in anything the device could look up.
    eventually("the connection opens a direct path to the host", || {
        connection.paths().iter().any(
            |path| matches!(path.remote_addr(), TransportAddr::Ip(addr) if direct.contains(addr)),
        )
    })
    .await;

    device.endpoint.close().await;
    host.endpoint.close().await;
}

/// KR-REQ-17.45: a hint from pairing is not a permanent route. A device pairs while the host's
/// home relay is one relay and keeps the bundle that says so, current relay and all. The host then
/// moves to another relay and the bundle is stale. Dialling with that bundle, the device resolves
/// the host's pinned identity again through the Pkarr relay the bundle selected, reaches the host
/// on its new relay, and authenticates it against the record it paired with.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_with_a_stale_bundle_resolves_the_pinned_host_again_on_its_new_relay() {
    let first = LocalRelay::spawn().await;
    let second = LocalRelay::spawn().await;
    let pkarr = PkarrRelay::spawn();
    // Private trust anchors for the two relays in this process. A deployment's relays present
    // publicly issued certificates, and a device needs nothing from the bundle to trust them.
    let anchors: Vec<Vec<u8>> = first
        .ca_roots
        .iter()
        .chain(&second.ca_roots)
        .cloned()
        .collect();
    // The relay is the host's only route, so the only way to reach it is through the relay it is
    // on now.
    let hosted_on = |relay: &RelayUrl| EndpointConfig {
        relay_urls: vec![relay.clone()],
        discovery: DiscoveryConfig {
            pkarr_publisher_url: Some(pkarr.url.clone()),
            pkarr_resolver_url: Some(pkarr.url.clone()),
            ..DiscoveryConfig::default()
        },
        relay_only: true,
        relay_ca_roots: anchors.clone(),
        ..EndpointConfig::default()
    };

    let host = side(&hosted_on(&first.url), 1, true).await;
    tokio::time::timeout(PATIENCE, host.endpoint.online())
        .await
        .expect("the host reaches its first relay");
    // What pairing handed the device: the host's selection with its current relay.
    let bundle = hosted_on(&first.url)
        .to_network_config()
        .expect("the host's network configuration");
    assert_eq!(
        bundle
            .relay_urls
            .iter()
            .map(|hint| hint.as_str().to_owned())
            .collect::<Vec<_>>(),
        vec![first.url.to_string()],
        "the bundle carries the host's current relay"
    );

    // The device builds its endpoint from the bundle, and dials from the bundle.
    let from_bundle = EndpointConfig {
        relay_ca_roots: anchors.clone(),
        bind_addr: loopback(),
        ..EndpointConfig::from_network_config(&bundle).expect("a usable bundle")
    };
    let device = side(&from_bundle, 2, false).await;
    let hinted = from_bundle
        .peer_addr(&host.record.endpoint_id)
        .expect("an address from the bundle");

    let accepting = accept_paired(&host, &device);
    let connection = tokio::time::timeout(PATIENCE, device.endpoint.connect(hinted.clone(), ALPN))
        .await
        .expect("the device reaches the host in time")
        .expect("a connection while the bundle is current");
    handshake::connect(&connection, &device.identity, &host.record)
        .await
        .expect("the paired host");
    accepting.await.expect("the host task").1.expect("admitted");
    connection.close(0_u32.into(), b"done");

    // The host moves to the second relay, keeping its identity, and publishes where it is now.
    let Side { keys, endpoint, .. } = host;
    endpoint.close().await;
    let host = side_with(&hosted_on(&second.url), keys, 1, true).await;
    tokio::time::timeout(PATIENCE, host.endpoint.online())
        .await
        .expect("the host reaches its second relay");
    let reader = side(
        &EndpointConfig {
            discovery: DiscoveryConfig {
                pkarr_resolver_url: Some(pkarr.url.clone()),
                ..DiscoveryConfig::default()
            },
            bind_addr: loopback(),
            ..EndpointConfig::default()
        },
        3,
        false,
    )
    .await;
    resolve_naming(&reader.endpoint, host.endpoint.id(), &second.url).await;

    // The bundle is stale: it names the first relay, and the host is on the second alone.
    assert_eq!(
        hinted.relay_urls().cloned().collect::<Vec<_>>(),
        vec![first.url.clone()]
    );
    assert_eq!(
        host.endpoint
            .addr()
            .relay_urls()
            .cloned()
            .collect::<Vec<_>>(),
        vec![second.url.clone()]
    );

    // Dialled with the stale bundle, the device finds the host where it is now, and the host it
    // finds is the one it paired with.
    let accepting = accept_paired(&host, &device);
    let connection = tokio::time::timeout(PATIENCE, device.endpoint.connect(hinted, ALPN))
        .await
        .expect("the device reaches the moved host in time")
        .expect("a connection with a stale bundle");
    let authorised = handshake::connect(&connection, &device.identity, &host.record)
        .await
        .expect("the moved host is the paired host");
    assert_eq!(authorised.peer_device_id, host.record.device_id);
    let (_host_side, admitted) = accepting.await.expect("the host task");
    assert!(matches!(
        admitted.expect("an admitted connection"),
        Admitted::Authorised(_)
    ));

    reader.endpoint.close().await;
    device.endpoint.close().await;
    host.endpoint.close().await;
}
