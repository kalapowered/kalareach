//! The device's one endpoint: its relays and lookups come from the hosts it dials, one host at a
//! time, and no rule of the endpoint refuses, closes or restarts one host's connection on account
//! of a request for another.
//!
//! Every relay is a real `iroh-relay` server in this process and every host and device is a real
//! iroh endpoint on the loopback. Every wait ends on a state that the case names: an answer, a
//! count, a report that holds a relay. The patience below is how long a state may take before the
//! case calls it a failure, never a time that anything is expected to take.

mod support;

use std::collections::BTreeSet;
use std::time::Duration;

use futures::StreamExt as _;
use iroh::address_lookup::{AddressLookupFailed, Error as LookupError, Item};
use iroh::endpoint::{Connection, VarInt};
use iroh::unstable_net_report::NetReport;
use iroh::{Endpoint, EndpointId, RelayUrl, TransportAddr, Watcher as _};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::scalars::EndpointKey;
use kr_transport::config::{DiscoveryConfig, EndpointConfig};
use kr_transport::dialler::{DeviceEndpoint, HostServices};
use kr_transport::{ALPN, TransportError};
use support::dns::NameServer;
use support::front::RelayFront;
use support::pkarr::PkarrRelay;
use support::proxy::HttpProxy;
use support::{LocalRelay, Side};
use tokio::task::JoinHandle;

/// How long a state may take before the case calls it a failure.
const PATIENCE: Duration = Duration::from_secs(60);

/// How long a net report may take to hold the relays that a case waits for, counted from the
/// start of the wait. The case with two such waits takes about 35 seconds on an idle machine, so
/// this is more than three times that, for a loaded one; it is still how long the case lets a
/// report be missing a relay before it calls the relay missing.
const REPORT_PATIENCE: Duration = Duration::from_secs(120);

/// How often a case looks at a count that no future announces.
const LOOK: Duration = Duration::from_millis(50);

fn loopback() -> Option<std::net::SocketAddr> {
    Some("127.0.0.1:0".parse().expect("a loopback address"))
}

/// A host that answers every stream with its label.
struct Host {
    side: Side,
    serving: JoinHandle<()>,
}

impl Host {
    /// A host that a relay alone reaches.
    async fn on(relay: &LocalRelay, label: &'static str, byte: u8) -> Self {
        let config = EndpointConfig {
            relay_urls: vec![relay.url.clone()],
            relay_ca_roots: relay.ca_roots.clone(),
            relay_only: true,
            ..EndpointConfig::default()
        };
        let host = Self::start(&config, label, byte).await;
        tokio::time::timeout(PATIENCE, host.side.endpoint.online())
            .await
            .expect("the host reaches its relay");
        host
    }

    /// A host that only its direct addresses on the loopback reach.
    async fn direct(label: &'static str, byte: u8) -> Self {
        let config = EndpointConfig {
            bind_addr: loopback(),
            ..EndpointConfig::default()
        };
        Self::start(&config, label, byte).await
    }

    async fn start(config: &EndpointConfig, label: &'static str, byte: u8) -> Self {
        let side = support::side(config, byte, true).await;
        let serving = serve(side.endpoint.clone(), label);
        Self { side, serving }
    }

    fn key(&self) -> EndpointKey {
        *self.side.keys.transport.public()
    }

    fn id(&self) -> EndpointId {
        self.side.endpoint.id()
    }

    /// What a device that paired with this host holds of it: the relays, and the direct addresses
    /// where the host has them.
    fn view(&self, relays: &[&RelayUrl]) -> EndpointConfig {
        EndpointConfig {
            relay_urls: relays.iter().map(|url| (*url).clone()).collect(),
            direct_addresses: if relays.is_empty() {
                support::direct_addr(&self.side)
                    .ip_addrs()
                    .copied()
                    .collect()
            } else {
                Vec::new()
            },
            ..EndpointConfig::default()
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// Answers every stream of every connection with `label`, once it has read the request.
fn serve(endpoint: Endpoint, label: &'static str) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                connection.set_max_concurrent_bi_streams(VarInt::from_u32(1024));
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    tokio::spawn(async move {
                        let _ = recv.read_to_end(1 << 20).await;
                        let _ = send.write_all(label.as_bytes()).await;
                        let _ = send.finish();
                    });
                }
            });
        }
    })
}

/// What the device's configuration is for a device that reaches `relays`' certificates.
fn device_config(relays: &[&LocalRelay], relay_only: bool) -> EndpointConfig {
    EndpointConfig {
        bind_addr: loopback(),
        relay_only,
        relay_ca_roots: relays
            .iter()
            .flat_map(|relay| relay.ca_roots.iter().cloned())
            .collect(),
        ..EndpointConfig::default()
    }
}

async fn device(relays: &[&LocalRelay], relay_only: bool) -> DeviceEndpoint {
    let keys = DeviceKeys::generate().expect("device keys");
    DeviceEndpoint::bind(&device_config(relays, relay_only), &keys.transport)
        .await
        .expect("the device's endpoint")
}

/// Dials `host` with the address that `view` gives it.
async fn dial(device: &DeviceEndpoint, view: &EndpointConfig, host: &Host) -> Connection {
    let address = view.peer_addr(&host.key()).expect("a host's address");
    tokio::time::timeout(
        PATIENCE,
        kr_transport::endpoint::connect(device.endpoint(), address, ALPN),
    )
    .await
    .expect("the attempt ends by itself")
    .expect("a connection to the host")
}

/// What `connection`'s peer answers on a new stream.
async fn answer(connection: &Connection) -> Result<String, String> {
    let (mut send, mut recv) = connection.open_bi().await.map_err(|e| e.to_string())?;
    send.write_all(b"?").await.map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    let label = recv.read_to_end(64).await.map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&label).into_owned())
}

async fn answered(connection: &Connection) -> String {
    tokio::time::timeout(PATIENCE, answer(connection))
        .await
        .expect("an answer comes")
        .expect("the peer answers")
}

/// The relays and the count of direct paths that `connection` has.
fn paths_of(connection: &Connection) -> (Vec<RelayUrl>, usize) {
    let mut relays = Vec::new();
    let mut direct = 0;
    for path in connection.paths().iter() {
        match path.remote_addr() {
            TransportAddr::Relay(url) => relays.push(url.clone()),
            TransportAddr::Ip(_) => direct += 1,
            _ => {}
        }
    }
    (relays, direct)
}

fn endpoint_id_of(key: &EndpointKey) -> EndpointId {
    EndpointId::from_bytes(key.as_bytes()).expect("an endpoint identity")
}

/// An identity that no host and no test endpoint owns.
fn stranger() -> (EndpointKey, EndpointId) {
    let key = *DeviceKeys::generate()
        .expect("device keys")
        .transport
        .public();
    (key, endpoint_id_of(&key))
}

/// What the endpoint's address-lookup registry yields for `id`, polled to its end.
async fn registry_yields(
    device: &DeviceEndpoint,
    id: EndpointId,
) -> Vec<Result<Result<Item, LookupError>, AddressLookupFailed>> {
    let registry = device
        .endpoint()
        .address_lookup()
        .expect("the endpoint's lookup registry");
    tokio::time::timeout(PATIENCE, registry.resolve(id).collect::<Vec<_>>())
        .await
        .expect("the lookup ends by itself")
}

/// Asserts that the registry gave no answer for `id`: exactly one item, the registry's "no
/// results" error with no error of any service behind it, and nothing after it.
async fn assert_registry_has_nothing_for(device: &DeviceEndpoint, id: EndpointId) {
    let yielded = registry_yields(device, id).await;
    assert_eq!(yielded.len(), 1, "one item and then the end");
    assert!(
        matches!(&yielded[0], Err(AddressLookupFailed::NoResults { errors, .. }) if errors.is_empty()),
        "the one item is a failure with no service's error behind it"
    );
}

/// Whether `report` holds a measurement of `relay`, which only an answered probe leaves.
fn measured(report: &NetReport, relay: &RelayUrl) -> bool {
    report
        .relay_latency
        .iter()
        .any(|(_, measured, _)| measured == relay)
}

/// Waits until the device's latest net report holds every relay in `relays`.
async fn until_reported(device: &DeviceEndpoint, relays: &[&RelayUrl]) {
    let mut report = device.endpoint().net_report();
    tokio::time::timeout(REPORT_PATIENCE, async {
        loop {
            if let Some(latest) = report.get()
                && relays.iter().all(|relay| measured(&latest, relay))
            {
                return;
            }
            report
                .updated()
                .await
                .expect("the device's endpoint is open");
        }
    })
    .await
    .expect("the device's net report holds the relays");
}

/// Waits until `reached` says that a count has been reached, looking at it every [`LOOK`].
async fn until(what: &str, mut reached: impl FnMut() -> bool) {
    tokio::time::timeout(PATIENCE, async {
        while !reached() {
            tokio::time::sleep(LOOK).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what} never came"));
}

fn paired(view: &EndpointConfig, host: &Host) -> HostServices {
    HostServices::paired(view, &host.key()).expect("a host's services")
}

fn invited(view: &EndpointConfig, host: &Host) -> HostServices {
    HostServices::invited(view, &host.key()).expect("a host's services")
}

/// KR-REQ-10.02: a relay that a host's address names is reached whatever the device's relay map
/// holds, so a host that was introduced as invited, with no relay in the map, is dialled through
/// its own relay, in the product's bind form and in the relay-only form.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_endpoint_dials_through_a_relay_that_its_map_does_not_hold() {
    let (r1, r2) = (LocalRelay::spawn().await, LocalRelay::spawn().await);
    let a = Host::on(&r1, "A", 1).await;
    let b = Host::on(&r2, "B", 2).await;
    let (view_a, view_b) = (a.view(&[&r1.url]), b.view(&[&r2.url]));

    for relay_only in [false, true] {
        let device = device(&[&r1, &r2], relay_only).await;
        device
            .introduce(invited(&view_a, &a))
            .await
            .expect("host A");
        device
            .introduce(invited(&view_b, &b))
            .await
            .expect("host B");

        let to_a = dial(&device, &view_a, &a).await;
        let to_b = dial(&device, &view_b, &b).await;
        assert_eq!(answered(&to_a).await, "A", "relay_only: {relay_only}");
        assert_eq!(answered(&to_b).await, "B", "relay_only: {relay_only}");

        assert_eq!(paths_of(&to_a), (vec![r1.url.clone()], 0));
        assert_eq!(paths_of(&to_b), (vec![r2.url.clone()], 0));
        assert!(
            device.relay_urls().is_empty(),
            "the map holds no relay of an invited host"
        );
        let me = device.endpoint().id();
        assert_eq!(r1.gate.admissions(&me), 1, "relay_only: {relay_only}");
        assert_eq!(r2.gate.admissions(&me), 1, "relay_only: {relay_only}");
        device.close().await;
    }
}

/// KR-REQ-10.02: an identity's lookups are asked about that identity alone. Two hosts have a
/// resolver and a DNS origin each; the name server and each Pkarr server are asked about their own
/// host and never the other's, and an identity that no host owns is asked about nowhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hosts_lookups_are_asked_about_that_host_alone() {
    let names = NameServer::spawn();
    let (p_a, p_b) = (PkarrRelay::spawn(), PkarrRelay::spawn());
    let (key_a, id_a) = stranger();
    let (key_b, id_b) = stranger();
    let (_, id_c) = stranger();

    let keys = DeviceKeys::generate().expect("device keys");
    let device =
        DeviceEndpoint::bind_asking(&device_config(&[], false), &keys.transport, names.address)
            .await
            .expect("the device's endpoint");
    let services = |origin: &str, resolver: &PkarrRelay, key: &EndpointKey| {
        let view = EndpointConfig {
            discovery: DiscoveryConfig {
                dns_origin: Some(origin.to_owned()),
                pkarr_resolver_url: Some(resolver.url.clone()),
                ..DiscoveryConfig::default()
            },
            ..EndpointConfig::default()
        };
        HostServices::paired(&view, key).expect("a host's services")
    };
    device
        .introduce(services("a.test", &p_a, &key_a))
        .await
        .expect("host A");
    device
        .introduce(services("b.test", &p_b, &key_b))
        .await
        .expect("host B");

    for id in [id_a, id_b] {
        let yielded = registry_yields(&device, id).await;
        assert!(
            yielded.iter().all(|item| !matches!(item, Ok(Ok(_)))),
            "no server holds a record, so nothing is found"
        );
    }
    let asked: BTreeSet<String> = names
        .asked()
        .into_iter()
        .map(|question| question.name)
        .collect();
    assert_eq!(
        asked,
        BTreeSet::from([
            format!("_iroh.{}.a.test", id_a.to_z32()),
            format!("_iroh.{}.b.test", id_b.to_z32()),
        ]),
        "each origin is asked about its own host and no other name is asked"
    );
    assert!(p_a.lookups(&id_a) >= 1 && p_b.lookups(&id_b) >= 1);
    assert_eq!(p_a.lookups(&id_b), 0, "A's server is never asked about B");
    assert_eq!(p_b.lookups(&id_a), 0, "B's server is never asked about A");

    let before = names.asked().len();
    assert_registry_has_nothing_for(&device, id_c).await;
    assert_eq!(
        names.asked().len(),
        before,
        "no name is asked for a stranger"
    );
    assert_eq!((p_a.lookups(&id_c), p_b.lookups(&id_c)), (0, 0));
    device.close().await;
}

/// KR-REQ-10.02: the device publishes nothing. A host's configuration names a Pkarr publisher, and
/// the device, which dials that host and has a home relay, publishes its record to none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_device_publishes_its_own_record_to_no_server() {
    let r1 = LocalRelay::spawn().await;
    let pkarr = PkarrRelay::spawn();
    let a = Host::direct("A", 1).await;

    // The control: an ordinary endpoint given the same publisher does publish, so a publication
    // that the device made would be counted here.
    let ordinary = support::side(
        &EndpointConfig {
            relay_urls: vec![r1.url.clone()],
            relay_ca_roots: r1.ca_roots.clone(),
            discovery: DiscoveryConfig {
                pkarr_publisher_url: Some(pkarr.url.clone()),
                ..DiscoveryConfig::default()
            },
            ..EndpointConfig::default()
        },
        9,
        false,
    )
    .await;
    until("the ordinary endpoint's publication", || {
        pkarr.holds(&ordinary.endpoint.id())
    })
    .await;

    let mut view = a.view(&[]);
    view.relay_urls = vec![r1.url.clone()];
    view.discovery = DiscoveryConfig {
        pkarr_publisher_url: Some(pkarr.url.clone()),
        pkarr_resolver_url: Some(pkarr.url.clone()),
        ..DiscoveryConfig::default()
    };
    let device = device(&[&r1], false).await;
    device.introduce(paired(&view, &a)).await.expect("host A");
    let to_a = dial(&device, &view, &a).await;
    assert_eq!(answered(&to_a).await, "A");
    assert!(paths_of(&to_a).1 >= 1, "the host is reached directly");

    let mut statuses = device.endpoint().home_relay_status();
    tokio::time::timeout(PATIENCE, async {
        while !statuses.get().iter().any(|status| status.is_connected()) {
            statuses
                .updated()
                .await
                .expect("the device's endpoint is open");
        }
    })
    .await
    .expect("the device has a home relay");

    let me = device.endpoint().id();
    assert_eq!(pkarr.publications(&me), 0, "the device published nothing");
    assert!(!pkarr.holds(&me));
    assert_eq!(pkarr.lookups(&me), 0, "nobody asked about the device");

    // The device's lookups go to this server for the host that owns them and for no other
    // identity: the server holds the ordinary endpoint's record, and the registry is asked about
    // that identity, which no host owns, as well as about the host.
    assert_registry_has_nothing_for(&device, ordinary.endpoint.id()).await;
    registry_yields(&device, a.id()).await;
    assert_eq!(
        pkarr.looked_up(),
        BTreeSet::from([a.id().to_z32()]),
        "the server was asked about the host and about no other identity"
    );
    device.close().await;
}

/// KR-REQ-10.02: one relay carries two hosts and a direct path a third, and nothing closes while
/// the device dials the next host.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_relay_carries_two_hosts_and_a_direct_path_a_third() {
    let r1 = LocalRelay::spawn().await;
    let a = Host::on(&r1, "A", 1).await;
    let b = Host::on(&r1, "B", 2).await;
    let c = Host::direct("C", 3).await;
    let (p_a, p_b, p_c) = (
        PkarrRelay::spawn(),
        PkarrRelay::spawn(),
        PkarrRelay::spawn(),
    );
    let (mut view_a, mut view_b, mut view_c) =
        (a.view(&[&r1.url]), b.view(&[&r1.url]), c.view(&[]));
    for (view, resolver) in [
        (&mut view_a, &p_a),
        (&mut view_b, &p_b),
        (&mut view_c, &p_c),
    ] {
        view.discovery.pkarr_resolver_url = Some(resolver.url.clone());
    }

    let device = device(&[&r1], false).await;
    for (view, host) in [(&view_a, &a), (&view_b, &b), (&view_c, &c)] {
        device.introduce(paired(view, host)).await.expect("a host");
    }

    let mut open: Vec<(Connection, &'static str)> = Vec::new();
    for (view, host, label) in [(&view_a, &a, "A"), (&view_c, &c, "C"), (&view_b, &b, "B")] {
        let connection = dial(&device, view, host).await;
        assert_eq!(answered(&connection).await, label);
        open.push((connection, label));
        for (earlier, earlier_label) in &open {
            assert_eq!(&answered(earlier).await, earlier_label);
        }
    }
    for (connection, label) in &open {
        assert!(
            connection.close_reason().is_none(),
            "{label}'s connection has no close reason"
        );
    }
    assert_eq!(paths_of(&open[0].0), (vec![r1.url.clone()], 0));
    assert_eq!(paths_of(&open[2].0), (vec![r1.url.clone()], 0));
    let (relays, direct) = paths_of(&open[1].0);
    assert!(relays.is_empty() && direct >= 1, "C is reached directly");
    assert_eq!(
        r1.gate.admissions(&device.endpoint().id()),
        1,
        "one client of the relay for the device, whatever the number of hosts"
    );

    // Three hosts, three resolvers, one dispatcher: each resolver is asked about its own host and
    // about neither of the others.
    for host in [&a, &b, &c] {
        registry_yields(&device, host.id()).await;
    }
    for (resolver, own, others) in [
        (&p_a, a.id(), [b.id(), c.id()]),
        (&p_b, b.id(), [a.id(), c.id()]),
        (&p_c, c.id(), [a.id(), b.id()]),
    ] {
        assert!(
            resolver.lookups(&own) >= 1,
            "a host's resolver is asked about that host"
        );
        for other in others {
            assert_eq!(resolver.lookups(&other), 0, "and about no other host");
        }
    }
    device.close().await;
}

/// KR-REQ-10.02: a dial to another host does not close or restart the connection of the first. The
/// first host's connection is open and answers after each introduction and each dial that follows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dial_to_a_second_host_does_not_close_the_first() {
    let (r1, r2) = (LocalRelay::spawn().await, LocalRelay::spawn().await);
    let a = Host::on(&r1, "A", 1).await;
    let b = Host::on(&r1, "B", 2).await;
    let c = Host::on(&r2, "C", 3).await;
    let (view_a, view_b, view_c) = (a.view(&[&r1.url]), b.view(&[&r1.url]), c.view(&[&r2.url]));

    let device = device(&[&r1, &r2], false).await;
    device.introduce(paired(&view_a, &a)).await.expect("host A");
    let first = dial(&device, &view_a, &a).await;
    let identity = first.stable_id();
    assert_eq!(answered(&first).await, "A");

    for (view, host, label) in [(&view_b, &b, "B"), (&view_c, &c, "C")] {
        device.introduce(paired(view, host)).await.expect("a host");
        assert!(first.close_reason().is_none(), "after introducing {label}");
        assert_eq!(answered(&first).await, "A", "after introducing {label}");
        let next = dial(&device, view, host).await;
        assert_eq!(answered(&next).await, label);
        assert!(first.close_reason().is_none(), "after dialling {label}");
        assert_eq!(answered(&first).await, "A", "after dialling {label}");
        assert_eq!(first.stable_id(), identity);
    }
    device.close().await;
}

/// KR-REQ-10.02, the transport's guarantee: a relay of a host that this run did not reach counts
/// no admission and no probe. A relay enters the map at the first dial of a paired host and not
/// before, so the rule runs in both directions: an invited host's relay is not contacted, and the
/// same relay is, once the host is paired.
///
/// Each relay is behind a front that counts every connection that reaches it, and only the device
/// is given the front's address, so a front counts what the device sends and nothing else. The
/// relays' QUIC address probes find nothing on the loopback, so a net report ends when every
/// relay in the map has had its HTTPS probe, which the front counts as a connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_of_a_host_this_run_did_not_reach_counts_no_admission_and_no_probe() {
    let (r1, r2, r3) = (
        LocalRelay::spawn().await,
        LocalRelay::spawn().await,
        LocalRelay::spawn().await,
    );
    let (f1, f2, f3) = (
        RelayFront::passing(&r1),
        RelayFront::passing(&r2),
        RelayFront::passing(&r3),
    );
    let a = Host::on(&r1, "A", 1).await;
    let b = Host::on(&r2, "B", 2).await;
    let c = Host::on(&r3, "C", 3).await;
    let (view_a, view_b, view_c) = (a.view(&[&f1.url]), b.view(&[&f2.url]), c.view(&[&f3.url]));

    let device = device(&[&r1, &r2, &r3], false).await;
    let me = device.endpoint().id();
    device.introduce(paired(&view_a, &a)).await.expect("host A");
    device.introduce(paired(&view_b, &b)).await.expect("host B");
    device
        .introduce(invited(&view_c, &c))
        .await
        .expect("host C");
    let to_a = dial(&device, &view_a, &a).await;
    let to_b = dial(&device, &view_b, &b).await;
    assert_eq!(answered(&to_a).await, "A");
    assert_eq!(answered(&to_b).await, "B");

    until_reported(&device, &[&f1.url, &f2.url]).await;
    assert_eq!(
        f3.accepted(),
        0,
        "no connection reached the unreached relay"
    );
    assert_eq!(r3.gate.admissions(&me), 0);
    assert!(f1.accepted() >= 1 && f2.accepted() >= 1);

    device
        .introduce(paired(&view_c, &c))
        .await
        .expect("host C, paired");
    until_reported(&device, &[&f3.url]).await;
    assert!(
        f3.accepted() >= 1,
        "the relay of a paired host is probed once its host is in"
    );
    device.close().await;
}

/// KR-REQ-10.02: forgetting a host takes its lookups out and takes out the relays that no other
/// host names, and nothing else: a connection that is open stays open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forgetting_a_host_removes_its_lookups_and_the_relays_no_other_host_names() {
    let (r1, r2) = (LocalRelay::spawn().await, LocalRelay::spawn().await);
    let names = NameServer::spawn();
    let (p_a, p_b) = (PkarrRelay::spawn(), PkarrRelay::spawn());
    let a = Host::on(&r1, "A", 1).await;
    let b = Host::on(&r1, "B", 2).await;
    let mut view_a = a.view(&[&r1.url]);
    view_a.discovery.pkarr_resolver_url = Some(p_a.url.clone());
    let mut view_b = b.view(&[&r1.url, &r2.url]);
    view_b.discovery.pkarr_resolver_url = Some(p_b.url.clone());
    view_b.discovery.dns_origin = Some("b.test".to_owned());

    let keys = DeviceKeys::generate().expect("device keys");
    let device = DeviceEndpoint::bind_asking(
        &device_config(&[&r1, &r2], false),
        &keys.transport,
        names.address,
    )
    .await
    .expect("the device's endpoint");
    device.introduce(paired(&view_a, &a)).await.expect("host A");
    device.introduce(paired(&view_b, &b)).await.expect("host B");
    let to_a = dial(&device, &view_a, &a).await;
    let to_b = dial(&device, &view_b, &b).await;
    assert_eq!(answered(&to_a).await, "A");
    assert_eq!(answered(&to_b).await, "B");
    assert_eq!(
        device.relay_urls(),
        BTreeSet::from([r1.url.clone(), r2.url.clone()])
    );

    // The control: while B is known, its lookups are asked about it.
    registry_yields(&device, b.id()).await;
    let asked_about_b = |names: &NameServer| {
        names
            .asked()
            .iter()
            .filter(|question| question.name.contains(&b.id().to_z32()))
            .count()
    };
    let (questions, requests) = (asked_about_b(&names), p_b.lookups(&b.id()));
    assert!(questions >= 1 && requests >= 1);

    device.forget(&b.key()).await.expect("forgetting B");
    assert_eq!(device.relay_urls(), BTreeSet::from([r1.url.clone()]));
    assert_eq!(answered(&to_a).await, "A");
    assert_eq!(
        answered(&to_b).await,
        "B",
        "forgetting a host closes none of its connections"
    );
    assert_registry_has_nothing_for(&device, b.id()).await;
    assert_eq!(asked_about_b(&names), questions);
    assert_eq!(p_b.lookups(&b.id()), requests);

    device.forget(&a.key()).await.expect("forgetting A");
    assert!(device.relay_urls().is_empty());
    assert_registry_has_nothing_for(&device, a.id()).await;
    assert!(to_a.close_reason().is_none() && to_b.close_reason().is_none());
    device.close().await;
}

/// KR-REQ-10.02: an introduction of a host whose services changed replaces the old entry: the new
/// resolver is asked, the old one is not, and a relay that only the old entry named leaves the map.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_whose_services_changed_is_asked_by_its_new_services() {
    let (r1, r2) = (LocalRelay::spawn().await, LocalRelay::spawn().await);
    let (p_1, p_2) = (PkarrRelay::spawn(), PkarrRelay::spawn());
    let a = Host::on(&r1, "A", 1).await;
    let with = |relay: &LocalRelay, resolver: &PkarrRelay| EndpointConfig {
        relay_urls: vec![relay.url.clone()],
        discovery: DiscoveryConfig {
            pkarr_resolver_url: Some(resolver.url.clone()),
            ..DiscoveryConfig::default()
        },
        ..EndpointConfig::default()
    };

    let device = device(&[&r1, &r2], false).await;
    device
        .introduce(paired(&with(&r1, &p_1), &a))
        .await
        .expect("host A");
    registry_yields(&device, a.id()).await;
    assert_eq!(device.relay_urls(), BTreeSet::from([r1.url.clone()]));
    let first = p_1.lookups(&a.id());
    assert!(
        first >= 1,
        "the first resolver is asked while it is the host's"
    );

    device
        .introduce(paired(&with(&r2, &p_2), &a))
        .await
        .expect("host A again");
    registry_yields(&device, a.id()).await;
    assert!(p_2.lookups(&a.id()) >= 1, "the new resolver is asked");
    assert_eq!(p_1.lookups(&a.id()), first, "the old resolver is not");
    assert_eq!(
        device.relay_urls(),
        BTreeSet::from([r2.url.clone()]),
        "the relay that only the old entry named is gone"
    );
    device.close().await;
}

/// KR-REQ-10.02: a relay that turns the device away is no reason for another host's connection to
/// change. The refusal comes through the relay of host B; host A's connection, through another
/// relay, stays and answers, and the failure of B's dial does not name A's relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relays_refusal_does_not_reach_a_host_on_another_relay() {
    let (r1, r2) = (LocalRelay::spawn().await, LocalRelay::spawn().await);
    let a = Host::on(&r1, "A", 1).await;
    let b = Host::on(&r2, "B", 2).await;
    let (view_a, view_b) = (a.view(&[&r1.url]), b.view(&[&r2.url]));

    let device = device(&[&r1, &r2], false).await;
    let me = device.endpoint().id();
    r2.gate.refuse(me);
    device.introduce(paired(&view_a, &a)).await.expect("host A");
    device.introduce(paired(&view_b, &b)).await.expect("host B");
    let to_a = dial(&device, &view_a, &a).await;
    assert_eq!(answered(&to_a).await, "A");

    let address = view_b.peer_addr(&b.key()).expect("B's address");
    let endpoint = device.endpoint().clone();
    // The deadline only ends the attempt once the state below has come: the refusal of the device
    // at B's relay, which the case waits for and which no time stands for.
    let attempt = tokio::spawn(tokio::time::timeout(Duration::from_secs(5), async move {
        kr_transport::endpoint::connect(&endpoint, address, ALPN).await
    }));
    until("the refusal of the device at B's relay", || {
        r2.gate.refusals(&me) >= 1
    })
    .await;
    assert_eq!(
        answered(&to_a).await,
        "A",
        "A's connection answers after it"
    );
    assert!(to_a.close_reason().is_none());

    match attempt.await.expect("the attempt's task") {
        Err(_elapsed) => {}
        Ok(Ok(_)) => panic!("a connection through a relay that refuses the device"),
        Ok(Err(TransportError::RelayRefused(refusal))) => {
            assert_ne!(
                refusal.relay, r1.url,
                "a refusal at B's relay is not reported as A's relay's"
            );
        }
        Ok(Err(_other)) => {}
    }
    assert_eq!(r1.gate.refusals(&me), 0);
    device.close().await;
}

/// KR-REQ-10.02: the device endpoint sends no relay token, to a relay outside the map and to one
/// inside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_device_endpoint_sends_no_relay_token() {
    let (r1, r2) = (LocalRelay::spawn().await, LocalRelay::spawn().await);
    let a = Host::on(&r1, "A", 1).await;
    let b = Host::on(&r2, "B", 2).await;
    let (view_a, view_b) = (a.view(&[&r1.url]), b.view(&[&r2.url]));

    let outside = device(&[&r1, &r2], false).await;
    outside
        .introduce(invited(&view_a, &a))
        .await
        .expect("host A");
    outside
        .introduce(invited(&view_b, &b))
        .await
        .expect("host B");
    let first = dial(&outside, &view_a, &a).await;
    let second = dial(&outside, &view_b, &b).await;
    assert_eq!(answered(&first).await, "A");
    assert_eq!(answered(&second).await, "B");

    let inside = device(&[&r1, &r2], false).await;
    inside.introduce(paired(&view_a, &a)).await.expect("host A");
    inside.introduce(paired(&view_b, &b)).await.expect("host B");
    let first = dial(&inside, &view_a, &a).await;
    let second = dial(&inside, &view_b, &b).await;
    assert_eq!(answered(&first).await, "A");
    assert_eq!(answered(&second).await, "B");
    until_reported(&inside, &[&r1.url, &r2.url]).await;

    for device in [&outside, &inside] {
        let me = device.endpoint().id();
        for relay in [&r1, &r2] {
            let requests = relay.gate.requests(&me);
            assert!(!requests.is_empty(), "the relay admitted the device");
            for request in requests {
                assert_eq!(request.token, None, "{request:?}");
                assert!(!request.headers.iter().any(|name| name == "authorization"));
                assert!(!request.uri.contains("token"), "{request:?}");
            }
        }
    }
    outside.close().await;
    inside.close().await;
}

/// KR-REQ-10.02: an introduction on a closed endpoint is refused with the endpoint's own error and
/// the map keeps its relays.
///
/// The table cannot be read from outside once the endpoint is closed: the library's lookup registry
/// is gone and its relay map no longer changes. The crate's own test of the same refusal reads the
/// table (`an_introduction_on_a_closed_endpoint_is_refused_and_the_table_does_not_take_the_host`),
/// so this case holds what the refusal and the map show.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_device_endpoint_refuses_an_introduction() {
    let (r1, r2) = (LocalRelay::spawn().await, LocalRelay::spawn().await);
    let a = Host::on(&r1, "A", 1).await;
    let b = Host::on(&r2, "B", 2).await;
    let (view_a, view_b) = (a.view(&[&r1.url]), b.view(&[&r2.url]));

    let device = device(&[&r1, &r2], false).await;
    device.introduce(paired(&view_a, &a)).await.expect("host A");
    device.close().await;
    let refused = device.introduce(paired(&view_b, &b)).await;
    assert!(
        matches!(&refused, Err(TransportError::Bind(reason)) if reason.contains("closed")),
        "{refused:?}"
    );
    assert_eq!(
        device.relay_urls(),
        BTreeSet::from([r1.url.clone()]),
        "B's relay did not enter the map"
    );
}

/// KR-REQ-10.02: a caller that stops waiting for an introduction leaves the change to finish. The
/// task that puts the relays in the map is held, the caller is dropped, and the task goes on: the
/// map holds the relay, and the host answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_introduction_whose_caller_stops_waiting_still_puts_the_relays_in_the_map() {
    let r1 = LocalRelay::spawn().await;
    let a = Host::on(&r1, "A", 1).await;
    let view_a = a.view(&[&r1.url]);

    let device = device(&[&r1], false).await;
    let mut hold = device.hold_next_map_task();
    {
        let introduction = device.introduce(paired(&view_a, &a));
        tokio::pin!(introduction);
        tokio::select! {
            _ = &mut introduction => panic!("the introduction ended while its task is held"),
            () = hold.reached() => {}
        }
        // The caller stops waiting here, while the gate holds the task.
    }
    assert!(
        device.relay_urls().is_empty(),
        "the held task has put nothing in"
    );
    hold.release().await;
    device
        .introduce(paired(&view_a, &a))
        .await
        .expect("host A again");

    assert_eq!(device.relay_urls(), BTreeSet::from([r1.url.clone()]));
    let to_a = dial(&device, &view_a, &a).await;
    assert_eq!(answered(&to_a).await, "A");
    device.close().await;
}

/// KR-REQ-10.02: a task that was started by an earlier introduction and runs late does not put
/// back what a later `forget` took out: it sets the map to the table as it then stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forgotten_hosts_relay_is_not_put_back_by_an_earlier_introduction() {
    let r1 = LocalRelay::spawn().await;
    let b = Host::on(&r1, "B", 2).await;
    let view_b = b.view(&[&r1.url]);

    let device = device(&[&r1], false).await;
    let mut hold = device.hold_next_map_task();
    {
        let introduction = device.introduce(paired(&view_b, &b));
        tokio::pin!(introduction);
        tokio::select! {
            _ = &mut introduction => panic!("the introduction ended while its task is held"),
            () = hold.reached() => {}
        }
    }
    device.forget(&b.key()).await.expect("forgetting B");
    assert!(device.relay_urls().is_empty());

    hold.release().await;
    assert!(
        device.relay_urls().is_empty(),
        "the late task did not put B's relay back"
    );
    assert_registry_has_nothing_for(&device, b.id()).await;
    device.close().await;
}

/// KR-REQ-10.02: a `forget` leaves no relay of an earlier entry in the map when it returns, also
/// when the entry that it removes names no relay. A host is introduced with a relay, then again
/// with none by an introduction whose caller stops waiting while the task that sets the map is
/// held: the table holds the entry with no relay and the map still holds the relay of the entry
/// before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forget_leaves_no_relay_of_an_earlier_entry_in_the_map() {
    let r1 = LocalRelay::spawn().await;
    let a = Host::on(&r1, "A", 1).await;
    let (with_relay, without_relay) = (a.view(&[&r1.url]), a.view(&[]));

    let device = device(&[&r1], false).await;
    device
        .introduce(paired(&with_relay, &a))
        .await
        .expect("host A with its relay");
    assert_eq!(device.relay_urls(), BTreeSet::from([r1.url.clone()]));

    let mut hold = device.hold_next_map_task();
    {
        let introduction = device.introduce(paired(&without_relay, &a));
        tokio::pin!(introduction);
        tokio::select! {
            _ = &mut introduction => panic!("the introduction ended while its task is held"),
            () = hold.reached() => {}
        }
        // The caller stops waiting here, while the gate holds the task.
    }
    assert_eq!(
        device.relay_urls(),
        BTreeSet::from([r1.url.clone()]),
        "the control: the held task has not changed the map"
    );

    // The forget has its own task, which the hold does not stop; a wait that has no end is a fault
    // that ends the case here.
    tokio::time::timeout(PATIENCE, device.forget(&a.key()))
        .await
        .unwrap_or_else(|_| panic!("the forget of A did not return within the bound"))
        .expect("forgetting A");
    assert!(
        device.relay_urls().is_empty(),
        "the relay of A's earlier entry stays in the map after the forget returned"
    );

    hold.release().await;
    assert!(
        device.relay_urls().is_empty(),
        "the late task did not put A's relay back"
    );
    assert_registry_has_nothing_for(&device, a.id()).await;
    device.close().await;
}

/// What a task that ended in a panic said, for a case that expects the panic.
fn panic_message(ended: Result<(), tokio::task::JoinError>) -> String {
    let payload = ended.expect_err("the task ended in a panic").into_panic();
    payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_default()
}

/// KR-REQ-10.02: a hold that the gate dropped fails both of its waits where the case sees it,
/// instead of letting the case go on as if a task had been held. Arming a second hold drops the
/// hold that was armed before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hold_that_the_gate_dropped_fails_both_its_waits() {
    let device = device(&[], false).await;
    let mut for_reached = device.hold_next_map_task();
    let for_release = device.hold_next_map_task();
    let _last = device.hold_next_map_task();

    let waiting = tokio::spawn(async move { for_reached.reached().await });
    let message = panic_message(waiting.await);
    assert!(message.contains("gate dropped the hold"), "{message:?}");

    let releasing = tokio::spawn(for_release.release());
    let message = panic_message(releasing.await);
    assert!(message.contains("gate dropped the hold"), "{message:?}");
    device.close().await;
}

/// KR-REQ-10.02: a host's record resolver is reached through the proxy that the device's bind
/// names, as the endpoint's other requests are. Two hosts have a resolver each, and the proxy is
/// asked for each host's record at that host's own resolver.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hosts_resolver_is_reached_through_the_proxy_of_the_bind() {
    let proxy = HttpProxy::forwarding();
    let (p_a, p_b) = (PkarrRelay::spawn(), PkarrRelay::spawn());
    let (key_a, id_a) = stranger();
    let (key_b, id_b) = stranger();

    let keys = DeviceKeys::generate().expect("device keys");
    let config = EndpointConfig {
        proxy_url: Some(proxy.url.clone()),
        ..device_config(&[], false)
    };
    let device = DeviceEndpoint::bind(&config, &keys.transport)
        .await
        .expect("the device's endpoint");
    for (resolver, key) in [(&p_a, &key_a), (&p_b, &key_b)] {
        let view = EndpointConfig {
            discovery: DiscoveryConfig {
                pkarr_resolver_url: Some(resolver.url.clone()),
                ..DiscoveryConfig::default()
            },
            ..EndpointConfig::default()
        };
        device
            .introduce(HostServices::paired(&view, key).expect("a host's services"))
            .await
            .expect("a host");
    }

    for id in [id_a, id_b] {
        registry_yields(&device, id).await;
    }
    let asked = proxy.asked();
    for (resolver, id) in [(&p_a, id_a), (&p_b, id_b)] {
        let record = format!("{}/{}", resolver.url, id.to_z32());
        assert!(
            asked
                .iter()
                .any(|asked| asked.method == "GET" && asked.target == record),
            "GET {record} went through the bind's proxy: {asked:?}"
        );
        assert!(resolver.lookups(&id) >= 1, "and the resolver was reached");
    }
    device.close().await;
}
