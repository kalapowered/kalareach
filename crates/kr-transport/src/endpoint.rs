//! Building an iroh endpoint from an explicit selection, and dialling from it.
//!
//! The whole of this module exists to make one guarantee visible: an endpoint reaches exactly the
//! services its [`EndpointConfig`] names. It starts from `presets::Minimal`, which sets the
//! cryptographic provider and nothing else, and then adds each selected service by hand. It never
//! uses `presets::N0`, `RelayMode::Default` or `RelayMode::Staging`, so no public default can
//! arrive by inheritance.
//!
//! [`connect`] is the dialling half: it opens a connection and, when a relay the connection needed
//! turned this endpoint away, says so rather than reporting a peer that did not answer.

use std::collections::{BTreeMap, BTreeSet};
use std::task::{Context, Poll};
use std::time::Duration;

use iroh::endpoint::{
    Builder, ConnectError, ConnectingError, Connection, ConnectionError, QuicTransportConfig,
    RelayStatus, presets,
};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey, TransportAddr, Watcher,
};
use iroh_mainline_address_lookup::DhtAddressLookup;
use iroh_mdns_address_lookup::MdnsAddressLookup;
use iroh_relay::tls::CaTlsConfig;
use kr_crypto::keys::TransportIdentityKeyPair;
use kr_protocol::hello::ALPN;
use kr_protocol::limits::{INACTIVITY_THRESHOLD, KEEPALIVE_INTERVAL, MAX_SEND_QUEUE_BYTES};
use rustls_pki_types::CertificateDer;

use crate::config::{EndpointConfig, PublishedAddresses};
use crate::error::{RelayRefusal, Result, TransportError};

/// How often an idle connection sends a QUIC keepalive.
///
/// Section 23: ten seconds while active.
pub const KEEPALIVE: Duration = Duration::from_millis(KEEPALIVE_INTERVAL.get());

/// How long a connection may be silent before the transport is declared unavailable.
///
/// Section 23: a 30-second inactivity threshold. A mobile suspension that trips it is a normal
/// disconnect, not a failure.
pub const IDLE_TIMEOUT: Duration = Duration::from_millis(INACTIVITY_THRESHOLD.get());

/// Builds an endpoint that listens for KalaReach connections.
///
/// The endpoint advertises the stable ALPN, so a peer that negotiates anything else never reaches
/// the handshake.
///
/// # Errors
///
/// Returns [`TransportError::Configuration`] when a selected service cannot be constructed, and
/// [`TransportError::Bind`] when the socket cannot be bound.
pub async fn bind_listener(
    config: &EndpointConfig,
    identity: &TransportIdentityKeyPair,
) -> Result<Endpoint> {
    bind(config, identity, true).await
}

/// Builds an endpoint that only dials.
///
/// It is configured identically except that it advertises no ALPN, so nothing can open a
/// connection to it. A client that never accepts connections cannot be reached by an unpaired
/// peer at all.
///
/// # Errors
///
/// As [`bind_listener`].
pub async fn bind_dialer(
    config: &EndpointConfig,
    identity: &TransportIdentityKeyPair,
) -> Result<Endpoint> {
    bind(config, identity, false).await
}

async fn bind(
    config: &EndpointConfig,
    identity: &TransportIdentityKeyPair,
    accept: bool,
) -> Result<Endpoint> {
    let seed = identity.export_endpoint_seed();
    let secret_key = SecretKey::from_bytes(seed.expose());
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(secret_key)
        .transport_config(transport_config())
        .relay_mode(relay_mode(config))
        // This endpoint keeps no TLS session tickets, so it never offers QUIC 0-RTT to anyone.
        // Version 1 accepts no application mutation in 0-RTT, and the simplest way not to send
        // early data is to have nothing to resume from.
        .max_tls_tickets(0);

    if accept {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }
    // An endpoint with no relay selected and no IP transport could reach nothing at all, so that
    // combination is a configuration error rather than a silent no-op. It is checked here, before
    // anything is bound.
    if config.relay_only && config.relays_disabled() {
        return Err(TransportError::Configuration {
            what: "relay_only".to_owned(),
            kind: "endpoint transports",
            reason: "an endpoint with no relay and no direct path can reach nothing".to_owned(),
        });
    }
    if !config.relay_ca_roots.is_empty() {
        let roots = config
            .relay_ca_roots
            .iter()
            .map(|der| CertificateDer::from(der.clone()));
        builder = builder.ca_tls_config(CaTlsConfig::default().with_extra_roots(roots));
    }
    builder = apply_discovery(builder, config)?;

    if let Some(addr) = config.bind_addr {
        // The bind address is the endpoint's one IP socket. iroh starts from an unspecified socket
        // for each address family, and naming an address replaces only the default of its own
        // family, so the defaults go first: an endpoint bound to the IPv4 loopback would otherwise
        // also listen on every IPv6 interface.
        builder = builder
            .clear_ip_transports()
            .bind_addr(addr)
            .map_err(|error| TransportError::Configuration {
                what: addr.to_string(),
                kind: "bind address",
                reason: error.to_string(),
            })?;
    }
    if config.relay_only {
        // Last, after every bind-address operation: naming a bind address adds an IP transport, so
        // clearing them earlier would leave one behind and the endpoint would still have a direct
        // path. Every packet then goes through the selected relay, because there is nothing else.
        builder = builder.clear_ip_transports();
    }
    builder
        .bind()
        .await
        .map_err(|error| TransportError::Bind(error.to_string()))
}

/// Opens a connection to `peer`, and names the relay that turned this endpoint away when that is
/// why no path opened.
///
/// iroh keeps the reason a relay gave for refusing this endpoint, but only for this endpoint's home
/// relay, and only as the latest thing that relay said. So the relay status is followed for the
/// whole attempt, and a refusal counts only when it came from a relay on this connection's route: a
/// relay the address names, or one this endpoint already holds for the peer, both of which iroh
/// tries. A home relay that refused but is not on the route says nothing about this connection. A
/// relay on the route that is not this endpoint's home relay leaves no reason to read, so a failure
/// through it is reported as any other failure is.
///
/// A refusal explains only a failure in which nothing answered: an attempt that timed out. A peer
/// that answered and refused, an endpoint that was closing and a request this endpoint could not
/// make are each their own reason, whatever a relay said at the time.
///
/// An endpoint with no IP transport of its own has nothing but relays to try, so once every relay
/// on its route has refused it the attempt ends there rather than at its deadline. An endpoint that
/// can take a direct path lets the attempt run, because an address hint or local discovery can
/// still open one, and the refusal is the reason only if none does.
///
/// # Errors
///
/// Returns [`TransportError::RelayRefused`] when a relay on the route refused this endpoint and
/// nothing else reached the peer, and [`TransportError::Connect`] for any other failure.
pub async fn connect(
    endpoint: &Endpoint,
    peer: impl Into<EndpointAddr>,
    alpn: &[u8],
) -> Result<Connection> {
    let peer: EndpointAddr = peer.into();
    let peer_id = peer.id;
    let named: BTreeSet<RelayUrl> = peer.relay_urls().cloned().collect();
    let direct = !endpoint.bound_sockets().is_empty();
    through_relays(
        endpoint.connect(peer, alpn),
        HomeRelays(endpoint.home_relay_status()),
        direct,
        || route(endpoint, peer_id, &named),
    )
    .await
}

/// Runs one connection attempt while following what this endpoint's relays say, and decides what a
/// failure of it is.
///
/// The status holds its latest value and no history of it, so it is read afresh at every point a
/// decision rests on it: before a relay-only endpoint gives up, after the route is read, because
/// reading it waits, and when the attempt has failed, because the change that explains the failure
/// can arrive together with it.
async fn through_relays<T, S, F, R>(
    attempt: impl Future<Output = std::result::Result<T, ConnectError>>,
    mut statuses: S,
    direct: bool,
    mut route: F,
) -> Result<T>
where
    S: RelayStatuses,
    F: FnMut() -> R,
    R: Future<Output = BTreeSet<RelayUrl>>,
{
    let mut refusals = Refusals::default();
    let mut watching = true;
    tokio::pin!(attempt);
    loop {
        refusals.observe(statuses.now());
        if !direct {
            let relays = route().await;
            refusals.observe(statuses.now());
            if let Some((relay, reason)) = refusals.throughout(&relays) {
                return Err(refused(relay, reason, direct));
            }
        }
        tokio::select! {
            outcome = &mut attempt => {
                let error = match outcome {
                    Ok(connected) => return Ok(connected),
                    Err(error) => error,
                };
                if !nothing_answered(&error) {
                    return Err(TransportError::Connect(error.to_string()));
                }
                let relays = route().await;
                refusals.observe(statuses.now());
                return Err(match refusals.on(&relays) {
                    Some((relay, reason)) => refused(relay, reason, direct),
                    None => TransportError::Connect(error.to_string()),
                });
            }
            changed = std::future::poll_fn(|context| statuses.poll_changed(context)), if watching => {
                // What changed is read at the top of the loop. A status whose endpoint has gone
                // will change no more, and the attempt ends on its own.
                if !changed {
                    watching = false;
                }
            }
        }
    }
}

/// Whether a failed attempt failed for want of any path that answered.
///
/// That is the only failure a relay's refusal can explain. Every other one says something answered
/// or something here stopped the attempt: a peer that closed or reset it, a handshake that failed,
/// an endpoint that was closing, a request that could not be made at all.
fn nothing_answered(error: &ConnectError) -> bool {
    matches!(
        error,
        ConnectError::Connection {
            source: ConnectionError::TimedOut,
            ..
        } | ConnectError::Connecting {
            source: ConnectingError::ConnectionError {
                source: ConnectionError::TimedOut,
                ..
            },
            ..
        }
    )
}

/// Returns the relays a connection to `peer` can go through: the ones its address names and the
/// ones this endpoint already holds for the peer.
async fn route(
    endpoint: &Endpoint,
    peer: EndpointId,
    named: &BTreeSet<RelayUrl>,
) -> BTreeSet<RelayUrl> {
    let mut relays = named.clone();
    if let Some(known) = endpoint.remote_info(peer).await {
        relays.extend(known.addrs().filter_map(|address| match address.addr() {
            TransportAddr::Relay(relay) => Some(relay.clone()),
            _ => None,
        }));
    }
    relays
}

/// Returns the failure a refusal by `relay` is.
fn refused(relay: &RelayUrl, reason: &str, direct: bool) -> TransportError {
    TransportError::RelayRefused(RelayRefusal::from_reason(relay.clone(), reason, direct))
}

/// What one relay's status says about whether it refuses this endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RelayObservation {
    relay: RelayUrl,
    /// Whether the endpoint is connected to the relay now.
    connected: bool,
    /// The reason the relay gave, when it refused the endpoint's latest attempt to reach it.
    refused: Option<String>,
    /// Whether the latest attempt to reach the relay failed, for that reason or any other.
    failed: bool,
}

impl RelayObservation {
    fn of(status: &RelayStatus) -> Self {
        Self {
            relay: status.url().clone(),
            connected: status.is_connected(),
            refused: status.auth_denied_reason().map(ToOwned::to_owned),
            failed: status.last_error().is_some(),
        }
    }
}

/// Where the relay status is read from while an attempt runs.
trait RelayStatuses {
    /// Returns the status as it stands now, which is every relay it reports on.
    fn now(&mut self) -> Vec<RelayObservation>;

    /// Returns whether the status changed since it was last read, and arranges to be woken when it
    /// does. `Ready(false)` means it never will again.
    fn poll_changed(&mut self, context: &mut Context<'_>) -> Poll<bool>;
}

/// This endpoint's home relays, as iroh reports them.
struct HomeRelays<W>(W);

impl<W: Watcher<Value = Vec<RelayStatus>>> RelayStatuses for HomeRelays<W> {
    fn now(&mut self) -> Vec<RelayObservation> {
        self.0.get().iter().map(RelayObservation::of).collect()
    }

    fn poll_changed(&mut self, context: &mut Context<'_>) -> Poll<bool> {
        self.0.poll_updated(context).map(|updated| updated.is_ok())
    }
}

/// The refusals this endpoint's relays last gave it, by relay.
#[derive(Debug, Default)]
struct Refusals(BTreeMap<RelayUrl, String>);

impl Refusals {
    /// Takes in the relay status as it stands now, which is every relay iroh reports on.
    ///
    /// A refusal stands while the endpoint dials the relay again, because the relay has said
    /// nothing newer. It ends when the relay admits the endpoint, when the latest attempt failed
    /// for another cause, since then the refusal is no longer why the relay cannot be reached, and
    /// when the relay leaves the status, since nothing that relay says afterwards is reported and
    /// what it said last can no longer be known to be current.
    fn observe(&mut self, snapshot: impl IntoIterator<Item = RelayObservation>) {
        let mut reported = BTreeSet::new();
        for observation in snapshot {
            reported.insert(observation.relay.clone());
            match observation.refused {
                Some(reason) => {
                    self.0.insert(observation.relay, reason);
                }
                None if observation.connected || observation.failed => {
                    self.0.remove(&observation.relay);
                }
                None => {}
            }
        }
        self.0.retain(|relay, _| reported.contains(relay));
    }

    /// Returns the refusal of the first relay on `route` that refused, if one did.
    fn on<'a>(&'a self, route: &'a BTreeSet<RelayUrl>) -> Option<(&'a RelayUrl, &'a str)> {
        route
            .iter()
            .find_map(|relay| self.0.get(relay).map(|reason| (relay, reason.as_str())))
    }

    /// Returns the refusal to report when every relay on `route` refused, which leaves an endpoint
    /// with no direct transport nothing else to try.
    fn throughout<'a>(&'a self, route: &'a BTreeSet<RelayUrl>) -> Option<(&'a RelayUrl, &'a str)> {
        if route.is_empty() || !route.iter().all(|relay| self.0.contains_key(relay)) {
            return None;
        }
        self.on(route)
    }
}

/// Returns the relay selection.
///
/// An empty relay list is [`RelayMode::Disabled`], not a fallback to the public map. A deployment
/// that wants no relay gets no relay.
fn relay_mode(config: &EndpointConfig) -> RelayMode {
    if config.relays_disabled() {
        RelayMode::Disabled
    } else {
        RelayMode::Custom(config.relay_map())
    }
}

/// Returns the filter that decides what goes into this endpoint's public discovery record.
///
/// It is applied to the publisher rather than to the endpoint, because an endpoint-wide filter
/// would also strip the direct addresses that local network discovery exists to advertise.
fn published_addresses(config: &EndpointConfig) -> iroh::address_lookup::AddrFilter {
    use iroh::address_lookup::AddrFilter;
    match config.discovery.publisher.published_addresses {
        PublishedAddresses::RelayOnly => AddrFilter::relay_only(),
        PublishedAddresses::RelayAndDirect => AddrFilter::unfiltered(),
    }
}

fn apply_discovery(mut builder: Builder, config: &EndpointConfig) -> Result<Builder> {
    let discovery = &config.discovery;

    if let Some(url) = &discovery.pkarr_publisher_url {
        let publisher = iroh::address_lookup::PkarrPublisher::builder(url.clone())
            .ttl(discovery.publisher.ttl_seconds)
            .republish_interval(discovery.publisher.republish_interval)
            .addr_filter(published_addresses(config));
        builder = builder.address_lookup(publisher);
    }
    if let Some(url) = &discovery.pkarr_resolver_url {
        builder = builder.address_lookup(iroh::address_lookup::PkarrResolver::builder(url.clone()));
    }
    if let Some(origin) = &discovery.dns_origin {
        builder = builder.address_lookup(iroh::address_lookup::DnsAddressLookup::builder(
            origin.clone(),
        ));
    }
    if discovery.local_discovery {
        // A local network advertisement is direct addresses by definition, and the local network is
        // not the public record the relay-only default protects.
        builder = builder.address_lookup(
            MdnsAddressLookup::builder()
                .addr_filter(iroh::address_lookup::AddrFilter::unfiltered()),
        );
    }
    if discovery.mainline_dht {
        builder = builder.address_lookup(
            DhtAddressLookup::builder()
                .ttl(discovery.publisher.ttl_seconds)
                .republish_delay(discovery.publisher.republish_interval)
                .addr_filter(published_addresses(config)),
        );
    }
    Ok(builder)
}

/// Returns the transport configuration every KalaReach connection uses.
///
/// The keepalive and the idle timeout are the section 23 values. Setting them here rather than per
/// connection means a connection cannot be opened without them.
fn transport_config() -> QuicTransportConfig {
    let idle_timeout = IDLE_TIMEOUT
        .try_into()
        .expect("the 30-second inactivity threshold fits an idle timeout");
    QuicTransportConfig::builder()
        .keep_alive_interval(KEEPALIVE)
        .max_idle_timeout(Some(idle_timeout))
        // Section 9's 8 MiB bounded send queue per peer, enforced by the connection itself rather
        // than only by the application's own accounting: past this, a write waits instead of
        // handing more bytes to a queue nothing can drain.
        .send_window(MAX_SEND_QUEUE_BYTES as u64)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-REQ-23.09: the transport ALPN is the stable `kalareach`.
    #[test]
    fn the_alpn_is_the_stable_one() {
        assert_eq!(ALPN, b"kalareach");
    }

    /// KR-REQ-23.22: the transport configuration every connection is opened with carries the
    /// ten-second keepalive and the thirty-second inactivity threshold.
    #[test]
    fn the_keepalive_and_idle_timeout_are_the_specified_values() {
        assert_eq!(KEEPALIVE, Duration::from_secs(10));
        assert_eq!(IDLE_TIMEOUT, Duration::from_secs(30));
    }

    /// KR-REQ-10.02: without a selected relay the endpoint relays nothing.
    #[test]
    fn an_unselected_relay_map_disables_relaying() {
        let config = EndpointConfig::default();
        assert_eq!(relay_mode(&config), RelayMode::Disabled);
    }

    /// KR-REQ-10.02: the relay map holds the selected relays and nothing else.
    #[test]
    fn a_selected_relay_map_is_custom_and_holds_only_what_was_selected() {
        let config = EndpointConfig {
            relay_urls: vec!["https://relay.kala.to".parse().expect("a relay URL")],
            ..EndpointConfig::default()
        };
        let RelayMode::Custom(map) = relay_mode(&config) else {
            panic!("a selected relay map is custom");
        };
        assert_eq!(map.len(), 1);
    }

    /// KR-REQ-17.43: the relay mode an endpoint is built with is a custom map of exactly the
    /// selected relays: every one of them, nothing else, and never the public default or staging
    /// map.
    #[test]
    fn the_relay_mode_is_a_custom_map_of_exactly_the_selected_relays() {
        let selected: Vec<iroh::RelayUrl> = [
            "https://relay-1.reach.kala.to",
            "https://relay-2.reach.kala.to",
        ]
        .into_iter()
        .map(|url| url.parse().expect("a relay URL"))
        .collect();
        let config = EndpointConfig {
            relay_urls: selected.clone(),
            ..EndpointConfig::default()
        };
        let mode = relay_mode(&config);
        assert_ne!(mode, RelayMode::Default);
        assert_ne!(mode, RelayMode::Staging);
        let RelayMode::Custom(map) = mode else {
            panic!("a selected relay map is custom");
        };
        assert_eq!(
            map.urls::<std::collections::BTreeSet<_>>(),
            selected
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
        );
    }

    /// Whether this machine can bind a socket on `addr` at all.
    ///
    /// An IPv6 loopback bind needs IPv6, which a host can have switched off. Such a host has no
    /// IPv6 socket to leave open either, so the family it lacks is the one leg with nothing to show.
    fn bindable(addr: std::net::SocketAddr) -> bool {
        std::net::UdpSocket::bind(addr).is_ok()
    }

    /// An endpoint given a loopback bind address listens on the loopback and nowhere else, in
    /// either address family. Every socket it binds is a loopback socket: the unspecified
    /// socket iroh binds by default for the *other* family is not left listening on every
    /// interface beside the one that was asked for.
    #[tokio::test]
    async fn a_loopback_bind_address_binds_only_loopback_sockets() {
        let identity = TransportIdentityKeyPair::generate().expect("a transport identity");
        for loopback in ["127.0.0.1:0", "[::1]:0"] {
            let addr: std::net::SocketAddr = loopback.parse().expect("a loopback address");
            if !bindable(addr) {
                eprintln!("{loopback} cannot be bound on this machine, so that leg is not run");
                continue;
            }
            let config = EndpointConfig {
                bind_addr: Some(addr),
                ..EndpointConfig::default()
            };
            for accept in [true, false] {
                let endpoint = bind(&config, &identity, accept).await.expect("an endpoint");
                let sockets = endpoint.bound_sockets();
                assert!(
                    !sockets.is_empty(),
                    "an endpoint bound to {loopback} has a socket"
                );
                assert!(
                    sockets.iter().all(|socket| socket.ip().is_loopback()),
                    "every socket an endpoint bound to {loopback} holds is a loopback socket: \
                     {sockets:?}"
                );
                eprintln!("{loopback}: bound {sockets:?}");
                endpoint.close().await;
            }
        }
    }

    /// A relay-only endpoint holds no IP socket at all, even when a bind address is named, because
    /// the bind address is applied before the IP transports are removed.
    #[tokio::test]
    async fn a_relay_only_endpoint_binds_no_ip_socket_even_with_a_bind_address() {
        let identity = TransportIdentityKeyPair::generate().expect("a transport identity");
        let config = EndpointConfig {
            relay_urls: vec![
                "https://relay.example.invalid"
                    .parse()
                    .expect("a relay URL"),
            ],
            bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
            relay_only: true,
            ..EndpointConfig::default()
        };
        let endpoint = bind_dialer(&config, &identity).await.expect("an endpoint");
        assert_eq!(endpoint.bound_sockets(), Vec::<std::net::SocketAddr>::new());
        endpoint.close().await;
    }

    fn relay(name: &str) -> RelayUrl {
        format!("https://{name}.reach.kala.to")
            .parse()
            .expect("a relay URL")
    }

    fn refusing(name: &str, reason: &str) -> RelayObservation {
        RelayObservation {
            relay: relay(name),
            connected: false,
            refused: Some(reason.to_owned()),
            failed: true,
        }
    }

    fn relays(names: &[&str]) -> BTreeSet<RelayUrl> {
        names.iter().map(|name| relay(name)).collect()
    }

    /// KR-REQ-17.40: a refusal is a connection's reason only when the relay that gave it is on
    /// that connection's route. A home relay that refused this endpoint says nothing about a route
    /// through another relay, and a route with a relay left that did not refuse is not refused
    /// throughout, so an endpoint with no direct transport still waits for that relay.
    #[test]
    fn a_refusal_counts_only_for_a_relay_on_the_route() {
        let mut refusals = Refusals::default();
        refusals.observe([refusing("relay-1", "allowance_spent: spent")]);

        assert_eq!(refusals.on(&relays(&["relay-2"])), None);
        assert_eq!(refusals.throughout(&relays(&["relay-2"])), None);
        assert_eq!(refusals.throughout(&relays(&[])), None);

        let only = relays(&["relay-1"]);
        assert_eq!(
            refusals.on(&only),
            Some((&relay("relay-1"), "allowance_spent: spent"))
        );
        assert_eq!(
            refusals.throughout(&only),
            Some((&relay("relay-1"), "allowance_spent: spent"))
        );

        let both = relays(&["relay-1", "relay-2"]);
        assert_eq!(
            refusals.on(&both),
            Some((&relay("relay-1"), "allowance_spent: spent")),
            "a failed attempt through both is reported as the refusal it met"
        );
        assert_eq!(
            refusals.throughout(&both),
            None,
            "the relay that did not refuse can still carry the attempt"
        );

        refusals.observe([
            refusing("relay-1", "allowance_spent: spent"),
            refusing("relay-2", "stopping: this relay is stopping"),
        ]);
        assert_eq!(
            refusals.throughout(&both),
            Some((&relay("relay-1"), "allowance_spent: spent"))
        );
    }

    /// KR-REQ-17.40: a refusal stands while the endpoint dials the relay again, and ends when the
    /// relay admits it or when the latest attempt failed for another cause.
    #[test]
    fn a_refusal_lasts_until_the_relay_says_something_newer() {
        let only = relays(&["relay-1"]);
        let redialling = RelayObservation {
            relay: relay("relay-1"),
            connected: false,
            refused: None,
            failed: false,
        };
        let unreachable = RelayObservation {
            failed: true,
            ..redialling.clone()
        };
        let admitted = RelayObservation {
            connected: true,
            ..redialling.clone()
        };

        let mut refusals = Refusals::default();
        refusals.observe([refusing("relay-1", "allowance_spent: spent")]);
        refusals.observe([redialling]);
        assert!(
            refusals.on(&only).is_some(),
            "dialling again is not an answer"
        );

        refusals.observe([unreachable]);
        assert_eq!(
            refusals.on(&only),
            None,
            "a relay that cannot be reached is not refusing"
        );

        refusals.observe([refusing("relay-1", "allowance_spent: spent")]);
        refusals.observe([admitted]);
        assert_eq!(
            refusals.on(&only),
            None,
            "a relay that admits the endpoint is not refusing"
        );
    }

    /// KR-REQ-17.40: a refusal is forgotten once its relay leaves the status. iroh reports on the
    /// home relays it has now, so once another relay is home nothing the first one says is reported
    /// again, and what it said last can no longer be known to be current.
    #[test]
    fn a_refusal_is_forgotten_once_its_relay_leaves_the_status() {
        let first = relays(&["relay-1"]);
        let mut refusals = Refusals::default();
        refusals.observe([refusing("relay-1", "allowance_spent: spent")]);
        refusals.observe([RelayObservation {
            relay: relay("relay-2"),
            connected: false,
            refused: None,
            failed: false,
        }]);
        assert_eq!(refusals.on(&first), None, "another relay became home");

        refusals.observe([refusing("relay-1", "allowance_spent: spent")]);
        refusals.observe([]);
        assert_eq!(refusals.on(&first), None, "no relay is home");
    }

    fn admitted(name: &str) -> RelayObservation {
        RelayObservation {
            relay: relay(name),
            connected: true,
            refused: None,
            failed: false,
        }
    }

    fn timed_out() -> ConnectError {
        ConnectError::from(ConnectionError::TimedOut)
    }

    /// A relay status a test changes at the moment it chooses.
    #[derive(Clone, Default)]
    struct Scripted(std::sync::Arc<std::sync::Mutex<ScriptedState>>);

    #[derive(Default)]
    struct ScriptedState {
        value: Vec<RelayObservation>,
        version: u64,
        waker: Option<std::task::Waker>,
    }

    impl Scripted {
        fn set(&self, value: Vec<RelayObservation>) {
            let mut state = self.0.lock().expect("the scripted status");
            state.value = value;
            state.version += 1;
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
        }

        fn reader(&self) -> ScriptedReader {
            ScriptedReader {
                shared: self.clone(),
                seen: 0,
            }
        }
    }

    /// One reader of a scripted status, which remembers what it has read.
    struct ScriptedReader {
        shared: Scripted,
        seen: u64,
    }

    impl RelayStatuses for ScriptedReader {
        fn now(&mut self) -> Vec<RelayObservation> {
            let state = self.shared.0.lock().expect("the scripted status");
            self.seen = state.version;
            state.value.clone()
        }

        fn poll_changed(&mut self, context: &mut Context<'_>) -> Poll<bool> {
            let mut state = self.shared.0.lock().expect("the scripted status");
            if state.version == self.seen {
                state.waker = Some(context.waker().clone());
                return Poll::Pending;
            }
            self.seen = state.version;
            Poll::Ready(true)
        }
    }

    /// KR-REQ-17.40: a refusal the status reports at the moment the attempt fails is still the
    /// failure's reason. The attempt and the change it waited on can finish together, and the
    /// status is read again when the failure is decided rather than only when it is seen to change.
    #[tokio::test]
    async fn a_refusal_that_arrives_with_the_failure_is_still_its_reason() {
        let status = Scripted::default();
        let setter = status.clone();
        let error = through_relays(
            async move {
                setter.set(vec![refusing("relay-1", "allowance_spent: spent")]);
                Err::<(), _>(timed_out())
            },
            status.reader(),
            true,
            || async { relays(&["relay-1"]) },
        )
        .await
        .expect_err("the attempt failed");
        assert!(
            matches!(&error, TransportError::RelayRefused(refusal)
                if refusal.relay == relay("relay-1")
                    && refusal.kind == crate::error::RelayRefusalKind::AllowanceSpent),
            "{error}"
        );
    }

    /// KR-REQ-17.40: a relay that admits the endpoint by the time the attempt fails is not the
    /// failure's reason, although it refused earlier.
    #[tokio::test]
    async fn a_relay_that_admits_the_endpoint_by_the_failure_is_not_its_reason() {
        let status = Scripted::default();
        status.set(vec![refusing("relay-1", "allowance_spent: spent")]);
        let setter = status.clone();
        let error = through_relays(
            async move {
                setter.set(vec![admitted("relay-1")]);
                Err::<(), _>(timed_out())
            },
            status.reader(),
            true,
            || async { relays(&["relay-1"]) },
        )
        .await
        .expect_err("the attempt failed");
        assert!(matches!(error, TransportError::Connect(_)), "{error}");
    }

    /// KR-REQ-17.40: an endpoint with no direct transport gives up on a refusal only as the status
    /// stands after its route was read. A relay that admitted it while the route was being read is
    /// not a reason to stop.
    #[tokio::test]
    async fn a_relay_only_endpoint_reads_the_status_again_after_its_route() {
        let status = Scripted::default();
        status.set(vec![refusing("relay-1", "allowance_spent: spent")]);
        let error = through_relays(
            async { Err::<(), _>(timed_out()) },
            status.reader(),
            false,
            || {
                let setter = status.clone();
                async move {
                    setter.set(vec![admitted("relay-1")]);
                    relays(&["relay-1"])
                }
            },
        )
        .await
        .expect_err("the attempt failed");
        assert!(matches!(error, TransportError::Connect(_)), "{error}");
    }

    /// KR-REQ-17.40: an endpoint with no direct transport stops at once when every relay on its
    /// route refused it, without waiting for the attempt.
    #[tokio::test]
    async fn a_relay_only_endpoint_refused_throughout_stops_at_once() {
        let status = Scripted::default();
        status.set(vec![refusing(
            "relay-1",
            "stopping: this relay is stopping",
        )]);
        let error = through_relays(
            std::future::pending::<std::result::Result<(), ConnectError>>(),
            status.reader(),
            false,
            || async { relays(&["relay-1"]) },
        )
        .await
        .expect_err("a refused route");
        assert!(
            matches!(&error, TransportError::RelayRefused(refusal)
                if refusal.kind == crate::error::RelayRefusalKind::Stopping),
            "{error}"
        );
    }

    /// KR-REQ-17.40: a failure in which something answered is its own reason, whatever a relay on
    /// the route said. A peer that reset the attempt reached this endpoint.
    #[tokio::test]
    async fn a_failure_something_answered_is_its_own_reason() {
        let status = Scripted::default();
        status.set(vec![refusing("relay-1", "allowance_spent: spent")]);
        let error = through_relays(
            async { Err::<(), _>(ConnectError::from(ConnectionError::Reset)) },
            status.reader(),
            true,
            || async { relays(&["relay-1"]) },
        )
        .await
        .expect_err("the attempt failed");
        assert!(matches!(error, TransportError::Connect(_)), "{error}");
    }

    /// KR-REQ-10.02: discovery is configured only when selected, apart from the relay choice.
    #[tokio::test]
    async fn a_minimal_endpoint_reaches_no_service_it_was_not_given() {
        let identity = TransportIdentityKeyPair::generate().expect("a transport identity");
        let endpoint = bind_listener(&EndpointConfig::default(), &identity)
            .await
            .expect("an endpoint");
        assert!(
            endpoint
                .address_lookup()
                .expect("address lookup services")
                .is_empty(),
            "no discovery service is configured unless one is selected"
        );
        assert_eq!(endpoint.id().as_bytes(), identity.public().as_bytes());
        endpoint.close().await;
    }
}
