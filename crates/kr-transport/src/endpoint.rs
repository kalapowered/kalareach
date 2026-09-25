//! Building an iroh endpoint from an explicit selection, and dialling from it.
//!
//! The whole of this module exists to make one guarantee visible: an endpoint reaches exactly the
//! services its [`EndpointConfig`] names. It starts from `presets::Minimal`, which sets the
//! cryptographic provider and nothing else, and then adds each selected service by hand. It never
//! uses `presets::N0`, `RelayMode::Default` or `RelayMode::Staging`, so no public default can
//! arrive by inheritance.
//!
//! The same holds for the way out. With a proxy named, the relay connection, iroh's relay latency
//! probe and captive-portal check, and the Pkarr publisher and resolver all go through it. With
//! none, the relay connection and the Pkarr requests go directly. The two relay probes are the
//! exception: iroh builds their client with the environment's proxy settings when it is given no
//! proxy, and offers no way to turn that off, so they follow `HTTP_PROXY`, `HTTPS_PROXY` and
//! `ALL_PROXY` when those are set. Name lookups go directly either way, over plain DNS or DNS over
//! TLS: the resolver is this module's, and it has no DNS-over-HTTPS client, which would follow
//! those variables too.
//!
//! [`connect`] is the dialling half: it opens a connection and, when a relay the connection needed
//! turned this endpoint away, or the network refused the relay's WebSocket upgrade, says so rather
//! than reporting a peer that did not answer.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::task::{Context, Poll};
use std::time::Duration;

use iroh::endpoint::{
    Builder, ConnectOptions, ConnectingError, Connection, ConnectionError, QuicTransportConfig,
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
    let ca_tls = CaTlsConfig::default().with_extra_roots(
        config
            .relay_ca_roots
            .iter()
            .map(|der| CertificateDer::from(der.clone())),
    );
    builder = builder
        .dns_resolver(dns_resolver(&ca_tls)?)
        .ca_tls_config(ca_tls);
    // The relay client tunnels through the proxy with CONNECT, and the net report sends its relay
    // latency probe and captive-portal check through it. Nothing falls back to a direct connection
    // when the proxy cannot be reached: the owner chose to go through it. `proxy_from_env` is never
    // called, because the proxy is this configuration's to name.
    if let Some(proxy) = &config.proxy_url {
        builder = builder.proxy_url(proxy.as_url().clone());
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

/// Opens a connection to `peer`, and names the relay that could not be used when that is why no
/// path opened: one that turned this endpoint away, or one whose WebSocket upgrade the network
/// refused.
///
/// iroh keeps the reason a relay gave for refusing this endpoint, but only for this endpoint's home
/// relay, and only until it dials that relay again. So the relay status is followed for the whole
/// attempt, and a refusal counts only while the status shows it, and only when it came from a relay
/// on this connection's route: a relay the address names, or one this endpoint already holds for
/// the peer, both of which iroh tries. The status reports the latest state and can pass over the
/// states between two readings, so a relay seen refusing and then seen being dialled again may have
/// admitted this endpoint in between; what it said before is not reported. A home relay that
/// refused but is not on the route says nothing about this connection. A relay on the route that is
/// not this endpoint's home relay leaves no reason to read, so a failure through it is reported as
/// any other failure is.
///
/// A refusal is reported only for an attempt that was made and then timed out before any
/// connection was established. A request this endpoint could not make, a peer that closed, reset
/// or refused the handshake and an endpoint that was closing are each their own reason, whatever a
/// relay said at the time. The timeout alone does not prove the refusal caused it: a peer that began
/// the handshake and fell silent times out the same way. What is reported is that the status showed
/// a relay on the route turning this endpoint away when the attempt ran out.
///
/// A network that blocks WebSocket upgrades lets the relay's HTTPS through and answers the upgrade
/// the relay connection starts with something other than `101 Switching Protocols`, such as `403`.
/// The relay itself never answered, so that is not the relay's refusal: it is a connection that
/// could not be established, reported under the same rules as a refusal, naming the relay and the
/// status the upgrade was refused with. The status is read from the error the relay status keeps
/// for the latest attempt to reach the relay, which is the only place iroh reports it. When the
/// route holds both, a relay's own refusal is reported first, because it says what may still work.
///
/// An endpoint with no IP transport of its own has nothing but relays to try, so once the status
/// shows every relay on its route refusing it, or refusing its upgrade, the attempt ends there
/// rather than at its deadline: only a change outside this endpoint can open a path, iroh goes on
/// dialling the relays on its own, and an attempt made once they admit it succeeds. An endpoint
/// that can take a direct path lets the attempt run, because an address hint or local discovery can
/// still open one, and the refusal is the reason only if none does and the status still shows it
/// when the attempt ends. At that moment iroh may be dialling the relay again, which shows no
/// refusal, and the failure is then a timeout.
///
/// # Errors
///
/// Returns [`TransportError::RelayRefused`] when a relay on the route had refused this endpoint as
/// described, and [`TransportError::Connect`] for any other failure, a refused upgrade included.
pub async fn connect(
    endpoint: &Endpoint,
    peer: impl Into<EndpointAddr>,
    alpn: &[u8],
) -> Result<Connection> {
    let peer: EndpointAddr = peer.into();
    let peer_id = peer.id;
    let named: BTreeSet<RelayUrl> = peer.relay_urls().cloned().collect();
    let direct = !endpoint.bound_sockets().is_empty();
    // The request is made first, and a request that cannot be made fails as itself: no relay has
    // anything to do with an address this endpoint cannot dial or a protocol it cannot name.
    let connecting = endpoint
        .connect_with_opts(peer, alpn, ConnectOptions::default())
        .await
        .map_err(|error| TransportError::Connect(error.to_string()))?;
    through_relays(
        connecting,
        HomeRelays(endpoint.home_relay_status()),
        direct,
        || route(endpoint, peer_id, &named),
    )
    .await
}

/// Runs one attempt that has been made while following what this endpoint's relays say, and
/// decides what a failure of it is.
///
/// A refusal counts only while the status shows it, so the status is read afresh wherever a
/// decision rests on it: before a relay-only endpoint gives up, after the route is read, because
/// reading it waits, and when the attempt has failed. A change the status delivers wakes a
/// relay-only endpoint to decide again. When a change and the attempt's end are ready at once, the
/// change is taken in first.
async fn through_relays<T, S, F, R>(
    attempt: impl Future<Output = std::result::Result<T, ConnectingError>>,
    statuses: S,
    direct: bool,
    mut route: F,
) -> Result<T>
where
    S: RelayStatuses,
    F: FnMut() -> R,
    R: Future<Output = BTreeSet<RelayUrl>>,
{
    let mut followed = Followed::new(statuses);
    let mut watching = true;
    tokio::pin!(attempt);
    loop {
        followed.refresh();
        if !direct {
            let relays = route().await;
            followed.refresh();
            // The attempt ran while the route was read, and an attempt that has ended is decided by
            // how it ended: a relay-only endpoint gives up on refusals only while its attempt is
            // still waiting on them.
            let ended =
                std::future::poll_fn(|context| Poll::Ready(attempt.as_mut().poll(context))).await;
            if let Poll::Ready(outcome) = ended {
                return decided(outcome, &mut followed, &mut route, direct).await;
            }
            if let Some((relay, refusal)) = followed.refusals().throughout(&relays) {
                return Err(refused(relay, refusal, direct));
            }
        }
        tokio::select! {
            biased;
            changed = std::future::poll_fn(|context| followed.poll_changed(context)), if watching => {
                // A status whose endpoint has gone will change no more, and the attempt ends on its
                // own.
                if !changed {
                    watching = false;
                }
            }
            outcome = &mut attempt => {
                return decided(outcome, &mut followed, &mut route, direct).await;
            }
        }
    }
}

/// Decides what an ended attempt comes to.
///
/// A connection is a connection. A failure is a relay's refusal, or a refused upgrade, only when
/// the attempt timed out before connecting and the status, as it stands now, shows a relay on its
/// route refusing this endpoint or its upgrade.
async fn decided<T, S, F, R>(
    outcome: std::result::Result<T, ConnectingError>,
    followed: &mut Followed<S>,
    route: &mut F,
    direct: bool,
) -> Result<T>
where
    S: RelayStatuses,
    F: FnMut() -> R,
    R: Future<Output = BTreeSet<RelayUrl>>,
{
    let error = match outcome {
        Ok(connected) => return Ok(connected),
        Err(error) => error,
    };
    if !timed_out_unconnected(&error) {
        return Err(TransportError::Connect(error.to_string()));
    }
    let relays = route().await;
    followed.refresh();
    Err(match followed.refusals().on(&relays) {
        Some((relay, refusal)) => refused(relay, refusal, direct),
        None => TransportError::Connect(error.to_string()),
    })
}

/// Whether an attempt that was made failed by timing out before any connection was established.
///
/// That is the only failure a relay's refusal may be reported for. Every other one says something
/// answered or something here ended the attempt: a peer that closed or reset it, a handshake that
/// failed, an endpoint that was closing.
fn timed_out_unconnected(error: &ConnectingError) -> bool {
    matches!(
        error,
        ConnectingError::ConnectionError {
            source: ConnectionError::TimedOut,
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

/// Returns the failure `refusal`, met at `relay`, is.
///
/// A refused upgrade stays a connection that could not be established, which is what it is on the
/// wire as well: the relay never answered, so it did not refuse anything.
fn refused(relay: &RelayUrl, refusal: &Refusal, direct: bool) -> TransportError {
    match refusal {
        Refusal::Relay(reason) => {
            TransportError::RelayRefused(RelayRefusal::from_reason(relay.clone(), reason, direct))
        }
        Refusal::Upgrade(status) => TransportError::Connect(format!(
            "the network refused the WebSocket upgrade to the relay {relay} with HTTP status \
             {status}"
        )),
    }
}

/// What one relay's status shows about whether it can be used.
///
/// iroh reports a refusal only while the latest attempt to reach the relay is the one that was
/// refused. A relay it is connected to, one it is dialling again and one it last failed to reach
/// for another cause show no refusal of either kind.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RelayObservation {
    relay: RelayUrl,
    /// The reason the relay gave, when it refused the endpoint's latest attempt to reach it.
    refused: Option<String>,
    /// The HTTP status the relay's WebSocket upgrade was refused with, when that is how the latest
    /// attempt to reach it ended.
    upgrade_refused: Option<u16>,
}

impl RelayObservation {
    fn of(status: &RelayStatus) -> Self {
        Self {
            relay: status.url().clone(),
            refused: status.auth_denied_reason().map(ToOwned::to_owned),
            upgrade_refused: status.last_error().and_then(|error| upgrade_refusal(error)),
        }
    }
}

/// Returns the HTTP status a relay's WebSocket upgrade was refused with, when `error` says that is
/// how an attempt to reach the relay ended.
///
/// iroh reports why an attempt failed only as a chain of errors meant to be displayed, so the chain
/// is searched for the two public types a refused upgrade appears as with the pinned iroh-relay and
/// tokio-websockets: tokio-websockets' refusal of any answer but `101 Switching Protocols`, which
/// is what an answer such as `403` produces, and iroh-relay's own unexpected-status error, which it
/// keeps for an answer that got past that check. The blocked-upgrade test reads a real refusal
/// through this, so a release that reports it differently fails there rather than here.
fn upgrade_refusal(error: &(dyn std::error::Error + 'static)) -> Option<u16> {
    use tokio_websockets::upgrade::Error as UpgradeError;

    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(iroh_relay::client::ConnectError::UnexpectedUpgradeStatus { code, .. }) =
            error.downcast_ref()
        {
            return Some(code.as_u16());
        }
        if let Some(tokio_websockets::Error::Upgrade(UpgradeError::DidNotSwitchProtocols(code))) =
            error.downcast_ref()
        {
            return Some(*code);
        }
        if let Some(UpgradeError::DidNotSwitchProtocols(code)) = error.downcast_ref() {
            return Some(*code);
        }
        current = error.source();
    }
    None
}

/// Where the relay status is read from while an attempt runs.
trait RelayStatuses {
    /// Returns the status as it stands now, which is every relay it reports on.
    fn now(&mut self) -> Vec<RelayObservation>;

    /// Returns the value the status took when it last changed since it was last read, and arranges
    /// to be woken when it changes. `Ready(None)` means it never will again.
    fn poll_next(&mut self, context: &mut Context<'_>) -> Poll<Option<Vec<RelayObservation>>>;
}

/// This endpoint's home relays, as iroh reports them.
struct HomeRelays<W>(W);

impl<W: Watcher<Value = Vec<RelayStatus>>> RelayStatuses for HomeRelays<W> {
    fn now(&mut self) -> Vec<RelayObservation> {
        self.0.get().iter().map(RelayObservation::of).collect()
    }

    fn poll_next(&mut self, context: &mut Context<'_>) -> Poll<Option<Vec<RelayObservation>>> {
        match self.0.poll_updated(context) {
            Poll::Ready(Ok(())) => Poll::Ready(Some(
                self.0.peek().iter().map(RelayObservation::of).collect(),
            )),
            Poll::Ready(Err(_)) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The relay status as one attempt follows it.
///
/// The status is read only through this, and everything read is taken in before it is returned or
/// dropped. What one reading shows replaces what the reading before it showed, because a refusal
/// counts only while the status shows it, and every decision is made on a reading taken for it.
struct Followed<S> {
    statuses: S,
    refusals: Refusals,
}

impl<S: RelayStatuses> Followed<S> {
    fn new(statuses: S) -> Self {
        Self {
            statuses,
            refusals: Refusals::default(),
        }
    }

    /// Reads the status as it stands now and takes it in.
    fn refresh(&mut self) {
        let now = self.statuses.now();
        self.refusals.observe(now);
    }

    /// Takes in the next value the status delivers. `Ready(false)` means it never will again.
    fn poll_changed(&mut self, context: &mut Context<'_>) -> Poll<bool> {
        match self.statuses.poll_next(context) {
            Poll::Ready(Some(value)) => {
                self.refusals.observe(value);
                Poll::Ready(true)
            }
            Poll::Ready(None) => Poll::Ready(false),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Returns the refusals taken in so far.
    fn refusals(&self) -> &Refusals {
        &self.refusals
    }
}

/// Why a relay cannot be used, as its status shows.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Refusal {
    /// The relay turned this endpoint away, giving this reason.
    Relay(String),
    /// The network refused the relay's WebSocket upgrade with this HTTP status.
    Upgrade(u16),
}

/// The refusals the relay status showed when it was last read, by relay.
#[derive(Debug, Default)]
struct Refusals(BTreeMap<RelayUrl, Refusal>);

impl Refusals {
    /// Takes in the relay status as one reading shows it, which is every relay iroh reports on.
    ///
    /// A refusal counts only while the status shows it, whether the relay turned this endpoint away
    /// or the network refused the upgrade, so what this reading shows replaces whatever an earlier
    /// one showed. The status reports the latest state and can pass over the states between two
    /// readings: a relay seen refusing and then seen being dialled again may have admitted the
    /// endpoint in between, and the network may have let an upgrade through. A relay that is being
    /// dialled again, is connected, last failed for another cause or has left the status shows no
    /// refusal. A relay's own refusal is kept over a refused upgrade in the same status, because
    /// the relay answered.
    fn observe(&mut self, snapshot: impl IntoIterator<Item = RelayObservation>) {
        self.0 = snapshot
            .into_iter()
            .filter_map(|observation| {
                let refusal = match (observation.refused, observation.upgrade_refused) {
                    (Some(reason), _) => Refusal::Relay(reason),
                    (None, Some(status)) => Refusal::Upgrade(status),
                    (None, None) => return None,
                };
                Some((observation.relay, refusal))
            })
            .collect();
    }

    /// Returns the refusal to report for `route`: the first relay on it that turned this endpoint
    /// away, or else the first whose upgrade the network refused. A relay's own refusal comes first
    /// because it says what may still work.
    fn on<'a>(&'a self, route: &'a BTreeSet<RelayUrl>) -> Option<(&'a RelayUrl, &'a Refusal)> {
        let first = |kind: fn(&Refusal) -> bool| {
            route.iter().find_map(|relay| {
                self.0
                    .get(relay)
                    .filter(|refusal| kind(refusal))
                    .map(|refusal| (relay, refusal))
            })
        };
        first(|refusal| matches!(refusal, Refusal::Relay(_)))
            .or_else(|| first(|refusal| matches!(refusal, Refusal::Upgrade(_))))
    }

    /// Returns the refusal to report when the status shows every relay on `route` refusing, which
    /// leaves an endpoint with no direct transport nothing else to try.
    fn throughout<'a>(
        &'a self,
        route: &'a BTreeSet<RelayUrl>,
    ) -> Option<(&'a RelayUrl, &'a Refusal)> {
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

    // This crate's own Pkarr services rather than iroh's, whose HTTP client takes no proxy and
    // follows the environment's instead: these take the configuration's proxy, or none.
    if let Some(url) = &discovery.pkarr_publisher_url {
        builder = builder.address_lookup(crate::pkarr::Publisher {
            server: url.clone(),
            ttl_seconds: discovery.publisher.ttl_seconds,
            republish_interval: discovery.publisher.republish_interval,
            filter: published_addresses(config),
            proxy: config.proxy_url.clone(),
        });
    }
    if let Some(url) = &discovery.pkarr_resolver_url {
        builder = builder.address_lookup(crate::pkarr::Resolver {
            server: url.clone(),
            proxy: config.proxy_url.clone(),
        });
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

/// The public resolvers this endpoint's lookups fall back to, each as its IPv4 and IPv6 primary
/// addresses and then its secondary ones.
///
/// They are the three iroh falls back to (n0-dns-resolver 0.1.0's `public_resolvers`: Cloudflare,
/// Google and Quad9), whose certificates name these addresses, so DNS over TLS verifies without a
/// server name.
const PUBLIC_RESOLVERS: [[IpAddr; 4]; 3] = [
    [
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
        IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
    ],
    [
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
    ],
    [
        IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe)),
        IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
        IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x0009)),
    ],
];

/// Returns the resolver this endpoint looks names up with: the system's configuration, and behind
/// it the public resolvers over plain DNS and DNS over TLS.
///
/// iroh's own resolver has the same two tiers, but its fallback also asks over DNS over HTTPS, and
/// that client follows `HTTPS_PROXY` and `ALL_PROXY` whether or not a proxy is selected. This one
/// speaks no HTTP, so no proxy variable moves a lookup. (On Windows the system's configuration
/// includes the hosts file, which the resolver reads under `SystemRoot`.) DNS over TLS verifies
/// against the same anchors as the relay, and like the rest of the lookup it goes directly.
fn dns_resolver(ca_tls: &CaTlsConfig) -> Result<iroh::dns::DnsResolver> {
    let tls = ca_tls
        .client_config(iroh_relay::tls::default_provider())
        .map_err(|error| TransportError::Configuration {
            what: "dns".to_owned(),
            kind: "DNS resolver",
            reason: error.to_string(),
        })?;
    Ok(iroh::dns::DnsResolver::builder()
        .with_system_defaults()
        .fallback_nameserver_configs(fallback_nameservers())
        .tls_client_config(tls)
        .build())
}

/// Returns the fallback tier in iroh's own order, with DNS over TLS where iroh has DNS over HTTPS.
///
/// Plain entries go round the providers, primary addresses first, and one encrypted entry per
/// provider sits after the first two, inside the first wave of queries, so on a network that
/// filters port 53 the encrypted ones are already racing. A plain entry asks over UDP and asks
/// again over TCP when an answer is truncated or does not come.
fn fallback_nameservers() -> Vec<iroh::dns::NameserverConfig> {
    use iroh::dns::NameserverConfig;

    let mut servers: Vec<NameserverConfig> = (0..4)
        .flat_map(|index| {
            PUBLIC_RESOLVERS
                .iter()
                .map(move |provider| NameserverConfig::udp(provider[index]))
        })
        .collect();
    servers.splice(
        2..2,
        PUBLIC_RESOLVERS
            .iter()
            .map(|provider| NameserverConfig::tls(provider[0])),
    );
    servers
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

    /// KR-REQ-26.14: the endpoint's lookups fall back to the public resolvers over plain DNS and DNS
    /// over TLS, in iroh's order, and to nothing that speaks HTTP.
    #[test]
    fn the_dns_fallback_is_the_public_resolvers_without_http() {
        use iroh::dns::NameserverConfig;

        let servers = fallback_nameservers();
        assert_eq!(
            servers.len(),
            15,
            "twelve plain entries and three encrypted"
        );
        for server in &servers {
            let described = format!("{server:?}");
            assert!(!described.contains("Https"), "{described}");
        }
        let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        assert_eq!(
            servers[..6],
            [
                NameserverConfig::udp(v4(1, 1, 1, 1)),
                NameserverConfig::udp(v4(8, 8, 8, 8)),
                NameserverConfig::tls(v4(1, 1, 1, 1)),
                NameserverConfig::tls(v4(8, 8, 8, 8)),
                NameserverConfig::tls(v4(9, 9, 9, 9)),
                NameserverConfig::udp(v4(9, 9, 9, 9)),
            ]
        );
    }

    /// KR-REQ-26.14: an endpoint looks names up with that resolver. Its fallback asks the public
    /// resolvers over DNS over TLS, and never over HTTPS, whose client would follow the
    /// environment's proxy variables.
    #[tokio::test]
    async fn an_endpoint_looks_names_up_with_no_http_client() {
        let identity = TransportIdentityKeyPair::generate().expect("a transport identity");
        let endpoint = bind_listener(&EndpointConfig::default(), &identity)
            .await
            .expect("an endpoint");
        let described = format!("{:?}", endpoint.dns_resolver().expect("a resolver"));
        endpoint.close().await;
        assert!(
            described.contains("protocol: Tls"),
            "the fallback asks the public resolvers over DNS over TLS"
        );
        assert!(
            !described.contains("protocol: Https"),
            "the fallback asks a resolver over HTTPS"
        );
    }

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

    /// A relay that turned the endpoint away with `reason` on the latest attempt.
    fn refusing(name: &str, reason: &str) -> RelayObservation {
        RelayObservation {
            relay: relay(name),
            refused: Some(reason.to_owned()),
            upgrade_refused: None,
        }
    }

    /// A relay whose WebSocket upgrade the network refused with `status` on the latest attempt.
    fn blocked(name: &str, status: u16) -> RelayObservation {
        RelayObservation {
            relay: relay(name),
            refused: None,
            upgrade_refused: Some(status),
        }
    }

    /// The refusal a relay gives when the allowance is spent, as [`refusing`] observes it.
    fn spent() -> Refusal {
        Refusal::Relay("allowance_spent: spent".to_owned())
    }

    fn relays(names: &[&str]) -> BTreeSet<RelayUrl> {
        names.iter().map(|name| relay(name)).collect()
    }

    /// An error that wraps another, as the chain iroh keeps for a failed attempt does.
    #[derive(Debug)]
    struct Wrapping(Box<dyn std::error::Error + Send + Sync + 'static>);

    impl std::fmt::Display for Wrapping {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("the attempt failed")
        }
    }

    impl std::error::Error for Wrapping {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    /// KR-REQ-10.02: the status a refused upgrade was answered with is found wherever the chain of
    /// errors that ended the attempt holds it, in either form the pinned libraries report it in,
    /// and nothing else in a chain is read as one.
    #[test]
    fn a_refused_upgrade_is_found_in_the_chain_that_ended_the_attempt() {
        let websocket = || {
            tokio_websockets::Error::Upgrade(
                tokio_websockets::upgrade::Error::DidNotSwitchProtocols(403),
            )
        };
        assert_eq!(upgrade_refusal(&websocket()), Some(403));
        assert_eq!(
            upgrade_refusal(&Wrapping(Box::new(Wrapping(Box::new(websocket()))))),
            Some(403)
        );
        assert_eq!(
            upgrade_refusal(&Wrapping(Box::new(
                tokio_websockets::upgrade::Error::DidNotSwitchProtocols(407)
            ))),
            Some(407)
        );
        for other in [
            Wrapping(Box::new(std::io::Error::from(
                std::io::ErrorKind::ConnectionRefused,
            ))),
            Wrapping(Box::new(tokio_websockets::Error::Upgrade(
                tokio_websockets::upgrade::Error::WrongWebSocketAccept,
            ))),
        ] {
            assert_eq!(upgrade_refusal(&other), None, "{other:?}");
        }
    }

    /// KR-REQ-10.02: a refused upgrade is a connection's reason under the rules a refusal is, and
    /// it stays a connection that could not be established, naming the relay and the status: the
    /// relay never answered, so it is not the relay's refusal.
    #[tokio::test]
    async fn a_refused_upgrade_is_the_reason_a_timed_out_attempt_names() {
        let status = Scripted::default();
        status.set(vec![blocked("relay-1", 403)]);
        let error = through_relays(
            async { Err::<(), _>(timed_out()) },
            status.reader(),
            true,
            || async { relays(&["relay-1"]) },
        )
        .await
        .expect_err("the attempt failed");
        let TransportError::Connect(message) = &error else {
            panic!("a refused upgrade is a connection that could not be established: {error}");
        };
        assert_eq!(
            message,
            "the network refused the WebSocket upgrade to the relay \
             https://relay-1.reach.kala.to/ with HTTP status 403"
        );
        assert_eq!(
            error.to_protocol_error().code,
            kr_protocol::error::ErrorCode::ResourceUnavailable
        );
    }

    /// KR-REQ-10.02: an endpoint with no direct transport stops at once when no relay on its route
    /// can be used, whether the relay refused it or the network refused the upgrade. A relay's own
    /// refusal is the one reported when the route holds both, and a route whose only relays could
    /// not be upgraded to is reported as that.
    #[tokio::test]
    async fn a_relay_only_endpoint_whose_route_cannot_be_used_stops_at_once() {
        let status = Scripted::default();
        status.set(vec![blocked("relay-1", 403)]);
        let error = through_relays(
            std::future::pending::<std::result::Result<(), ConnectingError>>(),
            status.reader(),
            false,
            || async { relays(&["relay-1"]) },
        )
        .await
        .expect_err("a route that cannot be used");
        assert!(
            matches!(&error, TransportError::Connect(message) if message.contains("403")),
            "{error}"
        );

        let status = Scripted::default();
        status.set(vec![
            blocked("relay-1", 403),
            refusing("relay-2", "stopping: this relay is stopping"),
        ]);
        let error = through_relays(
            std::future::pending::<std::result::Result<(), ConnectingError>>(),
            status.reader(),
            false,
            || async { relays(&["relay-1", "relay-2"]) },
        )
        .await
        .expect_err("a route that cannot be used");
        assert!(
            matches!(&error, TransportError::RelayRefused(refusal)
                if refusal.relay == relay("relay-2")),
            "{error}"
        );
    }

    /// KR-REQ-10.02: a refused upgrade counts only while the status shows it. It ends when the
    /// relay is dialled again, when the relay admits the endpoint and when the latest attempt
    /// failed for another cause. A relay that cannot be upgraded to is still waited for while
    /// another relay on the route might carry the attempt.
    #[test]
    fn a_refused_upgrade_counts_only_while_the_status_shows_it() {
        let only = relays(&["relay-1"]);
        let upgrade = Refusal::Upgrade(403);
        let mut refusals = Refusals::default();
        refusals.observe([blocked("relay-1", 403)]);
        assert_eq!(refusals.on(&only), Some((&relay("relay-1"), &upgrade)));
        assert_eq!(refusals.throughout(&relays(&["relay-1", "relay-2"])), None);

        refusals.observe([redialling("relay-1")]);
        assert_eq!(refusals.on(&only), None, "the relay is being dialled again");

        refusals.observe([blocked("relay-1", 403)]);
        refusals.observe([RelayObservation {
            upgrade_refused: None,
            ..blocked("relay-1", 403)
        }]);
        assert_eq!(refusals.on(&only), None, "it failed for another cause");

        refusals.observe([blocked("relay-1", 403)]);
        refusals.observe([admitted("relay-1")]);
        assert_eq!(refusals.on(&only), None, "the relay was reached");
    }

    /// KR-REQ-10.02: a refused upgrade the status has moved past is not the reason an attempt
    /// failed. The status can pass over a successful attempt and the failure after it, so a relay
    /// seen refused and then seen being dialled again is not reported as refusing when the
    /// attempt times out.
    #[tokio::test]
    async fn a_refused_upgrade_the_status_moved_past_is_not_the_reason() {
        let status = Scripted::default();
        status.set(vec![blocked("relay-1", 403)]);
        let setter = status.clone();
        let error = through_relays(
            async move {
                setter.set(vec![redialling("relay-1")]);
                tokio::task::yield_now().await;
                Err::<(), _>(timed_out())
            },
            status.reader(),
            true,
            || async { relays(&["relay-1"]) },
        )
        .await
        .expect_err("the attempt failed");
        assert!(
            matches!(&error, TransportError::Connect(message) if !message.contains("upgrade")),
            "{error}"
        );
    }

    /// KR-REQ-10.02: an endpoint that can take a direct path is not cut off by a refused upgrade.
    /// Its attempt runs on while every relay on the route refuses the upgrade, and a connection it
    /// makes, as a direct path makes one, is a connection.
    #[tokio::test]
    async fn a_refused_upgrade_leaves_an_endpoint_with_a_direct_path_trying() {
        let status = Scripted::default();
        status.set(vec![blocked("relay-1", 403)]);
        let connected = through_relays(
            async {
                for _ in 0..8 {
                    tokio::task::yield_now().await;
                }
                Ok::<_, ConnectingError>("a connection")
            },
            status.reader(),
            true,
            || async { relays(&["relay-1"]) },
        )
        .await;
        assert_eq!(connected.ok(), Some("a connection"));
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
        assert_eq!(refusals.on(&only), Some((&relay("relay-1"), &spent())));
        assert_eq!(
            refusals.throughout(&only),
            Some((&relay("relay-1"), &spent()))
        );

        let both = relays(&["relay-1", "relay-2"]);
        assert_eq!(
            refusals.on(&both),
            Some((&relay("relay-1"), &spent())),
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
            Some((&relay("relay-1"), &spent()))
        );
    }

    /// KR-REQ-17.40: a relay's own refusal counts only while the status shows it, as a refused
    /// upgrade does. The status reports the latest state and can pass over an admission between two
    /// readings, so a relay seen refusing and then seen being dialled again may have admitted the
    /// endpoint in between. The refusal ends when the relay is dialled again, when the latest
    /// attempt failed for another cause and when the relay admits the endpoint.
    #[test]
    fn a_refusal_counts_only_while_the_status_shows_it() {
        let only = relays(&["relay-1"]);
        let mut refusals = Refusals::default();
        refusals.observe([refusing("relay-1", "allowance_spent: spent")]);
        assert_eq!(refusals.on(&only), Some((&relay("relay-1"), &spent())));

        refusals.observe([redialling("relay-1")]);
        assert_eq!(
            refusals.on(&only),
            None,
            "a relay being dialled again may have admitted the endpoint since it refused"
        );

        refusals.observe([refusing("relay-1", "allowance_spent: spent")]);
        refusals.observe([RelayObservation {
            refused: None,
            ..refusing("relay-1", "allowance_spent: spent")
        }]);
        assert_eq!(
            refusals.on(&only),
            None,
            "a relay that cannot be reached is not refusing"
        );

        refusals.observe([refusing("relay-1", "allowance_spent: spent")]);
        refusals.observe([admitted("relay-1")]);
        assert_eq!(
            refusals.on(&only),
            None,
            "a relay that admits the endpoint is not refusing"
        );
    }

    /// KR-REQ-17.40: a refusal ends once its relay leaves the status. iroh reports on the home
    /// relays it has now, so once another relay is home nothing the first one says is shown.
    #[test]
    fn a_refusal_is_forgotten_once_its_relay_leaves_the_status() {
        let first = relays(&["relay-1"]);
        let mut refusals = Refusals::default();
        refusals.observe([refusing("relay-1", "allowance_spent: spent")]);
        refusals.observe([redialling("relay-2")]);
        assert_eq!(refusals.on(&first), None, "another relay became home");

        refusals.observe([refusing("relay-1", "allowance_spent: spent")]);
        refusals.observe([]);
        assert_eq!(refusals.on(&first), None, "no relay is home");
    }

    /// A relay the endpoint is connected to, whose status shows no refusal.
    fn admitted(name: &str) -> RelayObservation {
        RelayObservation {
            relay: relay(name),
            refused: None,
            upgrade_refused: None,
        }
    }

    fn timed_out() -> ConnectingError {
        ConnectingError::from(ConnectionError::TimedOut)
    }

    /// A relay the endpoint is dialling again, whose status shows no refusal whatever the relay
    /// said before.
    fn redialling(name: &str) -> RelayObservation {
        RelayObservation {
            relay: relay(name),
            refused: None,
            upgrade_refused: None,
        }
    }

    /// A relay status a test changes at the moment it chooses.
    ///
    /// Each change is the value the status delivers and the value it stands at afterwards, which
    /// are the same unless the test makes the status change again the moment it is read. A read of
    /// the status as it stands passes over every change not yet delivered, as iroh's does.
    #[derive(Clone, Default)]
    struct Scripted(std::sync::Arc<std::sync::Mutex<ScriptedState>>);

    #[derive(Default)]
    struct ScriptedState {
        current: Vec<RelayObservation>,
        changes: std::collections::VecDeque<(Vec<RelayObservation>, Vec<RelayObservation>)>,
        waker: Option<std::task::Waker>,
    }

    impl Scripted {
        fn set(&self, value: Vec<RelayObservation>) {
            self.change(value.clone(), value);
        }

        /// Delivers `delivered` as the next change, after which the status stands at `after`.
        fn change(&self, delivered: Vec<RelayObservation>, after: Vec<RelayObservation>) {
            let mut state = self.0.lock().expect("the scripted status");
            state.changes.push_back((delivered, after));
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
        }

        fn reader(&self) -> ScriptedReader {
            ScriptedReader(self.clone())
        }
    }

    /// The reading end of a scripted status.
    struct ScriptedReader(Scripted);

    impl RelayStatuses for ScriptedReader {
        fn now(&mut self) -> Vec<RelayObservation> {
            let mut state = self.0.0.lock().expect("the scripted status");
            while let Some((_, after)) = state.changes.pop_front() {
                state.current = after;
            }
            state.current.clone()
        }

        fn poll_next(&mut self, context: &mut Context<'_>) -> Poll<Option<Vec<RelayObservation>>> {
            let mut state = self.0.0.lock().expect("the scripted status");
            match state.changes.pop_front() {
                Some((delivered, after)) => {
                    state.current = after;
                    Poll::Ready(Some(delivered))
                }
                None => {
                    state.waker = Some(context.waker().clone());
                    Poll::Pending
                }
            }
        }
    }

    /// KR-REQ-17.40: a relay's own refusal the status has moved past is not the reason an attempt
    /// failed. The status reports only the latest state and can pass over an admission between two
    /// readings, so a relay seen refusing and then seen being dialled again may have admitted this
    /// endpoint in between, and its refusal is not reported when the attempt times out.
    #[tokio::test]
    async fn a_refusal_the_status_moved_past_is_not_the_reason() {
        let status = Scripted::default();
        status.set(vec![refusing("relay-1", "allowance_spent: spent")]);
        let setter = status.clone();
        let error = through_relays(
            async move {
                // The relay admitted the endpoint and the connection ended again, and no reading
                // saw either: the next one sees the relay being dialled again.
                setter.set(vec![redialling("relay-1")]);
                tokio::task::yield_now().await;
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

    /// KR-REQ-17.40: a value the status delivered is taken in, although the status changed again
    /// before it was next read. A relay that refused, then admitted the endpoint, then was dialled
    /// again, is not the reason the attempt failed, whether or not a reading saw the admission.
    #[tokio::test]
    async fn an_admission_the_status_delivered_is_taken_in_before_it_changes_again() {
        let status = Scripted::default();
        status.set(vec![refusing("relay-1", "allowance_spent: spent")]);
        let setter = status.clone();
        let error = through_relays(
            async move {
                setter.change(vec![admitted("relay-1")], vec![redialling("relay-1")]);
                tokio::task::yield_now().await;
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

    /// KR-REQ-17.40: a refusal the status delivered counts only while the status shows it. The
    /// status had moved on to dialling the relay again before it was next read, so the refusal is
    /// not the reason the attempt failed.
    #[tokio::test]
    async fn a_refusal_the_status_delivered_and_then_moved_past_is_not_the_reason() {
        let status = Scripted::default();
        let setter = status.clone();
        let error = through_relays(
            async move {
                setter.change(
                    vec![refusing("relay-1", "allowance_spent: spent")],
                    vec![redialling("relay-1")],
                );
                tokio::task::yield_now().await;
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
            std::future::pending::<std::result::Result<(), ConnectingError>>(),
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

    /// KR-REQ-17.40: an attempt that ends while a relay-only endpoint reads its route is decided by
    /// how it ended. A connection made then is a connection, and a failure in which something
    /// answered is its own reason, although every relay on the route had refused the endpoint.
    #[tokio::test]
    async fn an_attempt_that_ends_while_the_route_is_read_is_decided_by_how_it_ended() {
        let status = Scripted::default();
        status.set(vec![refusing("relay-1", "allowance_spent: spent")]);
        let (ended, ending) = tokio::sync::oneshot::channel::<()>();
        let mut ended = Some(ended);
        let connected = through_relays(
            async move {
                let _ = ending.await;
                Ok::<_, ConnectingError>("a connection")
            },
            status.reader(),
            false,
            || {
                if let Some(ended) = ended.take() {
                    let _ = ended.send(());
                }
                async { relays(&["relay-1"]) }
            },
        )
        .await;
        assert_eq!(connected.ok(), Some("a connection"));

        let status = Scripted::default();
        status.set(vec![refusing("relay-1", "allowance_spent: spent")]);
        let (ended, ending) = tokio::sync::oneshot::channel::<()>();
        let mut ended = Some(ended);
        let error = through_relays(
            async move {
                let _ = ending.await;
                Err::<(), _>(ConnectingError::from(ConnectionError::Reset))
            },
            status.reader(),
            false,
            || {
                if let Some(ended) = ended.take() {
                    let _ = ended.send(());
                }
                async { relays(&["relay-1"]) }
            },
        )
        .await
        .expect_err("the attempt was reset");
        assert!(matches!(error, TransportError::Connect(_)), "{error}");
    }

    /// KR-REQ-17.40: a failure in which something answered is its own reason, whatever a relay on
    /// the route said. A peer that reset the attempt reached this endpoint.
    #[tokio::test]
    async fn a_failure_something_answered_is_its_own_reason() {
        let status = Scripted::default();
        status.set(vec![refusing("relay-1", "allowance_spent: spent")]);
        let error = through_relays(
            async { Err::<(), _>(ConnectingError::from(ConnectionError::Reset)) },
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
