//! Building an iroh endpoint from an explicit selection.
//!
//! The whole of this module exists to make one guarantee visible: an endpoint reaches exactly the
//! services its [`EndpointConfig`] names. It starts from `presets::Minimal`, which sets the
//! cryptographic provider and nothing else, and then adds each selected service by hand. It never
//! uses `presets::N0`, `RelayMode::Default` or `RelayMode::Staging`, so no public default can
//! arrive by inheritance.

use std::time::Duration;

use iroh::endpoint::{Builder, QuicTransportConfig, presets};
use iroh::{Endpoint, RelayMode, SecretKey};
use iroh_mainline_address_lookup::DhtAddressLookup;
use iroh_mdns_address_lookup::MdnsAddressLookup;
use iroh_relay::tls::CaTlsConfig;
use kr_crypto::keys::TransportIdentityKeyPair;
use kr_protocol::hello::ALPN;
use kr_protocol::limits::{INACTIVITY_THRESHOLD, KEEPALIVE_INTERVAL, MAX_SEND_QUEUE_BYTES};
use rustls_pki_types::CertificateDer;

use crate::config::{EndpointConfig, PublishedAddresses};
use crate::error::{Result, TransportError};

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
