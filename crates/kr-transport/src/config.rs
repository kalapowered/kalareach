//! Endpoint configuration: every network service selected by name, none inherited.
//!
//! Section 17 is explicit: build each endpoint from `presets::Minimal`, then add the selected
//! relay map, Pkarr publisher, Pkarr resolver and DNS address lookup explicitly, and do not
//! inherit hidden n0 publishing, resolution or relay defaults. Local discovery and the Mainline
//! DHT stay disabled unless selected.
//!
//! [`EndpointConfig`] is that selection. Each service is its own field, so a self-hosted
//! deployment replaces one without touching the rest, and a field left unset means the service is
//! not used. There is no fallback list and no default URL anywhere in this module: the only way an
//! endpoint reaches a service is for a configuration to name it.
//!
//! The same selection travels in a pairing invitation and a host bundle as
//! [`kr_protocol::pairing::NetworkConfig`]. [`EndpointConfig::from_network_config`] and
//! [`EndpointConfig::to_network_config`] convert between the two, so the configuration a device
//! pairs with is the configuration it dials with. The one exception is the HTTP proxy
//! ([`ProxyUrl`]): how this machine reaches the network is its own choice, so no invitation
//! carries it.

use std::net::SocketAddr;
use std::time::Duration;

use iroh::{EndpointAddr, PublicKey, RelayMap, RelayUrl};
use kr_protocol::pairing::{MAX_NETWORK_HINTS, NetworkConfig, NetworkHint};
use kr_protocol::scalars::EndpointKey;
use kr_protocol::scalars::Nullable;
/// The URL type every selected service is named by.
///
/// Re-exported so a host that builds this configuration does not have to take a dependency on the
/// URL library to name the services it selected.
pub use url::Url;

use crate::error::{Result, TransportError};

/// How long a published discovery record stays valid, in seconds.
///
/// Section 17: a 30-second DNS time to live.
pub const DISCOVERY_RECORD_TTL_SECONDS: u32 = 30;

/// How often an unchanged discovery record is republished.
///
/// Section 17: republish unchanged records every five minutes. A changed home relay is published
/// immediately, which iroh's publisher does on its own because it watches the endpoint's address.
pub const DISCOVERY_REPUBLISH_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// What a publisher puts in a signed, public discovery record.
///
/// Signed Pkarr records are public, so the default publishes relay addresses only. Direct
/// addresses are exchanged through the protected pairing exchange and authenticated peer updates
/// instead.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PublishedAddresses {
    /// Relay addresses only. The default, and the only one that keeps direct addresses private.
    #[default]
    RelayOnly,
    /// Relay addresses and current direct addresses.
    ///
    /// An operator selects this for a deployment where the direct addresses are already public,
    /// such as a fixed server.
    RelayAndDirect,
}

/// The republish rules of a discovery publisher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublisherPolicy {
    /// The record's time to live, in seconds.
    pub ttl_seconds: u32,
    /// How often an unchanged record is republished. A changed home relay is published at once,
    /// without waiting for this interval.
    pub republish_interval: Duration,
    /// What goes into the public record.
    pub published_addresses: PublishedAddresses,
}

impl Default for PublisherPolicy {
    fn default() -> Self {
        Self {
            ttl_seconds: DISCOVERY_RECORD_TTL_SECONDS,
            republish_interval: DISCOVERY_REPUBLISH_INTERVAL,
            published_addresses: PublishedAddresses::RelayOnly,
        }
    }
}

/// The discovery services this endpoint uses.
///
/// Publication and resolution are separate choices, and so are the Pkarr and DNS paths: a
/// deployment can publish to its own Pkarr server while resolving over DNS, or resolve without
/// publishing at all. Nothing here has a default value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscoveryConfig {
    /// The Pkarr server this endpoint publishes its signed record to.
    pub pkarr_publisher_url: Option<Url>,
    /// The Pkarr server this endpoint resolves other endpoints from.
    pub pkarr_resolver_url: Option<Url>,
    /// The DNS origin this endpoint resolves other endpoints from.
    pub dns_origin: Option<String>,
    /// The republish rules of the publisher, when one is selected.
    pub publisher: PublisherPolicy,
    /// Whether local network discovery is selected. Disabled unless selected.
    pub local_discovery: bool,
    /// Whether the public Mainline DHT is selected. Disabled unless selected.
    ///
    /// It carries no KalaReach service guarantee and publishes to a public network, which is why
    /// it is never on by default.
    pub mainline_dht: bool,
}

impl DiscoveryConfig {
    /// Returns true when no discovery service is selected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pkarr_publisher_url.is_none()
            && self.pkarr_resolver_url.is_none()
            && self.dns_origin.is_none()
            && !self.local_discovery
            && !self.mainline_dht
    }
}

/// Everything an endpoint is built from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EndpointConfig {
    /// The selected relay map. An empty map disables relaying.
    pub relay_urls: Vec<RelayUrl>,
    /// The selected discovery services.
    pub discovery: DiscoveryConfig,
    /// Direct-address hints for peers this endpoint dials.
    ///
    /// Hints only. A cached hint is not a permanent route: after a failure or a network change the
    /// pinned endpoint identity is resolved again.
    pub direct_addresses: Vec<SocketAddr>,
    /// The address this endpoint binds to. `None` binds to an unspecified address and a free port.
    pub bind_addr: Option<SocketAddr>,
    /// Whether this endpoint may use direct IP paths at all.
    ///
    /// `false` is the ordinary case: an endpoint tries direct paths and falls back to the relay.
    /// `true` removes the IP transports altogether, so every packet goes through the selected
    /// relay. A deployment selects it where a direct path is not available or not wanted, and it
    /// is how the relay path is exercised on its own: two endpoints that can reach each other
    /// directly will, whatever addresses they were given.
    pub relay_only: bool,
    /// Extra trust anchors for the relay's HTTPS certificate, as DER-encoded certificates.
    ///
    /// The relay path is ordinary HTTPS, so by default it is verified against the public trust
    /// anchors. A self-hosted deployment whose relay presents a certificate from a private
    /// authority pins that authority here; the public anchors stay in force alongside it, so this
    /// adds trust rather than replacing it. An empty list is the ordinary case.
    pub relay_ca_roots: Vec<Vec<u8>>,
    /// The HTTP proxy this endpoint's own web requests go through: the relay connection, the
    /// relay latency probe and captive-portal check, and the Pkarr publisher and resolver.
    ///
    /// It is this machine's own choice. A pairing invitation and a host bundle never carry it, and
    /// nothing reads it from the environment. `None` sends the relay connection and the Pkarr
    /// requests directly; iroh's two relay probes then follow the environment's proxy variables,
    /// which [`crate::endpoint`] explains.
    pub proxy_url: Option<ProxyUrl>,
}

/// The HTTP proxy an endpoint's own web requests go through, named by its origin.
///
/// An `http` or `https` scheme, a host and an optional port, and nothing after them. A proxy URL
/// that names a user or a password cannot be built: a proxy that needs credentials is not
/// supported, and a credential is never dropped to use the proxy without it, because the proxy
/// would then turn every request away. So a value of this type carries no credential, and
/// printing one prints none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyUrl(Url);

impl ProxyUrl {
    /// Returns the proxy's URL.
    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.0
    }
}

impl std::str::FromStr for ProxyUrl {
    type Err = ProxyUrlError;

    /// Reads a proxy's origin.
    ///
    /// A credential is refused as written, before anything else is decided about the address, so
    /// the refusal says why even when something else is wrong with it too. The parsed URL is too
    /// late to tell: the parser drops an empty user and password, and it refuses a port it cannot
    /// read without saying anything about the user in front of it. So the parser is asked to report
    /// every user and password it reads as it reads them, and an address it cannot read that far
    /// is searched by the rule the host configuration document uses.
    fn from_str(value: &str) -> std::result::Result<Self, ProxyUrlError> {
        let credentials = std::cell::Cell::new(false);
        let noticed = |violation: url::SyntaxViolation| {
            if violation == url::SyntaxViolation::EmbeddedCredentials {
                credentials.set(true);
            }
        };
        let parsed = Url::options()
            .syntax_violation_callback(Some(&noticed))
            .parse(value);
        if credentials.get() || names_user_information(value) {
            return Err(ProxyUrlError::Credentials);
        }
        let url = parsed.map_err(ProxyUrlError::Unparsable)?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ProxyUrlError::Credentials);
        }
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ProxyUrlError::Scheme);
        }
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(ProxyUrlError::NotAnOrigin);
        }
        Ok(Self(url))
    }
}

impl std::fmt::Display for ProxyUrl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Whether `value` names a user or a password before its host, even an empty one, which is where a
/// URL carries a credential.
///
/// The authority is read as a URL parser reads it: after the scheme's colon and every `/` or `\`
/// that follows it, up to the next `/`, `\`, `?` or `#`, whatever the scheme. So an `@` in a path or
/// a query is not mistaken for one, and extra slashes do not hide one. The host configuration
/// document refuses a proxy by the same rule.
fn names_user_information(value: &str) -> bool {
    let after_scheme = value
        .split_once(':')
        .filter(|(scheme, _)| is_scheme(scheme))
        .map_or(value, |(_, rest)| rest);
    after_scheme
        .trim_start_matches(['/', '\\'])
        .split(['/', '?', '#', '\\'])
        .next()
        .is_some_and(|authority| authority.contains('@'))
}

/// Whether `value` is spelled as a URL scheme: a letter, then letters, digits, `+`, `-` or `.`.
fn is_scheme(value: &str) -> bool {
    value.starts_with(|character: char| character.is_ascii_alphabetic())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "+-.".contains(character))
}

/// Why an address is not a usable proxy.
///
/// None of these repeats the address. Whatever an owner wrote may carry a credential, so a
/// refusal names what is wrong with it rather than quoting it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProxyUrlError {
    /// The address is not a URL at all.
    #[error("{0}")]
    Unparsable(url::ParseError),
    /// The URL names a user or a password.
    #[error("a proxy that needs credentials is not supported")]
    Credentials,
    /// The scheme is neither `http` nor `https`.
    #[error("the scheme must be http or https")]
    Scheme,
    /// Something follows the host and port.
    #[error("a proxy is named by its scheme, host and port, with nothing after them")]
    NotAnOrigin,
}

impl EndpointConfig {
    /// Returns the address to dial a peer at, from this configuration's hints.
    ///
    /// The relay and the direct addresses in a pairing invitation describe where the *peer* is, not
    /// where this endpoint is reachable, so they belong on the address that is dialled rather than
    /// on the local endpoint. A hint is only a hint: the endpoint identity is what authenticates,
    /// and after a failure or a network change the identity is resolved again.
    /// # Errors
    ///
    /// Returns [`TransportError::Configuration`] when the identity is 32 bytes but not a public
    /// key. An endpoint identity arrives from a pairing invitation, so it is checked here rather
    /// than trusted.
    pub fn peer_addr(&self, endpoint_id: &EndpointKey) -> Result<EndpointAddr> {
        let key = PublicKey::from_bytes(endpoint_id.as_bytes()).map_err(|error| {
            TransportError::Configuration {
                what: kr_protocol::scalars::to_base64url(endpoint_id.as_bytes()),
                kind: "endpoint identity",
                reason: error.to_string(),
            }
        })?;
        let mut addr = EndpointAddr::new(key);
        if let Some(relay) = self.relay_urls.first() {
            addr = addr.with_relay_url(relay.clone());
        }
        for direct in &self.direct_addresses {
            addr = addr.with_ip_addr(*direct);
        }
        Ok(addr)
    }

    /// Returns the relay map iroh is configured with.
    #[must_use]
    pub fn relay_map(&self) -> RelayMap {
        RelayMap::from_iter(self.relay_urls.iter().cloned())
    }

    /// Returns true when no relay is selected.
    #[must_use]
    pub fn relays_disabled(&self) -> bool {
        self.relay_urls.is_empty()
    }

    /// Reads the configuration a pairing invitation or host bundle carried.
    ///
    /// Every field is validated here rather than at the point of use: an invitation arrives from
    /// the network, and a malformed URL must be refused before it becomes part of an endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Configuration`] naming the first field that is not a usable URL,
    /// origin or socket address.
    pub fn from_network_config(config: &NetworkConfig) -> Result<Self> {
        if !config.is_bounded() {
            return Err(TransportError::Configuration {
                what: "the network configuration".to_owned(),
                kind: "bounded selection",
                reason: format!("each list holds at most {MAX_NETWORK_HINTS} entries"),
            });
        }
        let relay_urls = config
            .relay_urls
            .iter()
            .map(|hint| parse_relay_url(hint.as_str()))
            .collect::<Result<Vec<_>>>()?;
        let direct_addresses = config
            .direct_addresses
            .iter()
            .map(|hint| parse_socket_addr(hint.as_str()))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            relay_urls,
            discovery: DiscoveryConfig {
                pkarr_publisher_url: optional_hint(&config.pkarr_publisher_url)
                    .map(|hint| parse_http_url(hint, "Pkarr publisher URL"))
                    .transpose()?,
                pkarr_resolver_url: optional_hint(&config.pkarr_resolver_url)
                    .map(|hint| parse_http_url(hint, "Pkarr resolver URL"))
                    .transpose()?,
                dns_origin: optional_hint(&config.dns_origin)
                    .map(parse_dns_origin)
                    .transpose()?,
                publisher: PublisherPolicy::default(),
                local_discovery: false,
                mainline_dht: false,
            },
            direct_addresses,
            bind_addr: None,
            relay_only: false,
            relay_ca_roots: Vec::new(),
            proxy_url: None,
        })
    }

    /// Builds the configuration a pairing invitation or host bundle carries.
    ///
    /// Local discovery, the Mainline DHT and the HTTP proxy are deliberately absent: they are a
    /// local choice on each device, not something one device selects on another's behalf.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Configuration`] when a value does not fit a network hint.
    pub fn to_network_config(&self) -> Result<NetworkConfig> {
        Ok(NetworkConfig {
            relay_urls: self
                .relay_urls
                .iter()
                .map(|url| hint(url.as_str()))
                .collect::<Result<Vec<_>>>()?,
            pkarr_publisher_url: nullable_hint(
                self.discovery.pkarr_publisher_url.as_ref().map(Url::as_str),
            )?,
            pkarr_resolver_url: nullable_hint(
                self.discovery.pkarr_resolver_url.as_ref().map(Url::as_str),
            )?,
            dns_origin: nullable_hint(self.discovery.dns_origin.as_deref())?,
            direct_addresses: self
                .direct_addresses
                .iter()
                .map(|addr| hint(&addr.to_string()))
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

fn optional_hint(value: &Nullable<NetworkHint>) -> Option<&str> {
    value.as_ref().map(NetworkHint::as_str)
}

fn hint(value: &str) -> Result<NetworkHint> {
    NetworkHint::new(value).map_err(|error| TransportError::Configuration {
        what: value.to_owned(),
        kind: "network hint",
        reason: error.to_string(),
    })
}

fn nullable_hint(value: Option<&str>) -> Result<Nullable<NetworkHint>> {
    match value {
        Some(value) => hint(value).map(Nullable::some),
        None => Ok(Nullable::null()),
    }
}

fn parse_relay_url(value: &str) -> Result<RelayUrl> {
    value.parse().map_err(
        |error: iroh::RelayUrlParseError| TransportError::Configuration {
            what: value.to_owned(),
            kind: "relay URL",
            reason: error.to_string(),
        },
    )
}

fn parse_http_url(value: &str, kind: &'static str) -> Result<Url> {
    let url = Url::parse(value).map_err(|error| TransportError::Configuration {
        what: value.to_owned(),
        kind,
        reason: error.to_string(),
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(TransportError::Configuration {
            what: value.to_owned(),
            kind,
            reason: "the scheme must be http or https".to_owned(),
        });
    }
    Ok(url)
}

fn parse_dns_origin(value: &str) -> Result<String> {
    // The origin is a domain suffix, not a URL. Anything that looks like a URL, a path or an empty
    // label is refused here rather than producing queries for a name that cannot exist.
    let invalid = value.is_empty()
        || value.len() > 253
        || value.contains(['/', ':', '@', '?', '#', ' '])
        || value.split('.').any(str::is_empty);
    if invalid {
        return Err(TransportError::Configuration {
            what: value.to_owned(),
            kind: "DNS origin",
            reason: "a DNS origin is a dotted domain name with no scheme or path".to_owned(),
        });
    }
    Ok(value.to_owned())
}

fn parse_socket_addr(value: &str) -> Result<SocketAddr> {
    value.parse().map_err(
        |error: std::net::AddrParseError| TransportError::Configuration {
            what: value.to_owned(),
            kind: "direct address",
            reason: error.to_string(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EndpointConfig {
        EndpointConfig {
            relay_urls: vec!["https://relay.kala.to".parse().expect("a relay URL")],
            discovery: DiscoveryConfig {
                pkarr_publisher_url: Some(
                    Url::parse("https://discovery.kala.to/pkarr").expect("a URL"),
                ),
                pkarr_resolver_url: Some(
                    Url::parse("https://discovery.kala.to/pkarr").expect("a URL"),
                ),
                dns_origin: Some("discovery.kala.to".to_owned()),
                publisher: PublisherPolicy::default(),
                local_discovery: false,
                mainline_dht: false,
            },
            direct_addresses: vec!["192.0.2.1:41234".parse().expect("an address")],
            bind_addr: None,
            relay_only: false,
            relay_ca_roots: Vec::new(),
            proxy_url: None,
        }
    }

    /// KR-REQ-10.02: the proxy is this machine's own choice. A pairing invitation carries the
    /// selection a device dials with, and never the proxy the inviting machine reaches the network
    /// through.
    #[test]
    fn no_invitation_carries_the_proxy() {
        let mut config = sample();
        config.proxy_url = Some("http://proxy.example.com:3128".parse().expect("a proxy"));
        let wire = config.to_network_config().expect("a network configuration");
        assert_eq!(
            wire,
            sample()
                .to_network_config()
                .expect("a network configuration"),
            "the invitation is the one the same selection without a proxy writes"
        );
        let parsed = EndpointConfig::from_network_config(&wire).expect("a parsed configuration");
        assert_eq!(parsed.proxy_url, None);
    }

    /// KR-REQ-10.02: a proxy is named by its origin and names no credential. A user or a password
    /// is refused as a proxy that needs credentials, before anything else about the address is
    /// decided, and no refusal repeats the address.
    #[test]
    fn a_proxy_is_an_origin_that_carries_no_credential() {
        for accepted in [
            "http://proxy.example.com:3128",
            "http://proxy.example.com:3128/",
            "https://proxy.example.com",
            "http://127.0.0.1:8080",
            "http://[::1]:3128",
        ] {
            let proxy: ProxyUrl = accepted.parse().unwrap_or_else(|error| {
                panic!("{accepted}: {error}");
            });
            assert!(proxy.as_url().username().is_empty() && proxy.as_url().password().is_none());
        }
        let secret = "hunter2";
        for (refused, expected) in [
            (
                format!("http://user:{secret}@proxy.example.com:3128"),
                ProxyUrlError::Credentials,
            ),
            (
                format!("http://{secret}@proxy.example.com"),
                ProxyUrlError::Credentials,
            ),
            (
                format!("socks5://user:{secret}@proxy.example.com:1080"),
                ProxyUrlError::Credentials,
            ),
            // An empty user and password are user information as written, although the URL
            // parser drops them, and a credential in front of a port the parser refuses is still
            // refused as a credential.
            (
                format!("http://@{secret}.example.com"),
                ProxyUrlError::Credentials,
            ),
            (
                format!("http://:@{secret}.example.com"),
                ProxyUrlError::Credentials,
            ),
            (
                format!("http://user:{secret}@proxy.example.com:99999"),
                ProxyUrlError::Credentials,
            ),
            // Extra slashes after the scheme, which the URL parser passes over, hide nothing.
            (
                format!("http:///@{secret}.example.com"),
                ProxyUrlError::Credentials,
            ),
            (
                format!("http:///:@{secret}.example.com"),
                ProxyUrlError::Credentials,
            ),
            (
                format!("https:\\\\user:{secret}@proxy.example.com"),
                ProxyUrlError::Credentials,
            ),
            (
                format!("socks5://{secret}.example.com:1080"),
                ProxyUrlError::Scheme,
            ),
            (
                format!("http://proxy.example.com:3128/{secret}"),
                ProxyUrlError::NotAnOrigin,
            ),
            (
                format!("http://proxy.example.com:3128/?{secret}"),
                ProxyUrlError::NotAnOrigin,
            ),
            (
                format!("http://proxy.example.com:3128/#{secret}"),
                ProxyUrlError::NotAnOrigin,
            ),
            (format!("{secret}.example.com:3128"), ProxyUrlError::Scheme),
        ] {
            let error = refused
                .parse::<ProxyUrl>()
                .expect_err("an address that is not a usable proxy");
            assert_eq!(error, expected, "{refused}");
            assert!(!error.to_string().contains(secret), "{refused}: {error}");
        }
        assert!(matches!(
            format!("http://{secret}.example.com:99999").parse::<ProxyUrl>(),
            Err(ProxyUrlError::Unparsable(_))
        ));
    }

    /// KR-REQ-10.02: a pairing invitation carries the selected network configuration.
    #[test]
    fn a_selection_survives_the_round_trip_through_a_pairing_invitation() {
        let config = sample();
        let wire = config.to_network_config().expect("a network configuration");
        let parsed = EndpointConfig::from_network_config(&wire).expect("a parsed configuration");
        assert_eq!(parsed.relay_urls, config.relay_urls);
        assert_eq!(
            parsed.discovery.pkarr_publisher_url,
            config.discovery.pkarr_publisher_url
        );
        assert_eq!(
            parsed.discovery.pkarr_resolver_url,
            config.discovery.pkarr_resolver_url
        );
        assert_eq!(parsed.discovery.dns_origin, config.discovery.dns_origin);
        assert_eq!(parsed.direct_addresses, config.direct_addresses);
    }

    /// KR-REQ-10.02: an invitation selects only the services the host chose.
    #[test]
    fn an_invitation_never_selects_local_discovery_or_the_public_dht() {
        let mut config = sample();
        config.discovery.local_discovery = true;
        config.discovery.mainline_dht = true;
        let wire = config.to_network_config().expect("a network configuration");
        let parsed = EndpointConfig::from_network_config(&wire).expect("a parsed configuration");
        assert!(!parsed.discovery.local_discovery);
        assert!(!parsed.discovery.mainline_dht);
    }

    /// KR-REQ-10.02: discovery and relay are separate choices, and choosing neither reaches
    /// neither.
    #[test]
    fn an_empty_selection_reaches_no_service() {
        let parsed = EndpointConfig::from_network_config(&NetworkConfig::empty())
            .expect("an empty configuration");
        assert!(parsed.relays_disabled());
        assert!(parsed.discovery.is_empty());
        assert!(parsed.relay_map().is_empty());
    }

    #[test]
    fn a_publisher_url_must_be_http() {
        let mut wire = sample().to_network_config().expect("a configuration");
        wire.pkarr_publisher_url =
            Nullable::some(NetworkHint::new("ftp://example.invalid").expect("a hint"));
        assert!(matches!(
            EndpointConfig::from_network_config(&wire),
            Err(TransportError::Configuration {
                kind: "Pkarr publisher URL",
                ..
            })
        ));
    }

    #[test]
    fn a_dns_origin_is_a_domain_not_a_url() {
        let mut wire = sample().to_network_config().expect("a configuration");
        wire.dns_origin =
            Nullable::some(NetworkHint::new("https://discovery.kala.to/").expect("a hint"));
        assert!(matches!(
            EndpointConfig::from_network_config(&wire),
            Err(TransportError::Configuration {
                kind: "DNS origin",
                ..
            })
        ));
    }

    #[test]
    fn the_publisher_defaults_match_the_specified_republish_rules() {
        let policy = PublisherPolicy::default();
        assert_eq!(policy.ttl_seconds, 30);
        assert_eq!(policy.republish_interval, Duration::from_secs(300));
        assert_eq!(policy.published_addresses, PublishedAddresses::RelayOnly);
    }
}
