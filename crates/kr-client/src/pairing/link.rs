//! How a device reaches a host it is pairing with, or paired with, over iroh.
//!
//! Every connection goes through [`EndpointPool`], which binds one dialling endpoint per distinct
//! network configuration with this device's one transport key, so each host is reached through
//! the relay and discovery services its own configuration selects: an iroh endpoint's relay map
//! and address lookups belong to the endpoint, and a connection dials through the endpoint it is
//! given. Hosts whose configurations select the same services share an endpoint.
//!
//! One key cannot hold two endpoints on one relay at once: a relay keeps one active client per key
//! and parks the other, so the parked endpoint's relayed path goes quiet. The pool therefore never
//! keeps two endpoints of different configurations that select a common relay; binding one closes
//! the other, and whatever used it connects again later.
//!
//! [`HostLink`] is the whole of what the pairing flows ask of the network, so a test can put a
//! dialler that reaches another host, or a layer that alters an answer, in its place. [`IrohLink`]
//! is the product's.

use std::net::SocketAddr;
use std::sync::Arc;

use iroh::Endpoint;
use iroh::endpoint::Connection;
use kr_crypto::keys::TransportIdentityKeyPair;
use kr_protocol::error::ProtocolError;
use kr_protocol::hello::{ALPN, HostSelection};
use kr_protocol::method::Method;
use kr_protocol::pairing::{NetworkConfig, NetworkHint, PairFinishRequest};
use kr_protocol::preauth::{
    PairFinishResult, PairRedeemParams, PairRedeemResult, PairStatusParams, PairStatusResult,
};
use kr_protocol::scalars::{EndpointKey, Nullable};
use kr_transport::config::EndpointConfig;
use kr_transport::handshake::{CandidateConnection, LocalIdentity};
use kr_transport::scheduler::SendLimits;
use tokio::sync::Mutex;

use super::BoxFuture;
use super::paired::PairedHost;
use crate::session::Session;
use crate::transport::NetworkTransport;

/// Why a call to a host did not answer.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    /// The host answered with a refusal of its own.
    #[error("the host refused: {}: {}", .0.code.as_str(), .0.message)]
    Refused(ProtocolError),
    /// The host could not be reached, or the connection to it ended.
    #[error("the host could not be reached: {0}")]
    Lost(String),
    /// The network configuration a host gave could not be used.
    #[error("the host's network configuration cannot be used: {0}")]
    Configuration(String),
}

impl From<kr_transport::TransportError> for LinkError {
    fn from(error: kr_transport::TransportError) -> Self {
        match error {
            kr_transport::TransportError::Handshake(refusal) => Self::Refused(refusal),
            kr_transport::TransportError::Configuration { .. } => {
                Self::Configuration(error.to_string())
            }
            other => Self::Lost(other.to_string()),
        }
    }
}

/// The bounded pre-authorisation surface of a host this device is pairing with.
///
/// It serves three methods and nothing else. A candidate's connection reaches nothing more.
pub trait Preauth: Send {
    /// The selection the host answered the unpaired offer with.
    fn selection(&self) -> &HostSelection;

    /// `pair.finish`: binds a short-code transcript to this connection's endpoints.
    fn finish<'a>(
        &'a mut self,
        request: &'a PairFinishRequest,
    ) -> BoxFuture<'a, Result<PairFinishResult, LinkError>>;

    /// `pair.redeem`: a direct invitation's challenge, or its proof.
    fn redeem<'a>(
        &'a mut self,
        params: &'a PairRedeemParams,
    ) -> BoxFuture<'a, Result<PairRedeemResult, LinkError>>;

    /// `pair.status`: where this device's own attempt has reached.
    fn status<'a>(
        &'a mut self,
        params: &'a PairStatusParams,
    ) -> BoxFuture<'a, Result<PairStatusResult, LinkError>>;
}

/// Everything the pairing flows ask of the network.
pub trait HostLink: Send + Sync {
    /// Dials `endpoint` through the endpoint for `network`, with that configuration's hints.
    ///
    /// What the connection's `remote_id` is decides whether it is the host: nothing here assumes
    /// the peer reached is the one asked for.
    fn dial<'a>(
        &'a self,
        network: &'a NetworkConfig,
        endpoint: &'a EndpointKey,
    ) -> BoxFuture<'a, Result<Connection, LinkError>>;

    /// Opens the pre-authorisation surface on `connection`, offering `identity`.
    fn open_unpaired<'a>(
        &'a self,
        connection: &'a Connection,
        identity: &'a LocalIdentity,
    ) -> BoxFuture<'a, Result<Box<dyn Preauth>, LinkError>>;

    /// Connects to a paired host as the device it became, and starts a session on the
    /// connection.
    fn connect_paired<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
    ) -> BoxFuture<'a, Result<Session, LinkError>>;
}

/// The live peer of a connection, as kr-pairing checks it.
///
/// It is read from the connection iroh authenticated, never from what an invitation or a bundle
/// said. A connection this device dialled completed its handshake before the dial returned, and
/// its endpoint keeps no TLS tickets, so nothing on it ever travelled as early data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionPeer(EndpointKey);

impl ConnectionPeer {
    /// The peer `connection` is authenticated to.
    #[must_use]
    pub fn of(connection: &Connection) -> Self {
        Self(EndpointKey::from_bytes(*connection.remote_id().as_bytes()))
    }

    /// The peer's endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> EndpointKey {
        self.0
    }
}

impl kr_pairing::platform::LivePeer for ConnectionPeer {
    fn live_endpoint(&self) -> kr_pairing::Result<EndpointKey> {
        Ok(self.0)
    }

    fn arrived_in_early_data(&self) -> bool {
        false
    }
}

/// What makes two configurations need two endpoints: the services an endpoint itself uses.
///
/// Direct-address hints describe where a *peer* is, not what the endpoint is, so two hosts whose
/// services agree share an endpoint whatever their hints.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Services {
    relays: Vec<String>,
    resolver: Option<String>,
    dns_origin: Option<String>,
}

impl Services {
    fn of(network: &NetworkConfig) -> Self {
        let text =
            |hint: &Nullable<NetworkHint>| hint.as_ref().map(|hint| hint.as_str().to_owned());
        let mut relays: Vec<String> = network
            .relay_urls
            .iter()
            .map(|hint| hint.as_str().to_owned())
            .collect();
        relays.sort();
        relays.dedup();
        Self {
            relays,
            resolver: text(&network.pkarr_resolver_url),
            dns_origin: text(&network.dns_origin),
        }
    }

    /// True when both select a relay in common.
    fn share_a_relay(&self, other: &Self) -> bool {
        self.relays.iter().any(|relay| other.relays.contains(relay))
    }
}

/// This device's dialling endpoints, one per distinct set of services its hosts select.
pub struct EndpointPool {
    transport: TransportIdentityKeyPair,
    bind: Option<SocketAddr>,
    open: Mutex<Vec<(Services, Endpoint)>>,
}

impl std::fmt::Debug for EndpointPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EndpointPool")
            .field("endpoint_id", self.transport.public())
            .field("bind", &self.bind)
            .finish_non_exhaustive()
    }
}

impl EndpointPool {
    /// A pool dialling as `transport`, this device's paired endpoint identity.
    #[must_use]
    pub fn new(transport: TransportIdentityKeyPair) -> Self {
        Self {
            transport,
            bind: None,
            open: Mutex::new(Vec::new()),
        }
    }

    /// The same pool, with every endpoint bound to `address`. A test binds to the loopback
    /// interface, so nothing it dials leaves the machine.
    #[must_use]
    pub const fn bound_to(mut self, address: SocketAddr) -> Self {
        self.bind = Some(address);
        self
    }

    /// The endpoint for `network`'s services, bound now if none is open.
    ///
    /// Binding one closes any open endpoint whose services differ but share a relay.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::Configuration`] for a configuration that cannot be used, and
    /// [`LinkError::Lost`] when the endpoint cannot be bound.
    pub async fn endpoint(&self, network: &NetworkConfig) -> Result<Endpoint, LinkError> {
        let services = Services::of(network);
        let mut open = self.open.lock().await;
        if let Some((_, endpoint)) = open.iter().find(|(held, _)| *held == services) {
            return Ok(endpoint.clone());
        }
        let mut kept = Vec::with_capacity(open.len());
        for (held, endpoint) in open.drain(..) {
            if held.share_a_relay(&services) {
                endpoint.close().await;
            } else {
                kept.push((held, endpoint));
            }
        }
        *open = kept;
        let endpoint =
            kr_transport::endpoint::bind_dialer(&self.config(network)?, &self.transport).await?;
        open.push((services, endpoint.clone()));
        Ok(endpoint)
    }

    /// How many endpoints are open, for the pool's own tests.
    pub async fn open_endpoints(&self) -> usize {
        self.open.lock().await.len()
    }

    /// Closes every endpoint.
    pub async fn close(&self) {
        for (_, endpoint) in self.open.lock().await.drain(..) {
            endpoint.close().await;
        }
    }

    /// The endpoint configuration a host's network configuration becomes for this device.
    ///
    /// An endpoint that only dials has no record of its own to publish, so a host's publisher is
    /// dropped: the device contacts the services it needs to reach the host and no others.
    fn config(&self, network: &NetworkConfig) -> Result<EndpointConfig, LinkError> {
        let mut config = EndpointConfig::from_network_config(network)?;
        config.discovery.pkarr_publisher_url = None;
        config.bind_addr = self.bind;
        Ok(config)
    }
}

/// The product's link: the pool's endpoints, `connect_unpaired`, and the authorised handshake.
#[derive(Debug)]
pub struct IrohLink {
    pool: Arc<EndpointPool>,
}

impl IrohLink {
    /// A link over `pool`.
    #[must_use]
    pub const fn new(pool: Arc<EndpointPool>) -> Self {
        Self { pool }
    }

    /// The pool this link dials through.
    #[must_use]
    pub fn pool(&self) -> &Arc<EndpointPool> {
        &self.pool
    }
}

impl HostLink for IrohLink {
    fn dial<'a>(
        &'a self,
        network: &'a NetworkConfig,
        endpoint: &'a EndpointKey,
    ) -> BoxFuture<'a, Result<Connection, LinkError>> {
        Box::pin(async move {
            let address = EndpointConfig::from_network_config(network)?.peer_addr(endpoint)?;
            let local = self.pool.endpoint(network).await?;
            local
                .connect(address, ALPN)
                .await
                .map_err(|error| LinkError::Lost(error.to_string()))
        })
    }

    fn open_unpaired<'a>(
        &'a self,
        connection: &'a Connection,
        identity: &'a LocalIdentity,
    ) -> BoxFuture<'a, Result<Box<dyn Preauth>, LinkError>> {
        Box::pin(async move {
            let surface = kr_transport::handshake::connect_unpaired(connection, identity).await?;
            Ok(Box::new(Unpaired(surface)) as Box<dyn Preauth>)
        })
    }

    fn connect_paired<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
    ) -> BoxFuture<'a, Result<Session, LinkError>> {
        Box::pin(async move {
            let address = EndpointConfig::from_network_config(&host.network_config)?
                .peer_addr(&host.host_endpoint_id)?;
            let local = self.pool.endpoint(&host.network_config).await?;
            let transport = NetworkTransport::connect(
                &local,
                address,
                identity,
                &host.peer(),
                SendLimits::default(),
            )
            .await
            .map_err(|error| match error {
                crate::ClientError::Transport(error) => LinkError::from(error),
                other => LinkError::Lost(other.to_string()),
            })?;
            Session::start(Arc::new(transport)).map_err(|error| LinkError::Lost(error.to_string()))
        })
    }
}

/// The pre-authorisation surface over an unpaired iroh connection.
struct Unpaired(CandidateConnection);

impl Preauth for Unpaired {
    fn selection(&self) -> &HostSelection {
        &self.0.selection
    }

    fn finish<'a>(
        &'a mut self,
        request: &'a PairFinishRequest,
    ) -> BoxFuture<'a, Result<PairFinishResult, LinkError>> {
        Box::pin(async move { Ok(self.0.call(Method::PairFinish, request).await?) })
    }

    fn redeem<'a>(
        &'a mut self,
        params: &'a PairRedeemParams,
    ) -> BoxFuture<'a, Result<PairRedeemResult, LinkError>> {
        Box::pin(async move { Ok(self.0.call(Method::PairRedeem, params).await?) })
    }

    fn status<'a>(
        &'a mut self,
        params: &'a PairStatusParams,
    ) -> BoxFuture<'a, Result<PairStatusResult, LinkError>> {
        Box::pin(async move { Ok(self.0.call(Method::PairStatus, params).await?) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(relays: &[&str], resolver: Option<&str>, hints: &[&str]) -> NetworkConfig {
        let hint = |text: &str| NetworkHint::new(text).expect("a hint");
        NetworkConfig {
            relay_urls: relays.iter().map(|relay| hint(relay)).collect(),
            pkarr_publisher_url: Nullable::null(),
            pkarr_resolver_url: resolver
                .map_or_else(Nullable::null, |url| Nullable::some(hint(url))),
            dns_origin: Nullable::null(),
            direct_addresses: hints.iter().map(|address| hint(address)).collect(),
        }
    }

    /// Two hosts whose services agree share one endpoint whatever their address hints; two whose
    /// services differ get one each; and two that differ but share a relay are never open at once.
    #[tokio::test]
    async fn one_endpoint_per_set_of_services_and_none_sharing_a_relay() {
        let pool = EndpointPool::new(TransportIdentityKeyPair::generate().expect("a key"))
            .bound_to("127.0.0.1:0".parse().expect("loopback"));
        let first = network(&[], Some("http://127.0.0.1:9/pkarr"), &["127.0.0.1:4001"]);
        let same_services = network(&[], Some("http://127.0.0.1:9/pkarr"), &["127.0.0.1:4002"]);
        let other_resolver = network(&[], Some("http://127.0.0.1:10/pkarr"), &[]);
        let a = pool.endpoint(&first).await.expect("an endpoint");
        let b = pool.endpoint(&same_services).await.expect("an endpoint");
        assert_eq!(a.bound_sockets(), b.bound_sockets(), "one endpoint");
        pool.endpoint(&other_resolver).await.expect("an endpoint");
        assert_eq!(pool.open_endpoints().await, 2);

        let relayed = network(&["https://relay.example.test"], None, &[]);
        let relayed_elsewhere = network(
            &["https://relay.example.test"],
            Some("http://127.0.0.1:11/pkarr"),
            &[],
        );
        pool.endpoint(&relayed).await.expect("an endpoint");
        assert_eq!(pool.open_endpoints().await, 3);
        pool.endpoint(&relayed_elsewhere)
            .await
            .expect("an endpoint");
        assert_eq!(
            pool.open_endpoints().await,
            3,
            "the endpoint sharing the relay was closed first"
        );
        pool.close().await;
    }
}
