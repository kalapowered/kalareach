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
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::hello::{ALPN, HostSelection};
use kr_protocol::method::Method;
use kr_protocol::pairing::{NetworkConfig, PairFinishRequest};
use kr_protocol::preauth::{
    PairFinishResult, PairRedeemParams, PairRedeemResult, PairStatusParams, PairStatusResult,
};
use kr_protocol::scalars::EndpointKey;
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
    /// Says what a transport failure is for the pairing flows.
    ///
    /// The transport reports a host's own refusal as a handshake error, and it reports some of its
    /// own conclusions the same way: a response stream that ended without an answer, or an answer
    /// to another request. Those say nothing about what the host decided, and treating one as a
    /// refusal would end an attempt the host may have accepted. So only the codes a host refuses
    /// a pairing step with are a refusal; everything else is a connection lost.
    fn from(error: kr_transport::TransportError) -> Self {
        match error {
            kr_transport::TransportError::Handshake(refusal) if is_host_refusal(refusal.code) => {
                Self::Refused(refusal)
            }
            kr_transport::TransportError::Configuration { .. } => {
                Self::Configuration(error.to_string())
            }
            other => Self::Lost(other.to_string()),
        }
    }
}

/// True for the codes a host refuses a pairing step or an unpaired offer with.
const fn is_host_refusal(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::PairingAuthFailed
            | ErrorCode::PairingExpired
            | ErrorCode::PairingAttemptsExhausted
            | ErrorCode::PairingRejected
            | ErrorCode::PermissionDenied
            | ErrorCode::OwnerConfirmationRequired
            | ErrorCode::UnsupportedSchema
    )
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
/// services agree share an endpoint whatever their hints. The services are compared as the
/// transport parses them, so two spellings of one relay are one relay.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Services {
    relays: Vec<iroh::RelayUrl>,
    resolver: Option<url::Url>,
    dns_origin: Option<String>,
}

impl Services {
    fn of(config: &EndpointConfig) -> Self {
        let mut relays = config.relay_urls.clone();
        relays.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        relays.dedup();
        Self {
            relays,
            resolver: config.discovery.pkarr_resolver_url.clone(),
            dns_origin: config.discovery.dns_origin.clone(),
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
        let config = self.config(network)?;
        let services = Services::of(&config);
        let mut open = self.open.lock().await;
        if let Some((_, endpoint)) = open.iter().find(|(held, _)| *held == services) {
            return Ok(endpoint.clone());
        }
        // The pool's record changes before anything waits, so a caller that stops waiting leaves
        // it whole: the endpoints kept are still recorded, and the ones being closed are closed by
        // tasks of their own, which finish whether or not anyone still waits for them.
        let (closing, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut *open)
            .into_iter()
            .partition(|(held, _)| held.share_a_relay(&services));
        *open = kept;
        let closes: Vec<_> = closing
            .into_iter()
            .map(|(_, endpoint)| tokio::spawn(async move { endpoint.close().await }))
            .collect();
        for close in closes {
            let _ = close.await;
        }
        let endpoint = kr_transport::endpoint::bind_dialer(&config, &self.transport).await?;
        open.push((services, endpoint.clone()));
        Ok(endpoint)
    }

    /// How many endpoints are open.
    pub async fn open_endpoints(&self) -> usize {
        self.open.lock().await.len()
    }

    /// True when the pool holds an endpoint for `network`'s services.
    pub async fn holds(&self, network: &NetworkConfig) -> bool {
        let Ok(config) = self.config(network) else {
            return false;
        };
        let services = Services::of(&config);
        self.open
            .lock()
            .await
            .iter()
            .any(|(held, _)| *held == services)
    }

    /// Closes every endpoint.
    pub async fn close(&self) {
        let closing = std::mem::take(&mut *self.open.lock().await);
        let closes: Vec<_> = closing
            .into_iter()
            .map(|(_, endpoint)| tokio::spawn(async move { endpoint.close().await }))
            .collect();
        for close in closes {
            let _ = close.await;
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
    use kr_protocol::pairing::NetworkHint;
    use kr_protocol::scalars::Nullable;

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
    /// services differ get one each; and two that differ but share a relay are never open at once,
    /// however the relay is spelled: the endpoint on it is closed before the other is bound.
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
        let respelled = network(
            &["https://relay.example.test/"],
            Some("http://127.0.0.1:11/pkarr"),
            &[],
        );
        let on_the_relay = pool.endpoint(&relayed).await.expect("an endpoint");
        assert_eq!(pool.open_endpoints().await, 3);
        pool.endpoint(&respelled).await.expect("an endpoint");
        assert!(
            on_the_relay.is_closed(),
            "the endpoint on the same relay, spelled another way, was closed first"
        );
        assert!(!pool.holds(&relayed).await);
        assert!(pool.holds(&respelled).await);
        assert_eq!(pool.open_endpoints().await, 3);
        pool.close().await;
        assert_eq!(pool.open_endpoints().await, 0);
    }

    /// A caller that stops waiting while an endpoint on a shared relay is being closed leaves the
    /// pool whole: every endpoint that did not share the relay is still recorded, a connection
    /// live on one of them stays up, and the endpoint that did share the relay is closed all the
    /// same.
    #[tokio::test]
    async fn stopping_part_way_loses_no_endpoint_and_keeps_none_it_closed() {
        let peer_key = TransportIdentityKeyPair::generate().expect("a key");
        let mut peer_config =
            EndpointConfig::from_network_config(&network(&[], None, &[])).expect("a config");
        peer_config.bind_addr = Some("127.0.0.1:0".parse().expect("loopback"));
        let peer = kr_transport::endpoint::bind_listener(&peer_config, &peer_key)
            .await
            .expect("a peer on loopback");
        let accepting = peer.clone();
        let accepted = tokio::spawn(async move {
            let incoming = accepting.accept().await.expect("a connection arrives");
            incoming.await.expect("the connection completes")
        });
        let peer_address = peer.bound_sockets()[0].to_string();

        let pool = Arc::new(
            EndpointPool::new(TransportIdentityKeyPair::generate().expect("a key"))
                .bound_to("127.0.0.1:0".parse().expect("loopback")),
        );
        let unrelated = network(&[], None, &[peer_address.as_str()]);
        let live = IrohLink::new(Arc::clone(&pool))
            .dial(&unrelated, peer_key.public())
            .await
            .expect("a connection to the peer");
        let held = accepted.await.expect("the peer's side");
        let relayed = network(&["https://relay.example.test"], None, &[]);
        let replacing = network(
            &["https://relay.example.test"],
            Some("http://127.0.0.1:13/pkarr"),
            &[],
        );
        let kept = pool.endpoint(&unrelated).await.expect("an endpoint");
        let closing = pool.endpoint(&relayed).await.expect("an endpoint");
        // The caller stops waiting at the first point the replacement waits, which is while the
        // endpoint on the shared relay is being closed.
        let finished_at_once = {
            let mut replacement = Box::pin(pool.endpoint(&replacing));
            std::future::poll_fn(|context| {
                std::task::Poll::Ready(replacement.as_mut().poll(context).is_ready())
            })
            .await
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !closing.is_closed() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the endpoint on the shared relay is closed whether or not anyone waited");
        assert!(
            pool.holds(&unrelated).await,
            "the unrelated endpoint is still recorded"
        );
        assert!(!kept.is_closed());
        assert!(
            live.close_reason().is_none(),
            "the live connection is still up"
        );
        assert!(held.close_reason().is_none());
        assert!(!pool.holds(&relayed).await);
        assert_eq!(pool.holds(&replacing).await, finished_at_once);
        pool.close().await;
        peer.close().await;
    }

    /// A host's own refusal is a refusal; the transport's own conclusions, such as a response
    /// stream that ended without an answer, are a connection lost.
    #[test]
    fn only_a_hosts_own_refusal_is_a_refusal() {
        for code in [
            ErrorCode::PairingAuthFailed,
            ErrorCode::PairingExpired,
            ErrorCode::PairingRejected,
            ErrorCode::PermissionDenied,
        ] {
            assert!(matches!(
                LinkError::from(kr_transport::TransportError::handshake(code, "refused")),
                LinkError::Refused(_)
            ));
        }
        for (code, detail) in [
            (ErrorCode::ResourceUnavailable, "the host answered nothing"),
            (
                ErrorCode::InvalidArgument,
                "the host answered another request",
            ),
        ] {
            assert!(matches!(
                LinkError::from(kr_transport::TransportError::handshake(code, detail)),
                LinkError::Lost(_)
            ));
        }
    }
}
