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
//! the other, and whatever used it connects again later. An endpoint being closed still holds its
//! relay until its connections have drained, so the pool records it until its close has finished,
//! and binds nothing on that relay before then.
//!
//! Whatever must not be cut off holds its endpoint ([`EndpointPool::hold`]): a pairing attempt for
//! as long as it runs, and an owner's review of a confirmation while it runs. A held endpoint is
//! closed for no other configuration: a request that would close it is refused until the last hold
//! ends, so a device watching the hosts it owns waits for them rather than cutting the attempt off.
//!
//! A visit is a look at a host that is not the one in use, made in the background: the inbox reads
//! the hosts a device is paired with, and the owner's watcher asks the hosts it owns what they want
//! confirmed. The host in use is the one the person is working with, and a visit never cuts it off:
//! a visit to a host whose services differ from the host in use's and share a relay with them is
//! refused ([`EndpointPool::visit_endpoint`]) as a connection lost, for as long as the other host
//! is the one in use.
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
use kr_protocol::pairing::{NetworkConfig, PairFinishRequest};
use kr_protocol::preauth::{
    PairFinishResult, PairRedeemParams, PairRedeemResult, PairStatusParams, PairStatusResult,
};
use kr_protocol::scalars::EndpointKey;
use kr_transport::config::EndpointConfig;
use kr_transport::handshake::{CandidateConnection, LocalIdentity};
use kr_transport::scheduler::SendLimits;
use tokio::sync::{Mutex, watch};

use super::BoxFuture;
use super::paired::PairedHost;
use crate::services::PairingAdmissions;
use crate::session::Session;
use crate::shown::{Said, Shown};
use crate::transport::{ControlTransport, NetworkTransport};

/// Why a call to a host did not answer.
///
/// What it says is the host's own refusal, through [`Shown::protocol`], or which of the other two
/// it was. The text those two carry is not said: this library puts only what a reducer decided
/// there, and anything else that builds one can put any text there.
#[derive(Clone, PartialEq, Eq)]
pub enum LinkError {
    /// The host answered with a refusal of its own.
    Refused(ProtocolError),
    /// The host could not be reached, or the connection to it ended.
    Lost(String),
    /// The network configuration a host gave could not be used.
    Configuration(String),
}

impl LinkError {
    /// The host could not be reached, for the reason `reason` says.
    pub(crate) fn lost(reason: Shown) -> Self {
        Self::Lost(reason.into_string())
    }
}

impl Said for LinkError {
    fn said(&self) -> Shown {
        match self {
            Self::Refused(error) => crate::shown!(
                "the host refused: {}: {}",
                error.code,
                Shown::protocol(error)
            ),
            Self::Lost(_) => Shown::said("the host could not be reached"),
            Self::Configuration(_) => {
                Shown::said("the host's network configuration cannot be used")
            }
        }
    }
}

crate::display_as_said!(LinkError);
crate::debug_as_display!(LinkError);

impl std::error::Error for LinkError {}

impl From<kr_transport::TransportError> for LinkError {
    /// Says what a transport failure is for the pairing flows.
    ///
    /// Only an error the host sent is a refusal, whatever its code. The transport keeps it apart
    /// from what it concluded itself, such as a response stream that ended without an answer or an
    /// answer to another request; those say nothing about what the host decided, and treating one
    /// as a refusal would end an attempt the host may have accepted, so they are a connection lost.
    fn from(error: kr_transport::TransportError) -> Self {
        match error {
            kr_transport::TransportError::Refused(refusal) => Self::Refused(refusal),
            kr_transport::TransportError::Configuration { .. } => {
                Self::Configuration(Shown::transport(&error).into_string())
            }
            other => Self::lost(Shown::transport(&other)),
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

/// The network configuration of the host in use, when there is one, as it stands when it is asked.
pub type HostInUse<'a> = dyn Fn() -> Option<NetworkConfig> + Send + Sync + 'a;

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

    /// Connects to a paired host as the device it became, and returns the connection's control
    /// transport, with no session started on it.
    ///
    /// A caller that speaks the protocol through [`Session`] takes [`Self::connect_paired`]; one
    /// that needs the frames themselves, as a terminal view does, takes the transport and owns
    /// what it reads.
    fn connect_paired_transport<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
    ) -> BoxFuture<'a, Result<Arc<dyn ControlTransport>, LinkError>>;

    /// Connects to a paired host as a visit: as [`Self::connect_paired_transport`], except that it
    /// never closes the endpoint the host in use is reached through. `in_use` says which host is in
    /// use at the moment it is asked, which is when the endpoint is chosen and not before: the
    /// person can choose another host while a visit waits.
    ///
    /// A visit whose host cannot be reached without closing that endpoint fails as a connection
    /// lost, and nothing the host in use has is touched.
    fn visit_paired_transport<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
        in_use: &'a HostInUse<'a>,
    ) -> BoxFuture<'a, Result<Arc<dyn ControlTransport>, LinkError>>;

    /// Connects to a paired host as a visit, and starts a session on the connection.
    fn visit_paired<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
        in_use: &'a HostInUse<'a>,
    ) -> BoxFuture<'a, Result<Session, LinkError>> {
        Box::pin(async move {
            let transport = self.visit_paired_transport(host, identity, in_use).await?;
            Session::start(transport).map_err(|error| LinkError::lost(error.said()))
        })
    }

    /// Connects to a paired host as the device it became, and starts a session on the
    /// connection.
    fn connect_paired<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
    ) -> BoxFuture<'a, Result<Session, LinkError>> {
        Box::pin(async move {
            let transport = self.connect_paired_transport(host, identity).await?;
            Session::start(transport).map_err(|error| LinkError::lost(error.said()))
        })
    }

    /// Holds the endpoint for `network`, so nothing this device does for another host closes it,
    /// until the hold is dropped.
    fn hold<'a>(
        &'a self,
        network: &'a NetworkConfig,
    ) -> BoxFuture<'a, Result<EndpointHold, LinkError>>;

    /// Whether a dial to `endpoint` that failed was held back by the managed service having no free
    /// capacity to admit this device through the relay the dial addresses.
    ///
    /// A device that holds no lease with the host asks the managed service for an admission as it
    /// dials, and a service that has none to give is a reason a person acts on differently from a
    /// host that is not there. It is asked after a dial has ended, and a link that asks no service
    /// answers no.
    fn relay_capacity_refused(&self, _network: &NetworkConfig, _endpoint: &EndpointKey) -> bool {
        false
    }
}

/// The live peer of a connection, as kr-pairing checks it.
///
/// It is read from the connection iroh authenticated, never from what an invitation or a bundle
/// said. A connection this device dialled completed its handshake before the dial returned, and
/// its endpoint keeps no TLS tickets, so nothing on it ever travelled as early data.
#[derive(Clone, Copy, PartialEq, Eq)]
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
#[derive(Clone, PartialEq, Eq)]
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

/// A hold on the endpoint of one set of services. While any hold on it lives, the pool closes that
/// endpoint for no other configuration; dropping the last one lets it be closed again.
#[derive(Debug)]
pub struct EndpointHold {
    _holds: Arc<()>,
}

/// This device's dialling endpoints, one per distinct set of services its hosts select.
pub struct EndpointPool {
    transport: TransportIdentityKeyPair,
    bind: Option<SocketAddr>,
    /// Extra trust anchors for a relay's HTTPS certificate, as DER certificates, beside the ones
    /// the platform trusts.
    relay_roots: Vec<Vec<u8>>,
    /// Whether every endpoint reaches hosts through relays only.
    relay_only: bool,
    endpoints: Mutex<Endpoints>,
    /// How many endpoints the pool has begun to bind, which its tests read without the lock.
    #[cfg(test)]
    binds: std::sync::atomic::AtomicUsize,
}

/// The pool's record: the endpoints open, and the ones still closing.
///
/// Every change to it is made before anything waits, so a caller that stops waiting leaves it
/// whole. A closing endpoint is closed by a task of its own, which finishes whether or not anyone
/// waits for it, and it stays recorded until that task says it has.
#[derive(Default)]
struct Endpoints {
    open: Vec<Open>,
    closing: Vec<(Services, watch::Receiver<bool>)>,
    /// Holds every close the pool starts until a test opens it, so a test decides when a close
    /// finishes rather than guessing how long one takes.
    #[cfg(test)]
    close_gate: Option<watch::Receiver<bool>>,
}

/// One open endpoint, the services it was bound for, and the holds on it.
struct Open {
    services: Services,
    endpoint: Endpoint,
    /// One more reference than there are holds.
    holds: Arc<()>,
}

impl Open {
    fn held(&self) -> bool {
        Arc::strong_count(&self.holds) > 1
    }
}

impl Endpoints {
    /// Moves every open endpoint `selected` picks to the closing record, and starts its close.
    fn start_closing(&mut self, selected: impl Fn(&Services) -> bool) {
        let (closing, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.open)
            .into_iter()
            .partition(|open| selected(&open.services));
        self.open = kept;
        for Open {
            services: held,
            endpoint,
            ..
        } in closing
        {
            let (closed, watching) = watch::channel(false);
            #[cfg(test)]
            let gate = self.close_gate.clone();
            tokio::spawn(async move {
                #[cfg(test)]
                if let Some(mut gate) = gate {
                    let _ = gate.wait_for(|open| *open).await;
                }
                endpoint.close().await;
                let _ = closed.send(true);
            });
            self.closing.push((held, watching));
        }
    }

    /// Waits until every closing endpoint `selected` picks has finished closing, and forgets the
    /// closes that have.
    async fn closed(&mut self, selected: impl Fn(&Services) -> bool) {
        let waits: Vec<_> = self
            .closing
            .iter()
            .filter(|(held, _)| selected(held))
            .map(|(_, watching)| watching.clone())
            .collect();
        for mut watching in waits {
            // A close task that ended without saying so has ended all the same.
            let _ = watching.wait_for(|closed| *closed).await;
        }
        self.closing
            .retain(|(_, watching)| !*watching.borrow() && watching.has_changed().is_ok());
    }
}

impl std::fmt::Debug for EndpointPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EndpointPool")
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
            relay_roots: Vec::new(),
            relay_only: false,
            endpoints: Mutex::new(Endpoints::default()),
            #[cfg(test)]
            binds: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// The same pool, with every endpoint bound to `address`. A test binds to the loopback
    /// interface, so nothing it dials leaves the machine.
    #[must_use]
    pub const fn bound_to(mut self, address: SocketAddr) -> Self {
        self.bind = Some(address);
        self
    }

    /// The same pool, with every endpoint reaching hosts through relays only and never on a direct
    /// path, as a device on a network that blocks them does. It is the setting a host's own
    /// configuration calls `network.relay_only`.
    #[must_use]
    pub const fn through_relays_only(mut self) -> Self {
        self.relay_only = true;
        self
    }

    /// The same pool, trusting `roots` as well as the platform's anchors for a relay's certificate:
    /// a relay run under a private authority is reached with that authority pinned, which adds
    /// trust and never replaces it. A test pins the certificate its own relay generated.
    #[must_use]
    pub fn trusting_relays(mut self, roots: Vec<Vec<u8>>) -> Self {
        self.relay_roots = roots;
        self
    }

    /// The endpoint for `network`'s services, bound now if none is open.
    ///
    /// Binding one first closes any open endpoint whose services differ but share a relay, and
    /// waits for every endpoint on those relays to finish closing, however it came to be closing.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::Configuration`] for a configuration that cannot be used, and
    /// [`LinkError::Lost`] when the endpoint cannot be bound, or when binding it would close an
    /// endpoint someone holds.
    pub async fn endpoint(&self, network: &NetworkConfig) -> Result<Endpoint, LinkError> {
        let config = self.config(network)?;
        let mut endpoints = self.endpoints.lock().await;
        let open = self.open_for(&mut endpoints, config).await?;
        Ok(open.endpoint.clone())
    }

    /// The endpoint for `network`'s services for a visit, bound now if none is open, as
    /// [`Self::endpoint`] gives it, except that it is refused when `network`'s services are not
    /// the host in use's and share a relay with them. Binding it would close the endpoint the host
    /// in use is reached through, or take the relay from it when it is not open at this moment, and
    /// a visit is not worth that.
    ///
    /// `in_use` is asked once the pool is this request's to change, and nothing waits between the
    /// answer and the close it decides: a host chosen while the visit waited for the pool is the
    /// host in use here.
    ///
    /// # Errors
    ///
    /// As [`Self::endpoint`], and [`LinkError::Lost`] when the visit would cut off the host in use.
    pub async fn visit_endpoint(
        &self,
        network: &NetworkConfig,
        in_use: &HostInUse<'_>,
    ) -> Result<Endpoint, LinkError> {
        let config = self.config(network)?;
        let mut endpoints = self.endpoints.lock().await;
        // A host in use whose configuration cannot be used has no endpoint to cut off.
        if let Some(using) = in_use().and_then(|using| self.config(&using).ok()) {
            let (using, services) = (Services::of(&using), Services::of(&config));
            if services != using && services.share_a_relay(&using) {
                return Err(LinkError::lost(Shown::said(
                    "the relay this host is reached through is in use for the host this device is using",
                )));
            }
        }
        let open = self.open_for(&mut endpoints, config).await?;
        Ok(open.endpoint.clone())
    }

    /// Holds the endpoint for `network`'s services, bound now if none is open, until the returned
    /// hold is dropped.
    ///
    /// # Errors
    ///
    /// As [`Self::endpoint`].
    pub async fn hold(&self, network: &NetworkConfig) -> Result<EndpointHold, LinkError> {
        let config = self.config(network)?;
        let mut endpoints = self.endpoints.lock().await;
        let open = self.open_for(&mut endpoints, config).await?;
        Ok(EndpointHold {
            _holds: Arc::clone(&open.holds),
        })
    }

    /// The open endpoint for `config`'s services, bound now if there is none.
    async fn open_for<'a>(
        &self,
        endpoints: &'a mut Endpoints,
        config: EndpointConfig,
    ) -> Result<&'a Open, LinkError> {
        let services = Services::of(&config);
        if let Some(index) = endpoints
            .open
            .iter()
            .position(|open| open.services == services)
        {
            return Ok(&endpoints.open[index]);
        }
        if endpoints
            .open
            .iter()
            .any(|open| open.held() && open.services.share_a_relay(&services))
        {
            return Err(LinkError::lost(Shown::said(
                "the relay this host is reached through is in use for another host",
            )));
        }
        endpoints.start_closing(|held| held.share_a_relay(&services));
        endpoints.closed(|held| held.share_a_relay(&services)).await;
        #[cfg(test)]
        self.binds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let endpoint = kr_transport::endpoint::bind_dialer(&config, &self.transport).await?;
        endpoints.open.push(Open {
            services,
            endpoint,
            holds: Arc::new(()),
        });
        let Some(open) = endpoints.open.last() else {
            unreachable!("an endpoint was just bound");
        };
        Ok(open)
    }

    /// How many endpoints are open.
    pub async fn open_endpoints(&self) -> usize {
        self.endpoints.lock().await.open.len()
    }

    /// True when the pool holds an endpoint for `network`'s services.
    pub async fn holds(&self, network: &NetworkConfig) -> bool {
        let Ok(config) = self.config(network) else {
            return false;
        };
        let services = Services::of(&config);
        self.endpoints
            .lock()
            .await
            .open
            .iter()
            .any(|open| open.services == services)
    }

    /// Closes every endpoint, and waits until each has finished closing.
    pub async fn close(&self) {
        let mut endpoints = self.endpoints.lock().await;
        endpoints.start_closing(|_| true);
        endpoints.closed(|_| true).await;
    }

    /// The endpoint configuration a host's network configuration becomes for this device.
    ///
    /// An endpoint that only dials has no record of its own to publish, so a host's publisher is
    /// dropped: the device contacts the services it needs to reach the host and no others.
    fn config(&self, network: &NetworkConfig) -> Result<EndpointConfig, LinkError> {
        let mut config = EndpointConfig::from_network_config(network)?;
        config.discovery.pkarr_publisher_url = None;
        config.bind_addr = self.bind;
        config.relay_ca_roots.clone_from(&self.relay_roots);
        config.relay_only = self.relay_only;
        Ok(config)
    }
}

/// The product's link: the pool's endpoints, `connect_unpaired`, and the authorised handshake.
#[derive(Debug)]
pub struct IrohLink {
    pool: Arc<EndpointPool>,
    admissions: Option<Arc<PairingAdmissions>>,
}

impl IrohLink {
    /// A link over `pool`.
    #[must_use]
    pub const fn new(pool: Arc<EndpointPool>) -> Self {
        Self {
            pool,
            admissions: None,
        }
    }

    /// The same link, asking the managed service for an admission to reach a host through a relay
    /// of its own before the device has paired with it.
    #[must_use]
    pub fn admitted_by(mut self, admissions: Arc<PairingAdmissions>) -> Self {
        self.admissions = Some(admissions);
        self
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
            if let Some(admissions) = &self.admissions {
                // The request goes as the dial starts, and the dial does not wait for it past a
                // short bound: the relay drops what an unadmitted pair sends until the admission
                // lands, and the transport sends again.
                admissions
                    .before_dial(
                        network,
                        endpoint,
                        EndpointKey::from_bytes(*local.id().as_bytes()),
                    )
                    .await;
            }
            let connection = local.connect(address, ALPN).await.map_err(|_| {
                LinkError::lost(Shown::said("the connection could not be established"))
            })?;
            if let Some(admissions) = &self.admissions {
                admissions.dial_succeeded(network, endpoint);
            }
            Ok(connection)
        })
    }

    fn relay_capacity_refused(&self, network: &NetworkConfig, endpoint: &EndpointKey) -> bool {
        self.admissions
            .as_ref()
            .is_some_and(|admissions| admissions.capacity_refused(network, endpoint))
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

    fn connect_paired_transport<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
    ) -> BoxFuture<'a, Result<Arc<dyn ControlTransport>, LinkError>> {
        Box::pin(connect_paired_over(
            host,
            identity,
            self.pool.endpoint(&host.network_config),
        ))
    }

    fn visit_paired_transport<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
        in_use: &'a HostInUse<'a>,
    ) -> BoxFuture<'a, Result<Arc<dyn ControlTransport>, LinkError>> {
        Box::pin(connect_paired_over(
            host,
            identity,
            self.pool.visit_endpoint(&host.network_config, in_use),
        ))
    }

    fn hold<'a>(
        &'a self,
        network: &'a NetworkConfig,
    ) -> BoxFuture<'a, Result<EndpointHold, LinkError>> {
        Box::pin(self.pool.hold(network))
    }
}

/// Connects to `host` as the device it became, over the endpoint `endpoint` gives.
async fn connect_paired_over(
    host: &PairedHost,
    identity: &LocalIdentity,
    endpoint: impl std::future::Future<Output = Result<Endpoint, LinkError>>,
) -> Result<Arc<dyn ControlTransport>, LinkError> {
    let address = EndpointConfig::from_network_config(&host.network_config)?
        .peer_addr(&host.host_endpoint_id)?;
    let local = endpoint.await?;
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
        other => LinkError::lost(other.said()),
    })?;
    Ok(Arc::new(transport) as Arc<dyn ControlTransport>)
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

    /// Polls `future` once and drops it, as a caller that stops waiting at its first wait does.
    /// Returns true when it had finished by then.
    async fn stop_at_first_wait(future: impl std::future::Future) -> bool {
        let mut future = std::pin::pin!(future);
        std::future::poll_fn(|context| {
            std::task::Poll::Ready(future.as_mut().poll(context).is_ready())
        })
        .await
    }

    /// Holds every close `pool` starts until the returned gate is opened.
    async fn hold_closes(pool: &EndpointPool) -> watch::Sender<bool> {
        let (gate, held) = watch::channel(false);
        pool.endpoints.lock().await.close_gate = Some(held);
        gate
    }

    fn binds(pool: &EndpointPool) -> usize {
        pool.binds.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Polls `future` once, which runs it as far as its first wait, and says whether it had
    /// finished by then. The future is kept, so the caller can go on with it.
    async fn finished_when_first_polled<F: std::future::Future>(
        mut future: std::pin::Pin<&mut F>,
    ) -> bool {
        std::future::poll_fn(|context| {
            std::task::Poll::Ready(future.as_mut().poll(context).is_ready())
        })
        .await
    }

    /// A caller that stops waiting while an endpoint on a shared relay is being closed leaves the
    /// pool whole: every endpoint that did not share the relay is still recorded, and a connection
    /// live on one of them stays up. The close it started stays recorded too, so a request made at
    /// once afterwards for another configuration on that relay binds nothing until the old
    /// endpoint has finished closing.
    #[tokio::test]
    async fn stopping_part_way_loses_no_endpoint_and_binds_nothing_on_a_relay_still_held() {
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
        let gate = hold_closes(&pool).await;
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
        let again = network(
            &["https://relay.example.test"],
            Some("http://127.0.0.1:14/pkarr"),
            &[],
        );
        let kept = pool.endpoint(&unrelated).await.expect("an endpoint");
        let closing = pool.endpoint(&relayed).await.expect("an endpoint");
        assert_eq!(binds(&pool), 2);

        assert!(
            !stop_at_first_wait(pool.endpoint(&replacing)).await,
            "the replacement waits for the endpoint on the shared relay to close"
        );
        // The request runs as far as its first wait, and a pool that did not wait for the close
        // would have counted its bind by then.
        let mut asking = std::pin::pin!(pool.endpoint(&again));
        assert!(!finished_when_first_polled(asking.as_mut()).await);
        assert!(
            pool.endpoints.try_lock().is_err(),
            "the request is in the pool, waiting for the close"
        );
        assert_eq!(
            binds(&pool),
            2,
            "nothing is bound on the relay while the endpoint on it is closing"
        );
        assert!(!closing.is_closed());

        gate.send_replace(true);
        asking.await.expect("an endpoint");
        assert!(
            closing.is_closed(),
            "the endpoint on the relay finished closing before another was bound on it"
        );
        assert_eq!(binds(&pool), 3, "and then exactly one was bound");
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
        assert!(!pool.holds(&replacing).await);
        assert!(pool.holds(&again).await);
        pool.close().await;
        peer.close().await;
    }

    /// A close of the whole pool that its caller stops waiting for still keeps relays apart: an
    /// endpoint asked for at once afterwards on a relay the pool held is bound only once the old
    /// endpoint has finished closing.
    #[tokio::test]
    async fn a_pool_close_stopped_part_way_binds_nothing_on_a_relay_still_held() {
        let pool = Arc::new(
            EndpointPool::new(TransportIdentityKeyPair::generate().expect("a key"))
                .bound_to("127.0.0.1:0".parse().expect("loopback")),
        );
        let gate = hold_closes(&pool).await;
        let relayed = network(&["https://relay.example.test"], None, &[]);
        let again = network(
            &["https://relay.example.test"],
            Some("http://127.0.0.1:15/pkarr"),
            &[],
        );
        let first = pool.endpoint(&relayed).await.expect("an endpoint");
        assert!(!stop_at_first_wait(pool.close()).await);
        let mut asking = std::pin::pin!(pool.endpoint(&again));
        assert!(!finished_when_first_polled(asking.as_mut()).await);
        assert!(
            pool.endpoints.try_lock().is_err(),
            "the request is in the pool, waiting for the close"
        );
        assert_eq!(
            binds(&pool),
            1,
            "nothing is bound while the old endpoint is closing"
        );
        assert!(!first.is_closed());

        gate.send_replace(true);
        asking.await.expect("an endpoint");
        assert!(
            first.is_closed(),
            "the relay is used again only once the old endpoint has finished closing"
        );
        assert_eq!(binds(&pool), 2);
        pool.close().await;
    }

    /// KR-REQ-10.27: an endpoint held for an attempt or a review is closed for no other
    /// configuration. While it is held, a request for another configuration on its relay is
    /// refused, for an endpoint and for a hold alike, and binds nothing; the held configuration
    /// itself, and one on no shared relay, are served at once. Once the last hold ends, the same
    /// request closes the endpoint and binds, as it does for an endpoint nobody holds.
    #[tokio::test]
    async fn a_held_endpoint_is_closed_for_no_other_configuration_on_its_relay() {
        let pool = EndpointPool::new(TransportIdentityKeyPair::generate().expect("a key"))
            .bound_to("127.0.0.1:0".parse().expect("loopback"));
        let held_config = network(
            &["https://relay.example.test"],
            Some("http://127.0.0.1:16/pkarr"),
            &[],
        );
        let other = network(
            &["https://relay.example.test"],
            Some("http://127.0.0.1:17/pkarr"),
            &[],
        );
        let elsewhere = network(&[], Some("http://127.0.0.1:18/pkarr"), &[]);

        let first = pool.hold(&held_config).await.expect("held");
        let second = pool.hold(&held_config).await.expect("held twice");
        let held = pool
            .endpoint(&held_config)
            .await
            .expect("the held one itself");
        assert!(matches!(
            pool.endpoint(&other).await,
            Err(LinkError::Lost(_))
        ));
        assert!(matches!(pool.hold(&other).await, Err(LinkError::Lost(_))));
        assert!(!held.is_closed(), "the held endpoint stays open");
        pool.endpoint(&elsewhere).await.expect("no shared relay");
        assert_eq!(binds(&pool), 2, "nothing was bound on the held relay");

        drop(first);
        assert!(
            matches!(pool.endpoint(&other).await, Err(LinkError::Lost(_))),
            "one hold still lives"
        );
        drop(second);
        pool.endpoint(&other)
            .await
            .expect("served once no hold lives");
        assert!(
            held.is_closed(),
            "and the endpoint it held was closed first"
        );
        assert!(pool.holds(&other).await);
        assert_eq!(binds(&pool), 3);
        pool.close().await;
    }

    /// The host in use, as a visit is told of it: this configuration.
    fn using(config: &NetworkConfig) -> impl Fn() -> Option<NetworkConfig> + Send + Sync {
        let config = config.clone();
        move || Some(config.clone())
    }

    /// No host in use.
    fn nobody() -> Option<NetworkConfig> {
        None
    }

    /// A visit never closes the endpoint the host in use is reached through, nor takes its relay
    /// while that endpoint is not open: the host in use's services are served as ever, a visit on
    /// its own services shares its endpoint, and a visit that shares no relay with it is bound.
    /// Without a host in use there is nothing to protect.
    #[tokio::test]
    async fn a_visit_never_cuts_off_the_host_in_use_on_a_shared_relay() {
        let pool = EndpointPool::new(TransportIdentityKeyPair::generate().expect("a key"))
            .bound_to("127.0.0.1:0".parse().expect("loopback"));
        let in_use = network(
            &["https://relay.example.test"],
            Some("http://127.0.0.1:19/pkarr"),
            &[],
        );
        let beside = network(
            &["https://relay.example.test"],
            Some("http://127.0.0.1:20/pkarr"),
            &[],
        );
        let same_services = network(
            &["https://relay.example.test"],
            Some("http://127.0.0.1:19/pkarr"),
            &["127.0.0.1:4003"],
        );
        let elsewhere = network(&[], Some("http://127.0.0.1:21/pkarr"), &[]);

        // The host in use is open, and not held: a visit on its relay is refused all the same.
        let using_it = pool.endpoint(&in_use).await.expect("the host in use");
        assert!(matches!(
            pool.visit_endpoint(&beside, &using(&in_use)).await,
            Err(LinkError::Lost(_))
        ));
        assert!(
            !using_it.is_closed(),
            "the host in use's endpoint stays open"
        );
        assert!(pool.holds(&in_use).await);
        assert_eq!(binds(&pool), 1, "nothing was bound on its relay");

        // A visit on the host in use's own services is served by its endpoint; one on no shared
        // relay is bound beside it.
        let same = pool
            .visit_endpoint(&same_services, &using(&in_use))
            .await
            .expect("the same services");
        assert_eq!(
            same.bound_sockets(),
            using_it.bound_sockets(),
            "one endpoint"
        );
        pool.visit_endpoint(&elsewhere, &using(&in_use))
            .await
            .expect("no shared relay");
        assert_eq!(binds(&pool), 2);
        assert!(!using_it.is_closed());

        // The host in use's endpoint is not open at this moment: a visit still leaves its relay to
        // it, so the host in use can open it again without finding the relay taken.
        pool.close().await;
        assert!(matches!(
            pool.visit_endpoint(&beside, &using(&in_use)).await,
            Err(LinkError::Lost(_))
        ));
        assert_eq!(binds(&pool), 2, "nothing was bound on its relay");

        // With no host in use, a visit is served like any request, and a request for the host
        // chosen afterwards closes it, as it closes any endpoint nobody holds.
        let visited = pool
            .visit_endpoint(&beside, &nobody)
            .await
            .expect("no host is in use");
        pool.endpoint(&in_use).await.expect("the host chosen later");
        assert!(visited.is_closed());
        pool.close().await;
    }

    /// The person can choose a host while a visit waits for the pool. The host in use is the one
    /// chosen when the visit's turn comes, so a visit that was asked before the choice still leaves
    /// the chosen host's relay to it.
    #[tokio::test]
    async fn a_host_chosen_while_a_visit_waits_for_the_pool_is_left_its_relay() {
        let pool = Arc::new(
            EndpointPool::new(TransportIdentityKeyPair::generate().expect("a key"))
                .bound_to("127.0.0.1:0".parse().expect("loopback")),
        );
        let chosen = network(
            &["https://relay.example.test"],
            Some("http://127.0.0.1:22/pkarr"),
            &[],
        );
        let beside = network(
            &["https://relay.example.test"],
            Some("http://127.0.0.1:23/pkarr"),
            &[],
        );
        let chosen_endpoint = pool.endpoint(&chosen).await.expect("the host chosen later");

        // Another request has the pool; the visit is asked for meanwhile.
        let turn = pool.endpoints.lock().await;
        let choice: Arc<std::sync::Mutex<Option<NetworkConfig>>> = Arc::default();
        let visit = tokio::spawn({
            let (pool, beside, choice) = (Arc::clone(&pool), beside.clone(), Arc::clone(&choice));
            async move {
                let in_use = || choice.lock().expect("the choice").clone();
                pool.visit_endpoint(&beside, &in_use).await
            }
        });
        *choice.lock().expect("the choice") = Some(chosen.clone());
        drop(turn);

        assert!(matches!(
            visit.await.expect("the visit ran"),
            Err(LinkError::Lost(_))
        ));
        assert!(!chosen_endpoint.is_closed());
        assert_eq!(binds(&pool), 1, "nothing was bound on its relay");
        pool.close().await;
    }

    /// An error the host sent is a refusal whatever its code, and what the transport concluded
    /// itself is a connection lost whatever its code: the variant says where an error came from,
    /// and the code does not.
    #[test]
    fn only_an_error_the_host_sent_is_a_refusal() {
        use kr_protocol::error::ErrorCode;
        for code in [
            ErrorCode::PairingAuthFailed,
            ErrorCode::RateLimited,
            ErrorCode::InvalidArgument,
            ErrorCode::ResourceUnavailable,
        ] {
            assert!(
                matches!(
                    LinkError::from(kr_transport::TransportError::Refused(ProtocolError::new(
                        code, "sent"
                    ))),
                    LinkError::Refused(_)
                ),
                "{code:?}"
            );
            assert!(
                matches!(
                    LinkError::from(kr_transport::TransportError::handshake(code, "concluded")),
                    LinkError::Lost(_)
                ),
                "{code:?}"
            );
        }
    }

    /// A link failure says the host's own refusal through its door, and otherwise only which kind
    /// of failure it was: the text a lost connection or a configuration carries is not said.
    #[test]
    fn a_link_failure_says_the_hosts_refusal_and_otherwise_only_its_kind() {
        use kr_protocol::error::ErrorCode;

        use crate::shown::marker::{MARKER, assert_unmarked, failure_renderings};

        for error in [
            LinkError::Lost(MARKER.to_owned()),
            LinkError::Configuration(MARKER.to_owned()),
        ] {
            assert_unmarked("a link failure", &failure_renderings(error));
        }
        assert_eq!(
            LinkError::lost(Shown::said("no connection")).to_string(),
            "the host could not be reached"
        );
        let refused = LinkError::Refused(crate::error::refusal(
            ErrorCode::PairingExpired,
            Shown::said("the invitation expired"),
        ));
        assert_eq!(
            format!("{refused:?}"),
            "LinkError(\"the host refused: PAIRING_EXPIRED: the invitation expired\")"
        );
    }
}
