//! How a device reaches a host it is pairing with, or paired with, over iroh.
//!
//! Every connection goes through [`EndpointPool`], which keeps one dialling endpoint for the whole
//! run. It is bound at the first request with this device's one transport key, an empty relay map
//! and no address lookup of its own, and a host enters it when the device first dials that host:
//! the host's address lookups are registered under the host's endpoint identity, so a lookup is
//! asked about that identity and no other, and, for a paired host, its relays go into the relay
//! map. The relays of a pairing invitation stay out of the map until the pairing completes and the
//! device dials the host as a paired host.
//!
//! One key holds one endpoint on a relay at a time: a relay keeps one active client per key and
//! parks the other. With one endpoint for every host, no request for one host refuses, closes or
//! restarts the connection of another. The pool closes its endpoint only when it is asked to
//! ([`EndpointPool::close`]) and when the run ends. A close waits until the endpoint has finished
//! closing, so that no second endpoint holds the key beside it, for a caller that awaits it to
//! its end; a caller that drops it part way leaves the endpoint closing while the next request
//! binds another. The next request after a close binds a new endpoint and introduces its host
//! again.
//!
//! A host the person forgets is taken out of the endpoint ([`HostLink::forget_host`]): its lookups
//! are no longer asked and the relays that no other host names leave the map. A connection that
//! is open stays open until whoever holds it closes it. The pool marks the forgotten pairing by the
//! identity its host gave the device, and refuses a dial under that pairing. A host's introduction
//! and its removal never overlap, because each holds the host's own lock, so no dial that began
//! before the forget puts the host back, however its caller ends. A new pairing with the same host
//! has an identity of its own and is not refused, and the host stays in the endpoint until the last
//! pairing that introduced it has been forgotten.
//!
//! [`HostLink`] is the whole of what the pairing flows ask of the network, so a test can put a
//! dialler that reaches another host, or a layer that alters an answer, in its place. [`IrohLink`]
//! is the product's.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

use iroh::Endpoint;
use iroh::endpoint::Connection;
use kr_crypto::keys::TransportIdentityKeyPair;
use kr_protocol::error::ProtocolError;
use kr_protocol::hello::{ALPN, HostSelection};
use kr_protocol::ids::DeviceId;
use kr_protocol::method::Method;
use kr_protocol::pairing::{NetworkConfig, PairFinishRequest};
use kr_protocol::preauth::{
    PairFinishResult, PairRedeemParams, PairRedeemResult, PairStatusParams, PairStatusResult,
};
use kr_protocol::scalars::{AuthorisationKey, EndpointKey};
use kr_transport::config::EndpointConfig;
use kr_transport::dialler::{DeviceEndpoint, HostServices};
use kr_transport::error::SelectionRefusal;
use kr_transport::handshake::{CandidateConnection, LocalIdentity};
use kr_transport::scheduler::SendLimits;
use tokio::sync::Mutex;

use super::BoxFuture;
use super::paired::PairedHost;
use crate::retry::UserAction;
use crate::services::{PairingAdmissions, RelayRefusal};
use crate::session::Session;
use crate::shown::{Said, Shown};
use crate::transport::{ControlTransport, NetworkTransport};

/// Why a call to a host did not answer.
///
/// What it says is the host's own refusal or the membership failure, through [`Shown::protocol`],
/// the check that refused a selection, in this program's own words, or which of the other two it
/// was. The text those two carry is not said: this library puts only what a reducer decided
/// there, and anything else that builds one can put any text there.
#[derive(Clone, PartialEq, Eq)]
pub enum LinkError {
    /// The host answered with a refusal of its own.
    Refused(ProtocolError),
    /// The device could not give the host the membership lease it needs on a connection, so the
    /// connection was not used for what it was made for. The cause is the organisation's service,
    /// this device's account, or the host's refusal of the lease it was given, and the message says
    /// which. It is no refusal of what the caller asked the host, so a caller that reads a refusal
    /// as the host's decision about that does not read this as one.
    ///
    /// The action is what a person is asked to do after the words, as the stop of the lease that
    /// made this failure says it: a stop whose words say their own next step asks nothing more, and
    /// one that states only a fact asks what tells the person what to do.
    Membership(ProtocolError, UserAction),
    /// The host refused the connection itself, with the error it answers a device with at
    /// admission, before the device had presented what the host needs of it: the connection was
    /// made, and the host's refusal came before the lease was taken. The refusal is the session's
    /// own record of it, which the session that kept it no longer holds, so it is the cause of the
    /// connection not being used, and a caller that tells a host that cannot take another
    /// connection from other refusals reads it here. It is no refusal of a request.
    ConnectionRefused(ProtocolError),
    /// A link that wraps the host's declined to dial, for a limit of its own: no connection was
    /// made and the host was asked nothing. The refusal is that link's and not the host's, so a
    /// caller that reads a refusal as the host's decision does not read this as one, and a caller
    /// that dials again later may be given a connection.
    Declined(ProtocolError),
    /// The host could not be reached, or the connection to it ended.
    Lost(String),
    /// The host answered, and this device refused its selection before using anything under it:
    /// the selection names another endpoint than the one that answered, or does not answer this
    /// device's offer. The host is reachable and is not who it said, or not speaking the exchange
    /// that was offered, which a new try does not change. Both pairing flows end such an attempt as
    /// a host that did not match.
    Selection(SelectionRefusal),
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
            Self::Membership(error, _) | Self::Declined(error) => Shown::protocol(error),
            Self::ConnectionRefused(error) => crate::shown!(
                "the host refused the connection: {}: {}",
                error.code,
                Shown::protocol(error)
            ),
            Self::Lost(_) => Shown::said("the host could not be reached"),
            Self::Selection(refusal) => Shown::selection(refusal),
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
    /// A selection this device refused is neither: the host answered, so the connection is not
    /// lost, and what it answered is why the attempt cannot go on.
    fn from(error: kr_transport::TransportError) -> Self {
        match error {
            kr_transport::TransportError::Refused(refusal) => Self::Refused(refusal),
            kr_transport::TransportError::Configuration { .. } => {
                Self::Configuration(Shown::transport(&error).into_string())
            }
            kr_transport::TransportError::Selection(refusal) => Self::Selection(refusal),
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

/// When a member's device presents its lease on a connection to a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presentation {
    /// The first thing on a connection: the lease the device holds is presented while it lasts, and
    /// the organisation's service is asked for another when none is held or the host refuses it.
    First,
    /// Again, on a connection that presented already and is kept: nothing is sent while the lease
    /// the host holds is not due to be replaced, and a new lease is asked for and presented when
    /// it is. A new lease that cannot be got is no failure while the lease the host holds lasts.
    IfDue,
}

/// What gives a host the membership lease a member's device needs on a connection to it, and
/// binds each such connection to the account it was opened under.
pub trait MembershipPresenter: Send + Sync {
    /// Opens a connection to `host` under the account signed in now, by running `dial`, and returns
    /// its transport ended at the moment that account signs out or another signs in, whatever
    /// opened it: a connection of the application's, a visit, a session link, a terminal view.
    /// Refuses before dialling when no account is signed in. Runs `dial` and returns its transport
    /// as it is for a host whose grant answers to no organisation.
    ///
    /// # Errors
    ///
    /// Returns why no connection under an account can be made, or `dial`'s own failure.
    fn bind<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
        dial: BoxFuture<'a, Result<Arc<dyn ControlTransport>, LinkError>>,
    ) -> BoxFuture<'a, Result<Arc<dyn ControlTransport>, LinkError>>;

    /// Presents the lease `host`'s grant needs, as `presentation` says, on `session`, which proves
    /// `device_key`, or does nothing for a host whose grant answers to no organisation.
    ///
    /// # Errors
    ///
    /// Returns why the host holds no lease and will not without a person or a new connection.
    fn present<'a>(
        &'a self,
        session: &'a Session,
        host: &'a PairedHost,
        device_key: AuthorisationKey,
        presentation: Presentation,
    ) -> BoxFuture<'a, Result<(), LinkError>>;
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
    ///
    /// The surface it returns holds a selection that answers the offer and names the endpoint that
    /// answered on `connection`: a link that opens one on another footing breaks the pairing
    /// flows, which rely on that and do not check it again.
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

    /// Connects to a paired host as the device it became, and starts a session on the
    /// connection, which holds whatever the host needs of this device before it answers anything
    /// else on it ([`Self::present_membership`]).
    fn connect_paired<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
    ) -> BoxFuture<'a, Result<Session, LinkError>> {
        Box::pin(async move {
            let transport = self.connect_paired_transport(host, identity).await?;
            presenting(self, transport, host, identity).await
        })
    }

    /// Gives the host what it needs of this device before it will answer anything else on
    /// `session`: the first thing done on a connection to a paired host
    /// ([`Presentation::First`]), and again on a connection that is kept, when the lease it holds is
    /// due to be replaced ([`Presentation::IfDue`]).
    ///
    /// A device whose grant answers to an organisation is refused every other method until the host
    /// holds a membership lease the organisation signed for it, and no lease survives a host's
    /// restart. A link that holds the account the lease is asked for with presents it here. The
    /// default asks for nothing: a host whose grant answers to no organisation needs none. A link
    /// that wraps another forwards this call, or the connections it makes present no lease.
    ///
    /// # Errors
    ///
    /// Returns why the host holds no lease and will not without a person or a new connection.
    fn present_membership<'a>(
        &'a self,
        _session: &'a Session,
        _host: &'a PairedHost,
        _identity: &'a LocalIdentity,
        _presentation: Presentation,
    ) -> BoxFuture<'a, Result<(), LinkError>> {
        Box::pin(async { Ok(()) })
    }

    /// Takes `host`, the pairing the person forgot, out of this device's one endpoint: its address
    /// lookups are no longer asked and each relay that no other host names leaves the relay map. A
    /// connection that is open stays open until whoever holds it closes it. A host the device never
    /// dialled changes nothing.
    ///
    /// A dial that began under that pairing and reaches the endpoint after this call is refused, and
    /// one that was in the middle of putting the host there is taken back, so the host is not in the
    /// endpoint when the call has returned. A new pairing with the same host is another pairing and
    /// is not refused.
    ///
    /// A link that wraps another forwards this call. It has no default, so that a wrapper cannot
    /// leave a forgotten host in the endpoint by forgetting to.
    fn forget_host<'a>(&'a self, host: &'a PairedHost) -> BoxFuture<'a, ()>;

    /// What the managed service's answer says a dial to `endpoint` that failed was held back by:
    /// no free capacity to admit this device through the relay the dial addresses, with the paths
    /// that still work, or a fault of the service.
    ///
    /// A device that holds no lease with the host asks the managed service for an admission as it
    /// dials, and a service that has none to give, or that failed, is a reason a person acts on
    /// differently from a host that is not there. It is asked after a dial has ended, and a link
    /// that asks no service answers none.
    fn relay_refusal(
        &self,
        _network: &NetworkConfig,
        _endpoint: &EndpointKey,
    ) -> Option<RelayRefusal> {
        None
    }
}

/// A session on `transport`, to a paired host, with what the host needs of this device presented
/// on it first; the connection is closed when that cannot be done.
async fn presenting<L: HostLink + ?Sized>(
    link: &L,
    transport: Arc<dyn ControlTransport>,
    host: &PairedHost,
    identity: &LocalIdentity,
) -> Result<Session, LinkError> {
    let session = Session::start(transport).map_err(|error| LinkError::lost(error.said()))?;
    if let Err(error) = link
        .present_membership(&session, host, identity, Presentation::First)
        .await
    {
        session.close();
        return Err(error);
    }
    Ok(session)
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

/// How the device stands with a host that it dials, which decides whether the host's relays
/// enter the endpoint's relay map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// A host that a pairing invitation names and the device is not paired with yet: its address
    /// lookups enter the endpoint and its relays do not.
    Invited,
    /// A host the device is paired with, by the identity the host gave this device in that pairing:
    /// its address lookups and its relays enter the endpoint, unless the person forgot that pairing
    /// in this run.
    Paired(DeviceId),
}

/// An endpoint of the pool, with what the pool knows of the hosts that were introduced to it.
struct Bound {
    endpoint: DeviceEndpoint,
    /// For each host introduced to this endpoint by a pairing, the pairings that introduced it and
    /// have not been forgotten. It describes this endpoint and no other, so a close takes it along,
    /// and the endpoint that the next request binds starts with none. Only a path that holds the
    /// host's own lock reads or changes a host's set; the mutex is never held across an await.
    introduced: std::sync::Mutex<BTreeMap<EndpointKey, BTreeSet<DeviceId>>>,
}

impl Bound {
    fn introduced(&self) -> std::sync::MutexGuard<'_, BTreeMap<EndpointKey, BTreeSet<DeviceId>>> {
        self.introduced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records that `pairing` introduced `host`.
    fn introduced_by(&self, host: &EndpointKey, pairing: DeviceId) {
        self.introduced().entry(*host).or_default().insert(pairing);
    }

    /// Records that `pairing` has left `host`, and says whether no pairing is left that introduced
    /// it, so that the host's entry goes.
    fn left_by(&self, host: &EndpointKey, pairing: DeviceId) -> bool {
        let mut introduced = self.introduced();
        let Some(pairings) = introduced.get_mut(host) else {
            return true;
        };
        pairings.remove(&pairing);
        let last = pairings.is_empty();
        if last {
            introduced.remove(host);
        }
        last
    }
}

/// This device's one dialling endpoint, bound at the first request and kept for the run.
///
/// Every introduction of a host and every removal of one holds that host's own lock, which a dial
/// takes before it decides, so the two never overlap: a dial that began before a forget either
/// finishes its introduction before the forget removes the host, or waits for the forget and then
/// meets its mark. A caller that stops waiting releases the lock where it stands, and what it
/// introduced is in the transport's table already, so the forget that follows removes it.
///
/// The locks are taken in one order on every path: a host's own lock, then the device lock.
/// [`Self::close`] and every other path that holds the device lock take no host's lock.
pub struct EndpointPool {
    transport: TransportIdentityKeyPair,
    bind: Option<SocketAddr>,
    /// Extra trust anchors for a relay's HTTPS certificate, as DER certificates, beside the ones
    /// the platform trusts.
    relay_roots: Vec<Vec<u8>>,
    /// Whether the endpoint reaches hosts through relays only.
    relay_only: bool,
    /// The endpoint, once one is bound. The lock is held while one binds and while one closes,
    /// and never while a host is introduced or forgotten.
    device: Mutex<Option<Arc<Bound>>>,
    /// The pairings the person forgot in this run, each by the identity its host gave this device.
    /// The set belongs to the pool, so a close and a new bind leave it as it is. It holds one
    /// identity for each forget of a run and nothing removes one: a new pairing with the same host
    /// has an identity of its own. The mutex is never held across an await.
    forgotten: std::sync::Mutex<BTreeSet<DeviceId>>,
    /// The host's own locks, one for each host key that this process dialled or forgot. A lock is
    /// never replaced or removed: a second lock for one host while a dial holds or awaits the first
    /// would end the exclusion. The table is as large as the number of host keys that the person
    /// pairs with or invites in a run, one `Arc` each. The mutex is never held across an await.
    hosts: std::sync::Mutex<BTreeMap<EndpointKey, Arc<Mutex<()>>>>,
    /// The hold a test puts on a dial between its decision and the introduction.
    #[cfg(feature = "testing")]
    gate: gate::Gate,
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
            device: Mutex::new(None),
            forgotten: std::sync::Mutex::new(BTreeSet::new()),
            hosts: std::sync::Mutex::new(BTreeMap::new()),
            #[cfg(feature = "testing")]
            gate: gate::Gate::default(),
        }
    }

    /// The same pool, with its endpoint bound to `address`. A test binds to the loopback
    /// interface, so nothing it dials leaves the machine.
    #[must_use]
    pub const fn bound_to(mut self, address: SocketAddr) -> Self {
        self.bind = Some(address);
        self
    }

    /// The same pool, with its endpoint reaching hosts through relays only and never on a direct
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

    /// The device's endpoint, bound now if none is open, with `host` introduced to it: the host's
    /// address lookups are registered under its identity, and for a [`Standing::Paired`] host its
    /// relays go into the relay map. Asking again for a host that is already there changes
    /// nothing, and a changed configuration for the same identity replaces what it had.
    ///
    /// A pairing that the person forgot ([`Self::forget`]) is refused. The dial takes the host's own
    /// lock first and looks at the pairing's mark after it holds the lock, so a dial that waited
    /// behind a forget meets the mark, and one that the forget waits for has finished its
    /// introduction before the forget removes the host. The lock is held through the introduction
    /// and no longer: the connection that the caller makes with the endpoint it gets is its own,
    /// and the pool is not asked again.
    ///
    /// A dial of a host that is already introduced, with the same services, holds the host's lock
    /// across no await but the one for the device lock, which binds the endpoint when none is open.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::Configuration`] for a configuration that cannot be used,
    /// [`LinkError::Lost`] when the endpoint cannot be bound, and [`LinkError::Lost`] when the
    /// pairing was forgotten.
    pub async fn endpoint(
        &self,
        network: &NetworkConfig,
        host: &EndpointKey,
        standing: Standing,
    ) -> Result<Endpoint, LinkError> {
        let config = EndpointConfig::from_network_config(network)?;
        let services = match standing {
            Standing::Invited => HostServices::invited(&config, host)?,
            Standing::Paired(_) => HostServices::paired(&config, host)?,
        };
        let pairing = match standing {
            Standing::Paired(pairing) => Some(pairing),
            Standing::Invited => None,
        };
        let lock = self.lock_of(host);
        #[cfg(feature = "testing")]
        self.gate.pass(host, gate::Point::BeforeTheLock).await;
        let _held = lock.lock().await;
        // The decision: made with the lock held, after any forget that held it first.
        if pairing.is_some_and(|pairing| self.is_forgotten(pairing)) {
            return Err(not_established());
        }
        let device = self.bound().await?;
        #[cfg(feature = "testing")]
        self.gate
            .pass(host, gate::Point::BeforeTheIntroduction)
            .await;
        device.endpoint.introduce(services).await?;
        if let Some(pairing) = pairing {
            device.introduced_by(host, pairing);
        }
        Ok(device.endpoint.endpoint().clone())
    }

    /// Takes `host` out of the endpoint when `pairing`, the identity the host gave this device in
    /// the pairing the person forgot, was the last pairing that introduced it: its lookups, and
    /// each relay that no other host names. A host that another pairing introduced stays. Nothing
    /// changes for a host the endpoint was never introduced to, or before an endpoint is bound.
    ///
    /// The pairing is marked first, so that no dial that begins under it is let through, and then
    /// the forget takes the host's own lock and removes the host while it holds it. It waits for
    /// what holds that lock: a dial of the same host, or another forget of it, that is between its
    /// decision and the end of its introduction. That dial waits for the device lock when a close
    /// or a first bind holds it, which a forget waits for in any case, and for the transport's
    /// change of the relay map, which takes the transport's own turn and the library's sends to its
    /// socket task. Nothing in it waits on the network but the library's own close, which the
    /// library bounds. A dial of another host and a forget of another host do not wait for it.
    pub async fn forget(&self, host: &EndpointKey, pairing: DeviceId) {
        self.forgotten
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(pairing);
        let lock = self.lock_of(host);
        let _held = lock.lock().await;
        let device = self.device.lock().await.clone();
        if let Some(device) = device
            && device.left_by(host, pairing)
        {
            // A host that is not a public key was never introduced, so it has nothing to leave.
            let _ = device.endpoint.forget(host).await;
        }
    }

    /// The lock of `host`, made at the first request that names it and kept.
    fn lock_of(&self, host: &EndpointKey) -> Arc<Mutex<()>> {
        Arc::clone(
            self.hosts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(*host)
                .or_default(),
        )
    }

    /// Whether the person forgot the pairing `pairing` in this run.
    fn is_forgotten(&self, pairing: DeviceId) -> bool {
        self.forgotten
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&pairing)
    }

    /// The relays in the endpoint's relay map now: none before the endpoint is bound.
    pub async fn relay_urls(&self) -> BTreeSet<iroh::RelayUrl> {
        match &*self.device.lock().await {
            Some(device) => device.endpoint.relay_urls(),
            None => BTreeSet::new(),
        }
    }

    /// Closes the endpoint and waits until it has finished closing, so that the endpoint a later
    /// request binds is never beside it on a relay. The pool's lock is held until then.
    ///
    /// A caller awaits it to its end. One that drops it part way leaves the endpoint closing, and
    /// the next request binds another beside it.
    ///
    /// It takes no host's lock. The pairings that introduced each host belong to the endpoint and
    /// go with it, so a dial that waited for the device lock through a close binds a new endpoint,
    /// introduces its host there and records itself there alone.
    pub async fn close(&self) {
        let mut device = self.device.lock().await;
        if let Some(open) = device.take() {
            open.endpoint.close().await;
        }
    }

    /// The open endpoint, bound now if there is none.
    async fn bound(&self) -> Result<Arc<Bound>, LinkError> {
        let mut device = self.device.lock().await;
        if let Some(open) = &*device {
            return Ok(Arc::clone(open));
        }
        let open = Arc::new(Bound {
            endpoint: DeviceEndpoint::bind(&self.config()?, &self.transport).await?,
            introduced: std::sync::Mutex::new(BTreeMap::new()),
        });
        *device = Some(Arc::clone(&open));
        Ok(open)
    }

    /// The configuration the device's endpoint is bound with: this device's own choices and no
    /// relay or address lookup, which each host brings when the device first dials it.
    fn config(&self) -> Result<EndpointConfig, LinkError> {
        let mut config = EndpointConfig::from_network_config(&NetworkConfig::empty())?;
        config.bind_addr = self.bind;
        config.relay_ca_roots.clone_from(&self.relay_roots);
        config.relay_only = self.relay_only;
        Ok(config)
    }
}

/// The product's link: the pool's endpoint, `connect_unpaired`, and the authorised handshake.
pub struct IrohLink {
    pool: Arc<EndpointPool>,
    admissions: Option<Arc<PairingAdmissions>>,
    membership: Option<Arc<dyn MembershipPresenter>>,
}

// The presenter is left out: a trait object prints whatever implements it.
crate::debug_fields!(IrohLink { pool, admissions });

impl IrohLink {
    /// A link over `pool`.
    #[must_use]
    pub const fn new(pool: Arc<EndpointPool>) -> Self {
        Self {
            pool,
            admissions: None,
            membership: None,
        }
    }

    /// The same link, giving a host the membership lease its grant needs through `presenter` as the
    /// first thing on every connection to it as a paired device.
    #[must_use]
    pub fn presenting_membership(mut self, presenter: Arc<dyn MembershipPresenter>) -> Self {
        self.membership = Some(presenter);
        self
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

    /// `dial`, bound to the account signed in when it is made when the link binds connections to a
    /// member's account. Every connection to a paired host is made by one of the two methods that
    /// call this, so what is bound here is every session the device opens to such a host.
    fn bound<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
        dial: BoxFuture<'a, Result<Arc<dyn ControlTransport>, LinkError>>,
    ) -> BoxFuture<'a, Result<Arc<dyn ControlTransport>, LinkError>> {
        match &self.membership {
            Some(presenter) => presenter.bind(host, identity, dial),
            None => dial,
        }
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
            let local = self
                .pool
                .endpoint(network, endpoint, Standing::Invited)
                .await?;
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
            let connection = local
                .connect(address, ALPN)
                .await
                .map_err(|_| not_established())?;
            if let Some(admissions) = &self.admissions {
                admissions.dial_succeeded(network, endpoint);
            }
            Ok(connection)
        })
    }

    fn relay_refusal(
        &self,
        network: &NetworkConfig,
        endpoint: &EndpointKey,
    ) -> Option<RelayRefusal> {
        self.admissions
            .as_ref()
            .and_then(|admissions| admissions.refusal(network, endpoint))
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

    fn present_membership<'a>(
        &'a self,
        session: &'a Session,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
        presentation: Presentation,
    ) -> BoxFuture<'a, Result<(), LinkError>> {
        match &self.membership {
            Some(presenter) => presenter.present(
                session,
                host,
                *identity.authorisation.public(),
                presentation,
            ),
            None => Box::pin(async { Ok(()) }),
        }
    }

    fn connect_paired_transport<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
    ) -> BoxFuture<'a, Result<Arc<dyn ControlTransport>, LinkError>> {
        self.bound(
            host,
            identity,
            Box::pin(connect_paired_over(&self.pool, host, identity)),
        )
    }

    fn forget_host<'a>(&'a self, host: &'a PairedHost) -> BoxFuture<'a, ()> {
        Box::pin(self.pool.forget(&host.host_endpoint_id, host.device_id))
    }
}

/// A dial that did not reach its host, in the words every such failure is shown with.
fn not_established() -> LinkError {
    LinkError::lost(Shown::said("the connection could not be established"))
}

/// Connects to `host` as the device it became, through the device's one endpoint.
async fn connect_paired_over(
    pool: &EndpointPool,
    host: &PairedHost,
    identity: &LocalIdentity,
) -> Result<Arc<dyn ControlTransport>, LinkError> {
    let address = EndpointConfig::from_network_config(&host.network_config)?
        .peer_addr(&host.host_endpoint_id)?;
    let local = pool
        .endpoint(
            &host.network_config,
            &host.host_endpoint_id,
            Standing::Paired(host.device_id),
        )
        .await?;
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

/// The hold a test puts on the next dial of a host at one of two places, which
/// [`EndpointPool::hold_next_dial_of`] (before the dial asks for its host's lock) and
/// [`EndpointPool::hold_next_introduce_of`] (after it decided, before it introduces the host) arm. A
/// test waits for the dial on a thread of its own, by asking [`Self::is_reached`].
#[cfg(feature = "testing")]
pub struct IntroduceHold {
    reached: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    seen: std::sync::atomic::AtomicBool,
    release: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

#[cfg(feature = "testing")]
impl IntroduceHold {
    /// Whether a dial has reached the hold so far.
    pub fn is_reached(&self) -> bool {
        use std::sync::atomic::Ordering;
        if self.seen.load(Ordering::SeqCst) {
            return true;
        }
        let arrived = self
            .reached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .try_recv()
            .is_ok();
        if arrived {
            self.seen.store(true, Ordering::SeqCst);
        }
        arrived
    }

    /// Lets the held dial go on, or the next one that reaches the hold pass at once.
    pub fn release(&self) {
        let release = self
            .release
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(release) = release {
            let _ = release.send(());
        }
    }
}

#[cfg(feature = "testing")]
impl EndpointPool {
    /// Arms a hold on the next dial of `host` that has decided, with its host's lock held, and is
    /// about to introduce the host: it stops there until the hold is released. For the
    /// cases of this crate and of the companion, as the transport's hold on its map task is for
    /// that crate's.
    #[must_use]
    pub fn hold_next_introduce_of(&self, host: &EndpointKey) -> IntroduceHold {
        self.gate.arm(*host, gate::Point::BeforeTheIntroduction)
    }

    /// Arms a hold on the next dial of `host`, before it asks for the host's lock and so before it
    /// decides: it stops there until the hold is released.
    #[must_use]
    pub fn hold_next_dial_of(&self, host: &EndpointKey) -> IntroduceHold {
        self.gate.arm(*host, gate::Point::BeforeTheLock)
    }
}

#[cfg(feature = "testing")]
mod gate {
    use std::sync::{Mutex, PoisonError, mpsc};

    use kr_protocol::scalars::EndpointKey;
    use tokio::sync::oneshot;

    use super::IntroduceHold;

    /// Where in a dial a hold stands.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum Point {
        /// Before the dial asks for its host's lock.
        BeforeTheLock,
        /// After the dial decided, before it introduces the host.
        BeforeTheIntroduction,
    }

    /// The one hold that is armed, if any: the next dial of its host that reaches its point takes it.
    #[derive(Default)]
    pub(super) struct Gate(Mutex<Option<Armed>>);

    struct Armed {
        host: EndpointKey,
        point: Point,
        reached: mpsc::Sender<()>,
        release: oneshot::Receiver<()>,
    }

    impl Gate {
        /// Holds the calling dial of `host` if a hold is armed for that host at `point`.
        pub(super) async fn pass(&self, host: &EndpointKey, point: Point) {
            let armed = {
                let mut armed = self.0.lock().unwrap_or_else(PoisonError::into_inner);
                if armed
                    .as_ref()
                    .is_some_and(|armed| armed.host == *host && armed.point == point)
                {
                    armed.take()
                } else {
                    None
                }
            };
            if let Some(armed) = armed {
                let _ = armed.reached.send(());
                let _ = armed.release.await;
            }
        }

        pub(super) fn arm(&self, host: EndpointKey, point: Point) -> IntroduceHold {
            let (reached, reaching) = mpsc::channel();
            let (release, releasing) = oneshot::channel();
            *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(Armed {
                host,
                point,
                reached,
                release: releasing,
            });
            IntroduceHold {
                reached: Mutex::new(reaching),
                seen: std::sync::atomic::AtomicBool::new(false),
                release: Mutex::new(Some(release)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::pairing::NetworkHint;
    use kr_protocol::scalars::Nullable;

    /// The identity a host gave this device in one pairing.
    fn pairing(number: u8) -> DeviceId {
        DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([number; 16]))
    }

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

    /// Hosts whose relays and resolvers differ, and a host dialled again, are all reached through
    /// the one endpoint, and no request for one host closes it.
    #[tokio::test]
    async fn one_endpoint_serves_every_set_of_services() {
        let pool = EndpointPool::new(TransportIdentityKeyPair::generate().expect("a key"))
            .bound_to("127.0.0.1:0".parse().expect("loopback"));
        let host = || {
            *TransportIdentityKeyPair::generate()
                .expect("a key")
                .public()
        };
        let (first_host, second_host, third_host) = (host(), host(), host());
        let first = network(&[], Some("http://127.0.0.1:9/pkarr"), &["127.0.0.1:4001"]);
        let other_resolver = network(&[], Some("http://127.0.0.1:10/pkarr"), &[]);
        let relayed = network(
            &["https://127.0.0.1:9"],
            Some("http://127.0.0.1:11/pkarr"),
            &[],
        );
        let a = pool
            .endpoint(&first, &first_host, Standing::Paired(pairing(1)))
            .await
            .expect("an endpoint");
        let b = pool
            .endpoint(&other_resolver, &second_host, Standing::Paired(pairing(2)))
            .await
            .expect("an endpoint");
        let c = pool
            .endpoint(&relayed, &third_host, Standing::Paired(pairing(3)))
            .await
            .expect("an endpoint");
        let again = pool
            .endpoint(&first, &first_host, Standing::Paired(pairing(1)))
            .await
            .expect("an endpoint");
        for each in [&b, &c, &again] {
            assert_eq!(a.bound_sockets(), each.bound_sockets(), "one endpoint");
            assert_eq!(a.id(), each.id(), "one identity");
        }
        assert!(!a.is_closed(), "no request closed the endpoint");
        pool.close().await;
        assert!(a.is_closed());
    }

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().expect("loopback")
    }

    fn relay(url: &str) -> iroh::RelayUrl {
        url.parse().expect("a relay URL")
    }

    /// An invitation's relays stay out of the endpoint's relay map when the device dials its host
    /// to pair, and the dial reaches the host through the hint. Once the pairing has completed and
    /// the device dials the host as a paired host, its relays are in the map.
    #[tokio::test]
    async fn an_invitations_relays_stay_out_of_the_map_until_the_pairing_completes() {
        let peer_key = TransportIdentityKeyPair::generate().expect("a key");
        let mut config =
            EndpointConfig::from_network_config(&NetworkConfig::empty()).expect("a config");
        config.bind_addr = Some(loopback());
        let peer = kr_transport::endpoint::bind_listener(&config, &peer_key)
            .await
            .expect("a peer on loopback");
        let accepting = peer.clone();
        let accepted = tokio::spawn(async move {
            let incoming = accepting.accept().await.expect("a connection arrives");
            incoming.await.expect("the connection completes")
        });
        let invitation = network(
            &["https://127.0.0.1:9"],
            None,
            &[&peer.bound_sockets()[0].to_string()],
        );
        let pool = Arc::new(
            EndpointPool::new(TransportIdentityKeyPair::generate().expect("a key"))
                .bound_to(loopback()),
        );
        let connection = IrohLink::new(Arc::clone(&pool))
            .dial(&invitation, peer_key.public())
            .await
            .expect("the dial reaches the host through its hint");
        assert!(
            pool.relay_urls().await.is_empty(),
            "the invitation's relay is not in the map"
        );

        pool.endpoint(&invitation, peer_key.public(), Standing::Paired(pairing(1)))
            .await
            .expect("the paired host's endpoint");
        assert_eq!(
            pool.relay_urls().await,
            BTreeSet::from([relay("https://127.0.0.1:9")]),
            "the paired host's relay is in the map"
        );
        drop(connection);
        drop(accepted.await.expect("the peer's side"));
        pool.close().await;
        peer.close().await;
    }

    /// What the endpoint's address-lookup registry yields for `host`, polled to its end.
    async fn registry_yields(
        endpoint: &Endpoint,
        host: &EndpointKey,
    ) -> Vec<
        Result<
            Result<iroh::address_lookup::Item, iroh::address_lookup::Error>,
            iroh::address_lookup::AddressLookupFailed,
        >,
    > {
        use futures_util::StreamExt as _;
        let registry = endpoint
            .address_lookup()
            .expect("the endpoint's lookup registry");
        let id = iroh::EndpointId::from_bytes(host.as_bytes()).expect("a public key");
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            registry.resolve(id).collect::<Vec<_>>(),
        )
        .await
        .expect("the lookup ends by itself")
    }

    /// Whether the registry gave no answer for a host: one item, its "no results" failure with no
    /// service's error behind it, and nothing after it.
    fn registry_knows_nothing<T>(
        yielded: &[Result<T, iroh::address_lookup::AddressLookupFailed>],
    ) -> bool {
        yielded.len() == 1
            && matches!(
                &yielded[0],
                Err(iroh::address_lookup::AddressLookupFailed::NoResults { errors, .. })
                    if errors.is_empty()
            )
    }

    /// Forgetting a host takes its own relay out of the map and its lookups out of the registry, and
    /// leaves the relay it shares with another host, and the endpoint stays open for the host that
    /// is left.
    #[tokio::test]
    async fn forgetting_a_host_takes_it_out_of_the_one_endpoint() {
        let pool = EndpointPool::new(TransportIdentityKeyPair::generate().expect("a key"))
            .bound_to(loopback());
        let host = || {
            *TransportIdentityKeyPair::generate()
                .expect("a key")
                .public()
        };
        let (first, second) = (host(), host());
        let shared = "https://127.0.0.1:9";
        let own = "https://127.0.0.1:10";
        let resolver = Some("http://127.0.0.1:9/pkarr");
        let endpoint = pool
            .endpoint(
                &network(&[shared], None, &[]),
                &first,
                Standing::Paired(pairing(1)),
            )
            .await
            .expect("an endpoint");
        pool.endpoint(
            &network(&[shared, own], resolver, &[]),
            &second,
            Standing::Paired(pairing(2)),
        )
        .await
        .expect("an endpoint");
        assert_eq!(
            pool.relay_urls().await,
            BTreeSet::from([relay(shared), relay(own)])
        );
        assert!(
            !registry_knows_nothing(&registry_yields(&endpoint, &second).await),
            "the control: while the host is known, its lookups are asked about it"
        );

        pool.forget(&second, pairing(2)).await;
        assert_eq!(
            pool.relay_urls().await,
            BTreeSet::from([relay(shared)]),
            "the forgotten host's own relay left the map and the shared one stayed"
        );
        assert!(
            registry_knows_nothing(&registry_yields(&endpoint, &second).await),
            "the registry answers nothing for the forgotten host and asks no service"
        );
        assert!(!endpoint.is_closed(), "forgetting a host closes nothing");
        pool.close().await;
    }

    /// The resolver the cases give a host, where nothing listens: a host that is in the transport's
    /// table is one whose lookups the registry asks, and the service's error shows it.
    const RESOLVER: &str = "http://127.0.0.1:9/pkarr";

    fn key() -> EndpointKey {
        *TransportIdentityKeyPair::generate()
            .expect("a key")
            .public()
    }

    fn loopback_pool() -> Arc<EndpointPool> {
        Arc::new(
            EndpointPool::new(TransportIdentityKeyPair::generate().expect("a key"))
                .bound_to(loopback()),
        )
    }

    /// Waits, on a thread of its own, until `ready` holds. A hold stands on the path that is waited
    /// on, so the wait is made by a blocking thread and no timer of the runtime.
    async fn until(what: &'static str, ready: impl Fn() -> bool + Send + 'static) {
        tokio::task::spawn_blocking(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !ready() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "gave up waiting: {what}"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        })
        .await
        .expect("the wait ran");
    }

    /// Runs `work` as a task of its own: the task, which a case can abort, and the receiver that
    /// hears the result once the work returned.
    fn running<T: Send + 'static>(
        work: impl std::future::Future<Output = T> + Send + 'static,
    ) -> (tokio::task::JoinHandle<()>, std::sync::mpsc::Receiver<T>) {
        let (done, receiver) = std::sync::mpsc::channel();
        let task = tokio::spawn(async move {
            let _ = done.send(work.await);
        });
        (task, receiver)
    }

    /// The result of work started by [`running`], awaited on a blocking thread.
    async fn heard<T: Send + 'static>(
        what: &'static str,
        receiver: std::sync::mpsc::Receiver<T>,
    ) -> T {
        tokio::task::spawn_blocking(move || {
            receiver
                .recv_timeout(std::time::Duration::from_secs(30))
                .unwrap_or_else(|_| panic!("gave up waiting: {what}"))
        })
        .await
        .expect("the wait ran")
    }

    /// A dial of `host` under the pairing `number`, as a task: whether it reached the host.
    fn dialling(
        pool: &Arc<EndpointPool>,
        config: &NetworkConfig,
        host: EndpointKey,
        number: u8,
    ) -> (tokio::task::JoinHandle<()>, std::sync::mpsc::Receiver<bool>) {
        let (pool, config) = (Arc::clone(pool), config.clone());
        running(async move {
            pool.endpoint(&config, &host, Standing::Paired(pairing(number)))
                .await
                .is_ok()
        })
    }

    /// The forget of the pairing `number` of `host`, as a task.
    fn forgetting(
        pool: &Arc<EndpointPool>,
        host: EndpointKey,
        number: u8,
    ) -> (tokio::task::JoinHandle<()>, std::sync::mpsc::Receiver<()>) {
        let pool = Arc::clone(pool);
        running(async move { pool.forget(&host, pairing(number)).await })
    }

    /// The pool's endpoint, which the case knows is bound.
    async fn the_bound(pool: &EndpointPool) -> Arc<Bound> {
        pool.device
            .lock()
            .await
            .clone()
            .expect("the endpoint is bound")
    }

    /// Whether the transport's table holds `host`: the registry asks its lookups for it, and a
    /// host that is not in the table gives "no results" and no service's error.
    async fn table_holds(pool: &EndpointPool, host: &EndpointKey) -> bool {
        let endpoint = the_bound(pool).await.endpoint.endpoint().clone();
        !registry_knows_nothing(&registry_yields(&endpoint, host).await)
    }

    /// A dial under a pairing the person forgot is refused, and nothing that it does puts the host
    /// back, in the relay map or in the transport's table. Another pairing with the same host has an
    /// identity of its own and is reached, and the marks outlast a close and a new bind.
    #[tokio::test]
    async fn a_forgotten_pairing_is_refused_and_a_new_pairing_with_its_host_is_reached() {
        let pool = loopback_pool();
        let host = key();
        let own = "https://127.0.0.1:10";
        let config = network(&[own], Some(RESOLVER), &[]);

        pool.endpoint(&config, &host, Standing::Paired(pairing(1)))
            .await
            .expect("the pairing is reached");
        assert!(
            table_holds(&pool, &host).await,
            "the control: the host that was reached is in the table"
        );
        pool.forget(&host, pairing(1)).await;
        assert!(pool.relay_urls().await.is_empty());
        assert!(!table_holds(&pool, &host).await);
        assert!(
            pool.endpoint(&config, &host, Standing::Paired(pairing(1)))
                .await
                .is_err(),
            "the forgotten pairing is refused"
        );
        assert!(
            pool.relay_urls().await.is_empty(),
            "the refused dial put nothing in the map"
        );
        assert!(
            !table_holds(&pool, &host).await,
            "the refused dial put nothing in the table"
        );

        // A pairing that was forgotten before it ever dialled is refused too.
        pool.forget(&host, pairing(2)).await;

        // A new pairing with the same host has an identity of its own and is reached at once.
        pool.endpoint(&config, &host, Standing::Paired(pairing(3)))
            .await
            .expect("the new pairing is reached");
        assert_eq!(
            pool.relay_urls().await,
            BTreeSet::from([relay(own)]),
            "the new pairing's relay is in the map"
        );
        assert!(table_holds(&pool, &host).await);
        assert!(
            pool.endpoint(&config, &host, Standing::Paired(pairing(1)))
                .await
                .is_err(),
            "the old pairing stays refused beside the new one"
        );
        pool.close().await;
        pool.endpoint(&config, &host, Standing::Paired(pairing(3)))
            .await
            .expect("the new pairing is reached through a new endpoint");
        for forgotten in [1, 2] {
            assert!(
                pool.endpoint(&config, &host, Standing::Paired(pairing(forgotten)))
                    .await
                    .is_err(),
                "the marks outlast a close and a new bind"
            );
        }
        pool.close().await;
    }

    /// A dial whose caller stops waiting, at each of the three places where it waits, leaves its
    /// host out of the table and the map once the forget returned, and after the transport's held
    /// change of the map has run. The third is the order that matters most: the forget begins before
    /// the dial introduces, and the caller stops after the table took the host in.
    #[tokio::test]
    async fn a_dial_that_is_dropped_leaves_its_host_out_once_the_forget_returned() {
        let pool = loopback_pool();
        let own = "https://127.0.0.1:10";
        let config = network(&[own], Some(RESOLVER), &[]);

        // At the endpoint's lock: a dial waits for it with its host's lock in hand, and the drop
        // releases the host's lock.
        let first = key();
        let endpoint_lock = pool.device.lock().await;
        let (dial, _) = dialling(&pool, &config, first, 1);
        until("the dial holds its host's lock", {
            let lock = pool.lock_of(&first);
            move || lock.try_lock().is_err()
        })
        .await;
        dial.abort();
        assert!(dial.await.is_err(), "the dial was dropped");
        assert!(
            pool.lock_of(&first).try_lock().is_ok(),
            "the dropped dial let its host's lock go"
        );
        drop(endpoint_lock);
        let (_, forgotten) = forgetting(&pool, first, 1);
        heard("the forget returns", forgotten).await;
        assert!(pool.relay_urls().await.is_empty());

        // At the pool's test gate, between its decision and the introduction.
        let second = key();
        let gate = Arc::new(pool.hold_next_introduce_of(&second));
        let (dial, _) = dialling(&pool, &config, second, 2);
        until("the dial is held at the gate", {
            let gate = Arc::clone(&gate);
            move || gate.is_reached()
        })
        .await;
        dial.abort();
        assert!(dial.await.is_err(), "the dial was dropped");
        assert!(
            pool.lock_of(&second).try_lock().is_ok(),
            "the dropped dial let its host's lock go"
        );
        let (_, forgotten) = forgetting(&pool, second, 2);
        heard("the forget returns", forgotten).await;
        assert!(pool.relay_urls().await.is_empty());
        assert!(!table_holds(&pool, &second).await);

        // At the introduction: the forget begins while the dial is held before it, the dial puts
        // the host into the table and waits for the transport's change of the map, which is held, and
        // its caller stops.
        let third = key();
        let gate = Arc::new(pool.hold_next_introduce_of(&third));
        let (dial, _) = dialling(&pool, &config, third, 3);
        until("the dial is held at the gate", {
            let gate = Arc::clone(&gate);
            move || gate.is_reached()
        })
        .await;
        let mut map_task = the_bound(&pool).await.endpoint.hold_next_map_task();
        let (_, forgotten) = forgetting(&pool, third, 3);
        until("the forget has marked its pairing", {
            let pool = Arc::clone(&pool);
            move || pool.is_forgotten(pairing(3))
        })
        .await;
        gate.release();
        map_task.reached().await;
        assert!(
            table_holds(&pool, &third).await,
            "the control: the dial's introduction put the host in the table"
        );
        dial.abort();
        assert!(dial.await.is_err(), "the dial was dropped");
        heard("the forget returns once the dropped dial let go", forgotten).await;
        assert!(
            !table_holds(&pool, &third).await,
            "the host is out of the table when the forget returns"
        );
        assert!(
            pool.relay_urls().await.is_empty(),
            "the host's relay is not in the map when the forget returns"
        );
        map_task.release().await;
        assert!(
            !table_holds(&pool, &third).await && pool.relay_urls().await.is_empty(),
            "the held change of the map left the host out"
        );
        pool.close().await;
    }

    /// A forget waits for the introduction of its own host and for nothing else: while a dial of one
    /// host is held, a dial of another host returns, and so does a forget of another host. A dial that
    /// began before the forget still returns its endpoint, and the host is out when both have ended.
    #[tokio::test]
    async fn a_forget_waits_for_the_introduction_of_its_host_and_no_other_host_waits() {
        let pool = loopback_pool();
        let (held_host, other, unknown) = (key(), key(), key());
        let held_relay = "https://127.0.0.1:10";
        let other_relay = "https://127.0.0.1:11";
        let held_config = network(&[held_relay], Some(RESOLVER), &[]);
        let other_config = network(&[other_relay], Some(RESOLVER), &[]);
        pool.endpoint(&other_config, &other, Standing::Paired(pairing(5)))
            .await
            .expect("the other host is reached and the endpoint is bound");

        let gate = Arc::new(pool.hold_next_introduce_of(&held_host));
        let (dial, dialled) = dialling(&pool, &held_config, held_host, 1);
        until("the dial is held at the gate", {
            let gate = Arc::clone(&gate);
            move || gate.is_reached()
        })
        .await;
        let (_, forgotten) = forgetting(&pool, held_host, 1);
        until("the forget has marked its pairing", {
            let pool = Arc::clone(&pool);
            move || pool.is_forgotten(pairing(1))
        })
        .await;

        // The dial held, and the forget behind it: a dial of another host returns at once, and so
        // does a forget of a host that was never introduced.
        let (_, again) = dialling(&pool, &other_config, other, 5);
        assert!(
            heard(
                "a dial of another host returns while the dial is held",
                again
            )
            .await,
            "the other host is reached"
        );
        let (_, unrelated) = forgetting(&pool, unknown, 7);
        heard(
            "a forget of another host returns while the dial is held",
            unrelated,
        )
        .await;

        gate.release();
        assert!(
            heard("the dial ends", dialled).await,
            "the dial that began before the forget returns its endpoint"
        );
        heard("the forget returns after the introduction ended", forgotten).await;
        dial.await.expect("the dial ran");
        assert!(
            !table_holds(&pool, &held_host).await,
            "the forget took out the host that the dial introduced"
        );
        assert_eq!(
            pool.relay_urls().await,
            BTreeSet::from([relay(other_relay)]),
            "only the other host's relay is left in the map"
        );
        assert!(table_holds(&pool, &other).await, "the other host stays");
        pool.close().await;
    }

    /// A dial that waited behind a forget meets its mark. The forget's removal is held at the
    /// transport's gate while it holds the host's lock, a dial of the forgotten pairing waits for the
    /// lock, and when the removal is let go the dial is refused and puts nothing in the table or the
    /// map. A mark set after the removal would let the dial through in between. So does a dial that
    /// began before the forget and asks for the lock only after the forget ended: a decision made
    /// before the lock would let it through.
    #[tokio::test]
    async fn a_dial_that_waited_behind_the_forget_is_refused() {
        let pool = loopback_pool();
        let host = key();
        let own = "https://127.0.0.1:10";
        let config = network(&[own], Some(RESOLVER), &[]);
        pool.endpoint(&config, &host, Standing::Paired(pairing(1)))
            .await
            .expect("the pairing is reached");
        let mut removal = the_bound(&pool).await.endpoint.hold_next_map_task();

        let (_, forgotten) = forgetting(&pool, host, 1);
        removal.reached().await;
        let (_, dialled) = dialling(&pool, &config, host, 1);
        // The forget holds the lock and the dial holds a copy of it: the dial is waiting for it.
        until("the dial waits for the host's lock", {
            let lock = pool.lock_of(&host);
            move || Arc::strong_count(&lock) >= 4
        })
        .await;
        removal.release().await;

        heard("the forget returns", forgotten).await;
        assert!(
            !heard("the dial ends", dialled).await,
            "the dial that waited behind the forget is refused"
        );
        assert!(!table_holds(&pool, &host).await);
        assert!(pool.relay_urls().await.is_empty());

        // A dial that began before the forget and asks for the lock after it meets the mark too: it
        // is held before the lock, the forget runs to its end, and the dial is let go.
        let early = key();
        pool.endpoint(&config, &early, Standing::Paired(pairing(2)))
            .await
            .expect("the pairing is reached");
        let before_the_lock = Arc::new(pool.hold_next_dial_of(&early));
        let (_, dialled) = dialling(&pool, &config, early, 2);
        until("the dial is held before the lock", {
            let before_the_lock = Arc::clone(&before_the_lock);
            move || before_the_lock.is_reached()
        })
        .await;
        let (_, forgotten) = forgetting(&pool, early, 2);
        heard("the forget returns", forgotten).await;
        before_the_lock.release();
        assert!(
            !heard("the dial ends", dialled).await,
            "the dial that began before the forget is refused when it asks for the lock after it"
        );
        assert!(!table_holds(&pool, &early).await);
        assert!(pool.relay_urls().await.is_empty());
        pool.close().await;
    }

    /// The overlap of a new pairing with a stale dial of the old one keeps the new pairing's entry,
    /// in both orders. (a) The new pairing introduced the host first and the old pairing's dial,
    /// begun before its forget, introduces it again: when the forget returns the host is still in
    /// the table and the map, and the host goes when the new pairing is forgotten too. (b) The
    /// new pairing's dial waits behind the old pairing's forget and introduces the host after it: its
    /// entry is there when the dial returns.
    #[tokio::test]
    async fn a_new_pairing_keeps_its_hosts_entry_beside_a_stale_dial_of_the_old_pairing() {
        let pool = loopback_pool();
        let own = "https://127.0.0.1:10";
        let config = network(&[own], Some(RESOLVER), &[]);

        // (a) The new pairing (2) first, the old pairing's (1) stale dial and its forget after.
        let host = key();
        pool.endpoint(&config, &host, Standing::Paired(pairing(2)))
            .await
            .expect("the new pairing is reached");
        let gate = Arc::new(pool.hold_next_introduce_of(&host));
        let (_, dialled) = dialling(&pool, &config, host, 1);
        until("the stale dial is held at the gate", {
            let gate = Arc::clone(&gate);
            move || gate.is_reached()
        })
        .await;
        let (_, forgotten) = forgetting(&pool, host, 1);
        until("the forget has marked the old pairing", {
            let pool = Arc::clone(&pool);
            move || pool.is_forgotten(pairing(1))
        })
        .await;
        gate.release();
        assert!(
            heard("the stale dial ends", dialled).await,
            "the dial that began before the forget returns its endpoint"
        );
        heard("the forget returns", forgotten).await;
        assert!(
            table_holds(&pool, &host).await,
            "the new pairing's entry is in the table when the forget returns"
        );
        assert_eq!(
            pool.relay_urls().await,
            BTreeSet::from([relay(own)]),
            "the new pairing's relay is in the map when the forget returns"
        );
        pool.forget(&host, pairing(2)).await;
        assert!(
            !table_holds(&pool, &host).await && pool.relay_urls().await.is_empty(),
            "the host goes when the last pairing that introduced it is forgotten"
        );

        // (b) The old pairing (3) is forgotten with its removal held, and the new pairing (4)
        // dials meanwhile.
        let host = key();
        pool.endpoint(&config, &host, Standing::Paired(pairing(3)))
            .await
            .expect("the old pairing is reached");
        let mut removal = the_bound(&pool).await.endpoint.hold_next_map_task();
        let (_, forgotten) = forgetting(&pool, host, 3);
        removal.reached().await;
        let (_, dialled) = dialling(&pool, &config, host, 4);
        until("the new pairing's dial waits for the host's lock", {
            let lock = pool.lock_of(&host);
            move || Arc::strong_count(&lock) >= 4
        })
        .await;
        removal.release().await;
        heard("the forget returns", forgotten).await;
        assert!(
            heard("the new pairing's dial ends", dialled).await,
            "the new pairing is reached"
        );
        assert!(
            table_holds(&pool, &host).await,
            "the new pairing's entry is in the table when its dial returns"
        );
        assert_eq!(
            pool.relay_urls().await,
            BTreeSet::from([relay(own)]),
            "the new pairing's relay is in the map when its dial returns"
        );
        pool.close().await;
    }

    /// The pool's lock is not held while a host is introduced: with one host's change of the relay
    /// map held at the transport's gate, the lock is free and a dial of a host the endpoint already
    /// knows returns.
    #[tokio::test]
    async fn a_dial_of_a_known_host_returns_while_another_host_is_introduced() {
        let pool = Arc::new(
            EndpointPool::new(TransportIdentityKeyPair::generate().expect("a key"))
                .bound_to(loopback()),
        );
        let host = || {
            *TransportIdentityKeyPair::generate()
                .expect("a key")
                .public()
        };
        let (known, other) = (host(), host());
        let shared = "https://127.0.0.1:9";
        let known_config = network(&[shared], None, &[]);
        pool.endpoint(&known_config, &known, Standing::Paired(pairing(1)))
            .await
            .expect("the first host is introduced");
        let device = pool
            .device
            .lock()
            .await
            .clone()
            .expect("the endpoint is bound");
        let mut hold = device.endpoint.hold_next_map_task();
        let introducing = tokio::spawn({
            let pool = Arc::clone(&pool);
            async move {
                pool.endpoint(
                    &network(&[shared, "https://127.0.0.1:10"], None, &[]),
                    &other,
                    Standing::Paired(pairing(2)),
                )
                .await
                .map(|_| ())
            }
        });
        hold.reached().await;

        assert!(
            pool.device.try_lock().is_ok(),
            "the pool's lock is free while a host's relays are being put into the map"
        );
        let (done, finished) = std::sync::mpsc::channel();
        tokio::spawn({
            let pool = Arc::clone(&pool);
            async move {
                let reached = pool
                    .endpoint(&known_config, &known, Standing::Paired(pairing(1)))
                    .await
                    .is_ok();
                let _ = done.send(reached);
            }
        });
        let returned = tokio::task::spawn_blocking(move || {
            finished.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await
        .expect("the wait ran");
        assert_eq!(
            returned,
            Ok(true),
            "a dial of a known host returns while another host is being introduced"
        );
        hold.release().await;
        introducing
            .await
            .expect("the introduction ran")
            .expect("the second host is introduced");
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
