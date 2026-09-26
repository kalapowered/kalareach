//! The daemon on the network.
//!
//! One call puts a host on the network, and this module is the host's half of it:
//!
//! ```text
//!   kr_transport::listener::register(config, identity, transport_key, handler)
//!                                                                      |
//!                                             NetworkHost  -----------+
//!                                              |        |        |
//!                        the device directory --+        |        +-- the pairing surface
//!                        (which endpoints are paired)    |            (what an unpaired
//!                                                        |             connection reaches)
//!                                     the authorised connection
//!                                     (dispatch.rs, proxy.rs)
//! ```
//!
//! # What the host owes the transport, and where each obligation is kept
//!
//! **Admission is atomic with registration, and the registration stays revocable.** The handshake
//! re-reads the paired record as late as it can, but a revocation that lands between that check and
//! the first protected read is the host's to fence. [`NetworkHost::admit`] therefore reads the
//! device record and writes the connection into the daemon's authority store in one critical
//! section, in the lock order a revocation also takes, so nothing can be admitted against authority
//! that has already been replaced. The registration is the daemon's own, shared with its local
//! callers, so one revocation fences both ingresses; and every read, subscription and dispatch
//! checks it, which is what makes it revocable for the life of the session rather than only at the
//! handshake.
//!
//! **Work that must complete is owned by something that outlives the connection.**
//! `HostHandler::serve` is dropped when the control stream ends, and dropping a future is a
//! cancellation. So a mutation's effect runs on its own task, and the release of what a connection
//! owned at the worker runs on another, after the handler has gone.
//!
//! # What a paired device is, and is not
//!
//! It is an actor with a grant. Its ingress is `paired_device`, which the authority table uses to
//! keep private-IPC methods unreachable from the network; its principal is derived from the device
//! identity this host assigned, so `(actor_id, action_id)` names one device's action; and its
//! dispatch to a worker needs a live lease from the current generation and revision, renewed only
//! after the worker has acknowledged that revision. Local input and stopping owned execution never
//! depend on that lease, because neither is remote dispatch.

pub mod config;
pub mod devices;
pub mod dispatch;
pub mod invitations;
pub mod lifetimes;
pub mod methods;
pub mod owner;
pub mod pairing;
pub mod proxy;
pub mod rendezvous;
pub mod rendezvous_https;

use std::sync::{Arc, Weak};

use kr_crypto::connect::PairedPeer;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::{SecretStore, StoreSelection};
use kr_pairing::host::HostIdentity;
use kr_protocol::ids::{ActorId, AuthorityRevision, ConnectionId, DeviceId, DeviceKeyRevision};
use kr_protocol::pairing::NetworkConfig;
use kr_protocol::scalars::EndpointKey;
use kr_transport::clock::ContinuousInstant;
use kr_transport::handshake::{HostEpochs, LocalIdentity, PairedDirectory};
use kr_transport::listener::{AuthorisedSession, BoxFuture, HostHandler, ListenerConfig};
use kr_transport::preauth::PairingSurface;
use kr_transport::window::AcceptedDeadline;

use crate::directory::KnownWorker;
use crate::error::{ControllerError, Result};
use crate::service::{AdmittedConnection, Controller};
use config::NetworkSettings;
use devices::{DeviceDirectory, DeviceRecord};
use dispatch::RemoteConnection;
use pairing::{HostPairingClock, PairingHost};
use proxy::{RELAY_DEPTH, RelayBudget, Relayed, WorkerProxy};

/// The scope this host's own network device keys are stored under.
///
/// Separate from the environment's controller identity, which signs generation tokens to its own
/// workers. These are the keys a *peer* authenticates: the transport key iroh proves and the
/// authorisation key the `kr-connect/1` transcript is signed with. One key set per purpose is the
/// rule the whole build follows, and conflating these two would make a worker's view of its daemon
/// and a device's view of its host the same secret.
#[must_use]
pub fn device_key_scope(environment_id: kr_protocol::ids::EnvironmentId) -> String {
    format!("{environment_id}/network-device")
}

/// How long the daemon waits for one worker to install an authority revision.
///
/// A worker holds its dispatch barrier for the length of one effect, so an announcement can
/// legitimately wait. What it must not do is wait for ever: a paused session would otherwise hold
/// up a device attaching to a different one.
pub const ACKNOWLEDGEMENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Everything a daemon needs to put itself on the network.
pub struct NetworkSetup {
    /// The services this host's configuration selected.
    pub settings: NetworkSettings,
    /// Where this host's own network device keys live.
    pub secrets: Arc<dyn SecretStore>,
    /// The rendezvous service short-code invitations are offered through. A host without one
    /// offers direct invitations and answers a code invitation with `RENDEZVOUS_CONFIG_ERROR`.
    pub rendezvous: Option<Arc<dyn rendezvous::Rendezvous>>,
}

impl std::fmt::Debug for NetworkSetup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkSetup")
            .field("settings", &self.settings)
            .field("secrets", &self.secrets.describe())
            .field("rendezvous", &self.rendezvous.is_some())
            .finish()
    }
}

impl NetworkSetup {
    /// Builds the setup a configuration document's network section selects.
    ///
    /// Returns `None` when the section does not put this host on the network. The selection is
    /// the document's alone ([`NetworkSettings::from_selection`]), and nothing here is read from
    /// this process's environment: the owner is recorded by the pairing that establishes it.
    ///
    /// Under [`StoreSelection::Platform`] the key store is the platform's own credential store
    /// where there is one, and the documented owner-only directory where there is not; the
    /// fallback is taken deliberately rather than discovered at the first write. Under
    /// [`StoreSelection::File`] it is the directory this environment keeps its secrets in, which
    /// is what a test, a bench or a demonstration run is given so that its keys leave with it.
    ///
    /// # Errors
    ///
    /// Returns a configuration error naming the selection or the store that could not be read.
    pub fn from_configuration(
        network: &kr_protocol::hostinfo::configuration::NetworkSelection,
        paths: &kr_ipc::paths::EnvironmentPaths,
        selection: StoreSelection,
    ) -> Result<Option<Self>> {
        let Some(settings) = NetworkSettings::from_selection(network)? else {
            return Ok(None);
        };
        let secrets: Arc<dyn SecretStore> = match selection {
            StoreSelection::Platform => match kr_crypto::store::PlatformStore::open(
                kr_ipc::verify::CONTROLLER_SECRET_SERVICE,
            ) {
                Ok(store) => Arc::new(store),
                Err(platform) => Arc::new(
                    kr_crypto::store::FileStore::open(paths.secrets_dir()).map_err(|file| {
                        ControllerError::NotConfigured(format!(
                            "this host has nowhere to keep its network keys: {platform}; {file}"
                        ))
                    })?,
                ),
            },
            StoreSelection::File => Arc::from(
                kr_crypto::store::open_store_in(&paths.secrets_dir())
                    .map_err(|error| {
                        ControllerError::NotConfigured(format!(
                            "this run has nowhere to keep its network keys: {error}"
                        ))
                    })?
                    .store,
            ),
        };
        // A host whose platform cannot verify a service's certificate offers no code invitation,
        // and says so when one is asked for. The rendezvous goes through the proxy the endpoint
        // goes through, the one this document selects, or none.
        let rendezvous =
            rendezvous_https::HttpsRendezvous::new(settings.endpoint.proxy_url.clone())
                .ok()
                .map(|service| Arc::new(service) as Arc<dyn rendezvous::Rendezvous>);
        Ok(Some(Self {
            settings,
            secrets,
            rendezvous,
        }))
    }
}

/// What a daemon owns while it is on the network.
///
/// The accept loop holds the handler, so anything the handler owned would be kept alive by the
/// loop itself and nothing would ever stop either. This is the other side of that: the listener
/// and the host's own tasks live here, outside the handler, and go when the last holder of this
/// goes. The host is reachable through it, because a revocation needs the host and the daemon
/// reaches it through this.
#[derive(Debug)]
pub struct NetworkGuard {
    host: Arc<NetworkHost>,
    /// The listener serving this host, once it is accepting.
    ///
    /// The guard is recorded on the daemon before the listener exists, because a revocation has to
    /// be able to reach a connection from the moment one can be admitted. Dropping a listener
    /// stops it accepting; a shutdown also closes its endpoint, which is the orderly end.
    listener: std::sync::Mutex<Option<kr_transport::listener::NetworkListener>>,
    /// The tasks this host runs for itself, rather than for one connection.
    tasks: std::sync::Mutex<Vec<tokio::task::AbortHandle>>,
}

impl NetworkGuard {
    /// Returns the host's pairing service.
    #[must_use]
    pub fn pairing(&self) -> &Arc<PairingHost> {
        &self.host.pairing
    }

    /// Returns the configuration a pairing invitation carries, with this endpoint's current hints.
    ///
    /// The selected services are this host's own configuration. The direct addresses are the ones
    /// this endpoint reports for itself now ([`Self::direct_addresses`]), taken as they stand,
    /// because that is all a hint ever is.
    ///
    /// # Errors
    ///
    /// Returns an error when a selected service cannot be expressed as a network hint.
    pub fn network_config(&self) -> Result<NetworkConfig> {
        let mut config = self
            .host
            .endpoint
            .to_network_config()
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        config.direct_addresses = self
            .direct_addresses()
            .into_iter()
            .filter_map(|socket| kr_protocol::pairing::NetworkHint::new(socket.to_string()).ok())
            .take(kr_protocol::pairing::MAX_NETWORK_HINTS)
            .collect();
        Ok(config)
    }

    /// Returns the direct addresses this endpoint reports for itself, which are where a peer dials
    /// it.
    ///
    /// They are not the sockets it bound. A socket bound to the unspecified address answers on the
    /// machine's own addresses, so the endpoint names those, on the port it bound, and never the
    /// unspecified address itself: `0.0.0.0` and `[::]` name no machine a peer could reach. The
    /// endpoint finds its interface addresses when it binds, before it accepts anything, and adds
    /// an address a relay observed or a gateway mapped once it learns one. An endpoint with no IP
    /// transport, one that only relays, has none.
    pub(crate) fn direct_addresses(&self) -> Vec<std::net::SocketAddr> {
        self.listener
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|listener| listener.endpoint().addr().ip_addrs().copied().collect())
            .unwrap_or_default()
    }

    /// Returns the configuration this host's endpoint was built from: its relay map and the
    /// discovery services it publishes to and resolves from.
    pub(crate) fn endpoint(&self) -> &kr_transport::config::EndpointConfig {
        &self.host.endpoint
    }

    /// Returns the sockets this endpoint is bound to, one per IP transport.
    ///
    /// A peer dials [`Self::direct_addresses`] instead: a socket bound to the unspecified address
    /// is not an address anyone can reach.
    pub(crate) fn bound_sockets(&self) -> Vec<std::net::SocketAddr> {
        self.listener
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|listener| listener.endpoint().bound_sockets())
            .unwrap_or_default()
    }

    /// Stops accepting connections, ends this host's own tasks and closes the endpoint.
    async fn shutdown(&self) {
        self.stop_tasks();
        let listener = self
            .listener
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(listener) = listener {
            listener.shutdown().await;
        }
    }

    fn stop_tasks(&self) {
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            task.abort();
        }
    }
}

impl Drop for NetworkGuard {
    fn drop(&mut self) {
        // Whichever way this goes: a shutdown that awaited the endpoint, a registration that
        // failed after the tasks had started, or a daemon that was simply dropped. Nothing here
        // can await, and dropping the listener is what stops it accepting.
        self.stop_tasks();
    }
}

/// A daemon that is on the network.
#[derive(Debug)]
pub struct Network {
    guard: Arc<NetworkGuard>,
}

impl Network {
    /// Returns this host's endpoint identity, which is what a pairing invitation pins.
    #[must_use]
    pub fn endpoint_id(&self) -> EndpointKey {
        self.guard.host.endpoint_id
    }

    /// Returns the configuration a pairing invitation carries, with this endpoint's current hints.
    ///
    /// The selected services are this host's own configuration. The direct addresses are the ones
    /// this endpoint reports for itself now ([`Self::direct_addresses`]), taken as they stand,
    /// because that is all a hint ever is.
    ///
    /// # Errors
    ///
    /// Returns an error when a selected service cannot be expressed as a network hint.
    pub fn network_config(&self) -> Result<NetworkConfig> {
        self.guard.network_config()
    }

    /// Returns the direct addresses this endpoint reports for itself, which are where a peer dials
    /// it and what a pairing invitation hints.
    ///
    /// They are not the sockets it bound: a socket bound to the unspecified address answers on the
    /// machine's own addresses, and the endpoint names those rather than the unspecified address.
    #[must_use]
    pub fn direct_addresses(&self) -> Vec<std::net::SocketAddr> {
        self.guard.direct_addresses()
    }

    /// Returns the sockets this endpoint is bound to, one per IP transport.
    #[must_use]
    pub fn bound_sockets(&self) -> Vec<std::net::SocketAddr> {
        self.guard.bound_sockets()
    }

    /// Returns the host's pairing service.
    #[must_use]
    pub fn pairing(&self) -> &Arc<PairingHost> {
        &self.guard.host.pairing
    }

    /// Returns the device directory this host authorises connections against.
    #[must_use]
    pub fn devices(&self) -> &Arc<DeviceDirectory> {
        &self.guard.host.devices
    }

    /// Revokes one device, and reports which workers have not yet acknowledged it.
    ///
    /// A restrictive change in the order every one takes: its debt is written, its restriction
    /// (the record) takes effect, and the daemon's one barrier retires the debt. The device cannot
    /// be admitted once its record is withdrawn, and the barrier fences whatever was admitted under
    /// it before.
    ///
    /// A revocation is not complete when it is recorded. It is complete for a worker once that
    /// worker has acknowledged the revision and said what its fence did, or has been confirmed
    /// ended, which is what the returned barrier reports per worker.
    ///
    /// # Errors
    ///
    /// Returns an error when the record or the revision cannot be written.
    pub async fn revoke_device(
        &self,
        device_id: DeviceId,
    ) -> Result<kr_protocol::action::RevocationBarrier> {
        self.guard.host.revoke_device(device_id).await
    }

    /// Establishes this host's clock again, on an owner confirmation answered for exactly that.
    ///
    /// A host whose wall clock was found to have gone backwards decides no grant's expiry from it
    /// until this is called. Nothing else clears that, because nothing else is evidence about the
    /// clock.
    ///
    /// # Errors
    ///
    /// Returns `OWNER_CONFIRMATION_REQUIRED` when no owner confirmation naming the clock has been
    /// answered through the owner-confirmation methods, and an error when the record cannot be
    /// written.
    pub async fn establish_clock(&self) -> Result<()> {
        self.guard.host.establish_clock().await
    }

    /// Stops accepting connections and closes the endpoint.
    pub async fn shutdown(self) {
        self.guard.shutdown().await;
    }
}

/// What the transport calls back into.
pub struct NetworkHost {
    /// The daemon this host belongs to.
    ///
    /// Weak, because the daemon owns this listener: an owning handle here would be a cycle that
    /// kept the daemon alive for as long as its own accept loop existed. A daemon that has gone is
    /// a connection that cannot be served, which is what the refusal below says.
    controller: Weak<Controller>,
    devices: Arc<DeviceDirectory>,
    pairing: Arc<PairingHost>,
    endpoint: kr_transport::config::EndpointConfig,
    /// When each device's grant runs out, under the host time contract the owner confirmations
    /// on this host are checked under as well.
    lifetimes: Arc<lifetimes::GrantLifetimes>,
    /// Every authorised connection this host is serving.
    ///
    /// A revocation needs them: withdrawing a registration stops the next request, and a device
    /// whose record has gone must also lose the write boundary it is holding and whatever it owns
    /// at its worker. Nothing else needs them, which is why they are recorded here rather than in
    /// the daemon's own authority store.
    /// Weak, and deliberately: a connection is owned by the task serving it, and it holds this
    /// daemon. An owning handle here would make the daemon, its host and every live connection one
    /// cycle that nothing could ever drop.
    live: std::sync::Mutex<std::collections::BTreeMap<ConnectionId, Weak<RemoteConnection>>>,
    /// This host's endpoint identity, which is what a pairing invitation pins.
    endpoint_id: EndpointKey,
}

impl std::fmt::Debug for NetworkHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkHost")
            .finish_non_exhaustive()
    }
}

impl PairedDirectory for NetworkHost {
    fn paired_peer(&self, endpoint_id: &EndpointKey) -> Option<PairedPeer> {
        self.devices.paired_peer(endpoint_id)
    }
}

impl HostHandler for NetworkHost {
    fn principal_for(&self, device_id: &DeviceId) -> ActorId {
        kr_transport::listener::device_principal(device_id)
    }

    fn pairing_surface(&self) -> Option<Arc<dyn PairingSurface>> {
        Some(Arc::clone(&self.pairing) as Arc<dyn PairingSurface>)
    }

    fn serve(self: Arc<Self>, session: AuthorisedSession) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            self.serve_connection(session).await;
        })
    }

    fn control_stream_lost(&self, connection_id: ConnectionId) {
        // Section 23 gives the end of the control stream a consequence: the transport revokes the
        // data streams, and stopping remote lease renewal is the host's half. Withdrawing the
        // registration is what does it here, because a lease is renewed only for a connection the
        // authority store still holds.
        if let Some(controller) = self.controller.upgrade() {
            tokio::spawn(async move {
                controller.deregister(connection_id);
            });
        }
    }
}

impl NetworkHost {
    /// Validates the caller's record and registers the connection in one step.
    ///
    /// The two have to be one step. Validating first and registering afterwards leaves a gap in
    /// which authority can be withdrawn, and a connection registered in that gap would pass every
    /// later check. The registry lock is taken first and the connection table second, which is the
    /// order a revocation uses, so neither can interleave with the other.
    async fn admit(&self, session: &AuthorisedSession) -> Result<DeviceRecord> {
        let controller = self.daemon()?;
        let registry = controller.registry.lock().await;
        let admitted_revision = registry.authority_revision()?;
        // The final validation the transport's contract names. The handshake checked the record
        // when it selected it; this checks it where the registration is written, and it checks the
        // device the handshake actually proved rather than one the peer named.
        let record = self
            .devices
            .record_for_endpoint(&session.peer_endpoint_id)?
            .filter(DeviceRecord::is_paired)
            .filter(|record| record.device_id == session.peer_device_id)
            .ok_or_else(|| ControllerError::PermissionDenied {
                detail: "this device's record was withdrawn during the handshake".to_owned(),
            })?;
        // A grant issued under authority that has since been replaced is not current authority.
        // The device pairs again, or the host advances its record; it does not act on the old one.
        if record.grant.authority_revision.get() > admitted_revision.get() {
            return Err(ControllerError::PermissionDenied {
                detail: "this device's grant names an authority revision this host has not reached"
                    .to_owned(),
            });
        }
        let mut admitted = controller.admitted_table();
        admitted.insert(
            session.connection_id,
            AdmittedConnection {
                actor_id: record.principal(),
                admitted_revision,
            },
        );
        drop(admitted);
        drop(registry);
        Ok(record)
    }

    /// Serves one authorised connection until it ends.
    async fn serve_connection(self: Arc<Self>, mut session: AuthorisedSession) {
        let connection_id = session.connection_id;
        let device = match self.admit(&session).await {
            Ok(device) => device,
            Err(error) => {
                let _ = session
                    .control
                    .send(&refusal(&error.to_protocol_error()))
                    .await;
                return;
            }
        };
        let Ok(controller) = self.daemon() else {
            return;
        };
        let (notifications, relayed) = tokio::sync::mpsc::channel(RELAY_DEPTH);
        // Section 9 makes the accepted deadline the earliest of the window's expiry, receipt time
        // plus the requested lifetime and any applicable authority deadline. A grant that runs out
        // is exactly such a deadline, and it is this host's one anchor for that device.
        let grant_deadline = match self.lifetimes.deadline(&device) {
            Ok(deadline) => deadline,
            Err(error) => {
                let _ = session
                    .control
                    .send(&refusal(&error.to_protocol_error()))
                    .await;
                controller.deregister(connection_id);
                return;
            }
        };
        let remote = Arc::new(RemoteConnection::new(
            Arc::clone(&controller),
            self.records(),
            device,
            &session,
            notifications,
            grant_deadline,
        ));
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(connection_id, Arc::downgrade(&remote));
        // The guard is what releases this connection, and it does it from a destructor because
        // this future is *cancelled* rather than finished the moment the control stream ends: the
        // transport races the handler against the stream and against the connection, so the end of
        // the loop below is not a place cleanup can live.
        let mut guard = ConnectionGuard {
            host: Arc::clone(&self),
            controller: Arc::clone(&controller),
            remote: Arc::clone(&remote),
            connection_id,
            relay: None,
        };
        // The relay is its own task, because a subscription delivers whenever the session produces
        // output and the request loop below is usually waiting for the device rather than for the
        // worker. It checks the registration and the grant before each batch it writes, which is
        // what stops a fenced connection from being served a subscription it had already started.
        let mut relay = tokio::spawn(relay_loop(relayed, Arc::clone(&remote)));
        // The guard owns the relay's abort handle, so a handler the transport drops still stops it.
        // A detached relay would hold this connection and its controller for as long as it waited.
        guard.relay = Some(relay.abort_handle());
        loop {
            tokio::select! {
                frame = session.control.recv() => {
                    let Some(frame) = frame else { break };
                    let Some(answer) = remote.answer(frame).await else {
                        break;
                    };
                    if !remote.write_answer(answer).await {
                        break;
                    }
                }
                // The relay stopping ends this connection. It stops when its link to the worker
                // went, when the authority behind it was withdrawn, or when the device fell far
                // enough behind that holding more of the session's output for it would have become
                // the worker's problem. Either way the subscription is gone, and section 8 has the
                // device reconnect and restore its state from the cursor it holds rather than go
                // on against a stream that has stopped without saying so.
                _ = &mut relay => break,
            }
        }
        relay.abort();
    }

    /// Revokes one device and fences whatever it was doing.
    ///
    /// The order is the contract: the debt, then the live fence, the record and the barrier. A
    /// failure after the fence is reported with the fence standing rather than silently leaving it
    /// undone.
    async fn revoke_device(
        &self,
        device_id: DeviceId,
    ) -> Result<kr_protocol::action::RevocationBarrier> {
        let controller = self.daemon()?;
        // The debt first, pending, so a stop after the record changes still owes a barrier.
        let debt = controller.owe_debt(
            &format!("the revocation of device {device_id}"),
            crate::service::Reach::Device(device_id),
        )?;
        // The live fence, because it is the only step that cannot fail and the only one whose
        // absence would leave a revoked device being served: its connections' write boundaries are
        // closed and what they owned at their workers is released.
        self.withdraw_device(device_id);
        // The restriction. The debt is published whether or not it landed: a barrier for a
        // revocation whose record did not change withdraws nothing more, and a failure is reported
        // with the fence standing rather than silently leaving it undone.
        let recorded = self.devices.revoke(device_id, kr_ipc::now_ms());
        let own = controller.publish_debts(&[(debt, crate::service::Reach::Device(device_id))]);
        // The barrier withdraws this device's registrations and admits every other connection at
        // the revision it advances to: nobody else's authority was withdrawn, and a local terminal
        // losing its connection because a phone was revoked would be a fence on the wrong thing.
        let barrier = controller.barrier(own).await;
        recorded?;
        controller.unbind_device(device_id);
        barrier
    }

    /// Establishes this host's clock again, on an owner's authority.
    ///
    /// Nothing a clock says about itself can do this, and neither can another decision the owner
    /// happened to make: section 9 wants qualified time evidence or an authenticated action about
    /// *this*. So it is its own operation, and it needs an approval this host's owner signed for
    /// it.
    ///
    /// # Errors
    ///
    /// Returns `OWNER_CONFIRMATION_REQUIRED` when no owner confirmation naming the clock has been
    /// answered, and an error when the record cannot be written.
    async fn establish_clock(&self) -> Result<()> {
        self.pairing.accept_clock()?;
        let established = self.lifetimes.clock_trust().establish(&self.devices)?;
        // The same word ends a boot's lost clock continuity, which the registry records for the
        // boot so a restart of this daemon in it does not lose it again.
        self.daemon()?.establish_clock_continuity(established).await
    }

    /// Returns the records a connection reads and writes, each of which outlives it.
    fn records(&self) -> devices::HostRecords {
        devices::HostRecords {
            devices: Arc::clone(&self.devices),
            pending: Arc::clone(self.lifetimes.pending_expiry()),
            clock: Arc::clone(self.lifetimes.clock_trust()),
        }
    }

    /// Returns the live connections this predicate selects, holding each one for the caller.
    ///
    /// The map holds weak handles, so an entry whose connection has already gone is skipped: its
    /// own guard removes it, and until then there is nothing there to fence.
    fn live_connections(
        &self,
        wanted: impl Fn(&RemoteConnection) -> bool,
    ) -> Vec<Arc<RemoteConnection>> {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter_map(Weak::upgrade)
            .filter(|remote| wanted(remote))
            .collect()
    }

    /// Fences every live connection whose registration has gone.
    ///
    /// A registration is what a remote connection writes under, and a revocation that withdraws
    /// one has to reach the connection itself: a frame already waiting for its peer is stopped by
    /// the connection closing rather than by the next check, and the closing is what makes the
    /// authority check a delivery barrier. A device revocation withdraws its own device's
    /// connections directly; this is for a revocation that withdrew registrations without naming
    /// the devices holding them.
    async fn fence_withdrawn(&self) {
        for remote in self.live_connections(|_| true) {
            if remote.is_authorised().await {
                continue;
            }
            remote.output().withdraw();
            // Releasing the worker link waits for a socket, so it belongs to a task rather than
            // to the caller of a revocation.
            tokio::spawn(async move {
                remote.release().await;
            });
        }
    }

    /// Withdraws every live connection of one device.
    ///
    /// Withdrawing the registration stops the next request; this stops the writes and releases
    /// what the connection owned at its worker, which is what a revoked device's attachment and
    /// input lease would otherwise keep holding.
    fn withdraw_device(&self, device_id: DeviceId) {
        for remote in self.live_connections(|remote| remote.device_id() == device_id) {
            remote.output().withdraw();
            // Releasing the worker link waits for a socket, so it belongs to a task rather than to
            // the critical section a revocation is holding.
            tokio::spawn(async move {
                remote.release().await;
            });
        }
    }

    fn daemon(&self) -> Result<Arc<Controller>> {
        self.controller
            .upgrade()
            .ok_or_else(|| ControllerError::NotConfigured("this daemon has stopped".to_owned()))
    }
}

/// The time the bounded offline validity has spent, kept on the continuous clock.
///
/// Taken when the policy that holds the bound is restored, accepted or synchronised, never when a
/// device first asks: how long had passed since the synchronisation the bound is measured from, at
/// an instant on the continuous clock. Only a different synchronisation replaces it. A change to
/// the maximum keeps the time already spent, so a shorter bound never ends later than the one it
/// replaces, and a wall clock wound back gives none of it back.
///
/// The time is written down per synchronisation ([`devices::StoredOfflineAnchor`]): when the
/// anchor is taken, when a decision finds the bound run out, and by the network's record task at
/// every mark. A daemon restarted in the same boot adds the boot clock's time since the record; one
/// started in a new boot keeps the recorded time and can add only what UTC shows.
///
/// It is refusal evidence and nothing else. The time is measured from readings taken after the
/// continuous instant it is attributed to, so it can only run out early; that is right for a
/// refusal, and it is why a lapse found here is never taken as a reading of UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OfflineAnchor {
    /// The synchronisation the bound is measured from, in UTC milliseconds.
    synchronised_at_ms: u64,
    /// The instant the time below was measured at, on the continuous clock.
    at: ContinuousInstant,
    /// How long had passed since the synchronisation at that instant.
    elapsed_ms: u64,
}

impl OfflineAnchor {
    /// The synchronisation the bound is measured from, in UTC milliseconds.
    pub(crate) const fn synchronised_at_ms(&self) -> u64 {
        self.synchronised_at_ms
    }

    /// When a bound of `maximum_offline_ms` measured with this anchor runs out: the first instant
    /// outside it. `None` when that is beyond what the clock can represent.
    fn until(&self, maximum_offline_ms: u64) -> Option<ContinuousInstant> {
        let outside_ms = maximum_offline_ms.checked_add(1)?;
        self.at.checked_add(std::time::Duration::from_millis(
            outside_ms.saturating_sub(self.elapsed_ms),
        ))
    }

    /// How long has passed since the synchronisation at `now`.
    fn elapsed_at(&self, now: ContinuousInstant) -> u64 {
        let since =
            u64::try_from(now.saturating_duration_since(self.at).as_millis()).unwrap_or(u64::MAX);
        self.elapsed_ms.saturating_add(since)
    }
}

/// Publishes the bounded offline validity in its cell ([`crate::grants::policy::BoundCell`]), as
/// `offline` and the anchor this daemon holds state it: its UTC end from the synchronisation, and
/// its continuous end from the anchor taken for that synchronisation.
///
/// A bound that has synchronised with no anchor for that synchronisation is shown ended, because
/// nothing shows it holding, and one that has never synchronised is outside its bound from the
/// moment it is chosen. With no bound chosen, the cell states no end. Called under the host
/// policy's lock, with the anchor the policy is measured from.
pub(crate) fn publish_offline_bound(
    cell: &crate::grants::policy::BoundCell,
    offline: Option<&kr_protocol::sharing::OfflineValidityPolicy>,
    anchor: Option<OfflineAnchor>,
) {
    use crate::grants::policy::BoundIdentity;

    let Some(offline) = offline else {
        cell.publish(
            BoundIdentity::Offline {
                synchronised_at_ms: None,
            },
            None,
            None,
            false,
        );
        return;
    };
    let synchronised_at_ms = offline.last_synchronised_at_ms.as_ref().map(|at| at.get());
    let utc_end = crate::grants::policy::offline_utc_end(offline);
    let identity = BoundIdentity::Offline { synchronised_at_ms };
    match (synchronised_at_ms, anchor) {
        (Some(at), Some(anchor)) if anchor.synchronised_at_ms == at => cell.publish(
            identity,
            anchor.until(offline.maximum_offline_ms.get()),
            utc_end,
            false,
        ),
        _ => cell.publish(identity, None, utc_end, true),
    }
}

/// Where an offline anchor's readings come from, and where it is written down.
pub(crate) struct AnchorSources<'a> {
    /// The suspend-aware continuous clock the bound runs on.
    pub clock: &'a dyn kr_transport::clock::ContinuousClock,
    /// The boot clock the record is written in.
    pub boot_clock: &'a dyn kr_ipc::clock::SharedClock,
    /// The wall clock, in UTC milliseconds.
    pub wall_clock: &'a dyn Fn() -> u64,
    /// The boot this host is running in.
    pub boot: &'a kr_protocol::identity::BootIdentity,
    /// Where the record is kept.
    pub devices: &'a DeviceDirectory,
    /// This host's clock floor, which the wall clock's reading raises.
    pub floor: &'a crate::grants::policy::UtcFloor,
}

impl AnchorSources<'_> {
    /// Writes down the time `anchor` has spent by now.
    ///
    /// The boot clock is read before the continuous clock, so the time recorded is never short at
    /// the boot-clock reading it is recorded against.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be written.
    fn record(&self, anchor: &OfflineAnchor) -> Result<()> {
        let anchored_boot_ms = self.boot_clock.boot_elapsed_ms();
        let elapsed_ms = anchor.elapsed_at(self.clock.now());
        self.devices.record_offline_anchor(
            self.boot,
            &devices::StoredOfflineAnchor {
                synchronised_at_ms: anchor.synchronised_at_ms,
                anchored_boot_ms,
                elapsed_ms,
            },
        )
    }
}

/// Returns the anchor `offline` is measured with, when the policy that holds it has just been
/// restored, accepted or synchronised.
///
/// `held` is the anchor in force, and it is kept when `offline` is measured from the
/// synchronisation it was taken for, whatever else changed. Otherwise a new one is taken and
/// written down. The time already spent is the later of what this host's reading of UTC says and
/// what this host recorded for the same synchronisation: the recorded time, advanced by the boot
/// clock since when it was recorded in this boot. Neither can shorten what the other found. The
/// reading of UTC raises the floor like any other reading, and the continuous clock is read first,
/// so the time measured after it is never short at that instant. `None` when there is no bound,
/// or one that has never synchronised, which UTC alone keeps outside itself.
///
/// # Errors
///
/// Returns an error when the record cannot be read or written. A bound whose time this host
/// cannot keep is not one it accepts.
pub(crate) fn offline_anchor(
    offline: Option<&kr_protocol::sharing::OfflineValidityPolicy>,
    held: Option<OfflineAnchor>,
    sources: &AnchorSources<'_>,
) -> Result<Option<OfflineAnchor>> {
    let Some(synchronised_at_ms) = offline
        .and_then(|offline| offline.last_synchronised_at_ms.as_ref())
        .map(|at| at.get())
    else {
        return Ok(None);
    };
    if let Some(held) = held.filter(|held| held.synchronised_at_ms == synchronised_at_ms) {
        return Ok(Some(held));
    }
    let at = sources.clock.now();
    let at_boot_ms = sources.boot_clock.boot_elapsed_ms();
    let by_utc = sources
        .floor
        .observe((sources.wall_clock)())
        .saturating_sub(synchronised_at_ms);
    let by_record = sources
        .devices
        .offline_anchor_for(synchronised_at_ms, sources.boot)?
        .map_or(0, |(recorded, this_boot)| {
            if this_boot {
                recorded
                    .elapsed_ms
                    .saturating_add(at_boot_ms.saturating_sub(recorded.anchored_boot_ms))
            } else {
                recorded.elapsed_ms
            }
        });
    let anchor = OfflineAnchor {
        synchronised_at_ms,
        at,
        elapsed_ms: by_utc.max(by_record),
    };
    sources.devices.record_offline_anchor(
        sources.boot,
        &devices::StoredOfflineAnchor {
            synchronised_at_ms,
            anchored_boot_ms: at_boot_ms,
            elapsed_ms: anchor.elapsed_ms,
        },
    )?;
    Ok(Some(anchor))
}

/// A paired device's request, as this host decided it.
///
/// The time bounds it was decided under travel inside it, each as the snapshot the decision loaded
/// with its cell: the membership lease ([`crate::grants::Permitted::lease`]) and the bounded offline
/// validity ([`crate::grants::Permitted::offline`]).
#[derive(Clone, Debug)]
pub(crate) struct DeviceDecision {
    /// The decision itself.
    pub decided: crate::config::ceilings::Decided,
}

impl DeviceDecision {
    /// Every time bound the decision was taken under besides the grant's own, each as the
    /// snapshot it loaded, with its cell.
    pub(crate) fn bounds(&self) -> Vec<crate::grants::policy::HeldBound> {
        let permitted = &self.decided.permitted;
        permitted
            .lease
            .iter()
            .chain(permitted.offline.iter())
            .cloned()
            .collect()
    }
}

/// How often this host writes down what its wall clock reads.
///
/// It bounds how much real time can pass unrecorded, which is how far a clock can be stepped
/// backwards without this host noticing.
pub const CLOCK_MARK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Keeps this host's records of the wall clock and of expiry moving while it is on the network.
///
/// Four things it owns rather than a connection: the mark that says time has passed, the
/// tombstones a connection observed but could not write, the clock floor a refusal stood on when
/// its write failed, and the time the offline bound has spent. Each has to outlive the connection
/// that noticed it, and none can wait for the next device to arrive.
async fn keep_the_record(
    controller: Weak<Controller>,
    devices: Arc<DeviceDirectory>,
    pending: Arc<devices::PendingExpiry>,
    clock: Arc<devices::ClockTrust>,
) {
    loop {
        tokio::time::sleep(CLOCK_MARK_INTERVAL).await;
        // A clock stepped backwards is the same fact whoever sees it. This task sees it between
        // connections, which is exactly when nothing else would, and it observes through the same
        // boundary every other reader and writer of that decision takes.
        if let Err(error) = clock.observe(&devices) {
            eprintln!("kr-controller: could not record the moment this host is at: {error}");
        }
        // Whatever the decision holds is written down until the write lands. A decision this host
        // has made about its own clock has to survive its own restart.
        if let Err(error) = clock.settle(&devices) {
            eprintln!(
                "kr-controller: could not record that this host's clock went backwards: {error}"
            );
        }
        pending.settle(&devices);
        if let Some(controller) = controller.upgrade() {
            controller.keep_offline_time();
            controller.settle_floor();
            // The stored grants' ends this host found and could not write yet.
            controller
                .lifetimes()
                .settle_stored(controller.sharing().grants());
        }
    }
}

/// What a remote close settled as.
#[derive(Debug)]
pub(crate) struct ClosedRemotely {
    /// The close result.
    pub value: kr_protocol::envelope::ParamsValue,
    /// Whether the worker answered from an action it had already performed.
    pub retained: bool,
}

/// How long a close's link is held for the acceptance to reach the device that asked for it.
///
/// It bounds a hold, not the close: the close itself has already happened. A device that has gone
/// releases the link at once, because the thing that would have told this that the acceptance
/// arrived goes with the connection.
pub const CLOSE_DELIVERY: std::time::Duration = std::time::Duration::from_secs(10);

/// Relays one connection's subscribed notifications, while it is still authorised to receive them.
async fn relay_loop(
    mut relayed: tokio::sync::mpsc::Receiver<Relayed>,
    remote: Arc<RemoteConnection>,
) {
    loop {
        let item = tokio::select! {
            item = relayed.recv() => match item {
                Some(item) => item,
                None => return,
            },
            // The link to the worker has gone, so the subscription this was relaying has gone
            // with it. Ending here ends the connection, and the device restores its state on the
            // next one from the cursor it holds.
            () = remote.link_lost() => return,
        };
        // Decided before it is written, like the request that opened the subscription: the grant,
        // the policy and the ceiling as they stand now. The registration, the grant and that
        // decision are then read inside the write boundary itself, and watched for as long as the
        // write waits, so a revocation or a change of policy that lands while this frame is queued
        // stops it there. A batch they no longer allow is not written, and the connection goes
        // with it. The item holds its charge against the connection's queue until it has been
        // written or dropped.
        //
        // The write is raced against the link it is relaying, because a device that has stopped
        // consuming output would otherwise hold this frame, and the connection, for as long as it
        // liked: the link ending while a frame waits for the peer has to end the connection too.
        let written = tokio::select! {
            written = remote.relay(item.frame()) => written,
            () = remote.link_lost() => false,
        };
        if !written {
            remote.output().withdraw();
            remote.release().await;
            return;
        }
        drop(item);
    }
}

/// Releases one connection when its handler goes, however it went.
///
/// The transport races a handler against the control stream and against the connection, so the
/// handler's future is dropped rather than finished in the ordinary case. A destructor is the one
/// place that runs either way.
struct ConnectionGuard {
    host: Arc<NetworkHost>,
    controller: Arc<Controller>,
    remote: Arc<RemoteConnection>,
    connection_id: ConnectionId,
    relay: Option<tokio::task::AbortHandle>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(relay) = self.relay.take() {
            relay.abort();
        }
        self.host
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.connection_id);
        let remote = Arc::clone(&self.remote);
        let controller = Arc::clone(&self.controller);
        let connection_id = self.connection_id;
        // Releasing the worker link and withdrawing the registration both have to complete, and
        // neither can run in a destructor, so they run on a task that outlives the connection.
        tokio::spawn(async move {
            remote.release().await;
            controller.deregister(connection_id);
        });
    }
}

fn refusal(error: &kr_protocol::error::ProtocolError) -> kr_protocol::envelope::ControlFrame {
    kr_protocol::envelope::ControlFrame::Response(kr_protocol::envelope::Response {
        request_id: kr_protocol::ids::RequestId::new(0),
        outcome: kr_protocol::envelope::Outcome::Error(error.clone()),
    })
}

/// Puts a daemon on the network.
///
/// The listener is registered once, after the daemon has recovered its reservations and rebuilt
/// its worker directory: a paired device must not reach a host that does not yet know what it is
/// running.
///
/// # Errors
///
/// Returns a configuration failure, a key-store failure or a bind failure. Once it returns, the
/// endpoint is accepting.
pub async fn register(controller: &Arc<Controller>, setup: NetworkSetup) -> Result<Network> {
    let environment_id = controller.paths().environment_id();
    let keys = host_device_keys(setup.secrets.as_ref(), environment_id)?;
    let devices = Arc::new(DeviceDirectory::open(
        controller.paths().registry_database(),
    )?);
    invitations::prepare(&devices)?;
    // The daemon's one record of every grant's lifetime, read by the connections this host admits
    // and by the owner confirmations it spends, on the daemon's own clocks.
    let lifetimes = Arc::clone(controller.lifetimes());
    let rows = invitations::InvitationRows::new(Arc::clone(&devices), Arc::clone(&lifetimes));
    // Section 10: a host restart cancels every invitation it left unfinished, because a
    // candidate's attempt lived only in memory and nothing can resume it. What an invitation
    // consumed, and how many failed confirmations it had spent, stays on record. This runs before
    // the listener serves anything, so no candidate can reach an invitation from before the
    // restart.
    kr_pairing::host::cancel_unfinished_invitations(&rows)
        .map_err(|error| invitations::from_store_failure(&error))?;
    // The host's own device identity is derived from its environment, so it is the same identity
    // across restarts without anything else having to be stored beside the keys.
    let device_id = DeviceId::new(environment_id.get());
    let endpoint_id = *keys.transport.public();
    let identity = Arc::new(LocalIdentity::new(
        device_id,
        DeviceKeyRevision::new(1),
        endpoint_id,
        keys.authorisation.clone(),
        controller.build_id.clone(),
    ));
    // Every host on the network serves pairing. Whether it has an owner yet is the owner
    // record's to say, and a host without one serves exactly the first-owner ceremony.
    let pairing = PairingHost::new(
        HostIdentity {
            device_id,
            endpoint_id,
            keys: keys.public_keys(),
            device_key_revision: DeviceKeyRevision::new(1),
            network_config: NetworkConfig::empty(),
        },
        keys.authorisation.clone(),
        HostPairingClock::new(&controller.boot_identity),
        rows,
        setup.rendezvous.clone(),
    );
    let host = Arc::new(NetworkHost {
        controller: Arc::downgrade(controller),
        devices,
        pairing,
        endpoint: setup.settings.endpoint.clone(),
        lifetimes,
        live: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        endpoint_id,
    });
    // The record of the wall clock moves while this host runs, whether or not anything asks it a
    // question. A mark that only advanced when a device connected would stand still through a
    // quiet night, and a clock stepped back to where it stood then would look perfectly ordinary:
    // a grant that ran out while nothing was watching would come back. This is what makes the
    // mark evidence of time having passed rather than of connections having arrived.
    let marking = tokio::spawn(keep_the_record(
        Arc::downgrade(controller),
        Arc::clone(&host.devices),
        Arc::clone(host.lifetimes.pending_expiry()),
        Arc::clone(host.lifetimes.clock_trust()),
    ));
    // The guard owns that task from here, so every way out of this function ends it: a duplicate
    // registration, an endpoint that will not bind, or a daemon that is dropped.
    let guard = Arc::new(NetworkGuard {
        host: Arc::clone(&host),
        listener: std::sync::Mutex::new(None),
        tasks: std::sync::Mutex::new(vec![marking.abort_handle()]),
    });
    // Before the listener serves anything. The daemon reaches these connections through this
    // handle when it withdraws their registrations, and a connection admitted before the handle
    // was there would be one a revocation could not fence. A daemon is a singleton, so it is set
    // once and never replaced: a second listener on one environment's identity is a mistake, not a
    // configuration.
    if controller.network.set(Arc::clone(&guard)).is_err() {
        return Err(ControllerError::NotConfigured(
            "this daemon is already on the network".to_owned(),
        ));
    }
    // The project service's location decisions are confirmed by this host's owner devices, the
    // owner every other sensitive action here is confirmed by. There is one owner, lent once, with
    // the network that holds its devices.
    controller
        .project
        .enrol_owner(Arc::new(crate::project::HostOwner::new(Arc::clone(
            &host.pairing,
        ))))?;
    // Whether the address the endpoint binds is one the configuration document chose, so a bind
    // that fails names the key that chose it rather than only the operating system's reason.
    let chosen_address = setup.settings.endpoint.bind_addr.is_some();
    let mut config = ListenerConfig::new(
        setup.settings.endpoint,
        HostEpochs {
            boot_epoch: controller.boot_epoch,
            clock_epoch: kr_protocol::ids::ClockEpoch::new(1),
        },
        controller.generation,
    );
    config.send_limits = setup.settings.send_limits;
    config.preauth_limits = setup.settings.preauth_limits;
    let listener = kr_transport::listener::register_with_clock(
        config,
        identity,
        &keys.transport,
        Arc::clone(&host),
        // The daemon's own clock, not a second one. Deadlines from the transport's action windows
        // are compared with deadlines the daemon decided: two clocks would make those comparisons
        // meaningless rather than merely imprecise.
        Arc::clone(&controller.clock),
    )
    .await
    .map_err(|error| match error {
        kr_transport::TransportError::Bind(reason) if chosen_address => {
            ControllerError::InvalidArgument(format!(
                "{} in this host's configuration document ({}) could not be bound: {reason}",
                kr_protocol::hostinfo::configuration::NETWORK_BIND_ADDRESS.key,
                kr_protocol::hostinfo::configuration::FILE_NAME,
            ))
        }
        kr_transport::TransportError::Configuration {
            kind: "bind address",
            reason,
            ..
        } => ControllerError::InvalidArgument(format!(
            "{} in this host's configuration document ({}) is not usable: {reason}",
            kr_protocol::hostinfo::configuration::NETWORK_BIND_ADDRESS.key,
            kr_protocol::hostinfo::configuration::FILE_NAME,
        )),
        other => ControllerError::NotConfigured(other.to_string()),
    })?;
    *guard
        .listener
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(listener);
    Ok(Network { guard })
}

/// Loads this host's network device keys, creating them on a genuine first start.
///
/// A host that lost these keys is a host every paired device would refuse to connect to, because
/// its endpoint identity is what an invitation pinned. So they are created once and loaded
/// afterwards, and a store that has them already is never given a fresh set.
pub(crate) fn host_device_keys(
    store: &dyn SecretStore,
    environment_id: kr_protocol::ids::EnvironmentId,
) -> Result<DeviceKeys> {
    let scope = device_key_scope(environment_id);
    if let Some(keys) =
        kr_crypto::store::load_device_keys(store, &scope).map_err(ControllerError::registry)?
    {
        return Ok(keys);
    }
    let keys = DeviceKeys::generate().map_err(ControllerError::registry)?;
    kr_crypto::store::store_device_keys(store, &scope, &keys).map_err(ControllerError::registry)?;
    Ok(keys)
}

impl Controller {
    /// Returns a remote connection's own link to the worker that owns one session.
    ///
    /// # Errors
    ///
    /// Returns an error when the session has no live worker, or when the worker refuses the link.
    pub(crate) async fn open_proxy(
        self: &Arc<Self>,
        session_id: kr_protocol::ids::SessionId,
        notifications: tokio::sync::mpsc::Sender<Relayed>,
        budget: Arc<RelayBudget>,
        lost: Arc<tokio::sync::Notify>,
    ) -> Result<Arc<WorkerProxy>> {
        // A worker that has started answering since the last attempt rejoins the directory here,
        // so a device can attach to a session the daemon had not reached at startup.
        if self.directory.lock().await.get(session_id).is_none() {
            let _ = self.recover_workers().await;
        }
        let worker: KnownWorker = self
            .directory
            .lock()
            .await
            .get(session_id)
            .cloned()
            .ok_or_else(|| ControllerError::UnknownSession {
                session: session_id.to_string(),
            })?;
        let proxy = WorkerProxy::open(self, &worker, notifications, budget, lost).await?;
        // A dispatch lease is renewed only after the worker has acknowledged the authority
        // revision in force, and a worker starts having acknowledged nothing. Asking *this* worker
        // for its acknowledgement is what makes the first remote dispatch to it possible; asking
        // every worker would make one paused session everybody's wait.
        let _ = self.acknowledge_worker_revision(session_id).await;
        Ok(proxy)
    }

    /// Fences every network connection whose registration a revocation has withdrawn.
    ///
    /// Called where registrations are withdrawn without the devices holding them being named.
    /// A host with no network has none to fence.
    pub(crate) async fn fence_network_connections(&self) {
        if let Some(guard) = self.network.get() {
            guard.host.fence_withdrawn().await;
        }
    }

    /// Closes one session over a link opened for the close, and settles what it answered.
    ///
    /// A remote close takes the journey every other remote mutation takes: a bounded link of its
    /// own, opened with a timeout and closed after the exchange, rather than the shared connection
    /// this host announces authority revisions on. A worker that stopped answering a close would
    /// otherwise hold that connection for as long as it liked, and the close is dispatched from a
    /// task that outlives the connection that asked for it.
    ///
    /// `answer` receives what the close settled as: the session is unknown, the link cannot be
    /// opened, the exchange does not complete inside the proxy's bound, or the worker refuses or
    /// accepts. `delivered` is how this learns that the acceptance reached the device, which is
    /// the moment the link may be released: section 7 has the worker hold the session's
    /// termination until its acceptance has been delivered, and closing this link is what says it
    /// has. A device that disconnects, or a hold that runs out, releases it too.
    pub(crate) async fn close_remote_session(
        self: &Arc<Self>,
        mutation: &kr_protocol::envelope::MutationRequest,
        vouched: proxy::Vouched<'_>,
        accepted: AcceptedDeadline,
        observer: &dispatch::ExpiryObserver,
        answer: tokio::sync::oneshot::Sender<Result<ClosedRemotely>>,
        delivered: tokio::sync::oneshot::Receiver<()>,
    ) {
        let mut link = None;
        let mut retained = false;
        let settled = self
            .close_through(
                mutation,
                vouched,
                accepted,
                observer,
                &mut link,
                &mut retained,
            )
            .await
            .map(|value| ClosedRemotely { value, retained });
        // A closure this host has accepted and not finished is a request outstanding, and section
        // 3's setting decides whether that keeps the machine awake while it finishes. The local
        // close reviews the setting where it accepts, and a close that arrived over the network is
        // the same outstanding work: without this, a remote close on a host whose owner enabled
        // inhibition would release an assertion it never took, and the machine could sleep part
        // way through a closure. The device's own answer does not wait for the review.
        self.review_power_soon();
        let _ = answer.send(settled);
        if let Some(proxy) = link {
            let _ = tokio::time::timeout(CLOSE_DELIVERY, delivered).await;
            proxy.close();
        }
    }

    /// The close itself. `link` receives the link it opened, whichever way the close ended.
    async fn close_through(
        self: &Arc<Self>,
        mutation: &kr_protocol::envelope::MutationRequest,
        vouched: proxy::Vouched<'_>,
        accepted: AcceptedDeadline,
        observer: &dispatch::ExpiryObserver,
        link: &mut Option<Arc<WorkerProxy>>,
        retained: &mut bool,
    ) -> Result<kr_protocol::envelope::ParamsValue> {
        let params: kr_protocol::session::SessionCloseParams =
            crate::service::parse(&mutation.params)?;
        let session_id = params.session_id;
        if self.directory.lock().await.get(session_id).is_none() {
            // Nothing is running under that identity. Either it has already closed, and the record
            // is the answer, or it never existed here.
            let closure = self.registry.lock().await.closure(session_id)?;
            // Whatever comes back here comes from a record rather than from a close performed now,
            // which is the same read the worker's own journal would have been. The caller decides
            // whether this device may be told it.
            *retained = true;
            return match closure {
                Some(closure) => {
                    crate::service::encode(&kr_protocol::session::SessionCloseResult {
                        session_id,
                        state: kr_protocol::session::SessionState::Closed,
                        durability: closure.durability,
                        closure: kr_protocol::scalars::Nullable::some(closure),
                    })
                }
                None => Err(ControllerError::UnknownSession {
                    session: session_id.to_string(),
                }),
            };
        }
        // The accepted deadline as it stands, and no dispatch lease behind it. Section 9 asks for
        // a live lease before a *remote dispatch*, and it exempts stopping owned execution from
        // that: a device may always stop what it is authorised to stop, and a worker that has not
        // acknowledged a revision yet is not a reason to refuse it. What still decides is the
        // worker's own check of current authority when the close arrives.
        let deadline = crate::service::remaining_deadline(
            &*self.shared_clock,
            &*self.clock,
            accepted.deadline,
            None,
        )
        .ok_or_else(|| {
            // This task outlives the connection that asked for the close, so it can be the one
            // that finds the grant's own deadline spent. Section 9 has that written down wherever
            // it is observed, and the observer here belongs to the device rather than to the
            // connection. It records nothing unless the grant itself has run out.
            observer.grant_expired();
            ControllerError::WindowExpired {
                detail: "the deadline this close was admitted under has passed".to_owned(),
            }
        })?;
        // The link is this close's own, and it is released whichever way the exchange ends.
        let (notifications, _unread) = tokio::sync::mpsc::channel(1);
        let proxy = self
            .open_proxy(
                session_id,
                notifications,
                Arc::new(RelayBudget::new(0)),
                Arc::new(tokio::sync::Notify::new()),
            )
            .await?;
        *link = Some(Arc::clone(&proxy));
        let answered = proxy.forward_mutation(mutation, vouched, deadline).await?;
        // Whether this came from the worker's journal rather than from a close it performed now.
        // The connection that asked decides whether it may be told a retained result; the close
        // itself happened either way, which is what section 7 asks of a stop.
        *retained = answered.retained;
        let value = match answered.response.outcome {
            kr_protocol::envelope::Outcome::Ok(value) => value,
            // The worker's own code, carried through rather than flattened. A reused action
            // identifier is `ID_CONFLICT` and expired authority is `PERMISSION_DENIED`, and
            // section 9 gives the caller something to do with each of them.
            kr_protocol::envelope::Outcome::Error(error) => {
                return Err(ControllerError::refused(&error));
            }
        };
        if *retained {
            // The close this answers happened, and whatever settled it settled then: the record
            // was written and the closure watched by the submission that performed it. What comes
            // back now is that action's retained answer, which may be its result or its receipt,
            // and it is passed through as it is rather than read as a close result it need not be.
            return Ok(value);
        }
        let reply: kr_protocol::session::SessionCloseResult = value
            .to_typed()
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        match reply.closure.as_ref() {
            Some(record) => self.retire(record).await?,
            // The worker has accepted the close and is stopping its processes.
            None => self.close_accepted(session_id).await,
        }
        crate::service::encode(&reply)
    }

    /// Asks one worker to install this environment's authority revision.
    ///
    /// A revocation is complete for a worker once that worker has acknowledged the revision that
    /// removed the authority, or is confirmed ended; and a dispatch lease is renewed only after
    /// that acknowledgement. This is the one-worker form of both: it announces over the authority
    /// connection, records what the worker installed, and lifts the lease's fence under the same
    /// binding the announcement travelled on.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read or written, or when the worker is not in
    /// the directory.
    pub(crate) async fn acknowledge_worker_revision(
        self: &Arc<Self>,
        session_id: kr_protocol::ids::SessionId,
    ) -> Result<()> {
        let revision = self.registry.lock().await.authority_revision()?;
        let worker = self
            .directory
            .lock()
            .await
            .get(session_id)
            .cloned()
            .ok_or_else(|| ControllerError::UnknownSession {
                session: session_id.to_string(),
            })?;
        // The binding is taken before the announcement travels, so an acknowledgement that arrives
        // over a control path this daemon has already given up on lifts nothing.
        let binding = self.leases.binding(session_id);
        // The bound covers the whole exchange, including waiting for this worker's connection:
        // another operation may be holding it, and a wait that only started once it was free would
        // not be a bound at all.
        let exchange = async {
            let mut held = self.worker_client(&worker).await?;
            // The connection is taken out of the shared slot for the exchange and put back only
            // when it finished. A cancelled exchange — this one running out of time — would
            // otherwise leave a connection in the slot with an acknowledgement still on the wire,
            // and the next caller would read somebody else's answer as its own.
            let mut client = held.take().expect("the connection is open");
            let answered = client
                .announce_revision(kr_protocol::worker::AuthorityRevisionNotice {
                    environment_id: self.paths().environment_id(),
                    revision,
                    // The first page of whatever its fence named: this worker has said nothing
                    // about this revocation yet, so there is nothing to continue from.
                    evidence_from: 0,
                })
                .await;
            match answered {
                Ok(ack) => {
                    *held = Some(client);
                    Ok(Some(ack))
                }
                Err(error) => Err(ControllerError::from(error)),
            }
        };
        let answered = match tokio::time::timeout(ACKNOWLEDGEMENT_TIMEOUT, exchange).await {
            Ok(Ok(answered)) => answered,
            // A worker that did not answer, or that could not be reached, has not installed the
            // revision. Renewal stops for it until it does.
            Ok(Err(_)) | Err(_) => {
                self.leases.stop_renewal(session_id, binding);
                None
            }
        };
        match answered {
            Some(ack) if ack.revision.get() >= revision.get() => {
                // What its fence rejected and could not take back travels with the
                // acknowledgement, because section 9 makes the acknowledgement two statements. A
                // worker that said nothing about its fence has made one of them, and the barrier
                // reports it as pending for exactly that reason.
                let evidenced = ack.fence.is_some();
                let accepted =
                    self.leases
                        .acknowledge(session_id, binding, ack.revision, ack.fence);
                if accepted && evidenced {
                    self.registry
                        .lock()
                        .await
                        .record_acknowledged_revision(session_id, ack.revision)?;
                    // The names travel a page at a time, and this announcement carried the first
                    // one. The rest of what this worker owes, for this revocation and for any
                    // older one whose pages never finished arriving, is collected here as it is
                    // after the announcement every worker gets.
                    self.collect_owed_evidence(session_id, binding, revision)
                        .await;
                }
                Ok(())
            }
            _ => {
                // A worker that is confirmed gone answers the question a different way: it can no
                // longer act under anything.
                if self.reconcile(session_id).await?.is_some() {
                    self.leases.worker_ended(session_id);
                }
                Err(ControllerError::supervision(
                    "this session's worker has not installed the environment's authority revision",
                ))
            }
        }
    }

    /// Returns the deadline a forwarded mutation carries, bounded by the dispatch lease.
    ///
    /// Section 9 requires a live worker-held authority lease from the current controller generation
    /// and revision for remote dispatch, taken at the moment the dispatch runs rather than one that
    /// was valid when the request arrived. The lease's own remaining time then bounds the deadline
    /// the worker is given, and the result is on the machine's own continuous clock, which is the
    /// clock the worker reads.
    ///
    /// This is the last thing this host decides before the mutation is forwarded, so the admission
    /// it was accepted under is asked here, after the lease: the connection and the revision it
    /// was admitted at are the ones `actor` carries.
    ///
    /// # Errors
    ///
    /// Returns an error when no lease can be taken, when the admission no longer stands, or when
    /// the accepted deadline has already passed: a spent deadline is never forwarded as though it
    /// had time left.
    pub(crate) async fn forwarded_deadline(
        self: &Arc<Self>,
        session_id: kr_protocol::ids::SessionId,
        actor: &kr_protocol::actor::ActorEnvelope,
        accepted: AcceptedDeadline,
    ) -> Result<kr_protocol::scalars::U64> {
        let lease: Option<ContinuousInstant> = match self.dispatch_lease(session_id, actor).await {
            Ok(lease) => lease,
            // A worker that has not installed the revision in force has no lease to renew. Asking
            // it once, here, is what lets a dispatch to a worker this daemon has not spoken to
            // about authority succeed rather than fail on a condition the daemon itself can meet.
            Err(refused) => {
                self.acknowledge_worker_revision(session_id).await?;
                let _ = refused;
                self.dispatch_lease(session_id, actor).await?
            }
        };
        // Taking the lease can wait for the worker to acknowledge the revision, and the mutation
        // waited for its link before that. The check every service asks from inside its work is
        // asked after those waits: a fence this host owes and could not raise leaves the revision
        // and the lease where they were, so only this refuses the forward while it is owed; a
        // registration withdrawn or replaced meanwhile, and a deadline that has passed, refuse it
        // as well. A worker already holding a forwarded mutation decides it under its own lease.
        let admitted_revision =
            actor
                .grant_revision
                .0
                .ok_or_else(|| ControllerError::PermissionDenied {
                    detail: "this request carries no authority revision it was admitted at"
                        .to_owned(),
                })?;
        self.check_registration(&crate::authority::AdmittedMutation {
            connection_id: actor.connection_id,
            admitted_revision,
            deadline: Some(accepted.deadline),
        })?;
        crate::service::remaining_deadline(
            &*self.shared_clock,
            &*self.clock,
            accepted.deadline,
            lease,
        )
        .ok_or_else(|| ControllerError::WindowExpired {
            detail: "the deadline this action was admitted under has passed".to_owned(),
        })
    }

    /// Decides one paired device's request through the one intersection: its grant, this host's
    /// policy and the rights ceiling this host's configuration put in force.
    ///
    /// [`crate::config::ceilings::decide_with_ceiling`] is the whole of the arithmetic; this only
    /// supplies what the daemon holds. The policy is decided against in place, so the clock floor
    /// the decision raises holds for every decision after it while the daemon runs. A refusal the
    /// clock decided is also owed the floor's record, because that is what a clock wound back
    /// before the next start could otherwise revive; a permission needs no record of its own,
    /// since a later reading can only find the same grant expired sooner. A record still owed from
    /// an earlier refusal is written by whichever decision comes next.
    ///
    /// The bounded offline validity is held on the continuous clock as well as in UTC, by the
    /// anchor taken when the policy holding it was restored, accepted or synchronised
    /// ([`offline_anchor`]). A decision that finds the anchor passed refuses, whatever a wall clock
    /// wound back since then says, and writes the time spent down, so the refusal stands after a
    /// restart or a reboot. The floor is left as the readings of UTC made it.
    ///
    /// # Errors
    ///
    /// Returns the refusal, naming the right when this host's configuration removed one the
    /// method needs.
    pub(crate) fn decide_for_device(
        &self,
        grant: &kr_protocol::grant::Grant,
        record: &crate::grants::GrantRecord,
        request: crate::grants::AccessRequest,
    ) -> std::result::Result<DeviceDecision, crate::config::ceilings::CeilingRefusal> {
        let ceiling = self
            .rights_ceiling
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut policy = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A floor still owed its record is written before anything is decided on it, whoever owed
        // it: an earlier refusal here, or a worker of this host whose copy's deadline passed at a
        // reading nothing had written down. The decision then stands on the record rather than
        // being refused for it.
        self.write_owed_floor(&policy);
        let decided = crate::config::ceilings::decide_with_ceiling(
            ceiling.as_ref(),
            grant,
            record,
            &mut policy,
            request,
        );
        // The offline bound the decision loaded, held to its continuous end as well: the one clock
        // that cannot be wound back. Run out there, it is refused, and the time it spent is written
        // down so the refusal stands after a restart or a reboot.
        let decided = match decided {
            Ok(decided)
                if decided.permitted.offline.as_ref().is_some_and(|offline| {
                    offline
                        .snapshot()
                        .ended_on_the_continuous_clock(self.clock.now())
                }) =>
            {
                self.write_offline_time(&policy);
                Err(crate::config::ceilings::CeilingRefusal::Refused(
                    crate::grants::Refusal::OfflineValidityLapsed {
                        last_synchronised_at_ms: policy
                            .offline_validity()
                            .and_then(|offline| offline.last_synchronised_at_ms.as_ref())
                            .map(|at| at.get()),
                    },
                ))
            }
            decided => decided.map(|decided| DeviceDecision { decided }),
        };
        if matches!(
            &decided,
            Err(crate::config::ceilings::CeilingRefusal::Refused(refusal))
                if refusal.is_clock_decided()
        ) {
            // A refusal the clock decided (an expiry, a lapsed offline bound, a lapsed lease) is
            // answered only once the floor it stood on is on disk,
            // as a workflow's is: before that, a clock wound back before the next start would
            // decide the other way, so the answer states no lapse. An expiry found here still
            // stops the connection's frames, which records nothing ([`Refusal::ExpiryUnrecorded`]).
            let floor = policy.utc_floor_ms();
            self.owe_floor(&policy);
            if self.utc_floor.written() < floor {
                return Err(crate::config::ceilings::CeilingRefusal::Refused(
                    match decided {
                        Err(crate::config::ceilings::CeilingRefusal::Refused(
                            crate::grants::Refusal::Expired { expired_at_ms },
                        )) => crate::grants::Refusal::ExpiryUnrecorded { expired_at_ms },
                        _ => crate::grants::Refusal::FloorUnrecorded,
                    },
                ));
            }
        }
        decided
    }

    /// The readings and the record an offline anchor on this daemon is taken from.
    pub(crate) fn anchor_sources(&self) -> AnchorSources<'_> {
        AnchorSources {
            clock: &*self.clock,
            boot_clock: &*self.shared_clock,
            wall_clock: &*self.wall,
            boot: &self.boot_identity,
            devices: &self.devices,
            floor: &self.utc_floor,
        }
    }

    /// Writes down the time the offline bound has spent by now, with the policy's lock held.
    ///
    /// A write that fails leaves the record owed, and the next step that settles the clock floor
    /// writes it; meanwhile this daemon's anchor still holds the time.
    pub(crate) fn write_offline_time(
        &self,
        _policy: &std::sync::MutexGuard<'_, crate::grants::HostPolicy>,
    ) {
        self.offline_time_owed
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let anchor = *self
            .offline_anchor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(anchor) = anchor else {
            return;
        };
        if let Err(error) = self.anchor_sources().record(&anchor) {
            self.offline_time_owed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            eprintln!(
                "kr-controller: could not record the time the offline bound has spent: {error}"
            );
        }
    }

    /// Records that the offline bound was found run out where nothing may wait, a poll among
    /// them, so the next step that settles the clock floor writes the time spent down.
    pub(crate) fn owe_offline_time(&self) {
        self.offline_time_owed
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Writes down the time the offline bound has spent, as the network's record task does at
    /// every mark.
    ///
    /// It bounds how much of the bound's time a reboot can take away, the way the clock mark
    /// bounds how far a clock can be stepped back unnoticed: a new boot keeps what was recorded,
    /// and adds only what UTC shows.
    pub(crate) fn keep_offline_time(&self) {
        let policy = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if policy.offline_validity().is_some() {
            self.write_offline_time(&policy);
        }
    }

    /// Returns the authority revision this environment is at.
    ///
    /// A grant is issued at the revision in force when it is written, and the host intersects it
    /// with current policy on every request, so whoever issues one asks for this rather than
    /// assuming it.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    pub async fn authority_revision(&self) -> Result<AuthorityRevision> {
        self.registry.lock().await.authority_revision()
    }

    /// Returns what this daemon owns of its network, when its environment selected one.
    #[must_use]
    pub fn network_guard(&self) -> Option<&Arc<NetworkGuard>> {
        self.network.get()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use kr_protocol::actor::ActorIngress;
    use kr_protocol::grant::{
        EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector,
    };
    use kr_protocol::ids::{AuthorityRevision, BuildId, DeviceId, GrantId};
    use kr_protocol::method::Method;
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};

    use crate::config::ceilings::CeilingRefusal;
    use crate::grants::{AccessRequest, GrantRecord, Refusal};
    use crate::service::{Controller, ControllerSetup};
    use crate::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};

    /// A supervisor that starts nothing. Deciding a request needs no worker.
    #[derive(Debug)]
    struct NoWorkers;

    impl WorkerSupervisor for NoWorkers {
        fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
            LaunchOutcome::NotStarted {
                detail: "this test starts no workers".to_owned(),
            }
        }

        fn describe(&self) -> &'static str {
            "a supervisor that starts nothing"
        }
    }

    /// Starts a daemon on an environment that may already hold an earlier daemon's records.
    pub(crate) async fn daemon(temp: &kr_ipc::testing::TempHost) -> Arc<Controller> {
        daemon_in(
            temp,
            kr_ipc::identity::boot_identity().expect("a boot identity"),
        )
        .await
    }

    /// Starts a daemon as [`daemon`] does, in the boot `boot_identity` names.
    async fn daemon_in(
        temp: &kr_ipc::testing::TempHost,
        boot_identity: kr_protocol::identity::BootIdentity,
    ) -> Arc<Controller> {
        started(|| Controller::start(setup(temp, boot_identity.clone()))).await
    }

    /// Starts a daemon as [`daemon`] does, on clocks this test moves by hand.
    pub(super) async fn daemon_on(
        temp: &kr_ipc::testing::TempHost,
        clocks: crate::service::Clocks,
    ) -> Arc<Controller> {
        started(|| {
            Controller::start_on_clocks(
                setup(
                    temp,
                    kr_ipc::identity::boot_identity().expect("a boot identity"),
                ),
                clocks.clone(),
            )
        })
        .await
    }

    /// How long a daemon is given to take over an environment a daemon before it held.
    ///
    /// A daemon lets go of its environment once nothing of it is left, and its own tasks can still
    /// hold it for a moment after the test has let it go: one asking its registry a question, or
    /// reading its clocks. A replacement started at once can therefore find the environment held.
    /// That is a liveness condition: what these tests assert is that the replacement takes the
    /// environment over, not how soon the last reference goes.
    const ENVIRONMENT_HANDOVER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

    /// Starts a daemon with `start`, and again while a daemon this test let go still holds the
    /// environment, until [`ENVIRONMENT_HANDOVER_DEADLINE`]. Any other failure fails the test.
    pub(crate) async fn started<F, S>(start: F) -> Arc<Controller>
    where
        F: Fn() -> S,
        S: std::future::Future<Output = crate::error::Result<Arc<Controller>>>,
    {
        let begun = std::time::Instant::now();
        loop {
            match start().await {
                Ok(controller) => return controller,
                Err(crate::error::ControllerError::AlreadyRunning { .. })
                    if begun.elapsed() < ENVIRONMENT_HANDOVER_DEADLINE => {}
                Err(error) => panic!("the daemon starts: {error}"),
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// Clocks this test moves by hand: a continuous clock, and a wall clock that reads what the
    /// test last set, from the machine's reading now. A bound on either passes only when the test
    /// moves it, however long the runner takes between two steps.
    pub(super) fn manual_clocks() -> (
        kr_transport::clock::ManualClock,
        Arc<std::sync::atomic::AtomicU64>,
        crate::service::Clocks,
    ) {
        let continuous = kr_transport::clock::ManualClock::new();
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(kr_ipc::now_ms().get()));
        let clocks = crate::service::Clocks {
            continuous: Arc::new(continuous.clone()),
            wall: {
                let wall = Arc::clone(&wall);
                crate::service::WallClock::from_fn(move || {
                    wall.load(std::sync::atomic::Ordering::SeqCst)
                })
            },
        };
        (continuous, wall, clocks)
    }

    /// What a test daemon is started with, in the boot `boot_identity` names.
    pub(crate) fn setup(
        temp: &kr_ipc::testing::TempHost,
        boot_identity: kr_protocol::identity::BootIdentity,
    ) -> ControllerSetup {
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let secrets = environment.secrets_dir();
        ControllerSetup {
            paths: environment,
            environment_id,
            identity: Box::new(move || {
                let store = kr_crypto::store::open_store_in(&secrets)
                    .expect("a secret store for the test environment");
                Ok(kr_ipc::verify::ControllerIdentity::open(
                    store.store.as_ref(),
                    environment_id,
                    false,
                )
                .expect("an identity"))
            }),
            secret_store: kr_crypto::store::StoreSelection::File,
            boot_identity,
            supervisor: Box::new(NoWorkers),
            worker_program: temp.root().join("kr-worker"),
            build_id: BuildId::new("kr-test/0").expect("a build identifier"),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(crate::supervision::NoTerminal),
        }
    }

    /// A redeemed grant to one device, carrying viewing.
    pub(super) fn granted(
        expiry: GrantExpiry,
        authority_revision: AuthorityRevision,
    ) -> (Grant, GrantRecord) {
        let device_id = DeviceId::new(kr_ipc::new_uuid());
        let grant = Grant {
            grant_id: GrantId::new(kr_ipc::new_uuid()),
            parent_grant_id: Nullable::null(),
            issuer_device_id: device_id,
            recipient_device_id: device_id,
            authority_revision,
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: [ActionRight::SessionView].into_iter().collect(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: false,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry,
            organisation: Nullable::null(),
        };
        let record = GrantRecord {
            grant: grant.clone(),
            session_id: None,
            issued_at_ms: 1,
            activated_at_ms: Some(1),
            revoked_at_ms: None,
            revoked_by_parent: None,
        };
        (grant, record)
    }

    /// A paired device's session listing, read against the wall clock as it says `now_ms`.
    pub(super) fn listing(temp: &kr_ipc::testing::TempHost, now_ms: u64) -> AccessRequest {
        AccessRequest {
            method: Method::SessionList,
            ingress: ActorIngress::PairedDevice,
            environment_id: temp.environment_id(),
            session_id: None,
            claims_geometry: false,
            own_subject: None,
            now_ms,
            continuous_now: kr_transport::clock::ContinuousClock::now(
                &kr_transport::clock::SystemContinuousClock::new(),
            ),
        }
    }

    /// Makes every write of the host's policy fail from here, as it would on a full disk.
    fn refuse_policy_writes(temp: &kr_ipc::testing::TempHost) -> rusqlite::Connection {
        let registry = rusqlite::Connection::open(temp.environment().registry_database())
            .expect("opens the registry");
        registry
            .busy_timeout(std::time::Duration::from_secs(5))
            .expect("waits for the daemon's writes");
        registry
            .execute_batch(
                "CREATE TRIGGER refuse_policy BEFORE INSERT ON host_authority
                 WHEN NEW.key = 'policy'
                 BEGIN SELECT RAISE(ABORT, 'no room'); END;",
            )
            .expect("the fault is in place");
        registry
    }

    /// Lets the host's policy be written again.
    fn allow_policy_writes(registry: &rusqlite::Connection) {
        registry
            .execute_batch("DROP TRIGGER refuse_policy;")
            .expect("the fault is cleared");
    }

    /// The clock floor this environment has written down.
    pub(super) fn written_floor(controller: &Controller) -> u64 {
        controller
            .sharing()
            .grants()
            .stored_policy()
            .expect("reads the policy")
            .expect("the host has written its policy")
            .utc_floor_ms
            .get()
    }

    /// A refusal the clock decided outlives a failed write of its floor: the next decision writes
    /// the floor as soon as storage takes it, permission or not, and a daemon started afterwards
    /// with its clock wound back still refuses the grant. While the floor is not on disk the
    /// device is not told of an expiry, which a clock wound back before the next start would
    /// reverse: the answer is that the floor is unrecorded. Once it is on disk, the expiry is
    /// answered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_clock_refusal_whose_record_failed_is_written_by_the_next_decision_and_outlives_a_restart()
     {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        let revision = controller.policy().authority_revision();
        let now = kr_ipc::now_ms().get();
        let expires = now + 60 * 60 * 1000;
        let (expiring, expiring_record) = granted(
            GrantExpiry::At {
                expires_at_ms: TimestampMs::new(expires),
            },
            revision,
        );
        let (lasting, lasting_record) = granted(GrantExpiry::Never, revision);
        controller
            .decide_for_device(&expiring, &expiring_record, listing(&temp, now))
            .expect("the grant stands before it expires");

        // From here every write of the host's policy fails, as it would on a full disk.
        let registry = refuse_policy_writes(&temp);

        // The wall clock steps past the expiry. The grant is refused, and the floor it was refused
        // on cannot be written.
        let refused = controller
            .decide_for_device(&expiring, &expiring_record, listing(&temp, expires + 1))
            .expect_err("the grant has run out by this reading");
        assert!(
            matches!(
                refused,
                CeilingRefusal::Refused(Refusal::ExpiryUnrecorded { .. })
            ),
            "the expiry is not answered while its floor is not on disk: {refused:?}"
        );
        assert_eq!(
            refused.to_protocol_error().code,
            kr_protocol::error::ErrorCode::StorageUnavailable
        );
        assert!(written_floor(&controller) < expires, "the write failed");
        // The clock is wound back. The floor in memory still refuses, and its write still fails.
        controller
            .decide_for_device(&expiring, &expiring_record, listing(&temp, now))
            .expect_err("a clock wound back does not revive the grant while this daemon runs");

        // Storage recovers. The next decision is a permission for another grant, which owes no
        // record of its own, and it writes the floor the refusal stood on before it answers.
        allow_policy_writes(&registry);
        controller
            .decide_for_device(&lasting, &lasting_record, listing(&temp, now))
            .expect("a grant that does not expire is served");
        assert!(
            written_floor(&controller) > expires,
            "the floor the refusal stood on is written down"
        );
        // The control: with the floor on disk, the expiry is answered.
        let refused = controller
            .decide_for_device(&expiring, &expiring_record, listing(&temp, now))
            .expect_err("the grant stays expired");
        assert!(
            matches!(refused, CeilingRefusal::Refused(Refusal::Expired { .. })),
            "{refused:?}"
        );

        // A daemon started afterwards, with the clock still wound back, decides from that floor.
        drop(controller);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let controller = daemon(&temp).await;
        let refused = controller
            .decide_for_device(&expiring, &expiring_record, listing(&temp, now))
            .expect_err("the refusal outlives the daemon that made it");
        assert!(
            matches!(refused, CeilingRefusal::Refused(Refusal::Expired { .. })),
            "{refused:?}"
        );
        drop(controller);
    }

    /// The clock floor this environment maps in this boot, mapped again as a worker maps it.
    fn worker_mapping(temp: &kr_ipc::testing::TempHost) -> kr_ipc::floor::SharedFloor {
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        kr_ipc::floor::SharedFloor::open(
            &temp.environment().utc_floor_file(),
            temp.environment_id(),
            kr_ipc::identity::boot_epoch(&boot).expect("a boot epoch"),
        )
        .expect("the floor is this environment's, for this boot")
    }

    /// Stops `controller` once nothing else holds it, so its environment lock is released.
    pub(in crate::service) async fn stopped(controller: Arc<Controller>) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while Arc::strong_count(&controller) > 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "the stopped daemon is still held"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        drop(controller);
    }

    /// Stops `controller` and starts the next daemon on the same environment, in this boot.
    async fn restarted(
        controller: Arc<Controller>,
        temp: &kr_ipc::testing::TempHost,
    ) -> Arc<Controller> {
        stopped(controller).await;
        daemon(temp).await
    }

    /// The host's floor is one word for the boot. A daemon's floor and a worker's mapping of it
    /// read and raise the same word; a daemon started again in the same boot keeps the file, its
    /// identity and its word, and marks nothing lost; a daemon started in another boot replaces a
    /// file of the earlier one with a new floor that starts at the host's record.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_shared_floor_is_one_word_for_the_boot() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        let worker = worker_mapping(&temp);
        let identity = worker.identity().expect("a mapped floor has an identity");
        assert_eq!(controller.utc_floor().get(), worker.load());
        let ahead = kr_ipc::now_ms().get() + 60 * 60 * 1000;
        worker.raise(ahead);
        assert_eq!(
            controller.utc_floor().get(),
            ahead,
            "a worker's reading is the daemon's floor at once"
        );
        let boot = controller.boot_epoch;
        assert_eq!(
            controller
                .registry
                .lock()
                .await
                .floors_of_boot(boot)
                .expect("readable"),
            vec![crate::registry::RecordedFloor {
                identity,
                in_force: true
            }]
        );

        // The control: ordinary reopening keeps the floor as it stands.
        let controller = restarted(controller, &temp).await;
        assert!(
            worker.named(),
            "the file was opened as it stands, not replaced"
        );
        assert_eq!(worker_mapping(&temp).identity(), Some(identity));
        assert!(controller.utc_floor().get() >= ahead, "the word is kept");
        assert!(!controller.utc_floor().continuity_lost());
        assert!(
            written_floor(&controller) >= ahead,
            "the start wrote the floor it found down"
        );

        // Another boot: the earlier boot's file is replaced by a floor that starts at the record.
        // On Unix only: on Windows a file cannot be replaced while anything maps it, and in another
        // boot nothing does.
        stopped(controller).await;
        #[cfg(unix)]
        another_boot_replaces_the_floor(&temp, &worker, identity, ahead).await;
    }

    /// Starts a daemon in another boot on `temp`, whose floor `worker` maps as `identity` with its
    /// word at `ahead`: the file is replaced by a floor that starts at the host's record.
    #[cfg(unix)]
    async fn another_boot_replaces_the_floor(
        temp: &kr_ipc::testing::TempHost,
        worker: &kr_ipc::floor::SharedFloor,
        identity: kr_ipc::floor::FloorIdentity,
        ahead: u64,
    ) {
        let later_boot = kr_protocol::identity::BootIdentity {
            source: kr_protocol::identity::BootIdentitySource::MacosBootSessionUuid,
            value: kr_protocol::scalars::Bytes::new(vec![0x5b; 16]),
        };
        let later = daemon_in(temp, later_boot.clone()).await;
        assert!(
            !worker.named(),
            "the earlier boot's file no longer has the name"
        );
        let replaced = kr_ipc::floor::SharedFloor::open(
            &temp.environment().utc_floor_file(),
            temp.environment_id(),
            kr_ipc::identity::boot_epoch(&later_boot).expect("a boot epoch"),
        )
        .expect("the later boot's floor");
        assert_ne!(replaced.identity(), Some(identity));
        assert!(
            replaced.load() >= ahead,
            "a new floor starts at the host's record"
        );
        assert!(replaced.recorded() >= ahead);
        assert!(
            !later.utc_floor().continuity_lost(),
            "a boot's first floor loses nothing"
        );
        drop(later);
    }

    /// A daemon with an expiring grant whose expiry lies an hour ahead, and a worker of the host
    /// whose own wall clock reads past that expiry: the worker publishes its reading in the floor and
    /// refuses a copy of the grant as unrecorded, since nothing written down covers the expiry. That
    /// is the order a lost floor must not undo: the durable floor below the expiry, a worker's
    /// reading past it, and nothing recorded since. Returns the daemon, the expiring grant and one
    /// that never expires, the wall clock reading the daemon decides at, and the expiry.
    async fn a_worker_passed_an_expiry(
        temp: &kr_ipc::testing::TempHost,
    ) -> (
        Arc<Controller>,
        (Grant, GrantRecord),
        (Grant, GrantRecord),
        u64,
        u64,
    ) {
        use kr_worker::action::time::{ManualWallClock, TimeContract, TimeSources, UtcDeadline};

        let controller = daemon(temp).await;
        let revision = controller.policy().authority_revision();
        let now = kr_ipc::now_ms().get();
        let expires = now + 60 * 60 * 1000;
        let expiring = granted(
            GrantExpiry::At {
                expires_at_ms: TimestampMs::new(expires),
            },
            revision,
        );
        let lasting = granted(GrantExpiry::Never, revision);
        controller
            .decide_for_device(&expiring.0, &expiring.1, listing(temp, now))
            .expect("the control: the grant stands at the daemon's own reading");
        assert!(
            written_floor(&controller) < expires,
            "the durable floor is below the expiry"
        );

        let worker = TimeContract::new(
            kr_ipc::identity::boot_identity().expect("a boot identity"),
            "",
            TimeSources {
                wall: Arc::new(ManualWallClock::new(expires + 1_000)),
                ..TimeSources::system().with_floor(Arc::new(worker_mapping(temp)))
            },
        );
        assert_eq!(
            worker.check_utc_deadline(expires),
            UtcDeadline::Unrecorded,
            "the worker refuses the copy and names no expiry"
        );
        assert!(controller.utc_floor().get() > expires);
        assert!(controller.utc_floor().is_owed());
        (controller, expiring, lasting, now, expires)
    }

    /// A floor whose file lost its name in a boot is a lost floor, not a first start. A worker had
    /// published a reading past a grant's expiry in it and refused a copy as unrecorded, and nothing
    /// written down covers that expiry. The next daemon creates a new floor at the durable floor,
    /// below the expiry, and records the boot's clock continuity as lost, so the grant is not decided
    /// again from a floor that lost that reading: every bound that can pass is refused as unproven,
    /// whatever its continuous deadline, until the owner establishes the clock, and no copy under it
    /// is cut. Authority that reads no clock is untouched. A restart in the boot keeps that state, and
    /// a lost floor moved back into place is never adopted.
    ///
    /// Unix only: on Windows every mapping holds the file open without delete sharing, so a floor
    /// loses its name only once every process of the boot has let it go, which one test process
    /// that keeps its daemon's tasks cannot arrange.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lost_floor_leaves_every_bound_unproven_until_the_owner_establishes_the_clock() {
        let temp = kr_ipc::testing::TempHost::create();
        let (controller, (expiring, expiring_record), (lasting, lasting_record), now, expires) =
            a_worker_passed_an_expiry(&temp).await;

        let path = temp.environment().utc_floor_file();
        let lost = worker_mapping(&temp);
        let kept = temp.environment().runtime_dir().join("kept");
        std::fs::hard_link(&path, &kept).expect("a link elsewhere");
        std::fs::remove_file(&path).expect("the floor's name is removed");
        assert!(!lost.named());

        let controller = restarted(controller, &temp).await;
        assert!(controller.utc_floor().continuity_lost());
        assert_ne!(worker_mapping(&temp).identity(), lost.identity());
        assert!(
            controller.utc_floor().get() < expires,
            "the new floor starts at the durable floor, below the expiry"
        );
        let refused = controller
            .decide_for_device(&expiring, &expiring_record, listing(&temp, now))
            .expect_err("nothing proves the bound, whatever the daemon's clock says");
        assert!(
            matches!(refused, CeilingRefusal::Refused(Refusal::ClockUnproven)),
            "{refused:?}"
        );
        assert_eq!(
            refused.to_protocol_error().code,
            kr_protocol::error::ErrorCode::ClockUntrusted
        );
        controller
            .decide_for_device(&lasting, &lasting_record, listing(&temp, now))
            .expect("a grant that reads no clock is served");

        // A restart in the same boot keeps the state, and so does moving the lost file back.
        let controller = restarted(controller, &temp).await;
        assert!(controller.utc_floor().continuity_lost());
        let current = worker_mapping(&temp).identity();
        stopped(controller).await;
        std::fs::rename(&kept, &path).expect("the lost file is moved back");
        let controller = daemon(&temp).await;
        let adopted = worker_mapping(&temp).identity();
        assert_ne!(adopted, lost.identity(), "a lost floor is never adopted");
        assert_ne!(adopted, current, "it is replaced by a new one");
        assert!(controller.utc_floor().continuity_lost());

        // The owner establishes the clock: the bound is decided again, and a restart in the boot
        // keeps it established.
        controller
            .establish_clock_continuity(TimestampMs::new(now))
            .await
            .expect("recorded");
        controller
            .decide_for_device(&expiring, &expiring_record, listing(&temp, now))
            .expect("the grant stands once the clock is established");
        let controller = restarted(controller, &temp).await;
        assert!(!controller.utc_floor().continuity_lost());
        controller
            .decide_for_device(&expiring, &expiring_record, listing(&temp, now))
            .expect("and it stays established in this boot");
        drop(controller);
    }

    /// The control for the lost floor: ordinary reopening. The same worker's reading past the
    /// expiry, the same unrecorded refusal, then a restart that finds the file in place. The new
    /// daemon keeps the word, writes it down as it starts, which covers what the worker owed, and
    /// refuses the grant as expired with its own clock below the expiry: nothing was lost, so
    /// nothing is unproven.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lapse_a_worker_owed_is_recorded_across_an_ordinary_restart() {
        let temp = kr_ipc::testing::TempHost::create();
        let (controller, (expiring, expiring_record), _, now, expires) =
            a_worker_passed_an_expiry(&temp).await;
        let controller = restarted(controller, &temp).await;
        assert!(!controller.utc_floor().continuity_lost());
        assert!(controller.utc_floor().get() > expires, "the word is kept");
        assert!(
            written_floor(&controller) > expires,
            "the start writes down the floor it found, which covers what the worker owed"
        );
        assert!(!controller.utc_floor().is_owed());
        let refused = controller
            .decide_for_device(&expiring, &expiring_record, listing(&temp, now))
            .expect_err("the worker's reading passed the expiry");
        assert!(
            matches!(refused, CeilingRefusal::Refused(Refusal::Expired { .. })),
            "{refused:?}"
        );
        assert!(
            written_floor(&controller) > expires,
            "the lapse is on record"
        );
        assert!(!controller.utc_floor().is_owed());
        drop(controller);
    }

    /// The daemon's floor keeps its record rule over the shared word. A worker's reading past an
    /// expiry is the daemon's floor, so the daemon refuses the grant whatever its own clock says,
    /// and answers the lapse only once the floor is written down, which it does before its next
    /// decision; a worker's owed lapse is owed here too; the file's record word says what is
    /// written; and a raise that decides no lapse owes and writes nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_shared_floor_keeps_the_record_rule_at_the_device_door() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        let worker = worker_mapping(&temp);
        let revision = controller.policy().authority_revision();
        let now = kr_ipc::now_ms().get();
        let expires = now + 60 * 60 * 1000;
        let expiry = GrantExpiry::At {
            expires_at_ms: TimestampMs::new(expires),
        };
        let (expiring, expiring_record) = granted(expiry, revision);
        let (lasting, lasting_record) = granted(GrantExpiry::Never, revision);

        // The control: a worker's raise that stays below every expiry decides no lapse, owes
        // nothing and writes nothing.
        worker.raise(now + 10 * 60 * 1000);
        controller
            .decide_for_device(&expiring, &expiring_record, listing(&temp, now))
            .expect("the grant stands");
        assert!(!controller.utc_floor().is_owed());
        assert!(written_floor(&controller) < now + 10 * 60 * 1000);

        let registry = refuse_policy_writes(&temp);
        worker.raise(expires + 1);
        assert_eq!(controller.utc_floor().get(), worker.load(), "one floor");
        let refused = controller
            .decide_for_device(&expiring, &expiring_record, listing(&temp, now))
            .expect_err("the worker's reading passed the expiry");
        assert!(
            matches!(
                refused,
                CeilingRefusal::Refused(Refusal::ExpiryUnrecorded { .. })
            ),
            "{refused:?}"
        );
        assert!(written_floor(&controller) < expires);
        let effect = controller
            .sharing()
            .grants()
            .bound_passed(expiry, now)
            .expect_err("an effect under the grant is not decided either");
        assert_eq!(
            effect.to_protocol_error().code,
            kr_protocol::error::ErrorCode::StorageUnavailable
        );

        // A worker that refused a copy on that reading owes it its record.
        worker.owe(worker.load());
        assert!(controller.utc_floor().is_owed());

        // Storage takes the write: the next decision writes the floor before it decides, and the
        // file's record word covers the expiry.
        allow_policy_writes(&registry);
        controller
            .decide_for_device(&lasting, &lasting_record, listing(&temp, now))
            .expect("a grant that does not expire is served");
        assert!(written_floor(&controller) > expires);
        assert!(worker.recorded() > expires);
        assert!(!controller.utc_floor().is_owed());
        let refused = controller
            .decide_for_device(&expiring, &expiring_record, listing(&temp, now))
            .expect_err("the grant stays expired");
        assert!(
            matches!(refused, CeilingRefusal::Refused(Refusal::Expired { .. })),
            "{refused:?}"
        );
        assert_eq!(
            controller.sharing().grants().bound_passed(expiry, now).ok(),
            Some(true)
        );
        assert_eq!(controller.utc_floor().get(), worker.load(), "one floor");
        drop(controller);
    }

    /// The cell of the lease the member device of `grant` holds in `organisation`.
    pub(super) fn member_cell(
        controller: &Controller,
        organisation: &crate::grants::organisation::testing::TestOrganisation,
        grant: &Grant,
    ) -> Arc<crate::grants::policy::BoundCell> {
        let policy = controller.policy();
        let enrolment = policy
            .enrolment(organisation.organisation_id)
            .expect("the host is enrolled");
        let binding = enrolment
            .binding(grant.recipient_device_id)
            .expect("the device is bound");
        Arc::clone(
            enrolment
                .installed(&binding.account_id, &binding.device_key)
                .expect("its lease is installed")
                .cell(),
        )
    }

    /// A lease's snapshot reaches its cell only once the policy holding it is written down: a
    /// renewal whose policy write fails leaves the cell publishing the lease before it, and one
    /// written down publishes itself through the same cell. A withdrawal of the enrolment ends the
    /// snapshot, so a reader holding the cell finds the lease ended without anything else.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lease_reaches_its_cell_only_once_its_policy_is_written_down() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        let now = kr_ipc::now_ms().get();
        let organisation =
            crate::grants::organisation::testing::TestOrganisation::new(0x23, now - 60 * 60 * 1000);
        let (grant, _) = leased_member(&controller, &organisation, now);
        let cell = member_cell(&controller, &organisation, &grant);
        let installed = cell.load();
        assert!(!installed.ended);
        let (account, key) = {
            let policy = controller.policy();
            let binding = policy
                .enrolment(organisation.organisation_id)
                .and_then(|enrolment| enrolment.binding(grant.recipient_device_id).cloned())
                .expect("bound");
            (binding.account_id, binding.device_key)
        };
        let renew = |issued: u64| {
            let lease = organisation.lease(&account, key, issued, &[ActionRight::SessionView]);
            controller.update_policy(|policy| {
                policy.install_lease(crate::grants::organisation::LeasePresentation {
                    lease: &lease,
                    device_id: grant.recipient_device_id,
                    proven_key: &key,
                    reading: Some(super::devices::ObservedUtc {
                        now: TimestampMs::new(issued),
                        behind_ms: 0,
                    }),
                    now: controller.clock.now(),
                    generation: controller.generation(),
                })
            })
        };

        let refusing = refuse_policy_writes(&temp);
        renew(now + 1_000).expect_err("the renewal's policy cannot be written");
        assert_eq!(
            *cell.load(),
            *installed,
            "the cell still publishes the lease before it"
        );
        allow_policy_writes(&refusing);
        renew(now + 2_000)
            .expect("written down")
            .expect("the renewal installs");
        assert!(
            Arc::ptr_eq(&member_cell(&controller, &organisation, &grant), &cell),
            "through the same cell"
        );
        let renewed = cell.load();
        assert_ne!(renewed.version, installed.version);
        assert_eq!(
            renewed.utc_deadline_ms,
            Some(now + 2_000 + kr_protocol::account::MEMBERSHIP_LEASE_MAX_LIFETIME_MS)
        );

        // A reader that decided under the renewal holds the cell; the withdrawal ends it there.
        let held = crate::grants::policy::HeldBound::load(&cell);
        controller
            .update_policy(|policy| policy.withdraw(organisation.organisation_id))
            .expect("the withdrawal is written down");
        assert!(
            cell.load().ended,
            "the withdrawal ended the lease's snapshot"
        );
        assert_eq!(
            held.stands_at(controller.clock.now(), now),
            crate::grants::policy::Stands::EndedOnTheContinuousClock
        );
        drop(controller);
    }

    /// The offline bound's cell states both of its ends: UTC from the synchronisation, and the
    /// continuous clock from the anchor taken for it. A new synchronisation publishes a new
    /// snapshot, and a daemon started again in the boot publishes the bound as its anchor was
    /// reconstructed, never ending later than before.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_offline_cell_states_both_ends_of_the_bound() {
        let temp = kr_ipc::testing::TempHost::create();
        let (_continuous, wall, clocks) = manual_clocks();
        let synchronised = wall.load(std::sync::atomic::Ordering::SeqCst);
        let controller = daemon_on(&temp, clocks.clone()).await;
        let unbounded = controller.policy().offline_cell().load();
        assert!(
            !unbounded.ended
                && unbounded.continuous_deadline.is_none()
                && unbounded.utc_deadline_ms.is_none(),
            "with no bound chosen the cell states no end"
        );

        choose_offline_bound(&controller, synchronised, 60_000);
        let bound = controller.policy().offline_cell().load();
        assert_eq!(
            bound.identity,
            crate::grants::policy::BoundIdentity::Offline {
                synchronised_at_ms: Some(synchronised)
            }
        );
        assert_eq!(bound.utc_deadline_ms, Some(synchronised + 60_001));
        assert!(
            !bound.ended && bound.continuous_deadline.is_some(),
            "anchored"
        );

        choose_offline_bound(&controller, synchronised + 500, 60_000);
        let moved = controller.policy().offline_cell().load();
        assert_ne!(
            moved.version, bound.version,
            "a synchronisation publishes anew"
        );
        assert_eq!(moved.utc_deadline_ms, Some(synchronised + 60_501));

        // A daemon started again in the boot publishes the bound as its anchor stands.
        stopped(controller).await;
        let restarted = started(|| {
            Controller::start_on_clocks(
                setup(
                    &temp,
                    kr_ipc::identity::boot_identity().expect("a boot identity"),
                ),
                clocks.clone(),
            )
        })
        .await;
        let reborn = restarted.policy().offline_cell().load();
        assert_eq!(reborn.utc_deadline_ms, Some(synchronised + 60_501));
        assert!(!reborn.ended);
        assert!(
            reborn
                .continuous_deadline
                .is_some_and(|until| until <= moved.continuous_deadline.expect("anchored")),
            "the reconstruction ends no later than the anchor it replaced"
        );
        drop(restarted);
    }

    /// Presents a renewal for the member device of `grant` in `organisation`, issued at `issued_ms`
    /// and read at the same moment, and writes the policy holding it down.
    pub(super) fn renew_member(
        controller: &Controller,
        organisation: &crate::grants::organisation::testing::TestOrganisation,
        grant: &Grant,
        issued_ms: u64,
    ) -> crate::error::Result<
        std::result::Result<
            crate::grants::organisation::LeaseInstalled,
            crate::grants::LeaseRefused,
        >,
    > {
        let binding = controller
            .policy()
            .enrolment(organisation.organisation_id)
            .and_then(|enrolment| enrolment.binding(grant.recipient_device_id).cloned())
            .expect("the device is bound");
        let lease = organisation.lease(
            &binding.account_id,
            binding.device_key,
            issued_ms,
            &[ActionRight::SessionView],
        );
        controller.update_policy(|policy| {
            policy.install_lease(crate::grants::organisation::LeasePresentation {
                lease: &lease,
                device_id: grant.recipient_device_id,
                proven_key: &binding.device_key,
                reading: Some(super::devices::ObservedUtc {
                    now: TimestampMs::new(issued_ms),
                    behind_ms: 0,
                }),
                now: controller.clock.now(),
                generation: controller.generation(),
            })
        })
    }

    /// Enrols `controller` in `organisation` at `now` and installs a lease issued then for a member
    /// on a device of its own, which binds it. Returns that device's organisation grant.
    pub(super) fn leased_member(
        controller: &Controller,
        organisation: &crate::grants::organisation::testing::TestOrganisation,
        now: u64,
    ) -> (Grant, GrantRecord) {
        let reading = super::devices::ObservedUtc {
            now: TimestampMs::new(now),
            behind_ms: 0,
        };
        let revision = controller.policy().authority_revision();
        controller
            .update_policy(|policy| {
                let verified = policy
                    .verify_enrolment(&organisation.authority(now), Some(&reading))
                    .expect("the chain verifies");
                policy.enrol(verified).expect("the host enrols");
            })
            .expect("the enrolment is written down");
        let (grant, record) = granted(GrantExpiry::Never, revision);
        let grant = Grant {
            organisation: Nullable::some(kr_protocol::grant::OrganisationRequirement {
                organisation_id: organisation.organisation_id,
                policy_revision: revision,
            }),
            ..grant
        };
        let record = GrantRecord {
            grant: grant.clone(),
            ..record
        };
        let key = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a device key");
        let account = kr_protocol::ids::AccountId::new("ada").expect("an account");
        let lease = organisation.lease(&account, *key.public(), now, &[ActionRight::SessionView]);
        controller
            .update_policy(|policy| {
                policy.install_lease(crate::grants::organisation::LeasePresentation {
                    lease: &lease,
                    device_id: grant.recipient_device_id,
                    proven_key: key.public(),
                    reading: Some(reading),
                    now: controller.clock.now(),
                    generation: controller.generation(),
                })
            })
            .expect("the lease is written down")
            .expect("the lease installs and binds the device");
        (grant, record)
    }

    /// A lease that lapsed by the wall clock is a refusal the clock decided, as a grant's expiry
    /// is: while the floor it was found on cannot be written, a paired device is told the floor is
    /// unrecorded rather than that the lease expired, which a clock wound back before the next
    /// start could reverse. Once the floor is on disk, the lapse is answered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lapsed_lease_is_answered_only_once_its_floor_is_written() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        let now = kr_ipc::now_ms().get();
        let organisation =
            crate::grants::organisation::testing::TestOrganisation::new(0x21, now - 60 * 60 * 1000);
        let (grant, record) = leased_member(&controller, &organisation, now);
        let (lasting, lasting_record) =
            granted(GrantExpiry::Never, controller.policy().authority_revision());
        controller
            .decide_for_device(&grant, &record, listing(&temp, now))
            .expect("the lease answers");

        let lapsed_at = now + crate::grants::HostPolicy::maximum_lease_lifetime_ms();
        let registry = refuse_policy_writes(&temp);
        let refused = controller
            .decide_for_device(&grant, &record, listing(&temp, lapsed_at))
            .expect_err("the lease has lapsed by this reading");
        assert!(
            matches!(refused, CeilingRefusal::Refused(Refusal::FloorUnrecorded)),
            "the lapse is not answered while its floor is not on disk: {refused:?}"
        );
        assert!(written_floor(&controller) < lapsed_at, "the write failed");

        // The control: once storage takes the floor, the lapse is answered.
        allow_policy_writes(&registry);
        controller
            .decide_for_device(&lasting, &lasting_record, listing(&temp, now))
            .expect("a grant that does not expire is served");
        assert!(written_floor(&controller) >= lapsed_at);
        let refused = controller
            .decide_for_device(&grant, &record, listing(&temp, now))
            .expect_err("the lease stays lapsed");
        assert!(
            matches!(
                refused,
                CeilingRefusal::Refused(Refusal::MembershipUnusable {
                    refusal: kr_protocol::sharing::MembershipRefusal::LeaseExpired
                })
            ),
            "{refused:?}"
        );
        drop(controller);
    }

    /// The same for a workflow's dispatch under a member device's organisation grant: while the
    /// floor a lapsed lease was found on cannot be written, authority is unavailable, and once it
    /// is written the lapse is answered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_workflow_under_a_lapsed_lease_is_answered_only_once_its_floor_is_written() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        let now = kr_ipc::now_ms().get();
        let organisation =
            crate::grants::organisation::testing::TestOrganisation::new(0x22, now - 60 * 60 * 1000);
        let (_, record) = leased_member(&controller, &organisation, now);
        controller
            .decide_for_workflow(
                &record,
                ActorIngress::PairedDevice,
                now,
                controller.clock.now(),
            )
            .expect("the lease answers");

        let lapsed_at = now + crate::grants::HostPolicy::maximum_lease_lifetime_ms();
        let registry = refuse_policy_writes(&temp);
        let refused = controller
            .decide_for_workflow(
                &record,
                ActorIngress::PairedDevice,
                lapsed_at,
                controller.clock.now(),
            )
            .expect_err("the lease has lapsed by this reading");
        assert!(
            matches!(
                refused,
                kr_automation::AutomationError::AuthorityUnavailable(_)
            ),
            "the lapse is not answered while its floor is not on disk: {refused:?}"
        );

        // The control: once storage takes the floor, the lapse is answered.
        allow_policy_writes(&registry);
        let refused = controller
            .decide_for_workflow(
                &record,
                ActorIngress::PairedDevice,
                now,
                controller.clock.now(),
            )
            .expect_err("the lease stays lapsed");
        assert!(
            matches!(refused, kr_automation::AutomationError::PermissionDenied(_)),
            "{refused:?}"
        );
        drop(controller);
    }

    /// A lapsed offline bound is decided on the clock floor as well, and has no expiry record of
    /// its own: the floor is all that keeps it lapsed across a restart. With no decision after the
    /// failed write, the network's record task writes the floor once storage takes it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lapsed_offline_bound_whose_floor_write_failed_is_written_by_the_record_task() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        let revision = controller.policy().authority_revision();
        let now = kr_ipc::now_ms().get();
        let hour = 60 * 60 * 1000;
        controller
            .update_policy(|policy| {
                policy.set_offline_validity(Some(kr_protocol::sharing::OfflineValidityPolicy {
                    maximum_offline_ms: kr_protocol::scalars::DurationMs::new(hour),
                    last_synchronised_at_ms: Nullable::some(TimestampMs::new(now)),
                }));
            })
            .expect("the owner chooses an offline bound of an hour");
        let (lasting, lasting_record) = granted(GrantExpiry::Never, revision);
        controller
            .decide_for_device(&lasting, &lasting_record, listing(&temp, now))
            .expect("inside the bound");

        let registry = refuse_policy_writes(&temp);
        let refused = controller
            .decide_for_device(&lasting, &lasting_record, listing(&temp, now + 2 * hour))
            .expect_err("the wall clock steps past the bound");
        assert!(
            matches!(refused, CeilingRefusal::Refused(Refusal::FloorUnrecorded)),
            "the lapse is not answered while its floor is not on disk: {refused:?}"
        );
        assert!(written_floor(&controller) < now + hour, "the write failed");

        // Storage recovers and nothing asks for a decision. The record task's own pass writes the
        // floor the refusal stood on.
        allow_policy_writes(&registry);
        controller.settle_floor();
        assert!(
            written_floor(&controller) >= now + 2 * hour,
            "the floor the refusal stood on is written down"
        );

        drop(controller);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let controller = daemon(&temp).await;
        let refused = controller
            .decide_for_device(&lasting, &lasting_record, listing(&temp, now))
            .expect_err("a clock wound back before the restart does not bring the bound back");
        assert!(
            matches!(
                refused,
                CeilingRefusal::Refused(Refusal::OfflineValidityLapsed { .. })
            ),
            "{refused:?}"
        );
        drop(controller);
    }

    /// The offline bound runs out on the continuous clock it was anchored on. A decision taken
    /// after the wall clock was wound back reads UTC inside the bound again, and is refused all the
    /// same; a synchronisation of the authority feed anchors the bound afresh. On clocks the test
    /// moves by hand, so no step depends on how much real time passes between two others.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_offline_bound_runs_out_on_the_clock_it_was_anchored_on() {
        let temp = kr_ipc::testing::TempHost::create();
        let (continuous, wall, clocks) = manual_clocks();
        let synchronised = wall.load(std::sync::atomic::Ordering::SeqCst);
        let controller = daemon_on(&temp, clocks).await;
        let revision = controller.policy().authority_revision();
        choose_offline_bound(&controller, synchronised, 200);
        let (lasting, lasting_record) = granted(GrantExpiry::Never, revision);
        let decision = controller
            .decide_for_device(&lasting, &lasting_record, listing(&temp, synchronised))
            .expect("inside the bound");
        assert!(
            decision
                .decided
                .permitted
                .offline
                .as_ref()
                .and_then(crate::grants::policy::HeldBound::continuous_deadline)
                .is_some(),
            "and the bound is anchored"
        );

        // The continuous clock passes the bound, and the wall clock is wound back five seconds.
        // With the floor this host holds, UTC is still inside the bound.
        continuous.advance(std::time::Duration::from_millis(300));
        wall.store(synchronised - 5_000, std::sync::atomic::Ordering::SeqCst);
        offline_lapsed(
            controller.decide_for_device(
                &lasting,
                &lasting_record,
                listing(&temp, synchronised - 5_000),
            ),
            "the bound ran out on the continuous clock",
        );

        // The control: a later reading alone anchors nothing, so the bound stays run out.
        let again = synchronised + 1_000;
        wall.store(again, std::sync::atomic::Ordering::SeqCst);
        offline_lapsed(
            controller.decide_for_device(&lasting, &lasting_record, listing(&temp, again)),
            "nothing anchored the bound afresh",
        );
        controller
            .update_policy(|policy| policy.note_feed_synchronised(again))
            .expect("the authority feed synchronises");
        controller
            .decide_for_device(&lasting, &lasting_record, listing(&temp, again))
            .expect("a synchronisation anchors the bound afresh");
        drop(controller);
    }

    /// The owner chooses an offline bound measured from `synchronised`, lasting `maximum_ms`.
    fn choose_offline_bound(controller: &Controller, synchronised: u64, maximum_ms: u64) {
        controller
            .update_policy(|policy| {
                policy.set_offline_validity(Some(kr_protocol::sharing::OfflineValidityPolicy {
                    maximum_offline_ms: kr_protocol::scalars::DurationMs::new(maximum_ms),
                    last_synchronised_at_ms: Nullable::some(TimestampMs::new(synchronised)),
                }));
            })
            .expect("the owner's choice is recorded");
    }

    /// Asserts that a decision was refused because the offline bound ran out.
    fn offline_lapsed(
        decided: std::result::Result<super::DeviceDecision, CeilingRefusal>,
        why: &str,
    ) {
        let refused = decided.expect_err(why);
        assert!(
            matches!(
                refused,
                CeilingRefusal::Refused(Refusal::OfflineValidityLapsed { .. })
            ),
            "{why}: {refused:?}"
        );
    }

    /// Makes every write of the offline bound's records fail from here, as a full disk would.
    fn refuse_offline_time_writes(temp: &kr_ipc::testing::TempHost) -> rusqlite::Connection {
        let registry = rusqlite::Connection::open(temp.environment().registry_database())
            .expect("opens the registry");
        registry
            .busy_timeout(std::time::Duration::from_secs(5))
            .expect("waits for the daemon's writes");
        registry
            .execute_batch(
                "CREATE TRIGGER refuse_offline_insert BEFORE INSERT ON network_offline_anchors
                 BEGIN SELECT RAISE(ABORT, 'no room'); END;
                 CREATE TRIGGER refuse_offline_update BEFORE UPDATE ON network_offline_anchors
                 BEGIN SELECT RAISE(ABORT, 'no room'); END;",
            )
            .expect("the fault is in place");
        registry
    }

    /// Lets the offline bound's records be written again.
    fn allow_offline_time_writes(registry: &rusqlite::Connection) {
        registry
            .execute_batch(
                "DROP TRIGGER refuse_offline_insert; DROP TRIGGER refuse_offline_update;",
            )
            .expect("the fault is cleared");
    }

    /// The time this environment has recorded the offline bound measured from `synchronised` as
    /// having spent.
    fn recorded_offline_time(controller: &Controller, synchronised: u64) -> u64 {
        controller
            .devices()
            .offline_anchor_for(synchronised, &controller.boot_identity)
            .expect("reads the record")
            .expect("the bound's time is recorded")
            .0
            .elapsed_ms
    }

    /// The offline bound runs from the moment the owner chose it, not from the first request a
    /// device makes under it. A bound that ran out while nothing asked is out when a device first
    /// asks, although the request's reading of the wall clock is the synchronisation itself. The
    /// lapse the continuous clock found is no reading of UTC, so the floor stays where the
    /// readings left it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_offline_bound_runs_from_when_it_was_chosen_and_not_from_its_first_use() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        let revision = controller.policy().authority_revision();
        let synchronised = kr_ipc::now_ms().get();
        choose_offline_bound(&controller, synchronised, 200);
        let (lasting, lasting_record) = granted(GrantExpiry::Never, revision);
        let floor = controller.policy().utc_floor_ms();

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        offline_lapsed(
            controller.decide_for_device(&lasting, &lasting_record, listing(&temp, synchronised)),
            "the bound ran out while nothing asked",
        );
        assert_eq!(
            controller.policy().utc_floor_ms(),
            floor,
            "the floor holds no moment the continuous clock implied"
        );
        drop(controller);
    }

    /// Through the daemon: a shorter maximum, chosen after the request's reading was wound back,
    /// is refused once the time spent since the bound was chosen passes it. That the time spent is
    /// kept across the change, rather than read again from a wall clock wound back, is shown with
    /// clocks driven by hand in `a_shorter_maximum_is_measured_against_the_time_already_spent`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_shorter_offline_bound_after_a_rollback_never_ends_later() {
        let temp = kr_ipc::testing::TempHost::create();
        let (continuous, wall, clocks) = manual_clocks();
        let controller = daemon_on(&temp, clocks).await;
        let revision = controller.policy().authority_revision();
        let synchronised = wall.load(std::sync::atomic::Ordering::SeqCst);
        choose_offline_bound(&controller, synchronised, 400);
        let (lasting, lasting_record) = granted(GrantExpiry::Never, revision);
        controller
            .decide_for_device(&lasting, &lasting_record, listing(&temp, synchronised))
            .expect("inside the bound");

        continuous.advance(std::time::Duration::from_millis(300));
        // The request's reading is wound back two hundred milliseconds, and the owner shortens the
        // bound to a quarter of a second without a synchronisation. Three hundred milliseconds
        // have passed, which is more than the shorter bound allows.
        choose_offline_bound(&controller, synchronised, 250);
        offline_lapsed(
            controller.decide_for_device(
                &lasting,
                &lasting_record,
                listing(&temp, synchronised + 100),
            ),
            "the shorter bound ran out with the time already spent",
        );
        drop(controller);
    }

    /// A lapse the continuous clock found is written down as the time the bound has spent, and a
    /// write of it that failed is written once storage takes it, so a daemon started afterwards
    /// with the request's reading still wound back refuses. The floor is not raised for it: the
    /// lapse is not a reading of UTC.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_offline_lapse_the_continuous_clock_found_is_written_down_once_storage_takes_it() {
        let temp = kr_ipc::testing::TempHost::create();
        let (continuous, wall, clocks) = manual_clocks();
        let controller = daemon_on(&temp, clocks).await;
        let revision = controller.policy().authority_revision();
        let synchronised = wall.load(std::sync::atomic::Ordering::SeqCst);
        choose_offline_bound(&controller, synchronised, 200);
        let (lasting, lasting_record) = granted(GrantExpiry::Never, revision);
        controller
            .decide_for_device(&lasting, &lasting_record, listing(&temp, synchronised))
            .expect("inside the bound");

        continuous.advance(std::time::Duration::from_millis(300));
        let registry = refuse_offline_time_writes(&temp);
        let floor = controller.policy().utc_floor_ms();
        offline_lapsed(
            controller.decide_for_device(
                &lasting,
                &lasting_record,
                listing(&temp, synchronised - 5_000),
            ),
            "the bound ran out on the continuous clock",
        );
        assert!(
            recorded_offline_time(&controller, synchronised) < 200,
            "the write failed"
        );
        assert_eq!(
            controller.policy().utc_floor_ms(),
            floor,
            "the floor holds no moment the lapse implied"
        );

        allow_offline_time_writes(&registry);
        controller.settle_floor();
        assert!(
            recorded_offline_time(&controller, synchronised) > 200,
            "the time spent is written down once storage takes it"
        );

        // A daemon on the machine's own clocks reads the time spent from the record.
        stopped(controller).await;
        let controller = daemon(&temp).await;
        offline_lapsed(
            controller.decide_for_device(
                &lasting,
                &lasting_record,
                listing(&temp, synchronised - 5_000),
            ),
            "a restart with the request's reading still wound back does not bring the bound back",
        );
        drop(controller);
    }

    /// Through the daemon: a bound that ran out while the daemon was down is refused after a
    /// restart, with the request's reading of the wall clock at the synchronisation itself. The
    /// restart takes the time spent from the record and from UTC; that the record alone is enough
    /// is shown with clocks driven by hand in `a_restart_in_the_same_boot_adds_the_time_since_the_record`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_offline_bound_that_ran_out_while_the_daemon_was_down_is_refused_after_a_restart() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        let revision = controller.policy().authority_revision();
        let synchronised = kr_ipc::now_ms().get();
        choose_offline_bound(&controller, synchronised, 200);
        let (lasting, lasting_record) = granted(GrantExpiry::Never, revision);

        drop(controller);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let controller = daemon(&temp).await;
        offline_lapsed(
            controller.decide_for_device(&lasting, &lasting_record, listing(&temp, synchronised)),
            "the bound ran out while the daemon was down",
        );
        drop(controller);
    }

    /// The network's record task writes down the time the offline bound has spent, whether or not
    /// anything asked, so a reboot loses no more than one mark of it; and it raises no floor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_record_task_writes_down_the_time_an_offline_bound_has_spent() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = daemon(&temp).await;
        let synchronised = kr_ipc::now_ms().get();
        choose_offline_bound(&controller, synchronised, 200);
        let floor = controller.policy().utc_floor_ms();

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        controller.keep_offline_time();
        assert!(
            recorded_offline_time(&controller, synchronised) >= 300,
            "the time spent is written down"
        );
        assert_eq!(
            controller.policy().utc_floor_ms(),
            floor,
            "and no floor is raised for it"
        );
        drop(controller);
    }

    /// The clocks and the record an offline anchor is taken from, every one driven by hand.
    struct ByHand {
        clock: kr_transport::clock::ManualClock,
        boot_clock: kr_ipc::clock::ManualSharedClock,
        wall_ms: std::sync::atomic::AtomicU64,
        /// Continuous time that passes while the wall clock is read, as a machine asleep between
        /// two readings would have it.
        paused_while_reading: std::time::Duration,
        boot: kr_protocol::identity::BootIdentity,
        devices: Arc<super::DeviceDirectory>,
        floor: crate::grants::policy::UtcFloor,
    }

    impl ByHand {
        /// A host in this boot whose wall clock reads `wall_ms` and whose floor is there too.
        fn at(wall_ms: u64) -> Self {
            Self {
                clock: kr_transport::clock::ManualClock::new(),
                boot_clock: kr_ipc::clock::ManualSharedClock::new(),
                wall_ms: std::sync::atomic::AtomicU64::new(wall_ms),
                paused_while_reading: std::time::Duration::ZERO,
                boot: kr_ipc::identity::boot_identity().expect("a boot identity"),
                devices: Arc::new(super::DeviceDirectory::in_memory().expect("a directory")),
                floor: crate::grants::policy::UtcFloor::at(wall_ms),
            }
        }

        /// The same host started again in the same boot, with a continuous clock of its own and a
        /// floor read back at `floor_ms`, keeping its boot clock and its record.
        fn restarted(&self, wall_ms: u64, floor_ms: u64) -> Self {
            Self {
                clock: kr_transport::clock::ManualClock::new(),
                boot_clock: self.boot_clock.clone(),
                wall_ms: std::sync::atomic::AtomicU64::new(wall_ms),
                paused_while_reading: std::time::Duration::ZERO,
                boot: self.boot.clone(),
                devices: Arc::clone(&self.devices),
                floor: crate::grants::policy::UtcFloor::at(floor_ms),
            }
        }

        /// The same host started in a new boot, whose boot clock starts again, keeping its record.
        fn rebooted(&self, wall_ms: u64, floor_ms: u64) -> Self {
            Self {
                boot_clock: kr_ipc::clock::ManualSharedClock::new(),
                boot: kr_protocol::identity::BootIdentity {
                    value: kr_protocol::scalars::Bytes::new(vec![0x5a; 16]),
                    ..self.boot.clone()
                },
                ..self.restarted(wall_ms, floor_ms)
            }
        }

        fn with_sources<T>(&self, body: impl FnOnce(&super::AnchorSources<'_>) -> T) -> T {
            let wall = || {
                self.clock.advance(self.paused_while_reading);
                self.boot_clock.advance(self.paused_while_reading);
                self.wall_ms.load(std::sync::atomic::Ordering::SeqCst)
            };
            body(&super::AnchorSources {
                clock: &self.clock,
                boot_clock: &self.boot_clock,
                wall_clock: &wall,
                boot: &self.boot,
                devices: &self.devices,
                floor: &self.floor,
            })
        }

        fn anchor(
            &self,
            offline: &kr_protocol::sharing::OfflineValidityPolicy,
            held: Option<super::OfflineAnchor>,
        ) -> super::OfflineAnchor {
            self.with_sources(|sources| super::offline_anchor(Some(offline), held, sources))
                .expect("the anchor is taken")
                .expect("a bound that has synchronised is anchored")
        }

        fn advance(&self, milliseconds: u64) {
            let elapsed = std::time::Duration::from_millis(milliseconds);
            self.clock.advance(elapsed);
            self.boot_clock.advance(elapsed);
        }

        /// Whether a bound of `maximum_ms` measured with `anchor` has run out now.
        fn run_out(&self, anchor: &super::OfflineAnchor, maximum_ms: u64) -> bool {
            anchor.until(maximum_ms).is_some_and(|until| {
                kr_transport::clock::ContinuousClock::now(&self.clock) >= until
            })
        }
    }

    /// A bound of `maximum_ms` measured from `synchronised`.
    fn offline_bound(
        synchronised: u64,
        maximum_ms: u64,
    ) -> kr_protocol::sharing::OfflineValidityPolicy {
        kr_protocol::sharing::OfflineValidityPolicy {
            maximum_offline_ms: kr_protocol::scalars::DurationMs::new(maximum_ms),
            last_synchronised_at_ms: Nullable::some(TimestampMs::new(synchronised)),
        }
    }

    /// The time an offline bound has spent survives a shorter maximum chosen after the wall clock
    /// was wound back: the new maximum is measured against the time already spent on the
    /// continuous clock, not against what the wall clock now says.
    #[test]
    fn a_shorter_maximum_is_measured_against_the_time_already_spent() {
        let synchronised = 1_000_000;
        let host = ByHand::at(synchronised);
        let anchor = host.anchor(&offline_bound(synchronised, 400), None);
        host.advance(300);
        host.wall_ms
            .store(synchronised + 100, std::sync::atomic::Ordering::SeqCst);

        let kept = host.anchor(&offline_bound(synchronised, 250), Some(anchor));
        assert!(
            host.run_out(&kept, 250),
            "three hundred milliseconds spent is past a bound of two hundred and fifty"
        );
        assert!(
            !host.run_out(&kept, 400),
            "and the longer bound it replaced has time left"
        );
    }

    /// A daemon restarted in the same boot adds the boot clock's time since the record, although
    /// its wall clock and its floor read the synchronisation itself.
    #[test]
    fn a_restart_in_the_same_boot_adds_the_time_since_the_record() {
        let synchronised = 1_000_000;
        let first = ByHand::at(synchronised);
        first.anchor(&offline_bound(synchronised, 200), None);
        first.advance(300);

        let restarted = first.restarted(synchronised, synchronised);
        let restored = restarted.anchor(&offline_bound(synchronised, 200), None);
        assert!(
            restarted.run_out(&restored, 200),
            "the bound ran out while the daemon was down"
        );
    }

    /// The time a boot recorded outlives a reboot. The new boot's clock says nothing about the old
    /// one, but the time spent since the synchronisation is still spent: a restart in the old boot
    /// that recorded three hundred milliseconds leaves them on record for the next boot, whose wall
    /// clock and floor read the synchronisation itself.
    #[test]
    fn a_reboot_keeps_the_time_a_boot_recorded() {
        let synchronised = 1_000_000;
        let first = ByHand::at(synchronised);
        first.anchor(&offline_bound(synchronised, 200), None);
        first.advance(300);
        first
            .restarted(synchronised, synchronised)
            .anchor(&offline_bound(synchronised, 200), None);

        let rebooted = first.rebooted(synchronised, synchronised);
        let restored = rebooted.anchor(&offline_bound(synchronised, 200), None);
        assert!(
            rebooted.run_out(&restored, 200),
            "the time recorded in the old boot still counts"
        );
    }

    /// A stop between writing a new synchronisation's record and writing the policy that names
    /// it leaves the record the policy on disk is measured from as it was: each synchronisation has
    /// a record of its own.
    #[test]
    fn a_stop_between_the_record_and_the_policy_keeps_the_record_the_policy_is_measured_from() {
        let synchronised = 1_000_000;
        let first = ByHand::at(synchronised);
        first.anchor(&offline_bound(synchronised, 200), None);
        first.advance(300);
        // The authority feed synchronises: the new synchronisation's record is written, and the
        // daemon stops before the policy naming it is.
        let later = synchronised + 300;
        first
            .wall_ms
            .store(later, std::sync::atomic::Ordering::SeqCst);
        first.anchor(&offline_bound(later, 200), None);

        let restarted = first.restarted(synchronised, synchronised);
        let restored = restarted.anchor(&offline_bound(synchronised, 200), None);
        assert!(
            restarted.run_out(&restored, 200),
            "the policy on disk is still measured from its own record"
        );
    }

    /// A pause between the continuous clock's reading and the wall clock's makes the bound run out
    /// early, which is the safe side for a refusal, and the floor holds only what the wall clock
    /// read: nothing the early end implies is taken as a reading of UTC.
    #[test]
    fn a_pause_between_the_readings_ends_the_bound_early_and_raises_the_floor_only_to_the_reading()
    {
        let synchronised = 1_000_000;
        let mut host = ByHand::at(synchronised);
        host.paused_while_reading = std::time::Duration::from_secs(6);
        host.wall_ms
            .store(synchronised + 6_000, std::sync::atomic::Ordering::SeqCst);
        let anchor = host.anchor(&offline_bound(synchronised, 10_000), None);
        assert!(
            host.run_out(&anchor, 10_000),
            "six seconds counted twice is past a ten-second bound"
        );
        assert_eq!(host.floor.get(), synchronised + 6_000);
    }
}
