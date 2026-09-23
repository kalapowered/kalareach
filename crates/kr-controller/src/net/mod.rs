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
    /// The services this environment selected.
    pub settings: NetworkSettings,
    /// Where this host's own network device keys live.
    pub secrets: Arc<dyn SecretStore>,
}

impl std::fmt::Debug for NetworkSetup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkSetup")
            .field("settings", &self.settings)
            .field("secrets", &self.secrets.describe())
            .finish()
    }
}

impl NetworkSetup {
    /// Reads the selection and the credentials from this process's environment.
    ///
    /// Returns `None` when the environment selects no network. Under
    /// [`StoreSelection::Platform`] the key store is the platform's own credential store where
    /// there is one, and the documented owner-only directory where there is not; the fallback is
    /// taken deliberately rather than discovered at the first write. Under
    /// [`StoreSelection::File`] it is the directory this environment keeps its secrets in, which
    /// is what a test, a bench or a demonstration run is given so that its keys leave with it.
    ///
    /// # Errors
    ///
    /// Returns a configuration error naming the variable or the store that could not be read.
    pub fn from_environment(
        paths: &kr_ipc::paths::EnvironmentPaths,
        selection: StoreSelection,
    ) -> Result<Option<Self>> {
        let Some(settings) = NetworkSettings::from_environment()? else {
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
        Ok(Some(Self { settings, secrets }))
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
    /// The selected services are this host's own configuration; the direct addresses are hints
    /// taken as they stand now, because that is all a hint ever is.
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
            .bound_sockets()
            .into_iter()
            .filter_map(|socket| kr_protocol::pairing::NetworkHint::new(socket.to_string()).ok())
            .take(kr_protocol::pairing::MAX_NETWORK_HINTS)
            .collect();
        Ok(config)
    }

    /// Returns the addresses this endpoint is bound to, which are the hints a peer dials.
    fn bound_sockets(&self) -> Vec<std::net::SocketAddr> {
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
    /// The selected services are this host's own configuration; the direct addresses are hints
    /// taken as they stand now, because that is all a hint ever is.
    ///
    /// # Errors
    ///
    /// Returns an error when a selected service cannot be expressed as a network hint.
    pub fn network_config(&self) -> Result<NetworkConfig> {
        self.guard.network_config()
    }

    /// Returns the addresses this endpoint is bound to, which are the hints a peer dials.
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
    /// The record and the authority revision move in one critical section, in the lock order the
    /// daemon's own revocation takes. That is what closes the window a revocation would otherwise
    /// have: a connection cannot be admitted between the moment the record is withdrawn and the
    /// moment the revision that fences the live ones is in force, because both happen before the
    /// registry lock is released.
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
                    if !remote.output().send(&answer).await {
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
    /// The order is the contract. The live fence goes first, because it is the only step that
    /// cannot fail and the only one whose absence would leave a revoked device being served: the
    /// registration is withdrawn, the connection's write boundary is closed, and what it owned at
    /// its worker is released. Only then is the record written and the revision advanced, both
    /// inside the same critical section, so nothing can be admitted between a withdrawn record and
    /// the revision that fences the connections already admitted. A failure after the fence is
    /// reported with the fence standing rather than silently leaving it undone.
    async fn revoke_device(
        &self,
        device_id: DeviceId,
    ) -> Result<kr_protocol::action::RevocationBarrier> {
        let controller = self.daemon()?;
        let revision = {
            let mut registry = controller.registry.lock().await;
            let revoked = kr_transport::listener::device_principal(&device_id);
            // The connections this fences are this device's. Nobody else's authority was
            // withdrawn, and a local terminal losing its connection because a phone was revoked
            // would be a fence on the wrong thing.
            let mut admitted = controller.admitted_table();
            admitted.retain(|_, connection| connection.actor_id != revoked);
            drop(admitted);
            self.withdraw_device(device_id);
            self.devices.revoke(device_id, kr_ipc::now_ms())?;
            registry.advance_authority_revision()?;
            let revision = registry.authority_revision()?;
            // The connections that were *not* withdrawn hold authority this revocation did not
            // touch, so they are admitted at the revision now in force. Leaving them at the
            // previous one would refuse their next mutation as revoked and make one device's
            // revocation everybody's reconnection. What the revision still fences is work already
            // admitted: a mutation carries the revision it was admitted under, and one admitted
            // before this point is refused inside its own transaction as it was before.
            let mut admitted = controller.admitted_table();
            for connection in admitted.values_mut() {
                connection.admitted_revision = revision;
            }
            drop(admitted);
            revision
        };
        controller.leases.revoke(revision);
        controller.announce_authority_revision().await
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
        self.lifetimes.clock_trust().establish(&self.devices)
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

/// How often this host writes down what its wall clock reads.
///
/// It bounds how much real time can pass unrecorded, which is how far a clock can be stepped
/// backwards without this host noticing.
pub const CLOCK_MARK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Keeps this host's records of the wall clock and of expiry moving while it is on the network.
///
/// Two things it owns rather than a connection: the mark that says time has passed, and the
/// tombstones a connection observed but could not write. Both have to outlive the connection that
/// noticed them, and neither can wait for the next device to arrive.
async fn keep_the_record(
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
        // The registration and the grant are read inside the write boundary itself, and watched
        // for as long as the write waits, so a revocation that lands while this frame is queued
        // stops it there. The item holds its charge against the connection's queue until it has
        // been written or dropped.
        //
        // The write is raced against the link it is relaying, because a device that has stopped
        // consuming output would otherwise hold this frame, and the connection, for as long as it
        // liked: the link ending while a frame waits for the peer has to end the connection too.
        let written = tokio::select! {
            written = remote.output().send(item.frame()) => written,
            () = remote.link_lost() => {
                remote.output().withdraw();
                remote.release().await;
                return;
            }
        };
        if !written {
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
    // The daemon's own clock, not a second one. Deadlines from the transport's action windows are
    // compared with deadlines the daemon decided, and a continuous instant is anchored privately:
    // two clocks would make those comparisons meaningless rather than merely imprecise.
    let clock: Arc<dyn kr_transport::clock::ContinuousClock> =
        Arc::clone(&controller.clock) as Arc<_>;
    // One record of every grant's lifetime, read by the connections this host admits and by the
    // owner confirmations it spends.
    let lifetimes = Arc::new(lifetimes::GrantLifetimes::new(
        Arc::clone(&devices),
        Arc::clone(&clock),
        Arc::clone(&controller.shared_clock),
        controller.boot_identity.clone(),
    ));
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
    let pairing = Arc::new(PairingHost::new(
        HostIdentity {
            device_id,
            endpoint_id,
            keys: keys.public_keys(),
            device_key_revision: DeviceKeyRevision::new(1),
            network_config: NetworkConfig::empty(),
        },
        HostPairingClock::new(&controller.boot_identity),
        rows,
    ));
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
        clock,
    )
    .await
    .map_err(|error| ControllerError::NotConfigured(error.to_string()))?;
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
            // The worker has accepted the close and is stopping its processes. Something has to
            // notice when that finishes, so the tombstone is written and the descriptor removed
            // rather than left pointing at a process that has gone.
            None => {
                tokio::spawn(Arc::clone(self).watch_closure(
                    session_id,
                    kr_protocol::session::ClosureReason::CloseRequested,
                ));
            }
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

/// Puts a daemon on the network, if its environment selects one.
///
/// This is the whole of the daemon's integration with the transport: one call, made once, at the
/// end of startup. An environment that selects no network serves its local endpoint alone.
///
/// # Errors
///
/// Returns a configuration failure, a key-store failure or a bind failure.
pub async fn register_from_environment(controller: &Arc<Controller>) -> Result<()> {
    let Some(setup) =
        NetworkSetup::from_environment(controller.paths(), controller.secret_store())?
    else {
        return Ok(());
    };
    // Registering records the host on the daemon and hands the listener to it, so the daemon owns
    // both for as long as it runs and a revocation can reach the connections they serve. The handle
    // returned here is for a caller that registers a network of its own.
    register(controller, setup).await?;
    Ok(())
}
