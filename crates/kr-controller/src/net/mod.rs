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
pub mod pairing;
pub mod proxy;

use std::sync::{Arc, Weak};

use kr_crypto::connect::PairedPeer;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::SecretStore;
use kr_pairing::confirm::HostEnrolment;
use kr_pairing::host::HostIdentity;
use kr_protocol::ids::{ActorId, AuthorityRevision, ConnectionId, DeviceId, DeviceKeyRevision};
use kr_protocol::pairing::NetworkConfig;
use kr_protocol::scalars::{AuthorisationKey, EndpointKey};
use kr_transport::clock::ContinuousInstant;
use kr_transport::handshake::{HostEpochs, LocalIdentity, PairedDirectory};
use kr_transport::lease::RevocationStatus;
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

/// The environment variable naming the signer every pairing confirmation must carry.
pub const OWNER_KEY: &str = "KR_NETWORK_OWNER_KEY";

/// Everything a daemon needs to put itself on the network.
pub struct NetworkSetup {
    /// The services this environment selected.
    pub settings: NetworkSettings,
    /// Where this host's own network device keys live.
    pub secrets: Arc<dyn SecretStore>,
    /// The enrolled owner signer a pairing confirmation is checked against.
    ///
    /// `None` means no owner is enrolled, and this host accepts no pairing: an unpaired connection
    /// is refused rather than offered a ceremony nobody could authorise.
    pub owner_signer: Option<AuthorisationKey>,
    /// Whether this host has an owner yet, which decides whether the bootstrap exception applies.
    pub enrolment: HostEnrolment,
}

impl std::fmt::Debug for NetworkSetup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkSetup")
            .field("settings", &self.settings)
            .field("secrets", &self.secrets.describe())
            .field("pairing", &self.owner_signer.is_some())
            .finish()
    }
}

impl NetworkSetup {
    /// Reads the selection and the credentials from this process's environment.
    ///
    /// Returns `None` when the environment selects no network. The key store is the platform's own
    /// credential store where there is one, and the documented owner-only directory where there is
    /// not; the fallback is taken deliberately rather than discovered at the first write.
    ///
    /// # Errors
    ///
    /// Returns a configuration error naming the variable or the store that could not be read.
    pub fn from_environment(paths: &kr_ipc::paths::EnvironmentPaths) -> Result<Option<Self>> {
        let Some(settings) = NetworkSettings::from_environment()? else {
            return Ok(None);
        };
        let secrets: Arc<dyn SecretStore> = match kr_crypto::store::PlatformStore::open(
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
        };
        let owner_signer = match std::env::var(OWNER_KEY) {
            Ok(text) if !text.trim().is_empty() => Some(owner_key(text.trim())?),
            Ok(_) | Err(_) => None,
        };
        Ok(Some(Self {
            settings,
            secrets,
            owner_signer,
            enrolment: if owner_signer.is_some() {
                HostEnrolment::Enrolled
            } else {
                HostEnrolment::InitialBootstrap
            },
        }))
    }
}

fn owner_key(text: &str) -> Result<AuthorisationKey> {
    let bytes = kr_protocol::scalars::from_base64url(text)
        .map_err(|error| ControllerError::InvalidArgument(format!("{OWNER_KEY}: {error}")))?;
    let bytes = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        ControllerError::InvalidArgument(format!(
            "{OWNER_KEY} is a 32-byte authorisation key in base64url"
        ))
    })?;
    Ok(AuthorisationKey::from_bytes(bytes))
}

/// A daemon that is on the network.
#[derive(Debug)]
pub struct Network {
    listener: kr_transport::listener::NetworkListener,
    host: Arc<NetworkHost>,
}

impl Network {
    /// Returns this host's endpoint identity, which is what a pairing invitation pins.
    #[must_use]
    pub fn endpoint_id(&self) -> EndpointKey {
        self.listener.endpoint_id()
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
            .listener
            .endpoint()
            .bound_sockets()
            .into_iter()
            .filter_map(|socket| kr_protocol::pairing::NetworkHint::new(socket.to_string()).ok())
            .take(kr_protocol::pairing::MAX_NETWORK_HINTS)
            .collect();
        Ok(config)
    }

    /// Returns the addresses this endpoint is bound to, which are the hints a peer dials.
    #[must_use]
    pub fn bound_sockets(&self) -> Vec<std::net::SocketAddr> {
        self.listener.endpoint().bound_sockets()
    }

    /// Returns the host's pairing state machine, for the owner operations it serves.
    #[must_use]
    pub fn pairing(&self) -> Option<&Arc<PairingHost>> {
        self.host.pairing.as_ref()
    }

    /// Returns the device directory this host authorises connections against.
    #[must_use]
    pub fn devices(&self) -> &Arc<DeviceDirectory> {
        &self.host.devices
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
    /// worker has acknowledged the revision, or has been confirmed ended, which is what the
    /// returned status reports.
    ///
    /// # Errors
    ///
    /// Returns an error when the record or the revision cannot be written.
    pub async fn revoke_device(&self, device_id: DeviceId) -> Result<RevocationStatus> {
        self.host.revoke_device(device_id).await
    }

    /// Stops accepting connections and closes the endpoint.
    pub async fn shutdown(self) {
        self.listener.shutdown().await;
    }
}

/// When one device's grant runs out, and whether it has been found to have run out.
#[derive(Clone, Copy, Debug)]
pub struct GrantDeadline {
    /// The moment on the continuous clock, absent for a grant that does not expire.
    pub deadline: Option<ContinuousInstant>,
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
    pairing: Option<Arc<PairingHost>>,
    endpoint: kr_transport::config::EndpointConfig,
    /// The clock every deadline this host decides is measured on.
    clock: Arc<dyn kr_transport::clock::ContinuousClock>,
    /// When each device's grant runs out, on the continuous clock.
    ///
    /// Anchored the first time a device connects and shared by every connection it makes
    /// afterwards, so a wall clock stepped backwards between two connections cannot give the same
    /// grant a longer life the second time. A device whose grant is found to have run out is
    /// recorded as expired, which is what makes the decision survive a restart as well.
    grant_deadlines: std::sync::Mutex<std::collections::BTreeMap<DeviceId, GrantDeadline>>,
    /// Every authorised connection this host is serving.
    ///
    /// A revocation needs them: withdrawing a registration stops the next request, and a device
    /// whose record has gone must also lose the write boundary it is holding and whatever it owns
    /// at its worker. Nothing else needs them, which is why they are recorded here rather than in
    /// the daemon's own authority store.
    live: std::sync::Mutex<std::collections::BTreeMap<ConnectionId, Arc<RemoteConnection>>>,
}

impl std::fmt::Debug for NetworkHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkHost")
            .field("pairing", &self.pairing.is_some())
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
        self.pairing
            .as_ref()
            .map(|host| Arc::clone(host) as Arc<dyn PairingSurface>)
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
                controller.deregister(connection_id).await;
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
        let mut admitted = controller.admitted.lock().await;
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

    /// Returns when this device's grant runs out, anchoring it the first time it is asked.
    ///
    /// One anchor per device, shared by every connection it makes, so the answer does not depend
    /// on what the wall clock said at each connection. A grant already past its expiry is recorded
    /// as expired, and that record is what a later run reads.
    fn grant_deadline(&self, record: &DeviceRecord) -> Option<ContinuousInstant> {
        let mut held = self
            .grant_deadlines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(anchored) = held.get(&record.device_id) {
            return anchored.deadline;
        }
        let kr_protocol::grant::GrantExpiry::At { expires_at_ms } = record.grant.expiry else {
            held.insert(record.device_id, GrantDeadline { deadline: None });
            return None;
        };
        let now = kr_ipc::now_ms();
        let remaining = expires_at_ms.get().saturating_sub(now.get());
        if remaining == 0 {
            // Already run out. Recording it is what stops a wall clock stepped backwards from
            // making the same grant look current on the next connection, or after a restart.
            let _ = self.devices.record_expiry(record.device_id, now);
        }
        let deadline = self
            .clock
            .now()
            .checked_add(std::time::Duration::from_millis(remaining));
        held.insert(record.device_id, GrantDeadline { deadline });
        deadline
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
        let grant_deadline = self.grant_deadline(&device);
        let remote = Arc::new(RemoteConnection::new(
            Arc::clone(&controller),
            device,
            &session,
            notifications,
            grant_deadline,
        ));
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(connection_id, Arc::clone(&remote));
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
    async fn revoke_device(&self, device_id: DeviceId) -> Result<RevocationStatus> {
        let controller = self.daemon()?;
        let revision = {
            let mut registry = controller.registry.lock().await;
            let revoked = kr_transport::listener::device_principal(&device_id);
            // The connections this fences are this device's. Nobody else's authority was
            // withdrawn, and a local terminal losing its connection because a phone was revoked
            // would be a fence on the wrong thing.
            let mut admitted = controller.admitted.lock().await;
            admitted.retain(|_, connection| connection.actor_id != revoked);
            drop(admitted);
            self.withdraw_device(device_id);
            self.devices.revoke(device_id, kr_ipc::now_ms())?;
            registry.advance_authority_revision()?;
            registry.authority_revision()?
        };
        controller.leases.revoke(revision);
        controller.announce_authority_revision().await
    }

    /// Withdraws every live connection of one device.
    ///
    /// Withdrawing the registration stops the next request; this stops the writes and releases
    /// what the connection owned at its worker, which is what a revoked device's attachment and
    /// input lease would otherwise keep holding.
    fn withdraw_device(&self, device_id: DeviceId) {
        let withdrawn: Vec<Arc<RemoteConnection>> = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|remote| remote.device_id() == device_id)
            .map(Arc::clone)
            .collect();
        for remote in withdrawn {
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
        if !remote.output().send(item.frame()).await {
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
            controller.deregister(connection_id).await;
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
    let pairing = setup.owner_signer.map(|signer| {
        Arc::new(PairingHost::new(
            HostIdentity {
                device_id,
                endpoint_id,
                keys: keys.public_keys(),
                device_key_revision: DeviceKeyRevision::new(1),
                network_config: NetworkConfig::empty(),
            },
            HostPairingClock::new(&controller.boot_identity),
            signer,
            setup.enrolment,
            Arc::clone(&devices),
        ))
    });
    // The daemon's own clock, not a second one. Deadlines from the transport's action windows are
    // compared with deadlines the daemon decided, and a continuous instant is anchored privately:
    // two clocks would make those comparisons meaningless rather than merely imprecise.
    let clock: Arc<dyn kr_transport::clock::ContinuousClock> =
        Arc::clone(&controller.clock) as Arc<_>;
    let host = Arc::new(NetworkHost {
        controller: Arc::downgrade(controller),
        devices,
        pairing,
        endpoint: setup.settings.endpoint.clone(),
        clock: Arc::clone(&clock),
        grant_deadlines: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        live: std::sync::Mutex::new(std::collections::BTreeMap::new()),
    });
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
    Ok(Network { listener, host })
}

/// Loads this host's network device keys, creating them on a genuine first start.
///
/// A host that lost these keys is a host every paired device would refuse to connect to, because
/// its endpoint identity is what an invitation pinned. So they are created once and loaded
/// afterwards, and a store that has them already is never given a fresh set.
fn host_device_keys(
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
                self.registry
                    .lock()
                    .await
                    .record_acknowledged_revision(session_id, ack.revision)?;
                self.leases.acknowledge(session_id, binding, ack.revision);
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
    /// # Errors
    ///
    /// Returns an error when no lease can be taken, or when the accepted deadline has already
    /// passed: a spent deadline is never forwarded as though it had time left.
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

    /// Returns the network this daemon is on, when its environment selected one.
    #[must_use]
    pub fn network(&self) -> Option<&Network> {
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
    let Some(setup) = NetworkSetup::from_environment(controller.paths())? else {
        return Ok(());
    };
    let network = register(controller, setup).await?;
    // A daemon is a singleton, so this is set once and never replaced. A second attempt would mean
    // two listeners on one environment's identity.
    if controller.network.set(network).is_err() {
        return Err(ControllerError::NotConfigured(
            "this daemon is already on the network".to_owned(),
        ));
    }
    Ok(())
}
