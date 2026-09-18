//! Starting the plugin host, taking its identity proof and publishing where it is.
//!
//! The controller owns this. It is here rather than in the control daemon because the daemon's only
//! interest in the plugin host is that one exists when a binding needs it, and everything else
//! about starting one belongs with the runtime that defines what it does.
//!
//! # Lazily
//!
//! Nothing here runs until a binding needs a component. A host serving idle shells has no plugin
//! process, no engine, no instance and no compiled cache in memory, which is what section 5 means
//! by no backend being created for an idle shell that does not use one.
//!
//! # Its own job, outside the kill tree
//!
//! The host is started the way a worker is: through the platform's service manager, as its own job.
//! A control daemon that exits, is upgraded or crashes therefore leaves it running, and the daemon
//! reconnects to its endpoint rather than to a pipe. That is the same contract the workers have,
//! and for a related reason: a plugin host that died with the daemon would take every rich binding
//! with it on every daemon restart.
//!
//! # The identity proof
//!
//! Four things establish which process is answering the plugin endpoint, and none of them
//! substitutes for another:
//!
//! | Proof | Who provides it | What it settles |
//! | --- | --- | --- |
//! | the owner-only runtime directory | the filesystem | another user cannot reach the socket |
//! | peer credentials | the kernel | the caller on the socket is this user |
//! | the rendezvous | the host, once at startup | this process is the one the launcher started |
//! | a verification challenge | the host, on demand | the process answering this endpoint is that one, now |
//!
//! The launcher records the process identity the service manager reported *before* the host
//! connects, and compares it with the connecting peer and with what the claim says. Exactly one
//! rendezvous per reservation succeeds; a second is refused and recorded, because two processes
//! claiming one reservation means the host does not know which of them owns the endpoint.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign;
use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::split;
use kr_ipc::paths::{Endpoint, EnvironmentPaths};
use kr_ipc::peer::PeerIdentity;
use kr_protocol::frame::StreamKind;
use kr_protocol::identity::{BootIdentity, ProcessStartIdentity};
use kr_protocol::ids::EnvironmentId;
use kr_protocol::scalars::{AuthorisationKey, Nonce256};
use kr_protocol::worker::ReservationId;

use crate::service::protocol::{
    self, HostDescriptor, HostRendezvous, HostVerifyProof, RENDEZVOUS_DOMAIN, RendezvousAccepted,
    VERIFY_DOMAIN,
};

/// The largest descriptor this host writes or reads.
const MAX_DESCRIPTOR_BYTES: u64 = 8 * 1024;

/// One environment's publication turn.
///
/// Writing a descriptor is a file write, a flush and a rename, and a timer cannot interrupt any of
/// it: a publication this launcher stopped waiting for still finishes. What must not happen is that
/// it finishes *after* a later launch published its own, and replaces it.
///
/// So a publication is not merely checked before it starts: it holds this environment's turn from
/// the check to the rename. Each attempt takes a number, and a publication that finds a newer
/// number when its turn comes writes nothing and says so. Two launches for one environment
/// therefore publish in order, and the older one never wins.
static PUBLICATIONS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<EnvironmentId, Arc<std::sync::Mutex<u64>>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// The source of publication numbers, which are never reused inside a process.
static NEXT_PUBLICATION: AtomicU64 = AtomicU64::new(1);

/// One acceptance still waiting for its publication.
///
/// Its drop is what tells a publication that nobody is waiting for it any more, whether the
/// acceptance gave up on its own deadline or its caller stopped polling it.
struct Waiting {
    abandoned: Arc<core::sync::atomic::AtomicBool>,
    finished: bool,
}

impl Waiting {
    fn finished(mut self) {
        self.finished = true;
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        if !self.finished {
            self.abandoned
                .store(true, core::sync::atomic::Ordering::Release);
        }
    }
}

/// Returns one environment's publication turn.
fn publication_turn(environment_id: EnvironmentId) -> Arc<std::sync::Mutex<u64>> {
    PUBLICATIONS.lock().map_or_else(
        |_poisoned| Arc::new(std::sync::Mutex::new(0)),
        |mut environments| {
            Arc::clone(
                environments
                    .entry(environment_id)
                    .or_insert_with(|| Arc::new(std::sync::Mutex::new(0))),
            )
        },
    )
}

/// Publishes a descriptor in this environment's publication order.
///
/// Called on a blocking thread, and it waits there: the turn is held by whoever is publishing, and
/// waiting for it is waiting for a file write rather than for anything on an executor. Taking the
/// number after the turn is what puts two launches in the order they reached publication, and the
/// turn is held from that point to the rename, so no later launch's descriptor can be replaced by
/// an earlier launch that was slow.
///
/// A launch whose acceptance has already given up publishes nothing: `abandoned` is what its
/// acceptance sets on its way out.
fn publish_in_turn(
    turn: &std::sync::Mutex<u64>,
    abandoned: &core::sync::atomic::AtomicBool,
    environment: &EnvironmentPaths,
    descriptor: &HostDescriptor,
) -> LaunchResult<()> {
    let attempt = NEXT_PUBLICATION.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let Ok(mut newest) = turn.lock() else {
        return Err(LaunchError::Refused {
            detail: "this environment's publication turn is unusable".to_owned(),
        });
    };
    if abandoned.load(core::sync::atomic::Ordering::Acquire) {
        return Err(LaunchError::Refused {
            detail: "this launch stopped waiting before its descriptor was published".to_owned(),
        });
    }
    if *newest > attempt {
        return Err(LaunchError::Refused {
            detail: "a later launch has published this environment's descriptor".to_owned(),
        });
    }
    *newest = attempt;
    publish_descriptor(environment, descriptor)
}

/// What can go wrong starting or verifying a plugin host.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LaunchError {
    /// The rendezvous endpoint could not be used.
    #[error("the plugin host rendezvous endpoint is unusable: {0}")]
    Endpoint(#[from] kr_ipc::IpcError),
    /// The service manager did not start the host.
    #[error("the plugin host was not started: {detail}")]
    NotStarted {
        /// What the service manager reported.
        detail: String,
    },
    /// The service manager may have started it and cannot say.
    ///
    /// Not the same as `NotStarted`. A failure after a successful spawn leaves a process that may
    /// be holding the endpoint, so the reservation keeps its slot until something settles it.
    #[error("the plugin host may be running and this host cannot say: {detail}")]
    Uncertain {
        /// What the service manager reported.
        detail: String,
        /// The process identifier it reported, where it reported one.
        pid: Option<u32>,
    },
    /// The host did not present a claim inside the deadline.
    #[error("the plugin host did not report itself within {deadline_ms} ms")]
    NoRendezvous {
        /// How long it was given.
        deadline_ms: u64,
    },
    /// The claim did not check out.
    #[error("the plugin host's claim was refused: {detail}")]
    Refused {
        /// Why.
        detail: String,
    },
    /// A cryptographic operation failed, including a signature that did not verify.
    #[error("{0}")]
    Crypto(#[from] kr_crypto::CryptoError),
}

/// The result of starting or verifying a plugin host.
pub type LaunchResult<T> = Result<T, LaunchError>;

/// What a launcher needs to be told to start the host as its own job.
///
/// Every field is non-secret. The host's key is generated inside the host process and its private
/// half never leaves that process's memory, so there is nothing here a job definition should not
/// carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostLaunchPlan {
    /// The job label.
    pub label: String,
    /// The host executable.
    pub program: PathBuf,
    /// The argument vector, passed as a vector rather than interpolated into a command line.
    pub arguments: Vec<String>,
    /// Where a generated job definition is written.
    pub jobs_directory: PathBuf,
    /// The directory the host process runs in.
    ///
    /// Its own, inside the environment's state directory, rather than whatever it would inherit: a
    /// service manager's directory belongs to the system and a daemon's belongs to whoever started
    /// the daemon. Neither is a directory this process has any claim on, and either can be a volume
    /// the person at the machine expects to be able to unmount -- which, on a host whose workspace
    /// is on a removable volume, is exactly what a launched process holding one prevents.
    pub working_directory: PathBuf,
}

/// What starting the job produced.
///
/// The same three answers a worker launch has, for the same reason: "nothing started" releases the
/// slot, "something may be running" does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostStartOutcome {
    /// The host started, and the kernel described it.
    Started(ProcessStartIdentity),
    /// Nothing was started.
    NotStarted {
        /// What went wrong.
        detail: String,
    },
    /// A process may be running, and the launcher cannot say whether it is.
    Uncertain {
        /// What went wrong.
        detail: String,
        /// The process identifier the launcher reported, where it reported one.
        pid: Option<u32>,
    },
}

/// What starts a job on this platform.
///
/// A function rather than a trait implemented here, so the control daemon supplies its own
/// supervisor and this crate does not have to depend on the daemon to be tested.
pub type HostStarter<'a> = &'a dyn Fn(&HostLaunchPlan) -> HostStartOutcome;

/// The plugin host's own per-process signing identity.
///
/// Generated in the host process at startup from the operating system's random generator. The
/// private half exists only in that process's memory and is never written to disk, put in an
/// argument vector or placed in an environment variable, so nothing that is not this process can
/// answer for it even with full access to the runtime directory.
#[derive(Debug)]
pub struct HostIdentity {
    keypair: AuthorisationKeyPair,
    environment_id: EnvironmentId,
    boot_identity: BootIdentity,
    process_start_identity: ProcessStartIdentity,
}

impl HostIdentity {
    /// Generates a fresh per-process keypair and reads this process's own identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the random generator or the kernel's identity source is unavailable.
    pub fn generate(environment_id: EnvironmentId) -> LaunchResult<Self> {
        let boot_identity =
            kr_ipc::identity::boot_identity().map_err(|error| LaunchError::Refused {
                detail: format!("this host's boot identity is unreadable: {error}"),
            })?;
        let process_start_identity = kr_ipc::identity::process_start_identity(std::process::id())
            .map_err(|error| LaunchError::Refused {
            detail: format!("this process's start identity is unreadable: {error}"),
        })?;
        Ok(Self {
            keypair: AuthorisationKeyPair::generate()?,
            environment_id,
            boot_identity,
            process_start_identity,
        })
    }

    /// Returns the public half.
    #[must_use]
    pub const fn public_key(&self) -> &AuthorisationKey {
        self.keypair.public()
    }

    /// Returns the environment this host serves.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Returns the boot this process started in.
    #[must_use]
    pub const fn boot_identity(&self) -> &BootIdentity {
        &self.boot_identity
    }

    /// Returns this process's own start identity.
    #[must_use]
    pub const fn process_start_identity(&self) -> &ProcessStartIdentity {
        &self.process_start_identity
    }

    /// Builds the startup claim for one reservation.
    ///
    /// # Errors
    ///
    /// Returns an error when the transcript cannot be encoded or signed.
    pub fn rendezvous(
        &self,
        reservation_id: ReservationId,
        endpoint: &str,
    ) -> LaunchResult<HostRendezvous> {
        let elements = protocol::rendezvous_elements(
            reservation_id,
            self.environment_id,
            self.keypair.public(),
            &self.boot_identity,
            &self.process_start_identity,
            endpoint,
        )
        .map_err(kr_crypto::CryptoError::from)?;
        let signature = sign::sign_elements(&self.keypair, RENDEZVOUS_DOMAIN, elements)?;
        Ok(HostRendezvous {
            reservation_id,
            environment_id: self.environment_id,
            host_public_key: *self.keypair.public(),
            boot_identity: self.boot_identity.clone(),
            process_start_identity: self.process_start_identity.clone(),
            endpoint: endpoint.to_owned(),
            signature,
        })
    }

    /// Answers a verification challenge on one endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the transcript cannot be encoded or signed.
    pub fn answer(&self, nonce: &Nonce256, endpoint: &str) -> LaunchResult<HostVerifyProof> {
        let elements = protocol::verify_elements(
            self.environment_id,
            &self.boot_identity,
            &self.process_start_identity,
            endpoint,
            nonce,
        )
        .map_err(kr_crypto::CryptoError::from)?;
        let signature = sign::sign_elements(&self.keypair, VERIFY_DOMAIN, elements)?;
        Ok(HostVerifyProof {
            environment_id: self.environment_id,
            boot_identity: self.boot_identity.clone(),
            process_start_identity: self.process_start_identity.clone(),
            endpoint: endpoint.to_owned(),
            signature,
        })
    }
}

/// Checks that a startup claim is signed by the key it presents.
///
/// The cryptographic half only. The launcher still has to match the reservation, compare the
/// connecting peer's process identity with what the service manager reported, and refuse a second
/// claim for the same reservation.
///
/// # Errors
///
/// Returns [`LaunchError::Crypto`] when the signature does not verify.
pub fn check_rendezvous(claim: &HostRendezvous) -> LaunchResult<()> {
    let elements = protocol::rendezvous_elements(
        claim.reservation_id,
        claim.environment_id,
        &claim.host_public_key,
        &claim.boot_identity,
        &claim.process_start_identity,
        &claim.endpoint,
    )
    .map_err(kr_crypto::CryptoError::from)?;
    sign::verify_elements(
        &claim.host_public_key,
        RENDEZVOUS_DOMAIN,
        elements,
        &claim.signature,
    )?;
    Ok(())
}

/// Checks a verification answer against a descriptor.
///
/// # Errors
///
/// Returns [`LaunchError::Refused`] when a field disagrees with the descriptor, or
/// [`LaunchError::Crypto`] when the signature does not verify.
pub fn check_proof(
    descriptor: &HostDescriptor,
    nonce: &Nonce256,
    proof: &HostVerifyProof,
) -> LaunchResult<()> {
    for (field, agrees) in [
        (
            "environment",
            proof.environment_id == descriptor.environment_id,
        ),
        ("boot", proof.boot_identity == descriptor.boot_identity),
        (
            "process",
            proof.process_start_identity == descriptor.process_start_identity,
        ),
        ("endpoint", proof.endpoint == descriptor.endpoint),
    ] {
        if !agrees {
            return Err(LaunchError::Refused {
                detail: format!("the plugin host answered with a different {field}"),
            });
        }
    }
    let elements = protocol::verify_elements(
        proof.environment_id,
        &proof.boot_identity,
        &proof.process_start_identity,
        &proof.endpoint,
        nonce,
    )
    .map_err(kr_crypto::CryptoError::from)?;
    sign::verify_elements(
        &descriptor.host_public_key,
        VERIFY_DOMAIN,
        elements,
        &proof.signature,
    )?;
    Ok(())
}

/// Generates a fresh 32-byte challenge.
///
/// # Errors
///
/// Returns an error when the random generator is unavailable.
pub fn fresh_challenge() -> LaunchResult<Nonce256> {
    let secret = kr_crypto::secret::Secret::<32>::random()?;
    Ok(Nonce256::from_bytes(*secret.expose()))
}

/// Returns the endpoint a plugin host serves workers on.
///
/// # Errors
///
/// Returns [`LaunchError::Endpoint`] when the path is too long for a socket address.
pub fn host_endpoint(environment: &EnvironmentPaths) -> LaunchResult<Endpoint> {
    endpoint_in(environment, protocol::ENDPOINT_NAME)
}

/// Returns the endpoint a launcher takes one reservation's rendezvous on.
///
/// One address per reservation. A launcher that reused one address would be binding a name a
/// previous launch had just given up, and a claim arriving in that window belongs to neither
/// launch clearly; naming the address after the reservation removes the question.
///
/// # Errors
///
/// Returns [`LaunchError::Endpoint`] when the path is too long for a socket address.
pub fn rendezvous_endpoint(
    environment: &EnvironmentPaths,
    reservation_id: ReservationId,
) -> LaunchResult<Endpoint> {
    let short = reservation_id.to_string();
    let short = short.get(..8).unwrap_or(&short);
    endpoint_in(
        environment,
        &format!("{}{short}.sock", protocol::RENDEZVOUS_PREFIX),
    )
}

fn endpoint_in(environment: &EnvironmentPaths, name: &str) -> LaunchResult<Endpoint> {
    #[cfg(windows)]
    {
        let prefix = kr_ipc::paths::short_prefix(environment.environment_id());
        Ok(Endpoint::from_name(format!("kalareach-{prefix}-{name}"))?)
    }
    #[cfg(not(windows))]
    {
        Ok(Endpoint::from_path(environment.runtime_dir().join(name))?)
    }
}

/// Returns where a plugin-host descriptor is published.
#[must_use]
pub fn descriptor_path(environment: &EnvironmentPaths) -> PathBuf {
    environment.runtime_dir().join(protocol::DESCRIPTOR_FILE)
}

/// Publishes a descriptor, atomically and owner-only.
///
/// # Errors
///
/// Returns [`LaunchError::Endpoint`] when the file cannot be written.
pub fn publish_descriptor(
    environment: &EnvironmentPaths,
    descriptor: &HostDescriptor,
) -> LaunchResult<()> {
    let document = serde_json::to_vec(descriptor).map_err(|error| LaunchError::Refused {
        detail: format!("the descriptor could not be written: {error}"),
    })?;
    kr_ipc::paths::write_owner_only_file(&descriptor_path(environment), &document)?;
    Ok(())
}

/// Reads a published descriptor, if there is one.
///
/// Nothing in it is acted on until the process behind the endpoint has answered a challenge.
///
/// # Errors
///
/// Returns [`LaunchError::Endpoint`] when the file cannot be read, or [`LaunchError::Refused`] when
/// it is not a descriptor this host wrote.
pub fn read_descriptor(environment: &EnvironmentPaths) -> LaunchResult<Option<HostDescriptor>> {
    let path = descriptor_path(environment);
    let Some(bytes) = kr_ipc::paths::read_owner_only_file(&path, MAX_DESCRIPTOR_BYTES)? else {
        return Ok(None);
    };
    let descriptor: HostDescriptor =
        serde_json::from_slice(&bytes).map_err(|error| LaunchError::Refused {
            detail: format!(
                "{} is not a plugin host descriptor: {error}",
                path.display()
            ),
        })?;
    if descriptor.protocol != protocol::PROTOCOL {
        return Err(LaunchError::Refused {
            detail: format!(
                "the descriptor names protocol {}, and this host speaks {}",
                descriptor.protocol,
                protocol::PROTOCOL
            ),
        });
    }
    if descriptor.environment_id != environment.environment_id() {
        return Err(LaunchError::Refused {
            detail: "the descriptor names a different environment from its directory".to_owned(),
        });
    }
    Ok(Some(descriptor))
}

/// Removes a published descriptor.
///
/// # Errors
///
/// Returns [`LaunchError::Refused`] when a present descriptor cannot be removed.
pub fn retire_descriptor(environment: &EnvironmentPaths) -> LaunchResult<()> {
    match std::fs::remove_file(descriptor_path(environment)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LaunchError::Refused {
            detail: format!("the descriptor could not be retired: {error}"),
        }),
    }
}

/// What keeps one reservation one host's.
///
/// The launcher holds this for as long as the host it started is running. It owns the rendezvous
/// endpoint that reservation was made on, so a second claim against it reaches this and nothing
/// else: the connection is accepted, refused without a word, and counted. Dropping the fence gives
/// the endpoint up, which is what a launcher does when the host it fenced is gone.
///
/// A fence rather than a record of every reservation this process ever accepted: a record would
/// grow for as long as the process ran, and this is one endpoint per running host.
#[derive(Debug)]
pub struct HostFence {
    reservation_id: ReservationId,
    duplicates: Arc<AtomicU64>,
    stop: tokio::sync::watch::Sender<bool>,
}

impl HostFence {
    /// Returns the reservation this fence holds.
    #[must_use]
    pub const fn reservation_id(&self) -> ReservationId {
        self.reservation_id
    }

    /// Returns how many second claims this reservation has refused.
    #[must_use]
    pub fn duplicate_claims(&self) -> u64 {
        self.duplicates.load(core::sync::atomic::Ordering::Acquire)
    }
}

impl Drop for HostFence {
    fn drop(&mut self) {
        let _told = self.stop.send(true);
    }
}

/// Holds one reservation's endpoint, refusing and counting every further claim on it.
fn fence(reservation_id: ReservationId, listener: Listener) -> HostFence {
    let duplicates = Arc::new(AtomicU64::new(0));
    let (stop, mut stopping) = tokio::sync::watch::channel(false);
    let counted = Arc::clone(&duplicates);
    tokio::spawn(async move {
        // The listener is held for as long as the fence is, and is given up only when the fence is
        // dropped. A fence that stopped listening while its holder still believed it owned the
        // address would be the opposite of what it is for. A listener that keeps failing is waited
        // on rather than abandoned, because spinning on it would cost a core for nothing.
        loop {
            tokio::select! {
                _stopped = stopping.changed() => return,
                accepted = listener.accept() => {
                    // Whatever arrived, this reservation already has its host. The connection is
                    // dropped without an answer and counted, because two processes claiming one
                    // reservation is something a host should be able to see. A connection that
                    // failed on arrival is a claim that arrived all the same.
                    counted.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
                    if accepted.is_err() {
                        tokio::time::sleep(core::time::Duration::from_millis(50)).await;
                    }
                }
            }
        }
    });
    HostFence {
        reservation_id,
        duplicates,
        stop,
    }
}

/// A reservation to start one plugin host, with the rendezvous endpoint already listening.
///
/// Created before anything is started, so a host that connects immediately finds a listener. The
/// reservation is consumed by [`Self::accept`], which is what makes exactly one rendezvous per
/// reservation succeed.
pub struct HostReservation {
    reservation_id: ReservationId,
    environment_id: EnvironmentId,
    listener: Listener,
    endpoint: Endpoint,
}

impl core::fmt::Debug for HostReservation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HostReservation")
            .field("reservation_id", &self.reservation_id)
            .field("environment_id", &self.environment_id)
            .finish_non_exhaustive()
    }
}

impl HostReservation {
    /// Reserves a launch and binds the rendezvous endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchError::Endpoint`] when the endpoint cannot be bound.
    pub fn open(environment: &EnvironmentPaths) -> LaunchResult<Self> {
        let reservation_id = ReservationId::new(kr_ipc::new_uuid());
        let endpoint = rendezvous_endpoint(environment, reservation_id)?;
        let listener = Listener::bind(&endpoint)?;
        Ok(Self {
            reservation_id,
            environment_id: environment.environment_id(),
            listener,
            endpoint,
        })
    }

    /// Returns the reservation identifier.
    #[must_use]
    pub const fn reservation_id(&self) -> ReservationId {
        self.reservation_id
    }

    /// Returns the rendezvous endpoint the host is told to connect to.
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Builds the argument vector a host is started with.
    ///
    /// Nothing in it is a secret, and nothing is assembled by interpolating text into a command
    /// line: the vector is passed as a vector.
    #[must_use]
    pub fn arguments(&self, environment: &EnvironmentPaths, packages: &Path) -> Vec<String> {
        vec![
            "--reservation".to_owned(),
            self.reservation_id.to_string(),
            "--environment".to_owned(),
            self.environment_id.to_string(),
            "--rendezvous".to_owned(),
            self.endpoint.as_text(),
            "--runtime-dir".to_owned(),
            environment.runtime_root().display().to_string(),
            "--state-dir".to_owned(),
            environment.state_root().display().to_string(),
            "--packages-dir".to_owned(),
            packages.display().to_string(),
        ]
    }

    /// Returns the job label for this reservation.
    #[must_use]
    pub fn label(&self) -> String {
        format!("kr-plugin-host-{}", self.reservation_id)
    }

    /// Returns the directory this launch's host process runs in.
    #[must_use]
    pub fn working_directory(&self, environment: &EnvironmentPaths) -> PathBuf {
        environment.state_dir().join("services").join(self.label())
    }

    /// Builds the launch plan for one host executable.
    #[must_use]
    pub fn plan(
        &self,
        environment: &EnvironmentPaths,
        program: impl Into<PathBuf>,
        packages: &Path,
    ) -> HostLaunchPlan {
        HostLaunchPlan {
            label: self.label(),
            program: program.into(),
            arguments: self.arguments(environment, packages),
            jobs_directory: environment.jobs_dir(),
            working_directory: self.working_directory(environment),
        }
    }

    /// Waits for the host's claim, checks it, publishes the descriptor and acknowledges it.
    ///
    /// `launched` is the process identity the service manager reported. It is compared with the
    /// connecting peer's own identity and with what the claim says, which is what stops another
    /// process from claiming a reservation it was not started for.
    ///
    /// `within` bounds the whole exchange and not just the connection: a peer that connects and
    /// then says nothing is a peer that would otherwise hold a startup open for ever. A connection
    /// that is refused does not end the wait either; the deadline does, and the last refusal is
    /// what the caller is told about.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchError::NoRendezvous`] when nothing claims the reservation in time, or
    /// [`LaunchError::Refused`] when the last claim did not match the reservation or the peer.
    pub async fn accept(
        self,
        environment: &EnvironmentPaths,
        launched: &ProcessStartIdentity,
        within: core::time::Duration,
    ) -> LaunchResult<(HostDescriptor, HostFence)> {
        let deadline = tokio::time::Instant::now() + within;
        let deadline_ms = u64::try_from(within.as_millis()).unwrap_or(u64::MAX);
        let mut refused: Option<LaunchError> = None;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return Err(refused.unwrap_or(LaunchError::NoRendezvous { deadline_ms }));
            }
            let accepted = match tokio::time::timeout(left, self.listener.accept()).await {
                Ok(accepted) => accepted?,
                Err(_elapsed) => {
                    return Err(refused.unwrap_or(LaunchError::NoRendezvous { deadline_ms }));
                }
            };
            let (connection, peer) = accepted;
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let received =
                tokio::time::timeout(left, self.receive(environment, launched, connection, peer))
                    .await;
            match received {
                Ok(Ok((descriptor, mut writer))) => {
                    // Publishing and acknowledging are inside the deadline too: a host waiting to
                    // be told it was accepted is a host that is not serving, and a launcher that
                    // took an unbounded time over either would be holding it there.
                    // Publishing writes a file, flushes it and renames it, and a timer cannot
                    // interrupt any of that: a publication this launcher stops waiting for still
                    // finishes. So it is fenced rather than merely bounded -- it writes nothing once
                    // a later launch has taken the environment's publication -- and the wait for it
                    // is inside the deadline like every other stage.
                    let turn = publication_turn(self.environment_id);
                    // Set when this acceptance stops waiting, however it stops: its own deadline,
                    // or a caller that dropped it. A publication still queued behind somebody
                    // else's then publishes nothing, because a descriptor for a startup nobody is
                    // waiting on is one no worker should find.
                    let abandoned = Arc::new(core::sync::atomic::AtomicBool::new(false));
                    let waiting = Waiting {
                        abandoned: Arc::clone(&abandoned),
                        finished: false,
                    };
                    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                    let publishing = {
                        let paths = environment.clone();
                        let descriptor = descriptor.clone();
                        let abandoned = Arc::clone(&abandoned);
                        tokio::task::spawn_blocking(move || {
                            publish_in_turn(&turn, &abandoned, &paths, &descriptor)
                        })
                    };
                    match tokio::time::timeout(left, publishing).await {
                        Ok(Ok(Ok(()))) => {}
                        Ok(Ok(Err(error))) => return Err(error),
                        Ok(Err(error)) => {
                            return Err(LaunchError::Refused {
                                detail: format!("the descriptor could not be published: {error}"),
                            });
                        }
                        Err(_elapsed) => return Err(LaunchError::NoRendezvous { deadline_ms }),
                    }
                    waiting.finished();

                    // The host does not serve workers until it has this. Publishing a descriptor
                    // for a process that had already started answering would mean a worker could
                    // reach a host the launcher was still deciding about. A deadline already spent
                    // is a startup this launcher is no longer waiting for, so the acknowledgement
                    // is not sent at all rather than sent late.
                    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if left.is_zero() {
                        return Err(LaunchError::NoRendezvous { deadline_ms });
                    }
                    let accepted = RendezvousAccepted {
                        reservation_id: descriptor.reservation_id,
                        environment_id: descriptor.environment_id,
                        endpoint: descriptor.endpoint.clone(),
                    };
                    match tokio::time::timeout(left, writer.write_message(&accepted)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => return Err(LaunchError::Endpoint(error)),
                        Err(_elapsed) => return Err(LaunchError::NoRendezvous { deadline_ms }),
                    }
                    // One reservation, one host: the endpoint stays this launcher's, and every
                    // later claim on it is refused and counted.
                    return Ok((descriptor, fence(self.reservation_id, self.listener)));
                }
                // One refused claim is not the end of the wait: the process the service manager
                // started may still be on its way. The refusal is kept and reported if nothing
                // better arrives.
                Ok(Err(error)) => refused = Some(error),
                Err(_elapsed) => {
                    return Err(refused.unwrap_or(LaunchError::NoRendezvous { deadline_ms }));
                }
            }
        }
    }

    async fn receive(
        &self,
        environment: &EnvironmentPaths,
        launched: &ProcessStartIdentity,
        connection: Connection,
        peer: PeerIdentity,
    ) -> LaunchResult<(HostDescriptor, kr_ipc::framed::FrameWriter)> {
        peer.authorise(kr_ipc::paths::current_uid())?;
        let (mut reader, writer) = split(connection, StreamKind::Control);
        let claim: HostRendezvous = reader.read_message().await?;
        check_rendezvous(&claim)?;

        if claim.reservation_id != self.reservation_id {
            return Err(LaunchError::Refused {
                detail: "the claim names a reservation this launcher did not make".to_owned(),
            });
        }
        if claim.environment_id != self.environment_id {
            return Err(LaunchError::Refused {
                detail: "the claim names a different environment".to_owned(),
            });
        }
        if &claim.process_start_identity != launched {
            return Err(LaunchError::Refused {
                detail: format!(
                    "the claim is from process {} and the service manager started {}",
                    claim.process_start_identity.pid.get(),
                    launched.pid.get()
                ),
            });
        }
        // The kernel's own account of who connected, which the claim cannot choose. A peer the
        // kernel will not name is a peer this launcher cannot check, and an unverifiable claim is
        // refused rather than taken on the strength of a signature anyone holding the key could
        // make.
        let Some(pid) = peer.pid else {
            return Err(LaunchError::Refused {
                detail: "the connecting process has no kernel identity to check the claim against"
                    .to_owned(),
            });
        };
        let observed = kr_ipc::identity::process_start_identity(pid).map_err(|error| {
            LaunchError::Refused {
                detail: format!("the connecting process is unreadable: {error}"),
            }
        })?;
        if !observed.matches(launched) {
            return Err(LaunchError::Refused {
                detail: format!(
                    "the connecting process is {} and the service manager started {}",
                    observed.pid.get(),
                    launched.pid.get()
                ),
            });
        }
        // The boot this launcher is running in. A claim carrying another boot's identity is a claim
        // from a recorded startup rather than from the process that just started.
        let boot = kr_ipc::identity::boot_identity().map_err(|error| LaunchError::Refused {
            detail: format!("this host's boot identity is unreadable: {error}"),
        })?;
        if claim.boot_identity != boot {
            return Err(LaunchError::Refused {
                detail: "the claim names a different boot from the one this launcher is running in"
                    .to_owned(),
            });
        }
        let expected = host_endpoint(environment)?.as_text();
        if claim.endpoint != expected {
            return Err(LaunchError::Refused {
                detail: format!(
                    "the claim serves {} and this environment's plugin endpoint is {expected}",
                    claim.endpoint
                ),
            });
        }
        Ok((
            HostDescriptor {
                protocol: protocol::PROTOCOL.to_owned(),
                environment_id: claim.environment_id,
                reservation_id: claim.reservation_id,
                endpoint: claim.endpoint,
                boot_identity: claim.boot_identity,
                process_start_identity: claim.process_start_identity,
                host_public_key: claim.host_public_key,
            },
            writer,
        ))
    }
}

/// Starts a plugin host and takes its identity proof.
///
/// The whole sequence in one call: reserve, bind the rendezvous, start the job, record what the
/// service manager reported, wait for the claim, check it, publish the descriptor.
///
/// # Errors
///
/// Returns the launch, rendezvous or verification failure.
pub async fn start(
    environment: &EnvironmentPaths,
    program: impl Into<PathBuf>,
    packages: &Path,
    starter: HostStarter<'_>,
    within: core::time::Duration,
) -> LaunchResult<(HostDescriptor, HostFence)> {
    // The rendezvous listener exists before anything is started, so a host that connects the
    // instant it starts finds somebody listening.
    let reservation = HostReservation::open(environment)?;
    let plan = reservation.plan(environment, program, packages);
    // Made before anything is started, so a launch cannot fail on a directory that does not exist
    // yet. It is inside this environment's state directory, which this host owns and which holds
    // nothing a person keeps.
    kr_ipc::paths::create_private_tree(environment.state_root(), &plan.working_directory)?;
    let launched = match starter(&plan) {
        HostStartOutcome::Started(identity) => identity,
        HostStartOutcome::NotStarted { detail } => return Err(LaunchError::NotStarted { detail }),
        HostStartOutcome::Uncertain { detail, pid } => {
            return Err(LaunchError::Uncertain { detail, pid });
        }
    };
    reservation.accept(environment, &launched, within).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn an_identity() -> HostIdentity {
        HostIdentity::generate(EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes(
            [1; 16],
        )))
        .expect("this host can describe itself")
    }

    fn descriptor_of(identity: &HostIdentity, endpoint: &str) -> HostDescriptor {
        HostDescriptor {
            protocol: protocol::PROTOCOL.to_owned(),
            environment_id: identity.environment_id(),
            reservation_id: ReservationId::new(kr_protocol::scalars::Uuid::from_bytes([2; 16])),
            endpoint: endpoint.to_owned(),
            boot_identity: identity.boot_identity().clone(),
            process_start_identity: identity.process_start_identity().clone(),
            host_public_key: *identity.public_key(),
        }
    }

    #[test]
    fn a_claim_is_signed_by_the_key_it_presents() {
        let identity = an_identity();
        let reservation = ReservationId::new(kr_protocol::scalars::Uuid::from_bytes([2; 16]));
        let claim = identity
            .rendezvous(reservation, "/run/kr/p.sock")
            .expect("the claim is signed");
        check_rendezvous(&claim).expect("the claim verifies");

        // A claim whose endpoint was changed after signing does not verify, so a host cannot be
        // made to appear to serve an endpoint it did not name.
        let mut tampered = claim.clone();
        tampered.endpoint = "/run/kr/other.sock".to_owned();
        assert!(check_rendezvous(&tampered).is_err());

        // Nor one whose key was swapped for another's.
        let other = an_identity();
        let mut swapped = claim;
        swapped.host_public_key = *other.public_key();
        assert!(check_rendezvous(&swapped).is_err());
    }

    #[test]
    fn a_challenge_answer_is_checked_against_the_descriptor() {
        let identity = an_identity();
        let descriptor = descriptor_of(&identity, "/run/kr/p.sock");
        let nonce = fresh_challenge().expect("a challenge");
        let proof = identity
            .answer(&nonce, &descriptor.endpoint)
            .expect("the answer is signed");
        check_proof(&descriptor, &nonce, &proof).expect("the answer verifies");

        // A different challenge is a different transcript, so an answer cannot be replayed.
        let replayed = fresh_challenge().expect("a challenge");
        assert!(check_proof(&descriptor, &replayed, &proof).is_err());

        // An answer for another endpoint is refused before its signature is even considered.
        let elsewhere = identity
            .answer(&nonce, "/run/kr/other.sock")
            .expect("the answer is signed");
        let error = check_proof(&descriptor, &nonce, &elsewhere)
            .expect_err("an answer for another endpoint is refused");
        assert!(error.to_string().contains("different endpoint"));
    }

    #[test]
    fn an_answer_from_another_process_is_refused() {
        let identity = an_identity();
        let descriptor = descriptor_of(&identity, "/run/kr/p.sock");
        let nonce = fresh_challenge().expect("a challenge");
        let mut proof = identity
            .answer(&nonce, &descriptor.endpoint)
            .expect("the answer is signed");
        proof.process_start_identity = ProcessStartIdentity::new(
            proof.process_start_identity.pid.get() + 1,
            kr_protocol::identity::ProcessStartSource::LinuxProcStat,
            7,
        );
        let error =
            check_proof(&descriptor, &nonce, &proof).expect_err("a different process is refused");
        assert!(error.to_string().contains("different process"));
    }

    #[test]
    fn two_hosts_of_one_environment_have_different_keys() {
        let first = an_identity();
        let second = an_identity();
        assert_ne!(first.public_key(), second.public_key());
    }

    #[test]
    fn a_descriptor_round_trips_and_a_foreign_protocol_is_refused() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        let identity = HostIdentity::generate(host.environment_id()).expect("an identity");
        let endpoint = host_endpoint(&environment).expect("an endpoint");
        let descriptor = HostDescriptor {
            protocol: protocol::PROTOCOL.to_owned(),
            environment_id: host.environment_id(),
            reservation_id: ReservationId::new(kr_protocol::scalars::Uuid::from_bytes([2; 16])),
            endpoint: endpoint.as_text(),
            boot_identity: identity.boot_identity().clone(),
            process_start_identity: identity.process_start_identity().clone(),
            host_public_key: *identity.public_key(),
        };

        assert!(
            read_descriptor(&environment).expect("a read").is_none(),
            "an environment with no plugin host has no descriptor"
        );
        publish_descriptor(&environment, &descriptor).expect("the descriptor is published");
        assert_eq!(
            read_descriptor(&environment).expect("a read"),
            Some(descriptor.clone())
        );

        let mut foreign = descriptor;
        foreign.protocol = "kr-plugin-host/99".to_owned();
        publish_descriptor(&environment, &foreign).expect("the descriptor is published");
        let error = read_descriptor(&environment).expect_err("a foreign protocol is refused");
        assert!(error.to_string().contains("kr-plugin-host/99"));

        retire_descriptor(&environment).expect("the descriptor is retired");
        assert!(read_descriptor(&environment).expect("a read").is_none());
        retire_descriptor(&environment).expect("a second retirement is quiet");
    }

    #[tokio::test]
    async fn the_argument_vector_carries_only_non_secret_facts() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        let reservation = HostReservation::open(&environment).expect("a reservation");
        let arguments = reservation.arguments(&environment, std::path::Path::new("/var/packages"));
        assert!(arguments.contains(&"--reservation".to_owned()));
        assert!(arguments.contains(&"--rendezvous".to_owned()));
        assert!(arguments.contains(&"--packages-dir".to_owned()));
        assert!(
            !arguments.iter().any(|argument| argument.contains("key")
                || argument.contains("token")
                || argument.contains("secret")),
            "no secret reaches the job definition"
        );
        assert!(reservation.label().starts_with("kr-plugin-host-"));
    }

    #[tokio::test]
    async fn a_launcher_that_starts_nothing_says_so() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        let outcome = start(
            &environment,
            "/nonexistent/kr-plugin-host",
            std::path::Path::new("/var/packages"),
            &|_plan| HostStartOutcome::NotStarted {
                detail: "no such file".to_owned(),
            },
            core::time::Duration::from_millis(50),
        )
        .await
        .expect_err("nothing started");
        assert!(matches!(outcome, LaunchError::NotStarted { .. }));
        // Nothing was published, so no worker can be told there is a host.
        assert!(read_descriptor(&environment).expect("a read").is_none());
    }

    #[tokio::test]
    async fn a_host_that_never_reports_itself_times_out_without_publishing() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        let identity = HostIdentity::generate(host.environment_id()).expect("an identity");
        let outcome = start(
            &environment,
            "/nonexistent/kr-plugin-host",
            std::path::Path::new("/var/packages"),
            &|_plan| HostStartOutcome::Started(identity.process_start_identity().clone()),
            core::time::Duration::from_millis(50),
        )
        .await
        .expect_err("nothing reported itself");
        assert!(matches!(outcome, LaunchError::NoRendezvous { .. }));
        assert!(read_descriptor(&environment).expect("a read").is_none());
    }

    #[tokio::test]
    async fn a_peer_that_connects_and_says_nothing_does_not_hold_a_startup_open() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        let identity = HostIdentity::generate(host.environment_id()).expect("an identity");
        let reservation = HostReservation::open(&environment).expect("a reservation");
        let endpoint = reservation.endpoint().clone();

        // Somebody connects to the rendezvous endpoint and never writes a claim. The deadline
        // covers receiving the claim, not just accepting the connection, so this ends.
        let silent = tokio::spawn(async move {
            let connection = Connection::connect(&endpoint).await.expect("connects");
            // Held open, saying nothing, for longer than the launcher's deadline.
            tokio::time::sleep(core::time::Duration::from_secs(2)).await;
            drop(connection);
        });

        let started = std::time::Instant::now();
        let outcome = reservation
            .accept(
                &environment,
                identity.process_start_identity(),
                core::time::Duration::from_millis(200),
            )
            .await
            .expect_err("a peer that says nothing does not complete a startup");
        let waited = started.elapsed();
        assert!(
            matches!(outcome, LaunchError::NoRendezvous { .. }),
            "{outcome}"
        );
        assert!(
            waited < core::time::Duration::from_secs(1),
            "the launcher waited {waited:?}"
        );
        assert!(read_descriptor(&environment).expect("a read").is_none());
        silent.abort();
    }

    #[test]
    fn a_publication_a_later_launch_superseded_writes_nothing() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        let identity =
            HostIdentity::generate(host.environment_id()).expect("this host can describe itself");
        let descriptor = descriptor_of(&identity, "/run/kr/first.sock");

        let turn = publication_turn(host.environment_id());
        let waiting = core::sync::atomic::AtomicBool::new(false);

        // The launch that reaches publication first publishes first.
        let later = descriptor_of(&identity, "/run/kr/second.sock");
        publish_in_turn(&turn, &waiting, &environment, &later).expect("the first publication wins");

        // A launch that reached publication later, with a number of its own, publishes after it.
        let third = descriptor_of(&identity, "/run/kr/third.sock");
        publish_in_turn(&turn, &waiting, &environment, &third).expect("a later launch publishes");
        let published = read_descriptor(&environment)
            .expect("a read")
            .expect("a descriptor");
        assert_eq!(published.endpoint, "/run/kr/third.sock");

        // A launch that stopped waiting publishes nothing, however long it was queued: replacing a
        // descriptor for a startup nobody is waiting on is the one thing it must not do.
        let abandoned = core::sync::atomic::AtomicBool::new(true);
        let refused = publish_in_turn(&turn, &abandoned, &environment, &descriptor)
            .expect_err("an abandoned publication is refused");
        assert!(matches!(refused, LaunchError::Refused { .. }), "{refused}");
        let published = read_descriptor(&environment)
            .expect("a read")
            .expect("a descriptor");
        assert_eq!(published.endpoint, "/run/kr/third.sock");

        // Another environment's publications are its own.
        let elsewhere = kr_ipc::testing::TempHost::create();
        let their_turn = publication_turn(elsewhere.environment_id());
        let their_identity =
            HostIdentity::generate(elsewhere.environment_id()).expect("an identity");
        let theirs = descriptor_of(&their_identity, "/run/kr/fourth.sock");
        publish_in_turn(&their_turn, &waiting, &elsewhere.environment(), &theirs)
            .expect("another environment is unaffected");
    }

    #[tokio::test]
    async fn one_reservation_is_one_host_and_a_second_claim_is_refused_and_counted() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        let reservation = HostReservation::open(&environment).expect("a reservation");
        let reservation_id = reservation.reservation_id();
        let endpoint = reservation.endpoint().clone();
        // The fence takes the endpoint the reservation was made on, which is the only address a
        // claim for that reservation can arrive at.
        let fenced = fence(reservation_id, reservation.listener);
        assert_eq!(fenced.reservation_id(), reservation_id);

        // Nobody else can take that address while the fence holds it, so a second launch cannot
        // put its own listener where this reservation's claims would arrive.
        assert!(
            Listener::bind(&endpoint).is_err(),
            "the reservation's endpoint was not held"
        );

        // A second process claiming this reservation gets no answer: the fence accepts it and
        // drops it, which its own connect sees as the peer going. Either way the claim arrived,
        // and the fence counted it.
        for _ in 0..3 {
            let attempt = Connection::connect(&endpoint).await;
            if let Ok(connection) = attempt {
                drop(connection);
            }
        }
        let deadline = std::time::Instant::now() + core::time::Duration::from_secs(5);
        while fenced.duplicate_claims() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the fence counted none of the second claims"
            );
            tokio::time::sleep(core::time::Duration::from_millis(10)).await;
        }

        // And the address goes when the fence does, so a launcher that gave one host up is not
        // still holding what a replacement needs.
        drop(fenced);
        let deadline = std::time::Instant::now() + core::time::Duration::from_secs(5);
        loop {
            if Listener::bind(&endpoint).is_ok() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the reservation's endpoint was never given up"
            );
            tokio::time::sleep(core::time::Duration::from_millis(10)).await;
        }
    }
}
