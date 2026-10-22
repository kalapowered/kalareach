//! This computer as a device that pairs with hosts.
//!
//! One [`Device`] holds everything pairing needs on this computer: its keys and name, its attempt
//! budget and its records of hosts on its own disk, the origin it sends codes through, the one
//! attempt it may be making, and an invitation read from the pasteboard and not yet used. The
//! commands reach it and nothing else does; what the page is sent is [`PairingView`], which holds
//! no secret, key, transcript or identifier.
//!
//! ```text
//!   <app data>/secrets          keys and the budget's key, when the platform has no store
//!   <app data>/pairing-budget   this computer's tries with each code ([`BUDGET_DIRECTORY`])
//!   <app data>/pairing          the hosts it is paired with, and an attempt still waiting
//!                               ([`HOSTS_DIRECTORY`])
//!   <app data>/pairing-origin   the origin it sends codes through, when it is not the default
//! ```

pub mod hosts;
pub mod identity;

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use companion_platform::scan::Sources;
use kr_client::pairing::candidate::{AttemptState, Candidate, CandidateRoom, Pairing};
use kr_client::pairing::clock::DeviceClock;
use kr_client::pairing::failure::{FailureKind, PairingFailure};
use kr_client::pairing::invitation::{Invitation, InvitationSummary, origin_host, read_invitation};
use kr_client::pairing::link::{EndpointPool, HostLink, IrohLink};
use kr_client::pairing::paired::{PairedHost, PairedHosts};
use kr_client::pairing::room::RoomConnector;
use kr_client::services::{ManagedPairingAdmission, PairingAdmissions, ServiceHttp};
use kr_crypto::store::SecretStore;
use kr_pairing::budget::DurableClientBudgetStore;
use kr_pairing::code::EnteredCode;
use kr_pairing::platform::PairingClock;
use kr_protocol::ids::{BuildId, DeviceId};
use kr_protocol::invitation::{DEFAULT_RENDEZVOUS_ORIGIN, default_rendezvous_origin};
use kr_protocol::pairing::RendezvousOrigin;
use serde::Serialize;
use tokio::sync::watch;

pub use hosts::HostRow;
pub use identity::DeviceIdentity;

use crate::error::{CommandError, Result};

/// How long a pasted invitation is held before it is dropped unused.
pub const HELD_FOR: Duration = Duration::from_secs(5 * 60);

/// The directory of this computer's tries with each code, under the application's data directory.
pub const BUDGET_DIRECTORY: &str = "pairing-budget";

/// The directory of the hosts this computer is paired with, under the application's data
/// directory.
pub const HOSTS_DIRECTORY: &str = "pairing";

/// The origin codes go through, as the page shows and changes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OriginView {
    /// The canonical origin.
    pub origin: String,
    /// Its host name, which is what a person is shown.
    pub host: String,
    /// True when it is the origin KalaReach ships with.
    pub is_default: bool,
}

impl OriginView {
    fn of(origin: &RendezvousOrigin) -> Self {
        Self {
            origin: origin.as_str().to_owned(),
            host: origin_host(origin).to_owned(),
            is_default: origin.as_str() == DEFAULT_RENDEZVOUS_ORIGIN,
        }
    }
}

/// Everything the pairing screen shows. None of it is a secret, a key, a transcript, a code or an
/// identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PairingView {
    /// The origin codes go through.
    pub origin: OriginView,
    /// The name this computer offers a host.
    pub device_name: String,
    /// Where the attempt has got to.
    pub state: AttemptState,
    /// What a person is shown of an invitation taken in and not yet used.
    pub invitation: Option<InvitationSummary>,
    /// Where this device reads a code from, besides the pasteboard.
    pub sources: Sources,
    /// The hosts this computer is paired with.
    pub hosts: Vec<HostRow>,
}

/// What taking an invitation in found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IntakeView {
    /// The invitation, when there was one and it is held for the person to use.
    pub invitation: Option<InvitationSummary>,
    /// Why nothing is held, when nothing is.
    pub failure: Option<FailureKind>,
    /// True when the pasteboard held an invitation and was cleared.
    pub cleared: bool,
    /// True when the invitation named another service and the person declined it.
    pub declined: bool,
    /// True when nothing was taken in because the person closed the scanner or the picker, or
    /// because a newer intake, a stop or an attempt came first. It is not a failure.
    pub cancelled: bool,
}

impl IntakeView {
    /// Nothing was taken in, and nothing is wrong.
    #[must_use]
    pub const fn cancelled() -> Self {
        Self {
            invitation: None,
            failure: None,
            cleared: false,
            declined: false,
            cancelled: true,
        }
    }
}

/// One intake of an invitation: it holds what it reads only while it is the one under way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Intake(u64);

/// Which intake is under way, by number, and whether it has read its text.
#[derive(Default)]
struct Intaking {
    number: u64,
    /// The text is read. What remains is the person's answer to the alert, and holding.
    read: bool,
}

/// An invitation taken in, held until it is used, dropped or too old.
struct Held {
    invitation: Invitation,
    read_at: Instant,
    /// The wall clock at the reading, because a phone's monotonic clock stops while it sleeps.
    read_wall: std::time::SystemTime,
}

impl Held {
    fn is_stale(&self) -> bool {
        self.read_at.elapsed() >= HELD_FOR
            || self
                .read_wall
                .elapsed()
                .is_ok_and(|elapsed| elapsed >= HELD_FOR)
    }
}

/// This computer as a device that pairs with hosts.
pub struct Device {
    identity: DeviceIdentity,
    pairing: Arc<Pairing>,
    origin_file: PathBuf,
    origin: Mutex<RendezvousOrigin>,
    held: Mutex<Option<Held>>,
    /// The intake under way: a newer one, a stop and an attempt's start void it.
    intake: Mutex<Intaking>,
    sources: Mutex<Sources>,
    running: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    progress: watch::Sender<AttemptState>,
    contact: Mutex<BTreeMap<DeviceId, bool>>,
    /// The host this application's commands go to, remembered across runs in `use_file`.
    in_use: Mutex<Option<DeviceId>>,
    use_file: PathBuf,
    changed: Box<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Device")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn failed(failure: &PairingFailure) -> CommandError {
    CommandError::local_failure(failure.to_string())
}

/// What a test puts a computer's own way of reaching a host behind: it is handed that way and
/// returns the one the device uses.
pub type LinkWrap = Box<dyn FnOnce(Arc<dyn HostLink>) -> Arc<dyn HostLink> + Send>;

/// What a device is made of besides its records: where its secrets live, how it opens a room,
/// where its endpoints bind and the clock it counts on. The product's come from the platform
/// ([`Parts::platform`]); a test gives its own.
pub struct Parts {
    /// The store this computer's keys and its budget's key live in.
    pub secrets: Arc<dyn SecretStore>,
    /// How it opens a room.
    pub room: Arc<dyn CandidateRoom>,
    /// The address its endpoints bind to, when not every interface.
    pub bind: Option<SocketAddr>,
    /// The clock its attempts are measured on.
    pub clock: Arc<dyn PairingClock + Send + Sync>,
    /// What this computer's own way of reaching a host is put behind, when it is put behind
    /// anything: a test holds or refuses the connections it is asked for.
    pub link: Option<LinkWrap>,
    /// The managed service this computer asks for an admission to reach a host through one of the
    /// service's relays before it has paired with it, when it asks any.
    pub managed: Option<ManagedService>,
}

/// The managed service a device asks to admit it through a relay, and how it reaches it.
#[derive(Clone)]
pub struct ManagedService {
    /// The origin the service answers as, which is also the origin its relays are named under.
    pub origin: kr_protocol::service::GatewayOrigin,
    /// How this computer reaches it.
    pub http: Arc<dyn ServiceHttp>,
}

impl Parts {
    /// This computer's own parts: `secrets`, the application's one secure store
    /// (`companion_platform::secrets::open`, the same store the account keeps its tokens in); the
    /// pairing service over the platform's TLS verifier; endpoints on every interface; and
    /// `clock`, this boot's.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the TLS verifier cannot be set.
    pub fn platform(secrets: Arc<dyn SecretStore>, clock: DeviceClock) -> Result<Self> {
        let room = RoomConnector::platform().map_err(|error| {
            CommandError::local_failure(format!(
                "the pairing service's TLS could not be set: {error}"
            ))
        })?;
        let origin =
            kr_protocol::service::GatewayOrigin::new(kr_client::services::account::ACCOUNT_ORIGIN)
                .map_err(|error| CommandError::local_failure(error.to_string()))?;
        let http = kr_client::services::HttpService::with(
            origin.clone(),
            kr_client::services::HttpDeadlines::default(),
            kr_client::services::managed_response_limits(),
        )
        .map_err(|error| {
            CommandError::local_failure(format!(
                "this computer cannot reach the managed service: {error}"
            ))
        })?;
        Ok(Self {
            secrets,
            room: Arc::new(room),
            bind: None,
            clock: Arc::new(clock),
            link: None,
            managed: Some(ManagedService {
                origin,
                http: Arc::new(http),
            }),
        })
    }
}

impl Device {
    /// This computer as a device made of `parts`, with its records under `data`.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the secret store, the budget or the records cannot be opened.
    pub fn with(
        data: &Path,
        parts: Parts,
        changed: impl Fn() + Send + Sync + 'static,
    ) -> Result<Arc<Self>> {
        let identity = DeviceIdentity::in_store(parts.secrets)?;
        let budget = DurableClientBudgetStore::open(
            data.join(BUDGET_DIRECTORY),
            Arc::clone(&identity.secrets),
            identity::SCOPE,
        )
        .map_err(|error| {
            CommandError::local_failure(format!("the attempt budget could not be opened: {error}"))
        })?;
        let hosts =
            PairedHosts::open(data.join(HOSTS_DIRECTORY)).map_err(|failure| failed(&failure))?;
        let pool = EndpointPool::new(identity.keys.transport.clone());
        let pool = match parts.bind {
            Some(address) => pool.bound_to(address),
            None => pool,
        };
        let build = BuildId::new(format!("kalareach-companion/{}", env!("CARGO_PKG_VERSION")))
            .map_err(|error| CommandError::local_failure(error.to_string()))?;
        let pairing = Pairing {
            candidate: Candidate::new(
                identity.keys.clone(),
                identity.name.clone(),
                identity.platform,
                build,
            ),
            budget: Arc::new(budget),
            clock: parts.clock,
            room: parts.room,
            link: {
                let link = IrohLink::new(Arc::new(pool));
                // A relay of the managed service carries a pairing only for a device it has been
                // told to admit, so this computer asks it as it dials; a relay of any other
                // service is never named to it.
                let link = match parts.managed {
                    Some(managed) => {
                        let signer = Arc::new(crate::recovery::DeviceSigner::new(
                            identity.keys.authorisation.clone(),
                        ));
                        let admit = ManagedPairingAdmission::new(
                            managed.origin.clone(),
                            managed.http,
                            signer,
                        );
                        let admissions =
                            PairingAdmissions::new(Arc::new(admit), &managed.origin)
                                .map_err(|error| CommandError::local_failure(error.to_string()))?;
                        link.admitted_by(Arc::new(admissions))
                    }
                    None => link,
                };
                let own: Arc<dyn HostLink> = Arc::new(link);
                match parts.link {
                    Some(behind) => behind(own),
                    None => own,
                }
            },
            hosts: Arc::new(hosts),
        };
        let origin_file = data.join("pairing-origin");
        let use_file = data.join("command-host");
        let in_use = std::fs::read_to_string(&use_file)
            .ok()
            .and_then(|text| text.trim().parse::<DeviceId>().ok());
        let origin = std::fs::read_to_string(&origin_file)
            .ok()
            .and_then(|text| RendezvousOrigin::new(text.trim()).ok())
            .unwrap_or_else(default_rendezvous_origin);
        Ok(Arc::new(Self {
            identity,
            pairing: Arc::new(pairing),
            origin_file,
            origin: Mutex::new(origin),
            held: Mutex::new(None),
            intake: Mutex::new(Intaking::default()),
            sources: Mutex::new(Sources::default()),
            running: Mutex::new(None),
            progress: watch::channel(AttemptState::Idle).0,
            contact: Mutex::new(BTreeMap::new()),
            in_use: Mutex::new(in_use),
            use_file,
            changed: Box::new(changed),
        }))
    }

    /// Starts telling the page about every change of the attempt, and takes up an attempt that
    /// was waiting for its owner when this computer last ran.
    pub fn start(self: &Arc<Self>) {
        let mut shown = self.progress.subscribe();
        let device = Arc::downgrade(self);
        tauri::async_runtime::spawn(async move {
            while shown.changed().await.is_ok() {
                match device.upgrade() {
                    Some(device) => (device.changed)(),
                    None => return,
                }
            }
        });
        if matches!(self.pairing.hosts.waiting_attempt(), Ok(Some(_))) {
            let _ = self.run(|pairing, progress| async move {
                let _ = pairing.resume(&progress).await;
            });
        }
    }

    /// This computer's identity.
    #[must_use]
    pub const fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// The pairing client this computer runs.
    #[must_use]
    pub const fn pairing(&self) -> &Arc<Pairing> {
        &self.pairing
    }

    /// Everything the pairing screen shows.
    #[must_use]
    pub fn view(&self) -> PairingView {
        let contact = lock(&self.contact).clone();
        let in_use = *lock(&self.in_use);
        let hosts = self
            .pairing
            .hosts
            .list()
            .unwrap_or_default()
            .iter()
            .rev()
            .map(|host| {
                let in_contact = host
                    .is_owner()
                    .then(|| contact.get(&host.host_device_id).copied().unwrap_or(false));
                HostRow::of(host, in_use == Some(host.host_device_id), in_contact)
            })
            .collect();
        PairingView {
            origin: OriginView::of(&lock(&self.origin)),
            device_name: self.identity.name.as_str().to_owned(),
            state: self.progress.borrow().clone(),
            invitation: self.held_summary(),
            sources: *lock(&self.sources),
            hosts,
        }
    }

    /// The paired host the page named by `reference`, when this computer has one by that name.
    #[must_use]
    pub fn host_by_reference(&self, reference: &str) -> Option<PairedHost> {
        self.pairing
            .hosts
            .list()
            .unwrap_or_default()
            .into_iter()
            .find(|host| hosts::reference_of(host) == reference)
    }

    /// The host this application's commands went to when it last ran or was last told, when this
    /// computer is still paired with it.
    #[must_use]
    pub fn host_in_use(&self) -> Option<PairedHost> {
        let id = (*lock(&self.in_use))?;
        self.pairing
            .hosts
            .list()
            .unwrap_or_default()
            .into_iter()
            .find(|host| host.host_device_id == id)
    }

    /// The host this computer paired with last, when it has paired with any.
    #[must_use]
    pub fn newest_host(&self) -> Option<PairedHost> {
        self.pairing
            .hosts
            .list()
            .unwrap_or_default()
            .into_iter()
            .last()
    }

    /// Records that this application's commands go to `host`, and keeps it for the next run.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the choice could not be kept, and then it is not made: a
    /// choice the next run would not find is not one this run reports.
    pub fn use_host(&self, host: DeviceId) -> Result<()> {
        let staging = self.use_file.with_extension("new");
        std::fs::write(&staging, host.to_string())
            .and_then(|()| std::fs::rename(&staging, &self.use_file))
            .map_err(|error| {
                CommandError::local_failure(format!(
                    "this computer could not keep which host you chose: {error}"
                ))
            })?;
        *lock(&self.in_use) = Some(host);
        (self.changed)();
        Ok(())
    }

    /// Whether this computer holds a record of being paired with `host`.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the records could not be read.
    pub fn is_paired_with(&self, host: DeviceId) -> Result<bool> {
        Ok(self
            .pairing
            .hosts
            .list()
            .map_err(|failure| failed(&failure))?
            .iter()
            .any(|each| each.host_device_id == host))
    }

    /// Forgets a paired host: this computer's record of it goes, and with it the choice of it, and
    /// says whether it was the host in use.
    ///
    /// A local action that reaches nothing, so it works for a host that no longer answers this
    /// computer, one that revoked it among them. The host keeps whatever it holds of this device;
    /// that is the host's to remove.
    ///
    /// A write of the records can report a failure after the record is gone, as one does whose
    /// last step, making the rename durable, fails. What the records hold decides: a host no longer
    /// in them is forgotten whatever the write said, and the rest of the forgetting is done, so no
    /// connection is kept to a host this computer does not list.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the records could not be changed, and then nothing is.
    pub fn forget_host(&self, host: DeviceId) -> Result<bool> {
        if let Err(failure) = self.pairing.hosts.forget(host) {
            // Still listed, or not readable: the host is not known to be forgotten.
            if self.is_paired_with(host).unwrap_or(true) {
                return Err(failed(&failure));
            }
        }
        let was_in_use = {
            let mut in_use = lock(&self.in_use);
            let was = *in_use == Some(host);
            if was {
                *in_use = None;
            }
            was
        };
        if was_in_use {
            // A choice left behind names no record, so nothing reads it as a host in use.
            let _ = std::fs::remove_file(&self.use_file);
        }
        lock(&self.contact).remove(&host);
        (self.changed)();
        Ok(was_in_use)
    }

    /// The hosts this computer is an owner of, which it watches for confirmations.
    #[must_use]
    pub fn owner_hosts(&self) -> Vec<PairedHost> {
        self.pairing
            .hosts
            .list()
            .unwrap_or_default()
            .into_iter()
            .filter(PairedHost::is_owner)
            .collect()
    }

    /// Records whether this computer is in contact with the host `host`.
    pub fn set_contact(&self, host: DeviceId, in_contact: bool) {
        let before = lock(&self.contact).insert(host, in_contact);
        if before != Some(in_contact) {
            (self.changed)();
        }
    }

    /// Changes the origin codes go through. What a person types is trimmed of surrounding space
    /// and one trailing `/`, and then must be a canonical origin.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for anything that is not an HTTPS origin, and a refusal while an
    /// attempt runs, because the origin is part of what a code is proved against.
    pub fn set_origin(&self, typed: &str) -> Result<OriginView> {
        if self.attempt_running() {
            return Err(CommandError::refused(
                "the service cannot change while an attempt is running",
            ));
        }
        let trimmed = typed.trim();
        let trimmed = trimmed.strip_suffix('/').unwrap_or(trimmed);
        let origin = RendezvousOrigin::new(trimmed).map_err(|error| {
            CommandError::invalid(format!(
                "that is not a service this device can use: {error}"
            ))
        })?;
        let _ = std::fs::write(&self.origin_file, origin.as_str());
        *lock(&self.origin) = origin.clone();
        (self.changed)();
        Ok(OriginView::of(&origin))
    }

    /// Starts pairing with a code a person typed, through the origin this computer uses.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for text that is not ten characters of the pairing alphabet, and
    /// a refusal while another attempt runs.
    pub fn start_code(self: &Arc<Self>, typed: &str) -> Result<()> {
        let code = EnteredCode::parse(typed).map_err(|_| {
            CommandError::invalid("a code has ten characters, and never contains 0, O, I or l")
        })?;
        let origin = lock(&self.origin).clone();
        self.run(move |pairing, progress| async move {
            let _ = pairing.pair_by_code(&origin, &code, &progress).await;
        })
    }

    /// Reads text taken from the pasteboard as an invitation, against the origin this computer
    /// uses.
    ///
    /// # Errors
    ///
    /// Returns how the text failed to be an invitation.
    pub fn read(&self, text: &str) -> std::result::Result<Invitation, PairingFailure> {
        let configured = lock(&self.origin).clone();
        read_invitation(text, &configured)
    }

    /// Begins taking an invitation in. Any intake still waiting is void from now on, and holds
    /// nothing when its text arrives. The invitation already held is let go of: a person has one
    /// in hand at a time, so closing the scanner or the picker leaves none rather than the one
    /// before it.
    pub fn begin_intake(&self) -> Intake {
        let mut intaking = lock(&self.intake);
        intaking.number += 1;
        intaking.read = false;
        let intake = Intake(intaking.number);
        let let_go = lock(&self.held).take().is_some();
        drop(intaking);
        if let_go {
            (self.changed)();
        }
        intake
    }

    /// Whether `intake` is still the one under way: nothing newer, no stop and no attempt has
    /// voided it.
    #[must_use]
    pub fn owns(&self, intake: Intake) -> bool {
        lock(&self.intake).number == intake.0
    }

    /// Says that `intake` has read its text, when it is still the one under way.
    pub fn mark_read(&self, intake: Intake) {
        let mut intaking = lock(&self.intake);
        if intaking.number == intake.0 {
            intaking.read = true;
        }
    }

    /// Voids the intake under way, when there is one.
    pub fn void_intakes(&self) {
        lock(&self.intake).number += 1;
    }

    /// The application stopped being in front. What was read and is not used yet is let go of: the
    /// invitation held for the person, and an intake that has read its text and waits for the
    /// answer to the alert, which then holds nothing. An intake still waiting for the scanner or
    /// the picker is left to that reader, which ends itself when the application leaves; a
    /// question the system asks, such as the camera's, also stops the application being in front,
    /// and must not end the scan it is asked for.
    pub fn suspend(&self) {
        let mut intaking = lock(&self.intake);
        if intaking.read {
            intaking.number += 1;
            intaking.read = false;
        }
        let let_go = lock(&self.held).take().is_some();
        drop(intaking);
        if let_go {
            (self.changed)();
        }
    }

    /// Holds `invitation` for `intake`, when it is still the intake under way, and drops it when
    /// [`HELD_FOR`] has passed. The answer is `None` when a newer intake, a stop or an attempt's
    /// start voided it first.
    #[must_use]
    pub fn hold_for(
        self: &Arc<Self>,
        intake: Intake,
        invitation: Invitation,
    ) -> Option<InvitationSummary> {
        // The check and the holding are one step under the intake's lock, so a stop that voids the
        // intake is either before both or after both.
        let intaking = lock(&self.intake);
        if intaking.number != intake.0 {
            return None;
        }
        let summary = invitation.summary();
        *lock(&self.held) = Some(Held {
            invitation,
            read_at: Instant::now(),
            read_wall: std::time::SystemTime::now(),
        });
        drop(intaking);
        // The invitation leaves when its time is up, whether or not anything looks at it again.
        let device = Arc::downgrade(self);
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(HELD_FOR).await;
            if let Some(device) = device.upgrade() {
                let dropped = {
                    let mut held = lock(&device.held);
                    let stale = held.as_ref().is_some_and(Held::is_stale);
                    if stale {
                        *held = None;
                    }
                    stale
                };
                if dropped {
                    (device.changed)();
                }
            }
        });
        (self.changed)();
        Some(summary)
    }

    /// Records where this device reads a code from, and tells the page.
    pub fn set_sources(&self, sources: Sources) {
        *lock(&self.sources) = sources;
        (self.changed)();
    }

    /// Starts pairing with the invitation held from the pasteboard.
    ///
    /// # Errors
    ///
    /// Returns a refusal when no invitation is held, it is too old, or another attempt runs.
    pub fn start_held(self: &Arc<Self>) -> Result<()> {
        if self.attempt_running() {
            return Err(CommandError::refused("an attempt is already running"));
        }
        let held = lock(&self.held)
            .take()
            .filter(|held| !held.is_stale())
            .ok_or_else(|| CommandError::refused("no invitation is waiting to be used"))?;
        match held.invitation {
            Invitation::Code(code) => self.run(move |pairing, progress| async move {
                let _ = pairing
                    .pair_by_code(&code.origin, &code.code, &progress)
                    .await;
            }),
            Invitation::Direct(payload) => self.run(move |pairing, progress| async move {
                let _ = pairing.pair_directly(&payload, &progress).await;
            }),
        }
    }

    /// Ends the attempt on this computer, drops a held invitation, and returns the screen to its
    /// start. A host keeps its side of an attempt until it expires or its owner declines it.
    pub async fn stop(&self) {
        // An intake still waiting must hold nothing once this has ended what is held.
        self.void_intakes();
        let running = lock(&self.running).take();
        if let Some(running) = running {
            running.abort();
            // Once the task has ended nothing more of the attempt is written, so the record of
            // it can go.
            let _ = running.await;
        }
        let _ = self.pairing.hosts.clear_attempt();
        *lock(&self.held) = None;
        self.progress.send_replace(AttemptState::Idle);
        (self.changed)();
    }

    fn attempt_running(&self) -> bool {
        lock(&self.running)
            .as_ref()
            .is_some_and(|running| !running.inner().is_finished())
    }

    /// What a person is shown of the held invitation, dropping it once it is too old.
    fn held_summary(&self) -> Option<InvitationSummary> {
        let mut held = lock(&self.held);
        if held.as_ref().is_some_and(Held::is_stale) {
            *held = None;
        }
        held.as_ref().map(|held| held.invitation.summary())
    }

    /// Runs one attempt, unless another is running.
    fn run<F, Running>(self: &Arc<Self>, attempt: F) -> Result<()>
    where
        F: FnOnce(Arc<Pairing>, watch::Sender<AttemptState>) -> Running + Send + 'static,
        Running: Future<Output = ()> + Send + 'static,
    {
        let mut running = lock(&self.running);
        if running
            .as_ref()
            .is_some_and(|running| !running.inner().is_finished())
        {
            return Err(CommandError::refused("an attempt is already running"));
        }
        // What an intake still waiting would hold is no longer wanted: an attempt has begun, and an
        // invitation held beside it is not the one this attempt uses.
        self.void_intakes();
        *lock(&self.held) = None;
        let pairing = Arc::clone(&self.pairing);
        let progress = self.progress.clone();
        let device = Arc::downgrade(self);
        *running = Some(tauri::async_runtime::spawn(async move {
            attempt(pairing, progress).await;
            if let Some(device) = device.upgrade() {
                (device.changed)();
            }
        }));
        Ok(())
    }
}
