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
//!   <app data>/pairing-budget   this computer's tries with each code
//!   <app data>/pairing          the hosts it is paired with, and an attempt still waiting
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

use kr_client::pairing::candidate::{AttemptState, Candidate, CandidateRoom, Pairing};
use kr_client::pairing::clock::DeviceClock;
use kr_client::pairing::failure::{FailureKind, PairingFailure};
use kr_client::pairing::invitation::{Invitation, InvitationSummary, origin_host, read_invitation};
use kr_client::pairing::link::{EndpointPool, IrohLink};
use kr_client::pairing::paired::{PairedHost, PairedHosts};
use kr_client::pairing::room::RoomConnector;
use kr_crypto::store::{SecretStore, open_store};
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
    /// What a person is shown of an invitation read from the pasteboard and not yet used.
    pub invitation: Option<InvitationSummary>,
    /// The hosts this computer is paired with.
    pub hosts: Vec<HostRow>,
}

/// What reading the pasteboard found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PasteView {
    /// The invitation, when there was one and it is held for the person to use.
    pub invitation: Option<InvitationSummary>,
    /// Why nothing is held, when nothing is.
    pub failure: Option<FailureKind>,
    /// True when the pasteboard held an invitation and was cleared.
    pub cleared: bool,
    /// True when the invitation named another service and the person declined it.
    pub declined: bool,
}

/// An invitation read from the pasteboard, held until it is used, dropped or too old.
struct Held {
    invitation: Invitation,
    read_at: Instant,
}

/// This computer as a device that pairs with hosts.
pub struct Device {
    identity: DeviceIdentity,
    pairing: Arc<Pairing>,
    origin_file: PathBuf,
    origin: Mutex<RendezvousOrigin>,
    held: Mutex<Option<Held>>,
    running: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    progress: watch::Sender<AttemptState>,
    contact: Mutex<BTreeMap<DeviceId, bool>>,
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
}

impl Parts {
    /// This computer's own parts: the platform's secret store, or the documented directory under
    /// `data` where it has none; the pairing service over the platform's TLS verifier; endpoints on
    /// every interface; and this boot's clock.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the secret store, the TLS verifier or the clock cannot be set.
    pub fn platform(data: &Path) -> Result<Self> {
        let opened =
            open_store(identity::SECRET_SERVICE, &data.join("secrets")).map_err(|error| {
                CommandError::local_failure(format!(
                    "the secret store could not be opened: {error}"
                ))
            })?;
        let clock = DeviceClock::current().map_err(CommandError::from)?;
        let room = RoomConnector::platform().map_err(|error| {
            CommandError::local_failure(format!(
                "the pairing service's TLS could not be set: {error}"
            ))
        })?;
        Ok(Self {
            secrets: Arc::from(opened.store),
            room: Arc::new(room),
            bind: None,
            clock: Arc::new(clock),
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
            data.join("pairing-budget"),
            Arc::clone(&identity.secrets),
            identity::SCOPE,
        )
        .map_err(|error| {
            CommandError::local_failure(format!("the attempt budget could not be opened: {error}"))
        })?;
        let hosts = PairedHosts::open(data.join("pairing")).map_err(|failure| failed(&failure))?;
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
            link: Arc::new(IrohLink::new(Arc::new(pool))),
            hosts: Arc::new(hosts),
        };
        let origin_file = data.join("pairing-origin");
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
            running: Mutex::new(None),
            progress: watch::channel(AttemptState::Idle).0,
            contact: Mutex::new(BTreeMap::new()),
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
                HostRow::of(host, in_contact)
            })
            .collect();
        PairingView {
            origin: OriginView::of(&lock(&self.origin)),
            device_name: self.identity.name.as_str().to_owned(),
            state: self.progress.borrow().clone(),
            invitation: self.held_summary(),
            hosts,
        }
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

    /// Holds `invitation` until the person uses it, drops it, or [`HELD_FOR`] passes.
    #[must_use]
    pub fn hold(&self, invitation: Invitation) -> InvitationSummary {
        let summary = invitation.summary();
        *lock(&self.held) = Some(Held {
            invitation,
            read_at: Instant::now(),
        });
        (self.changed)();
        summary
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
            .filter(|held| held.read_at.elapsed() < HELD_FOR)
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
        if held
            .as_ref()
            .is_some_and(|held| held.read_at.elapsed() >= HELD_FOR)
        {
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
