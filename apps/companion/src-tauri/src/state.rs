//! What the backend holds between commands.
//!
//! One connection, this computer as a device that pairs, its owner confirmations, one draft store,
//! and one record of where the last export was allowed to be written. Nothing here is reachable
//! from the WebView except through the commands, and a command returns protocol values rather than
//! handles: there is nothing the page can keep and use later.

use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, RwLock, TryLockError};

use kr_client::Session;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::EnvironmentId;

use crate::connection::{Connection, Standing};
use crate::contact::{ContactOwner, Publication, Target};
use crate::device::Device;
use crate::error::{CommandError, Result};
use crate::owner::Owner;
use crate::pairing::IntakePlatform;
use crate::recovery::Recovery;
use crate::sync_service::SyncService;

/// Why the pairing records are not open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordsNotOpen {
    /// The device is locked. iOS keeps what the records are kept in out of reach until the person
    /// unlocks the device, and the records are opened then.
    Locked,
    /// The records could not be opened, for the cause given.
    Failed(String),
}

/// The backend's long-lived state.
#[derive(Debug)]
pub struct AppState {
    /// Which host the commands go to, the connection to it and how contact with each host stands.
    contact: Arc<ContactOwner>,
    /// Held across the device step of a choice or a forget, so that two are made one after the
    /// other and what the device records is never at odds with the choice the owner holds. It holds
    /// no fact.
    choice_gate: Mutex<()>,
    device: OnceLock<Arc<Device>>,
    /// Why the pairing records are not open, when they are not.
    records_failure: RwLock<Option<RecordsNotOpen>>,
    /// Held for the length of one try at opening the pairing records, so that two tries (the
    /// application's start and an unlock) are made one after the other.
    opening_records: Mutex<()>,
    owner: OnceLock<Arc<Owner>>,
    revocations: OnceLock<Arc<crate::revocation::Revocations>>,
    intake: OnceLock<Arc<dyn IntakePlatform>>,
    sync_service: OnceLock<Arc<SyncService>>,
    sync_clients: OnceLock<Arc<dyn crate::services::SyncServices>>,
    recovery: OnceLock<Arc<Recovery>>,
    push: OnceLock<Arc<crate::push::PushDesk>>,
    inbox: Arc<crate::inbox::InboxDesk>,
    mailbox: OnceLock<Arc<crate::mailbox::MailboxDesk>>,
    settings: OnceLock<Arc<crate::settings::Settings>>,
    drafts: Arc<crate::drafts::DraftDesk>,
    questions: crate::questions::QuestionDesk,
    shares: Arc<crate::sharing::ShareDesk>,
    retained: crate::retained::Deletions,
    paired_links: Arc<crate::standing::PairedLinks>,
    export_destinations: Mutex<Vec<std::path::PathBuf>>,
    dropped_files: Mutex<Vec<std::path::PathBuf>>,
    /// Where a suite has paused the state's own steps.
    #[cfg(feature = "testing")]
    pauses: Arc<testing::Pauses>,
}

/// A choice of host that has been made ready: the host it is for, and what starts the task that
/// keeps its connection once the choice has its number.
pub struct Started {
    /// The host the choice is for.
    pub target: Target,
    /// Starts the task for the choice number it is given.
    pub spawn: Box<dyn FnOnce(u64) -> tauri::async_runtime::JoinHandle<()> + Send>,
}

impl AppState {
    /// Builds the state of an application that has not connected to anything yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            contact: Arc::new(ContactOwner::new()),
            choice_gate: Mutex::new(()),
            device: OnceLock::new(),
            records_failure: RwLock::new(None),
            opening_records: Mutex::new(()),
            owner: OnceLock::new(),
            revocations: OnceLock::new(),
            intake: OnceLock::new(),
            sync_service: OnceLock::new(),
            sync_clients: OnceLock::new(),
            recovery: OnceLock::new(),
            push: OnceLock::new(),
            inbox: Arc::new(crate::inbox::InboxDesk::default()),
            mailbox: OnceLock::new(),
            settings: OnceLock::new(),
            drafts: Arc::new(crate::drafts::DraftDesk::default()),
            questions: crate::questions::QuestionDesk::default(),
            shares: Arc::new(crate::sharing::ShareDesk::default()),
            retained: crate::retained::Deletions::default(),
            paired_links: Arc::new(crate::standing::PairedLinks::default()),
            export_destinations: Mutex::new(Vec::new()),
            dropped_files: Mutex::new(Vec::new()),
            #[cfg(feature = "testing")]
            pauses: Arc::default(),
        }
    }

    /// The owner of every host's contact.
    #[must_use]
    pub const fn contact_owner(&self) -> &Arc<ContactOwner> {
        &self.contact
    }

    /// Makes a new choice of host: `start` makes the choice ready (it may write the device's
    /// records), the host chosen before is let go, and the task `start` made ready is begun for the
    /// new choice's number and kept.
    ///
    /// The choice gate is held for all of it, so two choices made at once are made one after the
    /// other and the later one stands. The task begins after the owner has accepted the choice, so
    /// its first write finds its choice current.
    ///
    /// # Errors
    ///
    /// Returns what `start` returns, and then nothing has changed.
    pub fn choose_host(&self, reason: &str, start: impl FnOnce() -> Result<Started>) -> Result<()> {
        #[cfg(feature = "testing")]
        self.pauses.before_gate.wait();
        let _gate = self.lock_choice_gate();
        #[cfg(feature = "testing")]
        self.pauses.before_start.wait();
        let started = start()?;
        let chosen = self.contact.choose(&started.target, reason);
        let choice = chosen.value;
        let task = (started.spawn)(choice);
        let stale = self.contact.set_task(choice, task);
        #[cfg(feature = "testing")]
        self.pauses.before_cleanup.wait();
        // The sessions opened on the host before are let go with it, and the tokens that opened
        // them are forgotten, after the owner tells the host changed: a call that read the host
        // before the change then finds the generation moved when it hands its link over.
        self.paired_links.close_all();
        drop((chosen.disposal, stale));
        Ok(())
    }

    /// Takes the lock a choice of host is made under. A free lock is taken at once. One that is held
    /// is waited for through [`blocking`], so the task that waits does not keep its worker from the
    /// tasks of the same runtime, nor the runtime's timers and I/O, which go with a worker that
    /// waits in a plain lock.
    fn lock_choice_gate(&self) -> MutexGuard<'_, ()> {
        match self.choice_gate.try_lock() {
            Ok(gate) => gate,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => blocking(|| {
                self.choice_gate
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
            }),
        }
    }

    /// Runs `work` under the lock a choice of host is made under, so that it is done before a
    /// choice or a forget that is under way, or after it, and never in the middle of one.
    pub fn under_the_choice_gate<T>(&self, work: impl FnOnce() -> T) -> T {
        let _gate = self.lock_choice_gate();
        work()
    }

    /// Forgets the host `host` under the lock a choice of host is made under, and ends the
    /// connection to it when it was the one in use.
    ///
    /// `forget` removes this computer's record of the host. It runs inside the lock, so a choice
    /// made at the same time is made before it or after it. The owner drops what it holds of the
    /// host, and when the host was in use its task ends and no host is: the task of the choice may
    /// have been in the middle of reaching the host, and its result is dropped because its choice
    /// is no longer the current one.
    ///
    /// # Errors
    ///
    /// Returns what `forget` returns, and then nothing has changed.
    pub fn forget_host(
        &self,
        host: kr_protocol::ids::DeviceId,
        reason: &str,
        forget: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let _gate = self.lock_choice_gate();
        forget()?;
        let forgotten = self.contact.forget(host, reason);
        if forgotten.value {
            self.paired_links.close_all();
        }
        Ok(())
    }

    /// Installs a live connection with no host in use, for a suite that holds a connection of its
    /// own making.
    #[cfg(feature = "testing")]
    pub fn connected(&self, connection: Connection) {
        drop(self.contact.install(connection));
    }

    /// The session every command goes through.
    ///
    /// # Errors
    ///
    /// Returns `HOST_NOT_CONFIGURED` when there is no connection, which is the same answer the
    /// interface gets for a host that went away.
    pub fn session(&self) -> Result<Arc<Session>> {
        self.contact
            .held()
            .as_ref()
            .map(Connection::session)
            .ok_or_else(CommandError::not_connected)
    }

    /// The live connection itself, for what has to open another to the same host.
    ///
    /// # Errors
    ///
    /// Returns `HOST_NOT_CONFIGURED` when there is no connection.
    pub fn connection(&self) -> Result<Connection> {
        self.contact.held().ok_or_else(CommandError::not_connected)
    }

    /// Replaces the connection `session` is with one the host admits, when it is the one held to
    /// the host on this machine and that host has withdrawn it.
    ///
    /// A revision of the whole host withdraws the connections the host admitted before it, and a
    /// revocation of one device is not one. The host refuses every request on a withdrawn connection
    /// and keeps it open, so a connection that is held and not asked for what it is refused goes on
    /// being refused, and nothing ends it. The connection's supervision calls this when the host
    /// refuses a request on it as not permitted or answers one with an outcome it does not know,
    /// whichever path of the application made the request, except a read sent with
    /// `read_unsignalled`: that one asks whether the connection was withdrawn, and its refusal is
    /// its answer. The host is asked for its devices, which it lists to any connection of this
    /// computer's that it admits and to no other: a refusal of that over this connection, and an
    /// answer over another, say it was withdrawn, where one request's refusal for its own reasons
    /// does not. The other takes its place, and the withdrawn one is ended, which the supervision
    /// takes up in turn.
    pub async fn replace_if_withdrawn(&self, session: &Arc<Session>) {
        let Some(connection) = self.contact.held() else {
            return;
        };
        // Only the connection to the host on this machine is replaced. A host this device is paired
        // with closes each network connection whose registration it withdrew, so the supervision
        // already sees that end and connects again; nothing here replaces one.
        if Arc::ptr_eq(&connection.session(), session)
            && matches!(connection.standing(), Standing::Owner)
        {
            crate::settings::connected::listed_replacing(&connection, &self.replacer()).await;
        }
    }

    /// What replaces a withdrawn connection held to the host on this machine.
    #[must_use]
    pub fn replacer(&self) -> crate::connection::Replacer {
        let owner = Arc::clone(&self.contact);
        #[cfg(feature = "testing")]
        let pauses = Arc::clone(&self.pauses);
        Arc::new(move |withdrawn, fresh| {
            // The receiver is taken before the connection is installed, so that nothing the host
            // sends on it before the keeper takes it up is lost. The withdrawn session is closed
            // when the owner's answer is dropped, after the swap and outside the owner.
            let events = fresh.session().events();
            drop(owner.replaced(withdrawn, fresh, events));
            #[cfg(feature = "testing")]
            pauses.after_replacement.wait();
        })
    }

    /// The identity the host gave this device, the environment and the session of one connection,
    /// read together so they cannot belong to two hosts.
    ///
    /// # Errors
    ///
    /// Returns `HOST_NOT_CONFIGURED` when there is no connection, and a refusal when the
    /// connection is to the host on this machine, where this application is the owner and not a
    /// paired device.
    pub fn paired_snapshot(
        &self,
    ) -> Result<(kr_protocol::ids::DeviceId, EnvironmentId, Arc<Session>)> {
        let held = self.contact.held();
        let connection = held.as_ref().ok_or_else(CommandError::not_connected)?;
        match connection.standing() {
            Standing::Paired { device_id, .. } => Ok((
                *device_id,
                connection.environment_id(),
                connection.session(),
            )),
            Standing::Owner => Err(CommandError::refused(
                "this application is the owner of the host it is connected to, not a paired device",
            )),
        }
    }

    /// The sessions this application has opened on a host it is paired with.
    #[must_use]
    pub fn paired_links(&self) -> &Arc<crate::standing::PairedLinks> {
        &self.paired_links
    }

    /// The device and the host a session of a paired host is opened on, when this application is
    /// not the owner of the host it is connected to: the host it is connected to, or, while that
    /// connection is being taken up again, the one it was told to use.
    ///
    /// Opened sessions have connections of their own, so they do not wait for the main one. With
    /// no connection and no host in use the application is on its own machine, where a session's
    /// worker is reached by its descriptor. The device is asked after the owner has answered, so
    /// the owner is never held while the device's records are read.
    #[must_use]
    pub fn paired_context(&self) -> Option<PairedContext> {
        let device = self.device.get()?;
        loop {
            // The choice and the connection are read together, and read again once the device has
            // answered: a choice that completed meanwhile, or a connection that arrived, makes the
            // device's answer one about a host that is no longer the one in use.
            let stand = self.contact.stand();
            match stand.held.as_ref().map(Connection::standing) {
                Some(Standing::Owner) => return None,
                Some(Standing::Paired { host, .. }) => {
                    return Some(PairedContext {
                        device: Arc::clone(device),
                        host: (**host).clone(),
                    });
                }
                None => {
                    let host = device.host_in_use();
                    #[cfg(feature = "testing")]
                    self.pauses.device_read.wait();
                    if self.contact.stands_as(&stand) {
                        return host.map(|host| PairedContext {
                            device: Arc::clone(device),
                            host,
                        });
                    }
                }
            }
        }
    }

    /// The environment the connection belongs to, as the host stamped it on the handshake.
    ///
    /// # Errors
    ///
    /// Returns `HOST_NOT_CONFIGURED` when there is no connection.
    pub fn environment_id(&self) -> Result<EnvironmentId> {
        self.contact
            .held()
            .as_ref()
            .map(Connection::environment_id)
            .ok_or_else(CommandError::not_connected)
    }

    /// What the interface is told about the connection, as the revision it stands at.
    #[must_use]
    pub fn connection_state(&self) -> Publication {
        self.contact.snapshot()
    }

    /// Records this computer as a device that pairs, once it has been opened, and the platform it
    /// takes invitations in from.
    pub fn opened(
        &self,
        device: Arc<Device>,
        owner: Arc<Owner>,
        intake: Arc<dyn IntakePlatform>,
        revocations: Arc<crate::revocation::Revocations>,
    ) {
        let _ = self.device.set(device);
        let _ = self.owner.set(owner);
        let _ = self.intake.set(intake);
        let _ = self.revocations.set(revocations);
        // Once they are open, so that nothing that asks in between hears of a failure that is over.
        *self
            .records_failure
            .write()
            .expect("the state lock is not poisoned") = None;
    }

    /// Takes the turn to try opening this computer's pairing records, which is held until the try
    /// ends.
    pub fn opening_records(&self) -> MutexGuard<'_, ()> {
        self.opening_records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether this computer's pairing records are open.
    pub fn records_are_open(&self) -> bool {
        self.device.get().is_some()
    }

    /// Records why this computer's pairing records are not open, for the commands that need them to
    /// say. A later try that fails records its own reason in its place.
    pub fn records_not_opened(&self, why: RecordsNotOpen) {
        *self
            .records_failure
            .write()
            .expect("the state lock is not poisoned") = Some(why);
    }

    /// The failure of a command that needs the pairing records when they are not open.
    ///
    /// The words say what does not work and why, and what to do. They are stated: a locked device
    /// is told to be unlocked, which opens the records without another start, and any other cause
    /// is told to start the application again.
    fn records_unavailable(&self) -> CommandError {
        let lacks = "This device cannot pair with a host or use the hosts it is paired with";
        let words = match self
            .records_failure
            .read()
            .expect("the state lock is not poisoned")
            .as_ref()
        {
            Some(RecordsNotOpen::Locked) => format!(
                "{lacks} yet, because it is locked. KalaReach opens its pairing records when you \
                 unlock it."
            ),
            Some(RecordsNotOpen::Failed(cause)) => format!(
                "{lacks}, because its pairing records could not be opened. The cause: {}. Close \
                 KalaReach and open it again to try once more.",
                cause.trim_end_matches('.')
            ),
            None => format!(
                "{lacks}, because its pairing records are not open. Close KalaReach and open it \
                 again to try once more."
            ),
        };
        CommandError::stated(ErrorCode::ResourceUnavailable, words)
    }

    /// This computer as a device that pairs.
    ///
    /// # Errors
    ///
    /// Returns a stated local failure, with its cause, when its keys or records could not be
    /// opened.
    pub fn device(&self) -> Result<Arc<Device>> {
        self.device
            .get()
            .cloned()
            .ok_or_else(|| self.records_unavailable())
    }

    /// This computer's owner confirmations.
    ///
    /// # Errors
    ///
    /// Returns a stated local failure, with its cause, when its keys or records could not be
    /// opened.
    pub fn owner(&self) -> Result<Arc<Owner>> {
        self.owner
            .get()
            .cloned()
            .ok_or_else(|| self.records_unavailable())
    }

    /// This computer's revocations of devices on the hosts it owns.
    ///
    /// # Errors
    ///
    /// Returns a stated local failure, with its cause, when its keys or records could not be
    /// opened.
    pub fn revocations(&self) -> Result<Arc<crate::revocation::Revocations>> {
        self.revocations
            .get()
            .cloned()
            .ok_or_else(|| self.records_unavailable())
    }

    /// What a revocation is told of this application beyond this computer's records: the host on
    /// this computer, when the application is connected to it, the sync service, and settings.
    #[must_use]
    pub fn revocation_context(&self) -> crate::revocation::Context {
        crate::revocation::Context {
            local: self.connection().ok(),
            replace: self.replacer(),
            origin: self.sync_service().ok().map(|service| service.origin()),
            settings: self.settings().ok(),
            mailbox: self.mailbox.get().cloned(),
        }
    }

    /// Records the sync service this computer is set to use.
    pub fn sync_service_opened(&self, service: Arc<SyncService>) {
        let _ = self.sync_service.set(service);
    }

    /// Replaces the clients of the sync service this computer reaches. The first call is the one
    /// that stands, and it stands only if it comes before [`Self::sync_clients`] first runs: after
    /// that the clients are set, and this call changes nothing.
    pub fn sync_clients_replaced(&self, clients: Arc<dyn crate::services::SyncServices>) {
        let _ = self.sync_clients.set(clients);
    }

    /// The clients of the sync service that were installed with [`Self::sync_clients_replaced`] or
    /// made by [`Self::sync_clients`], when either has happened.
    #[must_use]
    pub fn installed_sync_clients(&self) -> Option<Arc<dyn crate::services::SyncServices>> {
        self.sync_clients.get().cloned()
    }

    /// The clients of the sync service this computer reaches: the ones installed with
    /// [`Self::sync_clients_replaced`], or the managed ones signing with `identity`'s key.
    #[must_use]
    pub fn sync_clients(
        &self,
        identity: &crate::device::DeviceIdentity,
    ) -> Arc<dyn crate::services::SyncServices> {
        Arc::clone(self.sync_clients.get_or_init(|| {
            Arc::new(crate::services::ManagedSyncServices::new(
                identity.keys.authorisation.clone(),
            ))
        }))
    }

    /// Records this computer's reader of its own mailbox, once it has been opened.
    pub fn mailbox_opened(&self, desk: Arc<crate::mailbox::MailboxDesk>) {
        let _ = self.mailbox.set(desk);
    }

    /// The inboxes of the hosts this device is paired with and is not using.
    #[must_use]
    pub fn inbox(&self) -> Arc<crate::inbox::InboxDesk> {
        Arc::clone(&self.inbox)
    }

    /// Records this phone's notifications, once they have been opened.
    pub fn push_opened(&self, desk: Arc<crate::push::PushDesk>) {
        let _ = self.push.set(desk);
    }

    /// This phone's notifications, when it has any: a computer has none.
    #[must_use]
    pub fn push(&self) -> Option<Arc<crate::push::PushDesk>> {
        self.push.get().cloned()
    }

    /// Records this computer's recovery seed and bundle, once they have been opened.
    pub fn recovery_opened(&self, recovery: Arc<Recovery>) {
        let _ = self.recovery.set(recovery);
    }

    /// This computer's reader of its own mailbox.
    ///
    /// # Errors
    ///
    /// Returns a local failure when this computer's records could not be opened.
    pub fn mailbox(&self) -> Result<Arc<crate::mailbox::MailboxDesk>> {
        self.mailbox.get().cloned().ok_or_else(|| {
            CommandError::local_failure("this computer's reader of its mailbox is not open")
        })
    }

    /// The sync service this computer is set to use.
    ///
    /// # Errors
    ///
    /// Returns a local failure when this computer's data directory could not be found.
    pub fn sync_service(&self) -> Result<Arc<SyncService>> {
        self.sync_service.get().cloned().ok_or_else(|| {
            CommandError::local_failure("this computer's sync service setting could not be opened")
        })
    }

    /// This computer's recovery seed and bundle.
    ///
    /// # Errors
    ///
    /// Returns a local failure when this computer's keys or records could not be opened.
    pub fn recovery(&self) -> Result<Arc<Recovery>> {
        self.recovery.get().cloned().ok_or_else(|| {
            CommandError::local_failure("this computer's recovery records could not be opened")
        })
    }

    /// The person's settings.
    ///
    /// # Errors
    ///
    /// Returns a local failure when this computer's data directory could not be found.
    pub fn settings(&self) -> Result<Arc<crate::settings::Settings>> {
        self.settings.get().cloned().ok_or_else(|| {
            CommandError::local_failure("this computer's settings could not be opened")
        })
    }

    /// Where this computer takes invitations in from.
    ///
    /// # Errors
    ///
    /// Returns a stated local failure, with its cause, when its keys or records could not be
    /// opened.
    pub fn intake(&self) -> Result<Arc<dyn IntakePlatform>> {
        self.intake
            .get()
            .cloned()
            .ok_or_else(|| self.records_unavailable())
    }

    /// Remembers that the person chose this destination in a save dialog.
    ///
    /// An export writes only where a dialog put it. The WebView never names a path: it asks for a
    /// destination, the platform's own dialog answers, and the answer is kept here until the one
    /// write that uses it. Without this the export commands would be a general file write with a
    /// path the page chose.
    pub fn allow_export_to(&self, path: std::path::PathBuf) {
        let mut allowed = self
            .export_destinations
            .lock()
            .expect("the export lock is not poisoned");
        // A handful at most: a person can have several dialogs open, and an abandoned one should
        // not keep its destination writable for the life of the application.
        if allowed.len() >= MAX_PENDING_EXPORTS {
            allowed.remove(0);
        }
        allowed.push(path);
    }

    /// Takes back a destination the person chose, once, for one write.
    ///
    /// # Errors
    ///
    /// Returns `PERMISSION_DENIED` for any path that is not one a save dialog returned.
    pub fn take_export_destination(&self, path: &std::path::Path) -> Result<std::path::PathBuf> {
        let mut allowed = self
            .export_destinations
            .lock()
            .expect("the export lock is not poisoned");
        match allowed.iter().position(|each| each == path) {
            Some(index) => Ok(allowed.remove(index)),
            None => Err(CommandError::refused(
                "an export is written only to a destination the save dialog returned",
            )),
        }
    }

    /// Remembers a file the platform said was dropped on this window.
    ///
    /// The page is told what was dropped so it can show it, and the page passes the path back when
    /// the person attaches it. Remembering it here is what makes that safe: a path the page names
    /// on its own was never dropped, and the upload refuses it.
    pub fn dropped(&self, paths: impl IntoIterator<Item = std::path::PathBuf>) {
        let mut held = self
            .dropped_files
            .lock()
            .expect("the drop lock is not poisoned");
        for path in paths {
            if held.len() >= MAX_PENDING_DROPS {
                held.remove(0);
            }
            held.push(path);
        }
    }

    /// Takes back a dropped file, once, for one upload.
    ///
    /// # Errors
    ///
    /// Returns `PERMISSION_DENIED` for any path this window was not given.
    pub fn take_dropped_file(&self, path: &std::path::Path) -> Result<std::path::PathBuf> {
        let mut held = self
            .dropped_files
            .lock()
            .expect("the drop lock is not poisoned");
        match held.iter().position(|each| each == path) {
            Some(index) => Ok(held.remove(index)),
            None => Err(CommandError::refused(
                "a file is attached by dropping it on this window",
            )),
        }
    }

    /// The attempts to share, accept, take back and hand over that this application keeps.
    #[must_use]
    pub fn shares(&self) -> Arc<crate::sharing::ShareDesk> {
        Arc::clone(&self.shares)
    }

    /// The confirmations of deleting a copy that left the host, which wait for their deletion.
    #[must_use]
    pub const fn retained(&self) -> &crate::retained::Deletions {
        &self.retained
    }

    /// The questions this application has read, and the answers it keeps.
    #[must_use]
    pub const fn questions(&self) -> &crate::questions::QuestionDesk {
        &self.questions
    }

    /// Gives what this application keeps on this device its place under the data directory: the
    /// answers a host did not confirm, the drafts a person has not sent and the person's
    /// settings. The application does this once, at start, before any command can run.
    pub fn keep_under(&self, data: &std::path::Path) {
        let _ = self
            .settings
            .set(Arc::new(crate::settings::Settings::open(data)));
        self.questions.keep_at(crate::questions::kept_in(data));
        self.drafts.keep_at(data.to_path_buf());
        self.shares.keep_at(crate::sharing::kept_in(data));
    }

    /// The drafts this device keeps.
    #[must_use]
    pub fn drafts(&self) -> Arc<crate::drafts::DraftDesk> {
        Arc::clone(&self.drafts)
    }
}

/// The device and the host a session is opened on.
#[derive(Clone)]
pub struct PairedContext {
    /// This computer as a device that pairs.
    pub device: Arc<Device>,
    /// The host it is paired with and uses.
    pub host: kr_client::pairing::paired::PairedHost,
}

/// How many save destinations may be waiting for their write at once.
const MAX_PENDING_EXPORTS: usize = 8;

/// How many dropped files may be waiting to be attached at once.
const MAX_PENDING_DROPS: usize = 64;

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs `wait`, which blocks the thread, so that it keeps no worker of the runtime from the
/// runtime's other tasks: on a multi-threaded runtime `block_in_place` moves them to another worker.
/// On a runtime with one thread, where `block_in_place` panics, and with no runtime at all, the
/// thread blocks.
fn blocking<T>(wait: impl FnOnce() -> T) -> T {
    let multi_threaded = tokio::runtime::Handle::try_current().is_ok_and(|runtime| {
        runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
    });
    if multi_threaded {
        tokio::task::block_in_place(wait)
    } else {
        wait()
    }
}

/// Seams the application's own suites act through.
#[cfg(feature = "testing")]
pub mod testing {
    use std::sync::{Mutex, PoisonError, mpsc};

    use tokio::sync::oneshot;

    /// A pause a suite set at one place of the state's own steps. The step that reaches the place
    /// waits until the hold is released or dropped.
    #[derive(Debug)]
    pub struct Hold {
        reached: oneshot::Receiver<()>,
        release: mpsc::Sender<Release>,
    }

    /// What a hold tells the step that waits at it.
    #[derive(Clone, Copy, Debug)]
    enum Release {
        /// Go on.
        Go,
        /// Stop, as a panic in the step would stop it.
        Stop,
    }

    impl Hold {
        /// Resolves once a step has reached the place and waits there.
        pub async fn reached(&mut self) {
            let _ = (&mut self.reached).await;
        }

        /// Lets the waiting step go on.
        pub fn release(self) {
            let _ = self.release.send(Release::Go);
        }

        /// Stops the waiting step: it leaves the wait through `std::panic::resume_unwind`, as a
        /// panic in that step would leave it, with no panic message of its own.
        pub fn stop(self) {
            let _ = self.release.send(Release::Stop);
        }
    }

    /// One place a step can be paused at.
    #[derive(Debug, Default)]
    pub(super) struct Place(Mutex<Option<(oneshot::Sender<()>, mpsc::Receiver<Release>)>>);

    impl Place {
        fn set(&self) -> Hold {
            let (reached, reached_by) = oneshot::channel();
            let (release, released) = mpsc::channel();
            *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some((reached, released));
            Hold {
                reached: reached_by,
                release,
            }
        }

        /// Waits here when a suite paused this place, once. A step that waits here is a plain
        /// function, which a command calls from a task of Tauri's multi-threaded runtime, or a
        /// suite calls from a thread of its own, and it cannot await, so it waits as the choice
        /// gate does ([`super::blocking`]).
        pub(super) fn wait(&self) {
            let held = self.0.lock().unwrap_or_else(PoisonError::into_inner).take();
            if let Some((reached, released)) = held {
                let _ = reached.send(());
                if let Ok(Release::Stop) = super::blocking(|| released.recv()) {
                    std::panic::resume_unwind(Box::new("the held step was stopped"));
                }
            }
        }
    }

    /// Every place a step can be paused at.
    #[derive(Debug, Default)]
    pub(super) struct Pauses {
        pub(super) device_read: Place,
        pub(super) before_gate: Place,
        pub(super) before_start: Place,
        pub(super) before_cleanup: Place,
        pub(super) after_replacement: Place,
    }

    /// Where in the making of a choice of host a step is paused.
    #[derive(Clone, Copy, Debug)]
    pub enum ChoicePoint {
        /// Before the choice gate is taken: the choice is resolved and holds nothing.
        BeforeGate,
        /// Inside the choice gate, before the choice is made ready.
        BeforeStart,
        /// Inside the choice gate, after the owner has accepted the choice and before the sessions
        /// the host before held are let go.
        BeforeCleanup,
    }

    impl super::AppState {
        /// Pauses the next read of the device's records that `paired_context` makes, after the
        /// device has answered and before the owner is read again.
        #[must_use]
        pub fn hold_the_device_read(&self) -> Hold {
            self.pauses.device_read.set()
        }

        /// Pauses the next replacement of a withdrawn connection once the replacer has put the new
        /// connection in its place and dropped what the owner removed, which is where the withdrawn
        /// session has been closed. The pause is reached whether or not it was.
        #[must_use]
        pub fn hold_after_replacement(&self) -> Hold {
            self.pauses.after_replacement.set()
        }

        /// Pauses the next choice of a host at `point`; the choice gate is held at every point but
        /// the first.
        #[must_use]
        pub fn hold_the_choice_at(&self, point: ChoicePoint) -> Hold {
            match point {
                ChoicePoint::BeforeGate => self.pauses.before_gate.set(),
                ChoicePoint::BeforeStart => self.pauses.before_start.set(),
                ChoicePoint::BeforeCleanup => self.pauses.before_cleanup.set(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_application_is_unconnected_and_says_why() {
        let state = AppState::new();
        let connection = state.connection_state();
        assert!(!connection.connected);
        assert!(connection.reason.is_some());
        assert!(state.session().is_err());
        assert!(
            state.device().is_err(),
            "nothing pairs before the device is opened"
        );
    }

    /// When the pairing records could not be opened, every command that needs them says why in the
    /// person's words, and asks for nothing to wait for.
    #[test]
    fn commands_that_need_the_pairing_records_say_why_they_did_not_open() {
        let state = AppState::new();
        state.records_not_opened(RecordsNotOpen::Failed(
            "this device's boot could not be recorded: the disk is full".to_owned(),
        ));
        for error in [
            state.device().expect_err("not open"),
            state.owner().expect_err("not open"),
            state.intake().expect_err("not open"),
        ] {
            assert_eq!(error.code, ErrorCode::ResourceUnavailable);
            assert_eq!(error.user_action, "nothing", "waiting does not open them");
            assert!(
                error.message.contains("the disk is full"),
                "the cause is in the words: {}",
                error.message
            );
            assert!(
                error.message.contains("Close KalaReach and open it again"),
                "and so is what to do: {}",
                error.message
            );
        }
    }

    /// A locked device is told to be unlocked, and not to start the application again: closing
    /// it would leave the records as far out of reach as they were.
    #[test]
    fn a_locked_device_is_told_to_unlock_and_not_to_start_again() {
        let state = AppState::new();
        state.records_not_opened(RecordsNotOpen::Locked);
        let error = state.device().expect_err("not open");
        assert_eq!(error.code, ErrorCode::ResourceUnavailable);
        assert_eq!(error.user_action, "nothing", "the words say what to do");
        assert!(error.message.contains("locked"), "{}", error.message);
        assert!(error.message.contains("unlock"), "{}", error.message);
        assert!(
            !error.message.contains("open it again"),
            "closing the application does not unlock the device: {}",
            error.message
        );
    }

    /// KR-REQ-13.21: an export is written only where a save dialog put it; a path the page names
    /// is refused.
    #[test]
    fn an_export_destination_the_dialog_never_returned_is_refused() {
        let state = AppState::new();
        let error = state
            .take_export_destination(std::path::Path::new("/etc/passwd"))
            .expect_err("that path came from the page");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::PermissionDenied);
    }

    /// KR-REQ-13.21: a destination the dialog returned serves one write and no more.
    #[test]
    fn a_chosen_destination_is_usable_once_and_not_twice() {
        let state = AppState::new();
        let chosen = std::path::PathBuf::from("/tmp/session.json");
        state.allow_export_to(chosen.clone());
        assert!(state.take_export_destination(&chosen).is_ok());
        assert!(
            state.take_export_destination(&chosen).is_err(),
            "one dialog is one write"
        );
    }

    /// KR-REQ-13.21: a file is uploaded only when it was dropped on this window; a path the page
    /// names is refused.
    #[test]
    fn a_path_this_window_was_never_given_is_not_uploadable() {
        let state = AppState::new();
        let error = state
            .take_dropped_file(std::path::Path::new("/Users/someone/.ssh/id_ed25519"))
            .expect_err("that file was not dropped on this window");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::PermissionDenied);
    }

    /// KR-REQ-13.21: a dropped file serves one upload and no more.
    #[test]
    fn a_dropped_file_is_uploadable_once_and_not_twice() {
        let state = AppState::new();
        let dropped = std::path::PathBuf::from("/tmp/diagram.png");
        state.dropped([dropped.clone()]);
        assert!(state.take_dropped_file(&dropped).is_ok());
        assert!(
            state.take_dropped_file(&dropped).is_err(),
            "one drop is one upload"
        );
    }

    #[test]
    fn abandoned_destinations_do_not_accumulate_without_bound() {
        let state = AppState::new();
        for index in 0..MAX_PENDING_EXPORTS + 4 {
            state.allow_export_to(std::path::PathBuf::from(format!("/tmp/export-{index}")));
        }
        assert!(
            state
                .take_export_destination(std::path::Path::new("/tmp/export-0"))
                .is_err(),
            "the oldest abandoned destination is forgotten"
        );
        assert!(
            state
                .take_export_destination(std::path::Path::new(&format!(
                    "/tmp/export-{}",
                    MAX_PENDING_EXPORTS + 3
                )))
                .is_ok()
        );
    }

    /// A task that takes the choice gate while a choice holds it leaves its worker to the runtime's
    /// other tasks, whichever way it takes it: to run its work under the gate, to forget a host
    /// under it, or to make a choice under it. The runtime has one worker: a task that blocked it
    /// would stop every other task of the runtime, and its timers and I/O with them.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_task_that_waits_for_the_choice_gate_leaves_its_worker_to_the_runtime() {
        use std::time::Duration;

        let state = Arc::new(AppState::new());
        for leg in 0..3 {
            let mut hold = state.hold_the_choice_at(testing::ChoicePoint::BeforeStart);
            // A choice that holds the gate, on a thread of its own, as the application runs one.
            let choosing = std::thread::spawn({
                let state = Arc::clone(&state);
                move || {
                    state.choose_host("reaching", || {
                        Err(CommandError::local_failure("the choice is not made"))
                    })
                }
            });
            hold.reached().await;
            let waiting = tokio::spawn({
                let state = Arc::clone(&state);
                async move {
                    match leg {
                        0 => state.under_the_choice_gate(|| ()),
                        1 => drop(state.forget_host(
                            kr_protocol::ids::DeviceId::new(
                                kr_protocol::scalars::Uuid::from_bytes([7; 16]),
                            ),
                            "forgetting",
                            || Ok(()),
                        )),
                        _ => drop(state.choose_host("reaching", || {
                            Err(CommandError::local_failure("the choice is not made"))
                        })),
                    }
                }
            });
            // This thread is not a worker: it lets the task reach the gate and wait there, and
            // then looks for a task that only a free worker can run.
            std::thread::sleep(Duration::from_millis(300));
            assert!(
                !waiting.is_finished(),
                "leg {leg}: the task waits for the gate while the choice holds it"
            );
            let other = tokio::spawn(async {});
            let ran = (0..200).any(|_| {
                std::thread::sleep(Duration::from_millis(25));
                other.is_finished()
            });
            assert!(
                ran,
                "leg {leg}: a task that waits for the choice gate keeps the runtime's only worker from its other tasks"
            );
            hold.release();
            assert!(choosing.join().expect("the choice ended").is_err());
            waiting.await.expect("the task took the gate");
        }
    }
}
