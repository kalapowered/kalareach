//! What the backend holds between commands.
//!
//! One connection, this computer as a device that pairs, its owner confirmations, one draft store,
//! and one record of where the last export was allowed to be written. Nothing here is reachable from the WebView except through the
//! commands, and a command returns protocol values rather than handles: there is nothing the page
//! can keep and use later.

use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};

use kr_client::Session;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::EnvironmentId;

use crate::connection::{Connection, ConnectionState, Standing};
use crate::device::Device;
use crate::error::{CommandError, Result};
use crate::owner::Owner;
use crate::pairing::PastePlatform;
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
    connection: Arc<RwLock<Option<Connection>>>,
    reason: RwLock<Option<String>>,
    device: OnceLock<Arc<Device>>,
    /// Why the pairing records are not open, when they are not.
    records_failure: RwLock<Option<RecordsNotOpen>>,
    /// Held for the length of one try at opening the pairing records, so that two tries (the
    /// application's start and an unlock) are made one after the other.
    opening_records: Mutex<()>,
    owner: OnceLock<Arc<Owner>>,
    revocations: OnceLock<Arc<crate::revocation::Revocations>>,
    paste: OnceLock<Arc<dyn PastePlatform>>,
    sync_service: OnceLock<Arc<SyncService>>,
    recovery: OnceLock<Arc<Recovery>>,
    settings: OnceLock<Arc<crate::settings::Settings>>,
    drafts: Arc<crate::drafts::DraftDesk>,
    questions: crate::questions::QuestionDesk,
    shares: Arc<crate::sharing::ShareDesk>,
    paired_links: Arc<crate::standing::PairedLinks>,
    export_destinations: Mutex<Vec<std::path::PathBuf>>,
    dropped_files: Mutex<Vec<std::path::PathBuf>>,
    supervision: Mutex<Supervision>,
}

/// The task that keeps the connection to the host the commands go to, and which choice of host it
/// belongs to.
///
/// Each choice has a number. A task installs a connection, or records that it has none, only while
/// its own choice is the current one, so a task that was ended after it had already reached the
/// host can never put that host's connection back.
#[derive(Debug, Default)]
struct Supervision {
    choice: u64,
    task: Option<tauri::async_runtime::JoinHandle<()>>,
}

impl AppState {
    /// Builds the state of an application that has not connected to anything yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            connection: Arc::new(RwLock::new(None)),
            reason: RwLock::new(Some(
                "this application has not reached a host yet".to_owned(),
            )),
            device: OnceLock::new(),
            records_failure: RwLock::new(None),
            opening_records: Mutex::new(()),
            owner: OnceLock::new(),
            revocations: OnceLock::new(),
            paste: OnceLock::new(),
            sync_service: OnceLock::new(),
            recovery: OnceLock::new(),
            settings: OnceLock::new(),
            drafts: Arc::new(crate::drafts::DraftDesk::default()),
            questions: crate::questions::QuestionDesk::default(),
            shares: Arc::new(crate::sharing::ShareDesk::default()),
            paired_links: Arc::new(crate::standing::PairedLinks::default()),
            export_destinations: Mutex::new(Vec::new()),
            dropped_files: Mutex::new(Vec::new()),
            supervision: Mutex::new(Supervision::default()),
        }
    }

    /// Makes a new choice of host: ends the task of the choice before it, records that there is no
    /// connection while the new host is reached, and starts the task `start` makes for the new
    /// choice's number.
    ///
    /// All of it happens under one lock, so two choices made at once are made one after the other
    /// and the later one stands, and what `start` records about the choice (which host is in use)
    /// is never at odds with the task that keeps its connection.
    ///
    /// # Errors
    ///
    /// Returns what `start` returns, and then nothing has changed.
    pub fn choose_host(
        &self,
        reason: &str,
        start: impl FnOnce(u64) -> Result<tauri::async_runtime::JoinHandle<()>>,
    ) -> Result<()> {
        let mut supervision = self
            .supervision
            .lock()
            .expect("the supervision lock is not poisoned");
        let choice = supervision.choice + 1;
        let task = start(choice)?;
        supervision.choice = choice;
        if let Some(before) = supervision.task.replace(task) {
            before.abort();
        }
        // The host in use is told as changed first, and the sessions opened on the host before are
        // let go with it, and the tokens that opened them are forgotten, after: a call that read the
        // host before the change then finds the generation moved when it hands its link over.
        self.disconnected(reason);
        self.paired_links.close_all();
        Ok(())
    }

    /// Forgets a host under the lock a choice of host is made under, and ends the connection to it
    /// when it was the one in use.
    ///
    /// `forget` removes this computer's record of the host and says whether it was the host in
    /// use. It runs inside the lock, so a choice made at the same time is made before it or after
    /// it, and what it reports is what the task in force is for. When the host was in use its task
    /// ends and no host is: the task of the choice may have been in the middle of reaching the
    /// host, and its result is dropped because its choice is no longer the current one.
    ///
    /// # Errors
    ///
    /// Returns what `forget` returns, and then nothing has changed.
    pub fn forget_host(&self, reason: &str, forget: impl FnOnce() -> Result<bool>) -> Result<()> {
        let mut supervision = self
            .supervision
            .lock()
            .expect("the supervision lock is not poisoned");
        if forget()? {
            supervision.choice += 1;
            if let Some(task) = supervision.task.take() {
                task.abort();
            }
            self.disconnected(reason);
            self.paired_links.close_all();
        }
        Ok(())
    }

    /// Whether `choice` is still the choice of host in force.
    fn current(supervision: &Supervision, choice: u64) -> bool {
        supervision.choice == choice
    }

    /// Records a live connection made for `choice`, unless another host has been chosen since.
    /// Returns whether it was kept.
    pub fn connected_for(&self, choice: u64, connection: Connection) -> bool {
        let supervision = self
            .supervision
            .lock()
            .expect("the supervision lock is not poisoned");
        if !Self::current(&supervision, choice) {
            return false;
        }
        self.connected(connection);
        true
    }

    /// Records that `choice` has no connection and why, unless another host has been chosen since.
    /// Returns whether it was recorded.
    pub fn disconnected_for(&self, choice: u64, reason: impl Into<String>) -> bool {
        let supervision = self
            .supervision
            .lock()
            .expect("the supervision lock is not poisoned");
        if !Self::current(&supervision, choice) {
            return false;
        }
        self.disconnected(reason);
        true
    }

    /// Records a live connection.
    pub fn connected(&self, connection: Connection) {
        *self.reason.write().expect("the state lock is not poisoned") = None;
        *self
            .connection
            .write()
            .expect("the state lock is not poisoned") = Some(connection);
    }

    /// Records that there is no connection, and why.
    pub fn disconnected(&self, reason: impl Into<String>) {
        *self
            .connection
            .write()
            .expect("the state lock is not poisoned") = None;
        *self.reason.write().expect("the state lock is not poisoned") = Some(reason.into());
    }

    /// The session every command goes through.
    ///
    /// # Errors
    ///
    /// Returns `HOST_NOT_CONFIGURED` when there is no connection, which is the same answer the
    /// interface gets for a host that went away.
    pub fn session(&self) -> Result<Arc<Session>> {
        self.connection
            .read()
            .expect("the state lock is not poisoned")
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
        self.connection
            .read()
            .expect("the state lock is not poisoned")
            .clone()
            .ok_or_else(CommandError::not_connected)
    }

    /// Replaces the connection `session` is with one the host admits, when it is the one held to
    /// the host on this machine and that host has withdrawn it.
    ///
    /// A revocation withdraws the connections the host admitted before it. The host refuses every
    /// request on one and keeps it open, so a connection that is held and not asked for what it
    /// is refused goes on being refused, and nothing ends it. The connection's supervision calls
    /// this when the host refuses a request on it as not permitted, whichever path of the
    /// application made the request. The host is asked for its devices, which it lists to any
    /// connection of this computer's that it admits and to no other: a refusal of that over this
    /// connection, and an answer over another, say it was withdrawn, where one request's refusal
    /// for its own reasons does not. The other takes its place, and the withdrawn one is ended,
    /// which the supervision takes up in turn.
    pub async fn replace_if_withdrawn(&self, session: &Arc<Session>) {
        let held = self
            .connection
            .read()
            .expect("the state lock is not poisoned")
            .clone();
        let Some(connection) = held else {
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
        let held = Arc::clone(&self.connection);
        Arc::new(move |withdrawn, fresh| {
            let mut held = held.write().expect("the state lock is not poisoned");
            // Only the connection that was refused is replaced: one installed since is the host's
            // to have admitted.
            if held
                .as_ref()
                .is_some_and(|connection| Arc::ptr_eq(&connection.session(), withdrawn))
            {
                *held = Some(fresh);
                drop(held);
                withdrawn.close();
            }
        })
    }

    /// Records that the connection `session` belongs to has ended, and why, unless a newer
    /// connection has already taken its place. The comparison and the removal are one step.
    pub fn disconnected_from(&self, session: &Arc<Session>, reason: impl Into<String>) {
        let removed = {
            let mut held = self
                .connection
                .write()
                .expect("the state lock is not poisoned");
            if held
                .as_ref()
                .is_some_and(|connection| Arc::ptr_eq(&connection.session(), session))
            {
                *held = None;
                true
            } else {
                false
            }
        };
        if removed {
            *self.reason.write().expect("the state lock is not poisoned") = Some(reason.into());
        }
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
        let held = self
            .connection
            .read()
            .expect("the state lock is not poisoned");
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
    /// worker is reached by its descriptor.
    #[must_use]
    pub fn paired_context(&self) -> Option<PairedContext> {
        let held = self
            .connection
            .read()
            .expect("the state lock is not poisoned");
        let device = self.device.get()?;
        match held.as_ref().map(Connection::standing) {
            Some(Standing::Owner) => None,
            Some(Standing::Paired { host, .. }) => Some(PairedContext {
                device: Arc::clone(device),
                host: (**host).clone(),
            }),
            None => device.host_in_use().map(|host| PairedContext {
                device: Arc::clone(device),
                host,
            }),
        }
    }

    /// The environment the connection belongs to, as the host stamped it on the handshake.
    ///
    /// # Errors
    ///
    /// Returns `HOST_NOT_CONFIGURED` when there is no connection.
    pub fn environment_id(&self) -> Result<EnvironmentId> {
        self.connection
            .read()
            .expect("the state lock is not poisoned")
            .as_ref()
            .map(Connection::environment_id)
            .ok_or_else(CommandError::not_connected)
    }

    /// What the interface is told about the connection.
    #[must_use]
    pub fn connection_state(&self) -> ConnectionState {
        let held = self
            .connection
            .read()
            .expect("the state lock is not poisoned");
        match held.as_ref() {
            Some(connection) => ConnectionState::of(connection),
            None => ConnectionState {
                connected: false,
                environment_id: None,
                reason: self
                    .reason
                    .read()
                    .expect("the state lock is not poisoned")
                    .clone(),
                rights: None,
                paired: false,
            },
        }
    }

    /// Records this computer as a device that pairs, once it has been opened, and where it pastes
    /// invitations from.
    pub fn opened(
        &self,
        device: Arc<Device>,
        owner: Arc<Owner>,
        paste: Arc<dyn PastePlatform>,
        revocations: Arc<crate::revocation::Revocations>,
    ) {
        let _ = self.device.set(device);
        let _ = self.owner.set(owner);
        let _ = self.paste.set(paste);
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
        }
    }

    /// Records the sync service this computer is set to use.
    pub fn sync_service_opened(&self, service: Arc<SyncService>) {
        let _ = self.sync_service.set(service);
    }

    /// Records this computer's recovery seed and bundle, once they have been opened.
    pub fn recovery_opened(&self, recovery: Arc<Recovery>) {
        let _ = self.recovery.set(recovery);
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

    /// Where this computer pastes invitations from.
    ///
    /// # Errors
    ///
    /// Returns a stated local failure, with its cause, when its keys or records could not be
    /// opened.
    pub fn paste(&self) -> Result<Arc<dyn PastePlatform>> {
        self.paste
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
            state.paste().expect_err("not open"),
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
}
