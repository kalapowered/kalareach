//! What the backend holds between commands.
//!
//! One connection, this computer as a device that pairs, its owner confirmations, one draft store,
//! and one record of where the last export was allowed to be written. Nothing here is reachable from the WebView except through the
//! commands, and a command returns protocol values rather than handles: there is nothing the page
//! can keep and use later.

use std::sync::{Arc, Mutex, OnceLock, RwLock};

use kr_client::Session;
use kr_protocol::ids::EnvironmentId;

use crate::connection::{Connection, ConnectionState, Standing};
use crate::device::Device;
use crate::error::{CommandError, Result};
use crate::owner::Owner;
use crate::pairing::PastePlatform;

/// The backend's long-lived state.
#[derive(Debug)]
pub struct AppState {
    connection: RwLock<Option<Connection>>,
    reason: RwLock<Option<String>>,
    device: OnceLock<Arc<Device>>,
    owner: OnceLock<Arc<Owner>>,
    paste: OnceLock<Arc<dyn PastePlatform>>,
    drafts: Mutex<Option<Arc<kr_client::drafts::DraftStore>>>,
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
            connection: RwLock::new(None),
            reason: RwLock::new(Some(
                "this application has not reached a host yet".to_owned(),
            )),
            device: OnceLock::new(),
            owner: OnceLock::new(),
            paste: OnceLock::new(),
            drafts: Mutex::new(None),
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
        self.disconnected(reason);
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
            },
        }
    }

    /// Records this computer as a device that pairs, once it has been opened, and where it pastes
    /// invitations from.
    pub fn opened(&self, device: Arc<Device>, owner: Arc<Owner>, paste: Arc<dyn PastePlatform>) {
        let _ = self.device.set(device);
        let _ = self.owner.set(owner);
        let _ = self.paste.set(paste);
    }

    /// This computer as a device that pairs.
    ///
    /// # Errors
    ///
    /// Returns a local failure when its keys or records could not be opened.
    pub fn device(&self) -> Result<Arc<Device>> {
        self.device.get().cloned().ok_or_else(|| {
            CommandError::local_failure("this computer's pairing records could not be opened")
        })
    }

    /// This computer's owner confirmations.
    ///
    /// # Errors
    ///
    /// Returns a local failure when its keys or records could not be opened.
    pub fn owner(&self) -> Result<Arc<Owner>> {
        self.owner.get().cloned().ok_or_else(|| {
            CommandError::local_failure("this computer's pairing records could not be opened")
        })
    }

    /// Where this computer pastes invitations from.
    ///
    /// # Errors
    ///
    /// Returns a local failure when its keys or records could not be opened.
    pub fn paste(&self) -> Result<Arc<dyn PastePlatform>> {
        self.paste.get().cloned().ok_or_else(|| {
            CommandError::local_failure("this computer's pairing records could not be opened")
        })
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

    /// Opens, or reuses, this device's draft store.
    ///
    /// A draft belongs to the device, so the store lives under this application's own per-user
    /// directory and never under a session's working directory.
    ///
    /// # Errors
    ///
    /// Returns the store's own failure when the directory cannot be made durable.
    pub fn drafts(
        &self,
        directory: &std::path::Path,
        device_id: kr_protocol::ids::DeviceId,
    ) -> Result<Arc<kr_client::drafts::DraftStore>> {
        let mut held = self.drafts.lock().expect("the draft lock is not poisoned");
        if let Some(store) = held.as_ref() {
            return Ok(Arc::clone(store));
        }
        let store = kr_client::drafts::DraftStore::open(directory, device_id)
            .map_err(CommandError::from)?;
        let store = Arc::new(store);
        *held = Some(Arc::clone(&store));
        Ok(store)
    }
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
