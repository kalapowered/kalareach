//! What the backend holds between commands.
//!
//! One connection, this computer as a device that pairs, its owner confirmations, one draft store,
//! and one record of where the last export was allowed to be written. Nothing here is reachable from the WebView except through the
//! commands, and a command returns protocol values rather than handles: there is nothing the page
//! can keep and use later.

use std::sync::{Arc, Mutex, OnceLock, RwLock};

use kr_client::Session;
use kr_protocol::ids::EnvironmentId;

use crate::connection::{Connection, ConnectionState};
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
        }
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
            Some(connection) => ConnectionState {
                connected: true,
                environment_id: Some(connection.environment_id().to_string()),
                reason: None,
            },
            None => ConnectionState {
                connected: false,
                environment_id: None,
                reason: self
                    .reason
                    .read()
                    .expect("the state lock is not poisoned")
                    .clone(),
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
