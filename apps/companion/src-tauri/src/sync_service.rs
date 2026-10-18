//! Which sync service this computer talks to.
//!
//! Section 17 has the service configuration select each service on its own, so the sync service
//! is a choice of its own: it is not the account's origin, the pairing service's or a host's. It
//! is the managed service until the person picks another, which is how a self-hosted one is
//! chosen. The choice is one origin kept in `sync-origin` in the application's data directory.
//!
//! Choosing an origin does not send anything there. What the service takes beside this device's
//! signature, the account's token, goes only to the origin that account is signed in to; that rule
//! is [`crate::recovery`]'s, where the token is presented, and it names this setting when it
//! refuses.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use kr_client::services::account::ACCOUNT_ORIGIN;
use kr_ipc::paths::{read_owner_only_file, write_owner_only_file};
use kr_protocol::service::GatewayOrigin;
use serde::Serialize;

use crate::error::{CommandError, Result};

/// The file the choice is kept in, in the application's data directory.
pub const FILE: &str = "sync-origin";

/// The most the file may hold, in bytes: an origin is at most 128.
const ORIGIN_LIMIT: u64 = 1024;

/// What the page is shown of the choice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SyncServiceView {
    /// The canonical origin.
    pub origin: String,
    /// Its host name, which is what a person is shown.
    pub host: String,
    /// True when it is the managed service, which is what KalaReach ships with.
    pub is_default: bool,
}

impl SyncServiceView {
    fn of(origin: &GatewayOrigin) -> Self {
        Self {
            origin: origin.as_str().to_owned(),
            host: host_of(origin),
            is_default: origin.as_str() == ACCOUNT_ORIGIN,
        }
    }
}

/// An origin's host name and port, without its scheme.
pub(crate) fn host_of(origin: &GatewayOrigin) -> String {
    let text = origin.as_str();
    text.split_once("://")
        .map_or(text, |(_, authority)| authority)
        .to_owned()
}

/// The sync service this computer is set to use.
#[derive(Debug)]
pub struct SyncService {
    file: PathBuf,
    origin: Mutex<GatewayOrigin>,
    /// Whether the file could not be read when it was last tried, so that the next use reads it
    /// again: a phone started before its first unlock cannot read its files, and the managed
    /// service that stands in for the setting meanwhile must not outlive the lock.
    unread: AtomicBool,
    /// Held from the moment a choice is written to the moment it is the one in memory, so that two
    /// choices made together leave the file and this run saying the same thing.
    keeping: Mutex<()>,
}

impl SyncService {
    /// The choice kept under `data`, or the managed service when none is kept or what is kept is
    /// not an origin this build admits.
    #[must_use]
    pub fn open(data: &Path) -> Self {
        let file = data.join(FILE);
        let (origin, readable) = read(&file, true);
        Self {
            file,
            origin: Mutex::new(origin),
            unread: AtomicBool::new(!readable),
            keeping: Mutex::new(()),
        }
    }

    /// Reads the setting again when it could not be read the last time it was tried. A choice made
    /// since is the newest word and is not read over.
    fn read_again(&self) {
        if !self.unread.load(Ordering::SeqCst) {
            return;
        }
        let _keeping = self.keeping.lock().unwrap_or_else(PoisonError::into_inner);
        if !self.unread.load(Ordering::SeqCst) {
            return;
        }
        let (origin, readable) = read(&self.file, false);
        if readable {
            *self.origin.lock().unwrap_or_else(PoisonError::into_inner) = origin;
            self.unread.store(false, Ordering::SeqCst);
        }
    }

    /// The origin this computer talks to for sync.
    #[must_use]
    pub fn origin(&self) -> GatewayOrigin {
        self.read_again();
        self.origin
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// What the page is shown.
    #[must_use]
    pub fn view(&self) -> SyncServiceView {
        SyncServiceView::of(&self.origin())
    }

    /// Chooses another sync service. What a person types is trimmed of surrounding space and one
    /// trailing `/`, and then must be an HTTPS origin, or an HTTP one on this computer.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for anything that is not one, and a local failure when the choice
    /// cannot be kept, in which case the earlier choice stands in this run. A failure after the
    /// file was replaced (the directory could not be flushed) leaves the new choice in the file,
    /// and the next start reads it.
    pub fn set(&self, typed: &str) -> Result<SyncServiceView> {
        let trimmed = typed.trim();
        let trimmed = trimmed.strip_suffix('/').unwrap_or(trimmed);
        let origin = GatewayOrigin::new(trimmed).map_err(|error| {
            CommandError::invalid(format!(
                "the sync service setting needs an https origin such as https://sync.example, or \
                 an http one on this computer: {error}"
            ))
        })?;
        let _keeping = self.keeping.lock().unwrap_or_else(PoisonError::into_inner);
        write_owner_only_file(&self.file, origin.as_str().as_bytes()).map_err(|error| {
            CommandError::local_failure(format!(
                "the sync service setting could not be kept: {error}"
            ))
        })?;
        *self.origin.lock().unwrap_or_else(PoisonError::into_inner) = origin.clone();
        self.unread.store(false, Ordering::SeqCst);
        Ok(SyncServiceView::of(&origin))
    }
}

/// The origin the file in `file` keeps, and whether the file could be read at all.
///
/// A setting this build will not follow (a link, another owner's file, one wider than owner-only,
/// text that is not an origin) is not taken to a service the person chose: the managed service
/// stands, and the log says why when `say` is set. A file that cannot be read stands for the same
/// service and is read again at the next use.
fn read(file: &Path, say: bool) -> (GatewayOrigin, bool) {
    match read_owner_only_file(file, ORIGIN_LIMIT) {
        Ok(None) => (managed(), true),
        Ok(Some(bytes)) => (
            kept_origin(bytes).unwrap_or_else(|why| {
                tracing::warn!(%why, "the sync service setting is not an origin, so the managed service stands");
                managed()
            }),
            true,
        ),
        Err(error) => {
            if say {
                tracing::warn!(%error, "the sync service setting could not be read, so the managed service stands");
            }
            (managed(), false)
        }
    }
}

/// The origin a kept setting names, or why it names none.
fn kept_origin(bytes: Vec<u8>) -> std::result::Result<GatewayOrigin, String> {
    let text = String::from_utf8(bytes).map_err(|_| "it is not text".to_owned())?;
    GatewayOrigin::new(text.trim()).map_err(|error| error.to_string())
}

/// The managed service's origin, which the setting holds until the person chooses another.
fn managed() -> GatewayOrigin {
    GatewayOrigin::new(ACCOUNT_ORIGIN).expect("the managed service's origin is one")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A phone started before its first unlock cannot read its files, and keeps the managed service
    /// in the meantime. The setting is read again at the next use, so that once the files can be read
    /// the service the person chose is the one used, and not the one that stood in for it.
    #[test]
    fn a_setting_that_could_not_be_read_is_read_again_and_the_choice_stands() {
        use std::os::unix::fs::PermissionsExt as _;

        let data = tempfile::tempdir().expect("a directory");
        let file = data.path().join(FILE);
        std::fs::write(&file, "https://sync.example").expect("a setting");
        // Wider than owner-only: the file is not read, as one that cannot be opened is not.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("a mode");
        let service = SyncService::open(data.path());
        assert!(
            service.view().is_default,
            "the managed service stands while the setting cannot be read"
        );

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("a mode");
        assert_eq!(service.origin().as_str(), "https://sync.example");
        assert!(!service.view().is_default);
    }
}
