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
}

impl SyncService {
    /// The choice kept under `data`, or the managed service when none is kept or what is kept is
    /// not an origin this build admits.
    #[must_use]
    pub fn open(data: &Path) -> Self {
        let file = data.join(FILE);
        let kept = match read_owner_only_file(&file, ORIGIN_LIMIT) {
            Ok(kept) => kept,
            Err(error) => {
                // A file this build will not read (a link, another owner's, wider than owner-only)
                // is not followed to a service the person chose, and the managed one stands; the
                // log says why, so that a person whose choice seems lost can find the cause.
                tracing::warn!(%error, "the sync service setting could not be read, so the managed service stands");
                None
            }
        };
        let origin = kept
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|text| GatewayOrigin::new(text.trim()).ok())
            .unwrap_or_else(managed);
        Self {
            file,
            origin: Mutex::new(origin),
        }
    }

    /// The origin this computer talks to for sync.
    #[must_use]
    pub fn origin(&self) -> GatewayOrigin {
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
        write_owner_only_file(&self.file, origin.as_str().as_bytes()).map_err(|error| {
            CommandError::local_failure(format!(
                "the sync service setting could not be kept: {error}"
            ))
        })?;
        *self.origin.lock().unwrap_or_else(PoisonError::into_inner) = origin.clone();
        Ok(SyncServiceView::of(&origin))
    }
}

/// The managed service's origin, which the setting holds until the person chooses another.
fn managed() -> GatewayOrigin {
    GatewayOrigin::new(ACCOUNT_ORIGIN).expect("the managed service's origin is one")
}
