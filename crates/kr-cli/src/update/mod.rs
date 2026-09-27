//! The releases this host keeps side by side, and updating between them: `kr host install`,
//! `kr host update` and `kr host versions`.
//!
//! What a release is and how a process holds the one it runs is [`kr_ipc::install`]'s. This module
//! is the command line's side: putting a checked release into the store, handing each control
//! daemon over to the new release, switching `current`, and saying what the host keeps.

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::install::InstallError;

/// What a failure of the store, or of a program's hold on its release, says.
///
/// Every path in one is the store's own, derived from where this program is or from a root the
/// person named, so it is said whole; what a manifest said about itself is not repeated.
#[must_use]
pub fn said(error: &InstallError) -> Shown {
    match error {
        InstallError::Image(source) => shown!(
            "where this program is could not be read from the operating system: {}",
            Shown::io(source)
        ),
        InstallError::Replaced { path, reason } => {
            shown!("{} {}", Shown::root(path), *reason)
        }
        InstallError::Manifest { path, .. } => shown!(
            "{} is not a release manifest this build reads",
            Shown::root(path)
        ),
        InstallError::Io {
            operation,
            path,
            source,
        } => shown!(
            "{} {}: {}",
            *operation,
            Shown::root(path),
            Shown::io(source)
        ),
        InstallError::Unsupported => {
            Shown::said("this host keeps no store of releases on this platform")
        }
    }
}
