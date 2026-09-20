//! Reading and editing this host's configuration from the command line.
//!
//! Section 23's host-and-environment group is `host.info`, `environment.list`,
//! `environment.capabilities` and `host.doctor`: four reads and no host-settings mutation. So a
//! command that changes a setting writes this user's own configuration document itself, and the
//! daemon reads the choice the next time it asks itself the question.
//!
//! Writing it here does not mean deciding here. The schema, the validation and the revision rule
//! are [`kr_protocol::hostinfo::configuration`]'s, the same ones the daemon applies, so a setting
//! written from the command line and one written by the host are the same edit.

use std::path::PathBuf;

use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::hostinfo::configuration::{self, Change};

use crate::error::{CliError, Result};

/// Returns where this environment's configuration document is.
#[must_use]
pub fn document_path(paths: &EnvironmentPaths) -> PathBuf {
    paths.state_dir().join(configuration::FILE_NAME)
}

/// Reads this environment's configuration document, bounded and owner-only.
#[must_use]
pub fn load(paths: &EnvironmentPaths) -> configuration::Loaded {
    match kr_ipc::paths::read_owner_only_file(&document_path(paths), configuration::MAX_LEN) {
        Ok(bytes) => configuration::load(bytes.as_deref()),
        Err(error) => configuration::unreadable(&error.to_string()),
    }
}

/// Applies one validated change to this environment's configuration document.
///
/// Validate, then check the revision again at the last moment, then write. A document at a version
/// this build does not know, or one another writer moved while this edit was being prepared, is
/// refused with nothing written.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when the edit is refused, and [`CliError::Ipc`] when the document
/// cannot be written.
pub fn apply(paths: &EnvironmentPaths, change: &Change) -> Result<u64> {
    // The same lock the host takes, so a setting written here and one written by the daemon are
    // one edit at a time rather than two writers racing for the same revision.
    let held = configuration::lock(paths.state_dir()).map_err(CliError::Usage)?;
    let edited = configuration::edit(&load(paths), change)
        .map_err(|refused| CliError::Usage(refused.to_string()))?;
    configuration::still_current(&edited, &load(paths))
        .map_err(|refused| CliError::Usage(refused.to_string()))?;
    kr_ipc::paths::write_owner_only_file(&document_path(paths), edited.contents.as_bytes())
        .map_err(CliError::Ipc)?;
    drop(held);
    Ok(edited.revision)
}
