//! Keeping what is tied to this device out of its backup.
//!
//! A device's pairing records hold counts and hosts that mean something only beside the keys in
//! this device's keychain, and those keys are for this device only: a backup restored onto another
//! phone brings the records and not the keys. A record without its key is worse than no record
//! (the attempt budget then refuses every code), so the directories that hold them are marked as
//! not to be backed up, and a restore leaves none, so the person pairs again.
//!
//! iOS marks a directory with the URL resource key Apple documents for it
//! (`isExcludedFromBackup`, `NSURLIsExcludedFromBackupKey`); the native half sets the key and reads
//! it back, and answers only when the system says the directory is excluded. Nothing else has a
//! backup of this kind to keep out of, so elsewhere there is nothing to do.

use std::path::Path;

use tauri::{AppHandle, Runtime};

use crate::PlatformError;

/// Marks `directory`, which must exist, as not to be backed up, and checks that the system says so.
///
/// # Errors
///
/// Returns an error when the system does not mark the directory or does not say that it is marked.
#[cfg(target_os = "ios")]
pub fn keep_out<R: Runtime>(app: &AppHandle<R>, directory: &Path) -> Result<(), PlatformError> {
    use tauri::Manager as _;

    let platform = app.state::<crate::Platform<R>>();
    let _: serde_json::Value = platform.call_blocking(
        "keepOutOfBackup",
        serde_json::json!({ "path": directory.to_string_lossy() }),
    )?;
    Ok(())
}

/// Nothing to keep out of: no other platform's backup holds a record whose key it does not carry.
///
/// # Errors
///
/// Never fails here.
#[cfg(not(target_os = "ios"))]
pub fn keep_out<R: Runtime>(_app: &AppHandle<R>, _directory: &Path) -> Result<(), PlatformError> {
    Ok(())
}

/// Whether the system says `directory` is excluded from the device's backup.
///
/// # Errors
///
/// Returns an error when the system cannot be asked.
#[cfg(target_os = "ios")]
pub fn is_kept_out<R: Runtime>(
    app: &AppHandle<R>,
    directory: &Path,
) -> Result<bool, PlatformError> {
    use tauri::Manager as _;

    #[derive(serde::Deserialize)]
    struct Answer {
        excluded: bool,
    }

    let platform = app.state::<crate::Platform<R>>();
    let answer: Answer = platform.call_blocking(
        "backupExclusion",
        serde_json::json!({ "path": directory.to_string_lossy() }),
    )?;
    Ok(answer.excluded)
}
