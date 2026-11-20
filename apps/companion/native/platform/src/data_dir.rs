//! The folder the companion keeps what it records in.
//!
//! One function chooses it, so that every record sits in one place and a case can show that no
//! call elsewhere names a folder of its own.

use std::path::PathBuf;

use tauri::{Manager, Runtime};

/// The companion's data folder.
///
/// On Windows it is in Local AppData and not in Roaming AppData, because a roaming profile carries
/// the Roaming folder to another computer, while this computer's keys are kept in the Credential
/// Manager with the Local persistence class, which does not travel: a record that went to another
/// computer without its key would be of no use there. On every other platform it is the folder
/// Tauri names as the application's data folder, as before.
///
/// A record that an earlier build wrote in the Roaming folder on Windows is not read from here.
///
/// # Errors
///
/// Returns Tauri's error when the system names no such folder.
pub fn companion_data_dir<R: Runtime, M: Manager<R>>(manager: &M) -> tauri::Result<PathBuf> {
    #[cfg(windows)]
    {
        manager.path().app_local_data_dir()
    }
    #[cfg(not(windows))]
    {
        manager.path().app_data_dir()
    }
}
