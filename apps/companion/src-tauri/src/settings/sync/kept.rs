//! A set of values kept in a file beside the other records of settings sync, changed under a lock
//! that holds across companions over one data directory.
//!
//! A change is read, made and written back under the lock, and written by renaming a file into
//! place and then making the directory's names durable. That last step can fail after the record
//! already names the change, so a failed write says whether the record may name it all the same.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kr_ipc::paths::{
    create_private_directory, flush_path_names, read_owner_only_file, write_owner_only_file,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{CommandError, Result};

/// The most bytes of a record that are read: far more than this computer's devices come to.
const LIMIT: u64 = 1 << 20;

/// A change of the record that did not end well.
pub(super) struct Unwritten {
    pub(super) error: CommandError,
    /// Whether the record may name the change all the same.
    pub(super) landed: bool,
}

/// A set of values in a file under `directory`, and the lock file beside it.
#[derive(Debug)]
pub(super) struct Kept {
    directory: PathBuf,
    file: &'static str,
    lock: &'static str,
    /// What the record is, in the words of an error: "this computer's record of ...".
    what: &'static str,
}

impl Kept {
    pub(super) fn in_directory(
        directory: &Path,
        file: &'static str,
        lock: &'static str,
        what: &'static str,
    ) -> Self {
        Self {
            directory: directory.to_path_buf(),
            file,
            lock,
            what,
        }
    }

    /// What the file holds.
    pub(super) fn on_disk<T: Ord + DeserializeOwned>(&self) -> Result<BTreeSet<T>> {
        let path = self.directory.join(self.file);
        let bytes = read_owner_only_file(&path, LIMIT).map_err(|error| {
            CommandError::local_failure(format!("{} could not be read: {error}", self.what))
        })?;
        match bytes {
            None => Ok(BTreeSet::new()),
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                CommandError::local_failure(format!(
                    "{} is not one it can read: {error}",
                    self.what
                ))
            }),
        }
    }

    /// Changes the file under its lock. `landed_if` says, of what the file holds after a write that
    /// failed, whether the change is in it: it is asked under the same lock, so no other companion
    /// has changed the file between the write and the question.
    pub(super) fn change<T: Ord + Clone + Serialize + DeserializeOwned>(
        &self,
        change: impl FnOnce(&mut BTreeSet<T>),
        landed_if: impl Fn(&BTreeSet<T>) -> bool,
    ) -> std::result::Result<(), Unwritten> {
        let before_the_write = |error: CommandError| Unwritten {
            error,
            landed: false,
        };
        // The directory is made, then locked, and only then are its names made durable: a flush
        // under the lock covers every rename the read below can see, whoever made it, so a change
        // with nothing to write stands on a record that is durable too.
        create_private_directory(&self.directory).map_err(|error| {
            before_the_write(CommandError::local_failure(format!(
                "{} could not be made: {error}",
                self.what
            )))
        })?;
        let _lock =
            crate::settings::locked_file(&self.directory.join(self.lock)).map_err(|error| {
                before_the_write(CommandError::local_failure(format!(
                    "{} could not be locked: {error}",
                    self.what
                )))
            })?;
        flush_path_names(&self.directory).map_err(|error| {
            before_the_write(CommandError::local_failure(format!(
                "{} could not be made durable: {error}",
                self.what
            )))
        })?;
        let mut values = self.on_disk().map_err(before_the_write)?;
        let before = values.clone();
        change(&mut values);
        if values == before {
            return Ok(());
        }
        let text = serde_json::to_vec(&values).map_err(|error| {
            before_the_write(CommandError::local_failure(format!(
                "{} could not be written: {error}",
                self.what
            )))
        })?;
        write_owner_only_file(&self.directory.join(self.file), &text).map_err(|error| {
            // The file is renamed into place and then its directory is flushed, so a failure can
            // come after the record already names the change. A record that cannot be read to say
            // is taken to name it: what is uncertain is held, not forgotten.
            let landed = self.on_disk().map_or(true, |kept| landed_if(&kept));
            Unwritten {
                error: CommandError::local_failure(format!(
                    "{} could not be kept: {error}",
                    self.what
                )),
                landed,
            }
        })
    }
}
