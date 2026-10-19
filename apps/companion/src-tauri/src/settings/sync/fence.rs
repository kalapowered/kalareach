//! The record of revocations that the membership has not taken in yet, and the gate it makes for
//! everything settings sync sends: revocations this computer sent, whatever became of the request,
//! and devices the host on this computer lists as revoked.
//!
//! A revocation this computer sends is written down before the request leaves, and a request whose
//! record cannot be written is not sent. A step may be in hand, waiting on the network, when the
//! person revokes, and the membership cannot take the revocation in then: the step holds the
//! membership for as long as it waits. From the moment the request leaves, nothing more may be
//! sealed under a key the device holds, so the record comes first and is forgotten once the
//! membership has taken the revocation in.
//!
//! **A record is only ever taken in, never taken back.** What becomes of a request after the record
//! is written is not always known here: a reply can be lost after a host acted, and two requests
//! can name one device. So a failed request does not lift its record. Only a step that has taken
//! the record into the membership lets go of it, or a step that finds no collection to take it
//! out of.
//!
//! The cost is stated, not hidden: a device taken in is out of the shared settings for good on this
//! computer. The membership keeps a revoked device's key for as long as it keeps its own records,
//! the device is out of the collection for every device that shares it (and if another member adds
//! it back, this computer takes it out again), and the device's keys are the same when it is paired
//! again, so pairing it anew does not undo it. A person who revoked a device and was told the
//! request failed can revoke it again to finish the job; nothing here brings it back into the
//! shared settings.
//!
//! The record is a file beside the other records of settings sync, so it is kept across a restart
//! and seen by a second companion over the same data directory: each step takes in what it finds
//! there, whoever wrote it, before it reconciles. Settings and drafts both ask [`Fence`], as a
//! [`PublishGate`], before they read and seal what they send, so a send it refuses leaves no record
//! and no sealed bytes behind. A send that has passed the gate is on its way and cannot be called
//! back. A device that the host on this computer lists as revoked without this computer having sent
//! the request is written down when this computer reads that list; a record that cannot be written
//! then holds this process only, until it can be.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use kr_client::sync::PublishGate;
use kr_ipc::paths::{
    create_private_directory, flush_path_names, read_owner_only_file, write_owner_only_file,
};
use kr_protocol::scalars::AuthorisationKey;

use crate::error::{CommandError, Result};

/// The file the revocations not yet recorded are kept in.
const FILE: &str = "revoking.json";

/// The file whose lock makes a change to [`FILE`] one act across companions.
const LOCK: &str = "revoking.lock";

/// The most bytes of [`FILE`] that are read: far more than this computer's devices come to.
const LIMIT: u64 = 1 << 20;

/// The devices whose revocation is known here and the membership has not recorded yet: those this
/// computer sent a request for, whatever became of it, and those the host on this computer lists as
/// revoked.
#[derive(Debug)]
pub struct Fence {
    directory: PathBuf,
    /// The same devices as this process knows them, so that a record that cannot be written down
    /// still holds this process's sends.
    held: Mutex<BTreeSet<AuthorisationKey>>,
}

/// A change of the record that did not end well.
struct Unwritten {
    error: CommandError,
    /// Whether the record may name the change all the same.
    landed: bool,
}

impl Fence {
    /// The record kept in `directory`.
    #[must_use]
    pub(in crate::settings) fn in_directory(directory: &Path) -> Self {
        Self {
            directory: directory.to_path_buf(),
            held: Mutex::new(BTreeSet::new()),
        }
    }

    fn held(&self) -> std::sync::MutexGuard<'_, BTreeSet<AuthorisationKey>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What the file holds.
    fn on_disk(&self) -> Result<BTreeSet<AuthorisationKey>> {
        let path = self.directory.join(FILE);
        let bytes = read_owner_only_file(&path, LIMIT).map_err(|error| {
            CommandError::local_failure(format!(
                "this computer's record of revocations not yet taken in could not be read: {error}"
            ))
        })?;
        match bytes {
            None => Ok(BTreeSet::new()),
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                CommandError::local_failure(format!(
                    "this computer's record of revocations not yet taken in is not one it can \
                     read: {error}"
                ))
            }),
        }
    }

    /// Changes the file under its lock. `landed_if` says, of what the file holds after a write that
    /// failed, whether the change is in it: it is asked under the same lock, so no other companion
    /// has changed the file between the write and the question.
    fn change(
        &self,
        change: impl FnOnce(&mut BTreeSet<AuthorisationKey>),
        landed_if: impl Fn(&BTreeSet<AuthorisationKey>) -> bool,
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
                "this computer's record of revocations not yet taken in could not be made: \
                 {error}"
            )))
        })?;
        let _lock = crate::settings::locked_file(&self.directory.join(LOCK)).map_err(|error| {
            before_the_write(CommandError::local_failure(format!(
                "this computer's record of revocations not yet taken in could not be locked: \
                 {error}"
            )))
        })?;
        flush_path_names(&self.directory).map_err(|error| {
            before_the_write(CommandError::local_failure(format!(
                "this computer's record of revocations not yet taken in could not be made \
                 durable: {error}"
            )))
        })?;
        let mut devices = self.on_disk().map_err(before_the_write)?;
        let before = devices.clone();
        change(&mut devices);
        if devices == before {
            return Ok(());
        }
        let text = serde_json::to_vec(&devices).map_err(|error| {
            before_the_write(CommandError::local_failure(format!(
                "this computer's record of revocations not yet taken in could not be written: \
                 {error}"
            )))
        })?;
        write_owner_only_file(&self.directory.join(FILE), &text).map_err(|error| {
            // The file is renamed into place and then its directory is flushed, so a failure can
            // come after the record already names the change. A record that cannot be read to say
            // is taken to name it: what is uncertain is held, not forgotten.
            let landed = self.on_disk().map_or(true, |kept| landed_if(&kept));
            Unwritten {
                error: CommandError::local_failure(format!(
                    "this computer's record of revocations not yet taken in could not be kept: \
                     {error}"
                )),
                landed,
            }
        })
    }

    /// Holds everything sent until `devices` are taken out of the shared settings, for a revocation
    /// this computer is about to send. The request is not sent unless this returns `Ok`.
    ///
    /// A write can fail after it has done its work: the file is renamed into place and then the
    /// directory is flushed. When the record may name the devices all the same, it is a hold, for
    /// every reader and for this process, and it stands: it is not rolled back, since a rollback is
    /// the same write and can fail the same way. The error says so, the request is not sent, and
    /// the next step takes the devices out where a membership exists.
    ///
    /// # Errors
    ///
    /// Returns why the record could not be made durable. The devices are held all the same when the
    /// error says so.
    pub(in crate::settings) fn raise(&self, devices: &[AuthorisationKey]) -> Result<()> {
        let outcome = self.change(
            |kept| kept.extend(devices.iter().copied()),
            |kept| devices.iter().all(|device| kept.contains(device)),
        );
        match outcome {
            Ok(()) => {
                self.held().extend(devices.iter().copied());
                Ok(())
            }
            Err(unwritten) if unwritten.landed => {
                self.held().extend(devices.iter().copied());
                let mut error = unwritten.error;
                if !error.message.ends_with('.') {
                    error.message.push('.');
                }
                error.message.push_str(
                    " The record may have been kept all the same, so this computer holds its \
                     settings back from that device.",
                );
                Err(error)
            }
            Err(unwritten) => Err(unwritten.error),
        }
    }

    /// Holds everything sent until `devices` are taken out of the shared settings, for devices
    /// whose revocation has happened or may have: the host on this computer lists them as revoked,
    /// or the request for one was sent and failed. This process holds them from memory when the
    /// record cannot be written, and writes them down when it can.
    pub(super) fn raise_regardless(&self, devices: &[AuthorisationKey]) {
        self.held().extend(devices.iter().copied());
        let _ = self.change(|kept| kept.extend(devices.iter().copied()), |_| false);
    }

    /// Lets go of `devices`, which the membership has taken in or which have no collection to be
    /// taken out of.
    ///
    /// # Errors
    ///
    /// Returns why the record could not be written; the devices stay held.
    pub(super) fn lift(&self, devices: &[AuthorisationKey]) -> Result<()> {
        self.change(
            |kept| {
                for device in devices {
                    kept.remove(device);
                }
            },
            |_| false,
        )
        .map_err(|unwritten| unwritten.error)?;
        let mut held = self.held();
        for device in devices {
            held.remove(device);
        }
        Ok(())
    }

    /// Writes down what this process holds and the file does not, as far as the file allows.
    pub(super) fn keep_held(&self) {
        let held: Vec<AuthorisationKey> = self.held().iter().copied().collect();
        if !held.is_empty() {
            let _ = self.change(|kept| kept.extend(held.iter().copied()), |_| false);
        }
    }

    /// The devices held, by this process or by the file.
    ///
    /// # Errors
    ///
    /// Returns why the file could not be read.
    pub(super) fn pending(&self) -> Result<Vec<AuthorisationKey>> {
        let mut devices = self.on_disk()?;
        devices.extend(self.held().iter().copied());
        Ok(devices.into_iter().collect())
    }

    /// Whether anything is held. A record that cannot be read holds everything: nothing is sent
    /// that a record this computer cannot read might forbid.
    #[must_use]
    pub fn is_raised(&self) -> bool {
        !self.held().is_empty() || self.on_disk().map_or(true, |devices| !devices.is_empty())
    }

    /// Whether none of `devices` is held.
    pub(super) fn holds_none_of(&self, devices: &[AuthorisationKey]) -> bool {
        self.pending()
            .is_ok_and(|held| !devices.iter().any(|device| held.contains(device)))
    }
}

impl PublishGate for Fence {
    fn is_open(&self) -> bool {
        !self.is_raised()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> AuthorisationKey {
        AuthorisationKey::from_bytes([byte; 32])
    }

    /// A revocation this computer is about to send is held in full or not at all: a record that
    /// cannot be written holds nothing, since the request is not sent, and what is not sent must
    /// not leave the device out of the shared settings.
    #[test]
    fn a_hold_that_cannot_be_written_holds_nothing() {
        let directory = tempfile::tempdir().expect("a directory");
        let kept = directory.path().join("settings-sync");
        let fence = Fence::in_directory(&kept);
        kr_ipc::paths::create_private_directory(&kept).expect("the directory");
        std::fs::create_dir(kept.join(FILE)).expect("an obstacle where the record would be");

        fence
            .raise(&[key(7)])
            .expect_err("the record cannot be written");
        std::fs::remove_dir(kept.join(FILE)).expect("the obstacle goes");

        assert!(!fence.is_raised(), "nothing is held");
        assert!(fence.pending().expect("readable").is_empty());
        fence
            .raise(&[key(7)])
            .expect("the record can be written now");
        assert!(fence.is_raised());
        assert!(fence.holds_none_of(&[key(8)]));
        assert!(!fence.holds_none_of(&[key(7)]));
    }

    /// A directory `settings-sync` reached through a link, so that the path it is written under
    /// and the path a flush of its name resolves to are two. Returns the fence, the first and the
    /// second.
    #[cfg(unix)]
    fn through_a_link() -> (
        tempfile::TempDir,
        Fence,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let directory = tempfile::tempdir().expect("a directory");
        let base = std::fs::canonicalize(directory.path()).expect("a path");
        std::fs::create_dir(base.join("real")).expect("the real directory");
        std::os::unix::fs::symlink(base.join("real"), base.join("alias")).expect("a link");
        let as_written = base.join("alias").join("settings-sync");
        let resolved = base.join("real").join("settings-sync");
        (
            directory,
            Fence::in_directory(&as_written),
            as_written,
            resolved,
        )
    }

    /// The name of the record's directory is made durable before anything is written in it, and a
    /// flush of it that fails sends the revocation nowhere and holds nothing.
    #[cfg(unix)]
    #[test]
    fn a_hold_whose_directory_cannot_be_made_durable_holds_nothing() {
        let (_directory, fence, _as_written, resolved) = through_a_link();
        let refused = kr_flush::testing::refuse_flushes_of(resolved);
        fence
            .raise(&[key(7)])
            .expect_err("the name of the directory cannot be made durable");
        drop(refused);
        assert!(!fence.is_raised(), "nothing is held");
        assert!(fence.pending().expect("readable").is_empty());
    }

    /// A write whose last step, the flush after the rename, fails has still renamed the record into
    /// place: the hold stands for every reader and for this process, the request is not sent, and
    /// the error says that the record may have been kept.
    #[cfg(unix)]
    #[test]
    fn a_hold_whose_flush_fails_after_the_rename_stands_and_stops_the_request() {
        let (_directory, fence, as_written, _resolved) = through_a_link();
        let refused = kr_flush::testing::refuse_flushes_of(as_written);
        let error = fence
            .raise(&[key(7)])
            .expect_err("the record cannot be made durable");
        drop(refused);
        assert!(
            error.message.contains("kept all the same"),
            "the person is told: {error}"
        );
        assert!(fence.is_raised(), "the hold stands");
        assert!(
            fence.on_disk().expect("readable").contains(&key(7)),
            "the record names the device"
        );
    }

    /// A record that can be read and cannot be written into place is not a hold: the write stops
    /// before the rename, so the record does not name the device, nothing is held for it, and the
    /// error does not say that the record may have been kept.
    #[cfg(unix)]
    #[test]
    fn a_hold_whose_write_stops_before_the_rename_holds_nothing_of_the_new_device() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a directory");
        let kept = directory.path().join("settings-sync");
        let fence = Fence::in_directory(&kept);
        fence.raise(&[key(7)]).expect("the first hold");
        std::fs::set_permissions(&kept, std::fs::Permissions::from_mode(0o500))
            .expect("the directory is read only");
        let refused = fence.raise(&[key(8)]);
        std::fs::set_permissions(&kept, std::fs::Permissions::from_mode(0o700))
            .expect("the directory is writable again");

        let error = refused.expect_err("the record cannot be written into place");
        assert!(
            !error.message.contains("kept all the same"),
            "nothing was kept: {error}"
        );
        assert!(fence.holds_none_of(&[key(8)]), "the new device is not held");
        assert!(!fence.holds_none_of(&[key(7)]), "the first still is");
    }
}
