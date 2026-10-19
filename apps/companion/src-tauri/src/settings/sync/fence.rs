//! The record of revocations this computer sent that the membership has not taken in yet, and the
//! gate it makes for everything settings sync sends.
//!
//! A revocation this computer sends is written down before the request leaves, and a request whose
//! record cannot be written is not sent. A step may be in hand, waiting on the network, when the
//! person revokes, and the membership cannot take the revocation in then: the step holds the
//! membership for as long as it waits. From the moment the request leaves, nothing more may be
//! sealed under a key the device holds, so the record comes first and is forgotten once the
//! membership has taken the revocation in.
//!
//! The record is a file beside the other records of settings sync, so it is kept across a restart
//! and seen by a second companion over the same data directory: each step takes in what it finds
//! there, whoever wrote it, before it reconciles. Settings and drafts both ask [`Fence`], as a
//! [`PublishGate`], before they read and seal what they send, so a send it refuses leaves no record
//! and no sealed bytes behind. A send that has passed the gate is on its way and cannot be called
//! back. A device that a host lists as revoked without this computer having sent the request is
//! written down when this computer reads that list; a record that cannot be written then holds this
//! process only, until it can be.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use kr_client::sync::PublishGate;
use kr_ipc::paths::{read_owner_only_file, write_owner_only_file};
use kr_protocol::scalars::AuthorisationKey;

use crate::error::{CommandError, Result};

/// The file the revocations not yet recorded are kept in.
const FILE: &str = "revoking.json";

/// The file whose lock makes a change to [`FILE`] one act across companions.
const LOCK: &str = "revoking.lock";

/// The most bytes of [`FILE`] that are read: far more than this computer's devices come to.
const LIMIT: u64 = 1 << 20;

/// The devices whose revocation this computer sent and the membership has not recorded yet.
#[derive(Debug)]
pub struct Fence {
    directory: PathBuf,
    /// The same devices as this process knows them, so that a record that cannot be written down
    /// still holds this process's sends.
    held: Mutex<BTreeSet<AuthorisationKey>>,
}

impl Fence {
    /// The record kept in `directory`.
    #[must_use]
    pub fn in_directory(directory: &Path) -> Self {
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

    /// Changes the file under its lock.
    fn change(&self, change: impl FnOnce(&mut BTreeSet<AuthorisationKey>)) -> Result<()> {
        let _lock = crate::settings::locked_file(&self.directory.join(LOCK)).map_err(|error| {
            CommandError::local_failure(format!(
                "this computer's record of revocations not yet taken in could not be locked: \
                 {error}"
            ))
        })?;
        let mut devices = self.on_disk()?;
        let before = devices.clone();
        change(&mut devices);
        if devices == before {
            return Ok(());
        }
        let text = serde_json::to_vec(&devices).map_err(|error| {
            CommandError::local_failure(format!(
                "this computer's record of revocations not yet taken in could not be written: \
                 {error}"
            ))
        })?;
        write_owner_only_file(&self.directory.join(FILE), &text).map_err(|error| {
            CommandError::local_failure(format!(
                "this computer's record of revocations not yet taken in could not be kept: {error}"
            ))
        })
    }

    /// Holds everything sent until `devices` are recorded as revoked. Nothing here can undo it
    /// except [`Self::lift`]: a record that cannot be written leaves this process holding its own,
    /// and the error says so.
    ///
    /// # Errors
    ///
    /// Returns why the record could not be written.
    pub fn raise(&self, devices: &[AuthorisationKey]) -> Result<()> {
        self.held().extend(devices.iter().copied());
        self.change(|kept| kept.extend(devices.iter().copied()))
    }

    /// Lets go of `devices`, whose revocation the membership has recorded.
    ///
    /// # Errors
    ///
    /// Returns why the record could not be written; the devices stay held.
    pub fn lift(&self, devices: &[AuthorisationKey]) -> Result<()> {
        self.change(|kept| {
            for device in devices {
                kept.remove(device);
            }
        })?;
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
            let _ = self.change(|kept| kept.extend(held.iter().copied()));
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
