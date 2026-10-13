//! The lease a production pass holds, and the staging it does under it.
//!
//! A pass reads the host's content, encrypts it and writes the ciphertext to the staging directory
//! before the store is asked to admit anything, so that no file is written while the store's lock
//! is held. That leaves the pass outside the account privacy mode keeps: a fence and its cleanup
//! can finish while the pass is between two writes, and the pass would then write a file nothing
//! owes anybody. The lease closes that.
//!
//! * It is granted under the store's lock, and only to a service that is ready, with no privacy
//!   fence up and no privacy request accepted whose fence is not up yet.
//! * It is held by the blocking worker that runs the pass, as a guard. The worker drops it after
//!   its last possible write. It is never released on a timeout, which would bring the race back.
//! * While one is live, the cleanup a fence owes does not discharge its staging scan, so the
//!   durable count privacy mode waits on stays above nothing until the pass has stopped.
//! * A fence, or a privacy step this process could not take, cancels it. Cancelling sets a flag
//!   and waits for nothing; the pass looks at the flag before and after every write and drops the
//!   files it wrote.
//! * The files it wrote and no generation has claimed are removed when it ends, however it ends.
//!
//! The lock the lease's end takes belongs to no holder of the store's lock: `admit` and the
//! cleanup read the registry while they hold the store, and the end of a lease takes the registry
//! alone.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId};

use crate::backup::{BackupSignals, sync_removal, write_staged};
use crate::error::ControllerError;

/// The leases that are live, by identity, each with the flag that cancels it.
#[derive(Debug, Default)]
pub(super) struct Leases {
    live: BTreeMap<u64, Arc<AtomicBool>>,
    next: u64,
}

impl Leases {
    pub(super) fn grant(&mut self) -> (u64, Arc<AtomicBool>) {
        let id = self.next;
        self.next += 1;
        let flag = Arc::new(AtomicBool::new(false));
        self.live.insert(id, Arc::clone(&flag));
        (id, flag)
    }

    fn end(&mut self, id: u64) {
        self.live.remove(&id);
    }

    /// Cancels every lease that is live. Nothing waits for any of them.
    pub(super) fn cancel_all(&self) {
        for flag in self.live.values() {
            flag.store(true, Ordering::SeqCst);
        }
    }

    /// Whether a pass is running.
    pub(super) fn any(&self) -> bool {
        !self.live.is_empty()
    }
}

/// Why a file was not staged.
#[derive(Debug)]
pub enum Staging {
    /// The pass was cancelled, because privacy mode fenced this host or a privacy step could not
    /// be taken. Whatever the pass wrote has been removed, and it stops without an error to show.
    Cancelled,
    /// The file could not be written.
    Failed(ControllerError),
}

/// One staged file: where it is and how long.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedFile {
    /// The object it holds the ciphertext of.
    pub object_id: BackupObjectId,
    /// Where it is.
    pub path: PathBuf,
    /// How many bytes it holds.
    pub len: u64,
}

/// A production pass's hold on the staging directory.
pub struct ProductionLease {
    id: u64,
    flag: Arc<AtomicBool>,
    leases: Arc<Mutex<Leases>>,
    signals: Arc<BackupSignals>,
    staging_root: PathBuf,
    read_under: u64,
    /// The files this pass wrote that no generation has claimed.
    unclaimed: Mutex<Vec<PathBuf>>,
}

impl std::fmt::Debug for ProductionLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionLease")
            .field("id", &self.id)
            .field("read_under", &self.read_under)
            .field("cancelled", &self.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl ProductionLease {
    pub(super) fn new(
        id: u64,
        flag: Arc<AtomicBool>,
        leases: Arc<Mutex<Leases>>,
        signals: Arc<BackupSignals>,
        staging_root: PathBuf,
        read_under: u64,
    ) -> Self {
        Self {
            id,
            flag,
            leases,
            signals,
            staging_root,
            read_under,
            unclaimed: Mutex::new(Vec::new()),
        }
    }

    /// The privacy generation in force when the lease was granted, which is the one the content
    /// the pass reads is read under.
    #[must_use]
    pub const fn read_under(&self) -> u64 {
        self.read_under
    }

    /// Whether privacy mode, or a privacy step this process could not take, has cancelled the
    /// pass. A pass that sees this stops and writes nothing more.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Where one object's ciphertext is staged.
    #[must_use]
    pub fn staged_path(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        object_id: BackupObjectId,
    ) -> PathBuf {
        staged_path_under(&self.staging_root, archive_id, backup_generation, object_id)
    }

    /// Writes one object's ciphertext to its staging file, durably, unless the pass was
    /// cancelled.
    ///
    /// The flag is looked at before the write and after it. A write that finds the pass cancelled
    /// once it is done takes its file away again, so a fence that went up in between is never left
    /// with a file it does not know of.
    ///
    /// # Errors
    ///
    /// Returns [`Staging::Cancelled`] when the pass was cancelled, and [`Staging::Failed`] when
    /// the file could not be written.
    pub fn stage(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        object_id: BackupObjectId,
        bytes: &[u8],
    ) -> Result<StagedFile, Staging> {
        if self.is_cancelled() {
            return Err(Staging::Cancelled);
        }
        let path = self.staged_path(archive_id, backup_generation, object_id);
        // A file that is already there is not this pass's to write over or to take away: it is
        // the ciphertext of a generation this host accounts for.
        if path.exists() {
            return Err(Staging::Failed(ControllerError::InvalidArgument(format!(
                "the ciphertext of object {object_id} is already staged on this host"
            ))));
        }
        // Named before the write, so a file the write left half made is removed with the rest.
        self.unclaimed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(path.clone());
        write_staged(&path, bytes).map_err(Staging::Failed)?;
        if self.is_cancelled() {
            return Err(Staging::Cancelled);
        }
        Ok(StagedFile {
            object_id,
            path,
            len: bytes.len() as u64,
        })
    }

    /// Records that a generation has claimed these files, so ending the pass leaves them.
    pub(super) fn claim(&self, paths: &[PathBuf]) {
        self.unclaimed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|held| !paths.contains(held));
    }

    /// Removes the files this pass wrote that no generation has claimed.
    ///
    /// Ending the pass does this, so a pass that failed, was cancelled or panicked leaves nothing
    /// of its own. What a kill leaves is found by the next start's sweep of unclaimed files.
    pub fn discard(&self) {
        let paths = std::mem::take(
            &mut *self
                .unclaimed
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        for path in &paths {
            let _ = std::fs::remove_file(path);
            if let Some(directory) = path.parent()
                && directory != self.staging_root
            {
                // Empty or not: a directory that still holds another generation's files stays.
                let _ = std::fs::remove_dir(directory);
            }
        }
        for path in &paths {
            let _ = sync_removal(path);
        }
    }
}

impl Drop for ProductionLease {
    fn drop(&mut self) {
        self.discard();
        self.leases
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .end(self.id);
        // Production waits for the pass to be over, and so does the cleanup a fence owes.
        self.signals.work.notify_one();
        self.signals.lease_ended.notify_one();
        self.signals.produce.notify_one();
    }
}

/// Where one object's ciphertext is staged under `staging_root`.
pub(super) fn staged_path_under(
    staging_root: &Path,
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
    object_id: BackupObjectId,
) -> PathBuf {
    staging_root
        .join(format!("{}-{}", archive_id, backup_generation.get()))
        .join(format!("{object_id}.krb"))
}
