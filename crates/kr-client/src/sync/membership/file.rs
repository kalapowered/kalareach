//! The membership file: one file per collection, replaced whole at every write.
//!
//! It is kept as the sync store keeps a request. The directory is the caller's and is made
//! owner-only where the platform expresses that; every write goes to a temporary name, is flushed,
//! and is renamed over the file, so a reader never sees one half written; and one operating-system
//! lock, `membership.lock`, is held for the whole of each operation, so two windows or two
//! processes never interleave a read, a decision and a write.
//!
//! # Durability
//!
//! The new contents are flushed before the rename, and the directory entry after it, so a write the
//! reconciler has returned from survives a crash or a power loss. On Windows the entry is flushed
//! through a handle on the directory that may add a file to it, which is what the operating system
//! asks of a flush there.

use std::path::{Path, PathBuf};

use kr_ipc::paths::{NameKind, flush_directory, flush_path_names};

use super::MembershipError;
use super::facts::{Facts, Kinds};
use crate::shown::{IoFault, Shown};
use crate::sync::store::{Lock, private_directory, write_whole};

/// The name of the file the facts are kept in.
const FACTS_NAME: &str = "membership.facts";
/// The name of the lock every operation holds.
const LOCK_NAME: &str = "membership.lock";
/// The extension of a file being written, which is not yet a file.
const PARTIAL_EXTENSION: &str = "partial";

/// The bounds the file is read under.
///
/// A file holds the records between the installed one and the head, each at most 64 KiB, so it is
/// read under larger bounds than one protocol message, and still under bounds.
const LIMITS: kr_cbor::Limits = kr_cbor::Limits {
    max_message_len: 16 << 20,
    max_depth: 32,
    max_items: 1 << 22,
    max_collection_len: 1 << 16,
    max_bytes_len: 16 << 20,
    max_text_len: 1 << 20,
};

/// Where one device keeps its membership file.
#[derive(Debug)]
pub(crate) struct MembershipFile {
    directory: PathBuf,
}

/// The hold one operation keeps on the membership file.
#[derive(Debug)]
pub(crate) struct FileLock {
    _lock: Lock,
}

impl MembershipFile {
    /// Opens or creates the directory, owner-only, and sweeps away any file a process that died
    /// while writing left behind. When another handle is in the middle of an operation the sweep
    /// is left to the next opening: a partial file is never read as the file.
    pub(crate) fn open(directory: impl Into<PathBuf>) -> Result<Self, MembershipError> {
        let directory = directory.into();
        private_directory(&directory).map_err(|source| storage(Shown::root(&directory), source))?;
        flush_path_names(&directory).map_err(|source| storage(Shown::root(&directory), source))?;
        let file = Self { directory };
        match file.lock() {
            Ok(guard) => {
                let swept = file.sweep_partials();
                drop(guard);
                swept?;
            }
            Err(MembershipError::Busy) => {}
            Err(error) => return Err(error),
        }
        Ok(file)
    }

    /// The directory the file is kept in.
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    /// Takes the lock for one operation.
    ///
    /// It never waits. An operation holds the lock across the service calls it makes, and a caller
    /// that blocked a thread waiting for it could stop the executor the holder needs to finish on,
    /// so a lock another handle holds is answered at once with [`MembershipError::Busy`].
    pub(crate) fn lock(&self) -> Result<FileLock, MembershipError> {
        let path = self.directory.join(LOCK_NAME);
        match Lock::try_take(&path) {
            Ok(Some(lock)) => Ok(FileLock { _lock: lock }),
            Ok(None) => Err(MembershipError::Busy),
            Err(crate::sync::SyncError::Storage { path, fault }) => {
                Err(MembershipError::Storage { path, fault })
            }
            Err(error) => Err(MembershipError::Storage {
                path: stored(&path),
                fault: IoFault::from(std::io::Error::other(crate::shown!("{}", error))),
            }),
        }
    }

    /// Reads the facts, or nothing when there is no file.
    pub(crate) fn load<K: Kinds>(&self) -> Result<Option<Facts<K>>, MembershipError> {
        let path = self.directory.join(FACTS_NAME);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => crate::sync::Zeroising(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(storage(stored(&path), error)),
        };
        let facts = kr_cbor::from_canonical_slice(&bytes.0, &LIMITS).map_err(|error| {
            MembershipError::Corrupt {
                path: stored(&path),
                reason: Shown::cbor(&error),
            }
        })?;
        Ok(Some(facts))
    }

    /// Replaces the facts whole: written to a temporary name, flushed, renamed over the file, and
    /// the directory entry flushed where the platform allows.
    pub(crate) fn replace<K: Kinds>(&self, facts: &Facts<K>) -> Result<(), MembershipError> {
        let bytes = crate::sync::Zeroising(kr_cbor::to_canonical_vec_within(facts, &LIMITS)?);
        let path = self.directory.join(FACTS_NAME);
        let partial = self.directory.join(format!(
            "{}.{PARTIAL_EXTENSION}",
            kr_transport::random::fresh_uuid_v4()
                .map_err(|error| MembershipError::Service(error.into()))?
        ));
        write_whole(&partial, &bytes.0).map_err(|source| storage(stored(&partial), source))?;
        if let Err(source) = std::fs::rename(&partial, &path) {
            let _ = std::fs::remove_file(&partial);
            return Err(storage(stored(&path), source));
        }
        flush_directory(&self.directory, NameKind::File)
            .map_err(|source| storage(Shown::root(&self.directory), source))
    }

    /// Removes every partial file. The caller holds the lock.
    fn sweep_partials(&self) -> Result<(), MembershipError> {
        let entries = std::fs::read_dir(&self.directory)
            .map_err(|source| storage(Shown::root(&self.directory), source))?;
        for entry in entries {
            let entry = entry.map_err(|source| storage(Shown::root(&self.directory), source))?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) == Some(PARTIAL_EXTENSION)
            {
                match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(storage(stored(&path), error)),
                }
            }
        }
        flush_directory(&self.directory, NameKind::File)
            .map_err(|source| storage(Shown::root(&self.directory), source))
    }
}

/// Says which path could not be used.
fn storage(path: Shown, source: std::io::Error) -> MembershipError {
    MembershipError::Storage {
        path,
        fault: IoFault::from(source),
    }
}

/// A file of the membership store's own, as a failure may name it: whole when the store wrote its
/// name.
fn stored(path: &Path) -> Shown {
    Shown::stored(path, &[FACTS_NAME, LOCK_NAME], &[PARTIAL_EXTENSION])
}
