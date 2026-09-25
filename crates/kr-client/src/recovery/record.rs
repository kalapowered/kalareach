//! The record a bundle store keeps, on this device's disk, of the last write it sent.
//!
//! A write whose answer never came back has to be ended before the store writes again, and what
//! ends it is the identity it went out under, the instant that was signed at, and the bytes it
//! sent. A store built fresh after a restart would know none of them, so they are written down
//! before the write leaves and read back when the store is opened. A store opened over the record
//! of a write nothing has settled starts with that write outstanding, exactly as if its answer had
//! just been lost, and it will not write until the write is reconciled: by a read that finds the
//! bytes it sent, or by the service fencing its identity.
//!
//! The same record is what recognises the write afterwards. A migration is complete only once its
//! destination write has been read back and its kit handed over, and a destination store opened
//! after a restart completes it from this record, whether or not the write was answered first.
//!
//! # What the record holds, and never holds
//!
//! Where the bundle is, the place the write compared against, the identity and instant it went out
//! under, the digest of the encrypted bundle it sent, and what is known of what became of it.
//! Never the bundle, its ciphertext or a key. The bundle is key material, and a digest recognises
//! bytes without being able to give any back.
//!
//! # When it is written
//!
//! It is written and flushed to the device before the write leaves, and the write is not sent if
//! that fails. It stays until the next write replaces it, as the store's own memory of the write
//! does. What is known of the write is written again when an answer arrives or the write is
//! settled. That second writing can fail and leave the record saying less than the store knows,
//! which is the safe direction: a restart then asks about the write again, and the service answers
//! the same way.
//!
//! # One store per record
//!
//! A store holds an exclusive lock beside its record for as long as it is open. A second store for
//! the same bundle on this device, in this process or another, is refused, where it would
//! otherwise replace the record of a write the first store may still have outstanding.

use std::path::{Path, PathBuf};

use kr_protocol::archive::RecoveryContext;
use kr_protocol::ids::SyncConflictId;
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, Uuid};
use serde::{Deserialize, Serialize};

use crate::recovery::{RecoveryError, Result};
use crate::services::SyncPosition;

/// The most a stored record may take, in bytes.
///
/// A record is a few identifiers and two strings. The bound is what reading one allows, and a
/// record that would not fit it is refused before the write it describes goes out.
const MAX_RECORD_BYTES: usize = 64 * 1024;

/// The extension of a record.
const RECORD_EXTENSION: &str = "bundle-write";
/// The extension of a record being written, which is not yet a record.
const PARTIAL_EXTENSION: &str = "bundle-write-partial";
/// The extension of the lock a store holds while it is open.
const LOCK_EXTENSION: &str = "bundle-lock";

/// The last write a bundle store sent, as the store records it.
///
/// It holds what settling and recognising that write take and nothing else. A read recognises the
/// write by the digest of the encrypted bundle it sent, the service ends it by the identity it went
/// out under and the instant that was signed at, and any receipt of it is held against the place it
/// compared against. Neither the bundle nor its ciphertext is here: a write the service says it
/// applied is read back from the locator, so nothing that settles a lost write needs the bundle's
/// bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WriteRecord {
    /// Where the bundle is stored: the service origin and the locator.
    pub(super) context: RecoveryContext,
    /// Where the write compared against, or null where it named no bundle at all.
    ///
    /// A receipt is history, so it names where *that* write landed. Another device can have moved
    /// the bundle on since, and this store can have read that; the receipt is then behind the
    /// store's own baseline and is not a service going back. Holding the receipt against where the
    /// write was dispatched is what tells the two apart.
    pub(super) expected: Nullable<SyncPosition>,
    /// The identity it went out under, which is what ends it.
    pub(super) request_id: Uuid,
    /// The instant it was signed at, which is what bounds when the service may still run it.
    pub(super) signed_at_ms: TimestampMs,
    /// The digest of the encrypted bundle it sent, which is how a read recognises it.
    ///
    /// The ciphertext and not the bundle, because the ciphertext is what only this write carried.
    /// Two devices that move one bundle at one instant write equal bundles, and a digest of the
    /// bundle could not tell them apart; each encryption starts from its own random header, so their
    /// ciphertexts differ.
    pub(super) sent: Digest256,
    /// What is known of what became of it.
    pub(super) known: Known,
}

/// What a store knows of what became of its last write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Known {
    /// Nothing: no answer came back and nothing has settled it since. The store writes nothing
    /// further until something does.
    Unsettled,
    /// The service answered it, applied or refused.
    Answered,
    /// No answer came back, and a read or the service established afterwards that it applied.
    Applied,
    /// No answer came back, and the service ended it without recording that it applied.
    Ended {
        /// The copy the service kept of the write, when it refused it and kept one.
        retained: Nullable<SyncConflictId>,
    },
}

/// Where one bundle store keeps its record, and the lock that makes it the only store doing so.
#[derive(Debug)]
pub(super) struct RecordFile {
    directory: PathBuf,
    path: PathBuf,
    partial: PathBuf,
    /// Held exclusively for as long as the store is open, and released when it is dropped.
    _lock: std::fs::File,
}

impl RecordFile {
    /// Takes the record of one bundle location in `directory`, and returns what it holds.
    ///
    /// The name is derived from the location, so one directory holds the records of every bundle a
    /// device writes. A partial file an interrupted write left behind is removed. It was never a
    /// record, the record it would have replaced is still there, and the write it describes never
    /// went out, because a write is sent only once its record is in place.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::BundleStoreInUse`] when another store holds this location's
    /// record, [`RecoveryError::Storage`] when the directory, the lock or the record cannot be
    /// used, and [`RecoveryError::UnreadableWriteRecord`] when the record is not one this build
    /// wrote for this location.
    pub(super) fn open(
        directory: &Path,
        context: &RecoveryContext,
    ) -> Result<(Self, Option<WriteRecord>)> {
        let name = hex(&kr_cbor::sha256(&context.to_canonical_bytes()?));
        let lock_path = directory.join(format!("{name}.{LOCK_EXTENSION}"));
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| storage(&lock_path, source))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(RecoveryError::BundleStoreInUse { path: lock_path });
            }
            Err(std::fs::TryLockError::Error(source)) => return Err(storage(&lock_path, source)),
        }
        let file = Self {
            directory: directory.to_path_buf(),
            path: directory.join(format!("{name}.{RECORD_EXTENSION}")),
            partial: directory.join(format!("{name}.{PARTIAL_EXTENSION}")),
            _lock: lock,
        };
        match std::fs::remove_file(&file.partial) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(storage(&file.partial, source)),
        }
        let record = file.read(context)?;
        Ok((file, record))
    }

    /// Reads the record, when there is one.
    fn read(&self, context: &RecoveryContext) -> Result<Option<WriteRecord>> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(storage(&self.path, source)),
        };
        let unreadable = || RecoveryError::UnreadableWriteRecord {
            path: self.path.clone(),
        };
        // A record this build cannot read is refused rather than ignored: it may be the only
        // account of a write that can still land, and a store that dropped it would write again
        // while that write was on its way.
        let record: WriteRecord = kr_cbor::from_canonical_slice(
            &bytes,
            &kr_cbor::Limits::DEFAULT.with_max_message_len(MAX_RECORD_BYTES),
        )
        .map_err(|_| unreadable())?;
        if &record.context != context {
            return Err(unreadable());
        }
        Ok(Some(record))
    }

    /// Replaces the record, whole or not at all, and makes the replacement durable.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::Storage`] when it cannot be written, and
    /// [`RecoveryError::UnreadableWriteRecord`] for a record too large to be read back.
    pub(super) fn save(&self, record: &WriteRecord) -> Result<()> {
        let bytes = kr_cbor::to_canonical_vec(record)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(RecoveryError::UnreadableWriteRecord {
                path: self.path.clone(),
            });
        }
        // A partial file an earlier failure in this process could not remove is not a record, and
        // this store holds the lock, so nothing else is writing one. Removing it keeps a failure
        // that is over from refusing every write after it.
        match std::fs::remove_file(&self.partial) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(storage(&self.partial, source)),
        }
        write_whole(&self.partial, &bytes).map_err(|source| storage(&self.partial, source))?;
        // A rename within one directory replaces the name in one step, so a reader finds the old
        // record or the new one and never a record half written.
        if let Err(source) = std::fs::rename(&self.partial, &self.path) {
            let _ = std::fs::remove_file(&self.partial);
            return Err(storage(&self.path, source));
        }
        kr_ipc::paths::flush_directory(&self.directory, kr_ipc::paths::NameKind::File)
            .map_err(|source| storage(&self.directory, source))
    }
}

fn storage(path: &Path, source: std::io::Error) -> RecoveryError {
    RecoveryError::Storage {
        path: path.to_path_buf(),
        source,
    }
}

/// Returns the lowercase hexadecimal spelling of some bytes, which is a name any filesystem holds.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut name, byte| {
            let _ = write!(name, "{byte:02x}");
            name
        })
}

/// Writes a new file whole, and flushes it to the device before anything renames it into place.
///
/// On Unix the file is owner-only from the moment it exists. A failure after it was created
/// removes it; a process that dies here leaves it, and the next [`RecordFile::open`] removes it.
fn write_whole(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    if written.is_err() {
        // Only this call could have created the file, because `create_new` refused an existing
        // name, so removing it here removes nothing another writer is using.
        let _ = std::fs::remove_file(path);
    }
    written
}
