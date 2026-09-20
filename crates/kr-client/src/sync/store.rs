//! This device's own synchronisation state, on this device's disk.
//!
//! Five things live here, and they are separate because privacy mode treats them differently:
//!
//! | What | Why it is here | What privacy mode does with it |
//! | --- | --- | --- |
//! | Staged ciphertext | An object admitted for publication and not yet sent | Removed. It is content on its way out. |
//! | Conflict copies | What the service held when a write of this device's lost | Removed. It is content another device produced. |
//! | Checkpoints | Where each object reached on the service | Removed. It is production state, not content, and losing it costs a comparison. |
//! | Publications | That this device published a collection at a generation, and when | **Kept.** It is the only account of what left, and section 24 shows what left rather than pretending it did not. |
//! | Pinned labels | The labels a person pinned | **Kept**, and excluded from what is published while privacy mode is on. |
//!
//! # One store, one lock
//!
//! Every change takes an exclusive lock on the store's own `store.lock`, so reading a checkpoint,
//! comparing it and replacing it is one step against every other window of the application and
//! against another process. The lock is the operating system's, so it is as good as the filesystem
//! holding it. A sync store belongs on the device, beside the draft store it works with.
//!
//! Each file is written to a temporary name, flushed, and renamed over its name, so a reader never
//! sees one half written. On Unix the directory entry is flushed afterwards; on Windows nothing
//! here flushes a directory, and this store makes no claim there that a name it acknowledged
//! survives losing power.

use std::path::{Path, PathBuf};

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{SyncConflictId, SyncObjectId, SyncRevisionId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};
use kr_protocol::sync::{MAX_SYNC_CONFLICT_COPIES, SyncObjectKind};
use serde::{Deserialize, Serialize};

use super::SyncObject;
use crate::retry::UserAction;

/// The extension of a stored object this device holds.
const OBJECT_EXTENSION: &str = "object";
/// The extension of the note recording where an object reached on the service.
const CHECKPOINT_EXTENSION: &str = "note";
/// The extension of ciphertext admitted for publication and not yet sent.
const STAGED_EXTENSION: &str = "staged";
/// The extension of a copy kept because a comparison was lost.
const CONFLICT_EXTENSION: &str = "conflict";
/// The extension of the record that this device published a collection.
const PUBLICATION_EXTENSION: &str = "published";
/// The extension of a file being written, which is not yet a file.
const PARTIAL_EXTENSION: &str = "partial";
/// The name of the store's lock.
const LOCK_NAME: &str = "store.lock";
/// The name the pinned labels are kept under.
const LABELS_NAME: &str = "pinned.labels";

/// Where an object has reached on the synchronisation service.
///
/// A note, not content: losing it costs a comparison and a fetch, never a setting. It is written
/// beside the object rather than inside it, and an object's own revision is never the generation a
/// comparison names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncCheckpoint {
    /// The generation the service holds.
    pub generation: U64,
    /// The revision *this device* published at that generation.
    ///
    /// Null when the generation came from another device's write, which this device only fetched.
    pub published_revision: Nullable<SyncRevisionId>,
}

/// Ciphertext admitted for publication and not yet sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Staged {
    /// The piece of work this is.
    pub work_id: Uuid,
    /// The object it publishes.
    pub object_id: SyncObjectId,
    /// What kind of object it is.
    pub kind: SyncObjectKind,
    /// The revision it carries.
    pub revision: SyncRevisionId,
    /// The generation it expects to replace.
    pub expected_generation: U64,
    /// The host's privacy generation this work was admitted under.
    ///
    /// A result carries it back, and the publication is accepted only when it is still the
    /// generation in force. An older one belongs to work privacy mode cancelled.
    pub produced_under: U64,
    /// The sealed object.
    pub ciphertext: Vec<u8>,
}

/// A copy kept because a comparison was lost.
///
/// Section 20 keeps a conflicting copy for the person to choose from instead of resolving it by
/// whichever clock was further ahead. What is kept is what the service held; this device's own
/// content is where it was, untouched, which is the direction section 24 makes the rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictCopy {
    /// The copy.
    pub conflict_id: SyncConflictId,
    /// The object the refused write was about.
    pub object_id: SyncObjectId,
    /// The revision this device offered and the service refused.
    pub offered_revision: SyncRevisionId,
    /// The generation this device expected to replace.
    pub expected_generation: U64,
    /// The generation the service held.
    pub current_generation: U64,
    /// What the service held, unchanged.
    pub other: SyncObject,
    /// When this device recorded the refusal.
    pub recorded_at_ms: TimestampMs,
}

/// That this device published one collection, and when.
///
/// It carries no content. It is the account of what left this device, which privacy mode keeps:
/// section 24 shows an artefact that has already been uploaded rather than claiming it was erased.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    /// The object that was published.
    pub object_id: SyncObjectId,
    /// What kind of object it was.
    pub kind: SyncObjectKind,
    /// The generation the service assigned the newest publication of it.
    pub generation: U64,
    /// When this device last published it.
    pub published_at_ms: TimestampMs,
}

/// A label the person pinned.
///
/// Section 24 retains a pinned label locally unless it is explicitly cleared, and excludes it from
/// subsequent sync while privacy mode is on.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedLabel {
    /// The label.
    pub label: String,
    /// When the person pinned it.
    pub pinned_at_ms: TimestampMs,
}

/// Why a synchronisation store refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
    /// The directory, the lock or a stored file could not be read or written.
    #[error("the sync store at {path} could not be used: {source}")]
    Storage {
        /// What was being read or written.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// No object with that identity is stored here.
    #[error("no synchronised object {object_id} is stored")]
    Unknown {
        /// The identity that was asked for.
        object_id: SyncObjectId,
    },
    /// A stored file is not something this build can read.
    #[error("the stored file at {path} could not be read: {reason}")]
    Corrupt {
        /// Which file.
        path: PathBuf,
        /// What was wrong with it.
        reason: String,
    },
    /// The object is larger than the contract carries.
    #[error("the object encodes to {len} bytes; the limit is {limit}")]
    TooLarge {
        /// The encoded size.
        len: usize,
        /// The limit.
        limit: usize,
    },
    /// The object that came down is not the one this collection was asked for.
    #[error("collection {collection} holds object {found}, not {expected}")]
    NotThatObject {
        /// The collection that was read.
        collection: String,
        /// The object it turned out to hold.
        found: SyncObjectId,
        /// The object that was asked for.
        expected: SyncObjectId,
    },
    /// A draft arrived where a settings object was expected.
    ///
    /// A draft belongs to the device's draft store and is published by its own synchronised half.
    /// Nothing here applies one, which is what keeps one way of writing a draft.
    #[error("collection {collection} holds a draft; drafts are synchronised by the draft store")]
    DraftElsewhere {
        /// The collection that was read.
        collection: String,
    },
    /// Sync production is fenced, because privacy mode is on.
    #[error("sync production is fenced at privacy generation {generation}")]
    Fenced {
        /// The generation it was fenced at.
        generation: u64,
    },
    /// The checkpoint names a generation the service no longer has.
    ///
    /// A service that was reset or replaced leaves one. The publication is refused and there is
    /// nothing to fetch; forgetting the checkpoint is the explicit recovery, and nothing does it
    /// automatically.
    #[error(
        "object {object_id} expects generation {expected}, which the service does not hold; forget its checkpoint to start again"
    )]
    StaleCheckpoint {
        /// The object.
        object_id: SyncObjectId,
        /// The generation the note names.
        expected: u64,
    },
    /// The client failed.
    #[error("{0}")]
    Client(#[from] Box<crate::ClientError>),
    /// A value could not be encoded or decoded as KR-CBOR-1.
    #[error("the stored value was not canonical: {0}")]
    Encoding(#[from] kr_cbor::CborError),
    /// The sealing or opening of an object failed.
    #[error("{0}")]
    Crypto(#[from] kr_crypto::CryptoError),
}

impl From<crate::ClientError> for SyncError {
    fn from(error: crate::ClientError) -> Self {
        Self::Client(Box::new(error))
    }
}

impl SyncError {
    /// Returns the stable protocol code this refusal is reported under.
    ///
    /// A local store is not a host, and the codes are a vocabulary rather than a claim about one.
    /// What a person is told comes from [`Self::user_action`].
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Storage { .. } => ErrorCode::StorageUnavailable,
            Self::Unknown { .. }
            | Self::Corrupt { .. }
            | Self::TooLarge { .. }
            | Self::NotThatObject { .. }
            | Self::DraftElsewhere { .. }
            | Self::Encoding(_)
            | Self::Crypto(_) => ErrorCode::InvalidArgument,
            Self::Fenced { .. } => ErrorCode::PermissionDenied,
            Self::StaleCheckpoint { .. } => ErrorCode::DraftConflict,
            Self::Client(error) => error.code(),
        }
    }

    /// Returns the direct action a user interface offers for this refusal.
    #[must_use]
    pub fn user_action(&self) -> UserAction {
        match self {
            Self::Storage { .. } => UserAction::FixConfiguration,
            Self::Client(error) => error.user_action(),
            // The message is the whole of it: choose a copy, shorten the settings, turn privacy
            // mode off, or start the object again against the service this device now uses.
            Self::Unknown { .. }
            | Self::Corrupt { .. }
            | Self::TooLarge { .. }
            | Self::NotThatObject { .. }
            | Self::DraftElsewhere { .. }
            | Self::Fenced { .. }
            | Self::StaleCheckpoint { .. }
            | Self::Encoding(_)
            | Self::Crypto(_) => UserAction::Nothing,
        }
    }
}

/// The result of a synchronisation call.
pub type Result<T> = std::result::Result<T, SyncError>;

/// This device's own synchronisation state, on this device's disk.
///
/// The directory is the caller's, as the draft store's is: a desktop application puts it under its
/// own support directory, a command line under the user's state directory, a test under a
/// temporary one. The store creates it owner-only where the platform expresses that, and writes
/// every file whole or not at all.
///
/// Every method blocks, on the filesystem and on the store's lock.
#[derive(Debug)]
pub struct SyncStore {
    directory: PathBuf,
}

impl SyncStore {
    /// Opens or creates the store.
    ///
    /// A file left behind by a process that died while writing is swept away here, because a
    /// partial name is not a record and the next writer would otherwise walk past it for ever.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be created, made owner-only or
    /// read.
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self> {
        let directory = directory.into();
        private_directory(&directory).map_err(|source| storage(&directory, source))?;
        sync_directory(&directory).map_err(|source| storage(&directory, source))?;
        let store = Self { directory };
        let guard = store.lock()?;
        let swept = store.sweep_partials();
        drop(guard);
        swept?;
        Ok(store)
    }

    /// Returns the directory this store keeps its files in.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    // -- objects this device holds ------------------------------------------------------------

    /// Returns the object this device holds, when it holds one.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] or [`SyncError::Corrupt`].
    pub fn object(&self, object_id: SyncObjectId) -> Result<Option<SyncObject>> {
        let guard = self.lock()?;
        let outcome = self.read_optional(&self.path(object_id, OBJECT_EXTENSION));
        drop(guard);
        outcome
    }

    /// Replaces the object this device holds.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::TooLarge`] when the record is past what one synchronised object
    /// carries, and [`SyncError::Storage`] when it cannot be written.
    pub fn put_object(&self, object: &SyncObject) -> Result<()> {
        let bytes = encode_within(object)?;
        let guard = self.lock()?;
        let outcome = self.write_bytes(&self.path(object.object_id, OBJECT_EXTENSION), &bytes);
        drop(guard);
        outcome
    }

    // -- checkpoints --------------------------------------------------------------------------

    /// Returns where an object last reached on the service, when it has.
    ///
    /// A note this build cannot read is removed and reported as absent. It is a cache: the next
    /// publication compares against nothing, learns where the object stands from the service, and
    /// writes the note again.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the note cannot be read or removed.
    pub fn checkpoint(&self, object_id: SyncObjectId) -> Result<Option<SyncCheckpoint>> {
        let guard = self.lock()?;
        let outcome = self.read_checkpoint(object_id);
        drop(guard);
        outcome
    }

    /// Records where an object reached on the service.
    ///
    /// A note that already names a later generation stands, and this returns false. Two answers can
    /// arrive out of order: a publication is accepted, another device writes, a fetch brings that
    /// down, and only then does the first answer come back naming the generation before it.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the note cannot be read or written.
    pub fn record_checkpoint(
        &self,
        object_id: SyncObjectId,
        checkpoint: SyncCheckpoint,
    ) -> Result<bool> {
        let bytes = kr_cbor::to_canonical_vec(&checkpoint)?;
        let guard = self.lock()?;
        let outcome = (|| {
            if let Some(held) = self.read_checkpoint(object_id)?
                && held.generation.get() > checkpoint.generation.get()
            {
                return Ok(false);
            }
            self.write_bytes(&self.path(object_id, CHECKPOINT_EXTENSION), &bytes)?;
            Ok(true)
        })();
        drop(guard);
        outcome
    }

    /// Forgets where an object reached on the service.
    ///
    /// A device signed out of the service, or starting again against a different one, has a note
    /// naming a generation nothing holds. Forgetting it costs the next publication a comparison and
    /// a fetch; keeping it costs a comparison against a number that means nothing. Nothing does it
    /// automatically, because a note that looks stale and is not is a note whose object another
    /// device has just written.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the note cannot be removed.
    pub fn forget_checkpoint(&self, object_id: SyncObjectId) -> Result<()> {
        let guard = self.lock()?;
        let outcome = self.remove_file(&self.path(object_id, CHECKPOINT_EXTENSION));
        drop(guard);
        outcome
    }

    // -- staged ciphertext --------------------------------------------------------------------

    /// Writes ciphertext admitted for publication.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when it cannot be written.
    pub fn stage(&self, staged: &Staged) -> Result<()> {
        let bytes = kr_cbor::to_canonical_vec(staged)?;
        let guard = self.lock()?;
        let outcome = self.write_bytes(&self.named(staged.work_id, STAGED_EXTENSION), &bytes);
        drop(guard);
        outcome
    }

    /// Returns every piece of staged ciphertext, oldest identifier first.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be read.
    pub fn staged(&self) -> Result<Vec<Staged>> {
        let guard = self.lock()?;
        let outcome = self.read_all(STAGED_EXTENSION);
        drop(guard);
        outcome
    }

    /// Removes one piece of staged ciphertext, and makes its absence durable.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when it cannot be removed.
    pub fn discard(&self, work_id: Uuid) -> Result<()> {
        let guard = self.lock()?;
        let outcome = self.remove_file(&self.named(work_id, STAGED_EXTENSION));
        drop(guard);
        outcome
    }

    // -- conflict copies ----------------------------------------------------------------------

    /// Keeps a copy beside this device's own content, bounded by section 20's limit.
    ///
    /// The oldest copy is dropped first when the limit is reached, so the newest refusal is always
    /// the one that is kept: a device that never resolves its conflicts cannot spend a person's
    /// storage without bound, and the copy that matters most is the one that just arrived.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::TooLarge`] or [`SyncError::Storage`].
    pub fn keep_conflict(&self, copy: &ConflictCopy) -> Result<()> {
        let bytes = kr_cbor::to_canonical_vec(copy)?;
        if bytes.len() as u64 > super::MAX_OBJECT_BYTES {
            return Err(SyncError::TooLarge {
                len: bytes.len(),
                limit: super::MAX_OBJECT_BYTES as usize,
            });
        }
        let guard = self.lock()?;
        let outcome = (|| {
            let mut held: Vec<ConflictCopy> = self.read_all(CONFLICT_EXTENSION)?;
            held.retain(|kept| kept.object_id == copy.object_id);
            held.sort_by_key(|kept| kept.recorded_at_ms.get());
            while held.len() as u64 >= MAX_SYNC_CONFLICT_COPIES {
                let oldest = held.remove(0);
                self.remove_file(&self.named(oldest.conflict_id.get(), CONFLICT_EXTENSION))?;
            }
            self.write_bytes(
                &self.named(copy.conflict_id.get(), CONFLICT_EXTENSION),
                &bytes,
            )
        })();
        drop(guard);
        outcome
    }

    /// Returns every copy kept for one object, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be read.
    pub fn conflicts(&self, object_id: SyncObjectId) -> Result<Vec<ConflictCopy>> {
        let guard = self.lock()?;
        let outcome = self.read_all::<ConflictCopy>(CONFLICT_EXTENSION);
        drop(guard);
        let mut copies = outcome?;
        copies.retain(|copy| copy.object_id == object_id);
        copies.sort_by_key(|copy| copy.recorded_at_ms.get());
        Ok(copies)
    }

    /// Takes one copy out of the store, which is how a person's choice is recorded.
    ///
    /// The choice itself is the caller's: it publishes what was chosen through the ordinary path.
    /// This library never decides between two copies, because section 20 says a person does.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the copy cannot be read or removed.
    pub fn resolve_conflict(&self, conflict_id: SyncConflictId) -> Result<Option<ConflictCopy>> {
        let path = self.named(conflict_id.get(), CONFLICT_EXTENSION);
        let guard = self.lock()?;
        let outcome = (|| {
            let copy: Option<ConflictCopy> = self.read_optional(&path)?;
            if copy.is_some() {
                self.remove_file(&path)?;
            }
            Ok(copy)
        })();
        drop(guard);
        outcome
    }

    // -- publications -------------------------------------------------------------------------

    /// Records that this device published one collection.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the record cannot be written.
    pub fn record_publication(&self, publication: &Publication) -> Result<()> {
        let bytes = kr_cbor::to_canonical_vec(publication)?;
        let guard = self.lock()?;
        let outcome = self.write_bytes(
            &self.path(publication.object_id, PUBLICATION_EXTENSION),
            &bytes,
        );
        drop(guard);
        outcome
    }

    /// Returns what this device has published, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be read.
    pub fn publications(&self) -> Result<Vec<Publication>> {
        let guard = self.lock()?;
        let outcome = self.read_all::<Publication>(PUBLICATION_EXTENSION);
        drop(guard);
        let mut records = outcome?;
        records.sort_by_key(|record| record.published_at_ms.get());
        Ok(records)
    }

    // -- pinned labels ------------------------------------------------------------------------

    /// Returns the labels the person pinned, in order.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] or [`SyncError::Corrupt`].
    pub fn pinned_labels(&self) -> Result<Vec<PinnedLabel>> {
        let guard = self.lock()?;
        let outcome = self.read_labels();
        drop(guard);
        outcome
    }

    /// Pins a label, or moves an existing one to this instant.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the labels cannot be written.
    pub fn pin_label(&self, label: impl Into<String>, now: TimestampMs) -> Result<()> {
        let label = label.into();
        let guard = self.lock()?;
        let outcome = (|| {
            let mut labels = self.read_labels()?;
            labels.retain(|held| held.label != label);
            labels.push(PinnedLabel {
                label,
                pinned_at_ms: now,
            });
            labels.sort();
            self.write_labels(&labels)
        })();
        drop(guard);
        outcome
    }

    /// Clears one pinned label, which is the only thing that removes one.
    ///
    /// Section 24 keeps a pinned label unless it is explicitly cleared, so privacy mode does not
    /// reach it and neither does anything else in this store.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the labels cannot be written.
    pub fn clear_pinned_label(&self, label: &str) -> Result<bool> {
        let guard = self.lock()?;
        let outcome = (|| {
            let mut labels = self.read_labels()?;
            let before = labels.len();
            labels.retain(|held| held.label != label);
            if labels.len() == before {
                return Ok(false);
            }
            self.write_labels(&labels)?;
            Ok(true)
        })();
        drop(guard);
        outcome
    }

    // -- privacy ------------------------------------------------------------------------------

    /// Removes the staged ciphertext, the conflict copies and the checkpoints, and says what went.
    ///
    /// The figure is what this call actually removed, counted from the files it deleted, so a
    /// report cannot claim a removal that did not happen. What stays is named rather than left out:
    /// the pinned labels, the objects this device holds, and the record of what has already been
    /// published.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when a file cannot be removed. What was removed before the
    /// failure stays removed; the caller asks again.
    pub fn remove_content(&self) -> Result<(u64, u64)> {
        let guard = self.lock()?;
        let outcome = (|| {
            let mut bytes = 0_u64;
            let mut records = 0_u64;
            for extension in [CONFLICT_EXTENSION, STAGED_EXTENSION, CHECKPOINT_EXTENSION] {
                for path in self.paths_with(extension)? {
                    let size = std::fs::metadata(&path).map(|data| data.len()).unwrap_or(0);
                    self.remove_file(&path)?;
                    bytes = bytes.saturating_add(size);
                    records = records.saturating_add(1);
                }
            }
            Ok((bytes, records))
        })();
        drop(guard);
        outcome
    }

    // -- the filesystem -----------------------------------------------------------------------

    fn lock(&self) -> Result<Lock> {
        Lock::take(&self.directory.join(LOCK_NAME))
    }

    fn path(&self, object_id: SyncObjectId, extension: &str) -> PathBuf {
        self.named(object_id.get(), extension)
    }

    fn named(&self, id: Uuid, extension: &str) -> PathBuf {
        self.directory.join(format!("{id}.{extension}"))
    }

    /// Reads a checkpoint, removing and reporting as absent one this build cannot read.
    ///
    /// The caller holds the lock.
    fn read_checkpoint(&self, object_id: SyncObjectId) -> Result<Option<SyncCheckpoint>> {
        let path = self.path(object_id, CHECKPOINT_EXTENSION);
        match self.read_optional::<SyncCheckpoint>(&path) {
            Ok(checkpoint) => Ok(checkpoint),
            Err(SyncError::Corrupt { .. } | SyncError::Encoding(_)) => {
                self.remove_file(&path)?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Reads one stored value, or nothing when the name is not there.
    ///
    /// The caller holds the lock.
    fn read_optional<T: Serialize + for<'a> Deserialize<'a>>(
        &self,
        path: &Path,
    ) -> Result<Option<T>> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(storage(path, error)),
        };
        let value =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).map_err(|error| {
                SyncError::Corrupt {
                    path: path.to_path_buf(),
                    reason: error.to_string(),
                }
            })?;
        Ok(Some(value))
    }

    /// Returns every path with one extension, in name order.
    ///
    /// The caller holds the lock.
    fn paths_with(&self, extension: &str) -> Result<Vec<PathBuf>> {
        let suffix = format!(".{extension}");
        let mut paths = Vec::new();
        for entry in
            std::fs::read_dir(&self.directory).map_err(|source| storage(&self.directory, source))?
        {
            let entry = entry.map_err(|source| storage(&self.directory, source))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.ends_with(&suffix) {
                paths.push(entry.path());
            }
        }
        paths.sort();
        Ok(paths)
    }

    /// Reads every stored value with one extension.
    ///
    /// A file this build cannot read is removed and left out. Each of these is a cache or a copy:
    /// losing one costs a comparison or a copy a person would have chosen between, never a setting
    /// this device holds.
    ///
    /// The caller holds the lock.
    fn read_all<T: Serialize + for<'a> Deserialize<'a>>(&self, extension: &str) -> Result<Vec<T>> {
        let mut values = Vec::new();
        for path in self.paths_with(extension)? {
            match self.read_optional::<T>(&path) {
                Ok(Some(value)) => values.push(value),
                Ok(None) => {}
                Err(SyncError::Corrupt { .. } | SyncError::Encoding(_)) => {
                    self.remove_file(&path)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(values)
    }

    fn read_labels(&self) -> Result<Vec<PinnedLabel>> {
        Ok(self
            .read_optional::<Vec<PinnedLabel>>(&self.directory.join(LABELS_NAME))?
            .unwrap_or_default())
    }

    fn write_labels(&self, labels: &[PinnedLabel]) -> Result<()> {
        let bytes = kr_cbor::to_canonical_vec(&labels.to_vec())?;
        self.write_bytes(&self.directory.join(LABELS_NAME), &bytes)
    }

    /// Writes one file whole and makes its name durable.
    ///
    /// The caller holds the lock.
    fn write_bytes(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        let partial = self.directory.join(format!(
            "{}.{PARTIAL_EXTENSION}",
            kr_transport::random::fresh_uuid_v4().map_err(|error| SyncError::Corrupt {
                path: path.to_path_buf(),
                reason: error.to_string(),
            })?
        ));
        write_whole(&partial, bytes).map_err(|source| storage(&partial, source))?;
        if let Err(source) = std::fs::rename(&partial, path) {
            let _ = std::fs::remove_file(&partial);
            return Err(storage(path, source));
        }
        sync_directory(&self.directory).map_err(|source| storage(&self.directory, source))?;
        Ok(())
    }

    /// Removes one file and makes its absence durable.
    ///
    /// The caller holds the lock.
    fn remove_file(&self, path: &Path) -> Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(storage(path, error)),
        }
        sync_directory(&self.directory).map_err(|source| storage(&self.directory, source))?;
        Ok(())
    }

    /// Removes what a process that died while writing left behind.
    ///
    /// The caller holds the lock.
    fn sweep_partials(&self) -> Result<()> {
        for path in self.paths_with(PARTIAL_EXTENSION)? {
            self.remove_file(&path)?;
        }
        Ok(())
    }
}

/// The store's lock, held for as long as this value is.
#[derive(Debug)]
struct Lock {
    _file: std::fs::File,
}

impl Lock {
    fn take(path: &Path) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|source| storage(path, source))?;
        file.lock().map_err(|source| storage(path, source))?;
        Ok(Self { _file: file })
    }
}

fn encode_within(object: &SyncObject) -> Result<Vec<u8>> {
    let bytes = kr_cbor::to_canonical_vec(object)?;
    if bytes.len() as u64 > super::MAX_OBJECT_BYTES {
        return Err(SyncError::TooLarge {
            len: bytes.len(),
            limit: super::MAX_OBJECT_BYTES as usize,
        });
    }
    Ok(bytes)
}

fn storage(path: &Path, source: std::io::Error) -> SyncError {
    SyncError::Storage {
        path: path.to_path_buf(),
        source,
    }
}

/// Creates the directory owner-only, and makes an existing one owner-only.
///
/// A person's settings and the labels they pinned. A directory anything on the machine could read
/// would be one this store had no business writing into, so an existing directory is narrowed
/// rather than accepted. On Windows the directory takes whatever access list it inherits, which
/// this store does not narrow: what protects it there is the access list of the directory the
/// caller chose.
fn private_directory(directory: &Path) -> std::io::Result<()> {
    // Each missing level is created in turn rather than all at once, because a directory is a name
    // in the directory above it and a name is durable only once that directory's entry is flushed.
    let mut missing = Vec::new();
    let mut level = Some(directory);
    while let Some(path) = level {
        if path.as_os_str().is_empty() || path.is_dir() {
            break;
        }
        missing.push(path);
        level = path.parent();
    }
    for path in missing.iter().rev() {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        match builder.create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            sync_directory(parent)?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(directory)?.permissions();
        if permissions.mode() & 0o777 != 0o700 {
            permissions.set_mode(0o700);
            std::fs::set_permissions(directory, permissions)?;
        }
    }
    Ok(())
}

/// Writes a new file whole, and flushes it to the device before anything renames it into place.
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

/// Flushes a directory entry, so a name that was replaced survives a crash.
///
/// Unix only. This build flushes no directory on Windows and makes no claim there that a name it
/// acknowledged survives losing power. What holds on both is that the new contents are written and
/// flushed before anything renames them into place, so a reader never sees a file half written.
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(directory)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
    }
    Ok(())
}
