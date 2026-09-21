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
//! | Unanswered dispatches | That this device sent a write the service holds no receipt for | **Kept.** It carries no content, and it is the only account of a write whose outcome nothing can establish. |
//! | Refused writes the service kept | That a refused write is held by the service as a copy of its own | **Kept.** It carries no content, and the ciphertext it names is on the service rather than here. |
//! | Pinned labels | The labels a person pinned | **Kept**, and excluded from what is published while privacy mode is on. |
//!
//! # One store, one lock
//!
//! Every change takes an exclusive lock on the store's own `store.lock`, so reading a checkpoint,
//! comparing it and replacing it is one step against every other window of the application and
//! against another process. The lock is the operating system's, so it is as good as the filesystem
//! holding it. A sync store belongs on the device, beside the draft store it works with.
//!
//! # One dispatch, one owner
//!
//! A dispatch is a transition this store owns as well. [`SyncStore::begin_dispatch`] marks the work
//! sent and takes a second operating-system lock, on the request itself, and anything that wants to
//! decide what became of that request claims the same lock first. So a client value holds no
//! authority this store has not recorded: two windows over one store cannot each conclude about the
//! other's live call, and a claim that succeeds because the owner died permits asking the service,
//! never concluding. The request's lock is taken **before** the store's wherever both are held,
//! which is what keeps the two orders from crossing.
//!
//! Each file is written to a temporary name, flushed, and renamed over its name, so a reader never
//! sees one half written. On Unix the directory entry is flushed afterwards; on Windows nothing
//! here flushes a directory, and this store makes no claim there that a name it acknowledged
//! survives losing power.

use std::path::{Path, PathBuf};

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{SyncConflictId, SyncObjectId, SyncRevisionId};
use kr_protocol::mailbox::mailbox_size_bucket;
use kr_protocol::scalars::{Bytes, Nullable, TimestampMs, U64, Uuid};
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
/// The extension of the record of a dispatch the service holds no receipt for.
const UNANSWERED_EXTENSION: &str = "unanswered";
/// The extension of the record of a refused write the service kept a copy of.
const RETAINED_EXTENSION: &str = "retained";
/// The extension of the lock one dispatch is owned through.
const CALLOUT_EXTENSION: &str = "callout";
/// The extension of a file being written, which is not yet a file.
const PARTIAL_EXTENSION: &str = "partial";
/// The name of the store's lock.
const LOCK_NAME: &str = "store.lock";
/// The name the pinned labels are kept under.
const LABELS_NAME: &str = "pinned.labels";
/// The name this device's privacy state is kept under.
const PRIVACY_NAME: &str = "privacy.state";

/// What this device's own notes on a copy may add to the object inside it.
///
/// A copy carries its own identity, the revision this device held, two generations and the instant
/// it arrived. Allowing for those separately is what keeps a copy that arrived at the service's
/// limit storable, rather than refusing to keep content the service was already carrying.
const CONFLICT_NOTE_BYTES: u64 = 512;

/// The most a stored conflict copy may carry, in bytes.
const MAX_CONFLICT_COPY_BYTES: u64 = super::MAX_OBJECT_BYTES + CONFLICT_NOTE_BYTES;

/// How many links the walk over a store's path follows before it gives up.
///
/// The walk is Unix only, and so is this.
#[cfg(unix)]
///
/// A backstop rather than the rule. Every kernel this runs on applies a limit of its own, usually
/// lower, and refuses to open through a longer chain before the walk ever sees it.
const MAX_PATH_LINKS: usize = 40;

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
    /// When this device sent it, when it has.
    ///
    /// Null while it is admitted and not sent. It says when this device let the content go, not
    /// that the service stored it.
    pub dispatched_at_ms: Nullable<TimestampMs>,
    /// Whether this work has been sent.
    ///
    /// Written durably **before** the call leaves, so a device that stops between the write and the
    /// answer still knows this may have reached the service. Admitted-and-never-dispatched work can
    /// be taken back; dispatched work can only be reconciled, and a record whose outcome is unknown
    /// stays here saying so.
    pub dispatched: bool,
    /// Whether another request has already worn this work's identity.
    ///
    /// A service answers `ID_CONFLICT` when the identity it is shown already answered a request
    /// carrying different content. The receipt under that identity is then an account of the other
    /// request, and settling this work from it would move the checkpoint to a revision this
    /// ciphertext never produced. So the identity is marked as taken and nothing is ever asked
    /// about it again: the work stays counted until privacy mode moves past the generation that
    /// admitted it, and the account of what left is kept the same way an unanswered dispatch's is.
    #[serde(default)]
    pub identity_taken: bool,
    /// The sealed object.
    ///
    /// A byte string on disk, not a list of numbers: the reader bounds a collection at four
    /// thousand members, so a sealed object above that written as a list would be a record this
    /// device could never open again, and a staged record it cannot open is work it can never
    /// settle.
    pub ciphertext: Bytes,
}

/// The staged record as the build before this one wrote it.
///
/// Two things changed: the sealed object is a byte string rather than a list of numbers, and a
/// record now says whether another request has worn its identity. A device that upgrades holds
/// records in the older form, and a device that cannot read a staged record can never settle the
/// dispatch it describes, so each one is read in this form once and written back in the current
/// one. It goes when no device can still hold a record written by that build.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StagedBefore {
    work_id: Uuid,
    object_id: SyncObjectId,
    kind: SyncObjectKind,
    revision: SyncRevisionId,
    expected_generation: U64,
    produced_under: U64,
    dispatched_at_ms: Nullable<TimestampMs>,
    dispatched: bool,
    ciphertext: Vec<u8>,
}

impl From<StagedBefore> for Staged {
    fn from(held: StagedBefore) -> Self {
        Self {
            work_id: held.work_id,
            object_id: held.object_id,
            kind: held.kind,
            revision: held.revision,
            expected_generation: held.expected_generation,
            produced_under: held.produced_under,
            dispatched_at_ms: held.dispatched_at_ms,
            dispatched: held.dispatched,
            identity_taken: false,
            ciphertext: Bytes::new(held.ciphertext),
        }
    }
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
    /// The revision this device held when the copy arrived.
    pub offered_revision: SyncRevisionId,
    /// The generation this device expected to replace, when it made a comparison.
    ///
    /// Null for a copy that came from a fetch, which compares nothing: it asked what was there and
    /// was told.
    pub expected_generation: Nullable<U64>,
    /// The generation the service held when the copy was taken.
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
    ///
    /// Null when the write was accepted and the service had moved past what it produced before this
    /// device could name a generation for it. The content left and was stored either way, which is
    /// what this record is for; where the object stands now is the next comparison's question.
    pub generation: Nullable<U64>,
    /// When this device let the content go.
    pub published_at_ms: TimestampMs,
}

/// A copy the service kept of one write it refused.
///
/// It carries no content: the object the write was about, the name the service gave what it kept,
/// and when this device let the content go. A refused comparison establishes that the write did not
/// replace the object; it does not establish that the service kept nothing, and a service that
/// stores the rejected write as a conflict copy of its own is holding ciphertext this device sent.
/// Section 24 shows what left rather than pretending it did not, so this record is kept for the same
/// reason a publication is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retained {
    /// The request this device sent.
    pub work_id: Uuid,
    /// The object the refused write was about.
    pub object_id: SyncObjectId,
    /// What kind of object it was.
    pub kind: SyncObjectKind,
    /// What the service called the copy it kept.
    pub conflict_id: SyncConflictId,
    /// When this device let the content go.
    ///
    /// Null for a record whose staged file named no instant, which is a device that stopped
    /// between marking the work dispatched and writing that mark.
    pub dispatched_at_ms: Nullable<TimestampMs>,
}

/// That this device sent one write the service holds no receipt for.
///
/// It carries no content: which object the write was about, what kind it was, and when this device
/// let it go. A receipt is what settles a dispatch, and a service that holds none for a request
/// either never received it or has passed section 9's thirty-day retention; neither establishes
/// that the write did not land. So the work is discarded under the late-result rule, because a
/// barrier nothing can lift is not a barrier, and this record keeps the one thing the discard must
/// not throw away: that the ciphertext left this device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unanswered {
    /// The request this device sent.
    pub work_id: Uuid,
    /// The object it would have published.
    pub object_id: SyncObjectId,
    /// What kind of object it was.
    pub kind: SyncObjectKind,
    /// When this device let the content go.
    ///
    /// Null for a record whose staged file named no instant, which is a device that stopped
    /// between marking the work dispatched and writing that mark.
    pub dispatched_at_ms: Nullable<TimestampMs>,
}

/// The privacy state this device records, durably.
///
/// Durably, because section 24 records the generation before any subsystem is touched: a boundary
/// a restart could not see would be a boundary a late result could cross. It lives in the store
/// rather than in memory for a second reason: every transition that has to be atomic against the
/// fence, admitting work, cancelling it and settling it, already takes the store's lock, so one
/// lock decides all of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyRecord {
    /// The host's privacy generation in force.
    pub generation: U64,
    /// Whether sync production is fenced.
    pub fenced: bool,
}

/// What the service said about one publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// It accepted the write, at this generation. The content has left this device.
    Accepted {
        /// The generation the service assigned.
        generation: U64,
    },
    /// It accepted the write and has moved past what the write produced.
    ///
    /// The content left and was stored. Where the object stands now is not something this answer
    /// names, so the publication is recorded and the note is left where it is: the next comparison
    /// is what finds out, and a note invented here could outrank the state that replaced this one.
    Superseded,
    /// It refused the comparison, so this write did not replace the object.
    ///
    /// The request carried its ciphertext to the service, so the content did leave the device. What
    /// the refusal establishes is that the comparison did not hold, and **not** that the service
    /// kept nothing: `retained` names the copy a service that stores a rejected write kept of it.
    ///
    /// The refusal is settled on its own, before anything is fetched. What the service holds
    /// instead is brought down afterwards and kept beside this device's content; a fetch that fails
    /// costs a copy, not the knowledge that the write did not land.
    Refused {
        /// What the service called the copy it kept of the refused write, when it kept one.
        retained: Option<SyncConflictId>,
    },
}

/// What settling one publication did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Settlement {
    /// The result was applied under the generation in force.
    Published,
    /// There was no such work to settle, because something had already settled it.
    ///
    /// Settling twice would write an effect twice. A second answer about work that is gone is
    /// therefore an answer about nothing, and it changes nothing.
    AlreadySettled,
    /// The result belonged to an earlier generation, so nothing was applied.
    ///
    /// An accepted write is still recorded as a publication, because it left this device and
    /// section 24 shows what left rather than pretending it did not. Nothing else is written: no
    /// checkpoint moves and no copy is kept, because both are retained content the cleanup that
    /// opened this generation has already removed.
    Discarded {
        /// The generation the work was produced under.
        produced_under: u64,
        /// The generation in force now.
        current: u64,
    },
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
    /// The dispatch that was presented is another request's.
    ///
    /// A settlement and a discard are decided under the dispatch they belong to, so the store can
    /// refuse a decision no owner is holding. A claim on one request says nothing about another.
    #[error("that dispatch is for request {holding}, not {wanted}")]
    OtherRequest {
        /// The request the dispatch is held for.
        holding: Uuid,
        /// The request the caller named.
        wanted: Uuid,
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
    /// The answer belonged to a privacy generation that is no longer in force.
    ///
    /// Nothing it brought down was written. Section 24 publishes no late old-generation result,
    /// and a copy or a note written now would be content the cleanup had already removed.
    #[error("that answer was produced under generation {produced_under}; {current} is in force")]
    LateResult {
        /// The generation the work was produced under.
        produced_under: u64,
        /// The generation in force now.
        current: u64,
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
            | Self::OtherRequest { .. }
            | Self::DraftElsewhere { .. }
            | Self::Encoding(_)
            | Self::Crypto(_) => ErrorCode::InvalidArgument,
            Self::Fenced { .. } | Self::LateResult { .. } => ErrorCode::PermissionDenied,
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
            | Self::OtherRequest { .. }
            | Self::DraftElsewhere { .. }
            | Self::Fenced { .. }
            | Self::LateResult { .. }
            | Self::StaleCheckpoint { .. }
            | Self::Encoding(_)
            | Self::Crypto(_) => UserAction::Nothing,
        }
    }
}

/// The result of a synchronisation call.
pub type Result<T> = std::result::Result<T, SyncError>;

/// What a listing found, including what it could not read.
///
/// A damaged file is named rather than dropped and rather than deleted. A conflict copy is content
/// a person is meant to choose between and a publication record is the only account of what left
/// this device; neither is a cache this store may throw away because a byte went wrong.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Listing<T> {
    /// What was read, oldest first.
    pub items: Vec<T>,
    /// The files that are not records this build reads.
    pub unreadable: Vec<PathBuf>,
}

impl<T> Listing<T> {
    /// Returns how many records were read.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true when nothing was read.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Every account of what has left this device, read together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhatLeft {
    /// The collections this device published, and the generation each reached.
    pub publications: Listing<Publication>,
    /// The work this device staged, whose dispatched records are writes with no settled outcome.
    pub staged: Listing<Staged>,
    /// The dispatches the service holds no receipt for.
    ///
    /// A request that is also staged is left out: a device that stopped between writing this record
    /// and removing the staged file holds both, and one request is one entry in any account of what
    /// left. The staged record is the one that stands, because it is the one that still counts as
    /// outstanding, and the first settlement of that request clears the other.
    pub unanswered: Listing<Unanswered>,
    /// The refused writes the service kept a copy of.
    pub retained: Listing<Retained>,
}

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
        // Every name on the way here, not only the levels this call created. Another opener may
        // have created one a moment ago and not yet flushed it, and a store that returned success
        // under such a name would be a store whose own path a crash could lose. A failure is
        // reported rather than ignored: a store that cannot open the directories its path is made
        // of cannot establish that the path survives a crash.
        flush_path_names(&directory).map_err(|source| storage(&directory, source))?;
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
        let outcome = self.read_object(object_id);
        drop(guard);
        outcome
    }

    /// Reads an object and the note beside it under one hold of the lock.
    ///
    /// Together, because a publication decides from both: the revision it is sending and the
    /// generation it expects to replace. Read separately, another writer could advance the object
    /// between them, and this one would send an older revision against the newer generation, which
    /// is a comparison it would win, replacing content it had never seen.
    ///
    /// # Errors
    ///
    /// As [`Self::object`] and [`Self::checkpoint`].
    pub fn object_and_checkpoint(
        &self,
        object_id: SyncObjectId,
    ) -> Result<(Option<SyncObject>, Option<SyncCheckpoint>)> {
        let guard = self.lock()?;
        let outcome = self
            .read_object(object_id)
            .and_then(|object| Ok((object, self.read_checkpoint(object_id)?)));
        drop(guard);
        outcome
    }

    /// Reads one stored object and checks that it is the object its own name says it is.
    ///
    /// The caller holds the lock.
    fn read_object(&self, object_id: SyncObjectId) -> Result<Option<SyncObject>> {
        let path = self.path(object_id, OBJECT_EXTENSION);
        let Some(object): Option<SyncObject> = self.read_optional(&path)? else {
            return Ok(None);
        };
        if object.object_id != object_id {
            return Err(SyncError::Corrupt {
                path,
                reason: format!("it holds object {}, not {object_id}", object.object_id),
            });
        }
        Ok(Some(object))
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
        let outcome = self.write_bytes(&self.path(object.object_id, OBJECT_EXTENSION), &bytes.0);
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
        let guard = self.lock()?;
        let outcome = self.write_checkpoint(object_id, checkpoint);
        drop(guard);
        outcome
    }

    /// Writes a checkpoint unless a later one already stands.
    ///
    /// The caller holds the lock.
    fn write_checkpoint(
        &self,
        object_id: SyncObjectId,
        checkpoint: SyncCheckpoint,
    ) -> Result<bool> {
        let bytes = kr_cbor::to_canonical_vec(&checkpoint)?;
        if let Some(held) = self.read_checkpoint(object_id)?
            && held.generation.get() > checkpoint.generation.get()
        {
            return Ok(false);
        }
        self.write_bytes(&self.path(object_id, CHECKPOINT_EXTENSION), &bytes)?;
        Ok(true)
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

    /// Reads this device's privacy state.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] or [`SyncError::Corrupt`].
    pub fn privacy(&self) -> Result<PrivacyRecord> {
        let guard = self.lock()?;
        let outcome = self.read_privacy();
        drop(guard);
        outcome
    }

    /// Records the privacy generation and whether production is fenced.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when it cannot be written. A generation this device cannot
    /// record is not one it claims to be in: the caller is told rather than left believing a
    /// boundary exists.
    pub fn record_privacy(&self, record: PrivacyRecord) -> Result<PrivacyRecord> {
        let guard = self.lock()?;
        let outcome = (|| {
            // A generation never goes backwards. Two control steps that overlap would otherwise
            // let the older one restore a boundary a newer one had already moved past, and every
            // result admitted under the newer generation would become acceptable again.
            let held = self.read_privacy()?;
            if held.generation.get() > record.generation.get() {
                return Ok(held);
            }
            let bytes = kr_cbor::to_canonical_vec(&record)?;
            self.write_bytes(&self.directory.join(PRIVACY_NAME), &bytes)?;
            Ok(record)
        })();
        drop(guard);
        outcome
    }

    /// Moves the generation forward, leaving the fence where it is, under one hold.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the record cannot be read or written.
    pub fn advance_privacy(&self, generation: u64) -> Result<PrivacyRecord> {
        let guard = self.lock()?;
        let outcome = (|| {
            let held = self.read_privacy()?;
            if held.generation.get() >= generation {
                return Ok(held);
            }
            let record = PrivacyRecord {
                generation: U64::new(generation),
                fenced: held.fenced,
            };
            let bytes = kr_cbor::to_canonical_vec(&record)?;
            self.write_bytes(&self.directory.join(PRIVACY_NAME), &bytes)?;
            Ok(record)
        })();
        drop(guard);
        outcome
    }

    /// Admits one object for publication, under one hold of the lock.
    ///
    /// The fence check, the object and its note, the sealing and the staged record are one step.
    /// Split apart, a fence could land between the check and the record, and the work would be
    /// admitted under a generation privacy mode had already closed.
    ///
    /// `seal` is given the object to encrypt. It runs inside the hold, which is what makes the
    /// generation the record names the generation that was in force when the ciphertext was made.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Fenced`] while privacy mode is on, [`SyncError::Unknown`] when no such
    /// object is stored, whatever `seal` failed with, and [`SyncError::Storage`] when the record
    /// cannot be written.
    pub fn admit(
        &self,
        object_id: SyncObjectId,
        seal: impl FnOnce(&SyncObject) -> Result<Vec<u8>>,
    ) -> Result<Staged> {
        let guard = self.lock()?;
        let outcome = (|| {
            let privacy = self.read_privacy()?;
            if privacy.fenced {
                return Err(SyncError::Fenced {
                    generation: privacy.generation.get(),
                });
            }
            let object = self
                .read_object(object_id)?
                .ok_or(SyncError::Unknown { object_id })?;
            let note = self.read_checkpoint(object_id)?;
            let ciphertext = seal(&object)?;
            let staged = Staged {
                work_id: self.fresh_id()?,
                object_id,
                kind: object.kind(),
                revision: object.revision,
                // Nothing there yet is generation nought, which is the comparison a first
                // publication makes.
                expected_generation: note.map_or(U64::new(0), |note| note.generation),
                produced_under: privacy.generation,
                dispatched: false,
                identity_taken: false,
                dispatched_at_ms: Nullable::null(),
                ciphertext: Bytes::new(ciphertext),
            };
            // Under the reader's own limits, so a record this device could not open again is
            // refused rather than written. Staged work it cannot read is work it can never settle.
            let bytes = encode_readable(&staged)?;
            self.write_bytes(&self.named(staged.work_id, STAGED_EXTENSION), &bytes.0)?;
            Ok(staged)
        })();
        drop(guard);
        outcome
    }

    /// Returns every piece of staged work, oldest identifier first.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be read.
    pub fn staged(&self) -> Result<Listing<Staged>> {
        let guard = self.lock()?;
        let outcome = self.read_staged_all();
        drop(guard);
        outcome
    }

    /// Takes ownership of one dispatch, and records that the work has been sent.
    ///
    /// The record is written before the call leaves, so a device that stops between the write and
    /// the answer still knows this may have reached the service. The fence is checked here too: a
    /// fence that lands after admission still reaches work that has not gone, and it takes the
    /// record back rather than letting the queue empty itself.
    ///
    /// Ownership is the store's and not the caller's. The returned [`Dispatch`] holds an exclusive
    /// operating-system lock on the request, so another client value, another window and another
    /// process all meet it, and none of them may decide what became of this request while somebody
    /// is still waiting for the answer. Releasing it says this device's call is over, never that
    /// the request stopped at the service.
    ///
    /// The request's own lock is taken **before** the store's, as it is everywhere that takes both,
    /// so two of them can never wait on each other.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Fenced`] when privacy mode reached this work before it left,
    /// [`SyncError::Storage`] when the record or the lock cannot be read or written, and
    /// [`SyncError::Unknown`] when nothing is staged under that work identifier.
    pub fn begin_dispatch(
        &self,
        work_id: Uuid,
        object_id: SyncObjectId,
        now: TimestampMs,
    ) -> Result<Dispatch> {
        let owned = Lock::take(&self.named(work_id, CALLOUT_EXTENSION))?;
        let path = self.named(work_id, STAGED_EXTENSION);
        let guard = self.lock()?;
        let outcome = (|| {
            let privacy = self.read_privacy()?;
            let mut staged: Staged = self
                .read_optional(&path)?
                .ok_or(SyncError::Unknown { object_id })?;
            // Already sent. Saying so again changes nothing, and it must not take the record
            // away: that record is the only thing that says this work may be out there.
            if staged.dispatched {
                return Ok(());
            }
            // The fence is checked here as well as at admission, because a fence can land between
            // the two. This work has not left, so the fence still reaches it: the record is taken
            // back rather than sent, which is exactly what the cancellation would have done to it.
            if privacy.fenced || privacy.generation.get() != staged.produced_under.get() {
                self.retire(work_id)?;
                self.remove_file(&path)?;
                return Err(SyncError::Fenced {
                    generation: privacy.generation.get(),
                });
            }
            staged.dispatched = true;
            staged.dispatched_at_ms = Nullable::some(now);
            let bytes = encode_readable(&staged)?;
            self.write_bytes(&path, &bytes.0)
        })();
        drop(guard);
        outcome?;
        Ok(Dispatch {
            work_id,
            _lock: owned,
        })
    }

    /// Claims one dispatched request, so that this device may decide what became of it.
    ///
    /// A claim is what the store grants instead of a client deciding for itself. It succeeds only
    /// when nobody holds the request: a process that died released its lock, which is why a claim
    /// can succeed after a crash, and what the claim then permits is **asking** the service, never
    /// concluding. The service's answer is what settles the request.
    ///
    /// The record comes back as the store holds it, not as a caller remembers it, and the claim is
    /// held for as long as the returned [`Dispatch`] lives, so a settlement decided under it cannot
    /// race a fresh dispatch of the same request.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the lock or the record cannot be read.
    pub fn claim_dispatched(&self, work_id: Uuid) -> Result<Claimed> {
        let Some(owned) = Lock::try_take(&self.named(work_id, CALLOUT_EXTENSION))? else {
            return Ok(Claimed::InHand);
        };
        let path = self.named(work_id, STAGED_EXTENSION);
        let guard = self.lock()?;
        let held = self.read_staged(&path);
        drop(guard);
        Ok(match held? {
            Some(staged) if staged.dispatched => Claimed::Taken(
                Dispatch {
                    work_id,
                    _lock: owned,
                },
                staged,
            ),
            _ => Claimed::Gone,
        })
    }

    /// Claims one request, whether or not this store still holds a staged record for it.
    ///
    /// A late answer is a decision about a request as much as a settlement is, and a request whose
    /// staged record has gone can still receive one: it was discarded, or something else settled
    /// it. Deciding about it takes the same lock, so a claim here is what a caller holding no
    /// dispatch of its own presents.
    ///
    /// Returns nothing when somebody has a call out for the request.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the lock cannot be taken.
    pub fn claim_request(&self, work_id: Uuid) -> Result<Option<Dispatch>> {
        Ok(
            Lock::try_take(&self.named(work_id, CALLOUT_EXTENSION))?.map(|owned| Dispatch {
                work_id,
                _lock: owned,
            }),
        )
    }

    /// Records that another request has already worn this work's identity.
    ///
    /// The service says so when the identity it is shown answered a request carrying different
    /// content. That receipt accounts for the other request, so this work can never be settled from
    /// it: it is marked here, under the lock, and nothing asks about that identity again. The work
    /// stays counted, and the account of what left it is kept the way an unanswered dispatch's is.
    ///
    /// Returns true when the record was marked, false when nothing is staged under that identity
    /// any more or the work was never sent.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the record cannot be read or written.
    pub fn disown_identity(&self, work_id: Uuid) -> Result<bool> {
        let path = self.named(work_id, STAGED_EXTENSION);
        let guard = self.lock()?;
        let outcome = (|| {
            let Some(mut staged) = self.read_staged(&path)? else {
                return Ok(false);
            };
            if !staged.dispatched {
                return Ok(false);
            }
            if staged.identity_taken {
                return Ok(true);
            }
            staged.identity_taken = true;
            let bytes = encode_readable(&staged)?;
            self.write_bytes(&path, &bytes.0)?;
            Ok(true)
        })();
        drop(guard);
        outcome
    }

    /// Takes back every piece of work that was admitted and never sent.
    ///
    /// Reading which records are undispatched and deleting them is one step, so a publication that
    /// marks itself dispatched cannot have its record taken away as though it had never gone.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when a record cannot be read or removed.
    pub fn take_back_undispatched(&self, generation: u64) -> Result<u64> {
        let guard = self.lock()?;
        let outcome = (|| {
            self.owns_cleanup(generation)?;
            let mut taken = 0_u64;
            for item in self.read_staged_all()?.items {
                // Work admitted under a later generation belongs to a later cleanup, not this one.
                if item.dispatched || item.produced_under.get() > generation {
                    continue;
                }
                self.remove_file(&self.named(item.work_id, STAGED_EXTENSION))?;
                taken = taken.saturating_add(1);
            }
            Ok(taken)
        })();
        drop(guard);
        outcome
    }

    /// Discards one dispatched request the service holds no receipt for.
    ///
    /// Only when privacy mode has moved past the generation the work was admitted under. That is
    /// the late-result rule: the cleanup has already decided that nothing produced under the older
    /// generation may be published, so a request nothing can account for is work this device will
    /// never apply an answer to, and holding the barrier open for it would make the cleanup
    /// incompletable rather than honest. Under the generation in force the work stays where it is,
    /// because the next reconciliation may still find a receipt for it.
    ///
    /// Reading the privacy record and removing the staged file are one hold, so a fence landing
    /// alongside cannot make this discard work the generation now in force admitted.
    ///
    /// The account of what left is kept: an [`Unanswered`] record replaces the staged file, and it
    /// carries no ciphertext.
    ///
    /// It is decided under the dispatch the request is claimed by, so a second caller cannot
    /// discard a request somebody is still waiting on.
    ///
    /// Returns true when the record was discarded, false when the work was never sent, when the
    /// generation that admitted it is still the one in force, or when something had already
    /// settled it.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::OtherRequest`] when the dispatch is held for a different request, and
    /// [`SyncError::Storage`] when a record cannot be read, written or removed.
    pub fn discard_unanswered(&self, dispatch: &Dispatch, staged: &Staged) -> Result<bool> {
        dispatch.owns(staged.work_id)?;
        let path = self.named(staged.work_id, STAGED_EXTENSION);
        let guard = self.lock()?;
        let outcome = (|| {
            // A record that is gone is work something else has already settled, so this discard is
            // a discard of nothing. The record on disk decides, not the copy the caller holds.
            let Some(held) = self.read_staged(&path)? else {
                return Ok(false);
            };
            // Work that was never sent is [`Self::take_back_undispatched`]'s, and nothing left the
            // device under it. Writing an account of a departure that never happened would be as
            // wrong as losing one that did.
            if !held.dispatched {
                return Ok(false);
            }
            let privacy = self.read_privacy()?;
            if privacy.generation.get() <= held.produced_under.get() {
                return Ok(false);
            }
            let record = Unanswered {
                work_id: held.work_id,
                object_id: held.object_id,
                kind: held.kind,
                dispatched_at_ms: held.dispatched_at_ms,
            };
            let bytes = kr_cbor::to_canonical_vec(&record)?;
            // The account is durable before the work is discarded. The other order would lose what
            // left this device if the store stopped between the two writes, and a device that stops
            // between them holds both records: every settlement clears the account of a request it
            // settles, and every report counts such a request once.
            self.write_bytes(&self.named(held.work_id, UNANSWERED_EXTENSION), &bytes)?;
            self.remove_file(&path)?;
            self.retire(held.work_id)?;
            Ok(true)
        })();
        drop(guard);
        outcome
    }

    /// Returns how much dispatched work has no settled outcome.
    ///
    /// A record this build cannot read counts too. A store cannot say that nothing is outstanding
    /// on the strength of a record it could not open.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be read.
    pub fn unsettled(&self) -> Result<u64> {
        let staged = self.staged()?;
        let dispatched = staged.items.iter().filter(|item| item.dispatched).count() as u64;
        Ok(dispatched.saturating_add(staged.unreadable.len() as u64))
    }
    /// Applies what the service answered, under the late-result rule, in one step.
    ///
    /// The generation is read and the effects are written under one hold, so a fence cannot land
    /// between deciding that a result may be applied and applying it. Settling the same work twice
    /// writes nothing the second time.
    ///
    /// An accepted write always records the publication, whatever generation is in force, because
    /// the content left this device and section 24 shows what left rather than pretending it did
    /// not. Under a late generation nothing else is written: the checkpoint would move on the
    /// strength of work privacy mode had already cancelled.
    ///
    /// It settles **this** request and nothing else. An answer about the object says what the
    /// service holds; it does not say what became of another request that is still out, and a
    /// request that had no answer can still be accepted afterwards. Retiring one on the strength of
    /// the other would be claiming knowledge this contract cannot give.
    ///
    /// An answer to work a reconciliation discarded corrects the account of what left rather than
    /// changing nothing: the generation that admitted it has been fenced either way, so nothing is
    /// published, but an accepted write becomes a publication record instead of a dispatch nothing
    /// could account for.
    ///
    /// It is decided under the dispatch the request is claimed by, so a second caller cannot settle
    /// a request somebody is still waiting on, and an answer is applied only where the record the
    /// store holds still expects one.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::OtherRequest`] when the dispatch is held for a different request, and
    /// [`SyncError::Storage`] when a record cannot be written or removed.
    pub fn settle(
        &self,
        dispatch: &Dispatch,
        staged: &Staged,
        outcome: Outcome,
        now: TimestampMs,
    ) -> Result<Settlement> {
        dispatch.owns(staged.work_id)?;
        let path = self.named(staged.work_id, STAGED_EXTENSION);
        let guard = self.lock()?;
        let settled = (|| {
            // The record on disk decides, never the copy the caller is holding. Settling twice
            // would write an effect twice, and a record that is gone is work something else has
            // already settled, so this answer is an answer about that instead.
            let Some(held) = self.read_staged(&path)? else {
                return self.settle_discarded(staged, outcome, now);
            };
            // Work that was never sent has no answer to apply: nothing left the device under it,
            // and a cleanup is what takes it back.
            if !held.dispatched {
                return Ok(Settlement::AlreadySettled);
            }
            let privacy = self.read_privacy()?;
            let in_force = privacy.generation.get() == held.produced_under.get();
            // When this device let the content go, which is what an account of what left says. A
            // reconciliation twenty days later settles the same departure, and writing its own
            // instant here would say the content left twenty days later than it did.
            let left_at = held.dispatched_at_ms.as_ref().copied().unwrap_or(now);

            self.record_outcome(&held, outcome, in_force, left_at)?;
            // A device that stopped between writing an account of an unanswered dispatch and
            // removing the staged file holds both. This answer settles the request, so that account
            // goes first: a device that stops here still holds the staged record, so the next
            // settlement of the request writes the same answer again and clears what is left.
            self.remove_file(&self.named(held.work_id, UNANSWERED_EXTENSION))?;
            self.remove_file(&path)?;
            self.retire(held.work_id)?;

            Ok(if in_force {
                Settlement::Published
            } else {
                Settlement::Discarded {
                    produced_under: held.produced_under.get(),
                    current: privacy.generation.get(),
                }
            })
        })();
        drop(guard);
        settled
    }

    /// Writes what one answer established, under the generation rule.
    ///
    /// An accepted write always records the publication, whatever generation is in force, because
    /// the content left this device. A copy the service kept of a refused write is recorded for the
    /// same reason: it is ciphertext this device sent that the service still holds. Neither record
    /// carries content, so neither is something a cleanup removes.
    ///
    /// The checkpoint is the one thing the generation rule gates, because it is production state a
    /// cleanup has already removed under a generation that has been fenced.
    ///
    /// The caller holds the lock.
    fn record_outcome(
        &self,
        staged: &Staged,
        outcome: Outcome,
        in_force: bool,
        left_at: TimestampMs,
    ) -> Result<()> {
        match outcome {
            Outcome::Accepted { generation } => {
                self.write_publication(&Publication {
                    object_id: staged.object_id,
                    kind: staged.kind,
                    generation: Nullable::some(generation),
                    published_at_ms: left_at,
                })?;
                if in_force {
                    self.write_checkpoint(
                        staged.object_id,
                        SyncCheckpoint {
                            generation,
                            published_revision: Nullable::some(staged.revision),
                        },
                    )?;
                }
            }
            Outcome::Superseded => {
                self.write_publication(&Publication {
                    object_id: staged.object_id,
                    kind: staged.kind,
                    generation: Nullable::null(),
                    published_at_ms: left_at,
                })?;
            }
            Outcome::Refused { retained } => {
                if let Some(conflict_id) = retained {
                    let record = Retained {
                        work_id: staged.work_id,
                        object_id: staged.object_id,
                        kind: staged.kind,
                        conflict_id,
                        // When the content left, as the store recovered it. The caller's copy of
                        // the record may predate the dispatch that wrote the instant down.
                        dispatched_at_ms: Nullable::some(left_at),
                    };
                    let bytes = kr_cbor::to_canonical_vec(&record)?;
                    self.write_bytes(&self.named(staged.work_id, RETAINED_EXTENSION), &bytes)?;
                }
            }
        }
        Ok(())
    }

    /// Settles an answer about work this store holds no staged record for.
    ///
    /// Two things look like this. The request was **discarded**, which happens when the service
    /// held no receipt for it and privacy mode had fenced the generation that admitted it; an
    /// answer arriving afterwards is that receipt reaching this device late, and it settles nothing
    /// that could be published, because the generation is gone, but it does say what became of
    /// content that left, so the account is corrected and the record of a dispatch nothing could
    /// account for goes. Or something else **settled** it already, which is what another window of
    /// the application reconciling the same store looks like.
    ///
    /// The generation is read either way, under this same hold. A request that was settled
    /// elsewhere under a generation privacy mode has since moved past is still a request no answer
    /// may be published for, and saying "already settled" to its caller would let a late answer be
    /// reported as an accepted publication under a generation that has been fenced.
    ///
    /// The caller holds the lock.
    fn settle_discarded(
        &self,
        staged: &Staged,
        outcome: Outcome,
        now: TimestampMs,
    ) -> Result<Settlement> {
        let privacy = self.read_privacy()?;
        let in_force = privacy.generation.get() == staged.produced_under.get();
        let discarded = self.named(staged.work_id, UNANSWERED_EXTENSION);
        let Some(account) = self.read_optional::<Unanswered>(&discarded)? else {
            return Ok(if in_force {
                Settlement::AlreadySettled
            } else {
                Settlement::Discarded {
                    produced_under: staged.produced_under.get(),
                    current: privacy.generation.get(),
                }
            });
        };
        let left_at = account.dispatched_at_ms.as_ref().copied().unwrap_or(now);
        // The generation that admitted this work has been fenced, which is what a discard means, so
        // the checkpoint is never moved from here whatever the answer was.
        self.record_outcome(staged, outcome, false, left_at)?;
        self.remove_file(&discarded)?;
        self.retire(staged.work_id)?;
        Ok(Settlement::Discarded {
            produced_under: staged.produced_under.get(),
            current: privacy.generation.get(),
        })
    }

    /// Applies what a fetch brought down, under the late-result rule, in one step.
    ///
    /// A fetch writes a copy and a note, and both are retained sync content. Checking the
    /// generation and writing them is one hold, so a cleanup cannot land between the check and the
    /// writes and leave behind content it had just removed.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when a record cannot be written.
    pub fn apply_fetch(
        &self,
        produced_under: u64,
        copy: Option<&ConflictCopy>,
        object_id: SyncObjectId,
        checkpoint: SyncCheckpoint,
    ) -> Result<Settlement> {
        let guard = self.lock()?;
        let applied = (|| {
            let privacy = self.read_privacy()?;
            if privacy.fenced || privacy.generation.get() != produced_under {
                return Ok(Settlement::Discarded {
                    produced_under,
                    current: privacy.generation.get(),
                });
            }
            if let Some(copy) = copy {
                self.write_conflict(copy)?;
            }
            self.write_checkpoint(object_id, checkpoint)?;
            Ok(Settlement::Published)
        })();
        drop(guard);
        applied
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
        let guard = self.lock()?;
        let outcome = self.write_conflict(copy);
        drop(guard);
        outcome
    }

    /// Writes one copy and prunes the object's oldest, keeping the one just written.
    ///
    /// The caller holds the lock.
    fn write_conflict(&self, copy: &ConflictCopy) -> Result<()> {
        // A copy is held to the storage bound rather than to the publishable bound. Content the
        // service was already carrying is content this device keeps: refusing it because this
        // device's own note around it costs a few hundred bytes would lose the very thing the
        // person is meant to choose from. A copy that arrived at the service's limit may therefore
        // be a few bytes too large to publish again from here.
        let bytes = encode_within_limit(copy, MAX_CONFLICT_COPY_BYTES)?;
        let bytes = &bytes.0;
        // The new copy is written first. Dropping an old one before the replacement is durable
        // would lose a choice the person had and keep nothing in its place.
        self.write_bytes(
            &self.named(copy.conflict_id.get(), CONFLICT_EXTENSION),
            bytes,
        )?;
        let mut held = self.read_all::<ConflictCopy>(CONFLICT_EXTENSION)?.items;
        // The copy just admitted is never the one pruned. Ordering is by a timestamp the caller
        // supplied, and a clock that stepped back, or two answers that finished out of order,
        // would otherwise make the newest refusal delete itself and leave a caller holding an
        // identity nothing is stored under.
        held.retain(|kept| {
            kept.object_id == copy.object_id && kept.conflict_id != copy.conflict_id
        });
        held.sort_by_key(|kept| (kept.recorded_at_ms.get(), kept.conflict_id.get()));
        while held.len() as u64 >= MAX_SYNC_CONFLICT_COPIES {
            let oldest = held.remove(0);
            self.remove_file(&self.named(oldest.conflict_id.get(), CONFLICT_EXTENSION))?;
        }
        Ok(())
    }

    /// Returns every copy kept for one object, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be read.
    pub fn conflicts(&self, object_id: SyncObjectId) -> Result<Listing<ConflictCopy>> {
        let guard = self.lock()?;
        let outcome = self.read_all::<ConflictCopy>(CONFLICT_EXTENSION);
        drop(guard);
        let mut listing = outcome?;
        listing.items.retain(|copy| copy.object_id == object_id);
        listing.items.sort_by_key(|copy| copy.recorded_at_ms.get());
        Ok(listing)
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
    pub fn record_publication(&self, publication: &Publication) -> Result<bool> {
        let guard = self.lock()?;
        let outcome = self.write_publication(publication);
        drop(guard);
        outcome
    }

    /// Writes a publication record unless a later one already stands.
    ///
    /// The caller holds the lock.
    fn write_publication(&self, publication: &Publication) -> Result<bool> {
        let bytes = kr_cbor::to_canonical_vec(publication)?;
        let path = self.path(publication.object_id, PUBLICATION_EXTENSION);
        // A record already naming a later generation stands, for the reason a checkpoint does: two
        // answers can arrive out of order, and writing the older one would say this device
        // published less recently than it did. Where one of the two names no generation there is no
        // such comparison to make, and an answer that could not say where a write left the object
        // is not thereby an older one, so the later departure is the one that stands.
        if let Some(held) = self.read_optional::<Publication>(&path)? {
            let standing = held.generation.as_ref().map(|value| value.get());
            let offered = publication.generation.as_ref().map(|value| value.get());
            let older = match (standing, offered) {
                (Some(standing), Some(offered)) => standing > offered,
                _ => held.published_at_ms.get() > publication.published_at_ms.get(),
            };
            if older {
                return Ok(false);
            }
        }
        self.write_bytes(&path, &bytes)?;
        Ok(true)
    }

    /// Returns every account of what has left this device, under one hold of the lock.
    ///
    /// Under one hold because a reconciliation moves a record from one list to another: it settles
    /// a dispatch or discards one nothing can account for, and a reader that took the lists
    /// separately could look at the staged work before that move and at the rest after it, and see
    /// the record in neither.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be read.
    pub fn what_left(&self) -> Result<WhatLeft> {
        let guard = self.lock()?;
        let outcome = (|| {
            let mut publications = self.read_all::<Publication>(PUBLICATION_EXTENSION)?;
            publications
                .items
                .sort_by_key(|record| record.published_at_ms.get());
            let staged = self.read_staged_all()?;
            let mut unanswered = self.read_all::<Unanswered>(UNANSWERED_EXTENSION)?;
            // A device that stopped between writing the account of an unanswered dispatch and
            // removing the staged file holds both records for one request. One request is one
            // entry: the staged record is the one that stands, because it is the one that still
            // counts as outstanding.
            unanswered.items.retain(|record| {
                !staged
                    .items
                    .iter()
                    .any(|work| work.work_id == record.work_id)
            });
            Ok(WhatLeft {
                publications,
                staged,
                unanswered,
                retained: self.read_all::<Retained>(RETAINED_EXTENSION)?,
            })
        })();
        drop(guard);
        outcome
    }

    /// Returns what this device has published, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be read.
    pub fn publications(&self) -> Result<Listing<Publication>> {
        let guard = self.lock()?;
        let outcome = self.read_all::<Publication>(PUBLICATION_EXTENSION);
        drop(guard);
        let mut listing = outcome?;
        listing
            .items
            .sort_by_key(|record| record.published_at_ms.get());
        Ok(listing)
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
    /// the pinned labels, the objects this device holds, the record of what has already been
    /// published and the record of a dispatch nothing could account for. The last two carry no
    /// content and are the only account of what left.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when a file cannot be removed. What was removed before the
    /// failure stays removed; the caller asks again.
    pub fn remove_content(&self, generation: u64) -> Result<(u64, u64)> {
        let guard = self.lock()?;
        let outcome = (|| {
            self.owns_cleanup(generation)?;
            let mut bytes = 0_u64;
            let mut records = 0_u64;
            let mut remove = |path: &Path| -> Result<()> {
                let size = std::fs::metadata(path).map(|data| data.len()).unwrap_or(0);
                self.remove_file(path)?;
                bytes = bytes.saturating_add(size);
                records = records.saturating_add(1);
                Ok(())
            };
            // A partial holds whatever a writer that died was putting down, which may be staged
            // ciphertext or a conflict copy, so it goes with them rather than waiting for the next
            // time the store is opened.
            for extension in [CONFLICT_EXTENSION, CHECKPOINT_EXTENSION, PARTIAL_EXTENSION] {
                for path in self.paths_with(extension)? {
                    remove(&path)?;
                }
            }
            // Staged work is not all alike. What was admitted and never sent is content on its way
            // out and goes; what was sent is not here any more, and its record is the only thing
            // that says so, so it stays and keeps counting as outstanding. A record this build
            // cannot read stays too, because a record it could not open is not one it may call
            // nothing. Work admitted under a *later* generation is another cleanup's, not this
            // one's.
            for path in self.paths_with(STAGED_EXTENSION)? {
                match self.read_staged(&path) {
                    Ok(Some(staged)) => {
                        if !staged.dispatched && staged.produced_under.get() <= generation {
                            remove(&path)?;
                        }
                    }
                    Ok(None) => {}
                    Err(SyncError::Corrupt { .. } | SyncError::Encoding(_)) => {}
                    Err(error) => return Err(error),
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

    /// Refuses a cleanup step that a later generation has overtaken.
    ///
    /// It is checked here, inside the hold that does the deleting, rather than before it: two
    /// control steps can overlap, and the later one has already decided what is retained, so an
    /// earlier step finishing afterwards would delete copies and notes that belong to the
    /// generation now in force.
    ///
    /// The caller holds the lock.
    fn owns_cleanup(&self, generation: u64) -> Result<()> {
        let privacy = self.read_privacy()?;
        if privacy.generation.get() > generation {
            return Err(SyncError::LateResult {
                produced_under: generation,
                current: privacy.generation.get(),
            });
        }
        Ok(())
    }

    /// Reads the privacy state, or the state of a device that has never enabled privacy mode.
    ///
    /// The caller holds the lock.
    fn read_privacy(&self) -> Result<PrivacyRecord> {
        Ok(self
            .read_optional(&self.directory.join(PRIVACY_NAME))?
            .unwrap_or_default())
    }

    /// Returns a fresh identity for a record this store is about to write.
    fn fresh_id(&self) -> Result<Uuid> {
        kr_transport::random::fresh_uuid_v4().map_err(|error| SyncError::Corrupt {
            path: self.directory.clone(),
            reason: error.to_string(),
        })
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

    /// Reads one staged record, rewriting one an earlier build wrote.
    ///
    /// A record this device cannot read is a dispatch it can never settle, so the older form is
    /// read and written back in the current one the first time it is seen. Anything else that
    /// cannot be read is reported as it was, because a record this build does not understand is
    /// not one it may quietly replace.
    ///
    /// The caller holds the lock.
    fn read_staged(&self, path: &Path) -> Result<Option<Staged>> {
        match self.read_optional::<Staged>(path) {
            Ok(staged) => Ok(staged),
            Err(error @ (SyncError::Corrupt { .. } | SyncError::Encoding(_))) => {
                let Some(held) = self.read_previous_staged(path)? else {
                    return Err(error);
                };
                let staged = Staged::from(held);
                let bytes = encode_readable(&staged)?;
                self.write_bytes(path, &bytes.0)?;
                Ok(Some(staged))
            }
            Err(error) => Err(error),
        }
    }

    /// Reads one staged record in the form an earlier build wrote, or nothing.
    ///
    /// The bound on how many members one collection may hold is raised for this read alone: the
    /// older form wrote the sealed object as a list of numbers, so a payload of any size is past
    /// the ordinary bound, and refusing to read it here would leave exactly the records this
    /// migration exists for. Everything else, including the bound on the whole record, is the
    /// reader's own.
    ///
    /// The caller holds the lock.
    fn read_previous_staged(&self, path: &Path) -> Result<Option<StagedBefore>> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => super::Zeroising(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(storage(path, error)),
        };
        let limits = kr_cbor::Limits {
            max_collection_len: kr_cbor::Limits::DEFAULT.max_message_len,
            ..kr_cbor::Limits::DEFAULT
        };
        Ok(kr_cbor::from_canonical_slice::<StagedBefore>(&bytes.0, &limits).ok())
    }

    /// Reads every staged record, naming what it could not read.
    ///
    /// The caller holds the lock.
    fn read_staged_all(&self) -> Result<Listing<Staged>> {
        let mut listing = Listing {
            items: Vec::new(),
            unreadable: Vec::new(),
        };
        for path in self.paths_with(STAGED_EXTENSION)? {
            match self.read_staged(&path) {
                Ok(Some(value)) => listing.items.push(value),
                Ok(None) => {}
                Err(SyncError::Corrupt { .. } | SyncError::Encoding(_)) => {
                    listing.unreadable.push(path);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(listing)
    }

    /// Reads one stored value, or nothing when the name is not there.
    ///
    /// The caller holds the lock.
    fn read_optional<T: Serialize + for<'a> Deserialize<'a>>(
        &self,
        path: &Path,
    ) -> Result<Option<T>> {
        let bytes = match std::fs::read(path) {
            // The file holds a record in the clear, so the buffer is cleared when it goes out of
            // scope rather than dropped as an ordinary vector.
            Ok(bytes) => super::Zeroising(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(storage(path, error)),
        };
        let value = kr_cbor::from_canonical_slice(&bytes.0, &kr_cbor::Limits::DEFAULT).map_err(
            |error| SyncError::Corrupt {
                path: path.to_path_buf(),
                reason: super::cbor_fault(&error),
            },
        )?;
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

    /// Reads every stored value with one extension, naming what it could not read.
    ///
    /// A damaged file is kept and named. Only a checkpoint is a cache this store throws away: a
    /// conflict copy is content a person is meant to choose between and a publication record is the
    /// only account of what left this device, so reading a list is never a reason to lose one.
    ///
    /// The caller holds the lock.
    fn read_all<T: Serialize + for<'a> Deserialize<'a>>(
        &self,
        extension: &str,
    ) -> Result<Listing<T>> {
        let mut listing = Listing {
            items: Vec::new(),
            unreadable: Vec::new(),
        };
        for path in self.paths_with(extension)? {
            match self.read_optional::<T>(&path) {
                Ok(Some(value)) => listing.items.push(value),
                Ok(None) => {}
                Err(SyncError::Corrupt { .. } | SyncError::Encoding(_)) => {
                    listing.unreadable.push(path);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(listing)
    }

    fn read_labels(&self) -> Result<Vec<PinnedLabel>> {
        Ok(self
            .read_optional::<Vec<PinnedLabel>>(&self.directory.join(LABELS_NAME))?
            .unwrap_or_default())
    }

    fn write_labels(&self, labels: &[PinnedLabel]) -> Result<()> {
        let bytes = encode_within_limit(&labels.to_vec(), MAX_CONFLICT_COPY_BYTES)?;
        self.write_bytes(&self.directory.join(LABELS_NAME), &bytes.0)
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

    /// Removes the lock one dispatch was owned through, once the request is retired.
    ///
    /// Nothing waits on that lock afterwards: a claim tries it without blocking rather than queuing
    /// behind it, and a request is dispatched once, so there is no second call to take it.
    ///
    /// The caller holds the lock.
    fn retire(&self, work_id: Uuid) -> Result<()> {
        self.remove_file(&self.named(work_id, CALLOUT_EXTENSION))
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
        let file = Self::open(path)?;
        file.lock().map_err(|source| storage(path, source))?;
        Ok(Self { _file: file })
    }

    /// Takes the lock when it is free, and answers rather than waiting when it is not.
    fn try_take(path: &Path) -> Result<Option<Self>> {
        let file = Self::open(path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(source)) => Err(storage(path, source)),
        }
    }

    fn open(path: &Path) -> Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|source| storage(path, source))
    }
}

/// One dispatch, owned for as long as this value lives, and the request it is for.
///
/// Holding it is what makes this device the owner of a request. The lock underneath is the
/// operating system's, so another client value, another window of the application and another
/// process over the same store all meet it, and none of them may decide what became of the request
/// while somebody is still waiting for its answer. Releasing it says this device's call is over; it
/// never says the request stopped at the service, which is why what a released request needs is a
/// claim and a question rather than a conclusion.
#[derive(Debug)]
pub struct Dispatch {
    work_id: Uuid,
    _lock: Lock,
}

impl Dispatch {
    /// Returns the request this dispatch is held for.
    #[must_use]
    pub const fn request(&self) -> Uuid {
        self.work_id
    }

    /// Refuses a decision about a request this dispatch is not held for.
    fn owns(&self, work_id: Uuid) -> Result<()> {
        if self.work_id == work_id {
            return Ok(());
        }
        Err(SyncError::OtherRequest {
            holding: self.work_id,
            wanted: work_id,
        })
    }
}

/// What a claim on one dispatched request found.
#[derive(Debug)]
pub enum Claimed {
    /// The claim was taken. The record is the one the store holds, under the dispatch it is held
    /// by, and it stays claimed for as long as that dispatch lives.
    Taken(Dispatch, Staged),
    /// Somebody has a call out for the request, so nothing here may decide about it.
    ///
    /// A service writes its receipt when it commits a write, so a request still on the wire looks
    /// exactly like one that never arrived. The device making the call is the only thing that can
    /// tell the two apart, and this is that device saying so.
    InHand,
    /// Nothing is staged under that identity any more, so there is nothing to decide.
    Gone,
}

/// Encodes an object and holds it to the size the service will actually take.
///
/// The bound is on the **padded** length, because padding is what is sealed and what a service
/// measures. An object that encodes to exactly the plaintext limit pads to the bucket above it,
/// which is a size no synchronised object may be, so accepting it locally would mean accepting one
/// that could never be published.
fn encode_within(object: &SyncObject) -> Result<super::Zeroising> {
    // The reader's own limits, not only a byte count. A value this store accepted and its own
    // decoder then refused would be a value a person could write and never read back, and the byte
    // bound does not catch it: four thousand short labels are small and are past the decoder's
    // bound on how many members one collection may have.
    let bytes = super::Zeroising(kr_cbor::to_canonical_vec_within(
        object,
        &kr_cbor::Limits::DEFAULT,
    )?);
    if mailbox_size_bucket(bytes.0.len() as u64) > super::MAX_OBJECT_BYTES {
        return Err(SyncError::TooLarge {
            len: bytes.0.len(),
            limit: largest_publishable_object() as usize,
        });
    }
    Ok(bytes)
}

/// Encodes one record this store must be able to read back.
///
/// Under the reader's own limits and not only a byte count: a record written past them would be one
/// this device could never open again. That matters most for staged work, because a staged record
/// the store cannot read is a dispatch it can never settle and a barrier it can never lift.
fn encode_readable<T: Serialize>(value: &T) -> Result<super::Zeroising> {
    Ok(super::Zeroising(kr_cbor::to_canonical_vec_within(
        value,
        &kr_cbor::Limits::DEFAULT,
    )?))
}

/// Encodes one record and holds it to a byte bound, under the reader's own structural limits.
fn encode_within_limit<T: Serialize>(value: &T, limit: u64) -> Result<super::Zeroising> {
    let bytes = super::Zeroising(kr_cbor::to_canonical_vec_within(
        value,
        &kr_cbor::Limits::DEFAULT,
    )?);
    if bytes.0.len() as u64 > limit {
        return Err(SyncError::TooLarge {
            len: bytes.0.len(),
            limit: limit as usize,
        });
    }
    Ok(bytes)
}

/// Returns the largest encoded object whose padded length is still one a service will take.
fn largest_publishable_object() -> u64 {
    let mut len = super::MAX_OBJECT_BYTES;
    while len > 0 && mailbox_size_bucket(len) > super::MAX_OBJECT_BYTES {
        len -= 1;
    }
    len
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
        #[cfg_attr(
            not(unix),
            expect(unused_mut, reason = "only Unix sets a mode on the builder")
        )]
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

/// Flushes the directory entry of every name this store's path is made of.
///
/// A path is a chain of names, and losing any one of them leaves a store nothing reaches. The chain
/// is not only the components a caller spelled: a link is a name in a directory, it leads
/// somewhere, and the rest of the path continues from there. So this resolves the path the way the
/// kernel does, one component at a time, flushing the directory each name lives in and continuing
/// from a link's target when it meets one.
#[cfg(unix)]
fn flush_path_names(directory: &Path) -> std::io::Result<()> {
    use std::collections::VecDeque;
    use std::ffi::OsString;

    let start = if directory.is_absolute() {
        directory.to_path_buf()
    } else {
        std::env::current_dir()?.join(directory)
    };
    let mut remaining: VecDeque<OsString> = start
        .components()
        .map(|component| component.as_os_str().to_os_string())
        .collect();
    let mut resolved = PathBuf::new();
    let mut flushed: Vec<PathBuf> = Vec::new();
    let mut followed = 0_usize;

    while let Some(name) = remaining.pop_front() {
        // A file cannot be called `.` or `..`, and only the root component is `/`, so what a name
        // means is not ambiguous.
        if name == std::path::MAIN_SEPARATOR_STR {
            resolved.push(&name);
            continue;
        }
        if name == "." {
            continue;
        }
        if name == ".." {
            resolved.pop();
            continue;
        }
        let parent = if resolved.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            resolved.clone()
        };
        if !flushed.contains(&parent) {
            sync_directory(&parent)?;
            flushed.push(parent);
        }
        resolved.push(&name);
        let metadata = std::fs::symlink_metadata(&resolved)?;
        if metadata.file_type().is_symlink() {
            followed += 1;
            if followed > MAX_PATH_LINKS {
                return Err(std::io::Error::other(
                    "the store's path passes through too many links to follow",
                ));
            }
            let target = std::fs::read_link(&resolved)?;
            resolved.pop();
            if target.is_absolute() {
                resolved = PathBuf::new();
            }
            for component in target.components().rev() {
                remaining.push_front(component.as_os_str().to_os_string());
            }
        }
    }
    sync_directory(&resolved)?;
    Ok(())
}

/// Flushes nothing, because this build flushes no directory on Windows.
#[cfg(not(unix))]
fn flush_path_names(directory: &Path) -> std::io::Result<()> {
    let _ = directory;
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
