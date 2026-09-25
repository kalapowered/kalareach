//! Drafts the device owns, and what an attachment has to do with them.
//!
//! Section 24: a draft is a durable `draft_id` owned by a device or client instance, with its own
//! revision and target session, application and binding revision. **An attachment is only its
//! current presentation association.** Connection loss removes that association, not the draft. The
//! same authorised device may rebind it to a new attachment on reconnect; a changed application or
//! binding marks it conflicted or orphaned for explicit retargeting, never automatic submission.
//! Local unsent drafts survive independently of host availability; synced drafts use compare and
//! swap with conflict copies. Reconnection never replaces the user's draft with stale remote input.
//!
//! # Two things, deliberately apart
//!
//! [`DraftStore`] holds drafts on this device's disk. [`Associations`] holds which attachment is
//! presenting which draft right now, in memory, and nothing else. They are separate types because
//! they have separate lifetimes: a draft outlives every connection this client makes, and an
//! association cannot outlive the connection that produced the attachment. Putting the attachment
//! inside the draft record would make losing a connection a change to durable state.
//!
//! # One draft, one file, one lock
//!
//! A draft is stored as `<draft_id>.draft`, written to a temporary file, flushed, and renamed over
//! its name. Every change takes an exclusive lock on the store's own `store.lock` file and reading a
//! draft takes a shared one, so reading a revision, comparing it and replacing it is one step against
//! every other window of the application and against another process. Without that a second editor
//! could pass the comparison a moment before the first one wrote, and the text it replaced would be
//! gone with no trace that it had ever been there.
//!
//! The lock is the operating system's, so it is as good as the filesystem holding it: on a local
//! disk it is exact, and on a network mount it is whatever that mount implements. A draft store
//! belongs on the device, which is what section 24 means by a device-owned draft.
//!
//! # Nothing here submits
//!
//! There is one way to reach a submission, [`Draft::submission`], and it is a check rather than an
//! action: it returns the target a caller would submit against, or the reason it may not.
//! [`Associations::bind`], [`Associations::connection_lost`] and [`Draft::rebind`] return no such
//! thing, so no reconnect and no rebind can turn into a submitted prompt. Sending it is the
//! caller's own separate step, as section 12 requires of transfer, insertion and submission.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use kr_ipc::paths::{NameKind, flush_directory, flush_path_names};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{
    AgentBindingRevision, ApplicationInstanceId, AttachmentId, DeviceId, DraftId, DraftRevision,
    SessionId, SyncConflictId, SyncObjectId,
};
use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};
use kr_protocol::sync::SyncObjectKind;
use kr_protocol::transfer::{AttachmentHandle, DraftState};
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};
use crate::retry::UserAction;
use crate::services::{SyncExchanged, SyncFetched, SyncPosition, SyncRecoveryId, nothing_held};
use crate::sync::client::{
    Answer, ask_about, count_settled, diverged, end_fenced, finish_resolutions, forked,
};
use crate::sync::store::standing;
use crate::sync::{
    Across, Claimed, InGeneration, Outcome, Reconciled, Resolutions, Settlement, Standing,
    SyncError, SyncStore,
};

/// The most a draft's synchronised payload may carry, in bytes.
///
/// It is [`kr_protocol::sync::MAX_SYNC_OBJECT_PLAINTEXT_BYTES`], the plaintext a synchronised object
/// carries before padding, and a draft is one of the three kinds section 20 admits. A draft too
/// large to synchronise would be a draft this contract cannot carry, so the bound applies to every
/// edit a person makes on the device as well as on the wire, and it applies to the encoded record
/// rather than to the text alone: attachments and a target take space too.
pub const MAX_DRAFT_BYTES: usize = kr_protocol::sync::MAX_SYNC_OBJECT_PLAINTEXT_BYTES as usize;

/// What this device's own notes on a stored draft may add to an encoded record.
///
/// [`Draft::conflict_of`] and [`Draft::retained`] are local: they say which draft a copy belongs
/// beside and which copy the service kept of the write it beat, and the service never carries
/// either. A copy also carries its own identity and the time it arrived. Allowing for those
/// separately is what keeps a payload that is exactly at the limit storable when it arrives here as
/// a copy, rather than refusing to keep content the service was already carrying. Each identity is
/// sixteen bytes where the payload carries a null, and each time at most eight more, which is
/// forty-eight of these sixty-four.
const LOCAL_FIELDS_BYTES: usize = 64;

/// The most a stored draft record may carry, in bytes.
pub const MAX_STORED_DRAFT_BYTES: usize = MAX_DRAFT_BYTES + LOCAL_FIELDS_BYTES;

/// The most attachments one draft may hold.
pub const MAX_DRAFT_ATTACHMENTS: usize = 64;

/// The extension every stored draft carries.
const DRAFT_EXTENSION: &str = "draft";

/// The extension of the note recording where a draft reached on the synchronisation service.
const CHECKPOINT_EXTENSION: &str = "sync";

/// The extension of a draft being written, which is not yet a draft.
const PARTIAL_EXTENSION: &str = "partial";

/// The name of the store's lock.
const LOCK_NAME: &str = "store.lock";

/// What a draft is for.
///
/// All three parts matter together. A draft written for one application in one session is not a
/// draft for whatever occupies that session later, and the binding revision is what says so: it
/// changes when the active upstream execution owner or the selected thread changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftTarget {
    /// The session it is for.
    pub session_id: SessionId,
    /// The foreground application it is for, when one was running.
    pub application_instance_id: Nullable<ApplicationInstanceId>,
    /// The binding the draft was written against, when the application had one.
    pub agent_binding_revision: Nullable<AgentBindingRevision>,
}

impl DraftTarget {
    /// A target that names a session and nothing inside it.
    #[must_use]
    pub const fn session(session_id: SessionId) -> Self {
        Self {
            session_id,
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// Names the application and binding this draft was written against.
    #[must_use]
    pub const fn in_application(
        mut self,
        application_instance_id: ApplicationInstanceId,
        agent_binding_revision: AgentBindingRevision,
    ) -> Self {
        self.application_instance_id = Nullable::some(application_instance_id);
        self.agent_binding_revision = Nullable::some(agent_binding_revision);
        self
    }
}

/// A durable draft this device owns.
///
/// The record carries no attachment identity. What it carries is the completed transfer handles a
/// person attached, which are the host's own durable objects and outlive a connection exactly as
/// the draft does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Draft {
    /// The draft's durable identity.
    pub draft_id: DraftId,
    /// Its revision. Every update names the revision it expects to replace.
    pub revision: DraftRevision,
    /// The device that owns it.
    pub device_id: DeviceId,
    /// What it is for.
    pub target: DraftTarget,
    /// Whether it can still be submitted against its target.
    pub state: DraftState,
    /// The text. This is not the native terminal edit buffer.
    pub text: String,
    /// The completed transfers attached to it, in the order they were attached.
    pub attachments: Vec<AttachmentHandle>,
    /// The draft this one is a copy of, when a synchronised write brought down another device's
    /// content beside it.
    ///
    /// Local. The synchronised payload never carries it: which draft a copy sits beside is this
    /// device's note about its own screen, not a fact about the object.
    pub conflict_of: Nullable<DraftId>,
    /// The copy the service kept of this device's refused write, when this draft is the content
    /// that beat it and the service kept one.
    ///
    /// A refusal is one choice with two sides: the content this device offered, which the service
    /// kept as a copy of its own, and the content that won, which came down beside the person's
    /// draft as this one. Choosing about this copy is choosing about that refused write, so this is
    /// the one copy on the service the choice takes with it. [`DraftSync::resolve`] reads it.
    ///
    /// Local, as `conflict_of` is: it names something on this device's account with the service,
    /// not a fact about the draft.
    pub retained: Nullable<SyncConflictId>,
    /// When it was created.
    pub created_at_ms: TimestampMs,
    /// When it was last changed.
    pub updated_at_ms: TimestampMs,
}

/// Why a draft may not be submitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NotSubmittable {
    /// The application or the binding changed under it. The caller retargets it explicitly.
    #[error("the draft's application or binding changed; retarget it before submitting")]
    Conflicted,
    /// Its target is gone. The caller gives it a new one.
    #[error("the draft's target is gone; give it a new one before submitting")]
    Orphaned,
}

impl Draft {
    /// Returns the target a submission would name, or why it may not be submitted.
    ///
    /// This is the only path in this module that leads towards a submission, and it performs none:
    /// it answers a question. A caller submits by calling the host itself, which keeps transfer,
    /// insertion and submission the separate actions section 12 requires.
    ///
    /// # Errors
    ///
    /// Returns [`NotSubmittable`] when the draft is conflicted or orphaned.
    pub const fn submission(&self) -> std::result::Result<&DraftTarget, NotSubmittable> {
        match self.state {
            DraftState::Open => Ok(&self.target),
            DraftState::Conflicted => Err(NotSubmittable::Conflicted),
            DraftState::Orphaned => Err(NotSubmittable::Orphaned),
        }
    }

    /// Records what the host now says about this draft's target, and returns the state it leaves.
    ///
    /// `observed` is null when the session no longer has the application the draft was written for,
    /// which orphans it. An application or binding that changed conflicts it. Neither submits it
    /// and neither discards it: section 24 keeps the draft for explicit retargeting.
    ///
    /// Rebinding is not retargeting. A draft that has already been marked stays marked until a
    /// caller says otherwise, because the host agreeing with itself a second time is not a person
    /// deciding what to do with the text.
    pub fn rebind(&mut self, observed: Option<&DraftTarget>) -> DraftState {
        let Some(observed) = observed else {
            self.state = DraftState::Orphaned;
            return self.state;
        };
        if observed.session_id != self.target.session_id {
            self.state = DraftState::Orphaned;
            return self.state;
        }
        let changed = observed.application_instance_id != self.target.application_instance_id
            || observed.agent_binding_revision != self.target.agent_binding_revision;
        if changed {
            self.state = DraftState::Conflicted;
        }
        self.state
    }

    /// Points the draft at a target the caller chose, which is the explicit retargeting.
    ///
    /// This is the one way out of a conflicted or orphaned state, and it is deliberately a caller's
    /// decision: the library cannot know whether the text a person wrote for one agent still means
    /// what they wanted for the next one.
    pub fn retarget(&mut self, target: DraftTarget) {
        self.target = target;
        self.state = DraftState::Open;
    }
}

/// Which attachment is presenting which draft, right now.
///
/// Nothing here is durable. An attachment belongs to one connection, so this is dropped whenever
/// that connection is, and the drafts are untouched: section 24 says connection loss removes the
/// association, not the draft.
#[derive(Clone, Debug, Default)]
pub struct Associations {
    by_draft: HashMap<DraftId, AttachmentId>,
}

impl Associations {
    /// Returns an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Associates a draft with the attachment presenting it, and returns the one it replaced.
    ///
    /// Replacing an attachment is the ordinary case: a person moves a draft from one panel to
    /// another, or reconnects and the same device binds it again. Nothing about the draft changes.
    pub fn bind(&mut self, draft_id: DraftId, attachment_id: AttachmentId) -> Option<AttachmentId> {
        self.by_draft.insert(draft_id, attachment_id)
    }

    /// Returns the attachment presenting a draft, when one is.
    #[must_use]
    pub fn attachment_of(&self, draft_id: DraftId) -> Option<AttachmentId> {
        self.by_draft.get(&draft_id).copied()
    }

    /// Returns the drafts one attachment is presenting.
    #[must_use]
    pub fn drafts_of(&self, attachment_id: AttachmentId) -> Vec<DraftId> {
        let mut found: Vec<DraftId> = self
            .by_draft
            .iter()
            .filter(|(_, bound)| **bound == attachment_id)
            .map(|(draft_id, _)| *draft_id)
            .collect();
        found.sort_unstable();
        found
    }

    /// Removes one association and returns the attachment it named.
    pub fn release(&mut self, draft_id: DraftId) -> Option<AttachmentId> {
        self.by_draft.remove(&draft_id)
    }

    /// Removes every association, which is what losing a connection means.
    ///
    /// It returns nothing a caller could submit. The drafts are on disk and are not consulted.
    pub fn connection_lost(&mut self) {
        self.by_draft.clear();
    }

    /// Returns how many drafts are currently presented.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_draft.len()
    }

    /// Returns true when nothing is presented.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_draft.is_empty()
    }
}

/// Why a draft store refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DraftError {
    /// The directory, the lock or a draft file could not be read or written.
    #[error("the draft store at {path} could not be used: {source}")]
    Storage {
        /// What was being read or written.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// No draft with that identity is stored here.
    #[error("no draft {draft_id} is stored")]
    Unknown {
        /// The identity that was asked for.
        draft_id: DraftId,
    },
    /// The update expected a revision the stored draft no longer holds.
    #[error("draft {draft_id} is at revision {current}, not {expected}")]
    RevisionConflict {
        /// The draft.
        draft_id: DraftId,
        /// The revision the caller expected to replace.
        expected: DraftRevision,
        /// The revision it actually holds.
        current: DraftRevision,
    },
    /// The draft belongs to another device, so this store will not change it.
    #[error("draft {draft_id} belongs to device {owner}, not {device_id}")]
    NotOwned {
        /// The draft.
        draft_id: DraftId,
        /// The device it names as its owner.
        owner: DeviceId,
        /// The device this store belongs to.
        device_id: DeviceId,
    },
    /// A draft was offered to the service at a revision this device does not hold.
    #[error(
        "draft {draft_id} is stored at revision {stored}; {offered} is not what this device holds"
    )]
    NotTheStoredRevision {
        /// The draft.
        draft_id: DraftId,
        /// The revision this device holds.
        stored: DraftRevision,
        /// The revision that was offered.
        offered: DraftRevision,
    },
    /// The draft is larger than the contract carries.
    #[error("the draft encodes to {len} bytes; the limit is {limit}")]
    TooLarge {
        /// The encoded size.
        len: usize,
        /// The limit.
        limit: usize,
    },
    /// The draft holds more attachments than one draft may.
    #[error("the draft holds {count} attachments; the limit is {limit}")]
    TooManyAttachments {
        /// How many it holds.
        count: usize,
        /// The limit.
        limit: usize,
    },
    /// A stored file is not a draft this build can read.
    #[error("the stored draft at {path} could not be read: {reason}")]
    Corrupt {
        /// Which file.
        path: PathBuf,
        /// What was wrong with it.
        reason: String,
    },
}

impl DraftError {
    /// Returns the stable protocol code this refusal is reported under.
    ///
    /// A local store is not a host, and the codes are a vocabulary rather than a claim about one:
    /// what they give a caller is one way to log and correlate every failure. What a person is told
    /// comes from [`Self::user_action`], not from the code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Storage { .. } => ErrorCode::StorageUnavailable,
            // A stored record this build cannot parse is a malformed value, whatever damaged it.
            // Nothing about it establishes that a newer build wrote it.
            Self::Unknown { .. }
            | Self::TooLarge { .. }
            | Self::TooManyAttachments { .. }
            | Self::NotOwned { .. }
            | Self::Corrupt { .. } => ErrorCode::InvalidArgument,
            Self::RevisionConflict { .. } | Self::NotTheStoredRevision { .. } => {
                ErrorCode::DraftConflict
            }
        }
    }

    /// Returns the direct action a user interface offers for this refusal.
    ///
    /// These are the store's own, not the protocol table's. A draft that is too long is not a
    /// reason to update the application, and a store that cannot be written is not a schema
    /// failure: each of these is answered by the person's own next move, or by the message.
    #[must_use]
    pub const fn user_action(&self) -> UserAction {
        match self {
            // A store that is full, unwritable, or on a volume that has gone.
            Self::Storage { .. } => UserAction::FixConfiguration,
            // The message is the whole of it: shorten the draft, drop an attachment, choose which
            // copy to keep, or look at a draft that is still there.
            Self::Unknown { .. }
            | Self::RevisionConflict { .. }
            | Self::NotTheStoredRevision { .. }
            | Self::NotOwned { .. }
            | Self::TooLarge { .. }
            | Self::TooManyAttachments { .. }
            | Self::Corrupt { .. } => UserAction::Nothing,
        }
    }
}

/// Where a draft has reached on the synchronisation service.
///
/// It is a note, not content: losing it costs a comparison and a fetch, never text. That is why it
/// is written beside the draft rather than inside it, and why a draft's own revision is never the
/// position a comparison names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCheckpoint {
    /// Where the service holds the draft.
    pub position: SyncPosition,
    /// The revision *this device* published at that position.
    ///
    /// Null when the position came from another device's write, which this device only fetched.
    /// A revision counter belongs to the device that keeps it, so the number another device reached
    /// says nothing about this device's own.
    ///
    /// It is what a client shows: a draft whose stored revision is this one is on the service, and
    /// one above it has changes nothing else has seen.
    pub published_revision: Nullable<DraftRevision>,
}

/// What a listing found, including what it could not read.
///
/// One damaged file does not hide the drafts beside it, and it is not dropped either: it is named,
/// so a client can say which one it cannot open rather than quietly showing one draft fewer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Listing {
    /// The drafts that were read, oldest first.
    pub drafts: Vec<Draft>,
    /// The files that are not drafts this build reads.
    pub unreadable: Vec<PathBuf>,
}

/// Drafts this device owns, on this device's disk.
///
/// The directory is the caller's: a desktop application puts it under its own support directory, a
/// command line under the user's state directory, a test under a temporary one. The store creates
/// it if it is not there, owner-only where the platform expresses that, and writes every draft
/// whole or not at all.
///
/// Every method blocks, on the filesystem and on the store's lock. A draft is a few kilobytes and
/// the calls are a person's own edits, so a caller on an asynchronous runtime that cares about the
/// difference runs them on a blocking task.
#[derive(Clone, Debug)]
pub struct DraftStore {
    directory: PathBuf,
    device_id: DeviceId,
}

impl DraftStore {
    /// Opens or creates a store in `directory` for one device.
    ///
    /// Opening tidies up: a temporary file a previous run was interrupted while writing is removed,
    /// because it is not a draft and nothing will ever publish it. The sweep runs under the same
    /// exclusive lock every write takes, so it cannot remove a file another writer is using.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::Storage`] when the directory cannot be created, read, locked or made
    /// owner-only.
    pub fn open(directory: impl Into<PathBuf>, device_id: DeviceId) -> Result<Self> {
        let directory = directory.into();
        private_directory(&directory).map_err(|source| storage(&directory, source))?;
        let store = Self {
            directory,
            device_id,
        };
        let guard = store.exclusive()?;
        store.sweep_partials()?;
        drop(guard);
        Ok(store)
    }

    /// Returns the directory the drafts are in.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Returns the device this store belongs to.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Creates a draft and writes it.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::Storage`] when the file cannot be written, and
    /// [`DraftError::TooLarge`] when the text does not fit the contract.
    pub fn create(&self, target: DraftTarget, text: String, now: TimestampMs) -> Result<Draft> {
        let draft = Draft {
            draft_id: DraftId::new(fresh_uuid()?),
            revision: DraftRevision::new(1),
            device_id: self.device_id,
            target,
            state: DraftState::Open,
            text,
            attachments: Vec::new(),
            conflict_of: Nullable::null(),
            retained: Nullable::null(),
            created_at_ms: now,
            updated_at_ms: now,
        };
        // An edit a person made has to be one the service could carry, so it is held to the payload
        // bound rather than to the larger one a stored record may reach.
        Self::encode_payload(&draft)?;
        let guard = self.exclusive()?;
        self.write(&draft)?;
        drop(guard);
        Ok(draft)
    }

    /// Reads one draft.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::Unknown`] when nothing is stored under that identity, and
    /// [`DraftError::Corrupt`] when the file is not a draft this build reads.
    pub fn load(&self, draft_id: DraftId) -> Result<Draft> {
        let guard = self.shared()?;
        let draft = self.read(draft_id);
        drop(guard);
        draft
    }

    /// Reads every stored draft, oldest first, and names what it could not read.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::Storage`] when the directory cannot be read.
    pub fn list(&self) -> Result<Listing> {
        let guard = self.shared()?;
        let mut listing = Listing::default();
        let entries = std::fs::read_dir(&self.directory)
            .map_err(|source| storage(&self.directory, source))?;
        for entry in entries {
            let entry = entry.map_err(|source| storage(&self.directory, source))?;
            let path = entry.path();
            let Some(draft_id) = path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .and_then(parse_draft_name)
            else {
                continue;
            };
            match self.read(draft_id) {
                Ok(draft) => listing.drafts.push(draft),
                Err(_) => listing.unreadable.push(path),
            }
        }
        drop(guard);
        listing.drafts.sort_by(|left, right| {
            left.created_at_ms
                .get()
                .cmp(&right.created_at_ms.get())
                .then_with(|| left.draft_id.cmp(&right.draft_id))
        });
        listing.unreadable.sort();
        Ok(listing)
    }

    /// Writes an edited draft, and advances its revision.
    ///
    /// `edited` is a draft the caller read and changed. Its revision is the one the change was made
    /// against, and the stored draft advances to the next. Reading the stored draft, comparing its
    /// revision and writing the result happen under one exclusive lock, so a second editor in this
    /// process or another either wrote before this call read or is told its comparison lost.
    /// Neither overwrites the other's text.
    ///
    /// The edit is the caller's own, made before the call. Nothing of the caller's runs while the
    /// lock is held, because a caller that reached back into the store from inside would be waiting
    /// for a lock this call cannot release until it returns.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::RevisionConflict`] when the stored draft has moved on,
    /// [`DraftError::NotOwned`] when the draft belongs to another device, [`DraftError::TooLarge`]
    /// or [`DraftError::TooManyAttachments`] when the result does not fit the contract, and
    /// [`DraftError::Storage`] when the file cannot be written.
    pub fn update(&self, edited: &Draft, now: TimestampMs) -> Result<Draft> {
        let draft_id = edited.draft_id;
        let expected = edited.revision;
        // The identity, the owner, the revision and the time are the store's, not an editor's. A
        // caller that changed one of them would produce a draft the store could not find or a
        // comparison nothing could win.
        let mut draft = Draft {
            draft_id,
            revision: DraftRevision::new(expected.get().saturating_add(1)),
            device_id: self.device_id,
            updated_at_ms: now,
            ..edited.clone()
        };
        let guard = self.exclusive()?;
        let outcome = (|| {
            let stored = self.read(draft_id)?;
            self.check_owner(&stored)?;
            if stored.revision != expected {
                return Err(DraftError::RevisionConflict {
                    draft_id,
                    expected,
                    current: stored.revision,
                }
                .into());
            }
            // When it was created is the stored draft's, whatever the caller handed back, and so is
            // the copy the service kept of the write this draft beat: that is this device's account
            // with the service, not something an edit changes.
            draft.created_at_ms = stored.created_at_ms;
            draft.retained = stored.retained;
            Self::encode_payload(&draft)?;
            self.write(&draft)?;
            Ok(draft)
        })();
        drop(guard);
        outcome
    }

    /// Writes a draft whose content came from somewhere else, under a fresh identity.
    ///
    /// This is what a lost synchronisation race produces: the content that won is kept *beside* the
    /// local draft rather than over it, because section 24 says reconnection never replaces the
    /// user's draft with remote input. The person chooses between them.
    ///
    /// The copy is held to the storage bound rather than to the payload bound. Content the service
    /// was already carrying is content this device keeps: refusing it because this device's own note
    /// beside it costs a few bytes would lose the very thing the person is meant to choose from. A
    /// copy that arrived at the service's limit may therefore be a few bytes too large to publish
    /// again from here, and shortening it is the person's own next edit.
    ///
    /// `retained` names the copy the service kept of this device's refused write, when this content
    /// is what beat it, and it is kept on the copy as [`Draft::retained`]. A fetch that answers no
    /// refusal names none.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::Storage`] when the file cannot be written, and
    /// [`DraftError::TooLarge`] when the content does not fit the storage bound.
    pub fn keep_copy(
        &self,
        of: DraftId,
        content: &Draft,
        retained: Option<SyncConflictId>,
        now: TimestampMs,
    ) -> Result<Draft> {
        let copy = Draft {
            draft_id: DraftId::new(fresh_uuid()?),
            revision: DraftRevision::new(1),
            device_id: self.device_id,
            target: content.target.clone(),
            state: content.state,
            text: content.text.clone(),
            attachments: content.attachments.clone(),
            conflict_of: Nullable::some(of),
            retained: Nullable::from(retained),
            created_at_ms: now,
            updated_at_ms: now,
        };
        let guard = self.exclusive()?;
        let written = self.write(&copy);
        drop(guard);
        written?;
        Ok(copy)
    }

    /// Removes a draft and its synchronisation note.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::NotOwned`] when the draft belongs to another device, and
    /// [`DraftError::Storage`] when a file cannot be removed. Removing a draft that is not there
    /// succeeds: the caller asked for it to be gone and it is.
    pub fn remove(&self, draft_id: DraftId) -> Result<()> {
        let guard = self.exclusive()?;
        let outcome = (|| {
            // A draft that is not there, or one this build cannot read, is one the caller may still
            // ask to be rid of. Neither leaves an owner to consult.
            if let Ok(draft) = self.read(draft_id) {
                self.check_owner(&draft)?;
            }
            // A removal is a name leaving a directory, and it is durable on the same terms a name
            // arriving is.
            remove_if_present(&self.draft_path(draft_id))?;
            self.remove_file(&self.checkpoint_path(draft_id))
        })();
        drop(guard);
        outcome
    }

    /// Reads a draft and where it has reached on the service, together.
    ///
    /// Together, because a publication decides from both: the revision it is sending and the
    /// position it expects to replace. Read separately, another publisher could advance the
    /// object between them, and this one would send an older revision against the newer
    /// position, which is a comparison it would win, replacing content it had never seen.
    ///
    /// # Errors
    ///
    /// As [`Self::load`] and [`Self::checkpoint`].
    pub fn draft_and_checkpoint(
        &self,
        draft_id: DraftId,
    ) -> Result<(Draft, Option<SyncCheckpoint>)> {
        let guard = self.exclusive()?;
        let outcome = self
            .read(draft_id)
            .and_then(|draft| Ok((draft, self.read_checkpoint(draft_id)?)));
        drop(guard);
        outcome
    }

    /// Returns where a draft last reached on the synchronisation service, when it has.
    ///
    /// A note this build cannot read is removed and reported as absent. It is a cache: the next
    /// publication compares against nothing, learns where the object stands from the service, and
    /// writes the note again.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::Storage`] when the note cannot be read or removed.
    pub fn checkpoint(&self, draft_id: DraftId) -> Result<Option<SyncCheckpoint>> {
        let guard = self.exclusive()?;
        let outcome = self.read_checkpoint(draft_id);
        drop(guard);
        outcome
    }

    /// Records where a draft reached on the synchronisation service, and says where the answer
    /// stood against the note already here.
    ///
    /// A note that already names a later write stands, and this answers [`Standing::Earlier`]. Two
    /// answers can arrive out of order: a publication is accepted, another device writes, a fetch
    /// brings that down, and only then does the first answer come back naming the write before it.
    /// Writing it would throw away what this device had already learnt, and leave a draft looking
    /// synchronised against an object that has moved on.
    ///
    /// A note naming the same place in the service's order under another name stands as well, and
    /// this answers [`Standing::Forked`]: one place names one write for the life of a collection, so
    /// the two come from two histories, and neither is a later state of the other. It is the rule a
    /// setting's note is held to, and the same function decides both.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::Storage`] when the note cannot be read or written.
    pub fn record_checkpoint(
        &self,
        draft_id: DraftId,
        checkpoint: SyncCheckpoint,
    ) -> Result<Standing> {
        let bytes = kr_cbor::to_canonical_vec(&checkpoint)?;
        let guard = self.exclusive()?;
        let outcome = (|| {
            let stands = match self.read_checkpoint(draft_id)? {
                Some(held) => standing(held.position, checkpoint.position),
                None => Standing::Later,
            };
            if matches!(
                stands,
                Standing::Earlier | Standing::Forked { .. } | Standing::OtherHistory { .. }
            ) {
                return Ok(stands);
            }
            self.write_bytes(&self.checkpoint_path(draft_id), &bytes)?;
            Ok(stands)
        })();
        drop(guard);
        outcome
    }

    /// Records where a draft reached on the service, for an answer the synchronisation store has
    /// read in the history of the draft's collection it reads, and says where it stood against the
    /// note already here.
    ///
    /// As [`Self::record_checkpoint`], with one difference: a note in another recovery's history is
    /// from a history the collection was put back from, and it is replaced rather than left
    /// standing, because no place in it compares with this one.
    pub(crate) fn answered_checkpoint(
        &self,
        draft_id: DraftId,
        checkpoint: SyncCheckpoint,
    ) -> Result<Standing> {
        let bytes = kr_cbor::to_canonical_vec(&checkpoint)?;
        let guard = self.exclusive()?;
        let outcome = (|| {
            let stands = match self.read_checkpoint(draft_id)? {
                Some(held) => standing(held.position, checkpoint.position),
                None => Standing::Later,
            };
            if matches!(stands, Standing::Earlier | Standing::Forked { .. }) {
                return Ok(stands);
            }
            self.write_bytes(&self.checkpoint_path(draft_id), &bytes)?;
            Ok(stands)
        })();
        drop(guard);
        outcome
    }

    /// Follows the collection with a draft's note after a refusal read in the history of the
    /// collection this device reads, when the note is in another.
    ///
    /// The note takes where the refusal says the draft stands, or goes when the refusal names no
    /// place: a note from a history the collection was put back from names nothing the service holds
    /// now, and a publication that compared against it would be refused for ever where the
    /// collection has never held the draft. A note in this history is left for the fetch that
    /// follows.
    pub(crate) fn follow_refusal(
        &self,
        draft_id: DraftId,
        current: Option<SyncPosition>,
        recovery: Option<SyncRecoveryId>,
    ) -> Result<()> {
        let guard = self.exclusive()?;
        let outcome = (|| {
            let Some(held) = self.read_checkpoint(draft_id)? else {
                return Ok(());
            };
            if held.position.recovery() == recovery {
                return Ok(());
            }
            match current {
                Some(position) => {
                    let bytes = kr_cbor::to_canonical_vec(&SyncCheckpoint {
                        position,
                        published_revision: Nullable::null(),
                    })?;
                    self.write_bytes(&self.checkpoint_path(draft_id), &bytes)
                }
                None => self.remove_file(&self.checkpoint_path(draft_id)),
            }
        })();
        drop(guard);
        outcome
    }

    /// Removes one of this store's files, and makes its absence durable.
    ///
    /// The caller holds the exclusive lock.
    fn remove_file(&self, path: &Path) -> Result<()> {
        remove_if_present(path)?;
        flush_directory(&self.directory, NameKind::File)
            .map_err(|source| storage(&self.directory, source))?;
        Ok(())
    }

    /// Forgets where a draft reached on the synchronisation service.
    ///
    /// A device that has been signed out of the service, or that is starting again against a
    /// different one, has a note that names a write nothing holds. Forgetting it costs the
    /// next publication a comparison and a fetch; keeping it would cost a comparison against a
    /// number that means nothing.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::Storage`] when the note cannot be removed.
    pub fn forget_checkpoint(&self, draft_id: DraftId) -> Result<()> {
        let guard = self.exclusive()?;
        let removed = self.remove_file(&self.checkpoint_path(draft_id));
        drop(guard);
        removed
    }

    /// Returns the bytes a synchronised copy of this draft is sealed from.
    ///
    /// This device's notes about which draft a copy sits beside and which copy the service kept of
    /// the write it beat are left out: both are local, and a service that carried them would be
    /// carrying one device's screen layout and one device's account.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::TooLarge`] or [`DraftError::TooManyAttachments`] when the draft does
    /// not fit the contract.
    pub fn encode_payload(draft: &Draft) -> Result<Vec<u8>> {
        let payload = Draft {
            conflict_of: Nullable::null(),
            retained: Nullable::null(),
            ..draft.clone()
        };
        encode_within(&payload, MAX_DRAFT_BYTES)
    }

    /// Returns the bytes one stored draft holds.
    ///
    /// # Errors
    ///
    /// As [`Self::encode_payload`], against the storage bound.
    pub fn encode_record(draft: &Draft) -> Result<Vec<u8>> {
        encode_within(draft, MAX_STORED_DRAFT_BYTES)
    }

    /// Reads a draft from the bytes [`Self::encode_record`] produced.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Cbor`] when the bytes are not a draft this build reads.
    pub fn decode(bytes: &[u8]) -> Result<Draft> {
        Self::decode_within(bytes, MAX_STORED_DRAFT_BYTES)
    }

    /// Reads a draft the service carried, against the bound a synchronised payload has.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Cbor`] when the bytes are not a draft this build reads, including
    /// one larger than section 20 lets a service carry.
    pub fn decode_payload(bytes: &[u8]) -> Result<Draft> {
        Self::decode_within(bytes, MAX_DRAFT_BYTES)
    }

    fn decode_within(bytes: &[u8], limit: usize) -> Result<Draft> {
        Ok(kr_cbor::from_canonical_slice(
            bytes,
            &kr_cbor::Limits::DEFAULT.with_max_message_len(limit),
        )?)
    }

    /// Reads one stored draft. The caller holds the lock.
    fn read(&self, draft_id: DraftId) -> Result<Draft> {
        let path = self.draft_path(draft_id);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(DraftError::Unknown { draft_id }.into());
            }
            Err(error) => return Err(storage(&path, error).into()),
        };
        let draft = Self::decode(&bytes).map_err(|error| DraftError::Corrupt {
            path: path.clone(),
            reason: error.to_string(),
        })?;
        // The name and the record have to agree. A record that names another draft is a file this
        // store cannot act on, whatever put it there.
        if draft.draft_id != draft_id {
            return Err(DraftError::Corrupt {
                path,
                reason: format!("it holds draft {}, not {draft_id}", draft.draft_id),
            }
            .into());
        }
        Ok(draft)
    }

    /// Reads a draft's note. The caller holds the exclusive lock, because a note this build cannot
    /// read is removed rather than returned.
    fn read_checkpoint(&self, draft_id: DraftId) -> Result<Option<SyncCheckpoint>> {
        let path = self.checkpoint_path(draft_id);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(storage(&path, error).into()),
        };
        match kr_cbor::from_canonical_slice::<SyncCheckpoint>(
            &bytes,
            &kr_cbor::Limits::DEFAULT.with_max_message_len(MAX_STORED_DRAFT_BYTES),
        ) {
            Ok(checkpoint) => Ok(Some(checkpoint)),
            Err(_) => {
                self.remove_file(&path)?;
                Ok(None)
            }
        }
    }

    fn check_owner(&self, draft: &Draft) -> Result<()> {
        if draft.device_id == self.device_id {
            return Ok(());
        }
        Err(DraftError::NotOwned {
            draft_id: draft.draft_id,
            owner: draft.device_id,
            device_id: self.device_id,
        }
        .into())
    }

    /// Writes one draft. The caller holds the exclusive lock.
    fn write(&self, draft: &Draft) -> Result<()> {
        let bytes = Self::encode_record(draft)?;
        self.write_bytes(&self.draft_path(draft.draft_id), &bytes)
    }

    /// Replaces one file's contents, whole or not at all. The caller holds the exclusive lock.
    fn write_bytes(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        let temporary = self.temporary_path()?;
        write_whole(&temporary, bytes).map_err(|source| storage(&temporary, source))?;
        // A rename within one directory replaces the name in one step, so a reader sees the old
        // contents or the new ones and never a file half written.
        if let Err(source) = std::fs::rename(&temporary, path) {
            let _ = std::fs::remove_file(&temporary);
            return Err(storage(path, source).into());
        }
        flush_directory(&self.directory, NameKind::File)
            .map_err(|source| storage(&self.directory, source))?;
        Ok(())
    }

    /// Removes what an interrupted write left behind. The caller holds the exclusive lock.
    fn sweep_partials(&self) -> Result<()> {
        let entries = std::fs::read_dir(&self.directory)
            .map_err(|source| storage(&self.directory, source))?;
        for entry in entries {
            let entry = entry.map_err(|source| storage(&self.directory, source))?;
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) == Some(PARTIAL_EXTENSION) {
                // Nothing else can be writing one: every write holds this lock from the moment it
                // creates its temporary file until the rename has landed.
                self.remove_file(&path)?;
            }
        }
        Ok(())
    }

    /// Takes the store's lock for writing.
    fn exclusive(&self) -> Result<Lock> {
        Lock::take(&self.directory.join(LOCK_NAME), true)
    }

    /// Takes the store's lock for reading.
    fn shared(&self) -> Result<Lock> {
        Lock::take(&self.directory.join(LOCK_NAME), false)
    }

    fn draft_path(&self, draft_id: DraftId) -> PathBuf {
        self.directory.join(format!("{draft_id}.{DRAFT_EXTENSION}"))
    }

    fn checkpoint_path(&self, draft_id: DraftId) -> PathBuf {
        self.directory
            .join(format!("{draft_id}.{CHECKPOINT_EXTENSION}"))
    }

    fn temporary_path(&self) -> Result<PathBuf> {
        Ok(self
            .directory
            .join(format!("{}.{PARTIAL_EXTENSION}", fresh_uuid()?)))
    }
}

/// The store's lock, held for as long as this value is.
///
/// Dropping it closes the file, and closing the file releases the lock on every platform the
/// standard library supports.
#[derive(Debug)]
struct Lock {
    _file: std::fs::File,
}

impl Lock {
    fn take(path: &Path, exclusive: bool) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|source| storage(path, source))?;
        let taken = if exclusive {
            file.lock()
        } else {
            file.lock_shared()
        };
        taken.map_err(|source| storage(path, source))?;
        Ok(Self { _file: file })
    }
}

/// Returns the draft one stored name belongs to.
fn parse_draft_name(name: &str) -> Option<DraftId> {
    name.strip_suffix(&format!(".{DRAFT_EXTENSION}"))?
        .parse()
        .ok()
}

fn encode_within(draft: &Draft, limit: usize) -> Result<Vec<u8>> {
    if draft.attachments.len() > MAX_DRAFT_ATTACHMENTS {
        return Err(DraftError::TooManyAttachments {
            count: draft.attachments.len(),
            limit: MAX_DRAFT_ATTACHMENTS,
        }
        .into());
    }
    let bytes = kr_cbor::to_canonical_vec(draft)?;
    if bytes.len() > limit {
        return Err(DraftError::TooLarge {
            len: bytes.len(),
            limit,
        }
        .into());
    }
    Ok(bytes)
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(storage(path, error).into()),
    }
}

fn storage(path: &Path, source: std::io::Error) -> DraftError {
    DraftError::Storage {
        path: path.to_path_buf(),
        source,
    }
}

pub(crate) fn fresh_uuid() -> Result<Uuid> {
    Ok(kr_transport::random::fresh_uuid_v4()?)
}

/// Returns a builder that creates a directory only its owner can read.
///
/// On Windows the directory takes whatever access list it inherits, which this store does not
/// narrow: what protects it there is the access list of the directory the caller chose.
#[cfg(unix)]
fn owner_only_builder() -> std::fs::DirBuilder {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder
}

/// Returns a builder for a new directory, which this platform does not narrow itself.
#[cfg(not(unix))]
fn owner_only_builder() -> std::fs::DirBuilder {
    std::fs::DirBuilder::new()
}

/// Creates the directory owner-only, and makes an existing one owner-only.
///
/// Unsent text a person has written. A directory anything on the machine could read would be one
/// this store had no business writing into, so an existing directory is narrowed rather than
/// accepted. On Windows the directory takes whatever access list it inherits, which this store does
/// not narrow: what protects it there is the access list of the directory the caller chose, so a
/// caller puts the store under its own per-user application data rather than somewhere shared.
pub(crate) fn private_directory(directory: &Path) -> std::io::Result<()> {
    // Each missing level is created in turn rather than all at once, because a directory is a name
    // in the directory above it and a name is durable only once *that* directory's entry is
    // flushed. One recursive create would make several names and leave every one of them in
    // whatever state a crash found.
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
        match owner_only_builder().create(path) {
            Ok(()) => {}
            // Another opener made it between the walk and here, which is not a failure: what this
            // call wanted was for the directory to be there. Something that is *not* a directory
            // under that name is a different matter, and it is not one to write a store into.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => {
                continue;
            }
            Err(error) => return Err(error),
        }
        flush_directory(holder_of(path), NameKind::Directory)?;
    }
    if !directory.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            format!("{} is not a directory", directory.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(directory)?.permissions().mode();
        if mode & 0o077 != 0 {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    flush_path_names(directory)
}

/// The directory one name lives in.
///
/// A relative path of one component has an empty parent, and an empty path is not a directory
/// anything can open. What holds that name is the working directory.
fn holder_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Writes a new file whole, and flushes it to the device before anything renames it into place.
///
/// The file is created exclusively and, on Unix, owner-only from the moment it exists rather than a
/// moment afterwards: a file that was briefly readable is a file that was readable. A failure after
/// it was created removes it; a process that dies here leaves it, and the next
/// [`DraftStore::open`] sweeps it away.
pub(crate) fn write_whole(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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

impl From<DraftError> for ClientError {
    fn from(error: DraftError) -> Self {
        Self::Draft(Box::new(error))
    }
}

/// How a device seals a draft before a service sees it.
///
/// Section 20: the service stores ciphertext and never holds the key. The sealing therefore belongs
/// to the device, and this is the seam: a client supplies its own, and nothing in this module ever
/// sees a key or decides what an object is encrypted with.
pub trait DraftSealer: Send + Sync + std::fmt::Debug {
    /// Seals one draft's canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns whatever the client's own sealing failed with.
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Opens what [`Self::seal`] produced.
    ///
    /// # Errors
    ///
    /// Returns whatever the client's own opening failed with, including a failed authentication.
    fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// Returns the collection one draft is stored in.
///
/// One object per draft, because the comparison is per draft: two drafts edited on two devices are
/// not a conflict, and a collection holding both would make them one.
#[must_use]
pub fn draft_collection(draft_id: DraftId) -> String {
    format!("drafts/{draft_id}")
}

/// What became of a synchronised write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Published {
    /// The service accepted it, leaving the draft here.
    Accepted {
        /// Where the service put this write.
        ///
        /// It is what the service answered, not necessarily what the next comparison will name: a
        /// note this device had already written from a later answer stands, so read the note when
        /// what matters is where this device thinks the object stands.
        position: SyncPosition,
    },
    /// Another device had written first.
    ///
    /// The local draft is exactly as it was. What the service held is kept beside it under `copy`,
    /// for the person to choose from, and the note now names where that content stands, so a caller
    /// that has chosen can publish against it.
    Conflicted {
        /// The copy that was kept.
        copy: DraftId,
        /// The revision the other device's draft carried.
        remote_revision: DraftRevision,
        /// Where the service holds the draft.
        position: SyncPosition,
    },
    /// The answer came back for a publication admitted under an earlier privacy generation.
    ///
    /// The account of what left is kept, and nothing else is written: the note does not move and
    /// no copy comes down, because section 24 publishes no late old-generation result.
    Discarded {
        /// The generation the publication was admitted under.
        produced_under: u64,
        /// The generation in force now.
        current: u64,
    },
}

/// What came down from the service, and where it was put.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched {
    /// The draft as the service held it.
    pub remote: Draft,
    /// Where the service answered that it holds the draft.
    ///
    /// As on [`Published::Accepted`]: a note already naming a later write stands, so this is what
    /// the service said rather than necessarily what the next comparison will name.
    pub position: SyncPosition,
    /// The copy this device kept beside its own.
    pub copy: Draft,
}

/// What recording the person's choice about one copy did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// The copy the person chose about, as this device kept it. The store no longer holds it.
    pub copy: Draft,
    /// What asking the service to drop the copies chosen about established.
    pub service: Resolutions,
}

/// What bringing a draft down beside the local one did.
enum BroughtDown {
    /// It was kept beside the local draft, and the note was written.
    ///
    /// Behind a pointer because it carries two drafts and the other variant two numbers.
    Kept(Box<Fetched>),
    /// Privacy mode fenced production or moved past the generation the work was started under, so
    /// nothing was written.
    Discarded {
        /// The generation the work was started under.
        produced_under: u64,
        /// The generation in force now.
        current: u64,
    },
}

/// One device's synchronised half of its drafts.
///
/// The comparison is against the position this device last saw, which is kept beside the draft as
/// a [`SyncCheckpoint`] and is *not* the draft's own revision: a draft edited three times offline is
/// at revision four and has still only ever been published once. Section 20 keeps the loser of a
/// comparison rather than resolving it by whichever clock was further ahead, and section 24 adds
/// the direction that matters on a device: what is kept is kept *beside* the local draft, so
/// reconnecting never replaces the person's text with what was on the service.
///
/// # One account per publication
///
/// Every publication keeps one record in the device's [`SyncStore`], the same store the settings
/// client keeps its own in, so the barrier, the fence and privacy mode's cleanup reach a draft
/// exactly as they reach a setting, and [`crate::sync::SyncClient::outstanding`] counts a draft
/// that has left without an answer. The record is written before the call leaves and replaced
/// whole at every step, so a device that stops anywhere comes back to one account of the
/// publication, never two.
///
/// A publication is one piece of work with one identity, chosen when it is admitted. Publishing the
/// same revision again while its answer is unknown is a later attempt at that work: it presents the
/// same identity, the same bytes and the same comparison, so a service that already ran it answers
/// from its receipt and runs nothing twice, and the record keeps the earliest and the latest
/// instant any attempt was signed at. That holds only while the service is certain to keep the
/// receipt of any attempt that ran, which is while every attempt is signed within one freshness
/// window of every other. Past that, the earlier publication keeps its account for a reconciliation
/// to end, and publishing again is a new publication under an identity of its own. Nothing makes
/// an attempt by itself. Section 23 retries nothing whose outcome is unknown, so a later attempt is
/// always a caller asking for one.
///
/// # A lost answer
///
/// [`Self::reconcile_unsettled`] settles a publication whose answer never came back by the rule the
/// settings client applies: it asks about the request's own identity, and a service that holds no
/// receipt for it under the generation in force leaves it counted for the next pass, while one
/// privacy mode has moved past is fenced in the same pass. An applied answer moves the note beside
/// the draft, unless the note already names a later write; a refused one brings the other device's
/// content down beside the draft.
///
/// A note that is lost or was never written costs a comparison, not a draft: the publication is
/// refused, the content the service holds comes down beside the local draft, and the note is
/// written from the position that fetch reported. A note that names a write the service no longer
/// has, because it was reset or replaced, is the case that does not resolve itself: the
/// publication is refused and there is nothing to fetch, and [`DraftStore::forget_checkpoint`] is
/// how a caller says so.
#[derive(Debug)]
pub struct DraftSync {
    service: std::sync::Arc<dyn crate::services::SyncBackupService>,
    sealer: std::sync::Arc<dyn DraftSealer>,
    store: SyncStore,
}

impl DraftSync {
    /// Builds the synchronised half over a service client, this device's sealing and the device's
    /// synchronisation store.
    ///
    /// The store is the one the device's settings client keeps its records in. A draft kept its
    /// accounts anywhere else would be a publication that store's barrier and cleanup could not
    /// see.
    #[must_use]
    pub fn new(
        service: std::sync::Arc<dyn crate::services::SyncBackupService>,
        sealer: std::sync::Arc<dyn DraftSealer>,
        store: SyncStore,
    ) -> Self {
        Self {
            service,
            sealer,
            store,
        }
    }

    /// Returns the store this half keeps its publications' records in.
    #[must_use]
    pub const fn store(&self) -> &SyncStore {
        &self.store
    }

    /// Publishes a draft, under compare and swap on the position this device last saw.
    ///
    /// What goes to the service is the record the store holds, not a value the caller supplied:
    /// the caller names which draft and which revision it means, and the bytes are the ones on
    /// disk. A caller that had edited a copy in memory would otherwise put content on the service
    /// that this device does not hold, and the note beside it would name a revision whose text is
    /// somewhere else.
    ///
    /// The draft and the note are read together, so the position a new publication sends against
    /// is the one that went with the revision it validated. When the publication of that revision
    /// is already out with no answer, this is a later attempt at it, under its identity and with
    /// its bytes and its comparison, for as long as that attempt is answered from a receipt rather
    /// than run again, as [`SyncStore::attempt_draft`] describes.
    ///
    /// A refused comparison is not a failure: it is the answer that another device wrote first, and
    /// it brings that content down beside the local draft rather than over it, naming on the copy
    /// the copy the service kept of this device's write. An answer that arrives after privacy mode
    /// has moved past the publication's generation is [`Published::Discarded`]. Any other failure leaves the
    /// publication counted rather than guessing at whether it landed.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Fenced`] while privacy mode is on, [`SyncError::InFlight`] when a call
    /// for this publication is already out, [`SyncError::StaleCheckpoint`] or
    /// [`SyncError::ForkedHistory`] when the answer cannot follow what this device's records hold,
    /// [`SyncError::SignedBeforeCutoff`] when the service refused the attempt as signed before its
    /// cutoff, which ends the publication with its account kept, the service's refusal, and,
    /// through [`SyncError::Client`],
    /// [`DraftError::NotTheStoredRevision`] when the revision named is not the one this device
    /// holds, [`DraftError::NotOwned`] when the draft belongs to another device,
    /// [`DraftError::TooLarge`] when it does not fit the contract, and [`DraftError::Storage`] when
    /// a copy or the note cannot be written.
    pub async fn publish(
        &self,
        drafts: &DraftStore,
        draft_id: DraftId,
        expected_revision: DraftRevision,
        now: TimestampMs,
    ) -> crate::sync::Result<Published> {
        let (stored, note) = drafts.draft_and_checkpoint(draft_id)?;
        if stored.device_id != drafts.device_id() {
            return Err(ClientError::from(DraftError::NotOwned {
                draft_id,
                owner: stored.device_id,
                device_id: drafts.device_id(),
            })
            .into());
        }
        if stored.revision != expected_revision {
            return Err(ClientError::from(DraftError::NotTheStoredRevision {
                draft_id,
                stored: stored.revision,
                offered: expected_revision,
            })
            .into());
        }
        let plaintext = DraftStore::encode_payload(&stored)?;
        // What this device last saw the service hold, read with the draft above. A draft that has
        // never been published expects nothing to be there, which is no position at all.
        let expected = note.map(|note| note.position);
        let attempt = self
            .store
            .attempt_draft(draft_id, stored.revision, expected, now, || {
                self.sealer.seal(&plaintext).map_err(SyncError::from)
            })?;
        let answer = self
            .service
            .compare_exchange(
                &attempt.record.collection(),
                // The publication's own identity, which is what makes it answerable afterwards and
                // what a later attempt presents again.
                attempt.record.work_id,
                // The instant the record says this attempt is signed at, so what is signed and what
                // a fence later carries are the one value.
                attempt.signed_at.get(),
                // The comparison the publication was admitted with, which is part of what a
                // service compares a later attempt against its receipt by.
                attempt.record.expected.as_ref().copied(),
                attempt.ciphertext.as_slice(),
            )
            .await;

        match answer {
            Ok(SyncExchanged::Applied { position }) => {
                let settled = self.store.settle_draft(
                    &attempt.dispatch,
                    &attempt.record,
                    Outcome::Accepted { position },
                    drafts,
                )?;
                // The settlement is durable before this is raised. An answer this device's records
                // cannot follow is one it may not carry on from, and the caller is told which.
                if settled.across == Across::Unfollowed {
                    return Err(SyncError::UnfollowedHistory {
                        object_id: attempt.record.object_id,
                    });
                }
                if let Some(held) = settled.diverged {
                    return Err(diverged(attempt.record.object_id, held, position));
                }
                Ok(match settled.settlement {
                    Settlement::Published | Settlement::AlreadySettled => {
                        Published::Accepted { position }
                    }
                    Settlement::Discarded {
                        produced_under,
                        current,
                    } => Published::Discarded {
                        produced_under,
                        current,
                    },
                })
            }
            Ok(SyncExchanged::Refused {
                retained,
                current,
                recovery,
            }) => {
                // The refusal is settled first and on its own, along with the account of whatever
                // the service kept of this write, so a fetch this device cannot make costs the copy
                // rather than the knowledge that the write did not land.
                let settled = self.store.settle_draft(
                    &attempt.dispatch,
                    &attempt.record,
                    Outcome::Refused {
                        retained,
                        current,
                        recovery,
                    },
                    drafts,
                )?;
                if let Settlement::Discarded {
                    produced_under,
                    current,
                } = settled.settlement
                {
                    return Ok(Published::Discarded {
                        produced_under,
                        current,
                    });
                }
                if settled.across == Across::Unfollowed {
                    return Err(SyncError::UnfollowedHistory {
                        object_id: attempt.record.object_id,
                    });
                }
                Ok(
                    match self
                        .bring_down(
                            drafts,
                            draft_id,
                            attempt.record.produced_under.get(),
                            retained,
                            now,
                        )
                        .await?
                    {
                        BroughtDown::Kept(fetched) => Published::Conflicted {
                            copy: fetched.copy.draft_id,
                            remote_revision: fetched.remote.revision,
                            position: fetched.position,
                        },
                        BroughtDown::Discarded {
                            produced_under,
                            current,
                        } => Published::Discarded {
                            produced_under,
                            current,
                        },
                    },
                )
            }
            // Refused as signed before the service's cutoff: this attempt ran nothing, and the
            // identity is never presented again, since an earlier attempt of it may have run and
            // had its receipt swept. The publication ends here with its account kept, or, while an
            // attempt signed later may still be on its way, stays counted until a fence ends it.
            // Publishing the draft again is new work under an identity of its own.
            Ok(SyncExchanged::SignedBeforeCutoff) => {
                self.store.close_signed_before_cutoff(
                    &attempt.dispatch,
                    attempt.record.work_id,
                    attempt.signed_at,
                )?;
                Err(SyncError::SignedBeforeCutoff {
                    object_id: attempt.record.object_id,
                })
            }
            // The identity this publication presented already answered a different request. That
            // receipt accounts for the other request and never for these bytes, and the service
            // compared them against it and declined to run them, so nothing of this attempt is on
            // the service and nothing asks about the identity again.
            Err(error) if error.code() == ErrorCode::IdConflict => {
                self.store
                    .close_unexecuted(&attempt.dispatch, attempt.record.work_id)?;
                Err(error.into())
            }
            // Anything else leaves the outcome open, and the record where it counts.
            Err(error) => Err(error.into()),
        }
    }

    /// Brings down what the service holds for a draft, beside the local one.
    ///
    /// It never replaces. The content arrives under a fresh identity that names the draft it belongs
    /// beside, which is what keeps a reconnect from putting remote input where the person's text
    /// was. Section 24 makes that the rule rather than a preference.
    ///
    /// The note is written from the position the service reported, so a device that had lost track
    /// of where the object stood knows again. Both it and the copy are written against the privacy
    /// generation this fetch started under, so a fetch is refused while privacy mode is on and an
    /// answer that arrives after a fence writes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Fenced`] while privacy mode is on, [`SyncError::LateResult`] when a
    /// fence landed while the answer was on its way, [`SyncError::NotAWrite`] when the service
    /// answered with a position no write of the draft can be at, [`SyncError::ForkedHistory`] when
    /// the note names the same place under another name, [`SyncError::UnfollowedHistory`] when
    /// the answer came from a history this device does not follow, the service's refusal,
    /// `UNKNOWN_SESSION` when the draft's collection holds none in the history this device reads
    /// it in, which a collection put back without it moves this device to first, and, through
    /// [`SyncError::Client`], [`ClientError::Cbor`] when the object is not a draft this build reads
    /// or is larger than a synchronised object may carry, [`DraftError::Corrupt`] when it opens to a
    /// different draft, and [`DraftError::Storage`] when the copy or the note cannot be written.
    pub async fn fetch_beside(
        &self,
        drafts: &DraftStore,
        draft_id: DraftId,
        now: TimestampMs,
    ) -> crate::sync::Result<Fetched> {
        let privacy = self.store.privacy()?;
        if privacy.fenced {
            return Err(SyncError::Fenced {
                generation: privacy.generation.get(),
            });
        }
        match self
            .bring_down(drafts, draft_id, privacy.generation.get(), None, now)
            .await?
        {
            BroughtDown::Kept(fetched) => Ok(*fetched),
            BroughtDown::Discarded {
                produced_under,
                current,
            } => Err(SyncError::LateResult {
                produced_under,
                current,
            }),
        }
    }

    /// Asks the service what became of every draft publication this device has no answer for.
    ///
    /// It is the settings client's reconciliation, applied to drafts, with the draft store at hand
    /// for what an answer writes there. Each publication is claimed before anything is asked about
    /// it, and one somebody has a call out for is left counted. Each answer settles the publication
    /// it is about and nothing else:
    ///
    /// - **applied** settles it as an accepted write, which records the publication and, under the
    ///   generation in force, moves the note beside the draft, unless the note already names a
    ///   later write;
    /// - **refused** settles it as a write that did not replace the draft, records the copy the
    ///   service kept of it, and brings down what the service holds instead, beside the draft;
    /// - **no receipt** leaves it counted while its generation is in force, and past that
    ///   generation it is fenced in the same pass;
    /// - **fenced** ends it, with no account where the service says nothing ran and with the
    ///   account kept where it cannot say so.
    ///
    /// Nothing is sent again. A service that cannot be asked leaves the publication counted.
    /// `unsettled` in the report is the store's whole count, settings included, because it is the
    /// one barrier privacy mode's cleanup measures.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the records cannot be read or a settlement cannot be
    /// written, and whatever the draft store failed with when a note could not be.
    pub async fn reconcile_unsettled(
        &self,
        drafts: &DraftStore,
        now: TimestampMs,
    ) -> crate::sync::Result<Reconciled> {
        let mut report = Reconciled::default();
        let dispatched: Vec<Uuid> = self
            .store
            .requests()?
            .items
            .iter()
            .filter(|item| item.kind == SyncObjectKind::Draft && item.dispatched())
            .map(|item| item.work_id)
            .collect();
        for work_id in dispatched {
            let (dispatch, staged) = match self.store.claim_dispatched(work_id)? {
                Claimed::Taken(dispatch, staged) => (dispatch, staged),
                Claimed::InHand => {
                    report.unresolved = report.unresolved.saturating_add(1);
                    continue;
                }
                Claimed::Gone => continue,
            };
            match ask_about(&*self.service, &self.store, &dispatch, &staged).await? {
                Answer::Applied(position) => {
                    let settled = self.store.settle_draft(
                        &dispatch,
                        &staged,
                        Outcome::Accepted { position },
                        drafts,
                    )?;
                    count_settled(&settled, &mut report);
                }
                Answer::Refused { retained, recovery } => {
                    // A receipt says what the refusal was told, not where the draft stands now, so
                    // it names no place to follow.
                    let settled = self.store.settle_draft(
                        &dispatch,
                        &staged,
                        Outcome::Refused {
                            retained,
                            current: None,
                            recovery,
                        },
                        drafts,
                    )?;
                    count_settled(&settled, &mut report);
                    // The copy belongs to the generation that admitted the work, and a fetch this
                    // device cannot make costs it rather than the settlement. One from a history
                    // this device does not follow keeps none: the next pass reads the collection.
                    if settled.settlement == Settlement::Published
                        && settled.across != Across::Unfollowed
                        && !matches!(
                            self.bring_down(
                                drafts,
                                DraftId::new(staged.object_id.get()),
                                staged.produced_under.get(),
                                retained,
                                now,
                            )
                            .await,
                            Ok(BroughtDown::Kept(_))
                        )
                    {
                        report.copies_not_taken = report.copies_not_taken.saturating_add(1);
                    }
                }
                Answer::Fenced {
                    never_ran,
                    recovery,
                } => {
                    end_fenced(
                        &self.store,
                        &dispatch,
                        &staged,
                        never_ran,
                        recovery,
                        &mut report,
                    )?;
                }
                Answer::Open => report.unresolved = report.unresolved.saturating_add(1),
            }
        }
        report.unsettled = self.store.unsettled()?;
        Ok(report)
    }

    /// Records the person's choice about one copy kept beside a draft, and drops the copy the
    /// service kept of the write it beat.
    ///
    /// The choice itself is the person's, as it always was: a draft that should say what the copy
    /// says is edited through [`DraftStore::update`] like any other. What this does is take the
    /// copy out of the draft store and tell the service. The copy the service kept of this device's
    /// refused write goes as well, and no other, because another refused write is another version
    /// the person has not decided about.
    ///
    /// The choice is recorded in the synchronisation store before the copy goes, and before the
    /// service is asked, so a stop between leaves the copy to choose about again rather than a
    /// choice the service never hears of, and a service that cannot be asked leaves the choice
    /// recorded for [`crate::sync::SyncClient::finish_resolutions`] to ask again.
    ///
    /// It sends identifiers and no content, so privacy mode does not stop it: dropping a copy takes
    /// content off the service rather than putting any there.
    ///
    /// Returns nothing when the draft store holds no such copy.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when a record cannot be read or written, and, through
    /// [`SyncError::Client`], whatever the draft store failed with.
    pub async fn resolve(
        &self,
        drafts: &DraftStore,
        copy: DraftId,
    ) -> crate::sync::Result<Option<Resolved>> {
        let held = match drafts.load(copy) {
            Ok(held) => held,
            Err(ClientError::Draft(error)) if matches!(*error, DraftError::Unknown { .. }) => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        // A draft that sits beside no other is not a copy, and there is nothing to choose about.
        if !held.conflict_of.is_present() {
            return Ok(None);
        }
        if let Some(retained) = held.retained.as_ref().copied() {
            self.store.drop_kept_copy(retained)?;
        }
        drafts.remove(copy)?;
        let service = finish_resolutions(&*self.service, &self.store).await?;
        Ok(Some(Resolved {
            copy: held,
            service,
        }))
    }

    /// Brings what the service holds for a draft down beside it, under the generation the work it
    /// answers was started under.
    ///
    /// What came down is a draft, so the position beside it is where a write of that draft landed.
    /// A removal produced no draft and nought is a place nothing occupies, so content at either is
    /// declined before anything is written. The copy and the note are written under one hold of
    /// the synchronisation store, against the generation, so a cleanup that landed while the answer
    /// was out finds nothing to undo. A note two histories claim is left where it is and reported,
    /// after the copy is kept, because the copy is what the person chooses from either way.
    ///
    /// A collection that holds no draft is read against the history of the collection under the
    /// same hold and the same generation, as a refusal that names no place is. Put back without
    /// the draft, the collection is followed and the note goes: the next publication compares
    /// against nothing, and one attempted in the history the restore replaced is never attempted
    /// again. The caller is told the draft is not held, or [`SyncError::UnfollowedHistory`] for a
    /// history this device does not follow.
    async fn bring_down(
        &self,
        drafts: &DraftStore,
        draft_id: DraftId,
        produced_under: u64,
        retained: Option<SyncConflictId>,
        now: TimestampMs,
    ) -> crate::sync::Result<BroughtDown> {
        let object_id = SyncObjectId::new(draft_id.get());
        // The history of the draft's collection the fetch is made against, taken as it leaves.
        let basis = self.store.basis(object_id)?;
        let (position, ciphertext) = match self.service.fetch(&draft_collection(draft_id)).await? {
            SyncFetched::Held {
                position,
                ciphertext,
            } => (position, ciphertext),
            SyncFetched::Absent { recovery } => {
                return match self.store.apply_under_history(
                    produced_under,
                    object_id,
                    basis,
                    recovery,
                    || {
                        drafts
                            .follow_refusal(draft_id, None, recovery)
                            .map_err(SyncError::from)
                    },
                )? {
                    InGeneration::Applied(()) => Err(nothing_held("draft").into()),
                    InGeneration::Discarded {
                        produced_under,
                        current,
                    } => Ok(BroughtDown::Discarded {
                        produced_under,
                        current,
                    }),
                    InGeneration::Unfollowed => Err(SyncError::UnfollowedHistory { object_id }),
                };
            }
        };
        if position.is_removal() || position.write_sequence == 0 {
            return Err(SyncError::NotAWrite {
                object_id,
                found: position,
            });
        }
        let plaintext = self.sealer.open(&ciphertext)?;
        let remote = DraftStore::decode_payload(&plaintext)?;
        // One collection holds one draft. An object that opens to a different one is not this
        // draft's, whatever opened it: sealing says the bytes came from a device that holds the
        // key, not that they belong where they were found.
        if remote.draft_id != draft_id {
            return Err(ClientError::from(DraftError::Corrupt {
                path: PathBuf::from(draft_collection(draft_id)),
                reason: format!("it holds draft {}, not {draft_id}", remote.draft_id),
            })
            .into());
        }
        let applied = self.store.apply_under_history(
            produced_under,
            object_id,
            basis,
            position.recovery(),
            || {
                let copy = drafts.keep_copy(draft_id, &remote, retained, now)?;
                // Where the object stands is this device's to remember; the revision beside it in
                // the note is not, because the revision that fetch carried is the other device's
                // counter and nothing about this device's own copies follows from it. A note from a
                // history the collection was put back from is replaced by it.
                let note = drafts.answered_checkpoint(
                    draft_id,
                    SyncCheckpoint {
                        position,
                        published_revision: Nullable::null(),
                    },
                )?;
                Ok((copy, note))
            },
        )?;
        let (copy, note) = match applied {
            InGeneration::Applied(written) => written,
            InGeneration::Discarded {
                produced_under,
                current,
            } => {
                return Ok(BroughtDown::Discarded {
                    produced_under,
                    current,
                });
            }
            InGeneration::Unfollowed => {
                return Err(SyncError::UnfollowedHistory { object_id });
            }
        };
        forked(object_id, Some(note), position)?;
        Ok(BroughtDown::Kept(Box::new(Fetched {
            remote,
            position,
            copy,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> DeviceId {
        DeviceId::new(Uuid::from_bytes([7; 16]))
    }

    fn session() -> SessionId {
        SessionId::new(Uuid::from_bytes([3; 16]))
    }

    fn application() -> ApplicationInstanceId {
        ApplicationInstanceId::new(Uuid::from_bytes([4; 16]))
    }

    fn store(directory: &tempfile::TempDir) -> DraftStore {
        DraftStore::open(directory.path().join("drafts"), device()).expect("a store")
    }

    /// The position a service would report for the nth write of a collection.
    fn at(write_sequence: u64) -> SyncPosition {
        SyncPosition::at(
            write_sequence,
            crate::services::SyncRevision::new(Uuid::from_bytes([write_sequence as u8; 16])),
            None,
        )
    }

    fn open_target() -> DraftTarget {
        DraftTarget::session(session()).in_application(application(), AgentBindingRevision::new(1))
    }

    fn drafts(store: &DraftStore) -> Vec<Draft> {
        let listing = store.list().expect("a listing");
        assert!(listing.unreadable.is_empty(), "{:?}", listing.unreadable);
        listing.drafts
    }

    /// The same draft with different text, which is what an edit is.
    fn edited(draft: &Draft, text: &str) -> Draft {
        Draft {
            text: text.to_owned(),
            ..draft.clone()
        }
    }

    #[test]
    fn a_store_opens_under_a_relative_path_and_under_levels_that_are_not_there_yet() {
        let directory = tempfile::tempdir().expect("a directory");
        // Several levels at once: each is made and its own name flushed into the level above it.
        let deep = directory
            .path()
            .join("support")
            .join("kalareach")
            .join("drafts");
        let store = DraftStore::open(&deep, device()).expect("a store");
        assert!(store.directory().is_dir());
        store
            .create(open_target(), "written".to_owned(), TimestampMs::new(1))
            .expect("a draft");

        // A path with one component has an empty parent, and an empty path is not a directory
        // anything can open. What holds that name is the working directory, which is what a store
        // under a relative path is created beside.
        assert_eq!(holder_of(Path::new("beside-me")), Path::new("."));
        assert_eq!(holder_of(Path::new("support/drafts")), Path::new("support"));
        assert_eq!(holder_of(&deep), deep.parent().expect("a parent"));
    }

    #[test]
    #[cfg(unix)]
    fn a_store_reached_through_a_link_makes_its_targets_own_names_durable() {
        // What a draft under a link depends on is the names the filesystem holds, not the ones the
        // caller spelled, so the walk resolves the path before it flushes anything.
        let directory = tempfile::tempdir().expect("a directory");
        let target = directory.path().join("data").join("drafts");
        let store = DraftStore::open(&target, device()).expect("a store");
        let draft = store
            .create(
                open_target(),
                "through a link".to_owned(),
                TimestampMs::new(1),
            )
            .expect("a draft");

        #[cfg(unix)]
        {
            let link = directory.path().join("links");
            std::os::unix::fs::symlink(directory.path().join("data"), &link).expect("a link");
            let through_the_link =
                DraftStore::open(link.join("drafts"), device()).expect("a store through a link");
            assert_eq!(
                through_the_link
                    .load(draft.draft_id)
                    .expect("the same draft")
                    .text,
                "through a link"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn every_link_on_the_way_is_a_name_the_store_answers_for() {
        // A chain: the path a caller spells leads to a link that leads to the store. The directory
        // holding the middle link is on neither end of the chain, and losing that name would leave
        // the drafts where they are and nothing reaching them. Making it unreadable is how a test
        // can see whether the walk got there: the store refuses rather than saying it is durable.
        use std::os::unix::fs::PermissionsExt as _;

        if kr_ipc::paths::current_uid() == 0 {
            // A process that bypasses the mode bits cannot be told anything by them.
            return;
        }

        let directory = tempfile::tempdir().expect("a directory");
        let data = directory.path().join("data");
        std::fs::create_dir_all(data.join("drafts")).expect("the store's real home");
        let middle = directory.path().join("middle");
        std::fs::create_dir(&middle).expect("the directory holding the second link");
        std::os::unix::fs::symlink(data.join("drafts"), middle.join("hop"))
            .expect("the second link");
        let entry = directory.path().join("entry");
        std::fs::create_dir(&entry).expect("the directory holding the first link");
        std::os::unix::fs::symlink(middle.join("hop"), entry.join("link")).expect("the first link");

        // Walked through but not read, which is what the middle of a chain can be.
        std::fs::set_permissions(&middle, std::fs::Permissions::from_mode(0o111))
            .expect("search but not read");
        let outcome = DraftStore::open(entry.join("link"), device());
        std::fs::set_permissions(&middle, std::fs::Permissions::from_mode(0o700))
            .expect("readable again");
        let error = outcome.expect_err("a name on the way this store cannot answer for");
        assert!(error.to_string().contains("could not be used"), "{error}");

        // Readable, and the same path opens and reads a draft written at the far end.
        let real = DraftStore::open(data.join("drafts"), device()).expect("a store");
        let draft = real
            .create(
                open_target(),
                "at the far end".to_owned(),
                TimestampMs::new(1),
            )
            .expect("a draft");
        let through_the_chain =
            DraftStore::open(entry.join("link"), device()).expect("a store through two links");
        assert_eq!(
            through_the_chain
                .load(draft.draft_id)
                .expect("the same draft")
                .text,
            "at the far end"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_link_that_leads_back_to_where_it_is_is_followed_once_per_component() {
        // `hop` points at the directory it lives in, so a path may name it as often as it likes and
        // still be an ordinary path the kernel opens. What bounds the walk is the links one
        // resolution follows, not how much work a walk that started again would do.
        let directory = tempfile::tempdir().expect("a directory");
        let base = directory.path().join("base");
        std::fs::create_dir_all(&base).expect("the base");
        std::os::unix::fs::symlink(".", base.join("hop")).expect("a link to its own directory");

        let mut path = base.clone();
        for _ in 0..8 {
            path.push("hop");
        }
        path.push("drafts");
        let store = DraftStore::open(&path, device()).expect("a store behind eight hops");
        let draft = store
            .create(
                open_target(),
                "behind the hops".to_owned(),
                TimestampMs::new(1),
            )
            .expect("a draft");
        assert_eq!(
            DraftStore::open(base.join("drafts"), device())
                .expect("the same store")
                .load(draft.draft_id)
                .expect("the same draft")
                .text,
            "behind the hops"
        );

        // Past the bound the store refuses rather than walking for ever. Which refusal arrives
        // first is the kernel's: most refuse a path of this many links themselves, at a figure of
        // their own, and the bound here is what answers on one that does not.
        let mut too_many = base.clone();
        for _ in 0..(kr_ipc::paths::MAX_PATH_LINKS + 1) {
            too_many.push("hop");
        }
        too_many.push("drafts");
        assert!(
            DraftStore::open(&too_many, device()).is_err(),
            "a path of more links than any resolution follows was accepted"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_store_says_so_when_it_cannot_make_its_own_path_durable() {
        // A directory a caller can walk through but not open is a directory this store cannot
        // establish a name in, and it says that rather than returning a success that means less
        // than it looks. Reaching the refusal is also what shows the walk covers the path the
        // caller supplied and not only the deepest level.
        use std::os::unix::fs::PermissionsExt as _;

        if kr_ipc::paths::current_uid() == 0 {
            return;
        }

        let directory = tempfile::tempdir().expect("a directory");
        let outer = directory.path().join("outer");
        let store_path = outer.join("drafts");
        std::fs::create_dir_all(&store_path).expect("the tree");
        std::fs::set_permissions(&outer, std::fs::Permissions::from_mode(0o111))
            .expect("search but not read");

        let outcome = DraftStore::open(&store_path, device());
        // Restore it first, so the temporary directory can be cleaned up whatever the assertion
        // does.
        std::fs::set_permissions(&outer, std::fs::Permissions::from_mode(0o700))
            .expect("readable again");
        let error = outcome.expect_err("a directory this store cannot open for reading");
        assert!(error.to_string().contains("could not be used"), "{error}");
    }

    #[test]
    fn a_name_that_is_not_a_directory_is_refused_rather_than_written_into() {
        let directory = tempfile::tempdir().expect("a directory");
        let occupied = directory.path().join("drafts");
        std::fs::write(&occupied, b"not a directory").expect("a file in the way");
        #[cfg(unix)]
        let before = {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::metadata(&occupied)
                .expect("the file")
                .permissions()
                .mode()
        };

        let error = DraftStore::open(&occupied, device()).expect_err("a file is not a store");
        assert!(error.to_string().contains("could not be used"), "{error}");
        assert!(occupied.is_file(), "the file is still a file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let after = std::fs::metadata(&occupied)
                .expect("the file")
                .permissions()
                .mode();
            assert_eq!(
                after, before,
                "a file in the way had its permissions changed"
            );
        }
    }

    #[test]
    fn a_draft_survives_the_process_that_wrote_it() {
        let directory = tempfile::tempdir().expect("a directory");
        let draft = {
            let store = store(&directory);
            store
                .create(
                    open_target(),
                    "half a thought".to_owned(),
                    TimestampMs::new(10),
                )
                .expect("a draft")
        };
        // A second store over the same directory is a second run of the application.
        let store = store(&directory);
        let loaded = store
            .load(draft.draft_id)
            .expect("the draft is still there");
        assert_eq!(loaded, draft);
        assert_eq!(loaded.text, "half a thought");
        assert_eq!(drafts(&store).len(), 1);
    }

    #[test]
    fn the_directory_is_the_callers_and_is_made_owner_only() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        assert!(store.directory().is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = || {
                std::fs::metadata(store.directory())
                    .expect("the directory")
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode(), 0o700);

            // A directory that already existed and that anything on the machine could read is
            // narrowed rather than accepted.
            std::fs::set_permissions(store.directory(), std::fs::Permissions::from_mode(0o755))
                .expect("loosened");
            let reopened =
                DraftStore::open(store.directory(), device()).expect("the same directory");
            assert_eq!(reopened.directory(), store.directory());
            assert_eq!(mode(), 0o700);
        }
    }

    #[test]
    fn a_stored_draft_is_owner_only() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let draft = store
            .create(open_target(), "private".to_owned(), TimestampMs::new(1))
            .expect("a draft");
        let path = store.draft_path(draft.draft_id);
        assert!(path.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .expect("the file")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn an_update_names_the_revision_it_replaces() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let draft = store
            .create(open_target(), "one".to_owned(), TimestampMs::new(1))
            .expect("a draft");
        let second = store
            .update(&edited(&draft, "one two"), TimestampMs::new(2))
            .expect("an update");
        assert_eq!(second.text, "one two");
        assert_eq!(second.revision, DraftRevision::new(2));
        assert_eq!(second.created_at_ms, draft.created_at_ms);
        assert_eq!(second.updated_at_ms, TimestampMs::new(2));

        // The first revision is stale now, and an editor holding it does not overwrite.
        let error = store
            .update(&edited(&draft, "lost"), TimestampMs::new(3))
            .expect_err("a stale comparison");
        assert!(error.to_string().contains("revision"));
        assert_eq!(
            store.load(draft.draft_id).expect("the draft").text,
            "one two"
        );
    }

    #[test]
    fn two_editors_writing_at_once_produce_one_draft_and_one_refusal() {
        let directory = tempfile::tempdir().expect("a directory");
        let first = store(&directory);
        let second = DraftStore::open(directory.path().join("drafts"), device()).expect("a store");
        let draft = first
            .create(open_target(), "shared".to_owned(), TimestampMs::new(1))
            .expect("a draft");

        // Both read revision one and both write revision two, as closely together as two threads
        // can be made to. Exactly one takes the lock first; the other finds the stored revision has
        // moved and is refused.
        let barrier = std::sync::Barrier::new(2);
        let (left, right) = std::thread::scope(|scope| {
            let left = scope.spawn(|| {
                barrier.wait();
                first.update(&edited(&draft, "the first editor"), TimestampMs::new(2))
            });
            let right = scope.spawn(|| {
                barrier.wait();
                second.update(&edited(&draft, "the second editor"), TimestampMs::new(2))
            });
            (
                left.join().expect("the first thread"),
                right.join().expect("the second thread"),
            )
        });

        let winner = match (&left, &right) {
            (Ok(draft), Err(error)) | (Err(error), Ok(draft)) => {
                assert!(error.to_string().contains("revision"), "{error}");
                draft.clone()
            }
            (Ok(_), Ok(_)) => panic!("both editors wrote revision two"),
            (Err(left), Err(right)) => panic!("neither editor wrote: {left}, {right}"),
        };
        assert_eq!(winner.revision, DraftRevision::new(2));
        assert_eq!(first.load(draft.draft_id).expect("the draft"), winner);
        assert_eq!(drafts(&first).len(), 1);
    }

    #[test]
    fn a_writer_that_paused_while_another_moved_on_twice_overwrites_nothing() {
        let directory = tempfile::tempdir().expect("a directory");
        // Two stores over one directory: two windows of one application, or two processes.
        let paused = store(&directory);
        let moving = DraftStore::open(directory.path().join("drafts"), device()).expect("a store");
        let draft = moving
            .create(open_target(), "shared".to_owned(), TimestampMs::new(1))
            .expect("a draft");

        // The first window read revision one and stopped there. The second wrote twice, so the
        // revision the first would have written has been and gone.
        let held = paused.load(draft.draft_id).expect("the draft");
        assert_eq!(held.revision, DraftRevision::new(1));
        let mut current = draft.clone();
        for (at, text) in [(2, "the second window, once"), (3, "and again")] {
            current = moving
                .update(&edited(&current, text), TimestampMs::new(at))
                .expect("a publication");
        }

        let error = paused
            .update(
                &edited(&held, "what the first window wrote"),
                TimestampMs::new(9),
            )
            .expect_err("a lost comparison");
        assert!(error.to_string().contains("revision"));
        let stored = paused.load(draft.draft_id).expect("the draft");
        assert_eq!(
            stored.text, "and again",
            "the writer that lost overwrote nothing"
        );
        assert_eq!(stored.revision, DraftRevision::new(3));
    }

    #[test]
    fn an_editor_cannot_change_the_identity_the_owner_or_the_times() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let draft = store
            .create(open_target(), "text".to_owned(), TimestampMs::new(1))
            .expect("a draft");
        let updated = store
            .update(
                &Draft {
                    device_id: DeviceId::new(Uuid::from_bytes([9; 16])),
                    created_at_ms: TimestampMs::new(999),
                    updated_at_ms: TimestampMs::new(999),
                    text: "changed".to_owned(),
                    ..draft.clone()
                },
                TimestampMs::new(2),
            )
            .expect("an update");
        assert_eq!(updated.draft_id, draft.draft_id);
        assert_eq!(updated.device_id, device(), "the owner is the store's");
        assert_eq!(updated.revision, DraftRevision::new(2));
        assert_eq!(
            updated.created_at_ms, draft.created_at_ms,
            "when it was created is the stored draft's"
        );
        assert_eq!(updated.updated_at_ms, TimestampMs::new(2));
        assert_eq!(updated.text, "changed");
        assert_eq!(drafts(&store).len(), 1);
    }

    #[test]
    fn a_store_neither_changes_nor_removes_another_devices_draft() {
        let directory = tempfile::tempdir().expect("a directory");
        let mine = store(&directory);
        let draft = mine
            .create(open_target(), "mine".to_owned(), TimestampMs::new(1))
            .expect("a draft");

        let other = DraftStore::open(
            directory.path().join("drafts"),
            DeviceId::new(Uuid::from_bytes([8; 16])),
        )
        .expect("a store");
        let error = other
            .update(&edited(&draft, "not yours to change"), TimestampMs::new(2))
            .expect_err("another device's draft");
        assert!(error.to_string().contains("belongs to device"));
        let error = other
            .remove(draft.draft_id)
            .expect_err("another device's draft");
        assert!(error.to_string().contains("belongs to device"));
        assert_eq!(mine.load(draft.draft_id).expect("the draft"), draft);
    }

    #[test]
    fn an_attachment_is_only_an_association_and_replacing_one_leaves_the_draft_alone() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let draft = store
            .create(open_target(), "kept".to_owned(), TimestampMs::new(1))
            .expect("a draft");

        let first = AttachmentId::new(Uuid::from_bytes([1; 16]));
        let second = AttachmentId::new(Uuid::from_bytes([2; 16]));
        let mut associations = Associations::new();
        assert_eq!(associations.bind(draft.draft_id, first), None);
        assert_eq!(associations.attachment_of(draft.draft_id), Some(first));
        assert_eq!(associations.drafts_of(first), vec![draft.draft_id]);

        // Replacing the attachment replaces the association and nothing else.
        assert_eq!(associations.bind(draft.draft_id, second), Some(first));
        assert_eq!(associations.attachment_of(draft.draft_id), Some(second));
        assert!(associations.drafts_of(first).is_empty());
        assert_eq!(store.load(draft.draft_id).expect("the draft"), draft);

        // Losing the connection removes every association and touches no draft.
        associations.connection_lost();
        assert!(associations.is_empty());
        assert_eq!(associations.attachment_of(draft.draft_id), None);
        assert_eq!(store.load(draft.draft_id).expect("the draft"), draft);

        // The same device binds it again on reconnect.
        let third = AttachmentId::new(Uuid::from_bytes([3; 16]));
        assert_eq!(associations.bind(draft.draft_id, third), None);
        assert_eq!(associations.len(), 1);
        assert_eq!(associations.release(draft.draft_id), Some(third));
    }

    #[test]
    fn a_changed_binding_conflicts_the_draft_and_refuses_it_until_it_is_retargeted() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let mut draft = store
            .create(
                open_target(),
                "for this agent".to_owned(),
                TimestampMs::new(1),
            )
            .expect("a draft");
        assert_eq!(draft.submission().expect("open"), &draft.target.clone());

        let moved_on = DraftTarget::session(session())
            .in_application(application(), AgentBindingRevision::new(2));
        assert_eq!(draft.rebind(Some(&moved_on)), DraftState::Conflicted);
        assert_eq!(draft.submission(), Err(NotSubmittable::Conflicted));
        // The text is untouched: a conflict retains the draft rather than resolving it.
        assert_eq!(draft.text, "for this agent");

        // Rebinding again does not clear it. Only the caller does.
        assert_eq!(draft.rebind(Some(&moved_on)), DraftState::Conflicted);
        draft.retarget(moved_on.clone());
        assert_eq!(draft.state, DraftState::Open);
        assert_eq!(draft.submission().expect("retargeted"), &moved_on);
    }

    #[test]
    fn a_target_that_is_gone_orphans_the_draft_and_keeps_it() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let mut draft = store
            .create(open_target(), "still here".to_owned(), TimestampMs::new(1))
            .expect("a draft");

        assert_eq!(draft.rebind(None), DraftState::Orphaned);
        assert_eq!(draft.submission(), Err(NotSubmittable::Orphaned));
        assert_eq!(draft.text, "still here");

        // A different session is the same thing: this draft is not for whatever is there now.
        let mut other = store
            .create(open_target(), "also here".to_owned(), TimestampMs::new(1))
            .expect("a draft");
        let elsewhere = DraftTarget::session(SessionId::new(Uuid::from_bytes([8; 16])));
        assert_eq!(other.rebind(Some(&elsewhere)), DraftState::Orphaned);
    }

    /// A draft whose fields are fixed, so a test can grow its text to an exact encoded size.
    ///
    /// Every field but the text is fixed width or is given here, because the bound is on the whole
    /// encoded record: a sample whose revision or timestamps were narrower than the draft under test
    /// would put the boundary in the wrong place.
    fn sample(revision: u64, at: u64, text: String) -> Draft {
        Draft {
            draft_id: DraftId::new(Uuid::from_bytes([1; 16])),
            revision: DraftRevision::new(revision),
            device_id: DeviceId::new(Uuid::from_bytes([2; 16])),
            target: open_target(),
            state: DraftState::Open,
            text,
            attachments: Vec::new(),
            conflict_of: Nullable::null(),
            retained: Nullable::null(),
            created_at_ms: TimestampMs::new(at),
            updated_at_ms: TimestampMs::new(at),
        }
    }

    /// The longest text whose payload is still within the bound, for a draft of that shape.
    ///
    /// Found by halving rather than by growing a byte at a time: the answer is the same and the
    /// work is a few dozen encodings instead of sixty-five thousand.
    fn text_at_the_payload_limit(revision: u64, at: u64) -> String {
        let fits = |length: usize| {
            DraftStore::encode_payload(&sample(revision, at, "x".repeat(length))).is_ok()
        };
        let (mut low, mut high) = (0, MAX_STORED_DRAFT_BYTES + 1);
        assert!(fits(low), "an empty draft fits");
        assert!(!fits(high), "a draft past the storage bound does not");
        while high - low > 1 {
            let middle = low + (high - low) / 2;
            if fits(middle) {
                low = middle;
            } else {
                high = middle;
            }
        }
        "x".repeat(low)
    }

    #[test]
    fn an_edit_the_service_could_not_carry_is_refused_where_it_is_made() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        // One byte past the payload bound and still inside the storage bound: it would fit the file
        // and could never be published, so it is refused at the edit rather than hours later at a
        // synchronisation.
        // The shape `create` produces: revision one, and the time this test gives it.
        let mut text = text_at_the_payload_limit(1, 1);
        text.push('x');
        let over = sample(1, 1, text.clone());
        assert!(DraftStore::encode_payload(&over).is_err());
        assert!(
            DraftStore::encode_record(&over).is_ok(),
            "the storage bound alone would have let this through"
        );

        let error = store
            .create(open_target(), text.clone(), TimestampMs::new(1))
            .expect_err("larger than the service carries");
        assert!(error.to_string().contains("limit"));
        assert!(drafts(&store).is_empty());

        let draft = store
            .create(open_target(), "short".to_owned(), TimestampMs::new(1))
            .expect("a draft");
        let error = store
            .update(&edited(&draft, &text), TimestampMs::new(2))
            .expect_err("larger than the service carries");
        assert!(error.to_string().contains("limit"));
        assert_eq!(store.load(draft.draft_id).expect("the draft").text, "short");
    }

    #[test]
    fn a_payload_at_the_limit_still_fits_when_it_arrives_here_as_a_copy() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        // Ten digits of milliseconds, which is what a real clock produces and the widest a
        // timestamp encodes to.
        let remote = sample(
            4,
            1_760_000_000_000,
            text_at_the_payload_limit(4, 1_760_000_000_000),
        );
        let payload = DraftStore::encode_payload(&remote).expect("at the limit");
        assert!(payload.len() <= MAX_DRAFT_BYTES);
        assert!(
            payload.len() > MAX_DRAFT_BYTES - 8,
            "the sample is at the limit, not near it: {}",
            payload.len()
        );

        let local = store
            .create(open_target(), "mine".to_owned(), TimestampMs::new(1))
            .expect("a draft");
        // Both of this device's own notes are set, which is the widest a copy is stored at: the
        // draft it sits beside and the copy the service kept of the write it beat.
        let retained = SyncConflictId::new(Uuid::from_bytes([9; 16]));
        let copy = store
            .keep_copy(
                local.draft_id,
                &remote,
                Some(retained),
                TimestampMs::new(1_760_000_000_001),
            )
            .expect("a copy of a draft the service was carrying");
        assert_eq!(copy.conflict_of, Nullable::some(local.draft_id));
        assert_eq!(copy.retained, Nullable::some(retained));
        // Neither note is anything the service carries.
        assert_eq!(
            DraftStore::decode_payload(&DraftStore::encode_payload(&copy).expect("a payload"))
                .expect("read back")
                .retained,
            Nullable::null()
        );
        assert_eq!(copy.text, remote.text);
        assert_eq!(copy.target, remote.target);
        assert_eq!(copy.state, remote.state);
        assert_eq!(copy.attachments, remote.attachments);
        // The copy is this device's, so its identity, owner, revision and times are this device's.
        assert_ne!(copy.draft_id, remote.draft_id);
        assert_eq!(copy.device_id, device());
        assert_eq!(copy.revision, DraftRevision::new(1));
        assert_eq!(store.load(copy.draft_id).expect("the copy"), copy);
    }

    #[test]
    fn a_copy_is_kept_beside_the_draft_rather_than_over_it() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let mine = store
            .create(
                open_target(),
                "what I wrote".to_owned(),
                TimestampMs::new(1),
            )
            .expect("a draft");
        let theirs = edited(&mine, "what the other device wrote");

        let copy = store
            .keep_copy(mine.draft_id, &theirs, None, TimestampMs::new(2))
            .expect("a copy");
        assert_eq!(
            copy.retained,
            Nullable::null(),
            "a fetch answers no refusal"
        );
        assert_ne!(copy.draft_id, mine.draft_id);
        assert_eq!(copy.conflict_of, Nullable::some(mine.draft_id));
        assert_eq!(copy.text, "what the other device wrote");
        assert_eq!(
            store.load(mine.draft_id).expect("mine").text,
            "what I wrote",
            "the local draft is never replaced"
        );
        assert_eq!(drafts(&store).len(), 2);
    }

    #[test]
    fn a_reconnect_leaves_the_draft_unsent() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let mut draft = store
            .create(open_target(), "unsent".to_owned(), TimestampMs::new(1))
            .expect("a draft");
        let mut associations = Associations::new();
        associations.bind(draft.draft_id, AttachmentId::new(Uuid::from_bytes([1; 16])));

        // Everything a reconnect does, in the order it does it. What each of them answers with is
        // a state or an attachment; none of them is a target, and `submission` is the only thing
        // that produces one.
        associations.connection_lost();
        associations.bind(draft.draft_id, AttachmentId::new(Uuid::from_bytes([2; 16])));
        let state: DraftState = draft.rebind(Some(&open_target()));
        assert_eq!(state, DraftState::Open);
        assert_eq!(
            store.load(draft.draft_id).expect("the draft").text,
            "unsent",
            "the draft is still unsent, and still the person's to send"
        );
    }

    #[test]
    fn an_interrupted_write_leaves_nothing_a_reader_can_find() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let draft = store
            .create(open_target(), "written".to_owned(), TimestampMs::new(1))
            .expect("a draft");
        // What a process killed part way through a write leaves behind.
        let abandoned = store.directory().join("half-a-draft.partial");
        std::fs::write(&abandoned, b"not a draft").expect("an interrupted write");
        assert_eq!(drafts(&store).len(), 1, "a partial file is not a draft");
        // The next run removes it.
        let reopened = DraftStore::open(store.directory(), device()).expect("a store");
        assert!(!abandoned.exists());
        assert_eq!(reopened.load(draft.draft_id).expect("the draft"), draft);
    }

    #[test]
    fn a_file_this_build_cannot_read_is_named_rather_than_hiding_the_drafts_beside_it() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let draft = store
            .create(open_target(), "readable".to_owned(), TimestampMs::new(1))
            .expect("a draft");
        let damaged = DraftId::new(Uuid::from_bytes([6; 16]));
        let damaged_path = store.draft_path(damaged);
        std::fs::write(&damaged_path, b"not canonical bytes").expect("a damaged file");

        let listing = store.list().expect("a listing");
        assert_eq!(listing.drafts, vec![draft.clone()]);
        assert_eq!(listing.unreadable, vec![damaged_path]);
        // Asking for the damaged one says so rather than answering with somebody else's draft.
        assert!(store.load(damaged).is_err());
        assert_eq!(store.load(draft.draft_id).expect("the draft"), draft);
    }

    #[test]
    fn a_record_that_names_another_draft_is_not_read_as_this_one() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let draft = store
            .create(open_target(), "mine".to_owned(), TimestampMs::new(1))
            .expect("a draft");
        let impostor = DraftId::new(Uuid::from_bytes([2; 16]));
        std::fs::write(
            store.draft_path(impostor),
            DraftStore::encode_record(&draft).expect("canonical bytes"),
        )
        .expect("a misfiled record");
        let error = store.load(impostor).expect_err("a misfiled record");
        assert!(error.to_string().contains("could not be read"));
    }

    #[test]
    fn removing_a_draft_takes_its_note_with_it() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let draft = store
            .create(open_target(), "one".to_owned(), TimestampMs::new(1))
            .expect("a draft");
        store
            .update(&edited(&draft, "two"), TimestampMs::new(2))
            .expect("an update");
        let checkpoint = SyncCheckpoint {
            position: at(3),
            published_revision: Nullable::some(DraftRevision::new(2)),
        };
        assert_eq!(
            store
                .record_checkpoint(draft.draft_id, checkpoint)
                .expect("a note"),
            Standing::Later
        );
        assert_eq!(
            store.checkpoint(draft.draft_id).expect("a note"),
            Some(checkpoint)
        );

        store.remove(draft.draft_id).expect("removed");
        assert!(drafts(&store).is_empty());
        assert_eq!(store.checkpoint(draft.draft_id).expect("no note"), None);
        assert!(
            store.remove(draft.draft_id).is_ok(),
            "removing twice is fine"
        );
    }

    #[test]
    fn a_note_this_build_cannot_read_is_treated_as_no_note_at_all() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let draft = store
            .create(open_target(), "one".to_owned(), TimestampMs::new(1))
            .expect("a draft");
        std::fs::write(store.checkpoint_path(draft.draft_id), b"not a note")
            .expect("a damaged note");
        // It is a cache: a publication then compares against nothing and learns where the object
        // stands from the service, rather than stopping because a cache is unreadable.
        assert_eq!(store.checkpoint(draft.draft_id).expect("no note"), None);
        assert!(!store.checkpoint_path(draft.draft_id).exists());
        assert_eq!(store.load(draft.draft_id).expect("the draft").text, "one");

        // Forgetting a note a caller no longer trusts is the same thing said deliberately.
        assert_eq!(
            store
                .record_checkpoint(
                    draft.draft_id,
                    SyncCheckpoint {
                        position: at(9),
                        published_revision: Nullable::null(),
                    },
                )
                .expect("a note"),
            Standing::Later
        );
        store.forget_checkpoint(draft.draft_id).expect("forgotten");
        assert_eq!(store.checkpoint(draft.draft_id).expect("no note"), None);
    }

    #[test]
    fn an_answer_that_arrives_late_does_not_take_the_note_backwards() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let draft = store
            .create(open_target(), "one".to_owned(), TimestampMs::new(1))
            .expect("a draft");

        // What a fetch writes after another device advanced the object.
        let current = SyncCheckpoint {
            position: at(2),
            published_revision: Nullable::null(),
        };
        assert_eq!(
            store
                .record_checkpoint(draft.draft_id, current)
                .expect("a note"),
            Standing::Later
        );

        // A publication this device made earlier, answered late, naming the write before it.
        // Writing it would throw away what the fetch already learnt.
        assert_eq!(
            store
                .record_checkpoint(
                    draft.draft_id,
                    SyncCheckpoint {
                        position: at(1),
                        published_revision: Nullable::some(draft.revision),
                    },
                )
                .expect("a note"),
            Standing::Earlier,
            "an older write was recorded over a newer one"
        );
        assert_eq!(
            store.checkpoint(draft.draft_id).expect("a note"),
            Some(current)
        );

        // Another name for the place the note already holds is a second history, and it stands
        // no more than older news does.
        let elsewhere = SyncPosition::at(
            2,
            crate::services::SyncRevision::new(Uuid::from_bytes([0xee; 16])),
            None,
        );
        assert_eq!(
            store
                .record_checkpoint(
                    draft.draft_id,
                    SyncCheckpoint {
                        position: elsewhere,
                        published_revision: Nullable::some(draft.revision),
                    },
                )
                .expect("a note"),
            Standing::Forked { held: at(2) }
        );
        assert_eq!(
            store.checkpoint(draft.draft_id).expect("a note"),
            Some(current)
        );

        // A later write still lands.
        let later = SyncCheckpoint {
            position: at(3),
            published_revision: Nullable::some(draft.revision),
        };
        assert_eq!(
            store
                .record_checkpoint(draft.draft_id, later)
                .expect("a note"),
            Standing::Later
        );
        assert_eq!(
            store.checkpoint(draft.draft_id).expect("a note"),
            Some(later)
        );
    }

    #[test]
    fn a_stored_name_is_read_back_as_the_draft_it_holds() {
        let draft_id = DraftId::new(Uuid::from_bytes([5; 16]));
        assert_eq!(
            parse_draft_name(&format!("{draft_id}.draft")),
            Some(draft_id)
        );
        assert_eq!(parse_draft_name(&format!("{draft_id}.sync")), None);
        assert_eq!(parse_draft_name(&format!("{draft_id}.partial")), None);
        assert_eq!(parse_draft_name(LOCK_NAME), None);
        assert_eq!(parse_draft_name("not-a-draft.draft"), None);
    }

    #[test]
    fn a_store_failure_tells_a_person_something_they_can_act_on() {
        // The store's refusals are its own. None of them tells a person to update the application,
        // which is what the protocol table would have said about the codes they are logged under.
        let too_long = DraftError::TooLarge {
            len: MAX_DRAFT_BYTES + 1,
            limit: MAX_DRAFT_BYTES,
        };
        assert_eq!(
            crate::retry::user_action(too_long.code()),
            UserAction::Update,
            "the code alone would send a person to look for an update"
        );
        assert_eq!(too_long.user_action(), UserAction::Nothing);
        let client_error = ClientError::from(too_long);
        assert_eq!(client_error.user_action(), UserAction::Nothing);
        assert_eq!(
            client_error
                .decision(crate::retry::RequestClass::IdempotentRead)
                .action,
            UserAction::Nothing,
            "the decision and the action agree"
        );

        let unwritable = DraftError::Storage {
            path: PathBuf::from("/drafts"),
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };
        assert_eq!(unwritable.user_action(), UserAction::FixConfiguration);
        assert_eq!(unwritable.code(), ErrorCode::StorageUnavailable);
    }
}
