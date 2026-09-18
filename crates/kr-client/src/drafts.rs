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
//! its name. Every change takes an exclusive lock on the store's own `.lock` file and every read
//! takes a shared one, so reading a revision, comparing it and replacing it is one step against
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

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{
    AgentBindingRevision, ApplicationInstanceId, AttachmentId, DeviceId, DraftId, DraftRevision,
    SessionId,
};
use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};
use kr_protocol::transfer::{AttachmentHandle, DraftState};
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};
use crate::retry::UserAction;

/// The most a draft's synchronised payload may carry, in bytes.
///
/// Section 20 gives a synchronised object 64 KiB of plaintext before padding, and a draft is one of
/// the three kinds it may be. A draft too large to synchronise would be a draft this contract
/// cannot carry, so the bound applies to every edit a person makes on the device as well as on the
/// wire, and it applies to the encoded record rather than to the text alone: attachments and a
/// target take space too.
pub const MAX_DRAFT_BYTES: usize = 64 * 1024;

/// What this device's own notes on a stored draft may add to an encoded record.
///
/// [`Draft::conflict_of`] is local: it says which draft a copy belongs beside, and the service never
/// carries it. A copy also carries its own identity and the time it arrived. Allowing for those
/// separately is what keeps a payload that is exactly at the limit storable when it arrives here as
/// a copy, rather than refusing to keep content the service was already carrying.
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
    /// An older copy of a draft was offered to the service after a newer one was accepted.
    #[error("draft {draft_id} was published at revision {published}; {offered} is older")]
    StalePublication {
        /// The draft.
        draft_id: DraftId,
        /// The revision the service was last given.
        published: DraftRevision,
        /// The revision that was offered now.
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
            Self::RevisionConflict { .. } | Self::StalePublication { .. } => {
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
            | Self::StalePublication { .. }
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
/// generation a comparison names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCheckpoint {
    /// The generation the service holds.
    pub generation: U64,
    /// The revision *this device* published at that generation.
    ///
    /// Null when the generation came from another device's write, which this device only fetched.
    /// A revision counter belongs to the device that keeps it, so the number another device reached
    /// says nothing about which of this device's own copies is the newest.
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

    /// Replaces a draft, and advances its revision.
    ///
    /// The expected revision is the one the caller last read. Reading the stored draft, comparing
    /// its revision and writing the result happen under one exclusive lock, so a second editor in
    /// this process or another either wrote before this call read or is told its comparison lost.
    /// Neither overwrites the other's text.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::RevisionConflict`] when the stored draft has moved on,
    /// [`DraftError::NotOwned`] when the draft belongs to another device, [`DraftError::TooLarge`]
    /// or [`DraftError::TooManyAttachments`] when the result does not fit the contract, and
    /// [`DraftError::Storage`] when the file cannot be written.
    pub fn update(
        &self,
        draft_id: DraftId,
        expected: DraftRevision,
        now: TimestampMs,
        edit: impl FnOnce(&mut Draft),
    ) -> Result<Draft> {
        let guard = self.exclusive()?;
        let outcome = (|| {
            let mut draft = self.read(draft_id)?;
            self.check_owner(&draft)?;
            if draft.revision != expected {
                return Err(DraftError::RevisionConflict {
                    draft_id,
                    expected,
                    current: draft.revision,
                }
                .into());
            }
            edit(&mut draft);
            // The identity, the owner and the revision are the store's, not an editor's. A closure
            // that changed one of them would produce a draft the store could not find or a
            // comparison nothing could win.
            draft.draft_id = draft_id;
            draft.device_id = self.device_id;
            draft.revision = DraftRevision::new(expected.get().saturating_add(1));
            draft.updated_at_ms = now;
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
    /// beside it costs a few bytes would lose the very thing the person is meant to choose from.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::Storage`] when the file cannot be written, and
    /// [`DraftError::TooLarge`] when the content does not fit the storage bound.
    pub fn keep_copy(&self, of: DraftId, content: &Draft, now: TimestampMs) -> Result<Draft> {
        let copy = Draft {
            draft_id: DraftId::new(fresh_uuid()?),
            revision: DraftRevision::new(1),
            device_id: self.device_id,
            target: content.target.clone(),
            state: content.state,
            text: content.text.clone(),
            attachments: content.attachments.clone(),
            conflict_of: Nullable::some(of),
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
            remove_if_present(&self.draft_path(draft_id))?;
            remove_if_present(&self.checkpoint_path(draft_id))
        })();
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

    /// Records where a draft reached on the synchronisation service.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::Storage`] when the note cannot be written.
    pub fn record_checkpoint(&self, draft_id: DraftId, checkpoint: SyncCheckpoint) -> Result<()> {
        let bytes = kr_cbor::to_canonical_vec(&checkpoint)?;
        let guard = self.exclusive()?;
        let written = self.write_bytes(&self.checkpoint_path(draft_id), &bytes);
        drop(guard);
        written
    }

    /// Forgets where a draft reached on the synchronisation service.
    ///
    /// A device that has been signed out of the service, or that is starting again against a
    /// different one, has a note that names a generation nothing holds. Forgetting it costs the
    /// next publication a comparison and a fetch; keeping it would cost a comparison against a
    /// number that means nothing.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::Storage`] when the note cannot be removed.
    pub fn forget_checkpoint(&self, draft_id: DraftId) -> Result<()> {
        let guard = self.exclusive()?;
        let removed = remove_if_present(&self.checkpoint_path(draft_id));
        drop(guard);
        removed
    }

    /// Returns the bytes a synchronised copy of this draft is sealed from.
    ///
    /// This device's note about which draft a copy sits beside is left out: it is local, and a
    /// service that carried it would be carrying one device's screen layout.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::TooLarge`] or [`DraftError::TooManyAttachments`] when the draft does
    /// not fit the contract.
    pub fn encode_payload(draft: &Draft) -> Result<Vec<u8>> {
        let payload = Draft {
            conflict_of: Nullable::null(),
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
                remove_if_present(&path)?;
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
        sync_directory(&self.directory).map_err(|source| storage(&self.directory, source))?;
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
                remove_if_present(&path)?;
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

fn fresh_uuid() -> Result<Uuid> {
    Ok(kr_transport::random::fresh_uuid_v4()?)
}

/// Creates the directory owner-only, and makes an existing one owner-only.
///
/// Unsent text a person has written. A directory anything on the machine could read would be one
/// this store had no business writing into, so an existing directory is narrowed rather than
/// accepted. On Windows the directory takes whatever access list it inherits, which this store does
/// not narrow: what protects it there is the access list of the directory the caller chose, so a
/// caller puts the store under its own per-user application data rather than somewhere shared.
fn private_directory(directory: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(directory)?.permissions().mode();
        if mode & 0o077 != 0 {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// Writes a new file whole, and flushes it to the device before anything renames it into place.
///
/// The file is created exclusively and, on Unix, owner-only from the moment it exists rather than a
/// moment afterwards: a file that was briefly readable is a file that was readable. A failure after
/// it was created removes it; a process that dies here leaves it, and the next
/// [`DraftStore::open`] sweeps it away.
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
/// Unix only. Windows offers no directory handle to flush, so what a replacement rests on there is
/// the filesystem's own ordering of the rename against the file's contents. The contents are
/// flushed before the rename on both, so a crash leaves the old draft or the new one; what Windows
/// does not promise is that the rename itself is durable.
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
    /// The service accepted it, at this generation.
    Accepted {
        /// The generation the service now holds, which the next comparison names.
        generation: u64,
    },
    /// Another device had written first.
    ///
    /// The local draft is exactly as it was. What the service held is kept beside it under `copy`,
    /// for the person to choose from, and the note now names the generation that content is at, so
    /// a caller that has chosen can publish against it.
    Conflicted {
        /// The copy that was kept.
        copy: DraftId,
        /// The revision the other device's draft carried.
        remote_revision: DraftRevision,
        /// The generation the service holds.
        generation: u64,
    },
}

/// What came down from the service, and where it was put.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched {
    /// The draft as the service held it.
    pub remote: Draft,
    /// The generation the service holds it at.
    pub generation: u64,
    /// The copy this device kept beside its own.
    pub copy: Draft,
}

/// One device's synchronised half of its drafts.
///
/// The comparison is against the generation this device last saw, which is kept beside the draft as
/// a [`SyncCheckpoint`] and is *not* the draft's own revision: a draft edited three times offline is
/// at revision four and has still only ever been published once. Section 20 keeps the loser of a
/// comparison rather than resolving it by whichever clock was further ahead, and section 24 adds
/// the direction that matters on a device: what is kept is kept *beside* the local draft, so
/// reconnecting never replaces the person's text with what was on the service.
///
/// A note that is lost or was never written costs a comparison, not a draft: the publication is
/// refused, the content the service holds comes down beside the local draft, and the note is written
/// from the generation that fetch reported. The next publication then compares against it.
#[derive(Clone, Debug)]
pub struct DraftSync {
    service: std::sync::Arc<dyn crate::services::SyncBackupService>,
    sealer: std::sync::Arc<dyn DraftSealer>,
}

impl DraftSync {
    /// Builds the synchronised half over a service client and this device's sealing.
    #[must_use]
    pub fn new(
        service: std::sync::Arc<dyn crate::services::SyncBackupService>,
        sealer: std::sync::Arc<dyn DraftSealer>,
    ) -> Self {
        Self { service, sealer }
    }

    /// Publishes a draft, under compare and swap on the generation this device last saw.
    ///
    /// A refused comparison is not a failure: it is the answer that another device wrote first, and
    /// it brings that content down beside the local draft rather than over it. Every other refusal
    /// is returned as it came.
    ///
    /// # Errors
    ///
    /// Returns the service's refusal, [`DraftError::StalePublication`] when an older copy of a
    /// draft is offered after a newer one was accepted, [`DraftError::TooLarge`] when the draft does
    /// not fit the contract, and [`DraftError::Storage`] when a conflict copy or the note cannot be
    /// written.
    pub async fn publish(
        &self,
        store: &DraftStore,
        draft: &Draft,
        now: TimestampMs,
    ) -> Result<Published> {
        let plaintext = DraftStore::encode_payload(draft)?;
        let ciphertext = self.sealer.seal(&plaintext)?;
        let collection = draft_collection(draft.draft_id);
        // What this device last saw the service hold. A draft that has never been published expects
        // nothing to be there, which is generation zero.
        let note = store.checkpoint(draft.draft_id)?;
        if let Some(published) = note.and_then(|note| note.published_revision.0)
            && draft.revision < published
        {
            // A caller holding an older copy of its own draft. The service would accept it, because
            // the generation is right and the draft's revision means nothing to it, and the newest
            // text would be gone from the object every other device reads.
            return Err(DraftError::StalePublication {
                draft_id: draft.draft_id,
                published,
                offered: draft.revision,
            }
            .into());
        }
        let expected = note.map_or(0, |note| note.generation.get());
        match self
            .service
            .compare_exchange(&collection, expected, &ciphertext)
            .await
        {
            Ok(accepted) => {
                store.record_checkpoint(
                    draft.draft_id,
                    SyncCheckpoint {
                        generation: U64::new(accepted),
                        published_revision: Nullable::some(draft.revision),
                    },
                )?;
                Ok(Published::Accepted {
                    generation: accepted,
                })
            }
            Err(error) if error.code() == ErrorCode::DraftConflict => {
                let fetched = self.fetch_beside(store, draft.draft_id, now).await?;
                Ok(Published::Conflicted {
                    copy: fetched.copy.draft_id,
                    remote_revision: fetched.remote.revision,
                    generation: fetched.generation,
                })
            }
            Err(error) => Err(error),
        }
    }

    /// Brings down what the service holds for a draft, beside the local one.
    ///
    /// It never replaces. The content arrives under a fresh identity that names the draft it belongs
    /// beside, which is what keeps a reconnect from putting remote input where the person's text
    /// was. Section 24 makes that the rule rather than a preference.
    ///
    /// The note is written from the generation the service reported, so a device that had lost track
    /// of where the object stood knows again.
    ///
    /// # Errors
    ///
    /// Returns the service's refusal, [`ClientError::Cbor`] when the object is not a draft this
    /// build reads or is larger than section 20 lets a service carry, and [`DraftError::Storage`]
    /// when the copy or the note cannot be written.
    pub async fn fetch_beside(
        &self,
        store: &DraftStore,
        draft_id: DraftId,
        now: TimestampMs,
    ) -> Result<Fetched> {
        let (generation, ciphertext) = self.service.fetch(&draft_collection(draft_id)).await?;
        let plaintext = self.sealer.open(&ciphertext)?;
        let remote = DraftStore::decode_payload(&plaintext)?;
        let copy = store.keep_copy(draft_id, &remote, now)?;
        // The generation is this device's to remember; the revision beside it is not, because the
        // revision that fetch carried is the other device's counter and nothing about this device's
        // own copies follows from it.
        store.record_checkpoint(
            draft_id,
            SyncCheckpoint {
                generation: U64::new(generation),
                published_revision: Nullable::null(),
            },
        )?;
        Ok(Fetched {
            remote,
            generation,
            copy,
        })
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

    fn open_target() -> DraftTarget {
        DraftTarget::session(session()).in_application(application(), AgentBindingRevision::new(1))
    }

    fn drafts(store: &DraftStore) -> Vec<Draft> {
        let listing = store.list().expect("a listing");
        assert!(listing.unreadable.is_empty(), "{:?}", listing.unreadable);
        listing.drafts
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
            .update(
                draft.draft_id,
                draft.revision,
                TimestampMs::new(2),
                |draft| {
                    draft.text.push_str(" two");
                },
            )
            .expect("an update");
        assert_eq!(second.text, "one two");
        assert_eq!(second.revision, DraftRevision::new(2));

        // The first revision is stale now, and an editor holding it does not overwrite.
        let error = store
            .update(
                draft.draft_id,
                draft.revision,
                TimestampMs::new(3),
                |draft| {
                    draft.text = "lost".to_owned();
                },
            )
            .expect_err("a stale comparison");
        assert!(error.to_string().contains("revision"));
        assert_eq!(
            store.load(draft.draft_id).expect("the draft").text,
            "one two"
        );
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
        for (revision, text) in [(1, "the second window, once"), (2, "and again")] {
            moving
                .update(
                    draft.draft_id,
                    DraftRevision::new(revision),
                    TimestampMs::new(revision + 1),
                    |draft| draft.text = text.to_owned(),
                )
                .expect("a publication");
        }

        let error = paused
            .update(
                draft.draft_id,
                held.revision,
                TimestampMs::new(9),
                |draft| {
                    draft.text = "what the first window wrote".to_owned();
                },
            )
            .expect_err("a lost comparison");
        assert!(error.to_string().contains("revision"));
        assert_eq!(
            paused.load(draft.draft_id).expect("the draft").text,
            "and again",
            "the writer that lost overwrote nothing"
        );
        assert_eq!(
            paused.load(draft.draft_id).expect("the draft").revision,
            DraftRevision::new(3)
        );
    }

    #[test]
    fn an_editor_cannot_change_the_identity_the_owner_or_the_revision() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let draft = store
            .create(open_target(), "text".to_owned(), TimestampMs::new(1))
            .expect("a draft");
        let updated = store
            .update(
                draft.draft_id,
                draft.revision,
                TimestampMs::new(2),
                |draft| {
                    draft.draft_id = DraftId::new(Uuid::from_bytes([9; 16]));
                    draft.device_id = DeviceId::new(Uuid::from_bytes([9; 16]));
                    draft.revision = DraftRevision::new(99);
                },
            )
            .expect("an update");
        assert_eq!(updated.draft_id, draft.draft_id);
        assert_eq!(updated.device_id, device());
        assert_eq!(updated.revision, DraftRevision::new(2));
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
            .update(
                draft.draft_id,
                draft.revision,
                TimestampMs::new(2),
                |draft| {
                    draft.text = "not yours to change".to_owned();
                },
            )
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

    #[test]
    fn an_edit_the_service_could_not_carry_is_refused_where_it_is_made() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        // Between the payload bound and the storage bound: it would fit the file and could never be
        // published, so it is refused at the edit rather than hours later at a synchronisation.
        let error = store
            .create(
                open_target(),
                "x".repeat(MAX_DRAFT_BYTES),
                TimestampMs::new(1),
            )
            .expect_err("larger than the service carries");
        assert!(error.to_string().contains("limit"));
        assert!(drafts(&store).is_empty());

        let draft = store
            .create(open_target(), "short".to_owned(), TimestampMs::new(1))
            .expect("a draft");
        let error = store
            .update(
                draft.draft_id,
                draft.revision,
                TimestampMs::new(2),
                |draft| {
                    draft.text = "x".repeat(MAX_DRAFT_BYTES);
                },
            )
            .expect_err("larger than the service carries");
        assert!(error.to_string().contains("limit"));
        assert_eq!(store.load(draft.draft_id).expect("the draft").text, "short");
    }

    #[test]
    fn a_payload_at_the_limit_still_fits_when_it_arrives_here_as_a_copy() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let sample = |text: String| Draft {
            draft_id: DraftId::new(Uuid::from_bytes([1; 16])),
            revision: DraftRevision::new(4),
            device_id: DeviceId::new(Uuid::from_bytes([2; 16])),
            target: open_target(),
            state: DraftState::Open,
            text,
            attachments: Vec::new(),
            conflict_of: Nullable::null(),
            // Ten digits of milliseconds, which is what a real clock produces and the widest a
            // timestamp encodes to.
            created_at_ms: TimestampMs::new(1_760_000_000_000),
            updated_at_ms: TimestampMs::new(1_760_000_000_000),
        };
        // Grow the text until one more byte would take the payload past the limit.
        let mut text = String::new();
        while DraftStore::encode_payload(&sample(format!("{text}x"))).is_ok() {
            text.push('x');
        }
        let remote = sample(text);
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
        let copy = store
            .keep_copy(local.draft_id, &remote, TimestampMs::new(1_760_000_000_001))
            .expect("a copy of a draft the service was carrying");
        assert_eq!(copy.conflict_of, Nullable::some(local.draft_id));
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
        let theirs = Draft {
            text: "what the other device wrote".to_owned(),
            ..mine.clone()
        };

        let copy = store
            .keep_copy(mine.draft_id, &theirs, TimestampMs::new(2))
            .expect("a copy");
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
            .update(
                draft.draft_id,
                draft.revision,
                TimestampMs::new(2),
                |draft| {
                    draft.text = "two".to_owned();
                },
            )
            .expect("an update");
        let checkpoint = SyncCheckpoint {
            generation: U64::new(3),
            published_revision: Nullable::some(DraftRevision::new(2)),
        };
        store
            .record_checkpoint(draft.draft_id, checkpoint)
            .expect("a note");
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
        assert_eq!(parse_draft_name("store.lock"), None);
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
        assert_eq!(too_long.user_action(), UserAction::Nothing);
        assert_eq!(too_long.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            ClientError::from(too_long).user_action(),
            UserAction::Nothing,
            "a client failure carries the store's answer, not the code's"
        );

        let unwritable = DraftError::Storage {
            path: PathBuf::from("/drafts"),
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };
        assert_eq!(unwritable.user_action(), UserAction::FixConfiguration);
        assert_eq!(unwritable.code(), ErrorCode::StorageUnavailable);
        let client_error = ClientError::from(unwritable);
        assert_eq!(client_error.user_action(), UserAction::FixConfiguration);
        assert_eq!(
            client_error
                .decision(crate::retry::RequestClass::IdempotentRead)
                .action,
            UserAction::FixConfiguration,
            "the decision and the action agree"
        );
    }
}
