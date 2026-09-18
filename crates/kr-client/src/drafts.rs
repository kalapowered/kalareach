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
//! # Nothing here submits
//!
//! There is one way to reach a submission, [`Draft::submission`], and it is a check rather than an
//! action: it returns the target a caller would submit against, or the reason it may not.
//! [`Associations::bind`], [`Associations::connection_lost`] and [`Draft::rebind`] return no such
//! thing, so no reconnect and no rebind can turn into a submitted prompt. Sending it is the
//! caller's own separate step, as section 12 requires of transfer, insertion and submission.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use kr_protocol::ids::{
    AgentBindingRevision, ApplicationInstanceId, AttachmentId, DeviceId, DraftId, DraftRevision,
    SessionId,
};
use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};
use kr_protocol::transfer::{AttachmentHandle, DraftState};
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};

/// The most an encoded draft may carry.
///
/// Section 20 gives a synchronised object 64 KiB of plaintext before padding, and a draft is one
/// of the three kinds it may be. A draft too large to synchronise would be a draft this contract
/// cannot carry, so the bound applies on the device as well as on the wire, and it applies to the
/// encoded record rather than to the text alone: attachments and a target take space too.
pub const MAX_DRAFT_BYTES: usize = 64 * 1024;

/// The most attachments one draft may hold.
pub const MAX_DRAFT_ATTACHMENTS: usize = 64;

/// The file extension every stored draft carries.
const DRAFT_EXTENSION: &str = "draft";

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
    /// The directory or a draft file could not be read or written.
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
    /// Returns the stable protocol code this refusal corresponds to.
    ///
    /// A local store is not a host, but a client that has one vocabulary for failures can show one
    /// direct action for them: the retry policy translates the code, and a draft that could not be
    /// written for want of space says the same thing a host would have said.
    #[must_use]
    pub const fn code(&self) -> kr_protocol::error::ErrorCode {
        use kr_protocol::error::ErrorCode;
        match self {
            Self::Storage { .. } => ErrorCode::StorageUnavailable,
            Self::Unknown { .. } | Self::TooLarge { .. } | Self::TooManyAttachments { .. } => {
                ErrorCode::InvalidArgument
            }
            Self::RevisionConflict { .. } => ErrorCode::DraftConflict,
            // A file this build cannot read is a build that is behind the one that wrote it.
            Self::Corrupt { .. } => ErrorCode::UnsupportedSchema,
        }
    }
}

/// Drafts this device owns, on this device's disk.
///
/// The directory is the caller's: a desktop application puts it under its own support directory, a
/// command line under the user's state directory, a test under a temporary one. The store creates
/// it if it is not there, owner-only where the platform expresses that, and writes every draft
/// whole or not at all.
#[derive(Clone, Debug)]
pub struct DraftStore {
    directory: PathBuf,
    device_id: DeviceId,
}

impl DraftStore {
    /// Opens or creates a store in `directory` for one device.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::Storage`] when the directory cannot be created or read.
    pub fn open(directory: impl Into<PathBuf>, device_id: DeviceId) -> Result<Self> {
        let directory = directory.into();
        create_private_directory(&directory).map_err(|source| storage(&directory, source))?;
        Ok(Self {
            directory,
            device_id,
        })
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
        self.write(&draft)?;
        Ok(draft)
    }

    /// Reads one draft.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::Unknown`] when nothing is stored under that identity, and
    /// [`DraftError::Corrupt`] when the file is not a draft this build reads.
    pub fn load(&self, draft_id: DraftId) -> Result<Draft> {
        let path = self.path_of(draft_id);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(DraftError::Unknown { draft_id }.into());
            }
            Err(error) => return Err(storage(&path, error).into()),
        };
        decode(&path, &bytes)
    }

    /// Reads every stored draft, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::Storage`] when the directory cannot be read, and
    /// [`DraftError::Corrupt`] when one of its files is not a draft this build reads.
    pub fn list(&self) -> Result<Vec<Draft>> {
        let entries = std::fs::read_dir(&self.directory)
            .map_err(|source| storage(&self.directory, source))?;
        let mut drafts = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| storage(&self.directory, source))?;
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some(DRAFT_EXTENSION) {
                continue;
            }
            let bytes = std::fs::read(&path).map_err(|source| storage(&path, source))?;
            drafts.push(decode(&path, &bytes)?);
        }
        drafts.sort_by(|left, right| {
            left.created_at_ms
                .get()
                .cmp(&right.created_at_ms.get())
                .then_with(|| left.draft_id.cmp(&right.draft_id))
        });
        Ok(drafts)
    }

    /// Replaces a draft, and advances its revision.
    ///
    /// The expected revision is the one the caller last read. A second editor on this device that
    /// wrote in between loses the comparison rather than overwriting, which is the same rule the
    /// synchronised copy follows.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::RevisionConflict`] when the stored draft has moved on,
    /// [`DraftError::TooLarge`] or [`DraftError::TooManyAttachments`] when the result does not fit
    /// the contract, and [`DraftError::Storage`] when the file cannot be written.
    pub fn update(
        &self,
        draft_id: DraftId,
        expected: DraftRevision,
        now: TimestampMs,
        edit: impl FnOnce(&mut Draft),
    ) -> Result<Draft> {
        let mut draft = self.load(draft_id)?;
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
        // that changed one of them would produce a draft the store could not find or a comparison
        // nothing could win.
        draft.draft_id = draft_id;
        draft.device_id = self.device_id;
        draft.revision = DraftRevision::new(expected.get().saturating_add(1));
        draft.updated_at_ms = now;
        self.write(&draft)?;
        Ok(draft)
    }

    /// Writes a draft whose content came from somewhere else, under a fresh identity.
    ///
    /// This is what a lost synchronisation race produces: the content that won is kept *beside*
    /// the local draft rather than over it, because section 24 says reconnection never replaces the
    /// user's draft with remote input. The person chooses between them.
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
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
        self.write(&copy)?;
        Ok(copy)
    }

    /// Removes a draft.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::Storage`] when the file cannot be removed. Removing one that is not
    /// there succeeds: the caller asked for it to be gone and it is.
    pub fn remove(&self, draft_id: DraftId) -> Result<()> {
        let path = self.path_of(draft_id);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(storage(&path, error).into()),
        }
    }

    /// Returns the canonical bytes of a draft, which is what a synchronised copy is sealed from.
    ///
    /// # Errors
    ///
    /// Returns [`DraftError::TooLarge`] or [`DraftError::TooManyAttachments`] when the draft does
    /// not fit the contract.
    pub fn encode(draft: &Draft) -> Result<Vec<u8>> {
        if draft.attachments.len() > MAX_DRAFT_ATTACHMENTS {
            return Err(DraftError::TooManyAttachments {
                count: draft.attachments.len(),
                limit: MAX_DRAFT_ATTACHMENTS,
            }
            .into());
        }
        let bytes = kr_cbor::to_canonical_vec(draft)?;
        if bytes.len() > MAX_DRAFT_BYTES {
            return Err(DraftError::TooLarge {
                len: bytes.len(),
                limit: MAX_DRAFT_BYTES,
            }
            .into());
        }
        Ok(bytes)
    }

    /// Reads a draft from the bytes [`Self::encode`] produced.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Cbor`] when the bytes are not a draft this build reads.
    pub fn decode(bytes: &[u8]) -> Result<Draft> {
        Ok(kr_cbor::from_canonical_slice(
            bytes,
            &kr_cbor::Limits::DEFAULT.with_max_message_len(MAX_DRAFT_BYTES),
        )?)
    }

    fn write(&self, draft: &Draft) -> Result<()> {
        let bytes = Self::encode(draft)?;
        let path = self.path_of(draft.draft_id);
        write_atomically(&self.directory, &path, &bytes)
            .map_err(|source| storage(&path, source))?;
        Ok(())
    }

    fn path_of(&self, draft_id: DraftId) -> PathBuf {
        self.directory.join(format!("{draft_id}.{DRAFT_EXTENSION}"))
    }
}

fn decode(path: &Path, bytes: &[u8]) -> Result<Draft> {
    DraftStore::decode(bytes).map_err(|error| {
        DraftError::Corrupt {
            path: path.to_path_buf(),
            reason: error.to_string(),
        }
        .into()
    })
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

/// Creates a directory nothing but its owner can read, where the platform expresses that.
fn create_private_directory(directory: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        // Unsent text a person has written. A directory anything on the machine could read would
        // be one this store had no business creating.
        builder.mode(0o700);
    }
    builder.create(directory)
}

/// Writes a file whole or not at all.
///
/// The bytes go to a temporary name in the same directory, are flushed to the device, and are then
/// renamed over the target: a rename within one directory replaces the name in one step, so a
/// reader sees the old draft or the new one and never a half-written file. The directory entry is
/// flushed afterwards where the platform lets it be, so a crash cannot leave the name pointing at
/// nothing.
fn write_atomically(directory: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let temporary = directory.join(format!(
        ".{}.partial",
        kr_transport::random::fresh_uuid_v4().map_err(std::io::Error::other)?
    ));
    // A guard, so a failure part way through does not leave the temporary behind.
    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::create(&temporary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(bytes)?;
        file.sync_all()
    })();
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    #[cfg(unix)]
    {
        // A directory can be opened and flushed on Unix; on Windows it cannot, and the rename is
        // ordered by the filesystem itself.
        if let Ok(handle) = std::fs::File::open(directory) {
            let _ = handle.sync_all();
        }
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
/// Section 20: the service stores ciphertext and never holds the key. The sealing therefore
/// belongs to the device, and this is the seam: a client supplies its own, and nothing in this
/// module ever sees a key or decides what an object is encrypted with.
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
    /// The service accepted it, at this revision.
    Accepted {
        /// The revision the service now holds.
        revision: DraftRevision,
    },
    /// Another device had written first.
    ///
    /// The local draft is exactly as it was. What the service held is kept beside it under `copy`,
    /// for the person to choose from.
    Conflicted {
        /// The copy that was kept.
        copy: DraftId,
        /// The revision the service held.
        current_revision: DraftRevision,
    },
}

/// One device's synchronised half of its drafts.
///
/// The compare and swap is on the draft's own revision: a write of revision *n* expects the
/// service to be holding *n - 1*, and a device whose write is refused has been overtaken. Section
/// 20 keeps the loser rather than resolving it by whichever clock was further ahead, and section 24
/// adds the direction that matters on a device: what is kept is kept *beside* the local draft, so
/// reconnecting never replaces the person's text with what was on the service.
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

    /// Publishes a draft, under compare and swap on its revision.
    ///
    /// A refused comparison is not a failure: it is the answer that another device wrote first, and
    /// it brings that content down beside the local draft rather than over it. Every other refusal
    /// is returned as it came.
    ///
    /// # Errors
    ///
    /// Returns the service's refusal, [`DraftError::TooLarge`] when the draft does not fit the
    /// contract, and [`DraftError::Storage`] when a conflict copy cannot be written.
    pub async fn publish(
        &self,
        store: &DraftStore,
        draft: &Draft,
        now: TimestampMs,
    ) -> Result<Published> {
        let plaintext = DraftStore::encode(draft)?;
        let ciphertext = self.sealer.seal(&plaintext)?;
        let collection = draft_collection(draft.draft_id);
        // The revision this write replaces. A first publication expects nothing to be there, which
        // is generation zero.
        let expected = draft.revision.get().saturating_sub(1);
        match self
            .service
            .compare_exchange(&collection, expected, &ciphertext)
            .await
        {
            Ok(accepted) => Ok(Published::Accepted {
                revision: DraftRevision::new(accepted),
            }),
            Err(error) if error.code() == kr_protocol::error::ErrorCode::DraftConflict => {
                let remote = self.fetch_beside(store, draft.draft_id, now).await?;
                Ok(Published::Conflicted {
                    copy: remote.draft_id,
                    current_revision: remote.revision,
                })
            }
            Err(error) => Err(error),
        }
    }

    /// Brings down what the service holds for a draft, beside the local one.
    ///
    /// It never replaces. The content arrives under a fresh identity that names the draft it
    /// belongs beside, which is what keeps a reconnect from putting remote input where the person's
    /// text was. Section 24 makes that the rule rather than a preference.
    ///
    /// # Errors
    ///
    /// Returns the service's refusal, [`ClientError::Cbor`] when the object is not a draft this
    /// build reads, and [`DraftError::Storage`] when the copy cannot be written.
    pub async fn fetch_beside(
        &self,
        store: &DraftStore,
        draft_id: DraftId,
        now: TimestampMs,
    ) -> Result<Draft> {
        let ciphertext = self.service.fetch(&draft_collection(draft_id)).await?;
        let plaintext = self.sealer.open(&ciphertext)?;
        let remote = DraftStore::decode(&plaintext)?;
        store.keep_copy(draft_id, &remote, now)
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
        assert_eq!(store.list().expect("a listing").len(), 1);
    }

    #[test]
    fn the_directory_is_the_callers_and_is_created_owner_only() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        assert!(store.directory().is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(store.directory())
                .expect("the directory")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
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
        assert_eq!(store.list().expect("a listing").len(), 1);
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
    fn a_draft_larger_than_the_contract_carries_is_refused_rather_than_truncated() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = store(&directory);
        let error = store
            .create(
                open_target(),
                "x".repeat(MAX_DRAFT_BYTES + 1),
                TimestampMs::new(1),
            )
            .expect_err("too large");
        assert!(error.to_string().contains("limit"));
        assert!(store.list().expect("a listing").is_empty());
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
        assert_eq!(store.list().expect("a listing").len(), 2);
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
}
