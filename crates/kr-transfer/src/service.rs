//! The transfer service: uploads, attachment handles, drafts, read grants, recovery and sweeps.
//!
//! One service per environment. It owns `transfers.sqlite`, the private staging area and the
//! authorised directories every transfer resolves through. The methods are synchronous: they talk
//! to SQLite and to files, so a host on an asynchronous runtime performs them on a blocking task
//! rather than pretending the work is not there.
//!
//! The separations section 12 and section 14 require are structural here, not conventions.
//!
//! * [`TransferService::upload_finish`] publishes a handle. It does not touch a draft.
//! * [`TransferService::draft_add_attachment`] binds a handle to a draft and records that the
//!   adapter was asked. It does not submit anything, and a failed insertion leaves both the draft
//!   and the published attachment exactly where they were.
//! * Submission is [`TransferService::mark_submitted`], which only changes what retention applies.
//!   Acceptance by the agent is [`TransferService::record_insertion_outcome`] with upstream
//!   evidence, and nothing else sets it.

use std::path::Path;
use std::sync::{Arc, Mutex};

use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActorId, DraftId, DraftRevision, EnvironmentId, GrantId, TransferId};
use kr_protocol::scalars::{Bytes, Digest256, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::transfer::{
    AgentDraftAddAttachmentParams, AgentDraftAddAttachmentResult, AttachmentHandle,
    AttachmentPreview, AttachmentReadGrant, ChunkBitmap, ChunkLayout, DOWNLOAD_SNAPSHOT_LIFETIME,
    DraftAttachment, DraftCreateParams, DraftCreateResult, DraftRecord, DraftState,
    DraftUpdateParams, DraftUpdateResult, InsertionMethod, InsertionState, MAX_MEDIA_TYPE_LEN,
    MAX_ORIGINAL_FILE_NAME_LEN, UNFINISHED_UPLOAD_LIFETIME, UNUSED_ATTACHMENT_LIFETIME,
    UploadBeginParams, UploadBeginResult, UploadCancelParams, UploadCancelResult,
    UploadChunkParams, UploadChunkResult, UploadFinishParams, UploadFinishResult, UploadState,
    UploadStatusParams, UploadStatusResult,
};

use crate::authority::{AuthorisedDirectory, AuthorisedFile, ObjectPolicy, RelativeName};
use crate::clock::{Clock, SystemClock};
use crate::error::{Result, TransferError};
use crate::staging::{StagingArea, StorageName};
use crate::store::{
    ActionOutcome, ActionRecord, BindingRow, DraftRow, GrantRow, Limits, RetainedAction, ScopeRow,
    SnapshotState, Store, UploadRow,
};

/// How long a narrow read grant over one attachment lives.
///
/// Long enough for an adapter to hand the path to an agent and for the agent to open it; short
/// enough that a grant left behind stops naming anything.
pub const READ_GRANT_LIFETIME_MS: u64 = 15 * 60 * 1000;

/// How large a read is when the service walks a whole file.
const READ_BUFFER_LEN: usize = 256 * 1024;

/// What a host tells the sweep about a session's retention.
///
/// A submitted attachment follows its session's retention policy rather than the seven-day
/// unused-attachment window, and the transfer service is not the owner of that policy. The host
/// answers for its own sessions.
pub trait SessionRetention {
    /// Returns true while the session's retention still covers what was submitted to it.
    fn retains(&self, session_id: kr_protocol::ids::SessionId) -> bool;
}

/// A retention that keeps everything.
///
/// What a host uses before it has a retention policy to apply, and what the default sweep uses:
/// declining to delete is the answer that cannot lose a file.
#[derive(Clone, Copy, Debug, Default)]
pub struct RetainEverything;

impl SessionRetention for RetainEverything {
    fn retains(&self, _session_id: kr_protocol::ids::SessionId) -> bool {
        true
    }
}

/// What one expiry sweep did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sweep {
    /// Unfinished uploads that outlived the twenty-four-hour window.
    pub expired_uploads: usize,
    /// Published attachments whose retention has ended.
    pub expired_attachments: usize,
    /// Download snapshots that outlived their expiry.
    pub expired_snapshots: usize,
    /// Payloads of closed transfers that were still on disk and have now been removed.
    pub removed_payloads: usize,
    /// Payloads that still could not be removed. Their bytes stay charged.
    pub unremovable_payloads: usize,
    /// Action claims whose effect had settled and whose result is now recorded.
    pub resolved_claims: usize,
    /// De-duplication records older than the protocol's retention.
    pub forgotten_actions: usize,
}

/// What one recovery pass resolved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Recovery {
    /// Publications that were interrupted after verification and have now completed.
    pub completed_publications: usize,
    /// Publications whose payload is gone, or is no longer the bytes that were verified, and are
    /// now invalidated.
    pub unresolved_publications: usize,
    /// Action claims whose effect finished without their result being recorded.
    pub resolved_claims: usize,
    /// Snapshots whose construction an earlier daemon never finished, now failed and released.
    pub interrupted_snapshots: usize,
    /// Payloads of closed uploads that were still on disk and have now been removed.
    pub removed_payloads: usize,
    /// Payloads that still could not be removed. Their bytes stay charged and the next pass
    /// tries again.
    pub unremovable_payloads: usize,
    /// Payloads no row accounted for at all, removed by reconciliation.
    pub orphans_removed: usize,
}

/// What an adapter reports after it offers an attachment to an agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertionOutcome {
    /// The agent took it, and this is the upstream part or native binding that says so.
    AcceptedByAgent {
        /// The upstream evidence. Nothing else moves a binding to accepted.
        upstream_evidence: String,
    },
    /// The insertion failed. The draft and the completed upload are both retained.
    Failed {
        /// What went wrong, for the user.
        detail: String,
    },
}

/// The action one mutation is performed under.
///
/// A mutation whose idempotency is its action identifier commits this together with the state it
/// changes, in one transaction. A second attempt at the same action therefore finds the first
/// already recorded and changes nothing, whether it arrives after the reply was lost or beside it
/// on another connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    /// The actor performing it.
    pub actor_id: ActorId,
    /// The durable operation identity.
    pub action_id: Uuid,
    /// The method being performed.
    pub method: String,
    /// The digest of the payload it was submitted with.
    pub payload_digest: Digest256,
}

impl Action {
    /// Builds the row this action is retained as, with the result it produced.
    fn retained(&self, result: Vec<u8>, recorded_at_ms: TimestampMs) -> RetainedAction {
        RetainedAction {
            actor_id: self.actor_id.clone(),
            action_id: self.action_id,
            method: self.method.clone(),
            payload_digest: self.payload_digest,
            subject: None,
            result: Some(result),
            recorded_at_ms,
        }
    }

    /// Builds the row this action is claimed as, for an effect whose result comes later.
    ///
    /// A publication and a cancellation are each more than one step, and the claim belongs to the
    /// first: there is no handle to record yet, and no bytes have been released yet. The transfer
    /// it acts on is recorded with it, so an interrupted claim is resolvable from that transfer's
    /// own state. The result is filled in when the last step has happened.
    fn claimed_for(&self, transfer_id: TransferId, recorded_at_ms: TimestampMs) -> RetainedAction {
        RetainedAction {
            actor_id: self.actor_id.clone(),
            action_id: self.action_id,
            method: self.method.clone(),
            payload_digest: self.payload_digest,
            subject: Some(transfer_id),
            result: None,
            recorded_at_ms,
        }
    }
}

/// Reads one action's record through a journal lock the caller already holds.
///
/// The same three answers as [`TransferService::recorded`], for the callers that have to decide
/// under the lock their mutation holds rather than before it.
fn recorded_with<T: serde::de::DeserializeOwned + serde::Serialize>(
    store: &Store,
    action: Option<&Action>,
) -> Result<Recorded<T>> {
    let Some(action) = action else {
        return Ok(Recorded::Absent);
    };
    let Some(record) = store.retained_action(&action.actor_id, action.action_id)? else {
        return Ok(Recorded::Absent);
    };
    if record.method != action.method || record.payload_digest != action.payload_digest {
        return Err(TransferError::IdConflict {
            action: action.action_id.to_string(),
            method: record.method,
        });
    }
    match (record.result, record.error_code) {
        (Some(result), _) => Ok(Recorded::Answered(
            kr_cbor::from_canonical_slice(&result, &kr_cbor::Limits::DEFAULT)
                .map_err(TransferError::store)?,
        )),
        // The failure this action produced, under the code it produced. A repeat is owed what
        // happened, not a fresh refusal in a different category.
        (None, Some(code)) => Err(TransferError::Retained {
            code: code.parse().unwrap_or(ErrorCode::OutcomeUnknown),
            detail: record
                .error_detail
                .unwrap_or_else(|| format!("action {} was recorded as {code}", action.action_id)),
        }),
        (None, None) => Ok(Recorded::Claimed),
    }
}

/// The method name `upload.finish` is retained under.
const UPLOAD_FINISH: &str = "upload.finish";
/// The method name `upload.cancel` is retained under.
const UPLOAD_CANCEL: &str = "upload.cancel";

/// What a claim's outcome turned out to be.
enum Settled {
    /// The effect produced this encoded result.
    Result(Vec<u8>),
    /// The effect ended as this refusal.
    Failure(ErrorCode, String),
}

/// What this actor's record of one action says.
enum Recorded<T> {
    /// The action produced this answer, and every copy of it is owed the same one.
    Answered(T),
    /// The action has claimed its effect and its result is not recorded yet.
    Claimed,
    /// This actor has no record of the action.
    Absent,
}

/// What a re-read says about the bytes behind a payload whose identity was checked.
enum PayloadIntegrity {
    /// The bytes are the ones the publication recorded.
    Verified,
    /// The identity is the recorded one and the bytes are not. The detail says what was found.
    Altered(String),
}

impl PayloadIntegrity {
    /// Reads a payload back through the handle whose identity was already checked.
    ///
    /// Identity is the cheap first gate, and it answers one question: was this object replaced by
    /// one the filesystem gave a different identifier? It does not say the object was not rewritten
    /// in place, and on a filesystem that hands a new file the identifier a removal has just freed
    /// it does not say the object was not replaced either. The digest is what decides, and this is
    /// where it is compared.
    ///
    /// The handle is the one the identity was read from, so the bytes hashed here belong to the
    /// object that passed that gate rather than to whatever the name resolves to now.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StagingUnavailable`] when the read fails. A read that fails says
    /// nothing about the bytes, which is why it is not an answer about them.
    fn of(file: &mut AuthorisedFile, byte_len: u64, digest: Digest256) -> Result<Self> {
        let (found, length) = digest_of(file)?;
        if length != byte_len || found != digest {
            return Ok(Self::Altered(format!(
                "the payload is {length} bytes with a different digest, and the verification \
                 recorded {byte_len}: these are not the bytes that were verified"
            )));
        }
        Ok(Self::Verified)
    }
}

/// What a mutation names in its parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subject {
    /// A transfer.
    Transfer(TransferId),
    /// A draft.
    Draft(DraftId),
}

/// The subject a stored transfer or draft belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredSubject {
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The session it is bound to, when it has one.
    pub session_id: Option<kr_protocol::ids::SessionId>,
    /// The application it targets, when it has one.
    pub application_instance_id: Option<kr_protocol::ids::ApplicationInstanceId>,
}

/// A retained mutation outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetainedOutcome {
    /// The mutation succeeded, and this is the canonically encoded result it returned.
    Ok(Vec<u8>),
    /// The mutation failed, and this is the error it returned.
    Error {
        /// The stable protocol code.
        code: ErrorCode,
        /// The message.
        detail: String,
    },
}

/// The transfer service of one environment.
#[derive(Debug)]
pub struct TransferService {
    pub(crate) environment_id: EnvironmentId,
    pub(crate) store: Mutex<Store>,
    pub(crate) staging: StagingArea,
    /// Serialises the operations that move or remove a payload file.
    ///
    /// Publishing, resolving an interrupted publication, cancelling and sweeping all decide from
    /// which name holds a file and then act on it. Two of them at once could each see a different
    /// half of the other's work: one renames while the other looks at both names and concludes the
    /// file is gone. This is the boundary that stops that. It is always taken **before** the
    /// journal's lock and never after, which is what keeps the two from deadlocking.
    pub(crate) payloads: Mutex<()>,
    pub(crate) clock: Arc<dyn Clock>,
    /// Set to stage every snapshot by copying its bytes, even where the filesystem clones.
    pub(crate) copy_snapshots: std::sync::atomic::AtomicBool,
}

impl TransferService {
    /// Opens the service for an environment, creating its store and staging area on first use.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] or [`TransferError::StagingUnavailable`] when
    /// either cannot be prepared.
    pub fn open(paths: &EnvironmentPaths) -> Result<Self> {
        Self::with_clock(paths, Arc::new(SystemClock))
    }

    /// Opens the service against a clock the caller supplies.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] or [`TransferError::StagingUnavailable`] when
    /// either cannot be prepared.
    pub fn with_clock(paths: &EnvironmentPaths, clock: Arc<dyn Clock>) -> Result<Self> {
        let root = StagingArea::prepare_root(paths)?;
        let store = Store::open(StagingArea::store_path(paths), paths.environment_id())?;
        let staging_name = store.staging_name(&StagingArea::random_name(), Limits::default())?;
        let staging = StagingArea::open(&root, &staging_name)?;
        // The staging directory's own identity is recorded the first time it is opened and checked
        // every time after. A directory replaced at the same name is refused rather than used:
        // the name is not a secret, and what makes this area this environment's is the object.
        match store.staging_identity()? {
            Some(recorded) => staging.check_identity(recorded)?,
            None => store.set_staging_identity(staging.identity())?,
        }
        Ok(Self {
            environment_id: paths.environment_id(),
            store: Mutex::new(store),
            staging,
            payloads: Mutex::new(()),
            clock,
            copy_snapshots: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Stages every snapshot by copying its bytes, even where the filesystem offers a clone.
    ///
    /// The two ways of taking a snapshot make different promises, and the weaker one has to be
    /// reachable on a machine whose filesystem offers the stronger one: a qualification run that
    /// only ever clones never exercises what a copy has to prove about its source. Setting this
    /// asks for the copy. It changes nothing else, because a copy is what a filesystem without a
    /// clone does anyway.
    pub fn copy_snapshots(&self, on: bool) {
        self.copy_snapshots
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// Returns the environment this service owns.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Returns the staging area, for a caller that needs to name its directories.
    #[must_use]
    pub const fn staging(&self) -> &StagingArea {
        &self.staging
    }

    /// Returns the environment's configured limits.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the row cannot be read.
    pub fn limits(&self) -> Result<Limits> {
        self.locked()?.limits()
    }

    /// Replaces the environment's configured limits.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the row cannot be written.
    pub fn set_limits(&self, limits: Limits) -> Result<()> {
        self.locked()?.set_limits(limits)
    }

    /// Returns how many bytes this environment has staged.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the sums cannot be read.
    pub fn staged_byte_len(&self) -> Result<u64> {
        self.locked()?.staged_byte_len()
    }

    /// Registers a directory as an authorised read scope and returns its identity.
    ///
    /// The directory is opened once, here. Every read beneath it afterwards resolves through that
    /// handle, so a rename of the path never hands the scope an unrelated tree.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::Escape`] when the directory cannot be opened, or
    /// [`TransferError::StoreUnavailable`] when the row cannot be written.
    pub fn register_scope(&self, purpose: &str, root: &Path) -> Result<GrantId> {
        let directory = AuthorisedDirectory::open_root(self.environment_id, root)?;
        let scope_id = GrantId::new(kr_ipc::new_uuid());
        self.locked()?.register_scope(&ScopeRow {
            scope_id,
            environment_id: self.environment_id,
            root_path: directory.display_path().display().to_string(),
            root_identity: directory.identity(),
            purpose: purpose.to_owned(),
            revoked: false,
        })?;
        Ok(scope_id)
    }

    /// Revokes a read scope, which stops further bytes from every transfer opened through it.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the row cannot be written.
    pub fn revoke_scope(&self, scope_id: GrantId) -> Result<()> {
        self.locked()?.revoke_scope(scope_id)
    }

    /// Reserves an upload's declared size and returns its identity, layout and expiry.
    ///
    /// The payload file is created before the row that names it, and the directory that names the
    /// file is flushed before the row is committed, so a record never claims a file the storage
    /// has not made durable.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::WrongEnvironment`] for another environment,
    /// [`TransferError::InvalidArgument`] for a size or a declaration this service will not accept,
    /// [`TransferError::QuotaExceeded`] when the environment's staged bytes would exceed their
    /// limit, or [`TransferError::Concurrency`] when the caller already holds as many transfers as
    /// it may.
    pub fn upload_begin(
        &self,
        actor: &ActorId,
        params: &UploadBeginParams,
        action: Option<&Action>,
    ) -> Result<UploadBeginResult> {
        self.check_environment(params.environment_id)?;
        let declared = params.declared_byte_len.get();
        check_media_type(&params.declared_media_type)?;
        check_original_name(&params.original_file_name)?;
        let now = self.clock.now_ms();
        let transfer_id = TransferId::new(kr_ipc::new_uuid());
        let storage = StorageName::derive(transfer_id, &params.original_file_name);
        let expires_at_ms =
            TimestampMs::new(now.get().saturating_add(UNFINISHED_UPLOAD_LIFETIME.get()));
        let layout = ChunkLayout::for_length(declared);
        let mut store = self.locked()?;
        let limits = store.limits()?;
        if declared > limits.max_file_len {
            return Err(TransferError::QuotaExceeded {
                detail: format!(
                    "a file is at most {} bytes in this environment, and this one declares \
                     {declared}",
                    limits.max_file_len
                ),
            });
        }
        // These two refusals are the ones a first attempt at this same action could have caused:
        // it holds the transfer slot, and it charged the bytes. So they are answered from the
        // record when there is one, rather than telling a retry that its own reservation is in
        // the way.
        let open = store.open_transfers(actor)?;
        if open >= limits.max_concurrent_transfers {
            let refusal = TransferError::Concurrency {
                detail: format!(
                    "this device already holds {open} of {} concurrent transfers; finish or cancel \
                     one first",
                    limits.max_concurrent_transfers
                ),
            };
            drop(store);
            return self.refuse_unless_performed(action, refusal);
        }
        let staged = store.staged_byte_len()?;
        let after = staged.saturating_add(declared);
        if after > limits.max_staged_len {
            let refusal = TransferError::QuotaExceeded {
                detail: format!(
                    "this environment has {staged} of {} staged bytes, and {declared} more would \
                     exceed it",
                    limits.max_staged_len
                ),
            };
            drop(store);
            return self.refuse_unless_performed(action, refusal);
        }
        // The payload file exists before the row does, so a row can never name a file that was
        // refused, and the exclusive create is what proves the name was unused.
        let incomplete = storage.incomplete()?;
        let file = self.staging.incomplete().create_new(&incomplete)?;
        let payload_identity = file.identity();
        drop(file);
        self.staging.incomplete().sync()?;
        let result = UploadBeginResult {
            transfer_id,
            environment_id: params.environment_id,
            layout,
            received_chunks: ChunkBitmap::empty(layout.chunk_count.get()).encode(),
            expires_at_ms,
            staged_byte_len: U64::new(after),
            staged_byte_limit: U64::new(limits.max_staged_len),
        };
        let retained = match action {
            Some(action) => Some(action.retained(
                kr_cbor::to_canonical_vec(&result).map_err(TransferError::store)?,
                now,
            )),
            None => None,
        };
        let row = UploadRow {
            transfer_id,
            environment_id: params.environment_id,
            session_id: params.session_id.0,
            device_id: params.device_id.0,
            actor_id: actor.clone(),
            declared_byte_len: declared,
            declared_digest: params.declared_digest,
            declared_media_type: params.declared_media_type.clone(),
            original_file_name: params.original_file_name.clone(),
            stored_name: storage.published()?.as_str().to_owned(),
            state: UploadState::Receiving,
            invalid_reason: None,
            reserved_byte_len: declared,
            content_digest: None,
            payload_identity: Some(payload_identity),
            cleanup_pending: false,
            preview: None,
            preview_unavailable: None,
            created_at_ms: now,
            expires_at_ms,
            published_at_ms: None,
            submitted_at_ms: None,
        };
        match store.insert_upload(&row, retained.as_ref()) {
            // Another attempt at the same action won the transaction. Nothing was written, so the
            // file this attempt created goes with it and the caller is answered from the record.
            Ok(ActionOutcome::AlreadyPerformed) => {
                drop(store);
                let _ = self.staging.incomplete().remove(&incomplete);
                self.retained_result(action)
            }
            Ok(ActionOutcome::Committed) => Ok(result),
            Err(error) => {
                drop(store);
                // Nothing names the file yet, so the failed reservation takes it with it.
                let _ = self.staging.incomplete().remove(&incomplete);
                Err(error)
            }
        }
    }

    /// Reports an upload's verified chunk status, and its handle once it is published.
    ///
    /// This is how a lost reply to `upload.finish` is resolved: a published upload answers with
    /// the handle it already has, and no second file is created.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::UnknownTransfer`] when this principal has no such transfer. One
    /// another principal began is refused by the same answer, so a caller learns nothing about
    /// which identifiers exist.
    pub fn upload_status(
        &self,
        actor: &ActorId,
        params: &UploadStatusParams,
    ) -> Result<UploadStatusResult> {
        let store = self.locked()?;
        let row = upload_of(&store, params.transfer_id, actor)?;
        let layout = ChunkLayout::for_length(row.declared_byte_len);
        let chunks = store.chunks(params.transfer_id)?;
        let mut bitmap = ChunkBitmap::empty(layout.chunk_count.get());
        let mut received = 0_u64;
        for chunk in &chunks {
            bitmap.insert(chunk.index.get());
            received = received.saturating_add(chunk.byte_len.get());
        }
        let handle = if row.state == UploadState::Published {
            Nullable::some(handle_of(&row)?)
        } else {
            Nullable::null()
        };
        Ok(UploadStatusResult {
            transfer_id: row.transfer_id,
            environment_id: row.environment_id,
            state: row.state,
            layout,
            received_chunks: bitmap.encode(),
            received_byte_len: U64::new(received),
            expires_at_ms: row.expires_at_ms,
            handle,
            invalid_reason: Nullable(row.invalid_reason.clone()),
        })
    }

    /// Accepts one chunk, verifying its length and digest before anything is written.
    ///
    /// A duplicate that matches what was recorded is acknowledged and nothing is rewritten. A
    /// duplicate that conflicts invalidates the upload: two different byte sequences claimed the
    /// same position, and there is no honest way to choose.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::Integrity`] when the bytes do not match their own descriptor,
    /// [`TransferError::WrongState`] when the upload is not receiving, or
    /// [`TransferError::InvalidArgument`] for an index or a length the layout does not have.
    pub fn upload_chunk(
        &self,
        actor: &ActorId,
        params: &UploadChunkParams,
        action: Option<&Action>,
    ) -> Result<UploadChunkResult> {
        // Before anything is written or invalidated: a repeat of this action gets the answer it
        // already produced, and an identifier carrying a different payload is refused without
        // touching the upload.
        if let Recorded::Answered(answered) = self.recorded(action)? {
            return Ok(answered);
        }
        let index = params.chunk.index.get();
        let now = self.clock.now_ms();
        let mut store = self.locked()?;
        let row = upload_of(&store, params.transfer_id, actor)?;
        self.check_live(&mut store, &row, "a chunk cannot be accepted")?;
        let layout = ChunkLayout::for_length(row.declared_byte_len);
        let expected_len = layout.length_of(index).ok_or_else(|| {
            TransferError::invalid(format!(
                "this upload has {} chunks, so there is no chunk {index}",
                layout.chunk_count.get()
            ))
        })?;
        if params.chunk.byte_len.get() != expected_len {
            return Err(TransferError::invalid(format!(
                "chunk {index} of this upload is {expected_len} bytes, and the descriptor declares \
                 {}",
                params.chunk.byte_len.get()
            )));
        }
        if params.bytes.len() as u64 != expected_len {
            return Err(TransferError::invalid(format!(
                "chunk {index} of this upload is {expected_len} bytes, and {} arrived",
                params.bytes.len()
            )));
        }
        // The bytes are checked against their own descriptor first. A transmission fault is the
        // caller's to retry and leaves the upload alone.
        let digest = Digest256::from_bytes(kr_cbor::sha256(params.bytes.as_slice()));
        if digest != params.chunk.digest {
            return Err(TransferError::integrity(format!(
                "chunk {index} does not match the digest it declares"
            )));
        }
        // Read again, under the lock this mutation holds. The read before the lock keeps an
        // ordinary repeat from reaching this far; this one is what makes the decision atomic with
        // the write, so two copies that both saw nothing cannot both act.
        match recorded_with(&store, action)? {
            Recorded::Answered(answered) => return Ok(answered),
            Recorded::Claimed | Recorded::Absent => {}
        }
        let mut duplicate = false;
        if let Some(recorded) = store.chunk(params.transfer_id, index)? {
            if recorded.digest == digest && recorded.byte_len == params.chunk.byte_len {
                duplicate = true;
            } else {
                let reason = format!(
                    "chunk {index} arrived twice with different content, so this upload cannot be \
                     completed under the same identifier"
                );
                store.close_upload(
                    params.transfer_id,
                    UploadState::Invalidated,
                    Some(&reason),
                    now,
                    None,
                )?;
                drop(store);
                self.discard_payloads(&row)?;
                return Err(TransferError::integrity(reason));
            }
        }
        // The result is built before the transaction that commits it, because the transaction
        // carries the action this call is performed under: two copies of one action must not
        // commit two rows and then answer differently.
        let recorded = store.chunks(params.transfer_id)?;
        let mut bitmap = ChunkBitmap::empty(layout.chunk_count.get());
        let mut received = 0_u64;
        for chunk in &recorded {
            bitmap.insert(chunk.index.get());
            received = received.saturating_add(chunk.byte_len.get());
        }
        if !duplicate {
            bitmap.insert(index);
            received = received.saturating_add(expected_len);
        }
        let result = UploadChunkResult {
            transfer_id: params.transfer_id,
            index: params.chunk.index,
            duplicate,
            received_chunks: bitmap.encode(),
            received_byte_len: U64::new(received),
        };
        let retained = match action {
            Some(action) => Some(action.retained(
                kr_cbor::to_canonical_vec(&result).map_err(TransferError::store)?,
                now,
            )),
            None => None,
        };
        if !duplicate {
            let offset = layout.offset_of(index).unwrap_or_default();
            let mut file = self.open_incomplete(&row)?;
            write_at(&mut file, offset, params.bytes.as_slice())?;
        }
        // The journal row follows the bytes. A row with no bytes behind it would let the
        // verification trust a hole. The action is claimed in the same transaction as the row, so
        // a second copy of this action finds it claimed and answers from the record rather than
        // computing its own answer.
        match store.record_chunk(params.transfer_id, params.chunk, now, retained.as_ref())? {
            ActionOutcome::Committed => Ok(result),
            ActionOutcome::AlreadyPerformed => {
                drop(store);
                self.retained_result(action)
            }
        }
    }

    /// Verifies the whole file and publishes the attachment handle.
    ///
    /// The declared size and digest must be the ones `upload.begin` recorded: a client that has
    /// changed its mind about what it is sending needs a new upload identifier, because the
    /// reservation, the layout and every chunk already accepted belong to the first declaration.
    ///
    /// The publish is two commits with a recoverable state between them, and the identity of the
    /// verified object is what ties them together. The row records that identity and that digest
    /// before the file moves; the object is then opened, checked against the identity and read back
    /// against the digest, so a file that took the name in between is invalidated rather than
    /// published, and so is one rewritten where it lies.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::Integrity`] when the file does not verify,
    /// [`TransferError::SourceChanged`] when the declaration changed, or
    /// [`TransferError::WrongState`] when the upload cannot be finished.
    pub fn upload_finish(
        &self,
        actor: &ActorId,
        params: &UploadFinishParams,
        action: Option<&Action>,
    ) -> Result<UploadFinishResult> {
        let now = self.clock.now_ms();
        // The record first. A repeat of this action gets the answer it already produced, and an
        // identifier carrying a different payload is refused before anything is read or moved.
        if let Recorded::Answered(answered) = self.recorded(action)? {
            return Ok(answered);
        }
        // A published upload is answered before anything is read. This is the retry after a lost
        // reply, and it must never produce a second file. An interrupted publish is resolved here
        // too, so a caller does not have to wait for the next start to learn what happened.
        {
            let row = {
                let store = self.locked()?;
                upload_of(&store, params.transfer_id, actor)?
            };
            match row.state {
                UploadState::Published => {
                    check_declaration(&row, params)?;
                    // One read, one decision. The record can settle between two reads, and
                    // asking twice is how two copies of one action end up with two answers.
                    //
                    // Answered: that is the answer. Claimed: the claim is this action's and its
                    // publication is done, so this action published this attachment. Absent: this
                    // call found an attachment something else published.
                    let mine = match self.recorded(action)? {
                        Recorded::Answered(answered) => return Ok(answered),
                        Recorded::Claimed => true,
                        Recorded::Absent => false,
                    };
                    let result = UploadFinishResult {
                        handle: handle_of(&row)?,
                        already_published: !mine,
                        preview_unavailable: Nullable(row.preview_unavailable.clone()),
                    };
                    // A claim this action left without a result is completed here, so every copy
                    // of it and every later repeat are answered the same.
                    self.complete_claim(action, &result)?;
                    return Ok(result);
                }
                UploadState::Publishing => {
                    check_declaration(&row, params)?;
                    let payloads = self.payloads.lock().map_err(|_| poisoned())?;
                    // Read again under the lock that guards the payload. The state above was read
                    // before this lock, and a copy of this action, a cancellation or a sweep can
                    // have moved the row since. Resolving a publication from a state that is no
                    // longer there is how a payload another state now owns gets removed.
                    let publishing = {
                        let store = self.locked()?;
                        upload_of(&store, params.transfer_id, actor)?
                    };
                    if publishing.state == UploadState::Publishing {
                        self.resolve_publication(&publishing, now)?;
                    }
                    drop(payloads);
                    let store = self.locked()?;
                    let row = upload_of(&store, params.transfer_id, actor)?;
                    return match row.state {
                        UploadState::Published => {
                            let published_at = row.preview_unavailable.clone();
                            let handle = handle_of(&row)?;
                            drop(store);
                            let mine = match self.recorded(action)? {
                                Recorded::Answered(answered) => return Ok(answered),
                                Recorded::Claimed => true,
                                Recorded::Absent => false,
                            };
                            let result = UploadFinishResult {
                                handle,
                                already_published: !mine,
                                preview_unavailable: Nullable(published_at),
                            };
                            self.complete_claim(action, &result)?;
                            Ok(result)
                        }
                        _ => {
                            drop(store);
                            // The claim this publication was made under is answered with the
                            // refusal it ended in, so a copy that arrives before the next recovery
                            // pass is owed this answer rather than one for the state this action's
                            // own publication reached. Where the action was settled first, that
                            // answer is the one that comes back.
                            self.refuse_publication(action, publication_refusal(&row))
                        }
                    };
                }
                _ => {}
            }
        }
        let row = {
            let mut store = self.locked()?;
            let row = upload_of(&store, params.transfer_id, actor)?;
            // Another copy of this action can have published it while this one was reading the
            // state above. Under the lock, the record decides before the state does: a copy is
            // owed the answer its action produced, not a refusal for a state its own action
            // reached.
            if let Recorded::Answered(answered) = recorded_with(&store, action)? {
                return Ok(answered);
            }
            // An upload that has already ended will never publish, and that is this action's
            // answer: recorded on its own claim, so a copy of it, and the sweep that may be
            // resolving claims behind this call, cannot produce a second one. An invalidated row
            // answers with the reason it recorded; any other ended state answers as that state.
            if matches!(
                row.state,
                UploadState::Cancelled | UploadState::Invalidated | UploadState::Expired
            ) {
                drop(store);
                return self.refuse_publication(action, publication_refusal(&row));
            }
            self.check_live(&mut store, &row, "it cannot be finished")?;
            check_declaration(&row, params)?;
            let layout = ChunkLayout::for_length(row.declared_byte_len);
            let chunks = store.chunks(params.transfer_id)?;
            let mut bitmap = ChunkBitmap::empty(layout.chunk_count.get());
            for chunk in &chunks {
                bitmap.insert(chunk.index.get());
            }
            if !bitmap.is_complete() {
                let missing = bitmap.missing();
                return Err(TransferError::WrongState {
                    transfer: row.transfer_id.to_string(),
                    state: row.state.as_str(),
                    detail: format!(
                        "{} of {} chunks are still missing, the first being {}",
                        missing.len(),
                        layout.chunk_count.get(),
                        missing.first().copied().unwrap_or_default()
                    ),
                });
            }
            row
        };
        // The whole-file verification and the preview happen without the store lock: they read the
        // payload, which for a large file takes long enough that holding the journal would stop
        // every other transfer in this environment.
        let mut file = match self.open_incomplete(&row) {
            Ok(file) => file,
            // Another copy of this action can have moved the payload between the checks above and
            // this open. Its answer is this call's answer; anything else is the failure it is.
            Err(error) => {
                return match self.recorded(action)? {
                    Recorded::Answered(answered) => Ok(answered),
                    _ => Err(error),
                };
            }
        };
        let payload_identity = file.identity();
        let (digest, byte_len) = digest_of(&mut file)?;
        if byte_len != row.declared_byte_len || digest != row.declared_digest {
            let reason = if byte_len == row.declared_byte_len {
                "the staged file does not match the digest this upload declared".to_owned()
            } else {
                format!(
                    "the staged file is {byte_len} bytes and this upload declared {}",
                    row.declared_byte_len
                )
            };
            drop(file);
            let payloads = self.payloads.lock().map_err(|_| poisoned())?;
            // Conditional on the state this call read before it spent time verifying the file. A
            // cancellation that landed in between has already closed this transfer and removed
            // its payload, and that terminal state is not this failure's to overwrite.
            let moved = self.locked()?.close_upload_from(
                row.transfer_id,
                row.state,
                UploadState::Invalidated,
                Some(&reason),
                now,
            )?;
            if moved {
                self.discard_payloads(&row)?;
            }
            drop(payloads);
            return Err(TransferError::integrity(reason));
        }
        let (preview, preview_unavailable) =
            match crate::preview::generate(file.handle_mut(), &row.declared_media_type) {
                Ok(preview) => (Some(preview), None),
                Err(refusal) => (None, Some(refusal.to_string())),
            };
        let encoded_preview = match &preview {
            Some(preview) => {
                Some(kr_cbor::to_canonical_vec(preview).map_err(TransferError::store)?)
            }
            None => None,
        };
        // Taken before the journal's lock, and held over both commits, so a cancellation, a
        // sweep or a recovery cannot act on this payload between them.
        let payloads = self.payloads.lock().map_err(|_| poisoned())?;
        let mut store = self.locked()?;
        // Rechecked under the lock: a cancellation could have landed while the file was read.
        let row = upload_of(&store, params.transfer_id, actor)?;
        if row.state == UploadState::Published {
            // Published while this call was reading the file. The same one read, one decision
            // rule as the paths above: a claim of this action's means this action published it,
            // and no claim means this call found somebody else's attachment.
            let handle = handle_of(&row)?;
            let reason = row.preview_unavailable.clone();
            drop(store);
            drop(payloads);
            let mine = match self.recorded(action)? {
                Recorded::Answered(answered) => return Ok(answered),
                Recorded::Claimed => true,
                Recorded::Absent => false,
            };
            let result = UploadFinishResult {
                handle,
                already_published: !mine,
                preview_unavailable: Nullable(reason),
            };
            self.complete_claim(action, &result)?;
            return Ok(result);
        }
        if !row.state.accepts_chunks() {
            return Err(TransferError::WrongState {
                transfer: row.transfer_id.to_string(),
                state: row.state.as_str(),
                detail: "it cannot be finished".to_owned(),
            });
        }
        // The intent is durable before the file moves, and it carries the identity of the object
        // that was verified, so an interrupted publish is resolved from the record rather than
        // guessed at.
        // The action is claimed in the same transaction as the intent, which is the commit that
        // makes this publication this action's. It is claimed without a result, because the handle
        // does not exist until the second commit; the result is filled in below. A second copy of
        // this action finds the claim and resolves the same publication rather than starting
        // another one.
        let claim = action.map(|action| action.claimed_for(row.transfer_id, now));
        let claim_outcome = store.begin_publish(
            row.transfer_id,
            &crate::store::Publication {
                content_digest: digest,
                payload_identity,
                preview: encoded_preview.as_deref(),
                preview_unavailable: preview_unavailable.as_deref(),
            },
            now,
            claim.as_ref(),
        )?;
        drop(store);
        drop(file);
        if claim_outcome == ActionOutcome::AlreadyPerformed {
            // Another copy of this action owns this publication. This one moves nothing: the file
            // it verified belongs to the transfer that copy is publishing, which may not even be
            // this one. The answer is the record's, and a claim with no result yet means the
            // caller asks again.
            drop(payloads);
            return match self.recorded(action)? {
                Recorded::Answered(answered) => Ok(answered),
                _ => Err(TransferError::OutcomeUnknown {
                    action: action
                        .map(|action| action.action_id.to_string())
                        .unwrap_or_default(),
                }),
            };
        }
        let published = UploadRow {
            content_digest: Some(digest),
            payload_identity: Some(payload_identity),
            preview: encoded_preview,
            preview_unavailable: preview_unavailable.clone(),
            state: UploadState::Publishing,
            ..row
        };
        self.resolve_publication(&published, now)?;
        drop(payloads);
        let store = self.locked()?;
        let row = upload_of(&store, params.transfer_id, actor)?;
        drop(store);
        if row.state != UploadState::Published {
            // This call's own claim, answered with what became of the publication it recorded. A
            // claim left open would be filled by the next recovery pass, and until then a copy of
            // this action would be told the outcome is unknown or refused for a state this action
            // reached itself.
            return self.refuse_publication(action, publication_refusal(&row));
        }
        let result = UploadFinishResult {
            handle: handle_of(&row)?,
            already_published: false,
            preview_unavailable: Nullable(preview_unavailable.clone()),
        };
        // The claim carried no result, because the handle did not exist yet. It does now, so the
        // record is completed with it and a later repeat is answered with this handle rather than
        // told the outcome is unknown. Nothing replaces a result already recorded.
        self.complete_claim(action, &result)?;
        Ok(result)
    }

    /// Completes, or invalidates, one publication whose intent is already durable.
    ///
    /// Called by `upload.finish` for the publication it just recorded, by a retried finish, and by
    /// recovery at startup. All three answer the same question: which name holds the object whose
    /// identity the row recorded, and are its bytes the ones that were verified?
    ///
    /// * The published name holding those bytes means the move landed and only the row was behind.
    /// * The incomplete name holding them means the move did not land, and the verified bytes are
    ///   still there to move.
    /// * A name that holds the recorded identity over different bytes is a payload rewritten in
    ///   place, or a replacement on a filesystem that hands a new file the identifier a removal
    ///   has just freed. The digest decides, so the upload is invalidated: nothing publishes a
    ///   handle over bytes this service never verified.
    /// * Neither name holding it means no handle can name it either, so the upload is invalidated.
    ///
    /// Only a failure that says nothing about the payload is reported: the journal, the storage, or
    /// the staging directory no longer being the directory this service opened. Every answer about
    /// the payload itself leaves the row terminal and its payloads discarded, so recovery resolves
    /// the rows behind this one instead of stopping on it and finding the same payload again at
    /// every start.
    fn resolve_publication(&self, row: &UploadRow, now: TimestampMs) -> Result<()> {
        let identity = row.payload_identity.ok_or_else(|| {
            TransferError::store("a publication was recorded without the identity it verified")
        })?;
        let storage = StorageName::derive(row.transfer_id, &row.original_file_name);
        let published = storage.published()?;
        let incomplete = storage.incomplete()?;
        let expires_at_ms = TimestampMs::new(
            row.published_at_ms
                .unwrap_or(now)
                .get()
                .saturating_add(UNUSED_ATTACHMENT_LIFETIME.get()),
        );
        let verified = row.content_digest.ok_or_else(|| {
            TransferError::store("a publication was recorded without the digest it verified")
        })?;
        if let Some(mut file) = self.holds(self.staging.complete(), &published, identity)? {
            if let PayloadIntegrity::Altered(detail) =
                PayloadIntegrity::of(&mut file, row.declared_byte_len, verified)?
            {
                return self.abandon_publication(row, &detail, now);
            }
            // Flushed here too. A first attempt can have renamed and then failed before its own
            // flush, and this is the path that answers for it.
            self.staging.complete().sync()?;
            self.staging.incomplete().sync()?;
            self.locked()?
                .complete_publish(row.transfer_id, now, expires_at_ms)?;
            return Ok(());
        }
        if let Some(mut file) = self.holds(self.staging.incomplete(), &incomplete, identity)? {
            let integrity = PayloadIntegrity::of(&mut file, row.declared_byte_len, verified)?;
            // Closed before the move. The bytes have been read, the move belongs to the staging
            // area rather than to this handle, and the platforms do not agree on what is allowed
            // while one is held.
            drop(file);
            if let PayloadIntegrity::Altered(detail) = integrity {
                return self.abandon_publication(row, &detail, now);
            }
            self.staging.incomplete().rename_into(
                &incomplete,
                self.staging.complete(),
                &published,
            )?;
            // The name is durable before the record that depends on it. Without this the journal
            // could say `published` while the rename was still only in the page cache.
            self.staging.complete().sync()?;
            self.staging.incomplete().sync()?;
            if self
                .holds(self.staging.complete(), &published, identity)?
                .is_none()
            {
                // Something took the published name between the move and this read, so a handle
                // over that name would not name the bytes that were verified.
                return self.abandon_publication(
                    row,
                    "the published name does not hold the object that was verified",
                    now,
                );
            }
            self.locked()?
                .complete_publish(row.transfer_id, now, expires_at_ms)?;
            return Ok(());
        }
        // Only a row that is still publishing. A cancellation that closed this transfer and
        // removed its payload is the other explanation for finding neither name, and it is not an
        // integrity failure to be overwritten with one.
        self.abandon_publication(
            row,
            "the verified payload is not in the staging area, so no handle can name it",
            now,
        )
    }

    /// Invalidates a publication no handle can name, and discards whatever its names still hold.
    ///
    /// One exit for every publication that cannot be completed, so all of them leave the same
    /// state behind: a terminal row carrying the reason, neither name holding a payload, the bytes
    /// released, and nothing for the next recovery pass to find.
    ///
    /// The transition is conditional on the row still publishing, and the removal happens only
    /// when the transition did. A row something else has moved on belongs to that state, and so
    /// does its payload: a publication another copy of the same finish completed must not have its
    /// attachment removed, and a cancellation that already closed this transfer is not an integrity
    /// failure to be overwritten with one. Whatever such a state left to clean up is marked on its
    /// own row, which the cleanup retry in this same pass picks up.
    fn abandon_publication(&self, row: &UploadRow, detail: &str, now: TimestampMs) -> Result<()> {
        let invalidated = self.locked()?.close_upload_from(
            row.transfer_id,
            UploadState::Publishing,
            UploadState::Invalidated,
            Some(detail),
            now,
        )?;
        if !invalidated {
            return Ok(());
        }
        self.discard_payloads(row)
    }

    /// Returns the open object when `name` in `directory` is the one whose identity was recorded.
    ///
    /// Opened without following a link and checked through the handle, so a replacement the
    /// filesystem gave a different identifier reads as absent rather than as the verified file. The
    /// handle comes back with the answer, because the bytes behind it are what decides the
    /// publication and reopening the name would be a second resolution to race. A name that is not
    /// there is `None`; a storage failure is reported, because it says nothing about what is there.
    fn holds(
        &self,
        directory: &AuthorisedDirectory,
        name: &RelativeName,
        identity: crate::authority::ObjectIdentity,
    ) -> Result<Option<AuthorisedFile>> {
        match directory.open_read(name, ObjectPolicy::HostOwnedFile) {
            Ok(file) => Ok((file.identity() == identity).then_some(file)),
            Err(crate::authority::Escape::NotFound { .. }) => Ok(None),
            // A link or the wrong kind of object has taken the name. It is not the verified file,
            // and saying so is what lets the caller look at the other name.
            Err(
                crate::authority::Escape::Link { .. } | crate::authority::Escape::WrongKind { .. },
            ) => Ok(None),
            Err(error) => Err(TransferError::from(error)),
        }
    }

    /// Removes whichever payload names a closed upload may still hold, and releases its bytes.
    ///
    /// The reservation is released only when the payload is gone, so a removal that fails leaves
    /// the row marked for cleanup and the bytes charged. Recovery retries it.
    fn discard_payloads(&self, row: &UploadRow) -> Result<()> {
        let storage = StorageName::derive(row.transfer_id, &row.original_file_name);
        self.staging.incomplete().remove(&storage.incomplete()?)?;
        self.staging.complete().remove(&storage.published()?)?;
        // The removals are durable before the charge is released. Without this a power loss could
        // bring a name back after SQLite had already forgotten it was spending bytes.
        self.staging.incomplete().sync()?;
        self.staging.complete().sync()?;
        self.locked()?.release_payload(row.transfer_id)
    }

    /// Cancels an unfinished upload and releases its reservation.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::UnknownTransfer`] when nothing is named, or
    /// [`TransferError::WrongState`] when the upload is already published.
    pub fn upload_cancel(
        &self,
        actor: &ActorId,
        params: &UploadCancelParams,
        action: Option<&Action>,
    ) -> Result<UploadCancelResult> {
        // The record first, so a repeat neither closes a row again nor removes a payload twice.
        if let Recorded::Answered(answered) = self.recorded(action)? {
            return Ok(answered);
        }
        let now = self.clock.now_ms();
        // Before the journal's lock, and held across the removal: a cancellation and a publish
        // are the two things that move the same payload, and this is what keeps them apart.
        let payloads = self.payloads.lock().map_err(|_| poisoned())?;
        let mut store = self.locked()?;
        let row = upload_of(&store, params.transfer_id, actor)?;
        match row.state {
            UploadState::Published => {
                return Err(TransferError::WrongState {
                    transfer: row.transfer_id.to_string(),
                    state: row.state.as_str(),
                    detail: "a published attachment is removed by its retention, not cancelled"
                        .to_owned(),
                });
            }
            // Cancelling something already closed is the same answer twice, which is what a
            // repeated cancellation has to be. When this call carries an action that closed it,
            // the answer is the one that action recorded: a copy of the winning cancellation must
            // not be told that it released nothing.
            UploadState::Cancelled | UploadState::Invalidated | UploadState::Expired => {
                drop(store);
                // One read, three answers. Answered: that is the answer, whoever produced it.
                // Claimed: this action closed the row and its removal may not have finished, so
                // any copy of it finishes that and records what it released. Absent: this call
                // found a transfer something else had closed, and released nothing.
                match self.recorded(action)? {
                    Recorded::Answered(answered) => {
                        drop(payloads);
                        return Ok(answered);
                    }
                    Recorded::Claimed => {
                        self.discard_payloads(&row)?;
                        drop(payloads);
                        let result = UploadCancelResult {
                            transfer_id: row.transfer_id,
                            state: UploadState::Cancelled,
                            // The reservation this upload made, which is its declared size. The
                            // row's own reserved field is zeroed by the release, so a copy that
                            // reads the row after another copy released it must not take the
                            // answer from there.
                            released_byte_len: U64::new(row.declared_byte_len),
                        };
                        self.complete_claim(action, &result)?;
                        return Ok(result);
                    }
                    Recorded::Absent => {
                        drop(payloads);
                        return Ok(UploadCancelResult {
                            transfer_id: row.transfer_id,
                            state: row.state,
                            released_byte_len: U64::ZERO,
                        });
                    }
                }
            }
            UploadState::Receiving | UploadState::Publishing => {}
        }
        // The action is claimed in the same transaction as the close, and claimed *without* a
        // result: the bytes are not released until the payload is gone, and a reply that said they
        // were would be wrong. The result is recorded once the release has actually happened.
        let claim = action.map(|action| action.claimed_for(row.transfer_id, now));
        let outcome = store.close_upload(
            row.transfer_id,
            UploadState::Cancelled,
            None,
            now,
            claim.as_ref(),
        )?;
        drop(store);
        if outcome == ActionOutcome::AlreadyPerformed {
            // Another copy of this action closed it. That copy owns the payload removal and the
            // answer both callers get; a claim with no result yet means this caller asks again.
            drop(payloads);
            return match self.recorded(action)? {
                Recorded::Answered(answered) => Ok(answered),
                _ => Err(TransferError::OutcomeUnknown {
                    action: action
                        .map(|action| action.action_id.to_string())
                        .unwrap_or_default(),
                }),
            };
        }
        // Both names, because a cancellation can arrive on an upload whose publish had already
        // moved the file. The reservation is released only once the payload is gone.
        self.discard_payloads(&row)?;
        drop(payloads);
        let result = UploadCancelResult {
            transfer_id: row.transfer_id,
            state: UploadState::Cancelled,
            released_byte_len: U64::new(row.declared_byte_len),
        };
        // Recorded now, because now it is true.
        self.complete_claim(action, &result)?;
        Ok(result)
    }

    /// Returns one published attachment's handle, for the principal that owns it.
    ///
    /// The actor is not optional. A handle names bytes, and a principal that did not upload them
    /// has no claim on them: a transfer identifier is opaque, but it is not a credential.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::UnknownTransfer`] when nothing this principal owns is named, or
    /// [`TransferError::WrongState`] when the upload is not published.
    pub fn attachment_handle(
        &self,
        actor: &ActorId,
        transfer_id: TransferId,
    ) -> Result<AttachmentHandle> {
        let store = self.locked()?;
        let row = upload_of(&store, transfer_id, actor)?;
        self.check_environment(row.environment_id)?;
        if row.state != UploadState::Published {
            return Err(TransferError::WrongState {
                transfer: transfer_id.to_string(),
                state: row.state.as_str(),
                detail: "there is no attachment handle until an upload is published".to_owned(),
            });
        }
        handle_of(&row)
    }

    /// Returns the session and application a stored transfer or draft belongs to.
    ///
    /// A mutation's envelope names its subject and its parameters name the transfer or the draft.
    /// Neither one proves the other, so a host that has to check the two agree needs the stored
    /// subject, which is what this is. A subject nothing this principal owns is named for is
    /// refused the same way every other unknown identifier is.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::UnknownTransfer`] or [`TransferError::UnknownDraft`] when nothing
    /// this principal owns is named.
    pub fn stored_subject(&self, actor: &ActorId, subject: Subject) -> Result<StoredSubject> {
        let store = self.locked()?;
        match subject {
            Subject::Transfer(transfer_id) => {
                let row = upload_of(&store, transfer_id, actor)?;
                Ok(StoredSubject {
                    environment_id: row.environment_id,
                    session_id: row.session_id,
                    application_instance_id: None,
                })
            }
            Subject::Draft(draft_id) => {
                let row = draft_of(&store, draft_id, actor)?;
                Ok(StoredSubject {
                    environment_id: row.environment_id,
                    session_id: row.session_id,
                    application_instance_id: row.application_instance_id,
                })
            }
        }
    }

    /// Creates a durable draft.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::WrongEnvironment`] for another environment, or
    /// [`TransferError::StoreUnavailable`] when the write fails.
    pub fn draft_create(
        &self,
        actor: &ActorId,
        params: &DraftCreateParams,
        action: Option<&Action>,
    ) -> Result<DraftCreateResult> {
        self.check_environment(params.environment_id)?;
        let now = self.clock.now_ms();
        let draft_id = DraftId::new(kr_ipc::new_uuid());
        let row = DraftRow {
            draft_id,
            environment_id: params.environment_id,
            actor_id: actor.clone(),
            device_id: params.device_id.0,
            session_id: params.session_id.0,
            application_instance_id: params.application_instance_id.0,
            revision: DraftRevision::new(1),
            state: DraftState::Open,
            text: params.text.clone(),
            created_at_ms: now,
            updated_at_ms: now,
        };
        let result = DraftCreateResult {
            draft: self.draft_record(&row, &[])?,
        };
        check_result_size(&result, "this draft")?;
        let retained = match action {
            Some(action) => Some(action.retained(
                kr_cbor::to_canonical_vec(&result).map_err(TransferError::store)?,
                now,
            )),
            None => None,
        };
        let outcome = self.locked()?.insert_draft(&row, retained.as_ref())?;
        match outcome {
            // The guard above is dropped with the statement, so reading the retained record does
            // not take the same lock twice.
            ActionOutcome::AlreadyPerformed => self.retained_result(action),
            ActionOutcome::Committed => Ok(result),
        }
    }

    /// Replaces a draft's text at its exact revision.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::DraftConflict`] when the expected revision is not current.
    pub fn draft_update(
        &self,
        actor: &ActorId,
        params: &DraftUpdateParams,
        action: Option<&Action>,
    ) -> Result<DraftUpdateResult> {
        let now = self.clock.now_ms();
        let mut store = self.locked()?;
        let row = draft_of(&store, params.draft_id, actor)?;
        self.check_environment(row.environment_id)?;
        if row.revision != params.expected_revision {
            // The revision this update expects can be one its own first attempt moved past, so
            // the record answers before the conflict does.
            let refusal = TransferError::DraftConflict {
                detail: format!(
                    "this draft is at revision {} and the update expects {}",
                    row.revision.get(),
                    params.expected_revision.get()
                ),
            };
            drop(store);
            return self.refuse_unless_performed(action, refusal);
        }
        // The result is built before the transaction, because the transaction commits it beside
        // the state it changes.
        let bindings = store.bindings(params.draft_id)?;
        let handles = self.handles_of(&store, &bindings)?;
        let updated = DraftRow {
            revision: DraftRevision::new(params.expected_revision.get().saturating_add(1)),
            text: params.text.clone(),
            updated_at_ms: now,
            ..row
        };
        let result = DraftUpdateResult {
            draft: self.compose_draft(&updated, &bindings, &handles)?,
        };
        check_result_size(&result, "this draft")?;
        let retained = match action {
            Some(action) => Some(action.retained(
                kr_cbor::to_canonical_vec(&result).map_err(TransferError::store)?,
                now,
            )),
            None => None,
        };
        match store.update_draft(
            params.draft_id,
            params.expected_revision,
            &params.text,
            now,
            retained.as_ref(),
        )? {
            Some(_) => Ok(result),
            None => {
                drop(store);
                // Either the revision moved between the read and the write, or this action had
                // already been performed. The record says which.
                match self.retained_result(action) {
                    Ok(retained) => Ok(retained),
                    Err(_) => Err(TransferError::DraftConflict {
                        detail: "this draft's revision moved while the update was written"
                            .to_owned(),
                    }),
                }
            }
        }
    }

    /// Binds a completed attachment to a draft and records that the adapter was asked.
    ///
    /// This is the whole of what the transfer service does about insertion. The binding starts at
    /// [`InsertionState::Recorded`], which says an adapter was asked and nothing more; the agent
    /// has accepted nothing until [`Self::record_insertion_outcome`] is given upstream evidence.
    /// Nothing here submits a prompt.
    ///
    /// The attachment and the draft must both belong to the caller, and where both name a session
    /// it must be the same one: an attachment bound to one session would otherwise be retained
    /// against it while a draft for another session held it.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::DraftConflict`] for a stale revision,
    /// [`TransferError::WrongState`] when the attachment is not published, and
    /// [`TransferError::InvalidArgument`] when the declared contribution does not admit it.
    pub fn draft_add_attachment(
        &self,
        actor: &ActorId,
        params: &AgentDraftAddAttachmentParams,
        action: Option<&Action>,
    ) -> Result<AgentDraftAddAttachmentResult> {
        let now = self.clock.now_ms();
        let mut store = self.locked()?;
        let row = draft_of(&store, params.draft_id, actor)?;
        self.check_environment(row.environment_id)?;
        // The attachment is loaded under the same lock as the binding, through the same
        // actor-authorised lookup the upload methods use.
        let upload = upload_of(&store, params.transfer_id, actor)?;
        self.check_environment(upload.environment_id)?;
        if upload.state != UploadState::Published {
            return Err(TransferError::WrongState {
                transfer: params.transfer_id.to_string(),
                state: upload.state.as_str(),
                detail: "only a published attachment can be bound to a draft".to_owned(),
            });
        }
        if let (Some(attachment_session), Some(draft_session)) = (upload.session_id, row.session_id)
            && attachment_session != draft_session
        {
            return Err(TransferError::invalid(format!(
                "this attachment belongs to session {attachment_session} and the draft targets \
                 {draft_session}"
            )));
        }
        let handle = handle_of(&upload)?;
        check_contribution(&params.contribution, &handle)?;
        let existing = store.bindings(params.draft_id)?;
        if existing.len() as u64 >= params.contribution.max_count.get()
            && !existing
                .iter()
                .any(|binding| binding.transfer_id == params.transfer_id)
        {
            return Err(TransferError::invalid(format!(
                "this operation accepts {} attachments and the draft already holds {}",
                params.contribution.max_count.get(),
                existing.len()
            )));
        }
        if row.revision != params.expected_revision {
            // As for an update: a binding's own first attempt is one explanation for the revision
            // having moved, and one action answers once.
            let refusal = TransferError::DraftConflict {
                detail: format!(
                    "this draft is at revision {} and the binding expects {}",
                    row.revision.get(),
                    params.expected_revision.get()
                ),
            };
            drop(store);
            return self.refuse_unless_performed(action, refusal);
        }
        // A method that needs the agent to open the file gets a narrow read grant over that one
        // file, inside the staging area and outside every repository. A typed submission needs no
        // path at all and is given none.
        let grant = if params.contribution.insertion_method.needs_read_grant() {
            Some(self.read_grant_for(&handle, params.contribution.insertion_method, now)?)
        } else {
            None
        };
        // An attachment with no session of its own becomes the draft's when it is bound, in the
        // same transaction as the binding.
        let session_for_attachment = upload
            .session_id
            .is_none()
            .then_some(row.session_id)
            .flatten();
        let ordinal = existing
            .iter()
            .map(|binding| binding.ordinal)
            .max()
            .unwrap_or(-1)
            .saturating_add(1);
        let binding = BindingRow {
            draft_id: params.draft_id,
            transfer_id: params.transfer_id,
            insertion_method: params.contribution.insertion_method,
            state: InsertionState::Recorded,
            upstream_evidence: None,
            failure_detail: None,
            grant_id: grant.as_ref().map(|grant| grant.grant_id),
            // Recorded with the binding, so the draft still discloses where the bytes go once the
            // call that declared it has returned.
            external_destination: params.contribution.external_destination.0.clone(),
            bound_at_ms: now,
            ordinal,
        };
        let updated = DraftRow {
            revision: DraftRevision::new(params.expected_revision.get().saturating_add(1)),
            updated_at_ms: now,
            ..row
        };
        let mut bindings = existing
            .into_iter()
            .filter(|held| held.transfer_id != params.transfer_id)
            .collect::<Vec<_>>();
        bindings.push(binding.clone());
        bindings.sort_by_key(|held| held.ordinal);
        let mut handles = self.handles_of(&store, &bindings)?;
        let position = bindings
            .iter()
            .position(|held| held.transfer_id == params.transfer_id);
        // Neither the session this binding assigns nor the grant it carries is in the store yet,
        // so the reply names both from the rows that are about to be committed with it. Otherwise
        // the first reply would say the attachment belongs to no session while the committed row
        // says it belongs to the draft's, and the retained reply would keep that wrong value.
        if let Some(session_id) = session_for_attachment
            && let Some(slot) = position.and_then(|position| handles.get_mut(position))
        {
            slot.0.session_id = Nullable::some(session_id);
        }
        if let Some(grant) = &grant
            && let Some(slot) = position.and_then(|position| handles.get_mut(position))
        {
            slot.1 = Some(AttachmentReadGrant {
                grant_id: grant.grant_id,
                environment_id: grant.environment_id,
                transfer_id: grant.transfer_id,
                insertion_method: grant.insertion_method,
                host_path: grant.host_path.clone(),
                expires_at_ms: grant.expires_at_ms,
            });
        }
        let draft = self.compose_draft(&updated, &bindings, &handles)?;
        let attachment = draft
            .attachments
            .iter()
            .find(|attachment| attachment.handle.transfer_id == params.transfer_id)
            .cloned()
            .ok_or_else(|| TransferError::store("the binding that was written is not readable"))?;
        let result = AgentDraftAddAttachmentResult { draft, attachment };
        check_result_size(&result, "this draft with the attachment bound to it")?;
        let retained = match action {
            Some(action) => Some(action.retained(
                kr_cbor::to_canonical_vec(&result).map_err(TransferError::store)?,
                now,
            )),
            None => None,
        };
        match store.bind_attachment(
            &binding,
            params.expected_revision,
            grant.as_ref(),
            retained.as_ref(),
            session_for_attachment,
        )? {
            Some(_) => Ok(result),
            None => {
                drop(store);
                match self.retained_result(action) {
                    Ok(retained) => Ok(retained),
                    Err(_) => Err(TransferError::DraftConflict {
                        detail: "this draft's revision moved while the binding was written"
                            .to_owned(),
                    }),
                }
            }
        }
    }

    /// Records what an adapter reported about one binding.
    ///
    /// A failure keeps the draft and the completed upload. Acceptance requires upstream evidence,
    /// which is what this records; nothing infers it from a call that returned.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::UnknownDraft`] when nothing is named, or
    /// [`TransferError::InvalidArgument`] when the attachment is not bound to that draft.
    pub fn record_insertion_outcome(
        &self,
        actor: &ActorId,
        draft_id: DraftId,
        transfer_id: TransferId,
        outcome: &InsertionOutcome,
    ) -> Result<DraftAttachment> {
        let now = self.clock.now_ms();
        let mut store = self.locked()?;
        let row = draft_of(&store, draft_id, actor)?;
        let existing = store
            .bindings(draft_id)?
            .into_iter()
            .find(|binding| binding.transfer_id == transfer_id)
            .ok_or_else(|| {
                TransferError::invalid(format!("{transfer_id} is not bound to this draft"))
            })?;
        check_insertion_detail(outcome)?;
        let binding = match outcome {
            InsertionOutcome::AcceptedByAgent { upstream_evidence } => {
                if upstream_evidence.trim().is_empty() {
                    return Err(TransferError::invalid(
                        "acceptance by an agent is recorded only with the upstream evidence for it",
                    ));
                }
                BindingRow {
                    state: InsertionState::AcceptedByAgent,
                    upstream_evidence: Some(upstream_evidence.clone()),
                    failure_detail: None,
                    bound_at_ms: now,
                    ..existing
                }
            }
            InsertionOutcome::Failed { detail } => BindingRow {
                state: InsertionState::Failed,
                upstream_evidence: None,
                failure_detail: Some(detail.clone()),
                bound_at_ms: now,
                ..existing
            },
        };
        // The draft this outcome produces has to fit the frame that carries it, and an outcome
        // adds text to it. So the whole draft is composed and measured before the outcome commits,
        // the same way an update and a binding are.
        {
            let mut prospective = store.bindings(draft_id)?;
            for held in &mut prospective {
                if held.transfer_id == transfer_id {
                    *held = binding.clone();
                }
            }
            let handles = self.handles_of(&store, &prospective)?;
            let updated = DraftRow {
                revision: DraftRevision::new(row.revision.get().saturating_add(1)),
                updated_at_ms: now,
                ..row.clone()
            };
            let composed = self.compose_draft(&updated, &prospective, &handles)?;
            check_result_size(&composed, "this draft with the outcome recorded on it")?;
        }
        store
            // The insertion outcome changes the binding's state and nothing about which session
            // owns the attachment.
            .bind_attachment(&binding, row.revision, None, None, None)?
            .ok_or_else(|| TransferError::store("the draft's revision moved during this record"))?;
        let bindings = store.bindings(draft_id)?;
        let handles = self.handles_of(&store, &bindings)?;
        drop(store);
        let updated = DraftRow {
            revision: DraftRevision::new(row.revision.get().saturating_add(1)),
            updated_at_ms: now,
            ..row
        };
        self.compose_draft(&updated, &bindings, &handles)?
            .attachments
            .into_iter()
            .find(|attachment| attachment.handle.transfer_id == transfer_id)
            .ok_or_else(|| TransferError::store("the binding that was written is not readable"))
    }

    /// Records that a draft was submitted, which is what moves its attachments onto the session's
    /// retention.
    ///
    /// Submission itself is a separate action performed elsewhere: this records its consequence for
    /// storage and nothing else.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::UnknownDraft`] when nothing is named.
    pub fn mark_submitted(&self, actor: &ActorId, draft_id: DraftId) -> Result<usize> {
        let now = self.clock.now_ms();
        let mut store = self.locked()?;
        let row = draft_of(&store, draft_id, actor)?;
        let bindings = store.bindings(draft_id)?;
        for binding in &bindings {
            // An attachment uploaded without a session takes the draft's when it is submitted to
            // one. Without that its retention would stay the seven-day window while the session
            // was the thing actually holding it.
            store.mark_submitted(binding.transfer_id, now, row.session_id)?;
        }
        Ok(bindings.len())
    }

    /// Returns one draft with its bindings.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::UnknownDraft`] when nothing is named.
    pub fn draft(&self, actor: &ActorId, draft_id: DraftId) -> Result<DraftRecord> {
        let store = self.locked()?;
        let row = draft_of(&store, draft_id, actor)?;
        let bindings = store.bindings(draft_id)?;
        let handles = self.handles_of(&store, &bindings)?;
        drop(store);
        let record = self.compose_draft(&row, &bindings, &handles)?;
        // The same budget a mutation is held to. A record too large to send is refused with the
        // reason rather than turned into a frame the connection cannot carry.
        check_result_size(&record, "this draft")?;
        Ok(record)
    }

    /// Returns one narrow read grant, refusing a revoked or expired one.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::PermissionDenied`] when the grant is unknown, revoked or expired.
    pub fn read_grant(&self, grant_id: GrantId) -> Result<AttachmentReadGrant> {
        let store = self.locked()?;
        let row = store
            .grant(grant_id)?
            .ok_or_else(|| TransferError::PermissionDenied {
                detail: format!("{grant_id} is not a read grant this environment issued"),
            })?;
        self.check_environment(row.environment_id)?;
        if row.revoked {
            return Err(TransferError::PermissionDenied {
                detail: format!("read grant {grant_id} has been revoked"),
            });
        }
        if row.expires_at_ms.get() <= self.clock.now_ms().get() {
            return Err(TransferError::PermissionDenied {
                detail: format!("read grant {grant_id} has expired"),
            });
        }
        Ok(AttachmentReadGrant {
            grant_id: row.grant_id,
            environment_id: row.environment_id,
            transfer_id: row.transfer_id,
            insertion_method: row.insertion_method,
            host_path: row.host_path,
            expires_at_ms: row.expires_at_ms,
        })
    }

    /// Resolves everything an earlier daemon left unfinished.
    ///
    /// Two jobs, both idempotent.
    ///
    /// A publication interrupted between its two commits is resolved from the identity the row
    /// recorded and the digest it verified: whichever name holds that object says what happened,
    /// and the digest says whether its bytes are still the ones that were verified. A row whose
    /// object is in neither place, or whose bytes are no longer those, is invalidated, because no
    /// handle can name it. Neither of those stops the pass: the row ends invalidated and the rows
    /// behind it are resolved in the same pass. A storage or journal failure still does stop it,
    /// because it says nothing about what the staging area holds.
    ///
    /// A payload whose upload is closed but whose bytes are still on disk is removed, and only then
    /// is its reservation released. That is the other half of the cleanup contract: a removal that
    /// failed, or a daemon that died between the row and the unlink, leaves bytes charged and a row
    /// marked, and this is what retries it.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the journal cannot be read or written.
    pub fn recover(&self) -> Result<Recovery> {
        let now = self.clock.now_ms();
        let payloads = self.payloads.lock().map_err(|_| poisoned())?;
        let mut recovery = Recovery::default();
        let pending = self.locked()?.uploads_in(&[UploadState::Publishing])?;
        for row in pending {
            self.resolve_publication(&row, now)?;
            let resolved = self.locked()?.upload(row.transfer_id)?;
            match resolved.map(|row| row.state) {
                Some(UploadState::Published) => recovery.completed_publications += 1,
                _ => recovery.unresolved_publications += 1,
            }
        }
        // Nothing here yet: claims are resolved below, after the cleanup they depend on.
        // A snapshot whose construction was interrupted is a reservation with no caller behind
        // it: nothing will ever open it, and its bytes and its transfer slot stay charged until
        // something closes it. Nothing is being staged yet at this point, so every reserving row
        // found here is one an earlier daemon left.
        let reserving = self
            .locked()?
            .snapshots_in(crate::store::SnapshotState::Reserving)?;
        for row in reserving {
            self.release_snapshot_held(
                &row,
                crate::store::SnapshotState::Failed,
                Some("this snapshot was still being staged when its daemon ended"),
                now,
            )?;
            recovery.interrupted_snapshots += 1;
        }
        let (removed, unremovable) = self.retry_cleanup()?;
        recovery.removed_payloads = removed;
        recovery.unremovable_payloads = unremovable;
        recovery.orphans_removed = self.reconcile_orphans()?;
        // After the cleanup, because a cancellation's answer is true only once its payload is gone.
        // A claim with no result is a two-commit effect that was interrupted between its commits;
        // a repeat completes it from the row too, and this is what settles one whose caller never
        // comes back.
        recovery.resolved_claims = self.resolve_claims()?;
        drop(payloads);
        Ok(recovery)
    }

    /// Completes every action claim whose effect has since settled.
    ///
    /// A claim with no result is a two-commit effect that was interrupted between its commits. The
    /// transfer it names has a state now, and that state is the answer: published means the handle,
    /// and anything terminal means the refusal the repeat would have been given.
    fn resolve_claims(&self) -> Result<usize> {
        let claims = self.locked()?.unfinished_claims()?;
        let mut resolved = 0;
        for claim in claims {
            let Some(transfer_id) = claim.transfer else {
                continue;
            };
            let Some(row) = self.locked()?.upload(transfer_id)? else {
                continue;
            };
            // The method decides the shape of the answer. A claim made for a finish is never
            // completed with a cancellation's result, whatever became of the transfer, because a
            // caller decodes the reply as the shape its own method returns.
            let settled = match (claim.method.as_str(), row.state) {
                (UPLOAD_FINISH, UploadState::Published) => {
                    let result = UploadFinishResult {
                        handle: handle_of(&row)?,
                        // This claim is what published it, which is what the live paths record.
                        already_published: false,
                        preview_unavailable: Nullable(row.preview_unavailable.clone()),
                    };
                    Settled::Result(
                        kr_cbor::to_canonical_vec(&result).map_err(TransferError::store)?,
                    )
                }
                // A publication that ended in neither of those ways ended as a refusal, and the
                // repeat is owed that refusal rather than a handle that names nothing.
                (UPLOAD_FINISH, UploadState::Invalidated | UploadState::Expired) => {
                    Settled::Failure(
                        ErrorCode::AttachmentIntegrity,
                        row.invalid_reason.clone().unwrap_or_else(|| {
                            "this upload ended without being published".to_owned()
                        }),
                    )
                }
                // Cancelled *and* released: the bytes are only back in the budget once the payload
                // is gone, and a result that said otherwise would be wrong. A row still marked for
                // cleanup is left to the next pass, which runs after the retry that removes it.
                (UPLOAD_CANCEL, UploadState::Cancelled) if !row.cleanup_pending => {
                    let result = UploadCancelResult {
                        transfer_id,
                        state: row.state,
                        // The reservation this upload made, not the field the release zeroed.
                        released_byte_len: U64::new(row.declared_byte_len),
                    };
                    Settled::Result(
                        kr_cbor::to_canonical_vec(&result).map_err(TransferError::store)?,
                    )
                }
                // Still in flight, or ended in a way this claim's method does not describe. The
                // record stays open and the next pass looks again.
                _ => continue,
            };
            let wrote = match settled {
                Settled::Result(encoded) => self.locked()?.complete_action(
                    &claim.actor_id,
                    claim.action_id,
                    &claim.method,
                    claim.payload_digest,
                    &encoded,
                )?,
                Settled::Failure(code, detail) => self.locked()?.fail_action(
                    &claim.actor_id,
                    claim.action_id,
                    &claim.method,
                    claim.payload_digest,
                    code.as_str(),
                    &detail,
                )?,
            };
            if wrote {
                resolved += 1;
            }
        }
        Ok(resolved)
    }

    /// Removes every payload a closed transfer left behind, and releases its bytes.
    ///
    /// Returns how many were removed and how many still could not be.
    fn retry_cleanup(&self) -> Result<(usize, usize)> {
        let mut removed = 0;
        let mut unremovable = 0;
        // Both lists are bound to locals first. A guard in the head of a `for` loop lives for the
        // whole body, and the body takes the journal again.
        let uploads = self.locked()?.uploads_needing_cleanup()?;
        for row in uploads {
            match self.discard_payloads(&row) {
                Ok(()) => removed += 1,
                // A removal that still fails keeps its row marked and its bytes charged. The next
                // pass tries again rather than forgetting the file exists.
                Err(_) => unremovable += 1,
            }
        }
        let snapshots = self.locked()?.snapshots_needing_cleanup()?;
        for row in snapshots {
            match self.discard_snapshot_payload(&row) {
                Ok(()) => removed += 1,
                Err(_) => unremovable += 1,
            }
        }
        Ok((removed, unremovable))
    }

    /// Removes every payload in the staging areas that no row accounts for.
    ///
    /// This is the cleanup ownership of a file created before its row was. `upload.begin` creates
    /// the payload first, so a daemon that died between the create and the commit, or a commit that
    /// failed and whose own removal failed too, leaves a name with nothing behind it. Every name in
    /// these three areas is derived from a transfer identifier, so the journal can be asked about
    /// each one.
    fn reconcile_orphans(&self) -> Result<usize> {
        let mut removed = 0;
        for directory in [
            self.staging.incomplete(),
            self.staging.complete(),
            self.staging.snapshots(),
        ] {
            let entries =
                std::fs::read_dir(directory.display_path()).map_err(TransferError::staging)?;
            let mut removed_here = 0;
            for entry in entries {
                let Ok(entry) = entry else { continue };
                let name = entry.file_name().to_string_lossy().to_string();
                let Ok(relative) = RelativeName::parse(&name) else {
                    continue;
                };
                let Some(transfer_id) = StorageName::transfer_of(&name) else {
                    continue;
                };
                let accounted = {
                    let store = self.locked()?;
                    let upload = store.upload(transfer_id)?;
                    let snapshot = store.snapshot(transfer_id)?;
                    upload.is_some_and(|row| row.state.holds_payload() || row.cleanup_pending)
                        || snapshot
                            .is_some_and(|row| row.state.holds_bytes() || row.cleanup_pending)
                };
                if accounted {
                    continue;
                }
                if directory.remove(&relative).is_ok() {
                    removed_here += 1;
                }
            }
            if removed_here > 0 {
                directory.sync()?;
            }
            removed += removed_here;
        }
        Ok(removed)
    }

    /// Expires everything whose retention has run out.
    ///
    /// Every transition is conditional on the state the row is still in, because the candidates
    /// were listed before the lock each transition takes: a finish, a cancellation or a submission
    /// can land in between, and a sweep that overwrote one of those would expire an attachment its
    /// session had just taken responsibility for.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the journal cannot be read or written.
    pub fn sweep(&self, retention: &dyn SessionRetention) -> Result<Sweep> {
        let now = self.clock.now_ms();
        let payloads = self.payloads.lock().map_err(|_| poisoned())?;
        let mut sweep = Sweep::default();
        let unfinished = self
            .locked()?
            .uploads_in(&[UploadState::Receiving, UploadState::Publishing])?;
        for candidate in unfinished {
            let mut store = self.locked()?;
            let Some(row) = store.upload(candidate.transfer_id)? else {
                continue;
            };
            if row.expires_at_ms.get() > now.get() {
                continue;
            }
            // The permitted state is checked rather than taken on trust from the re-read, so a
            // row a cancellation moved in between is left alone instead of expired twice.
            if !matches!(row.state, UploadState::Receiving | UploadState::Publishing) {
                continue;
            }
            let moved = store.close_upload_from(
                row.transfer_id,
                row.state,
                UploadState::Expired,
                Some("this upload was unfinished for longer than its expiry"),
                now,
            )?;
            drop(store);
            if moved {
                let _ = self.discard_payloads(&row);
                sweep.expired_uploads += 1;
            }
        }
        let published = self.locked()?.uploads_in(&[UploadState::Published])?;
        for candidate in published {
            let mut store = self.locked()?;
            let Some(row) = store.upload(candidate.transfer_id)? else {
                continue;
            };
            if row.state != UploadState::Published {
                continue;
            }
            // Two retentions, and which one applies is which of them the attachment is under.
            // A submitted attachment follows its session, whatever its own unused-attachment
            // deadline says; an unsubmitted one follows that deadline.
            let expired = match (row.submitted_at_ms, row.session_id) {
                (Some(_), Some(session_id)) => !retention.retains(session_id),
                (Some(_), None) => row.expires_at_ms.get() <= now.get(),
                (None, _) => row.expires_at_ms.get() <= now.get(),
            };
            if !expired {
                continue;
            }
            let moved = store.close_upload_from(
                row.transfer_id,
                UploadState::Published,
                UploadState::Expired,
                Some("this attachment's retention has ended"),
                now,
            )?;
            if !moved {
                continue;
            }
            store.revoke_grants_for(row.transfer_id)?;
            drop(store);
            let _ = self.discard_payloads(&row);
            sweep.expired_attachments += 1;
        }
        // Open rows only. A reserving row belongs to a call that is still staging: closing it
        // would release a reservation whose file is about to exist, and nothing would be charged
        // for those bytes. An abandoned reservation is resolved at the next start, by recovery,
        // where nothing is in flight.
        let snapshots = self.locked()?.snapshots_in(SnapshotState::Open)?;
        for candidate in snapshots {
            let Some(row) = self.locked()?.snapshot(candidate.transfer_id)? else {
                continue;
            };
            if !row.state.holds_bytes() || row.expires_at_ms.get() > now.get() {
                continue;
            }
            // The payload lock is already held here, so the release must not take it again.
            self.release_snapshot_held(
                &row,
                SnapshotState::Expired,
                Some("this snapshot outlived its expiry"),
                now,
            )?;
            sweep.expired_snapshots += 1;
        }
        // The same cleanup retry recovery runs. A removal that failed once should not wait for
        // the next start.
        let (removed, unremovable) = self.retry_cleanup()?;
        sweep.removed_payloads = removed;
        sweep.unremovable_payloads = unremovable;
        // A cleanup that succeeded here may be what a claim was waiting for.
        sweep.resolved_claims = self.resolve_claims()?;
        let horizon = TimestampMs::new(
            now.get()
                .saturating_sub(kr_protocol::limits::DEDUPLICATION_RETENTION.get()),
        );
        sweep.forgotten_actions = self.locked()?.forget_actions_before(horizon)?;
        drop(payloads);
        Ok(sweep)
    }

    /// Returns a retained mutation outcome for an exact repeat of one action.
    ///
    /// A repeat with the same identifier and a different payload is a reused identifier, which is
    /// refused rather than answered with the first result.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::IdConflict`] when the same identifier carried a different payload,
    /// or [`TransferError::StoreUnavailable`] when the read fails.
    pub fn retained_action(
        &self,
        actor: &ActorId,
        action_id: Uuid,
        method: &str,
        payload_digest: Digest256,
    ) -> Result<Option<RetainedOutcome>> {
        let Some(record) = self.locked()?.retained_action(actor, action_id)? else {
            return Ok(None);
        };
        if record.method != method || record.payload_digest != payload_digest {
            return Err(TransferError::IdConflict {
                action: action_id.to_string(),
                method: record.method,
            });
        }
        Ok(match (record.result, record.error_code) {
            (Some(result), _) => Some(RetainedOutcome::Ok(result)),
            (None, Some(code)) => Some(RetainedOutcome::Error {
                code: code.parse().unwrap_or(ErrorCode::OutcomeUnknown),
                detail: record.error_detail.unwrap_or_default(),
            }),
            // Claimed and not settled. This is *not* an answer: the request goes through to the
            // service, which finishes the effect its claim started and records what it produced.
            // Answering `OUTCOME_UNKNOWN` here would leave a caller with no way to learn the
            // outcome of an action this host can still complete.
            (None, None) => None,
        })
    }

    /// Retains one mutation outcome so an exact repeat is answered rather than performed again.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn record_action(
        &self,
        actor: &ActorId,
        action_id: Uuid,
        method: &str,
        payload_digest: Digest256,
        outcome: &RetainedOutcome,
    ) -> Result<Option<RetainedOutcome>> {
        let record = match outcome {
            RetainedOutcome::Ok(result) => ActionRecord {
                method: method.to_owned(),
                payload_digest,
                result: Some(result.clone()),
                error_code: None,
                error_detail: None,
                recorded_at_ms: self.clock.now_ms(),
            },
            RetainedOutcome::Error { code, detail } => ActionRecord {
                method: method.to_owned(),
                payload_digest,
                result: None,
                error_code: Some(code.as_str().to_owned()),
                error_detail: Some(detail.clone()),
                recorded_at_ms: self.clock.now_ms(),
            },
        };
        if self.locked()?.record_action(actor, action_id, &record)? {
            // This outcome is the retained one, so it is the one the caller is owed.
            return Ok(None);
        }
        // Another copy of this action recorded first. Two callers of one action get one answer,
        // and it is the answer that was retained, not the one this copy happened to compute. A
        // record carrying a different payload is a reused identifier and says so.
        self.retained_action(actor, action_id, method, payload_digest)
    }

    /// Returns the result an action already recorded, decoded into the method's own shape.
    ///
    /// Reached when a transaction carrying an action found it already recorded, which means
    /// another attempt at the same action committed first. That attempt's result is the answer
    /// this one owes its caller.
    /// Reads this action's record and says which of the three things it is.
    ///
    /// Read at every point where the answer could already exist: before the effect, and again at
    /// each place that finds the effect already done. The record can settle between two reads, so
    /// the later read is the one that decides.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::IdConflict`] when the same identifier carried a different payload,
    /// and [`TransferError::StoreUnavailable`] when the read fails.
    fn recorded<T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        action: Option<&Action>,
    ) -> Result<Recorded<T>> {
        let store = self.locked()?;
        recorded_with(&store, action)
    }

    /// Records the result of an action that was claimed without one.
    ///
    /// A two-commit effect claims its action with the first commit; this is the second half. It
    /// replaces nothing: the first result recorded for an identifier is the one that stands.
    fn complete_claim<T: serde::Serialize>(
        &self,
        action: Option<&Action>,
        result: &T,
    ) -> Result<()> {
        let Some(action) = action else {
            return Ok(());
        };
        let encoded = kr_cbor::to_canonical_vec(result).map_err(TransferError::store)?;
        // The completion names the claim it completes: the identifier alone is not enough, because
        // an identifier can be claimed by a different request between reading the record and
        // writing to it. A completion that matches nothing changes nothing, which is the right
        // answer for a caller whose claim is no longer there.
        self.locked()?
            .complete_action(
                &action.actor_id,
                action.action_id,
                &action.method,
                action.payload_digest,
                &encoded,
            )
            .map(|_| ())
    }

    /// Answers a publication that did not complete, recording the refusal on its own claim.
    ///
    /// A publication is claimed when its intent commits and answered when the move has landed. One
    /// that cannot be completed has an answer too, and it is this refusal. Without recording it the
    /// claim would stay open until the next recovery pass settled it, and a copy arriving in
    /// between would be refused for the terminal state this action's own publication reached.
    ///
    /// The refusal is this call's answer only while the claim is still open. Where something else
    /// settled the action first, a copy of it or a sweep that expired the transfer and resolved its
    /// claim, that is the action's answer and this caller is owed it rather than a refusal computed
    /// from a state it read afterwards. One read decides which, and nothing replaces an answer
    /// already recorded. A call that claimed nothing, which is every retried finish that found
    /// somebody else's publication, records nothing and keeps its own refusal.
    fn refuse_publication(
        &self,
        action: Option<&Action>,
        refusal: TransferError,
    ) -> Result<UploadFinishResult> {
        let Some(action) = action else {
            return Err(refusal);
        };
        let recorded = self.locked()?.fail_action(
            &action.actor_id,
            action.action_id,
            &action.method,
            action.payload_digest,
            refusal.code().as_str(),
            &refusal.to_string(),
        )?;
        if recorded {
            return Err(refusal);
        }
        match self.recorded(Some(action))? {
            Recorded::Answered(answered) => Ok(answered),
            // Nothing this refusal could fill: no record at all, or a claim that is somehow still
            // open. Either way this call's answer is the refusal it came with.
            Recorded::Claimed | Recorded::Absent => Err(refusal),
        }
    }

    /// Answers a refusal from the retained record when this action has already been performed.
    ///
    /// A precondition a request fails can be one its own first attempt created: the reservation it
    /// charged against the environment, or the revision it moved. Two concurrent copies of one
    /// action must not answer differently, so where a refusal could have that explanation the
    /// record is consulted before the refusal is returned. An identifier carrying a different
    /// payload is still a reused identifier.
    fn refuse_unless_performed<T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        action: Option<&Action>,
        refusal: TransferError,
    ) -> Result<T> {
        if action.is_none() {
            return Err(refusal);
        }
        match self.retained_result(action) {
            Ok(result) => Ok(result),
            // A reused identifier is what it is whatever this request would have failed for.
            Err(conflict @ TransferError::IdConflict { .. }) => Err(conflict),
            Err(_) => Err(refusal),
        }
    }

    fn retained_result<T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        action: Option<&Action>,
    ) -> Result<T> {
        let action = action.ok_or_else(|| {
            TransferError::store("a transaction reported an action that was not supplied")
        })?;
        let record = self
            .locked()?
            .retained_action(&action.actor_id, action.action_id)?
            .ok_or_else(|| {
                TransferError::store("the action this transaction yielded to is not recorded")
            })?;
        // The claim is by identifier alone, so the payload has to be compared here: two different
        // requests under one identifier are a reused identifier, not a retry, and the second must
        // not receive the first one's result.
        if record.method != action.method || record.payload_digest != action.payload_digest {
            return Err(TransferError::IdConflict {
                action: action.action_id.to_string(),
                method: record.method,
            });
        }
        let result = record.result.ok_or_else(|| {
            TransferError::store("the action this transaction yielded to recorded no result")
        })?;
        kr_cbor::from_canonical_slice(&result, &kr_cbor::Limits::DEFAULT)
            .map_err(TransferError::store)
    }

    pub(crate) fn locked(&self) -> Result<std::sync::MutexGuard<'_, Store>> {
        self.store.lock().map_err(|_| poisoned())
    }

    pub(crate) fn check_environment(&self, environment_id: EnvironmentId) -> Result<()> {
        if environment_id == self.environment_id {
            Ok(())
        } else {
            Err(TransferError::WrongEnvironment {
                named: environment_id.to_string(),
                owned: self.environment_id.to_string(),
            })
        }
    }

    /// Refuses an upload that cannot take more bytes, expiring it first when its time is up.
    fn check_live(
        &self,
        store: &mut std::sync::MutexGuard<'_, Store>,
        row: &UploadRow,
        detail: &str,
    ) -> Result<()> {
        let now = self.clock.now_ms();
        if row.state.accepts_chunks() && row.expires_at_ms.get() <= now.get() {
            store.close_upload(
                row.transfer_id,
                UploadState::Expired,
                Some("this upload was unfinished for longer than its expiry"),
                now,
                // An expiry is the host's own decision, not the caller's action.
                None,
            )?;
            // The row is marked for cleanup and its bytes stay charged. The next recovery or sweep
            // removes the payload and releases them; this call does not, because it holds the
            // journal's lock and the removal must not happen under it.
            return Err(TransferError::WrongState {
                transfer: row.transfer_id.to_string(),
                state: UploadState::Expired.as_str(),
                detail: detail.to_owned(),
            });
        }
        if !row.state.accepts_chunks() {
            return Err(TransferError::WrongState {
                transfer: row.transfer_id.to_string(),
                state: row.state.as_str(),
                detail: detail.to_owned(),
            });
        }
        Ok(())
    }

    fn open_incomplete(&self, row: &UploadRow) -> Result<AuthorisedFile> {
        let storage = StorageName::derive(row.transfer_id, &row.original_file_name);
        let file = self
            .staging
            .incomplete()
            .open_write(&storage.incomplete()?)?;
        file.check_environment(row.environment_id)?;
        Ok(file)
    }

    pub(crate) fn open_published(&self, row: &UploadRow) -> Result<AuthorisedFile> {
        let storage = StorageName::derive(row.transfer_id, &row.original_file_name);
        let file = self
            .staging
            .complete()
            .open_read(&storage.published()?, ObjectPolicy::HostOwnedFile)?;
        file.check_environment(row.environment_id)?;
        // The object has to be the one the publication verified, not merely a file of that name.
        if let Some(identity) = row.payload_identity {
            file.check_identity(identity)?;
        }
        Ok(file)
    }

    /// Builds the narrow read grant one binding needs, without writing it.
    ///
    /// The row is committed by the transaction that writes the binding, so a grant never outlives
    /// a binding that did not happen.
    fn read_grant_for(
        &self,
        handle: &AttachmentHandle,
        insertion_method: InsertionMethod,
        now: TimestampMs,
    ) -> Result<GrantRow> {
        let storage = StorageName::derive(handle.transfer_id, &handle.original_file_name);
        let host_path = self
            .staging
            .complete()
            .host_path(&storage.published()?)
            .display()
            .to_string();
        // A staged file is outside every repository by construction, and the check says so rather
        // than assuming it.
        if crate::staging::inside_repository(std::path::Path::new(&host_path)) {
            return Err(TransferError::PermissionDenied {
                detail: "the staging area is inside a repository working tree, so no read grant \
                         over it can be issued"
                    .to_owned(),
            });
        }
        let row = GrantRow {
            grant_id: GrantId::new(kr_ipc::new_uuid()),
            environment_id: self.environment_id,
            transfer_id: handle.transfer_id,
            insertion_method,
            host_path,
            expires_at_ms: TimestampMs::new(now.get().saturating_add(READ_GRANT_LIFETIME_MS)),
            revoked: false,
        };
        Ok(row)
    }

    fn handles_of(
        &self,
        store: &std::sync::MutexGuard<'_, Store>,
        bindings: &[BindingRow],
    ) -> Result<Vec<(AttachmentHandle, Option<AttachmentReadGrant>)>> {
        let mut handles = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let row = store
                .upload(binding.transfer_id)?
                .ok_or_else(|| unknown(binding.transfer_id))?;
            let grant = match binding.grant_id {
                Some(grant_id) => {
                    store
                        .grant(grant_id)?
                        .filter(|grant| !grant.revoked)
                        .map(|grant| AttachmentReadGrant {
                            grant_id: grant.grant_id,
                            environment_id: grant.environment_id,
                            transfer_id: grant.transfer_id,
                            insertion_method: grant.insertion_method,
                            host_path: grant.host_path,
                            expires_at_ms: grant.expires_at_ms,
                        })
                }
                None => None,
            };
            handles.push((handle_of(&row)?, grant));
        }
        Ok(handles)
    }

    fn draft_record(&self, row: &DraftRow, bindings: &[BindingRow]) -> Result<DraftRecord> {
        self.compose_draft(row, bindings, &[])
    }

    fn compose_draft(
        &self,
        row: &DraftRow,
        bindings: &[BindingRow],
        handles: &[(AttachmentHandle, Option<AttachmentReadGrant>)],
    ) -> Result<DraftRecord> {
        let mut attachments = Vec::with_capacity(bindings.len());
        for (binding, (handle, grant)) in bindings.iter().zip(handles.iter()) {
            attachments.push(DraftAttachment {
                handle: handle.clone(),
                insertion_method: binding.insertion_method,
                state: binding.state,
                upstream_evidence: Nullable(binding.upstream_evidence.clone()),
                failure_detail: Nullable(binding.failure_detail.clone()),
                read_grant: Nullable(grant.clone()),
                external_destination: Nullable(binding.external_destination.clone()),
            });
        }
        Ok(DraftRecord {
            draft_id: row.draft_id,
            environment_id: row.environment_id,
            revision: row.revision,
            device_id: Nullable(row.device_id),
            session_id: Nullable(row.session_id),
            application_instance_id: Nullable(row.application_instance_id),
            state: row.state,
            text: row.text.clone(),
            attachments,
            created_at_ms: row.created_at_ms,
            updated_at_ms: row.updated_at_ms,
        })
    }
}

pub(crate) fn poisoned() -> TransferError {
    TransferError::store("the transfer journal's lock was left poisoned by an earlier failure")
}

pub(crate) fn unknown(transfer_id: TransferId) -> TransferError {
    TransferError::UnknownTransfer {
        transfer: transfer_id.to_string(),
    }
}

/// Returns one upload, for the principal that began it.
///
/// A transfer another principal owns is refused exactly as one that does not exist is, so a caller
/// cannot learn from the refusal whether an identifier it guessed names anything.
pub(crate) fn upload_of(
    store: &Store,
    transfer_id: TransferId,
    actor: &ActorId,
) -> Result<UploadRow> {
    match store.upload(transfer_id)? {
        Some(row) if &row.actor_id == actor => Ok(row),
        _ => Err(unknown(transfer_id)),
    }
}

/// Returns one draft, for the principal that owns it. Refused the same way as above.
fn draft_of(store: &Store, draft_id: DraftId, actor: &ActorId) -> Result<DraftRow> {
    match store.draft(draft_id)? {
        Some(row) if &row.actor_id == actor => Ok(row),
        _ => Err(TransferError::UnknownDraft {
            draft: draft_id.to_string(),
        }),
    }
}

/// Refuses a finish whose declaration is not the one the reservation was made for.
fn check_declaration(row: &UploadRow, params: &UploadFinishParams) -> Result<()> {
    if params.declared_byte_len.get() != row.declared_byte_len
        || params.declared_digest != row.declared_digest
    {
        return Err(TransferError::source_changed(
            "this upload was reserved for a different size or digest; a changed source needs a \
             new upload identifier",
        ));
    }
    Ok(())
}

/// The refusal a caller is owed when the publication it asked for did not and will not happen.
///
/// An invalidated publication is an integrity refusal carrying the reason the row recorded: the
/// bytes were not the bytes that were verified, or they were gone, and either way the identifier is
/// spent. Every caller is told that, and so is every copy of the action, because the refusal is
/// recorded on the claim as it happens.
///
/// Any other ended state is that state. A cancellation that closed this transfer first is not an
/// integrity failure, and neither is an expiry: an upload that ran out of time did not fail a
/// digest, and answering as though it had would spend the wrong code on it and disagree with the
/// refusal the expiry itself gives.
fn publication_refusal(row: &UploadRow) -> TransferError {
    if row.state == UploadState::Invalidated {
        return TransferError::integrity(
            row.invalid_reason
                .clone()
                .unwrap_or_else(|| "this upload ended without being published".to_owned()),
        );
    }
    TransferError::WrongState {
        transfer: row.transfer_id.to_string(),
        state: row.state.as_str(),
        detail: "this upload ended before it published, so it cannot be finished".to_owned(),
    }
}

/// Builds the opaque handle of a published upload.
fn handle_of(row: &UploadRow) -> Result<AttachmentHandle> {
    let preview = match &row.preview {
        Some(bytes) => {
            let preview: AttachmentPreview =
                kr_cbor::from_canonical_slice(bytes, &kr_cbor::Limits::DEFAULT)
                    .map_err(|error| TransferError::store(error.to_string()))?;
            Nullable::some(preview)
        }
        None => Nullable::null(),
    };
    Ok(AttachmentHandle {
        environment_id: row.environment_id,
        transfer_id: row.transfer_id,
        session_id: Nullable(row.session_id),
        byte_len: U64::new(row.declared_byte_len),
        content_digest: row.content_digest.unwrap_or(row.declared_digest),
        declared_media_type: row.declared_media_type.clone(),
        original_file_name: row.original_file_name.clone(),
        // Whether this is presented as a model image is whether its bytes decoded, and nothing
        // else. A declared media type is a claim; unsupported media transfers as a file.
        presented_as_image: preview.is_present(),
        preview,
        published_at_ms: row.published_at_ms.unwrap_or(row.created_at_ms),
        expires_at_ms: row.expires_at_ms,
        submitted: row.submitted_at_ms.is_some(),
    })
}

fn check_media_type(media_type: &str) -> Result<()> {
    if media_type.is_empty() || media_type.len() > MAX_MEDIA_TYPE_LEN {
        return Err(TransferError::invalid(format!(
            "a declared media type is between one and {MAX_MEDIA_TYPE_LEN} bytes"
        )));
    }
    if media_type
        .bytes()
        .any(|byte| byte.is_ascii_control() || !byte.is_ascii())
    {
        return Err(TransferError::invalid(
            "a declared media type is printable ASCII",
        ));
    }
    if !media_type.contains('/') {
        return Err(TransferError::invalid(
            "a declared media type names a type and a subtype",
        ));
    }
    Ok(())
}

fn check_original_name(name: &str) -> Result<()> {
    if name.len() > MAX_ORIGINAL_FILE_NAME_LEN {
        return Err(TransferError::invalid(format!(
            "an original filename is at most {MAX_ORIGINAL_FILE_NAME_LEN} bytes"
        )));
    }
    // The name is metadata and never a path, so separators are not refused; a control byte is,
    // because it would corrupt whatever is asked to display it.
    if name.bytes().any(|byte| byte == 0) || name.chars().any(char::is_control) {
        return Err(TransferError::invalid(
            "an original filename carries no control characters",
        ));
    }
    Ok(())
}

/// Refuses a handle the declared contribution does not admit.
/// Refuses an insertion outcome whose text a draft could not carry.
///
/// A draft's reply holds one of these per binding. Bounding each one is what keeps the reply
/// bounded, and the bound is on the text rather than on how many bindings a draft may have.
fn check_insertion_detail(outcome: &InsertionOutcome) -> Result<()> {
    let text = match outcome {
        InsertionOutcome::AcceptedByAgent { upstream_evidence } => upstream_evidence,
        InsertionOutcome::Failed { detail } => detail,
    };
    if text.chars().count() > kr_protocol::transfer::MAX_INSERTION_DETAIL_LEN {
        return Err(TransferError::invalid(format!(
            "an insertion outcome carries at most {} characters",
            kr_protocol::transfer::MAX_INSERTION_DETAIL_LEN
        )));
    }
    Ok(())
}

/// Refuses a result too large to travel in the frame that carries it.
///
/// Every mutation that returns a draft can grow the reply: one more attachment, one more preview,
/// a longer text. A reply the host cannot send would leave the caller with a committed effect and
/// no receipt, so the encoded size is checked before the commit and the refusal changes nothing.
fn check_result_size<T: serde::Serialize>(result: &T, what: &str) -> Result<u64> {
    let encoded = kr_cbor::to_canonical_vec(result).map_err(TransferError::store)?;
    let len = encoded.len() as u64;
    if len > kr_protocol::transfer::MAX_TRANSFER_RESULT_BYTES {
        return Err(TransferError::QuotaExceeded {
            detail: format!(
                "{what} encodes to {len} bytes and a reply carries at most {}; remove an \
                 attachment or shorten the text",
                kr_protocol::transfer::MAX_TRANSFER_RESULT_BYTES
            ),
        });
    }
    Ok(len)
}

fn check_contribution(
    contribution: &kr_protocol::transfer::AttachmentContribution,
    handle: &AttachmentHandle,
) -> Result<()> {
    if contribution.max_count.get() == 0 {
        return Err(TransferError::invalid(
            "this operation declares that it accepts no attachments",
        ));
    }
    if handle.byte_len.get() > contribution.max_byte_len.get() {
        return Err(TransferError::invalid(format!(
            "this operation accepts {} bytes and the attachment is {}",
            contribution.max_byte_len.get(),
            handle.byte_len.get()
        )));
    }
    let declared = handle.declared_media_type.to_ascii_lowercase();
    let accepted = contribution
        .accepted_media_types
        .iter()
        .any(|media_type| media_type.to_ascii_lowercase() == declared);
    if !accepted {
        return Err(TransferError::invalid(format!(
            "this operation accepts {} and the attachment declares {}",
            contribution.accepted_media_types.join(", "),
            handle.declared_media_type
        )));
    }
    // A declared destination is a disclosure, so it has to be one a client can show: declared
    // means named, and a name is bounded like every other string that reaches a person.
    if let Some(destination) = &contribution.external_destination.0 {
        if destination.trim().is_empty() {
            return Err(TransferError::invalid(
                "this operation declares an external destination without naming it",
            ));
        }
        if destination.chars().count() > kr_protocol::transfer::MAX_EXTERNAL_DESTINATION_LEN {
            return Err(TransferError::invalid(format!(
                "an external destination is at most {} characters",
                kr_protocol::transfer::MAX_EXTERNAL_DESTINATION_LEN
            )));
        }
    }
    // An image is only offered as one when the bytes decoded as one. A contribution that claims a
    // model media capability for something that did not decode would present a file as an image.
    if contribution.model_media_capability
        && declared.starts_with("image/")
        && !handle.presented_as_image
    {
        return Err(TransferError::invalid(
            "these bytes did not decode as a supported image, so they transfer as a file rather \
             than as a model image",
        ));
    }
    Ok(())
}

/// Writes one chunk at its own offset and flushes it before the journal records it.
pub(crate) fn write_at(file: &mut AuthorisedFile, offset: u64, bytes: &[u8]) -> Result<()> {
    use std::io::{Seek as _, SeekFrom, Write as _};

    let handle = file.handle_mut();
    handle
        .seek(SeekFrom::Start(offset))
        .map_err(TransferError::staging)?;
    handle.write_all(bytes).map_err(TransferError::staging)?;
    handle.sync_data().map_err(TransferError::staging)?;
    Ok(())
}

/// Reads a whole file through its handle and returns its digest and length.
pub(crate) fn digest_of(file: &mut AuthorisedFile) -> Result<(Digest256, u64)> {
    use sha2::Digest as _;
    use std::io::{Read as _, Seek as _, SeekFrom};

    let handle = file.handle_mut();
    handle
        .seek(SeekFrom::Start(0))
        .map_err(TransferError::staging)?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0_u8; READ_BUFFER_LEN];
    let mut total = 0_u64;
    loop {
        let read = handle.read(&mut buffer).map_err(TransferError::staging)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total = total.saturating_add(read as u64);
    }
    handle
        .seek(SeekFrom::Start(0))
        .map_err(TransferError::staging)?;
    Ok((Digest256::from_bytes(hasher.finalize().into()), total))
}

/// Reads exactly one chunk of a file through its handle.
pub(crate) fn read_at(file: &mut AuthorisedFile, offset: u64, len: u64) -> Result<Bytes> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let len = usize::try_from(len)
        .map_err(|_| TransferError::invalid("a chunk longer than this host can address"))?;
    let handle = file.handle_mut();
    handle
        .seek(SeekFrom::Start(offset))
        .map_err(TransferError::staging)?;
    let mut bytes = vec![0_u8; len];
    handle
        .read_exact(&mut bytes)
        .map_err(TransferError::staging)?;
    Ok(Bytes::new(bytes))
}

/// Returns a relative name for one snapshot's payload.
pub(crate) fn snapshot_name(transfer_id: TransferId, stored_name: &str) -> Result<RelativeName> {
    if stored_name.is_empty() {
        return StorageName::derive(transfer_id, "").published();
    }
    RelativeName::parse(stored_name).map_err(TransferError::from)
}

/// The expiry a new snapshot is given.
pub(crate) fn snapshot_expiry(now: TimestampMs) -> TimestampMs {
    TimestampMs::new(now.get().saturating_add(DOWNLOAD_SNAPSHOT_LIFETIME.get()))
}
