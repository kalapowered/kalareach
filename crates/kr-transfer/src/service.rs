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
    ActionRecord, BindingRow, DraftRow, GrantRow, Limits, ScopeRow, SnapshotState, Store, UploadRow,
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
    /// Published attachments that went unused for seven days.
    pub expired_attachments: usize,
    /// Download snapshots that outlived their expiry.
    pub expired_snapshots: usize,
    /// De-duplication records older than the protocol's retention.
    pub forgotten_actions: usize,
}

/// What one recovery pass resolved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Recovery {
    /// Publications that were interrupted after verification and have now completed.
    pub completed_publications: usize,
    /// Publications whose payload could not be found and are now invalidated.
    pub unresolved_publications: usize,
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
    pub(crate) scopes: Mutex<std::collections::BTreeMap<GrantId, Arc<AuthorisedDirectory>>>,
    pub(crate) clock: Arc<dyn Clock>,
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
        Ok(Self {
            environment_id: paths.environment_id(),
            store: Mutex::new(store),
            staging,
            scopes: Mutex::new(std::collections::BTreeMap::new()),
            clock,
        })
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
        self.scopes
            .lock()
            .map_err(|_| poisoned())?
            .insert(scope_id, Arc::new(directory));
        Ok(scope_id)
    }

    /// Revokes a read scope, which stops further bytes from every transfer opened through it.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the row cannot be written.
    pub fn revoke_scope(&self, scope_id: GrantId) -> Result<()> {
        self.locked()?.revoke_scope(scope_id)?;
        self.scopes
            .lock()
            .map_err(|_| poisoned())?
            .remove(&scope_id);
        Ok(())
    }

    /// Reserves an upload's declared size and returns its identity, layout and expiry.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::WrongEnvironment`] for another environment,
    /// [`TransferError::InvalidArgument`] for a size or a declaration this service will not accept,
    /// [`TransferError::QuotaExceeded`] when the environment's staged bytes would exceed their
    /// limit, or [`TransferError::Concurrency`] when the device already holds as many transfers as
    /// it may.
    pub fn upload_begin(
        &self,
        actor: &ActorId,
        params: &UploadBeginParams,
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
        let (staged, staged_limit) = {
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
            let open = store.open_transfers(params.device_id.0, actor)?;
            if open >= limits.max_concurrent_transfers {
                return Err(TransferError::Concurrency {
                    detail: format!(
                        "this device already holds {open} of {} concurrent transfers; finish or \
                         cancel one first",
                        limits.max_concurrent_transfers
                    ),
                });
            }
            let staged = store.staged_byte_len()?;
            let after = staged.saturating_add(declared);
            if after > limits.max_staged_len {
                return Err(TransferError::QuotaExceeded {
                    detail: format!(
                        "this environment has {staged} of {} staged bytes, and {declared} more \
                         would exceed it",
                        limits.max_staged_len
                    ),
                });
            }
            // The payload file exists before the row does, so a row can never name a file that
            // was refused, and the exclusive create is what proves the name was unused.
            let incomplete = storage.incomplete()?;
            let file = self.staging.incomplete().create_new(&incomplete)?;
            drop(file);
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
                preview: None,
                preview_unavailable: None,
                created_at_ms: now,
                expires_at_ms,
                published_at_ms: None,
                submitted_at_ms: None,
            };
            if let Err(error) = store.insert_upload(&row) {
                // Nothing names the file yet, so the failed reservation takes it with it.
                let _ = self.staging.incomplete().remove(&incomplete);
                return Err(error);
            }
            (after, limits.max_staged_len)
        };
        let layout = ChunkLayout::for_length(declared);
        Ok(UploadBeginResult {
            transfer_id,
            environment_id: params.environment_id,
            layout,
            received_chunks: ChunkBitmap::empty(layout.chunk_count.get()).encode(),
            expires_at_ms,
            staged_byte_len: U64::new(staged),
            staged_byte_limit: U64::new(staged_limit),
        })
    }

    /// Reports an upload's verified chunk status, and its handle once it is published.
    ///
    /// This is how a lost reply to `upload.finish` is resolved: a published upload answers with
    /// the handle it already has, and no second file is created.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::UnknownTransfer`] when nothing is named, or
    /// [`TransferError::PermissionDenied`] when another actor began it.
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
    ) -> Result<UploadChunkResult> {
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
                )?;
                let _ = self
                    .staging
                    .incomplete()
                    .remove(&StorageName::derive(row.transfer_id, "").incomplete()?);
                return Err(TransferError::integrity(reason));
            }
        }
        if !duplicate {
            let offset = layout.offset_of(index).unwrap_or_default();
            let mut file = self.open_incomplete(&row)?;
            write_at(&mut file, offset, params.bytes.as_slice())?;
            // The journal row follows the bytes. A row with no bytes behind it would let the
            // verification trust a hole.
            store.record_chunk(params.transfer_id, params.chunk, now)?;
        }
        let chunks = store.chunks(params.transfer_id)?;
        let mut bitmap = ChunkBitmap::empty(layout.chunk_count.get());
        let mut received = 0_u64;
        for chunk in &chunks {
            bitmap.insert(chunk.index.get());
            received = received.saturating_add(chunk.byte_len.get());
        }
        Ok(UploadChunkResult {
            transfer_id: params.transfer_id,
            index: params.chunk.index,
            duplicate,
            received_chunks: bitmap.encode(),
            received_byte_len: U64::new(received),
        })
    }

    /// Verifies the whole file and publishes the attachment handle.
    ///
    /// The declared size and digest must be the ones `upload.begin` recorded: a client that has
    /// changed its mind about what it is sending needs a new upload identifier, because the
    /// reservation, the layout and every chunk already accepted belong to the first declaration.
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
    ) -> Result<UploadFinishResult> {
        let now = self.clock.now_ms();
        // A published upload is answered before anything is read. This is the retry after a lost
        // reply, and it must never produce a second file.
        {
            let store = self.locked()?;
            let row = upload_of(&store, params.transfer_id, actor)?;
            if row.state == UploadState::Published {
                return Ok(UploadFinishResult {
                    handle: handle_of(&row)?,
                    already_published: true,
                    preview_unavailable: Nullable(row.preview_unavailable.clone()),
                });
            }
        }
        let row = {
            let mut store = self.locked()?;
            let row = upload_of(&store, params.transfer_id, actor)?;
            self.check_live(&mut store, &row, "it cannot be finished")?;
            if params.declared_byte_len.get() != row.declared_byte_len
                || params.declared_digest != row.declared_digest
            {
                return Err(TransferError::source_changed(
                    "this upload was reserved for a different size or digest; a changed source \
                     needs a new upload identifier",
                ));
            }
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
        let mut file = self.open_incomplete(&row)?;
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
            let mut store = self.locked()?;
            store.close_upload(
                row.transfer_id,
                UploadState::Invalidated,
                Some(&reason),
                now,
            )?;
            drop(store);
            let _ = self
                .staging
                .incomplete()
                .remove(&StorageName::derive(row.transfer_id, "").incomplete()?);
            return Err(TransferError::integrity(reason));
        }
        let (preview, preview_unavailable) =
            match crate::preview::generate(file.handle_mut(), &row.declared_media_type) {
                Ok(preview) => (Some(preview), None),
                Err(refusal) => (None, Some(refusal.to_string())),
            };
        let encoded_preview = match &preview {
            Some(preview) => Some(
                kr_cbor::to_canonical_vec(preview)
                    .map_err(|error| TransferError::store(error.to_string()))?,
            ),
            None => None,
        };
        let storage = StorageName::derive(row.transfer_id, &row.original_file_name);
        let expires_at_ms =
            TimestampMs::new(now.get().saturating_add(UNUSED_ATTACHMENT_LIFETIME.get()));
        let mut store = self.locked()?;
        // Rechecked under the lock: a cancellation could have landed while the file was read.
        let row = upload_of(&store, params.transfer_id, actor)?;
        if row.state == UploadState::Published {
            return Ok(UploadFinishResult {
                handle: handle_of(&row)?,
                already_published: true,
                preview_unavailable: Nullable(row.preview_unavailable.clone()),
            });
        }
        if !row.state.accepts_chunks() {
            return Err(TransferError::WrongState {
                transfer: row.transfer_id.to_string(),
                state: row.state.as_str(),
                detail: "it cannot be finished".to_owned(),
            });
        }
        // The intent is durable before the file moves, so an interrupted publish is resolved from
        // the record rather than guessed at.
        store.begin_publish(
            row.transfer_id,
            digest,
            encoded_preview.as_deref(),
            preview_unavailable.as_deref(),
            now,
        )?;
        drop(file);
        self.staging.incomplete().rename_into(
            &storage.incomplete()?,
            self.staging.complete(),
            &storage.published()?,
        )?;
        store.complete_publish(row.transfer_id, now, expires_at_ms)?;
        drop(store);
        let published = self
            .locked()?
            .upload(row.transfer_id)?
            .ok_or_else(|| unknown(row.transfer_id))?;
        // The published file is read back through the completed area's own handle, so what the
        // handle describes is an object this host has opened rather than a row it trusts.
        let mut file = self.open_published(&published)?;
        file.revalidate()?;
        if file.byte_len() != published.declared_byte_len {
            return Err(TransferError::integrity(
                "the published file is not the size that was verified",
            ));
        }
        Ok(UploadFinishResult {
            handle: handle_of(&published)?,
            already_published: false,
            preview_unavailable: Nullable(preview_unavailable),
        })
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
    ) -> Result<UploadCancelResult> {
        let now = self.clock.now_ms();
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
            // repeated cancellation has to be.
            UploadState::Cancelled | UploadState::Invalidated | UploadState::Expired => {
                return Ok(UploadCancelResult {
                    transfer_id: row.transfer_id,
                    state: row.state,
                    released_byte_len: U64::ZERO,
                });
            }
            UploadState::Receiving | UploadState::Publishing => {}
        }
        store.close_upload(row.transfer_id, UploadState::Cancelled, None, now)?;
        drop(store);
        let storage = StorageName::derive(row.transfer_id, &row.original_file_name);
        let _ = self.staging.incomplete().remove(&storage.incomplete()?);
        Ok(UploadCancelResult {
            transfer_id: row.transfer_id,
            state: UploadState::Cancelled,
            released_byte_len: U64::new(row.reserved_byte_len),
        })
    }

    /// Returns one published attachment's handle.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::UnknownTransfer`] when nothing is named, or
    /// [`TransferError::WrongState`] when the upload is not published.
    pub fn attachment_handle(&self, transfer_id: TransferId) -> Result<AttachmentHandle> {
        let store = self.locked()?;
        let row = store
            .upload(transfer_id)?
            .ok_or_else(|| unknown(transfer_id))?;
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
        self.locked()?.insert_draft(&row)?;
        Ok(DraftCreateResult {
            draft: self.draft_record(&row, &[])?,
        })
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
    ) -> Result<DraftUpdateResult> {
        let now = self.clock.now_ms();
        let mut store = self.locked()?;
        let row = draft_of(&store, params.draft_id, actor)?;
        self.check_environment(row.environment_id)?;
        let revision = store
            .update_draft(params.draft_id, params.expected_revision, &params.text, now)?
            .ok_or_else(|| TransferError::DraftConflict {
                detail: format!(
                    "this draft is at revision {} and the update expects {}",
                    row.revision.get(),
                    params.expected_revision.get()
                ),
            })?;
        let bindings = store.bindings(params.draft_id)?;
        let handles = self.handles_of(&store, &bindings)?;
        drop(store);
        let updated = DraftRow {
            revision,
            text: params.text.clone(),
            updated_at_ms: now,
            ..row
        };
        Ok(DraftUpdateResult {
            draft: self.compose_draft(&updated, &bindings, &handles)?,
        })
    }

    /// Binds a completed attachment to a draft and records that the adapter was asked.
    ///
    /// This is the whole of what the transfer service does about insertion. The binding starts at
    /// [`InsertionState::Recorded`], which says an adapter was asked and nothing more; the agent
    /// has accepted nothing until [`Self::record_insertion_outcome`] is given upstream evidence.
    /// Nothing here submits a prompt.
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
    ) -> Result<AgentDraftAddAttachmentResult> {
        let now = self.clock.now_ms();
        let handle = self.attachment_handle(params.transfer_id)?;
        check_contribution(&params.contribution, &handle)?;
        let mut store = self.locked()?;
        let row = draft_of(&store, params.draft_id, actor)?;
        self.check_environment(row.environment_id)?;
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
        // A method that needs the agent to open the file gets a narrow read grant over that one
        // file, inside the staging area and outside every repository. A typed submission needs no
        // path at all and is given none.
        let grant = if params.contribution.insertion_method.needs_read_grant() {
            Some(self.issue_read_grant(
                &store,
                &handle,
                params.contribution.insertion_method,
                now,
            )?)
        } else {
            None
        };
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
            bound_at_ms: now,
            ordinal,
        };
        let revision = store
            .bind_attachment(&binding, params.expected_revision)?
            .ok_or_else(|| TransferError::DraftConflict {
                detail: format!(
                    "this draft is at revision {} and the binding expects {}",
                    row.revision.get(),
                    params.expected_revision.get()
                ),
            })?;
        let bindings = store.bindings(params.draft_id)?;
        let handles = self.handles_of(&store, &bindings)?;
        drop(store);
        let updated = DraftRow {
            revision,
            updated_at_ms: now,
            ..row
        };
        let draft = self.compose_draft(&updated, &bindings, &handles)?;
        let attachment = draft
            .attachments
            .iter()
            .find(|attachment| attachment.handle.transfer_id == params.transfer_id)
            .cloned()
            .ok_or_else(|| TransferError::store("the binding that was written is not readable"))?;
        Ok(AgentDraftAddAttachmentResult { draft, attachment })
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
        store
            .bind_attachment(&binding, row.revision)?
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
        let store = self.locked()?;
        let _ = draft_of(&store, draft_id, actor)?;
        let bindings = store.bindings(draft_id)?;
        for binding in &bindings {
            store.mark_submitted(binding.transfer_id, now)?;
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
        self.compose_draft(&row, &bindings, &handles)
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

    /// Resolves every publication an earlier daemon did not finish.
    ///
    /// A `publishing` row names both the incomplete and the published payload. Whichever exists
    /// says what happened: the published name means the rename landed and only the row is behind,
    /// and the incomplete name means it did not and the verified bytes are still there to move.
    /// A row with neither is invalidated, because a handle whose file is gone is not a handle.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the journal cannot be read or written.
    pub fn recover(&self) -> Result<Recovery> {
        let now = self.clock.now_ms();
        let pending = self.locked()?.uploads_in(&[UploadState::Publishing])?;
        let mut recovery = Recovery::default();
        for row in pending {
            let storage = StorageName::derive(row.transfer_id, &row.original_file_name);
            let published = storage.published()?;
            let incomplete = storage.incomplete()?;
            let expires_at_ms = TimestampMs::new(
                row.published_at_ms
                    .unwrap_or(now)
                    .get()
                    .saturating_add(UNUSED_ATTACHMENT_LIFETIME.get()),
            );
            if self.staging.complete().exists(&published) {
                self.locked()?
                    .complete_publish(row.transfer_id, now, expires_at_ms)?;
                recovery.completed_publications += 1;
            } else if self.staging.incomplete().exists(&incomplete) {
                self.staging.incomplete().rename_into(
                    &incomplete,
                    self.staging.complete(),
                    &published,
                )?;
                self.locked()?
                    .complete_publish(row.transfer_id, now, expires_at_ms)?;
                recovery.completed_publications += 1;
            } else {
                self.locked()?.close_upload(
                    row.transfer_id,
                    UploadState::Invalidated,
                    Some(
                        "the verified payload is not in the staging area, so no handle can name it",
                    ),
                    now,
                )?;
                recovery.unresolved_publications += 1;
            }
        }
        Ok(recovery)
    }

    /// Expires everything whose retention has run out.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the journal cannot be read or written.
    pub fn sweep(&self, retention: &dyn SessionRetention) -> Result<Sweep> {
        let now = self.clock.now_ms();
        let mut sweep = Sweep::default();
        let unfinished = self
            .locked()?
            .uploads_in(&[UploadState::Receiving, UploadState::Publishing])?;
        for row in unfinished {
            if row.expires_at_ms.get() > now.get() {
                continue;
            }
            self.locked()?.close_upload(
                row.transfer_id,
                UploadState::Expired,
                Some("this upload was unfinished for longer than its expiry"),
                now,
            )?;
            let storage = StorageName::derive(row.transfer_id, &row.original_file_name);
            let _ = self.staging.incomplete().remove(&storage.incomplete()?);
            sweep.expired_uploads += 1;
        }
        // Bound to a local first. A guard in the head of a `for` loop lives for the whole body,
        // and the body takes the journal again.
        let published = self.locked()?.uploads_in(&[UploadState::Published])?;
        for row in published {
            // A submitted attachment follows its session, and a session the host still retains
            // keeps it whatever its own expiry says.
            if let Some(session_id) = row.session_id
                && row.submitted_at_ms.is_some()
                && retention.retains(session_id)
            {
                continue;
            }
            if row.expires_at_ms.get() > now.get() {
                continue;
            }
            self.locked()?.close_upload(
                row.transfer_id,
                UploadState::Expired,
                Some("this attachment went unused for longer than its expiry"),
                now,
            )?;
            self.locked()?.revoke_grants_for(row.transfer_id)?;
            let storage = StorageName::derive(row.transfer_id, &row.original_file_name);
            let _ = self.staging.complete().remove(&storage.published()?);
            sweep.expired_attachments += 1;
        }
        let snapshots = self.locked()?.snapshots_in(SnapshotState::Open)?;
        for row in snapshots {
            if row.expires_at_ms.get() > now.get() {
                continue;
            }
            self.release_snapshot(
                &row,
                SnapshotState::Expired,
                Some("this snapshot outlived its expiry"),
                now,
            )?;
            sweep.expired_snapshots += 1;
        }
        let horizon = TimestampMs::new(
            now.get()
                .saturating_sub(kr_protocol::limits::DEDUPLICATION_RETENTION.get()),
        );
        sweep.forgotten_actions = self.locked()?.forget_actions_before(horizon)?;
        Ok(sweep)
    }

    /// Returns a retained mutation outcome for an exact repeat of one action.
    ///
    /// A repeat with the same identifier and a different payload is a reused identifier, which is
    /// refused rather than answered with the first result.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::InvalidArgument`] when the same identifier carried a different
    /// payload, or [`TransferError::StoreUnavailable`] when the read fails.
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
            return Err(TransferError::invalid(format!(
                "this action identifier was already used for {} with a different payload",
                record.method
            )));
        }
        Ok(Some(match (record.result, record.error_code) {
            (Some(result), _) => RetainedOutcome::Ok(result),
            (None, Some(code)) => RetainedOutcome::Error {
                code: code.parse().unwrap_or(ErrorCode::OutcomeUnknown),
                detail: record.error_detail.unwrap_or_default(),
            },
            (None, None) => RetainedOutcome::Error {
                code: ErrorCode::OutcomeUnknown,
                detail: "this action was recorded without an outcome".to_owned(),
            },
        }))
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
    ) -> Result<()> {
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
        self.locked()?.record_action(actor, action_id, &record)
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
            )?;
            let storage = StorageName::derive(row.transfer_id, &row.original_file_name);
            let _ = self.staging.incomplete().remove(&storage.incomplete()?);
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
        Ok(file)
    }

    fn issue_read_grant(
        &self,
        store: &std::sync::MutexGuard<'_, Store>,
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
        store.issue_grant(&row)?;
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

fn upload_of(store: &Store, transfer_id: TransferId, actor: &ActorId) -> Result<UploadRow> {
    let row = store
        .upload(transfer_id)?
        .ok_or_else(|| unknown(transfer_id))?;
    if &row.actor_id != actor {
        return Err(TransferError::PermissionDenied {
            detail: format!("{transfer_id} belongs to another principal"),
        });
    }
    Ok(row)
}

fn draft_of(store: &Store, draft_id: DraftId, actor: &ActorId) -> Result<DraftRow> {
    let row = store
        .draft(draft_id)?
        .ok_or_else(|| TransferError::UnknownDraft {
            draft: draft_id.to_string(),
        })?;
    if &row.actor_id != actor {
        return Err(TransferError::PermissionDenied {
            detail: format!("{draft_id} belongs to another principal"),
        });
    }
    Ok(row)
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
