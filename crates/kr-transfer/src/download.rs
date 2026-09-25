//! Verified downloads: immutable sources, bounded snapshots and the client's own publish.
//!
//! Section 14 makes one distinction do most of the work here. A **published attachment** is already
//! an immutable revision: nothing writes it after it is verified, so it is read where it lies. Any
//! other source is concurrently writable, and an open file handle does not make it otherwise, so
//! the host stages a bounded immutable copy and serves that. Which of the two happened is in the
//! result, never inferred.
//!
//! A snapshot records the source's identity, size and modification time as they were when the copy
//! was taken. If any of them moved by the time the copy finished, the snapshot fails with
//! `SOURCE_CHANGED` and keeps a failed record, rather than serving chunks that came from two
//! versions of a file.
//!
//! [`DownloadWriter`] is the other half, the one a client performs. It verifies every chunk against
//! its own digest, refuses a conflicting duplicate, writes through a temporary file in the
//! destination, checks the total size and the whole-file digest before anything is named, and
//! refuses an existing destination unless the user has taken an explicit overwrite action for that
//! exact destination.

use std::io::Write as _;

use kr_ipc::paths::NameKind;
use kr_protocol::ids::{ActorId, GrantId, TransferId};
use kr_protocol::scalars::{Bytes, Digest256, TimestampMs, U64};
use kr_protocol::transfer::{
    ChunkBitmap, ChunkDescriptor, ChunkLayout, DownloadBeginParams, DownloadBeginResult,
    DownloadChunkParams, DownloadChunkResult, DownloadImmutability, DownloadPlacement,
    DownloadSource, UploadState,
};

use crate::authority::{AuthorisedDirectory, AuthorisedFile, ObjectPolicy, RelativeName};
use crate::error::{Result, TransferError};
use crate::service::{
    TransferService, digest_of, read_at, snapshot_expiry, snapshot_name, unknown, write_at,
};
use crate::staging::StorageName;
use crate::store::{ScopeRow, SnapshotRow, SnapshotState, UploadRow};

/// How much of a source is copied at a time while a snapshot is staged.
const COPY_BUFFER_LEN: usize = 256 * 1024;

impl TransferService {
    /// Opens an immutable source or stages a bounded immutable snapshot, and describes its chunks.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::SourceChanged`] when a resumed snapshot is gone or a source moved
    /// while it was staged, [`TransferError::PermissionDenied`] when read authority does not reach
    /// the source, [`TransferError::QuotaExceeded`] when the snapshot would not fit the
    /// environment's budget, and [`TransferError::Concurrency`] at the device's transfer ceiling.
    pub fn download_begin(
        &self,
        actor: &ActorId,
        params: &DownloadBeginParams,
    ) -> Result<DownloadBeginResult> {
        self.check_environment(params.environment_id)?;
        if let Some(transfer_id) = params.resume_transfer_id.0 {
            return self.resume_download(actor, transfer_id);
        }
        let source = params.source.as_ref().ok_or_else(|| {
            TransferError::invalid("a download names a source, or the transfer it resumes")
        })?;
        let now = self.clock.now_ms();
        match source {
            DownloadSource::Attachment { transfer_id } => {
                self.open_attachment_source(actor, params, *transfer_id, now)
            }
            DownloadSource::Scope {
                scope_id,
                relative_path,
            } => self.stage_snapshot(actor, params, *scope_id, relative_path, now),
        }
    }

    /// Reads one chunk of an open snapshot, rechecking read authority first.
    ///
    /// Read authority is checked on every request, not once at the start: a revoked scope stops
    /// further bytes, and an attachment whose retention ended stops them too.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::PermissionDenied`] when authority no longer reaches the source,
    /// [`TransferError::SourceChanged`] for a snapshot that is gone or expired,
    /// [`TransferError::Integrity`] when the bytes no longer match the recorded digest, and
    /// [`TransferError::InvalidArgument`] for an index the layout does not have.
    pub fn download_chunk(
        &self,
        actor: &ActorId,
        params: &DownloadChunkParams,
    ) -> Result<DownloadChunkResult> {
        let now = self.clock.now_ms();
        let row = self.open_snapshot(actor, params.transfer_id, now)?;
        let recorded = self
            .locked()?
            .snapshot_chunk(params.transfer_id, params.index.get())?
            .ok_or_else(|| {
                TransferError::invalid(format!("this transfer has no chunk {}", params.index.get()))
            })?;
        let layout = ChunkLayout::for_length(row.byte_len);
        let offset = layout.offset_of(params.index.get()).ok_or_else(|| {
            TransferError::invalid(format!("this transfer has no chunk {}", params.index.get()))
        })?;
        let mut file = self.open_snapshot_payload(&row)?;
        let bytes = read_at(&mut file, offset, recorded.byte_len.get())?;
        let digest = Digest256::from_bytes(kr_cbor::sha256(bytes.as_slice()));
        if digest != recorded.digest {
            let reason = format!(
                "chunk {} of this transfer no longer matches the digest recorded for it",
                params.index.get()
            );
            self.release_snapshot(&row, SnapshotState::Failed, Some(&reason), now)?;
            return Err(TransferError::integrity(reason));
        }
        Ok(DownloadChunkResult {
            transfer_id: row.transfer_id,
            chunk: recorded,
            bytes,
        })
    }

    /// Releases a snapshot the client has finished with.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::UnknownTransfer`] when this principal has no such transfer. A
    /// transfer another principal opened is refused by the same answer: a transfer identifier is
    /// opaque, and which identifiers exist is not something a caller learns by asking.
    pub fn download_release(&self, actor: &ActorId, transfer_id: TransferId) -> Result<()> {
        let now = self.clock.now_ms();
        let row = {
            let store = self.locked()?;
            snapshot_of(&store, transfer_id, actor)?
        };
        if !row.state.holds_bytes() {
            return Ok(());
        }
        self.release_snapshot(&row, SnapshotState::Released, None, now)
    }

    /// Closes a snapshot and removes whatever it staged.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the row cannot be written.
    pub(crate) fn release_snapshot(
        &self,
        row: &SnapshotRow,
        state: SnapshotState,
        reason: Option<&str>,
        now: TimestampMs,
    ) -> Result<()> {
        // Before the journal's lock, and held across the removal, which is the order every path
        // that needs both locks uses. A caller that already holds it uses
        // [`Self::release_snapshot_held`] instead; this mutex is not reentrant.
        let payloads = self
            .payloads
            .lock()
            .map_err(|_| crate::service::poisoned())?;
        let outcome = self.release_snapshot_held(row, state, reason, now);
        drop(payloads);
        outcome
    }

    /// Closes a snapshot and removes whatever it staged, with the payload lock already held.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the row cannot be written.
    pub(crate) fn release_snapshot_held(
        &self,
        row: &SnapshotRow,
        state: SnapshotState,
        reason: Option<&str>,
        now: TimestampMs,
    ) -> Result<()> {
        if !self
            .locked()?
            .close_snapshot(row.transfer_id, state, reason, now)?
        {
            // Something else closed it first. Its payload is that caller's to remove.
            return Ok(());
        }
        self.discard_snapshot_payload(row)
    }

    fn resume_download(
        &self,
        actor: &ActorId,
        transfer_id: TransferId,
    ) -> Result<DownloadBeginResult> {
        let now = self.clock.now_ms();
        let row = self.open_snapshot(actor, transfer_id, now)?;
        Ok(DownloadBeginResult {
            transfer_id: row.transfer_id,
            environment_id: row.environment_id,
            immutability: row.immutability,
            byte_len: U64::new(row.byte_len),
            content_digest: row.content_digest,
            layout: ChunkLayout::for_length(row.byte_len),
            chunks: self.locked()?.snapshot_chunks(transfer_id)?,
            expires_at_ms: row.expires_at_ms,
            resumed: true,
        })
    }

    /// Returns an open snapshot whose read authority still reaches its source.
    fn open_snapshot(
        &self,
        actor: &ActorId,
        transfer_id: TransferId,
        now: TimestampMs,
    ) -> Result<SnapshotRow> {
        let row = {
            let store = self.locked()?;
            snapshot_of(&store, transfer_id, actor)?
        };
        self.check_environment(row.environment_id)?;
        match row.state {
            SnapshotState::Open => {}
            // A snapshot that is gone is never silently replaced. The client asks for a new one.
            state => {
                return Err(TransferError::source_changed(format!(
                    "transfer {transfer_id} is {}, so it serves no more bytes; a new transfer is \
                     required",
                    state.as_str()
                )));
            }
        }
        if row.expires_at_ms.get() <= now.get() {
            self.release_snapshot(
                &row,
                SnapshotState::Expired,
                Some("this snapshot outlived its expiry"),
                now,
            )?;
            return Err(TransferError::source_changed(format!(
                "transfer {transfer_id} has expired; a new transfer is required"
            )));
        }
        // Read authority is rechecked here, on every request, rather than trusted from the start.
        match row.immutability {
            DownloadImmutability::ImmutableSource => {
                let source = row.source_transfer_id.ok_or_else(|| {
                    TransferError::store("an immutable-source transfer names no attachment")
                })?;
                let upload = {
                    let store = self.locked()?;
                    crate::service::upload_of(&store, source, actor)?
                };
                if let Err(error) = self.check_source_retention(&upload, now) {
                    let reason = error.to_string();
                    self.release_snapshot(&row, SnapshotState::Failed, Some(&reason), now)?;
                    return Err(TransferError::PermissionDenied { detail: reason });
                }
            }
            DownloadImmutability::ClonedSnapshot | DownloadImmutability::StagedSnapshot => {
                if let Some(scope_id) = row.scope_id {
                    self.authorised_scope(scope_id)?;
                }
            }
        }
        Ok(row)
    }

    /// Serves a published attachment in place.
    ///
    /// Its whole-file digest and its per-chunk digests were recorded when it was verified, and the
    /// object itself is checked against the identity the row recorded, so what is served is the
    /// revision that was verified or the request fails. That is what makes it an immutable source
    /// revision for this purpose. It is not a claim that another process under the same
    /// operating-system user cannot touch the file; such a change makes the affected chunk fail
    /// integrity instead of being served, and the result says which mechanism produced it.
    fn open_attachment_source(
        &self,
        actor: &ActorId,
        params: &DownloadBeginParams,
        source: TransferId,
        now: TimestampMs,
    ) -> Result<DownloadBeginResult> {
        let upload = {
            let store = self.locked()?;
            let limits = store.limits()?;
            let open = store.open_transfers(actor)?;
            if open >= limits.max_concurrent_transfers {
                return Err(TransferError::Concurrency {
                    detail: format!(
                        "this device already holds {open} of {} concurrent transfers; finish or \
                         release one first",
                        limits.max_concurrent_transfers
                    ),
                });
            }
            // The same actor-authorised lookup every upload method uses. A transfer identifier is
            // opaque; it is not a credential, and another principal's attachment is refused
            // exactly as one that does not exist is.
            crate::service::upload_of(&store, source, actor)?
        };
        self.check_environment(upload.environment_id)?;
        self.check_source_retention(&upload, now)?;
        // Opened through the completed area's own handle and checked against the identity the row
        // recorded, so what is served is the object that was verified.
        let mut file = self.open_published(&upload)?;
        let byte_len = file.revalidate()?;
        if byte_len != upload.declared_byte_len {
            return Err(TransferError::integrity(format!(
                "attachment {source} is {byte_len} bytes and its record says {}",
                upload.declared_byte_len
            )));
        }
        let layout = ChunkLayout::for_length(byte_len);
        // The upload's own per-chunk journal describes these exact bytes at this exact layout, so
        // a complete journal is reused and only an incomplete one is recomputed.
        let recorded = self.locked()?.chunks(source)?;
        let chunks = if recorded.len() as u64 == layout.chunk_count.get()
            && recorded
                .iter()
                .enumerate()
                .all(|(position, chunk)| chunk.index.get() == position as u64)
        {
            recorded
        } else {
            chunk_digests(&mut file, layout)?
        };
        let transfer_id = TransferId::new(kr_ipc::new_uuid());
        let row = SnapshotRow {
            transfer_id,
            environment_id: self.environment_id,
            actor_id: actor.clone(),
            device_id: params.device_id.0,
            scope_id: None,
            source_transfer_id: Some(source),
            // The fields below are the same whatever the admission decides; the row is built here
            // so the check and the insert can be one transaction.
            immutability: DownloadImmutability::ImmutableSource,
            source_label: format!("attachment {source}"),
            stored_name: None,
            byte_len,
            content_digest: upload.content_digest.unwrap_or(upload.declared_digest),
            // The bytes are already charged to the attachment that holds them. Charging them again
            // would count one file twice against the environment's budget.
            reserved_byte_len: 0,
            state: SnapshotState::Open,
            cleanup_pending: false,
            failure_reason: None,
            source_identity: Some(file.identity()),
            source_modified_ms: None,
            created_at_ms: now,
            expires_at_ms: snapshot_expiry(now),
        };
        {
            // The ceiling is checked again here, in the same transaction as the row that occupies
            // a slot. Checked only at the start, two concurrent downloads could each see the last
            // slot free and both take it.
            let mut store = self.locked()?;
            let limits = store.limits()?;
            let open = store.open_transfers(actor)?;
            if open >= limits.max_concurrent_transfers {
                return Err(TransferError::Concurrency {
                    detail: format!(
                        "this device already holds {open} of {} concurrent transfers; finish or \
                         release one first",
                        limits.max_concurrent_transfers
                    ),
                });
            }
            store.insert_snapshot(&row, &chunks)?;
        }
        Ok(DownloadBeginResult {
            transfer_id,
            environment_id: self.environment_id,
            immutability: DownloadImmutability::ImmutableSource,
            byte_len: U64::new(byte_len),
            content_digest: row.content_digest,
            layout,
            chunks,
            expires_at_ms: row.expires_at_ms,
            resumed: false,
        })
    }

    /// Refuses an attachment whose own retention has run out.
    ///
    /// The sweep is a schedule, not the policy. An attachment past its deadline stops serving the
    /// moment it is past it, whether or not a sweep has come round.
    fn check_source_retention(&self, upload: &UploadRow, now: TimestampMs) -> Result<()> {
        if upload.state != UploadState::Published {
            return Err(TransferError::WrongState {
                transfer: upload.transfer_id.to_string(),
                state: upload.state.as_str(),
                detail: "only a published attachment can be downloaded".to_owned(),
            });
        }
        if upload.submitted_at_ms.is_none() && upload.expires_at_ms.get() <= now.get() {
            return Err(TransferError::PermissionDenied {
                detail: format!(
                    "attachment {}'s retention has ended, so it serves no more bytes",
                    upload.transfer_id
                ),
            });
        }
        Ok(())
    }

    /// Stages an immutable snapshot of a concurrently writable source.
    ///
    /// The order is what makes the reservation honest. The row exists, in
    /// [`SnapshotState::Reserving`], with its bytes charged, **before** anything is copied: two
    /// requests that both passed a quota check and then both copied would otherwise exceed the
    /// environment's budget together, and an upload admitted during either copy would not see it.
    ///
    /// The copy is a filesystem clone where the platform and the filesystem offer one, and a
    /// bounded byte copy where they do not. Which of the two happened is in the result, because
    /// only the clone is atomic with respect to the source.
    fn stage_snapshot(
        &self,
        actor: &ActorId,
        params: &DownloadBeginParams,
        scope_id: GrantId,
        relative_path: &str,
        now: TimestampMs,
    ) -> Result<DownloadBeginResult> {
        let scope = self.authorised_scope(scope_id)?;
        let name = RelativeName::parse(relative_path)?;
        let mut source = scope.open_read(&name, ObjectPolicy::ReadableFile)?;
        source.check_environment(self.environment_id)?;
        let before = source_state(&mut source)?;
        let transfer_id = TransferId::new(kr_ipc::new_uuid());
        let storage = StorageName::derive(transfer_id, relative_path);
        let stored = storage.published()?;
        let reserved = SnapshotRow {
            transfer_id,
            environment_id: self.environment_id,
            actor_id: actor.clone(),
            device_id: params.device_id.0,
            scope_id: Some(scope_id),
            source_transfer_id: None,
            immutability: DownloadImmutability::StagedSnapshot,
            source_label: relative_path.to_owned(),
            stored_name: Some(stored.as_str().to_owned()),
            byte_len: before.byte_len,
            // Set when the copy is verified. Until then the row is `reserving` and serves nothing.
            content_digest: Digest256::from_bytes([0; 32]),
            reserved_byte_len: before.byte_len,
            state: SnapshotState::Reserving,
            cleanup_pending: false,
            failure_reason: None,
            source_identity: Some(before.identity),
            source_modified_ms: before.modified_ms,
            created_at_ms: now,
            expires_at_ms: snapshot_expiry(now),
        };
        {
            let mut store = self.locked()?;
            let limits = store.limits()?;
            if before.byte_len > limits.max_file_len {
                return Err(TransferError::QuotaExceeded {
                    detail: format!(
                        "a snapshot is at most {} bytes in this environment, and this source is {}",
                        limits.max_file_len, before.byte_len
                    ),
                });
            }
            let staged = store.staged_byte_len()?;
            if staged.saturating_add(before.byte_len) > limits.max_staged_len {
                return Err(TransferError::QuotaExceeded {
                    detail: format!(
                        "this environment has {staged} of {} staged bytes, and a {}-byte snapshot \
                         would exceed it",
                        limits.max_staged_len, before.byte_len
                    ),
                });
            }
            let open = store.open_transfers(actor)?;
            if open >= limits.max_concurrent_transfers {
                return Err(TransferError::Concurrency {
                    detail: format!(
                        "this device already holds {open} of {} concurrent transfers; finish or \
                         release one first",
                        limits.max_concurrent_transfers
                    ),
                });
            }
            // The reservation and the checks it passed are one transaction.
            store.insert_snapshot(&reserved, &[])?;
        }
        match self.fill_snapshot(&reserved, &stored, &mut source, before, now) {
            Ok(result) => Ok(result),
            Err(error) => {
                // The reservation goes with the failure, and its payload with it. Whether this
                // call was the one that closed the row does not change whose file it is, so the
                // removal does not depend on that answer — but it does depend on the close having
                // been written at all. A close that failed leaves the row and the payload for
                // recovery rather than releasing bytes whose file is gone.
                // Bound to a local first: a guard in the head of a `match` lives for the whole
                // expression, and the removal below takes the journal again.
                let closed = {
                    let mut store = self.locked()?;
                    store.close_snapshot(
                        transfer_id,
                        SnapshotState::Failed,
                        Some(&error.to_string()),
                        now,
                    )
                };
                match closed {
                    Ok(_) => {
                        let _ = self.discard_snapshot_payload(&reserved);
                        Err(error)
                    }
                    // The journal failed, which is the failure that leaves something behind: the
                    // row still says this snapshot holds bytes and the payload is still there for
                    // recovery. It is reported instead of the one that started this, which it
                    // carries as the reason the snapshot was being failed at all.
                    Err(close) => Err(TransferError::store(format!(
                        "{close}, while recording that {} failed: {error}",
                        reserved.source_label
                    ))),
                }
            }
        }
    }

    /// Copies the source into the reserved snapshot and opens it for serving.
    fn fill_snapshot(
        &self,
        reserved: &SnapshotRow,
        stored: &RelativeName,
        source: &mut AuthorisedFile,
        before: SourceState,
        now: TimestampMs,
    ) -> Result<DownloadBeginResult> {
        let cloned = if self
            .copy_snapshots
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            Err(std::io::Error::other("this service was asked to copy"))
        } else {
            clone_file(source, self.staging.snapshots(), stored)
        };
        let (immutability, copied) = match cloned {
            // A clone is atomic with respect to the source, so nothing a writer does afterwards
            // can reach it and the before-and-after comparison is a formality.
            Ok(()) => (DownloadImmutability::ClonedSnapshot, before.byte_len),
            Err(_) => {
                let mut destination = self.staging.snapshots().create_new(stored)?;
                let copied = copy_bounded(source, &mut destination, before.byte_len)?;
                (DownloadImmutability::StagedSnapshot, copied)
            }
        };
        // The name is durable before the record that says it serves bytes.
        self.staging.snapshots().sync(NameKind::File)?;
        let mut destination = self
            .staging
            .snapshots()
            .open_read(stored, ObjectPolicy::HostOwnedFile)?;
        // The payload's own length, before anything reads all of it. A source that grew between
        // the reservation and the clone would otherwise be hashed in full and only then compared
        // with the bytes the environment reserved for it.
        let staged_len = destination.revalidate()?;
        if staged_len != before.byte_len {
            return Err(TransferError::source_changed(format!(
                "{} was {} bytes when this snapshot was reserved and the snapshot is {staged_len}",
                reserved.source_label, before.byte_len
            )));
        }
        // A clone copies the source's mode bits, so an executable source would otherwise produce
        // an executable payload. The payload policy is this host's, not the source's.
        normalise_payload(&destination)?;
        if immutability == DownloadImmutability::ClonedSnapshot {
            // The copy path flushed the handle it wrote through. A clone wrote through no handle
            // of this host's, so its data is flushed here, before the record that says the
            // snapshot serves bytes. Only a clone: Windows refuses a flush on a handle opened for
            // reading, and Windows has no clone.
            flush_payload(&destination)?;
        }
        let (content_digest, byte_len) = digest_of(&mut destination)?;
        if byte_len != before.byte_len {
            return Err(TransferError::integrity(
                "the staged snapshot is not the size that was copied into it",
            ));
        }
        if immutability == DownloadImmutability::StagedSnapshot {
            // A byte copy is not atomic, so what it produced has to be shown to be one revision
            // of the source rather than assumed to be.
            //
            // The cheap evidence first: an identity, a size or a modification time that moved
            // means the copy may cover two versions.
            let after = source_state(source)?;
            if after != before || copied != before.byte_len {
                return Err(TransferError::source_changed(format!(
                    "{} changed while it was being staged, so this snapshot covers no single \
                     version of it",
                    reserved.source_label
                )));
            }
            // Then the evidence that does not depend on metadata at all. A writer that rewrote the
            // same number of bytes and restored the modification time passes the comparison above,
            // so the source is read again and its digest compared with the copy's: equal digests
            // mean the copy is byte-for-byte a state the source actually held.
            let (source_digest, source_len) = digest_bounded(source, before.byte_len)?;
            if source_len != byte_len || source_digest != content_digest {
                return Err(TransferError::source_changed(format!(
                    "{} does not match the copy taken of it, so this snapshot covers no single \
                     version of it",
                    reserved.source_label
                )));
            }
        }
        let layout = ChunkLayout::for_length(byte_len);
        let chunks = chunk_digests(&mut destination, layout)?;
        {
            let mut store = self.locked()?;
            if !store.open_snapshot_row(reserved.transfer_id, content_digest, &chunks, now)? {
                return Err(TransferError::source_changed(
                    "this snapshot was closed while it was being staged",
                ));
            }
            if immutability != reserved.immutability {
                store.set_snapshot_immutability(reserved.transfer_id, immutability)?;
            }
        }
        Ok(DownloadBeginResult {
            transfer_id: reserved.transfer_id,
            environment_id: self.environment_id,
            immutability,
            byte_len: U64::new(byte_len),
            content_digest,
            layout,
            chunks,
            expires_at_ms: reserved.expires_at_ms,
            resumed: false,
        })
    }

    /// Removes a snapshot's payload and releases its reservation, in that order.
    pub(crate) fn discard_snapshot_payload(&self, row: &SnapshotRow) -> Result<()> {
        if row.immutability.is_staged()
            && let Some(stored) = &row.stored_name
        {
            let name = snapshot_name(row.transfer_id, stored)?;
            self.staging.snapshots().remove(&name)?;
            self.staging.snapshots().sync(NameKind::File)?;
        }
        self.locked()?.release_snapshot_payload(row.transfer_id)
    }

    /// Returns a scope's opened directory, checked against its record on every use.
    ///
    /// Nothing is cached. A revocation is a row, so every use reads that row; a cache would have to
    /// be kept coherent with it, and a reader that installed an entry between another thread's read
    /// and its revocation would serve bytes from a scope that no longer exists. An open is
    /// microseconds, and a revoked scope stops bytes at once.
    ///
    /// The reopened directory is checked against the identity its registration recorded, so a
    /// rename, a case alias or a replacement directory at the same path does not extend the grant.
    pub(crate) fn authorised_scope(&self, scope_id: GrantId) -> Result<AuthorisedDirectory> {
        let row: ScopeRow =
            self.locked()?
                .scope(scope_id)?
                .ok_or_else(|| TransferError::UnknownScope {
                    scope: scope_id.to_string(),
                })?;
        if row.revoked {
            return Err(TransferError::UnknownScope {
                scope: scope_id.to_string(),
            });
        }
        self.check_environment(row.environment_id)?;
        let directory = AuthorisedDirectory::open_root(
            self.environment_id,
            std::path::Path::new(&row.root_path),
        )?;
        directory.check_identity(row.root_identity)?;
        Ok(directory)
    }

    fn open_snapshot_payload(&self, row: &SnapshotRow) -> Result<AuthorisedFile> {
        match row.immutability {
            DownloadImmutability::ImmutableSource => {
                let source = row.source_transfer_id.ok_or_else(|| {
                    TransferError::store("an immutable-source transfer names no attachment")
                })?;
                let upload = self
                    .locked()?
                    .upload(source)?
                    .ok_or_else(|| unknown(source))?;
                self.open_published(&upload)
            }
            DownloadImmutability::ClonedSnapshot | DownloadImmutability::StagedSnapshot => {
                let stored = row.stored_name.as_deref().ok_or_else(|| {
                    TransferError::store("a staged snapshot names no payload file")
                })?;
                let name = snapshot_name(row.transfer_id, stored)?;
                let file = self
                    .staging
                    .snapshots()
                    .open_read(&name, ObjectPolicy::HostOwnedFile)?;
                file.check_environment(row.environment_id)?;
                Ok(file)
            }
        }
    }
}

/// Clones a source into a snapshot payload, where the platform and filesystem offer a clone.
///
/// A copy-on-write clone is atomic with respect to the source: the snapshot is one revision of it
/// whatever a writer does next. Apple platforms have `clonefile` on APFS; Linux has the `FICLONE`
/// ioctl on btrfs and XFS. Everywhere else, and on a filesystem without it, this fails and the
/// caller falls back to a bounded byte copy whose weaker guarantee the result names.
#[cfg(target_vendor = "apple")]
fn clone_file(
    source: &AuthorisedFile,
    destination: &AuthorisedDirectory,
    name: &RelativeName,
) -> std::io::Result<()> {
    use std::os::fd::AsFd as _;

    rustix::fs::fclonefileat(
        source.handle().as_fd(),
        destination.handle().as_fd(),
        name.as_str(),
        rustix::fs::CloneFlags::empty(),
    )
    .map_err(std::io::Error::from)
}

#[cfg(target_os = "linux")]
fn clone_file(
    source: &AuthorisedFile,
    destination: &AuthorisedDirectory,
    name: &RelativeName,
) -> std::io::Result<()> {
    use std::os::fd::AsFd as _;

    // The destination has to exist before the ioctl, and it has to be one this host created.
    let created = destination
        .create_new(name)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    match rustix::fs::ioctl_ficlone(created.handle().as_fd(), source.handle().as_fd()) {
        Ok(()) => Ok(()),
        Err(error) => {
            drop(created);
            let _ = destination.remove(name);
            Err(std::io::Error::from(error))
        }
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn clone_file(
    _source: &AuthorisedFile,
    _destination: &AuthorisedDirectory,
    _name: &RelativeName,
) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "this platform offers no filesystem clone",
    ))
}

/// Flushes a cloned payload's data to storage.
///
/// A flush through a handle opened for reading is a Unix operation; Windows requires write access
/// for it, and Windows never takes the clone path this is for.
#[cfg(unix)]
fn flush_payload(file: &AuthorisedFile) -> Result<()> {
    use std::os::fd::AsFd as _;

    rustix::fs::fsync(file.handle().as_fd())
        .map_err(|error| TransferError::staging(std::io::Error::from(error)))
}

#[cfg(not(unix))]
fn flush_payload(_file: &AuthorisedFile) -> Result<()> {
    Ok(())
}

/// Digests at most `bound` bytes of a file, refusing one that has more.
///
/// A verification read is work, and work a source can decide the size of is work this host does
/// not do. The source was admitted at a length; a source with more bytes than that is one that
/// grew, which is the answer rather than a longer read.
fn digest_bounded(file: &mut AuthorisedFile, bound: u64) -> Result<(Digest256, u64)> {
    use sha2::Digest as _;
    use std::io::{Read as _, Seek as _, SeekFrom};

    file.handle_mut()
        .seek(SeekFrom::Start(0))
        .map_err(TransferError::staging)?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_LEN];
    let mut read_total = 0_u64;
    loop {
        let read = file
            .handle_mut()
            .read(&mut buffer)
            .map_err(TransferError::staging)?;
        if read == 0 {
            break;
        }
        read_total = read_total.saturating_add(read as u64);
        if read_total > bound {
            return Err(TransferError::source_changed(
                "the source grew past the length this transfer was admitted at",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok((Digest256::from_bytes(digest), read_total))
}

/// Applies this host's payload permissions to a staged snapshot.
///
/// A copy-on-write clone carries the source's mode bits across, so a clone of a world-readable or
/// executable file would be a payload with those permissions. Every other payload this service
/// creates is owner-only and never executable, and a snapshot is no different.
#[cfg(unix)]
fn normalise_payload(file: &AuthorisedFile) -> Result<()> {
    use std::os::fd::AsFd as _;

    rustix::fs::fchmod(
        file.handle().as_fd(),
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|error| TransferError::staging(std::io::Error::from(error)))
}

/// Windows has no mode bits, and a clone there is a byte copy into a file this host created, which
/// already carries the staging area's inherited owner-only entry.
#[cfg(not(unix))]
fn normalise_payload(_file: &AuthorisedFile) -> Result<()> {
    Ok(())
}

/// Returns one snapshot, for the principal that opened it.
///
/// Another principal's snapshot is refused exactly as one that does not exist is.
fn snapshot_of(
    store: &crate::store::Store,
    transfer_id: TransferId,
    actor: &ActorId,
) -> Result<SnapshotRow> {
    match store.snapshot(transfer_id)? {
        Some(row) if &row.actor_id == actor => Ok(row),
        _ => Err(unknown(transfer_id)),
    }
}

/// The source facts a snapshot is checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceState {
    identity: crate::authority::ObjectIdentity,
    byte_len: u64,
    modified_ms: Option<i64>,
}

fn source_state(file: &mut AuthorisedFile) -> Result<SourceState> {
    let byte_len = file.revalidate()?;
    let modified_ms = file
        .handle()
        .metadata()
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|time| time.into_std().duration_since(std::time::UNIX_EPOCH).ok())
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX));
    Ok(SourceState {
        identity: file.identity(),
        byte_len,
        modified_ms,
    })
}

/// Copies at most `bound` bytes from one handle to another, refusing a source that grew.
fn copy_bounded(
    source: &mut AuthorisedFile,
    destination: &mut AuthorisedFile,
    bound: u64,
) -> Result<u64> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    source
        .handle_mut()
        .seek(SeekFrom::Start(0))
        .map_err(TransferError::staging)?;
    let mut buffer = vec![0_u8; COPY_BUFFER_LEN];
    let mut copied = 0_u64;
    loop {
        let read = source
            .handle_mut()
            .read(&mut buffer)
            .map_err(TransferError::staging)?;
        if read == 0 {
            break;
        }
        copied = copied.saturating_add(read as u64);
        if copied > bound {
            return Err(TransferError::source_changed(
                "the source grew past the size the snapshot reserved for it",
            ));
        }
        destination
            .handle_mut()
            .write_all(&buffer[..read])
            .map_err(TransferError::staging)?;
    }
    destination
        .handle_mut()
        .sync_data()
        .map_err(TransferError::staging)?;
    Ok(copied)
}

/// Computes every chunk's digest by reading the file through its own handle.
fn chunk_digests(file: &mut AuthorisedFile, layout: ChunkLayout) -> Result<Vec<ChunkDescriptor>> {
    let mut chunks =
        Vec::with_capacity(usize::try_from(layout.chunk_count.get()).unwrap_or_default());
    for index in 0..layout.chunk_count.get() {
        let offset = layout.offset_of(index).unwrap_or_default();
        let len = layout.length_of(index).unwrap_or_default();
        let bytes = read_at(file, offset, len)?;
        chunks.push(ChunkDescriptor {
            index: U64::new(index),
            byte_len: U64::new(len),
            digest: Digest256::from_bytes(kr_cbor::sha256(bytes.as_slice())),
        });
    }
    Ok(chunks)
}

/// The client half of a verified download.
///
/// Every chunk is verified against its own digest before it is written, a conflicting duplicate
/// fails integrity rather than replacing what was accepted, and the destination is named only after
/// the total size and the whole-file digest both check out. An existing destination is refused
/// unless the placement carries the user's explicit overwrite action.
#[derive(Debug)]
pub struct DownloadWriter<'destination> {
    destination: &'destination AuthorisedDirectory,
    /// The temporary name, taken when the writer publishes or abandons. While it is still here the
    /// writer's own drop removes the file, so an abandoned download leaves no partial name behind.
    temporary: Option<RelativeName>,
    final_name: RelativeName,
    file: Option<AuthorisedFile>,
    layout: ChunkLayout,
    seen: ChunkBitmap,
    placement: DownloadPlacement,
    written: u64,
}

impl<'destination> DownloadWriter<'destination> {
    /// Opens a temporary file in the client's chosen destination.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::Escape`] when the destination name is not one this host writes,
    /// [`TransferError::InvalidArgument`] when the placement does not describe the transfer, and
    /// [`TransferError::PermissionDenied`] when the destination exists and no explicit overwrite
    /// action was taken.
    pub fn open(
        destination: &'destination AuthorisedDirectory,
        placement: &DownloadPlacement,
    ) -> Result<Self> {
        let final_name = RelativeName::parse(&placement.destination_name)?;
        // Checked here so a client learns early, and decided again at the publish, where the link
        // that refuses an existing name is the thing that actually enforces it.
        if destination.occupied(&final_name)? && !placement.allow_overwrite {
            return Err(TransferError::PermissionDenied {
                detail: format!(
                    "{} already exists in this destination, and overwriting it is an action the \
                     user takes explicitly",
                    placement.destination_name
                ),
            });
        }
        let layout = ChunkLayout::for_length(placement.byte_len.get());
        // The temporary name is in the destination itself, so the publish is a rename inside one
        // directory rather than a copy across filesystems.
        let temporary = RelativeName::parse(&format!(
            "{}.{}.part",
            final_name.as_str(),
            crate::staging::StagingArea::random_name()
        ))?;
        let file = destination.create_new(&temporary)?;
        Ok(Self {
            destination,
            temporary: Some(temporary),
            final_name,
            file: Some(file),
            layout,
            seen: ChunkBitmap::empty(layout.chunk_count.get()),
            placement: placement.clone(),
            written: 0,
        })
    }

    /// Returns which chunks have been verified and written.
    #[must_use]
    pub const fn received(&self) -> &ChunkBitmap {
        &self.seen
    }

    /// Verifies one chunk and writes it at its own offset.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::Integrity`] when the bytes do not match their descriptor or a
    /// duplicate conflicts with what was accepted, and [`TransferError::InvalidArgument`] for an
    /// index or a length the layout does not have.
    pub fn write_chunk(&mut self, chunk: &ChunkDescriptor, bytes: &[u8]) -> Result<()> {
        let index = chunk.index.get();
        let expected = self.layout.length_of(index).ok_or_else(|| {
            TransferError::invalid(format!(
                "this download has {} chunks, so there is no chunk {index}",
                self.layout.chunk_count.get()
            ))
        })?;
        if chunk.byte_len.get() != expected || bytes.len() as u64 != expected {
            return Err(TransferError::invalid(format!(
                "chunk {index} of this download is {expected} bytes, and {} arrived",
                bytes.len()
            )));
        }
        let digest = Digest256::from_bytes(kr_cbor::sha256(bytes));
        if digest != chunk.digest {
            return Err(TransferError::integrity(format!(
                "chunk {index} does not match the digest it declares"
            )));
        }
        if self.seen.contains(index) {
            // A duplicate is only harmless when it is the same bytes. Two different ones claiming
            // the same position fail integrity rather than overwriting what was accepted.
            let offset = self.layout.offset_of(index).unwrap_or_default();
            let file = self.handle()?;
            let existing = read_at(file, offset, expected)?;
            if Digest256::from_bytes(kr_cbor::sha256(existing.as_slice())) != digest {
                return Err(TransferError::integrity(format!(
                    "chunk {index} arrived twice with different content"
                )));
            }
            return Ok(());
        }
        let offset = self.layout.offset_of(index).unwrap_or_default();
        let file = self.handle()?;
        write_at(file, offset, bytes)?;
        self.seen.insert(index);
        self.written = self.written.saturating_add(expected);
        Ok(())
    }

    /// Verifies the whole download and names it in the destination.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::Integrity`] when the size or the whole-file digest does not match
    /// the placement, [`TransferError::WrongState`] when chunks are missing, and
    /// [`TransferError::PermissionDenied`] when the destination exists and no explicit overwrite
    /// action was taken.
    pub fn publish(mut self) -> Result<()> {
        if !self.seen.is_complete() {
            return Err(TransferError::WrongState {
                transfer: self.placement.transfer_id.to_string(),
                state: "incomplete",
                detail: format!(
                    "{} of {} chunks are still missing",
                    self.seen.missing().len(),
                    self.layout.chunk_count.get()
                ),
            });
        }
        let file = self.handle()?;
        let verified = file.identity();
        let (digest, byte_len) = digest_of(file)?;
        if byte_len != self.placement.byte_len.get() {
            return Err(TransferError::integrity(format!(
                "this download is {byte_len} bytes and the transfer declared {}",
                self.placement.byte_len.get()
            )));
        }
        if digest != self.placement.content_digest {
            return Err(TransferError::integrity(
                "this download does not match the whole-file digest the transfer declared",
            ));
        }
        let temporary = self
            .temporary
            .clone()
            .ok_or_else(|| TransferError::staging("this download has already been published"))?;
        // Everything above read the open handle, which keeps its object whatever happens to the
        // name. What publishes is the *name*, so the name has to be shown to still hold the
        // object that was verified before it is published: something that took the temporary name
        // in between would otherwise be what the destination ends up holding.
        let staged = self
            .destination
            .open_read(&temporary, ObjectPolicy::ReadableFile)?;
        if staged.identity() != verified {
            return Err(TransferError::integrity(format!(
                "{} no longer holds the object this download verified",
                temporary.as_str()
            )));
        }
        drop(staged);
        if self.placement.allow_overwrite {
            // The user asked for this destination to be replaced. A rename replaces atomically, so
            // there is no moment when the name holds nothing. The handle is closed first, because
            // Windows refuses to replace a name a handle still holds open.
            //
            // This is the one publish that cannot be undone: between the check above and the
            // rename there is no read, but there is also nothing to restore if the name were
            // swapped in that instant, because the file it replaced is the one the user asked to
            // replace.
            self.file = None;
            self.destination
                .rename_into(&temporary, self.destination, &self.final_name)?;
        } else {
            // A link is the one portable atomic no-replace publish: it fails when the name is
            // taken, so a file that appeared while the download ran is never overwritten. There is
            // no check-then-act window to lose.
            match self
                .destination
                .link_into(&temporary, self.destination, &self.final_name)
            {
                Ok(()) => {}
                Err(error) => {
                    return Err(match self.destination.occupied(&self.final_name) {
                        Ok(true) => TransferError::PermissionDenied {
                            detail: format!(
                                "{} exists in this destination, and overwriting it is an action \
                                 the user takes explicitly",
                                self.placement.destination_name
                            ),
                        },
                        _ => TransferError::from(error),
                    });
                }
            }
            // The link named the object this call verified, because the name it copied was
            // checked immediately above. So a destination that now holds something else is one
            // something else replaced *after* this download published, and that file is not this
            // call's to remove: it belongs to whoever wrote it. The refusal says what happened
            // and leaves the destination as it found it.
            let published = self
                .destination
                .open_read(&self.final_name, ObjectPolicy::ReadableFile)?;
            if published.identity() != verified {
                return Err(TransferError::integrity(format!(
                    "{} does not hold the object this download verified, so this transfer \
                     published nothing it can vouch for",
                    self.placement.destination_name
                )));
            }
            drop(published);
            // The temporary name goes only once the published one holds the file.
            self.file = None;
            self.destination.remove(&temporary)?;
        }
        // The name now has to hold the object that was verified. A rename and a link both preserve
        // it, so anything else means something took the name in between.
        let published = self
            .destination
            .open_read(&self.final_name, ObjectPolicy::ReadableFile)?;
        if published.identity() != verified {
            return Err(TransferError::integrity(format!(
                "{} does not hold the object this download verified",
                self.placement.destination_name
            )));
        }
        self.destination.sync(NameKind::File)?;
        // Taken only now. Until this point the drop still owns the temporary name, so a failure
        // anywhere above leaves nothing partial behind.
        self.temporary = None;
        Ok(())
    }

    /// Removes the temporary file and publishes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::Escape`] when the temporary file cannot be removed.
    pub fn abandon(mut self) -> Result<()> {
        self.file = None;
        match self.temporary.take() {
            Some(temporary) => self
                .destination
                .remove(&temporary)
                .map_err(TransferError::from),
            None => Ok(()),
        }
    }

    fn handle(&mut self) -> Result<&mut AuthorisedFile> {
        self.file
            .as_mut()
            .ok_or_else(|| TransferError::staging("this download's file is already closed"))
    }
}

impl Drop for DownloadWriter<'_> {
    fn drop(&mut self) {
        // A writer that is dropped without publishing takes its partial file with it. A client
        // destination is the user's directory, and leaving a half-written name in it is not
        // something a failure should do.
        self.file = None;
        if let Some(temporary) = self.temporary.take() {
            let _ = self.destination.remove(&temporary);
        }
    }
}

/// Reads one whole transfer into a destination, one chunk at a time.
///
/// This is the shape a client performs: begin, then every chunk, then publish. It is here so the
/// contract is exercised by the same code a client uses rather than restated by each of them.
///
/// # Errors
///
/// Returns whatever the service or the writer refused.
pub fn publish_transfer(
    service: &TransferService,
    actor: &ActorId,
    destination: &AuthorisedDirectory,
    placement: &DownloadPlacement,
) -> Result<u64> {
    let begun = service.download_begin(
        actor,
        &DownloadBeginParams {
            environment_id: service.environment_id(),
            resume_transfer_id: kr_protocol::scalars::Nullable::some(placement.transfer_id),
            source: kr_protocol::scalars::Nullable::null(),
            device_id: kr_protocol::scalars::Nullable::null(),
        },
    )?;
    let mut writer = DownloadWriter::open(destination, placement)?;
    for index in 0..begun.layout.chunk_count.get() {
        let chunk = service.download_chunk(
            actor,
            &DownloadChunkParams {
                transfer_id: placement.transfer_id,
                index: U64::new(index),
            },
        )?;
        writer.write_chunk(&chunk.chunk, chunk.bytes.as_slice())?;
    }
    writer.publish()?;
    Ok(begun.byte_len.get())
}

/// Returns the bytes of a chunk sequence, for a caller assembling one in memory.
///
/// Bounded by the caller's own choice of transfer: a client that wants a file on disk uses
/// [`DownloadWriter`] instead, which never holds more than one chunk.
#[must_use]
pub fn concatenate(chunks: &[(ChunkDescriptor, Bytes)]) -> Vec<u8> {
    let mut ordered: Vec<_> = chunks.iter().collect();
    ordered.sort_by_key(|(chunk, _)| chunk.index.get());
    let mut bytes = Vec::new();
    for (_, chunk) in ordered {
        bytes.extend_from_slice(chunk.as_slice());
    }
    bytes
}
