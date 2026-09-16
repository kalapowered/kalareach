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
    TransferService, digest_of, poisoned, read_at, snapshot_expiry, snapshot_name, unknown,
    write_at,
};
use crate::staging::StorageName;
use crate::store::{ScopeRow, SnapshotRow, SnapshotState};

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
        self.check_transfer_ceiling(actor, params.device_id.0)?;
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
    /// Returns [`TransferError::UnknownTransfer`] when nothing is named, or
    /// [`TransferError::PermissionDenied`] when another actor opened it.
    pub fn download_release(&self, actor: &ActorId, transfer_id: TransferId) -> Result<()> {
        let now = self.clock.now_ms();
        let row = self
            .locked()?
            .snapshot(transfer_id)?
            .ok_or_else(|| unknown(transfer_id))?;
        if &row.actor_id != actor {
            return Err(TransferError::PermissionDenied {
                detail: format!("{transfer_id} belongs to another principal"),
            });
        }
        if row.state != SnapshotState::Open {
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
        self.locked()?
            .close_snapshot(row.transfer_id, state, reason, now)?;
        if row.immutability == DownloadImmutability::StagedSnapshot
            && let Some(stored) = &row.stored_name
            && let Ok(name) = snapshot_name(row.transfer_id, stored)
        {
            let _ = self.staging.snapshots().remove(&name);
        }
        Ok(())
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
        let row = self
            .locked()?
            .snapshot(transfer_id)?
            .ok_or_else(|| unknown(transfer_id))?;
        self.check_environment(row.environment_id)?;
        if &row.actor_id != actor {
            return Err(TransferError::PermissionDenied {
                detail: format!("{transfer_id} belongs to another principal"),
            });
        }
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
                let upload = self
                    .locked()?
                    .upload(source)?
                    .ok_or_else(|| unknown(source))?;
                if upload.state != UploadState::Published {
                    let reason = format!(
                        "the attachment behind transfer {transfer_id} is {} and no longer serves \
                         bytes",
                        upload.state.as_str()
                    );
                    self.release_snapshot(&row, SnapshotState::Failed, Some(&reason), now)?;
                    return Err(TransferError::PermissionDenied { detail: reason });
                }
            }
            DownloadImmutability::StagedSnapshot => {
                if let Some(scope_id) = row.scope_id {
                    self.authorised_scope(scope_id)?;
                }
            }
        }
        Ok(row)
    }

    fn check_transfer_ceiling(
        &self,
        actor: &ActorId,
        device_id: Option<kr_protocol::ids::DeviceId>,
    ) -> Result<()> {
        let store = self.locked()?;
        let limits = store.limits()?;
        let open = store.open_transfers(device_id, actor)?;
        if open >= limits.max_concurrent_transfers {
            return Err(TransferError::Concurrency {
                detail: format!(
                    "this device already holds {open} of {} concurrent transfers; finish or \
                     release one first",
                    limits.max_concurrent_transfers
                ),
            });
        }
        Ok(())
    }

    /// Serves a published attachment in place, because it is already an immutable revision.
    fn open_attachment_source(
        &self,
        actor: &ActorId,
        params: &DownloadBeginParams,
        source: TransferId,
        now: TimestampMs,
    ) -> Result<DownloadBeginResult> {
        let upload = self
            .locked()?
            .upload(source)?
            .ok_or_else(|| unknown(source))?;
        self.check_environment(upload.environment_id)?;
        if upload.state != UploadState::Published {
            return Err(TransferError::WrongState {
                transfer: source.to_string(),
                state: upload.state.as_str(),
                detail: "only a published attachment can be downloaded".to_owned(),
            });
        }
        // Opened through the completed area's own handle and revalidated, so what is served is an
        // object this host holds rather than a row it trusts.
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
            immutability: DownloadImmutability::ImmutableSource,
            source_label: format!("attachment {source}"),
            stored_name: None,
            byte_len,
            content_digest: upload.content_digest.unwrap_or(upload.declared_digest),
            // The bytes are already charged to the attachment that holds them. Charging them again
            // would count one file twice against the environment's budget.
            reserved_byte_len: 0,
            state: SnapshotState::Open,
            failure_reason: None,
            source_identity: Some(file.identity()),
            source_modified_ms: None,
            created_at_ms: now,
            expires_at_ms: snapshot_expiry(now),
        };
        self.locked()?.insert_snapshot(&row, &chunks)?;
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

    /// Stages a bounded immutable copy of a concurrently writable source.
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
        {
            let store = self.locked()?;
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
        }
        let transfer_id = TransferId::new(kr_ipc::new_uuid());
        let storage = StorageName::derive(transfer_id, relative_path);
        let stored = storage.published()?;
        let mut destination = self.staging.snapshots().create_new(&stored)?;
        let copy = copy_bounded(&mut source, &mut destination, before.byte_len);
        let copied = match copy {
            Ok(copied) => copied,
            Err(error) => {
                drop(destination);
                let _ = self.staging.snapshots().remove(&stored);
                return Err(error);
            }
        };
        // The source is read again through the same handle. A size, an identity or a modification
        // time that moved means the copy covers two versions, and there is no honest way to serve
        // it. The failure is recorded so the client learns why rather than seeing a silent retry.
        let after = source_state(&mut source)?;
        if after != before || copied != before.byte_len {
            drop(destination);
            let _ = self.staging.snapshots().remove(&stored);
            let reason = format!(
                "{relative_path} changed while it was being staged, so this snapshot covers no \
                 single version of it"
            );
            let failed = SnapshotRow {
                transfer_id,
                environment_id: self.environment_id,
                actor_id: actor.clone(),
                device_id: params.device_id.0,
                scope_id: Some(scope_id),
                source_transfer_id: None,
                immutability: DownloadImmutability::StagedSnapshot,
                source_label: relative_path.to_owned(),
                stored_name: None,
                byte_len: before.byte_len,
                content_digest: Digest256::from_bytes([0; 32]),
                reserved_byte_len: 0,
                state: SnapshotState::Failed,
                failure_reason: Some(reason.clone()),
                source_identity: Some(before.identity),
                source_modified_ms: before.modified_ms,
                created_at_ms: now,
                expires_at_ms: snapshot_expiry(now),
            };
            self.locked()?.insert_snapshot(&failed, &[])?;
            return Err(TransferError::source_changed(reason));
        }
        // The copy is verified through its own handle, so a snapshot something else wrote while it
        // was being staged fails here rather than serving bytes nothing checked.
        let (content_digest, byte_len) = digest_of(&mut destination)?;
        if byte_len != before.byte_len {
            drop(destination);
            let _ = self.staging.snapshots().remove(&stored);
            return Err(TransferError::integrity(
                "the staged snapshot is not the size that was copied into it",
            ));
        }
        let layout = ChunkLayout::for_length(byte_len);
        let chunks = chunk_digests(&mut destination, layout)?;
        let row = SnapshotRow {
            transfer_id,
            environment_id: self.environment_id,
            actor_id: actor.clone(),
            device_id: params.device_id.0,
            scope_id: Some(scope_id),
            source_transfer_id: None,
            immutability: DownloadImmutability::StagedSnapshot,
            source_label: relative_path.to_owned(),
            stored_name: Some(stored.as_str().to_owned()),
            byte_len,
            content_digest,
            reserved_byte_len: byte_len,
            state: SnapshotState::Open,
            failure_reason: None,
            source_identity: Some(before.identity),
            source_modified_ms: before.modified_ms,
            created_at_ms: now,
            expires_at_ms: snapshot_expiry(now),
        };
        if let Err(error) = self.locked()?.insert_snapshot(&row, &chunks) {
            drop(destination);
            let _ = self.staging.snapshots().remove(&stored);
            return Err(error);
        }
        Ok(DownloadBeginResult {
            transfer_id,
            environment_id: self.environment_id,
            immutability: DownloadImmutability::StagedSnapshot,
            byte_len: U64::new(byte_len),
            content_digest,
            layout,
            chunks,
            expires_at_ms: row.expires_at_ms,
            resumed: false,
        })
    }

    /// Returns a scope's opened directory, reopening it when this process has not yet.
    ///
    /// A reopened scope is checked against the identity its registration recorded, so a rename, a
    /// case alias or a replacement directory at the same path does not extend the grant.
    pub(crate) fn authorised_scope(
        &self,
        scope_id: GrantId,
    ) -> Result<std::sync::Arc<AuthorisedDirectory>> {
        if let Some(directory) = self
            .scopes
            .lock()
            .map_err(|_| poisoned())?
            .get(&scope_id)
            .cloned()
        {
            directory.revalidate()?;
            return Ok(directory);
        }
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
        let directory = std::sync::Arc::new(directory);
        self.scopes
            .lock()
            .map_err(|_| poisoned())?
            .insert(scope_id, std::sync::Arc::clone(&directory));
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
            DownloadImmutability::StagedSnapshot => {
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
        if destination.exists(&final_name) && !placement.allow_overwrite {
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
        // Rechecked here, not only at the open: a destination that appeared while the download ran
        // is still the user's to decide about.
        let exists = self.destination.exists(&self.final_name);
        if exists && !self.placement.allow_overwrite {
            return Err(TransferError::PermissionDenied {
                detail: format!(
                    "{} appeared in this destination while the download ran, and overwriting it is \
                     an action the user takes explicitly",
                    self.placement.destination_name
                ),
            });
        }
        let temporary = self
            .temporary
            .take()
            .ok_or_else(|| TransferError::staging("this download has already been published"))?;
        // The handle is closed before the rename, because Windows refuses to replace a name a
        // handle still holds open.
        self.file = None;
        if exists {
            // The explicit overwrite the user asked for. The old name is removed and the verified
            // file takes its place; between the two there is a moment with no file at that name,
            // which is the cost of a rename that has to work the same way on every platform.
            self.destination.remove(&self.final_name)?;
        }
        self.destination
            .rename_into(&temporary, self.destination, &self.final_name)?;
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
