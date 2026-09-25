//! Driving one upload from a local file to a verified attachment handle.
//!
//! Section 14 makes a transfer four methods and four records: `upload.begin` reserves the budget,
//! `upload.chunk` carries the bytes, `upload.finish` publishes the handle, and `upload.status`
//! resolves a reply that was lost. Every graphical client needs that sequence and none of them
//! should write it again, so the sequence lives here, beside the session that carries it.
//!
//! # What this is, and what it is not
//!
//! [`Upload`] is the plan, not the connection. It holds the content, the layout the host chose and
//! the chunks the host has acknowledged, and [`Upload::next`] says what to send now. The caller
//! sends it and hands the answer back through [`Upload::accept`]. Nothing here opens a stream,
//! so a desktop application that carries chunks on its control connection and a client that
//! carries them on the protocol's attachment-chunk stream drive the same plan over their own lane.
//!
//! That separation is also what makes resumption ordinary. A reconnected client rebuilds the plan,
//! feeds it the bitmap `upload.status` returned, and the plan asks only for the chunks the host is
//! still missing.
//!
//! ```text
//! Begin ──▶ Chunk(0) ──▶ Chunk(1) ──▶ … ──▶ Finish ──▶ Done(handle)
//!   ▲          │                                           │
//!   └── status ┴── a lost reply resumes from the bitmap ────┘
//! ```

use kr_protocol::ids::{DeviceId, EnvironmentId, SessionId};
use kr_protocol::limits::UPLOAD_CHUNK_LEN;
use kr_protocol::scalars::{Bytes, Digest256, Nullable, U64};
use kr_protocol::transfer::{
    AttachmentHandle, ChunkBitmap, ChunkDescriptor, ChunkLayout, UploadBeginParams,
    UploadBeginResult, UploadChunkParams, UploadChunkResult, UploadFinishParams,
    UploadFinishResult, UploadStatusResult,
};

use crate::error::{ClientError, Result};

/// The bytes an upload carries, and how they are read.
///
/// A desktop client reads a file the person dropped; a mobile client reads what its picker
/// returned. Both answer the same three questions, so both drive the same plan.
pub trait Content: std::fmt::Debug + Send + Sync {
    /// The whole length, in bytes.
    fn byte_len(&self) -> u64;

    /// The SHA-256 digest of the whole content.
    ///
    /// Declared before the first byte is sent and repeated at `upload.finish`, so a host can
    /// refuse a client that changed its mind about what it was sending.
    fn digest(&self) -> Digest256;

    /// Reads exactly `len` bytes at `offset`.
    ///
    /// # Errors
    ///
    /// Returns a failure when the source cannot produce exactly that range, which ends the upload:
    /// content that changed under a transfer is a new transfer.
    fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>>;
}

/// Content already held in memory.
#[derive(Clone)]
pub struct Held {
    bytes: Vec<u8>,
    digest: Digest256,
}

impl std::fmt::Debug for Held {
    /// How much is held and its digest, never the bytes.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Held")
            .field("bytes", &self.bytes.len())
            .field("digest", &self.digest)
            .finish()
    }
}

impl Held {
    /// Takes ownership of the bytes and digests them once.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        let digest = Digest256::from_bytes(kr_cbor::sha256(&bytes));
        Self { bytes, digest }
    }
}

impl Content for Held {
    fn byte_len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn digest(&self) -> Digest256 {
        self.digest
    }

    fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>> {
        let start = usize::try_from(offset).map_err(|_| out_of_range())?;
        let end = start
            .checked_add(usize::try_from(len).map_err(|_| out_of_range())?)
            .ok_or_else(out_of_range)?;
        self.bytes
            .get(start..end)
            .map(<[u8]>::to_vec)
            .ok_or_else(out_of_range)
    }
}

/// A refusal that leaves the plan exactly as it was.
fn refuse(message: &'static str) -> ClientError {
    ClientError::refusal(
        kr_protocol::error::ErrorCode::InvalidArgument,
        crate::shown::Shown::said(message),
    )
}

fn out_of_range() -> ClientError {
    ClientError::refusal(
        kr_protocol::error::ErrorCode::InvalidArgument,
        crate::shown::Shown::said("the upload asked for a range the content does not hold"),
    )
}

/// What the upload names itself as.
///
/// These are the fields `upload.begin` reserves against, and the ones the published handle repeats.
/// The filename is metadata: the host never builds a storage path from it.
#[derive(Clone, PartialEq, Eq)]
pub struct Subject {
    /// The environment that will own the bytes.
    pub environment_id: EnvironmentId,
    /// The session the upload belongs to, when it has one.
    pub session_id: Option<SessionId>,
    /// The device the host counts its concurrency limit against.
    pub device_id: Option<DeviceId>,
    /// The media type this client believes it is sending.
    pub declared_media_type: String,
    /// The original filename, kept for display.
    pub original_file_name: String,
}

impl std::fmt::Debug for Subject {
    /// Where the upload belongs, and how long its declared names are, never the names: a file
    /// name is a person's own.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Subject")
            .field("environment_id", &self.environment_id)
            .field("session_id", &self.session_id)
            .field("device_id", &self.device_id)
            .field("declared_media_type_bytes", &self.declared_media_type.len())
            .field("original_file_name_bytes", &self.original_file_name.len())
            .finish()
    }
}

/// What the caller should send next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Reserve the transfer.
    Begin(Box<UploadBeginParams>),
    /// Send one chunk.
    Chunk(Box<UploadChunkParams>),
    /// Publish the handle.
    Finish(UploadFinishParams),
    /// Nothing is left to send; the handle is published.
    Done(Box<AttachmentHandle>),
}

/// What one sent step answered with.
#[derive(Clone, Debug)]
pub enum Answer {
    /// The result of `upload.begin`.
    Begun(Box<UploadBeginResult>),
    /// The result of one `upload.chunk`.
    Chunked(Box<UploadChunkResult>),
    /// The result of `upload.finish`.
    Finished(Box<UploadFinishResult>),
    /// The result of `upload.status`, which a client reads after a reply it never saw.
    Status(Box<UploadStatusResult>),
}

/// The state one upload is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Reserving,
    Sending,
    Publishing,
    Published,
}

/// One upload, from the content to the published handle.
#[derive(Debug)]
pub struct Upload {
    subject: Subject,
    content: Box<dyn Content>,
    layout: ChunkLayout,
    sent: Option<ChunkBitmap>,
    transfer_id: Option<kr_protocol::ids::TransferId>,
    handle: Option<AttachmentHandle>,
    phase: Phase,
}

impl Upload {
    /// Plans the upload of `content` under `subject`.
    ///
    /// The layout here is the one the protocol's chunk length implies. The host answers
    /// `upload.begin` with the layout it actually chose, and [`Upload::accept`] adopts that one.
    #[must_use]
    pub fn new(subject: Subject, content: Box<dyn Content>) -> Self {
        let layout = ChunkLayout::for_length(content.byte_len());
        Self {
            subject,
            content,
            layout,
            sent: None,
            transfer_id: None,
            handle: None,
            phase: Phase::Reserving,
        }
    }

    /// The transfer this upload was given, once `upload.begin` has answered.
    #[must_use]
    pub const fn transfer_id(&self) -> Option<&kr_protocol::ids::TransferId> {
        self.transfer_id.as_ref()
    }

    /// Rebuilds a plan for a transfer that was already reserved.
    ///
    /// A client that restarted holds the transfer identity and the same content. It resumes by
    /// building this and feeding it the bitmap `upload.status` returns, which is the only way a
    /// plan may be given a transfer it did not reserve itself.
    #[must_use]
    pub fn resuming(
        subject: Subject,
        content: Box<dyn Content>,
        transfer_id: kr_protocol::ids::TransferId,
    ) -> Self {
        let mut plan = Self::new(subject, content);
        plan.transfer_id = Some(transfer_id);
        plan.phase = Phase::Sending;
        plan.sent = Some(ChunkBitmap::empty(plan.layout.chunk_count.get()));
        plan
    }

    /// The published handle, once there is one.
    #[must_use]
    pub const fn handle(&self) -> Option<&AttachmentHandle> {
        self.handle.as_ref()
    }

    /// How many of the layout's chunks the host has acknowledged.
    #[must_use]
    pub fn acknowledged_chunks(&self) -> u64 {
        let Some(bitmap) = self.sent.as_ref() else {
            return 0;
        };
        (0..self.layout.chunk_count.get())
            .filter(|index| bitmap.contains(*index))
            .count() as u64
    }

    /// The fraction of the content the host has acknowledged, between 0 and 1.
    ///
    /// Empty content is complete as soon as the transfer is reserved, because it has no chunks.
    #[must_use]
    pub fn progress(&self) -> f64 {
        let total = self.layout.chunk_count.get();
        if total == 0 {
            return if self.phase == Phase::Reserving {
                0.0
            } else {
                1.0
            };
        }
        self.acknowledged_chunks() as f64 / total as f64
    }

    /// Says what to send now.
    ///
    /// # Errors
    ///
    /// Returns a failure when the content cannot produce the chunk the layout names.
    pub fn next(&self) -> Result<Step> {
        match self.phase {
            Phase::Reserving => Ok(Step::Begin(Box::new(UploadBeginParams {
                environment_id: self.subject.environment_id,
                session_id: self
                    .subject
                    .session_id
                    .map_or(Nullable::null(), Nullable::some),
                device_id: self
                    .subject
                    .device_id
                    .map_or(Nullable::null(), Nullable::some),
                declared_byte_len: U64::new(self.content.byte_len()),
                declared_digest: self.content.digest(),
                declared_media_type: self.subject.declared_media_type.clone(),
                original_file_name: self.subject.original_file_name.clone(),
            }))),
            Phase::Sending => {
                let transfer_id = self.transfer_id.ok_or_else(|| {
                    ClientError::refusal(
                        kr_protocol::error::ErrorCode::InvalidArgument,
                        crate::shown::Shown::said(
                            "the upload is sending chunks without a transfer identity",
                        ),
                    )
                })?;
                let index = self.next_missing_chunk().ok_or_else(|| {
                    ClientError::refusal(
                        kr_protocol::error::ErrorCode::InvalidArgument,
                        crate::shown::Shown::said("the upload is sending chunks with none missing"),
                    )
                })?;
                Ok(Step::Chunk(Box::new(
                    self.chunk_params(transfer_id, index)?,
                )))
            }
            Phase::Publishing => {
                let transfer_id = self.transfer_id.ok_or_else(|| {
                    ClientError::refusal(
                        kr_protocol::error::ErrorCode::InvalidArgument,
                        crate::shown::Shown::said(
                            "the upload is publishing without a transfer identity",
                        ),
                    )
                })?;
                Ok(Step::Finish(UploadFinishParams {
                    transfer_id,
                    declared_byte_len: U64::new(self.content.byte_len()),
                    declared_digest: self.content.digest(),
                }))
            }
            Phase::Published => {
                let handle = self.handle.clone().ok_or_else(|| {
                    ClientError::refusal(
                        kr_protocol::error::ErrorCode::InvalidArgument,
                        crate::shown::Shown::said("the upload is published without a handle"),
                    )
                })?;
                Ok(Step::Done(Box::new(handle)))
            }
        }
    }

    /// Folds one answer into the plan.
    ///
    /// # Errors
    ///
    /// Returns a failure when the answer names a transfer this plan is not driving, or a bitmap
    /// that does not fit the layout.
    pub fn accept(&mut self, answer: Answer) -> Result<()> {
        match answer {
            Answer::Begun(result) => {
                // A reservation answers a plan that has not reserved yet. One that arrives for a
                // plan already driving a transfer would silently replace it, and the chunks
                // already sent would be sent to a transfer nobody is tracking.
                if self.phase != Phase::Reserving {
                    return Err(refuse("this upload has already been reserved"));
                }
                if result.environment_id != self.subject.environment_id {
                    return Err(refuse("the reservation names another environment"));
                }
                if result.layout.byte_len() != self.content.byte_len() {
                    return Err(refuse(
                        "the layout the host chose does not cover this content",
                    ));
                }
                self.layout = result.layout;
                self.transfer_id = Some(result.transfer_id);
                self.adopt_bitmap(&result.received_chunks)?;
                self.advance();
                Ok(())
            }
            Answer::Chunked(result) => {
                self.same_transfer(&result.transfer_id)?;
                self.adopt_bitmap(&result.received_chunks)?;
                self.advance();
                Ok(())
            }
            Answer::Finished(result) => {
                self.accept_handle(&result.handle)?;
                Ok(())
            }
            Answer::Status(result) => {
                self.same_transfer(&result.transfer_id)?;
                if let Some(handle) = result.handle.as_ref() {
                    self.accept_handle(handle)?;
                    return Ok(());
                }
                // A transfer the host has ended cannot be continued. Section 14 spends the
                // identifier in each of these states, so the honest answer is that this upload is
                // over and a new one is required, rather than a plan that keeps asking.
                match result.state {
                    kr_protocol::transfer::UploadState::Receiving
                    | kr_protocol::transfer::UploadState::Publishing => {}
                    ended => {
                        return Err(refuse(match ended {
                            kr_protocol::transfer::UploadState::Cancelled => {
                                "this upload was cancelled; a new one is required"
                            }
                            kr_protocol::transfer::UploadState::Invalidated => {
                                "this upload was invalidated; a new one is required"
                            }
                            kr_protocol::transfer::UploadState::Expired => {
                                "this upload expired; a new one is required"
                            }
                            _ => "this upload is no longer open",
                        }));
                    }
                }
                if result.layout.byte_len() != self.content.byte_len() {
                    return Err(refuse("the host's layout does not cover this content"));
                }
                self.layout = result.layout;
                self.adopt_bitmap(&result.received_chunks)?;
                self.advance();
                Ok(())
            }
        }
    }

    /// Accepts a published handle, after checking it is this upload's.
    ///
    /// A handle names the environment, the transfer, the length and the digest. Taking one that
    /// disagrees with any of those would be taking someone else's file as this draft's attachment.
    fn accept_handle(&mut self, handle: &AttachmentHandle) -> Result<()> {
        self.same_transfer(&handle.transfer_id)?;
        if handle.environment_id != self.subject.environment_id {
            return Err(refuse("the published handle names another environment"));
        }
        if handle.byte_len.get() != self.content.byte_len() {
            return Err(refuse("the published handle is not this content's length"));
        }
        if handle.content_digest != self.content.digest() {
            return Err(refuse("the published handle is not this content's digest"));
        }
        self.handle = Some(handle.clone());
        self.phase = Phase::Published;
        Ok(())
    }

    fn advance(&mut self) {
        self.phase = if self.next_missing_chunk().is_some() {
            Phase::Sending
        } else {
            Phase::Publishing
        };
    }

    fn same_transfer(&self, transfer_id: &kr_protocol::ids::TransferId) -> Result<()> {
        if self.transfer_id.as_ref() == Some(transfer_id) {
            return Ok(());
        }
        Err(ClientError::refusal(
            kr_protocol::error::ErrorCode::InvalidArgument,
            crate::shown::Shown::said("the answer names a transfer this upload is not driving"),
        ))
    }

    fn adopt_bitmap(&mut self, encoded: &Bytes) -> Result<()> {
        let bitmap = ChunkBitmap::decode(encoded, self.layout.chunk_count.get()).map_err(|_| {
            ClientError::refusal(
                kr_protocol::error::ErrorCode::InvalidArgument,
                crate::shown::Shown::said(
                    "the host's received-chunk bitmap does not fit the layout it chose",
                ),
            )
        })?;
        self.sent = Some(bitmap);
        Ok(())
    }

    fn next_missing_chunk(&self) -> Option<u64> {
        let bitmap = self.sent.as_ref()?;
        (0..self.layout.chunk_count.get()).find(|index| !bitmap.contains(*index))
    }

    fn chunk_params(
        &self,
        transfer_id: kr_protocol::ids::TransferId,
        index: u64,
    ) -> Result<UploadChunkParams> {
        let len = self.layout.length_of(index).ok_or_else(|| {
            ClientError::refusal(
                kr_protocol::error::ErrorCode::InvalidArgument,
                crate::shown::Shown::said("the layout has no chunk at that index"),
            )
        })?;
        let offset = self.layout.offset_of(index).ok_or_else(|| {
            ClientError::refusal(
                kr_protocol::error::ErrorCode::InvalidArgument,
                crate::shown::Shown::said("the layout has no offset for that chunk"),
            )
        })?;
        let bytes = self.content.read_at(offset, len)?;
        if bytes.len() as u64 != len {
            return Err(out_of_range());
        }
        let digest = Digest256::from_bytes(kr_cbor::sha256(&bytes));
        Ok(UploadChunkParams {
            transfer_id,
            chunk: ChunkDescriptor {
                index: U64::new(index),
                byte_len: U64::new(len),
                digest,
            },
            bytes: Bytes::from(bytes),
        })
    }
}

/// The protocol's chunk length, republished so a caller can size its reads without reaching past
/// this module.
pub const CHUNK_LEN: usize = UPLOAD_CHUNK_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    fn subject() -> Subject {
        Subject {
            environment_id: "33333333-3333-4333-8333-333333333333"
                .parse()
                .expect("a valid environment"),
            session_id: None,
            device_id: None,
            declared_media_type: "image/png".into(),
            original_file_name: "diagram.png".into(),
        }
    }

    fn begun(upload: &Upload, chunk_count: u64, received: &ChunkBitmap) -> Answer {
        Answer::Begun(Box::new(UploadBeginResult {
            transfer_id: transfer_id(),
            environment_id: subject().environment_id,
            layout: ChunkLayout {
                chunk_len: U64::new(CHUNK_LEN as u64),
                chunk_count: U64::new(chunk_count),
                last_chunk_len: U64::new(upload.content.byte_len() % CHUNK_LEN as u64),
            },
            received_chunks: received.encode(),
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(1),
            staged_byte_len: U64::new(0),
            staged_byte_limit: U64::new(1 << 30),
        }))
    }

    fn transfer_id() -> kr_protocol::ids::TransferId {
        kr_protocol::ids::TransferId::new(
            "11111111-1111-4111-8111-111111111111"
                .parse()
                .expect("a uuid"),
        )
    }

    #[test]
    fn an_upload_asks_to_reserve_before_it_sends_anything() {
        let upload = Upload::new(subject(), Box::new(Held::new(b"hello".to_vec())));
        let Step::Begin(params) = upload.next().expect("a step") else {
            panic!("the first step reserves the transfer");
        };
        assert_eq!(params.declared_byte_len.get(), 5);
        assert_eq!(params.declared_media_type, "image/png");
        assert_eq!(params.original_file_name, "diagram.png");
        assert_eq!(upload.progress(), 0.0);
    }

    #[test]
    fn an_upload_sends_only_the_chunks_the_host_is_missing() {
        let content = vec![7_u8; CHUNK_LEN * 2 + 16];
        let mut upload = Upload::new(subject(), Box::new(Held::new(content)));
        let mut received = ChunkBitmap::empty(3);
        received.insert(0);
        let answer = begun(&upload, 3, &received);
        upload.accept(answer).expect("the reservation folds in");

        let Step::Chunk(first) = upload.next().expect("a step") else {
            panic!("a missing chunk is next");
        };
        assert_eq!(first.chunk.index.get(), 1, "chunk 0 was already verified");
        assert!((upload.progress() - 1.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn an_upload_publishes_once_every_chunk_is_acknowledged() {
        let mut upload = Upload::new(subject(), Box::new(Held::new(b"small".to_vec())));
        let mut received = ChunkBitmap::empty(1);
        let answer = begun(&upload, 1, &received);
        upload.accept(answer).expect("the reservation folds in");
        assert!(matches!(upload.next().expect("a step"), Step::Chunk(_)));

        received.insert(0);
        upload
            .accept(Answer::Chunked(Box::new(UploadChunkResult {
                transfer_id: transfer_id(),
                index: U64::new(0),
                duplicate: false,
                received_chunks: received.encode(),
                received_byte_len: U64::new(5),
            })))
            .expect("the chunk folds in");

        let Step::Finish(params) = upload.next().expect("a step") else {
            panic!("publishing is next once nothing is missing");
        };
        assert_eq!(params.declared_byte_len.get(), 5);
        assert_eq!(upload.progress(), 1.0);
    }

    #[test]
    fn a_lost_reply_resumes_from_the_status_bitmap_without_resending_verified_chunks() {
        let content = vec![3_u8; CHUNK_LEN + 8];
        let mut upload = Upload::new(subject(), Box::new(Held::new(content)));
        let empty = ChunkBitmap::empty(2);
        let answer = begun(&upload, 2, &empty);
        upload.accept(answer).expect("the reservation folds in");

        let mut both = ChunkBitmap::empty(2);
        both.insert(0);
        both.insert(1);
        upload
            .accept(Answer::Status(Box::new(UploadStatusResult {
                transfer_id: transfer_id(),
                environment_id: subject().environment_id,
                state: kr_protocol::transfer::UploadState::Receiving,
                layout: ChunkLayout {
                    chunk_len: U64::new(CHUNK_LEN as u64),
                    chunk_count: U64::new(2),
                    last_chunk_len: U64::new(8),
                },
                received_chunks: both.encode(),
                received_byte_len: U64::new(CHUNK_LEN as u64 + 8),
                expires_at_ms: kr_protocol::scalars::TimestampMs::new(1),
                handle: Nullable::null(),
                invalid_reason: Nullable::null(),
            })))
            .expect("the status folds in");

        assert!(
            matches!(upload.next().expect("a step"), Step::Finish(_)),
            "every chunk the host holds is skipped"
        );
    }

    #[test]
    fn a_status_that_already_holds_the_handle_ends_the_upload() {
        let mut upload = Upload::new(subject(), Box::new(Held::new(b"x".to_vec())));
        let empty = ChunkBitmap::empty(1);
        let answer = begun(&upload, 1, &empty);
        upload.accept(answer).expect("the reservation folds in");

        let handle = AttachmentHandle {
            environment_id: subject().environment_id,
            transfer_id: transfer_id(),
            session_id: Nullable::null(),
            byte_len: U64::new(1),
            content_digest: Digest256::from_bytes(kr_cbor::sha256(b"x")),
            declared_media_type: "image/png".into(),
            original_file_name: "diagram.png".into(),
            preview: Nullable::null(),
            presented_as_image: false,
            published_at_ms: kr_protocol::scalars::TimestampMs::new(2),
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(3),
            submitted: false,
        };
        let mut received = ChunkBitmap::empty(1);
        received.insert(0);
        upload
            .accept(Answer::Status(Box::new(UploadStatusResult {
                transfer_id: transfer_id(),
                environment_id: subject().environment_id,
                state: kr_protocol::transfer::UploadState::Published,
                layout: ChunkLayout {
                    chunk_len: U64::new(CHUNK_LEN as u64),
                    chunk_count: U64::new(1),
                    last_chunk_len: U64::new(1),
                },
                received_chunks: received.encode(),
                received_byte_len: U64::new(1),
                expires_at_ms: kr_protocol::scalars::TimestampMs::new(1),
                handle: Nullable::some(handle.clone()),
                invalid_reason: Nullable::null(),
            })))
            .expect("the status folds in");

        let Step::Done(published) = upload.next().expect("a step") else {
            panic!("a published status ends the upload");
        };
        assert_eq!(*published, handle);
        assert_eq!(upload.handle(), Some(&handle));
    }

    #[test]
    fn a_second_reservation_does_not_replace_the_transfer_this_plan_is_driving() {
        let mut upload = Upload::new(subject(), Box::new(Held::new(b"x".to_vec())));
        let answer = begun(&upload, 1, &ChunkBitmap::empty(1));
        upload.accept(answer).expect("the reservation folds in");
        let again = begun(&upload, 1, &ChunkBitmap::empty(1));
        assert!(
            upload.accept(again).is_err(),
            "a plan reserves once, and what it sent belongs to that transfer"
        );
    }

    #[test]
    fn a_published_handle_for_other_content_is_refused() {
        let mut upload = Upload::new(subject(), Box::new(Held::new(b"x".to_vec())));
        let answer = begun(&upload, 1, &ChunkBitmap::empty(1));
        upload.accept(answer).expect("the reservation folds in");

        let wrong = AttachmentHandle {
            environment_id: subject().environment_id,
            transfer_id: transfer_id(),
            session_id: Nullable::null(),
            byte_len: U64::new(9_999),
            content_digest: Digest256::from_bytes(kr_cbor::sha256(b"something else")),
            declared_media_type: "image/png".into(),
            original_file_name: "diagram.png".into(),
            preview: Nullable::null(),
            presented_as_image: false,
            published_at_ms: kr_protocol::scalars::TimestampMs::new(2),
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(3),
            submitted: false,
        };
        let refusal = upload.accept(Answer::Finished(Box::new(UploadFinishResult {
            handle: wrong,
            already_published: false,
            preview_unavailable: Nullable::null(),
        })));
        assert!(refusal.is_err(), "that handle is not this content");
        assert!(upload.handle().is_none(), "and the plan is left as it was");
    }

    #[test]
    fn an_upload_the_host_ended_is_not_continued() {
        for ended in [
            kr_protocol::transfer::UploadState::Cancelled,
            kr_protocol::transfer::UploadState::Invalidated,
            kr_protocol::transfer::UploadState::Expired,
        ] {
            let mut upload = Upload::new(subject(), Box::new(Held::new(b"x".to_vec())));
            let answer = begun(&upload, 1, &ChunkBitmap::empty(1));
            upload.accept(answer).expect("the reservation folds in");
            let refusal = upload.accept(Answer::Status(Box::new(UploadStatusResult {
                transfer_id: transfer_id(),
                environment_id: subject().environment_id,
                state: ended,
                layout: ChunkLayout {
                    chunk_len: U64::new(CHUNK_LEN as u64),
                    chunk_count: U64::new(1),
                    last_chunk_len: U64::new(1),
                },
                received_chunks: ChunkBitmap::empty(1).encode(),
                received_byte_len: U64::new(0),
                expires_at_ms: kr_protocol::scalars::TimestampMs::new(1),
                handle: Nullable::null(),
                invalid_reason: Nullable::null(),
            })));
            assert!(refusal.is_err(), "{ended:?} spends the transfer identifier");
        }
    }

    #[test]
    fn a_resumed_plan_takes_the_transfer_it_is_resuming_and_asks_only_for_what_is_missing() {
        let content = vec![5_u8; CHUNK_LEN + 4];
        let mut upload = Upload::resuming(subject(), Box::new(Held::new(content)), transfer_id());
        let mut held = ChunkBitmap::empty(2);
        held.insert(0);
        upload
            .accept(Answer::Status(Box::new(UploadStatusResult {
                transfer_id: transfer_id(),
                environment_id: subject().environment_id,
                state: kr_protocol::transfer::UploadState::Receiving,
                layout: ChunkLayout {
                    chunk_len: U64::new(CHUNK_LEN as u64),
                    chunk_count: U64::new(2),
                    last_chunk_len: U64::new(4),
                },
                received_chunks: held.encode(),
                received_byte_len: U64::new(CHUNK_LEN as u64),
                expires_at_ms: kr_protocol::scalars::TimestampMs::new(1),
                handle: Nullable::null(),
                invalid_reason: Nullable::null(),
            })))
            .expect("the status folds in");

        let Step::Chunk(next) = upload.next().expect("a step") else {
            panic!("the missing chunk is next");
        };
        assert_eq!(next.chunk.index.get(), 1);
    }

    #[test]
    fn an_answer_for_another_transfer_is_refused() {
        let mut upload = Upload::new(subject(), Box::new(Held::new(b"x".to_vec())));
        let empty = ChunkBitmap::empty(1);
        let answer = begun(&upload, 1, &empty);
        upload.accept(answer).expect("the reservation folds in");

        let other = kr_protocol::ids::TransferId::new(
            "22222222-2222-4222-8222-222222222222"
                .parse()
                .expect("a uuid"),
        );
        let refusal = upload.accept(Answer::Chunked(Box::new(UploadChunkResult {
            transfer_id: other,
            index: U64::new(0),
            duplicate: false,
            received_chunks: empty.encode(),
            received_byte_len: U64::new(0),
        })));
        assert!(
            refusal.is_err(),
            "another transfer's answer is not this upload's"
        );
    }

    #[test]
    fn every_chunk_carries_the_digest_of_exactly_its_own_bytes() {
        let content: Vec<u8> = (0..CHUNK_LEN as u32 + 32).map(|byte| byte as u8).collect();
        let mut upload = Upload::new(subject(), Box::new(Held::new(content.clone())));
        let empty = ChunkBitmap::empty(2);
        let answer = begun(&upload, 2, &empty);
        upload.accept(answer).expect("the reservation folds in");

        let Step::Chunk(first) = upload.next().expect("a step") else {
            panic!("a chunk is next");
        };
        assert_eq!(first.chunk.byte_len.get(), CHUNK_LEN as u64);
        assert_eq!(
            first.chunk.digest,
            Digest256::from_bytes(kr_cbor::sha256(&content[..CHUNK_LEN]))
        );
        assert_eq!(first.bytes.as_slice(), &content[..CHUNK_LEN]);
    }

    #[test]
    fn empty_content_has_no_chunks_and_goes_straight_to_publishing() {
        let mut upload = Upload::new(subject(), Box::new(Held::new(Vec::new())));
        let answer = begun(&upload, 0, &ChunkBitmap::empty(0));
        upload.accept(answer).expect("the reservation folds in");
        assert!(matches!(upload.next().expect("a step"), Step::Finish(_)));
        assert_eq!(upload.progress(), 1.0);
    }
}
