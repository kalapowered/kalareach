//! A transfer service on a disposable host tree, with the chunk arithmetic each test would
//! otherwise repeat.
//!
//! Every test here drives the real store, the real staging area and the real authorised
//! directories. Nothing is mocked: the point of these tests is what the filesystem and SQLite
//! actually do.

// Each test binary uses a different part of this module.
#![allow(dead_code)]

use std::sync::Arc;

use kr_ipc::testing::TempHost;
use kr_protocol::ids::{ActorId, EnvironmentId, SessionId, TransferId};
use kr_protocol::scalars::{Bytes, Digest256, Nullable, U64};
use kr_protocol::transfer::{
    AttachmentHandle, ChunkDescriptor, ChunkLayout, UploadBeginParams, UploadBeginResult,
    UploadChunkParams, UploadFinishParams, UploadFinishResult,
};
use kr_transfer::store::Limits;
use kr_transfer::{ManualClock, Result, TransferService};

/// Where the clock starts, so an expiry window is easy to read in a test.
pub const START_MS: u64 = 1_700_000_000_000;

/// One environment's transfer service, its clock and its host tree.
pub struct Harness {
    /// The disposable host tree. Dropped last, so it outlives the service.
    pub host: TempHost,
    /// The service under test.
    pub service: TransferService,
    /// The clock the service reads expiries from.
    pub clock: Arc<ManualClock>,
    /// The principal every call in a test is made as.
    pub actor: ActorId,
}

impl Harness {
    /// Creates a service on a fresh host tree.
    #[must_use]
    pub fn create() -> Self {
        let host = TempHost::create();
        let clock = Arc::new(ManualClock::new(START_MS));
        let service =
            TransferService::with_clock(&host.environment(), Arc::clone(&clock) as Arc<_>)
                .expect("a transfer service");
        Self {
            host,
            service,
            clock,
            actor: ActorId::new("local:transfer-test").expect("a valid principal"),
        }
    }

    /// Returns the environment this service owns.
    #[must_use]
    pub fn environment_id(&self) -> EnvironmentId {
        self.service.environment_id()
    }

    /// Replaces the environment's configured limits.
    pub fn set_limits(&self, limits: Limits) {
        self.service.set_limits(limits).expect("writes the limits");
    }

    /// Reserves an upload for exactly these bytes.
    pub fn begin(
        &self,
        bytes: &[u8],
        media_type: &str,
        original_file_name: &str,
    ) -> Result<UploadBeginResult> {
        self.begin_for(bytes, media_type, original_file_name, Nullable::null())
    }

    /// Reserves an upload bound to a session.
    pub fn begin_for(
        &self,
        bytes: &[u8],
        media_type: &str,
        original_file_name: &str,
        session_id: Nullable<SessionId>,
    ) -> Result<UploadBeginResult> {
        self.service.upload_begin(
            &self.actor,
            &UploadBeginParams {
                environment_id: self.environment_id(),
                session_id,
                device_id: Nullable::null(),
                declared_byte_len: U64::new(bytes.len() as u64),
                declared_digest: digest(bytes),
                declared_media_type: media_type.to_owned(),
                original_file_name: original_file_name.to_owned(),
            },
            None,
        )
    }

    /// Sends one chunk of a byte sequence.
    pub fn send(&self, transfer_id: TransferId, bytes: &[u8], index: u64) -> Result<()> {
        let (chunk, payload) = chunk_of(bytes, index);
        self.service
            .upload_chunk(
                &self.actor,
                &UploadChunkParams {
                    transfer_id,
                    chunk,
                    bytes: payload,
                },
                None,
            )
            .map(|_| ())
    }

    /// Sends every chunk of a byte sequence, in order.
    pub fn send_all(&self, transfer_id: TransferId, bytes: &[u8]) -> Result<()> {
        let layout = ChunkLayout::for_length(bytes.len() as u64);
        for index in 0..layout.chunk_count.get() {
            self.send(transfer_id, bytes, index)?;
        }
        Ok(())
    }

    /// Verifies and publishes an upload.
    pub fn finish(&self, transfer_id: TransferId, bytes: &[u8]) -> Result<UploadFinishResult> {
        self.finish_as(transfer_id, bytes, None)
    }

    /// Verifies and publishes an upload under one action.
    pub fn finish_as(
        &self,
        transfer_id: TransferId,
        bytes: &[u8],
        action: Option<&kr_transfer::service::Action>,
    ) -> Result<UploadFinishResult> {
        self.service.upload_finish(
            &self.actor,
            &UploadFinishParams {
                transfer_id,
                declared_byte_len: U64::new(bytes.len() as u64),
                declared_digest: digest(bytes),
            },
            action,
        )
    }

    /// Sends one chunk under one action.
    pub fn send_as(
        &self,
        transfer_id: TransferId,
        bytes: &[u8],
        index: u64,
        action: Option<&kr_transfer::service::Action>,
    ) -> Result<kr_protocol::transfer::UploadChunkResult> {
        let (chunk, payload) = chunk_of(bytes, index);
        self.service.upload_chunk(
            &self.actor,
            &UploadChunkParams {
                transfer_id,
                chunk,
                bytes: payload,
            },
            action,
        )
    }

    /// Cancels an upload under one action.
    pub fn cancel_as(
        &self,
        transfer_id: TransferId,
        action: Option<&kr_transfer::service::Action>,
    ) -> Result<kr_protocol::transfer::UploadCancelResult> {
        self.service.upload_cancel(
            &self.actor,
            &kr_protocol::transfer::UploadCancelParams { transfer_id },
            action,
        )
    }

    /// Runs a whole upload and returns the published handle.
    pub fn publish(
        &self,
        bytes: &[u8],
        media_type: &str,
        original_file_name: &str,
    ) -> AttachmentHandle {
        let begun = self
            .begin(bytes, media_type, original_file_name)
            .expect("reserves the upload");
        self.send_all(begun.transfer_id, bytes)
            .expect("sends every chunk");
        self.finish(begun.transfer_id, bytes)
            .expect("publishes the attachment")
            .handle
    }
}

/// Returns the SHA-256 digest of these bytes.
#[must_use]
pub fn digest(bytes: &[u8]) -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(bytes))
}

/// Returns one chunk's descriptor and payload under the protocol's chunk size.
///
/// # Panics
///
/// Panics when the index is not in the layout, which in a test means the test is wrong.
#[must_use]
pub fn chunk_of(bytes: &[u8], index: u64) -> (ChunkDescriptor, Bytes) {
    let layout = ChunkLayout::for_length(bytes.len() as u64);
    let offset = layout.offset_of(index).expect("an index in the layout");
    let len = layout.length_of(index).expect("an index in the layout");
    let start = usize::try_from(offset).expect("an offset this host can address");
    let end = start + usize::try_from(len).expect("a length this host can address");
    let payload = &bytes[start..end];
    (
        ChunkDescriptor {
            index: U64::new(index),
            byte_len: U64::new(len),
            digest: digest(payload),
        },
        Bytes::new(payload.to_vec()),
    )
}

/// Returns a byte sequence of `len` bytes that no two lengths share a prefix of.
#[must_use]
pub fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from((index * 31 + len) % 251).unwrap_or(0))
        .collect()
}

/// Returns a small valid PNG.
#[must_use]
pub fn png(width: u32, height: u32) -> Vec<u8> {
    let mut image = image::RgbaImage::new(width, height);
    for (index, pixel) in image.pixels_mut().enumerate() {
        let shade = u8::try_from(index % 251).unwrap_or(0);
        *pixel = image::Rgba([shade, 255 - shade, shade / 2, 255]);
    }
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image)
        .write_to(&mut out, image::ImageFormat::Png)
        .expect("encodes a PNG");
    out.into_inner()
}
