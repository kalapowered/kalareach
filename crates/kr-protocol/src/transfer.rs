//! Uploads, verified downloads, attachment handles and draft bindings.
//!
//! Section 14 keeps three things apart that a user experiences as one. **Transfer** moves bytes
//! into or out of an execution environment with bounded chunks, per-chunk integrity and resumable
//! progress. **Storage** publishes the verified bytes as an opaque, environment-bound attachment
//! handle. **Insertion** hands that handle to an agent through its adapter, and **submission** is
//! a further action again. Each stage has its own method and its own recorded outcome, so a failed
//! insertion keeps the draft and the completed upload rather than losing both.
//!
//! Two consequences shape every type here.
//!
//! * A handle is opaque and carries its environment. It is never a client-supplied absolute host
//!   path, and a handle from one environment means nothing in another: a Windows path and a WSL
//!   path are different environments and never alias.
//! * Only upstream evidence moves an insertion to accepted. A recorded binding says the adapter
//!   was asked; it does not claim the agent took the file.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{
    ApplicationInstanceId, DeviceId, DraftId, DraftRevision, EnvironmentId, GrantId, SessionId,
    TransferId,
};
use crate::limits::UPLOAD_CHUNK_LEN;
use crate::scalars::{Bytes, Digest256, DurationMs, Nullable, TimestampMs, U64};

/// How long an unfinished upload is kept before it expires.
pub const UNFINISHED_UPLOAD_LIFETIME: DurationMs = DurationMs::new(24 * 60 * 60 * 1000);

/// How long a completed but unused attachment is kept before it expires.
///
/// A submitted attachment follows its session's retention policy instead, which is why submission
/// is recorded on the attachment rather than inferred from its age.
pub const UNUSED_ATTACHMENT_LIFETIME: DurationMs = DurationMs::new(7 * 24 * 60 * 60 * 1000);

/// How long a download snapshot is kept before it expires.
///
/// A snapshot occupies the same environment budget as a staged upload, so it is swept on the same
/// schedule as one that was never finished.
pub const DOWNLOAD_SNAPSHOT_LIFETIME: DurationMs = DurationMs::new(24 * 60 * 60 * 1000);

/// Maximum pixels a preview decoder accepts in its input.
pub const MAX_PREVIEW_PIXELS: u64 = 40_000_000;

/// Maximum memory a preview decode may allocate, in bytes.
pub const MAX_PREVIEW_DECODE_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum size of a decoded thumbnail, in bytes.
pub const MAX_PREVIEW_THUMBNAIL_BYTES: u64 = 16 * 1024 * 1024;

/// Largest encoded thumbnail a result carries, in bytes.
///
/// The specification's 16 MiB is the *decoded* budget. A result travels in one frame, and a draft's
/// result carries one preview per bound attachment, so the encoded thumbnail has a much smaller
/// ceiling than the decode does: a 1 MiB control frame has to hold a draft with several of them
/// plus everything else in it. A thumbnail that does not fit is re-encoded at a smaller edge, and
/// one that still does not fit is left out entirely.
pub const MAX_PREVIEW_FRAME_BYTES: u64 = 48 * 1024;

/// The thumbnail edges tried, largest first, until one encodes inside the frame budget.
///
/// The first is the longest edge a thumbnail ever has. The rest are what an image whose thumbnail
/// does not encode small enough steps down to, and the last is small enough that its raw pixels
/// fit the frame budget whatever they are, so the ladder always ends somewhere.
pub const PREVIEW_THUMBNAIL_EDGES: &[u32] = &[512, 320, 192, 96];

/// Largest encoded image a preview decoder reads.
///
/// The decode-memory limit is what bounds the decoded pixels; this bounds the *encoded* input,
/// which several decoders read into memory before they report a dimension. Without it a small
/// image with a large trailing payload would spend the whole decode budget in the pass that was
/// supposed to read only a header. An attachment above this publishes as a file.
pub const MAX_PREVIEW_INPUT_BYTES: u64 = 48 * 1024 * 1024;

/// Maximum length of a recorded original filename, in bytes.
///
/// The name is metadata. It is bounded so a client cannot spend the whole metadata allowance of an
/// attachment frame on it, and it never decides a storage path.
pub const MAX_ORIGINAL_FILE_NAME_LEN: usize = 255;

/// Maximum length of a declared media type, in bytes.
pub const MAX_MEDIA_TYPE_LEN: usize = 127;

/// Largest encoded transfer result, in bytes.
///
/// A reply travels in one control frame, and a draft's reply carries every attachment bound to it
/// with its preview. A frame the host cannot send is a mutation whose effect committed and whose
/// receipt never arrived, so the size of the reply is checked before the effect rather than
/// discovered after it. The margin below the frame bound is the envelope around the result.
pub const MAX_TRANSFER_RESULT_BYTES: u64 = 768 * 1024;

/// Maximum length of a declared external destination, in characters.
///
/// It is a disclosure a person reads, so it is bounded like every other string that reaches a
/// client rather than left to the caller's generosity.
pub const MAX_EXTERNAL_DESTINATION_LEN: usize = 255;

/// The chunk layout of one transfer.
///
/// Both directions use the same shape: a fixed chunk size, a count, and the length of the final
/// chunk. A zero-length file has no chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChunkLayout {
    /// Bytes per chunk, except the last.
    pub chunk_len: U64,
    /// How many chunks the transfer has.
    pub chunk_count: U64,
    /// Length of the final chunk. Equal to `chunk_len` when the size divides exactly.
    pub last_chunk_len: U64,
}

impl ChunkLayout {
    /// Returns the layout a file of `byte_len` bytes has under the protocol's chunk size.
    #[must_use]
    pub const fn for_length(byte_len: u64) -> Self {
        let chunk_len = UPLOAD_CHUNK_LEN as u64;
        if byte_len == 0 {
            return Self {
                chunk_len: U64::new(chunk_len),
                chunk_count: U64::new(0),
                last_chunk_len: U64::new(0),
            };
        }
        let chunk_count = byte_len.div_ceil(chunk_len);
        let remainder = byte_len % chunk_len;
        Self {
            chunk_len: U64::new(chunk_len),
            chunk_count: U64::new(chunk_count),
            last_chunk_len: U64::new(if remainder == 0 { chunk_len } else { remainder }),
        }
    }

    /// Returns the exact length chunk `index` must carry, or `None` when the index is out of range.
    #[must_use]
    pub const fn length_of(&self, index: u64) -> Option<u64> {
        let count = self.chunk_count.get();
        if index >= count {
            return None;
        }
        Some(if index + 1 == count {
            self.last_chunk_len.get()
        } else {
            self.chunk_len.get()
        })
    }

    /// Returns the byte offset chunk `index` starts at, or `None` when the index is out of range.
    #[must_use]
    pub const fn offset_of(&self, index: u64) -> Option<u64> {
        if index >= self.chunk_count.get() {
            return None;
        }
        Some(index * self.chunk_len.get())
    }

    /// Returns the total length this layout covers.
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        let count = self.chunk_count.get();
        if count == 0 {
            return 0;
        }
        (count - 1) * self.chunk_len.get() + self.last_chunk_len.get()
    }
}

/// One chunk's index, exact length and digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChunkDescriptor {
    /// The chunk's position in the layout.
    pub index: U64,
    /// Its exact length.
    pub byte_len: U64,
    /// The SHA-256 digest of exactly those bytes.
    pub digest: Digest256,
}

/// The received-chunk bitmap of a transfer.
///
/// Bit `index` lives in byte `index / 8` at bit position `index % 8`, counted from the least
/// significant bit. A bitmap is not a wire type on its own: the methods carry it as bytes, and this
/// type reads and writes those bytes so both sides agree on the layout. A 2 GiB upload needs 256
/// bytes, which is why a bitmap rather than a set of indices travels beside every chunk reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkBitmap {
    count: u64,
    bits: Vec<u8>,
}

impl ChunkBitmap {
    /// Creates an empty bitmap for a transfer of `count` chunks.
    #[must_use]
    pub fn empty(count: u64) -> Self {
        Self {
            count,
            bits: vec![0; usize::try_from(count.div_ceil(8)).unwrap_or(usize::MAX)],
        }
    }

    /// Reads a bitmap of `count` chunks from its encoded bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BitmapError`] when the byte count does not match `count`, or when a bit above
    /// `count` is set.
    pub fn decode(bytes: &Bytes, count: u64) -> Result<Self, BitmapError> {
        let expected = usize::try_from(count.div_ceil(8)).unwrap_or(usize::MAX);
        if bytes.as_slice().len() != expected {
            return Err(BitmapError::WrongLength {
                len: bytes.as_slice().len(),
                expected,
            });
        }
        let bitmap = Self {
            count,
            bits: bytes.as_slice().to_vec(),
        };
        // A bit above the chunk count would claim a chunk the layout does not have.
        let used = count % 8;
        if used != 0
            && let Some(last) = bitmap.bits.last()
            && last >> used != 0
        {
            return Err(BitmapError::BitAboveCount);
        }
        Ok(bitmap)
    }

    /// Returns the encoded bytes.
    #[must_use]
    pub fn encode(&self) -> Bytes {
        Bytes::new(self.bits.clone())
    }

    /// Returns how many chunks the bitmap covers.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Records chunk `index` as verified.
    ///
    /// An index at or above the chunk count is ignored: the layout decides what exists.
    pub fn insert(&mut self, index: u64) {
        if index >= self.count {
            return;
        }
        let Ok(byte) = usize::try_from(index / 8) else {
            return;
        };
        if let Some(slot) = self.bits.get_mut(byte) {
            *slot |= 1 << (index % 8);
        }
    }

    /// Returns true when chunk `index` is recorded as verified.
    #[must_use]
    pub fn contains(&self, index: u64) -> bool {
        if index >= self.count {
            return false;
        }
        usize::try_from(index / 8)
            .ok()
            .and_then(|byte| self.bits.get(byte))
            .is_some_and(|slot| slot & (1 << (index % 8)) != 0)
    }

    /// Returns how many chunks are recorded as verified.
    #[must_use]
    pub fn received(&self) -> u64 {
        self.bits
            .iter()
            .map(|slot| u64::from(slot.count_ones()))
            .sum()
    }

    /// Returns true when every chunk in the layout is recorded.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.received() == self.count
    }

    /// Returns the indices still missing, in ascending order.
    #[must_use]
    pub fn missing(&self) -> Vec<u64> {
        (0..self.count)
            .filter(|index| !self.contains(*index))
            .collect()
    }
}

/// Why a received-chunk bitmap was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BitmapError {
    /// The byte count does not match the chunk count.
    #[error("a bitmap for this transfer is {expected} bytes, not {len}")]
    WrongLength {
        /// The length that arrived.
        len: usize,
        /// The length the layout requires.
        expected: usize,
    },
    /// A bit above the chunk count was set.
    #[error("the bitmap sets a bit above the transfer's chunk count")]
    BitAboveCount,
}

/// What state an upload is in.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum UploadState {
    /// Chunks are being accepted.
    Receiving,
    /// Every chunk is verified and the file is being moved into the completed area. A daemon that
    /// restarts here resolves the move from the recorded names rather than starting again.
    Publishing,
    /// The whole-file digest and size were verified and the handle exists.
    Published,
    /// The client cancelled it.
    Cancelled,
    /// A conflicting duplicate chunk or a failed whole-file verification ended it. The upload
    /// identifier is spent; a new one is required.
    Invalidated,
    /// It was unfinished for longer than [`UNFINISHED_UPLOAD_LIFETIME`], or the published
    /// attachment went unused for longer than [`UNUSED_ATTACHMENT_LIFETIME`].
    Expired,
}

impl UploadState {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Receiving => "receiving",
            Self::Publishing => "publishing",
            Self::Published => "published",
            Self::Cancelled => "cancelled",
            Self::Invalidated => "invalidated",
            Self::Expired => "expired",
        }
    }

    /// Parses a stored state.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "receiving" => Some(Self::Receiving),
            "publishing" => Some(Self::Publishing),
            "published" => Some(Self::Published),
            "cancelled" => Some(Self::Cancelled),
            "invalidated" => Some(Self::Invalidated),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }

    /// Returns true when the upload can still accept chunks.
    #[must_use]
    pub const fn accepts_chunks(self) -> bool {
        matches!(self, Self::Receiving)
    }

    /// Returns true when a payload of this upload is meant to be on disk.
    ///
    /// What a reconciliation pass asks of a name it found: is there a row that accounts for it.
    #[must_use]
    pub const fn holds_payload(self) -> bool {
        matches!(self, Self::Receiving | Self::Publishing | Self::Published)
    }
}

/// The image formats a preview decoder accepts.
///
/// Nothing else is decoded. HTML and SVG are files, not images: rendering either needs a reviewed
/// renderer, which this is not.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PreviewFormat {
    /// Portable Network Graphics.
    Png,
    /// JPEG.
    Jpeg,
    /// WebP.
    Webp,
    /// The first frame of a GIF. Later frames are never decoded.
    GifFirstFrame,
}

impl PreviewFormat {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpeg",
            Self::Webp => "webp",
            Self::GifFirstFrame => "gif_first_frame",
        }
    }

    /// Returns the media type this format is presented under.
    #[must_use]
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::Png | Self::GifFirstFrame => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
        }
    }
}

/// A bounded thumbnail of a completed attachment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachmentPreview {
    /// The format the source was decoded from.
    pub source_format: PreviewFormat,
    /// The source's width in pixels.
    pub source_width: U64,
    /// The source's height in pixels.
    pub source_height: U64,
    /// The thumbnail's width in pixels.
    pub width: U64,
    /// The thumbnail's height in pixels.
    pub height: U64,
    /// The encoded thumbnail, always PNG, always within [`MAX_PREVIEW_THUMBNAIL_BYTES`].
    pub thumbnail: Bytes,
}

/// A completed, verified attachment.
///
/// This is the opaque handle section 14 requires. It names the environment that owns the bytes, the
/// transfer that produced them and the digest that was verified before anything was published. It
/// carries no host path: an adapter that needs a readable location asks for an
/// [`AttachmentReadGrant`] instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachmentHandle {
    /// The environment that owns the file. A handle never crosses environments.
    pub environment_id: EnvironmentId,
    /// The transfer that produced it, which is also this attachment's durable identity.
    pub transfer_id: TransferId,
    /// The session the upload was bound to, when it had one.
    pub session_id: Nullable<SessionId>,
    /// The verified length in bytes.
    pub byte_len: U64,
    /// The verified whole-file SHA-256 digest.
    pub content_digest: Digest256,
    /// The media type the client declared. Declared, not sniffed: it says what the client believes
    /// it sent.
    pub declared_media_type: String,
    /// The original filename, kept as metadata only.
    pub original_file_name: String,
    /// The bounded preview, when one could be produced. A failed preview leaves this null and the
    /// file itself is unaffected.
    pub preview: Nullable<AttachmentPreview>,
    /// True only when the bytes decoded as one of [`PreviewFormat`]'s formats.
    ///
    /// Unsupported media transfers as a file and is never presented as a model image, so an adapter
    /// reads this rather than guessing from the declared media type or the filename.
    pub presented_as_image: bool,
    /// When the handle was published.
    pub published_at_ms: TimestampMs,
    /// When an unused attachment expires. Submission replaces this with the session's retention.
    pub expires_at_ms: TimestampMs,
    /// True once a draft binding holding this attachment was submitted.
    pub submitted: bool,
}

/// How an integration puts an attachment in front of its agent.
///
/// Section 12 allows exactly three, per operation, declared in advance. None of them is a guess at
/// a composer's quoting rules.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InsertionMethod {
    /// A typed submission against the exact upstream binding.
    TypedSubmission,
    /// Verified insertion into a native composer behind a qualified atomic editor boundary.
    VerifiedComposerInsertion,
    /// The user performs the native operation after an environment-local transfer completes. The
    /// host shows the tested syntax; it never injects at a guessed prompt.
    ManualTerminalWorkflow,
}

impl InsertionMethod {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TypedSubmission => "typed_submission",
            Self::VerifiedComposerInsertion => "verified_composer_insertion",
            Self::ManualTerminalWorkflow => "manual_terminal_workflow",
        }
    }

    /// Parses a stored method.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "typed_submission" => Some(Self::TypedSubmission),
            "verified_composer_insertion" => Some(Self::VerifiedComposerInsertion),
            "manual_terminal_workflow" => Some(Self::ManualTerminalWorkflow),
            _ => None,
        }
    }

    /// Returns true when this method needs the agent to read the file from the filesystem.
    ///
    /// Only these require an [`AttachmentReadGrant`]. A typed submission hands the bytes upstream
    /// and needs no readable path at all.
    #[must_use]
    pub const fn needs_read_grant(self) -> bool {
        matches!(
            self,
            Self::VerifiedComposerInsertion | Self::ManualTerminalWorkflow
        )
    }
}

/// What one integration declares it accepts for one operation.
///
/// Section 11 requires the declaration to exist before anything is offered: accepted media types,
/// the selected model's limits, counts, the insertion method and any external destination. A
/// contribution receives completed opaque handles; it never performs the transfer itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachmentContribution {
    /// The operation this declaration covers.
    pub operation_id: String,
    /// The media types the installed agent accepts, exactly as declared.
    pub accepted_media_types: Vec<String>,
    /// The largest file the selected model accepts, in bytes.
    pub max_byte_len: U64,
    /// How many attachments one draft may carry.
    pub max_count: U64,
    /// How the handle reaches the agent.
    pub insertion_method: InsertionMethod,
    /// The external destination bytes reach, when the operation has one. Null means the bytes stay
    /// in this environment.
    pub external_destination: Nullable<String>,
    /// True when the selected model advertises a media capability for these types.
    ///
    /// An adapter verifies this before offering an image; a false value means the file transfers
    /// but is not presented as a model image.
    pub model_media_capability: bool,
}

/// A narrow, expiring read grant over exactly one completed attachment.
///
/// This is how an adapter reaches a staging file when its insertion method needs a readable path.
/// It covers one file, read only, for one purpose, and it weakens nothing else: the agent's sandbox
/// is unchanged, and no file is placed inside a repository.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachmentReadGrant {
    /// The grant's identity.
    pub grant_id: GrantId,
    /// The environment the grant is valid in, and only that one.
    pub environment_id: EnvironmentId,
    /// The attachment it covers.
    pub transfer_id: TransferId,
    /// The insertion method it was issued for.
    pub insertion_method: InsertionMethod,
    /// The environment-local path the agent may read, valid only while this grant is.
    ///
    /// It is inside the environment's staging area and outside every repository, which is what
    /// keeps an upload from becoming a file in the user's working tree.
    pub host_path: String,
    /// When the grant expires.
    pub expires_at_ms: TimestampMs,
}

/// What became of one attachment binding on a draft.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InsertionState {
    /// The adapter was asked and the binding is recorded. This says nothing about the agent.
    Recorded,
    /// The adapter reported upstream evidence. Only this state means the agent took the file.
    AcceptedByAgent,
    /// The insertion failed. The draft and the completed upload are both retained for a retry.
    Failed,
}

impl InsertionState {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::AcceptedByAgent => "accepted_by_agent",
            Self::Failed => "failed",
        }
    }

    /// Parses a stored state.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "recorded" => Some(Self::Recorded),
            "accepted_by_agent" => Some(Self::AcceptedByAgent),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// One attachment bound to a draft, and what became of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftAttachment {
    /// The completed attachment.
    pub handle: AttachmentHandle,
    /// How it was offered to the agent.
    pub insertion_method: InsertionMethod,
    /// What became of the offer.
    pub state: InsertionState,
    /// The upstream part or native draft binding the adapter reported. Present only for
    /// [`InsertionState::AcceptedByAgent`], because nothing else establishes acceptance.
    pub upstream_evidence: Nullable<String>,
    /// Why the insertion failed, when it did.
    pub failure_detail: Nullable<String>,
    /// The read grant issued for this binding, when its insertion method needed one.
    pub read_grant: Nullable<AttachmentReadGrant>,
    /// Where the bytes leave this environment for, as the operation declared it.
    ///
    /// Null means the bytes stay here. A value is a disclosure: it is recorded with the binding so
    /// a client can show the destination before the prompt is submitted, and so the draft record
    /// still names it afterwards. The host does not resolve it, reach it or check it against
    /// anything; what it does is refuse to lose it.
    pub external_destination: Nullable<String>,
}

/// What state a draft is in.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DraftState {
    /// The draft is bound to its target and can be updated.
    Open,
    /// The application or binding revision changed. The draft is retained for explicit
    /// retargeting and is never submitted automatically.
    Conflicted,
    /// The target is gone. The draft is retained, unbound.
    Orphaned,
}

impl DraftState {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Conflicted => "conflicted",
            Self::Orphaned => "orphaned",
        }
    }

    /// Parses a stored state.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "open" => Some(Self::Open),
            "conflicted" => Some(Self::Conflicted),
            "orphaned" => Some(Self::Orphaned),
            _ => None,
        }
    }
}

/// A durable device-owned draft.
///
/// A draft outlives the attachment that displays it: losing a connection removes the association,
/// not the draft. Submission is always a separate action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftRecord {
    /// The draft's identity.
    pub draft_id: DraftId,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// Its current revision. Every update names the revision it expects.
    pub revision: DraftRevision,
    /// The device that owns it, when one does.
    pub device_id: Nullable<DeviceId>,
    /// The session it targets.
    pub session_id: Nullable<SessionId>,
    /// The foreground application it targets.
    pub application_instance_id: Nullable<ApplicationInstanceId>,
    /// Its state.
    pub state: DraftState,
    /// The draft text. This is not the native terminal edit buffer.
    pub text: String,
    /// The attachments bound to it, in binding order.
    pub attachments: Vec<DraftAttachment>,
    /// When it was created.
    pub created_at_ms: TimestampMs,
    /// When it was last updated.
    pub updated_at_ms: TimestampMs,
}

/// Parameters of `upload.begin`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UploadBeginParams {
    /// The environment the file will belong to. Uploads bind to an environment, never to a path.
    pub environment_id: EnvironmentId,
    /// The session the upload is for, when it has one.
    pub session_id: Nullable<SessionId>,
    /// The device the concurrency limit is counted against.
    pub device_id: Nullable<DeviceId>,
    /// The declared size, reserved against the environment budget before anything is written.
    pub declared_byte_len: U64,
    /// The declared whole-file digest, verified before anything is published.
    pub declared_digest: Digest256,
    /// The media type the client believes it is sending.
    pub declared_media_type: String,
    /// The original filename. Metadata: separators, traversal segments and reserved device names
    /// never reach the storage path.
    pub original_file_name: String,
}

/// The result of `upload.begin`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UploadBeginResult {
    /// The upload's identity, which every later chunk and the published handle share.
    pub transfer_id: TransferId,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The chunk layout the client must follow.
    pub layout: ChunkLayout,
    /// The received-chunk bitmap, empty at this point.
    pub received_chunks: Bytes,
    /// When the unfinished upload expires.
    pub expires_at_ms: TimestampMs,
    /// Bytes now staged in this environment, this reservation included.
    pub staged_byte_len: U64,
    /// The environment's staged-byte limit.
    pub staged_byte_limit: U64,
}

/// Parameters of `upload.status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UploadStatusParams {
    /// The upload.
    pub transfer_id: TransferId,
}

/// The result of `upload.status`.
///
/// This is how a lost reply to `upload.finish` is resolved. A published upload answers with its
/// handle, so a client that never saw the reply learns the file exists instead of sending it again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UploadStatusResult {
    /// The upload.
    pub transfer_id: TransferId,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// Its state.
    pub state: UploadState,
    /// Its chunk layout.
    pub layout: ChunkLayout,
    /// Which chunks are verified.
    pub received_chunks: Bytes,
    /// How many verified bytes are staged.
    pub received_byte_len: U64,
    /// When it expires.
    pub expires_at_ms: TimestampMs,
    /// The published handle, once there is one.
    pub handle: Nullable<AttachmentHandle>,
    /// Why the upload was invalidated, when it was.
    pub invalid_reason: Nullable<String>,
}

/// Parameters of `upload.chunk`.
///
/// This rides the attachment-chunk stream, whose frame bound is one 1 MiB chunk plus its metadata.
/// A control stream cannot carry it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UploadChunkParams {
    /// The upload.
    pub transfer_id: TransferId,
    /// The chunk's index, exact length and digest.
    pub chunk: ChunkDescriptor,
    /// The chunk bytes. Their length must equal the descriptor's exactly.
    pub bytes: Bytes,
}

/// The result of `upload.chunk`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UploadChunkResult {
    /// The upload.
    pub transfer_id: TransferId,
    /// The chunk that was accepted.
    pub index: U64,
    /// True when this chunk was already verified with the same digest, so nothing was rewritten.
    pub duplicate: bool,
    /// Which chunks are verified now.
    pub received_chunks: Bytes,
    /// How many verified bytes are staged now.
    pub received_byte_len: U64,
}

/// Parameters of `upload.finish`.
///
/// The declared size and digest are repeated so the host can refuse a client that has changed its
/// mind about what it was sending. A changed source needs a new upload identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UploadFinishParams {
    /// The upload.
    pub transfer_id: TransferId,
    /// The declared whole-file length, which must match the one `upload.begin` recorded.
    pub declared_byte_len: U64,
    /// The declared whole-file digest, which must match the one `upload.begin` recorded.
    pub declared_digest: Digest256,
}

/// The result of `upload.finish`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UploadFinishResult {
    /// The published attachment.
    pub handle: AttachmentHandle,
    /// True when this call found the attachment already published, which is what a retry after a
    /// lost reply sees. No second file is ever created.
    pub already_published: bool,
    /// Why no preview was produced, when none was. The file itself is unaffected.
    pub preview_unavailable: Nullable<String>,
}

/// Parameters of `upload.cancel`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UploadCancelParams {
    /// The upload.
    pub transfer_id: TransferId,
}

/// The result of `upload.cancel`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UploadCancelResult {
    /// The upload.
    pub transfer_id: TransferId,
    /// Its state after the cancellation.
    pub state: UploadState,
    /// Bytes returned to the environment budget.
    pub released_byte_len: U64,
}

/// Where a download's bytes come from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DownloadSource {
    /// A completed attachment in this environment.
    ///
    /// A published attachment is already an immutable revision: nothing writes it after its
    /// verification, so it is served without a copy.
    Attachment {
        /// The attachment.
        transfer_id: TransferId,
    },
    /// A file beneath an authorised read scope.
    ///
    /// The source is concurrently writable, so the host stages a bounded immutable snapshot rather
    /// than trusting an open handle.
    Scope {
        /// The scope, which is an opened directory handle the host holds.
        scope_id: GrantId,
        /// The path beneath it. Absolute paths, traversal segments, separators the host does not
        /// accept and reserved device names are refused.
        relative_path: String,
    },
}

/// Parameters of `download.begin`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DownloadBeginParams {
    /// The environment that owns the source.
    pub environment_id: EnvironmentId,
    /// The transfer to resume. Resuming addresses the same snapshot and rechecks read authority; a
    /// missing or expired snapshot is refused rather than silently replaced.
    pub resume_transfer_id: Nullable<TransferId>,
    /// The source, when beginning a new transfer. Ignored when resuming.
    pub source: Nullable<DownloadSource>,
    /// The device the concurrency limit is counted against.
    pub device_id: Nullable<DeviceId>,
}

/// How a download's bytes were made immutable.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DownloadImmutability {
    /// A published attachment, read in place.
    ///
    /// Its whole-file digest and its per-chunk digests were recorded when it was verified, and
    /// every chunk served is checked against them. Nothing this host does writes it afterwards.
    /// What that does **not** promise is that another process under the same operating-system user
    /// cannot change it: such a change makes the affected chunk fail integrity rather than being
    /// served.
    ImmutableSource,
    /// The host took a filesystem clone of the source.
    ///
    /// An atomic copy-on-write clone, so the snapshot is one revision of the source whatever a
    /// concurrent writer does afterwards. Available where the filesystem supports it, which is
    /// APFS on Apple platforms and btrfs or XFS on Linux.
    ClonedSnapshot,
    /// The host staged a bounded byte copy, because the filesystem offers no clone.
    ///
    /// The source's stable identity, its size and its modification time are compared before and
    /// after, so a replacement or a resize fails the snapshot. A writer that rewrites the source in
    /// place with the same length and restores its modification time is not detectable from those
    /// facts, which is why the result names which of the three mechanisms produced it.
    StagedSnapshot,
}

impl DownloadImmutability {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ImmutableSource => "immutable_source",
            Self::ClonedSnapshot => "cloned_snapshot",
            Self::StagedSnapshot => "staged_snapshot",
        }
    }

    /// Parses a stored value.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "immutable_source" => Some(Self::ImmutableSource),
            "cloned_snapshot" => Some(Self::ClonedSnapshot),
            "staged_snapshot" => Some(Self::StagedSnapshot),
            _ => None,
        }
    }

    /// Returns true when the host holds its own copy of the bytes.
    #[must_use]
    pub const fn is_staged(self) -> bool {
        matches!(self, Self::ClonedSnapshot | Self::StagedSnapshot)
    }
}

/// The result of `download.begin`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DownloadBeginResult {
    /// The transfer's opaque identity. A resumed transfer keeps this identity.
    pub transfer_id: TransferId,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// How the bytes were made immutable.
    pub immutability: DownloadImmutability,
    /// The size.
    pub byte_len: U64,
    /// The whole-file digest.
    pub content_digest: Digest256,
    /// The chunk layout.
    pub layout: ChunkLayout,
    /// Every chunk's index, length and digest.
    pub chunks: Vec<ChunkDescriptor>,
    /// When the snapshot expires.
    pub expires_at_ms: TimestampMs,
    /// True when this call resumed an existing snapshot rather than creating one.
    pub resumed: bool,
}

/// Parameters of `download.chunk`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DownloadChunkParams {
    /// The transfer.
    pub transfer_id: TransferId,
    /// The chunk index.
    pub index: U64,
}

/// The result of `download.chunk`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DownloadChunkResult {
    /// The transfer.
    pub transfer_id: TransferId,
    /// The chunk's index, exact length and digest.
    pub chunk: ChunkDescriptor,
    /// The chunk bytes.
    pub bytes: Bytes,
}

/// How a client publishes a verified download to its own destination.
///
/// The host never writes to a client destination. This is the contract the client half performs:
/// verify every chunk, the total size and the whole-file digest, write through a temporary file,
/// and refuse an existing destination unless the user has taken an explicit overwrite action for
/// that exact destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DownloadPlacement {
    /// The transfer being published.
    pub transfer_id: TransferId,
    /// The name inside the client's chosen destination.
    pub destination_name: String,
    /// The verified length the client must have received.
    pub byte_len: U64,
    /// The verified whole-file digest the client must have computed.
    pub content_digest: Digest256,
    /// True only when the user has taken an explicit overwrite action for this destination.
    ///
    /// A default value is never true. Without it an existing destination is refused, and the
    /// temporary file is removed rather than renamed over anything.
    pub allow_overwrite: bool,
}

/// Parameters of `draft.create`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftCreateParams {
    /// The environment the draft belongs to.
    pub environment_id: EnvironmentId,
    /// The device that owns it.
    pub device_id: Nullable<DeviceId>,
    /// The session it targets.
    pub session_id: Nullable<SessionId>,
    /// The foreground application it targets.
    pub application_instance_id: Nullable<ApplicationInstanceId>,
    /// Its initial text.
    pub text: String,
}

/// The result of `draft.create`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftCreateResult {
    /// The draft.
    pub draft: DraftRecord,
}

/// Parameters of `draft.update`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftUpdateParams {
    /// The draft.
    pub draft_id: DraftId,
    /// The revision the caller expects. A mismatch is `DRAFT_CONFLICT` and changes nothing.
    pub expected_revision: DraftRevision,
    /// The replacement text.
    pub text: String,
}

/// The result of `draft.update`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftUpdateResult {
    /// The draft after the update.
    pub draft: DraftRecord,
}

/// Parameters of `agent.draft.add_attachment`.
///
/// This binds a completed handle to a draft and records what the adapter reported. It never
/// submits: `agent.prompt.submit` is a separate action, and a failed insertion keeps both the
/// draft and the upload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentDraftAddAttachmentParams {
    /// The draft.
    pub draft_id: DraftId,
    /// The revision the caller expects.
    pub expected_revision: DraftRevision,
    /// The completed attachment.
    pub transfer_id: TransferId,
    /// The contribution the integration declared for this operation.
    pub contribution: AttachmentContribution,
}

/// The result of `agent.draft.add_attachment`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentDraftAddAttachmentResult {
    /// The draft after the binding.
    pub draft: DraftRecord,
    /// The binding this call recorded.
    pub attachment: DraftAttachment,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_layout_covers_the_length_it_was_built_for() {
        for length in [
            0_u64,
            1,
            1024,
            UPLOAD_CHUNK_LEN as u64,
            UPLOAD_CHUNK_LEN as u64 + 1,
        ] {
            let layout = ChunkLayout::for_length(length);
            assert_eq!(layout.byte_len(), length, "length {length}");
            let total: u64 = (0..layout.chunk_count.get())
                .map(|index| layout.length_of(index).expect("in range"))
                .sum();
            assert_eq!(total, length, "length {length}");
        }
    }

    #[test]
    fn a_layout_refuses_an_index_it_does_not_have() {
        let layout = ChunkLayout::for_length(10);
        assert_eq!(layout.length_of(0), Some(10));
        assert_eq!(layout.length_of(1), None);
        assert_eq!(layout.offset_of(1), None);
    }

    #[test]
    fn a_bitmap_round_trips_through_its_bytes() {
        let mut bitmap = ChunkBitmap::empty(20);
        assert_eq!(bitmap.received(), 0);
        bitmap.insert(0);
        bitmap.insert(19);
        bitmap.insert(20);
        assert!(bitmap.contains(0));
        assert!(bitmap.contains(19));
        assert!(!bitmap.contains(20));
        assert_eq!(bitmap.received(), 2);
        let decoded = ChunkBitmap::decode(&bitmap.encode(), 20).expect("round trips");
        assert_eq!(decoded, bitmap);
        assert_eq!(decoded.missing().len(), 18);
    }

    #[test]
    fn a_bitmap_refuses_a_bit_above_the_chunk_count() {
        let bits = Bytes::new(vec![0b1000_0000]);
        assert_eq!(
            ChunkBitmap::decode(&bits, 4),
            Err(BitmapError::BitAboveCount)
        );
    }

    #[test]
    fn a_bitmap_refuses_a_length_the_layout_does_not_have() {
        let bits = Bytes::new(vec![0, 0]);
        assert!(matches!(
            ChunkBitmap::decode(&bits, 4),
            Err(BitmapError::WrongLength { .. })
        ));
    }

    #[test]
    fn a_complete_bitmap_reports_itself_complete() {
        let mut bitmap = ChunkBitmap::empty(3);
        for index in 0..3 {
            bitmap.insert(index);
        }
        assert!(bitmap.is_complete());
        assert!(bitmap.missing().is_empty());
    }

    #[test]
    fn every_state_and_method_parses_back_from_its_wire_string() {
        for state in [
            UploadState::Receiving,
            UploadState::Publishing,
            UploadState::Published,
            UploadState::Cancelled,
            UploadState::Invalidated,
            UploadState::Expired,
        ] {
            assert_eq!(UploadState::parse(state.as_str()), Some(state));
        }
        for method in [
            InsertionMethod::TypedSubmission,
            InsertionMethod::VerifiedComposerInsertion,
            InsertionMethod::ManualTerminalWorkflow,
        ] {
            assert_eq!(InsertionMethod::parse(method.as_str()), Some(method));
        }
        for state in [
            InsertionState::Recorded,
            InsertionState::AcceptedByAgent,
            InsertionState::Failed,
        ] {
            assert_eq!(InsertionState::parse(state.as_str()), Some(state));
        }
        for state in [
            DraftState::Open,
            DraftState::Conflicted,
            DraftState::Orphaned,
        ] {
            assert_eq!(DraftState::parse(state.as_str()), Some(state));
        }
        for immutability in [
            DownloadImmutability::ImmutableSource,
            DownloadImmutability::ClonedSnapshot,
            DownloadImmutability::StagedSnapshot,
        ] {
            assert_eq!(
                DownloadImmutability::parse(immutability.as_str()),
                Some(immutability)
            );
        }
    }

    #[test]
    fn only_a_readable_path_insertion_needs_a_read_grant() {
        assert!(!InsertionMethod::TypedSubmission.needs_read_grant());
        assert!(InsertionMethod::VerifiedComposerInsertion.needs_read_grant());
        assert!(InsertionMethod::ManualTerminalWorkflow.needs_read_grant());
    }

    #[test]
    fn a_full_size_chunk_mutation_fits_one_attachment_frame() {
        use crate::envelope::{ActionTarget, MutationRequest, ParamsValue};
        use crate::frame::{FrameCodec, StreamKind};
        use crate::ids::{ActionId, ActionWindowId, RequestId};
        use crate::method::{MethodName, MethodVersion};
        use crate::scalars::Uuid;

        let transfer_id = TransferId::new(Uuid::from_bytes([9; 16]));
        let params = UploadChunkParams {
            transfer_id,
            chunk: ChunkDescriptor {
                index: U64::new(2047),
                byte_len: U64::new(UPLOAD_CHUNK_LEN as u64),
                digest: Digest256::from_bytes([7; 32]),
            },
            bytes: Bytes::new(vec![0xab; UPLOAD_CHUNK_LEN]),
        };
        let mutation = MutationRequest {
            request_id: RequestId::new(u64::MAX),
            method: MethodName::new("upload.chunk").expect("a listed method"),
            method_version: MethodVersion(1),
            action_id: ActionId::new(Uuid::from_bytes([1; 16])),
            grant_id: Nullable::null(),
            target: ActionTarget {
                environment_id: EnvironmentId::new(Uuid::from_bytes([2; 16])),
                session_id: Nullable::some(SessionId::new(Uuid::from_bytes([3; 16]))),
                session_epoch: Nullable::some(crate::ids::SessionEpoch::new(u64::MAX)),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            expected: ParamsValue::empty(),
            action_window_id: ActionWindowId::new("w".repeat(64)).expect("an opaque identifier"),
            requested_ttl_ms: DurationMs::new(300_000),
            params: ParamsValue::from_typed(&params).expect("encodes"),
        };
        let frame = FrameCodec::new(StreamKind::AttachmentChunks)
            .encode_message(&crate::envelope::ControlFrame::Mutation(Box::new(mutation)))
            .expect("a full chunk fits an attachment frame");
        assert!(
            frame.len() <= StreamKind::AttachmentChunks.max_frame_len(),
            "a full chunk mutation is {} bytes",
            frame.len()
        );
        // The metadata around the chunk stays inside the 4 KiB allowance section 23 gives it.
        assert!(
            frame.len() - UPLOAD_CHUNK_LEN <= crate::limits::MAX_ATTACHMENT_METADATA_LEN,
            "the metadata around a chunk is {} bytes",
            frame.len() - UPLOAD_CHUNK_LEN
        );
    }
}
