//! Stream headers and the length-delimited frame codec.
//!
//! A data frame is a four-byte unsigned big-endian length followed by one KR-CBOR-1 object. The
//! length is validated against the stream's bound *before* the payload is allocated, so a peer
//! cannot make the host reserve memory by claiming a large frame.
//!
//! Each stream first supplies a bounded 1 KiB header declaring its kind and the authorised
//! resource it belongs to. The header is validated against the established control connection
//! before any data frame is accepted.

use kr_cbor::Limits as CborLimits;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{AttachmentId, ConnectionId, EnvironmentId, SessionId, StreamId, TransferId};
use crate::limits::{
    MAX_ATTACHMENT_FRAME_LEN, MAX_CONTROL_FRAME_LEN, MAX_INPUT_FRAME_LEN, MAX_STREAM_HEADER_LEN,
};
use crate::scalars::Nullable;

/// Length of a frame's length prefix, in bytes.
pub const FRAME_LENGTH_PREFIX_LEN: usize = 4;

/// What one stream carries.
///
/// Control and receipts, terminal output, terminal input, semantic updates and attachment chunks
/// use distinct streams so the host's scheduler can prioritise control and receipts over bulk
/// transfers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    /// Requests, responses and receipts.
    Control,
    /// Terminal output bytes.
    TerminalOutput,
    /// Terminal input bytes.
    TerminalInput,
    /// Semantic updates.
    SemanticUpdates,
    /// Attachment chunks.
    AttachmentChunks,
}

impl StreamKind {
    /// Every stream kind, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Control,
        Self::TerminalOutput,
        Self::TerminalInput,
        Self::SemanticUpdates,
        Self::AttachmentChunks,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::TerminalOutput => "terminal_output",
            Self::TerminalInput => "terminal_input",
            Self::SemanticUpdates => "semantic_updates",
            Self::AttachmentChunks => "attachment_chunks",
        }
    }

    /// Returns the maximum size of a complete frame on this stream kind, in bytes.
    ///
    /// This covers the four-byte length prefix as well as the payload. The attachment bound is
    /// larger than the control bound and cannot be selected on a control stream, which is why the
    /// bound is a property of the stream kind rather than of a frame.
    #[must_use]
    pub const fn max_frame_len(self) -> usize {
        match self {
            Self::Control | Self::TerminalOutput | Self::SemanticUpdates => MAX_CONTROL_FRAME_LEN,
            Self::TerminalInput => MAX_INPUT_FRAME_LEN,
            Self::AttachmentChunks => MAX_ATTACHMENT_FRAME_LEN,
        }
    }

    /// Returns the maximum payload this stream kind accepts, in bytes.
    ///
    /// The frame bound less its length prefix.
    #[must_use]
    pub const fn max_payload_len(self) -> usize {
        self.max_frame_len() - FRAME_LENGTH_PREFIX_LEN
    }

    /// Returns the KR-CBOR-1 decode limits for this stream kind.
    #[must_use]
    pub fn cbor_limits(self) -> CborLimits {
        CborLimits::DEFAULT.with_max_message_len(self.max_payload_len())
    }
}

/// The authorised resource a stream belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamResource {
    /// The environment that owns the resource.
    pub environment_id: EnvironmentId,
    /// The session, for session streams.
    pub session_id: Nullable<SessionId>,
    /// The attachment, for attachment-scoped terminal streams.
    pub attachment_id: Nullable<AttachmentId>,
    /// The transfer, for attachment chunk streams.
    pub transfer_id: Nullable<TransferId>,
}

/// The bounded header every stream sends first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamHeader {
    /// What this stream carries.
    pub kind: StreamKind,
    /// The control connection this stream is validated against.
    pub connection_id: ConnectionId,
    /// The event stream this data stream corresponds to, where one applies.
    pub stream_id: Nullable<StreamId>,
    /// The authorised resource.
    pub resource: StreamResource,
}

impl StreamHeader {
    /// Encodes the header, rejecting one that exceeds the 1 KiB bound.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::HeaderTooLarge`] when the encoding is longer than
    /// [`MAX_STREAM_HEADER_LEN`], or a CBOR error when the header cannot be represented.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let bytes = kr_cbor::to_canonical_vec(self).map_err(FrameError::Cbor)?;
        if bytes.len() > MAX_STREAM_HEADER_LEN {
            return Err(FrameError::HeaderTooLarge {
                len: bytes.len(),
                limit: MAX_STREAM_HEADER_LEN,
            });
        }
        Ok(bytes)
    }

    /// Decodes a header from bytes that are already bounded by [`MAX_STREAM_HEADER_LEN`].
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::HeaderTooLarge`] when the input is longer than the bound, or a CBOR
    /// error when it is not a canonical header.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() > MAX_STREAM_HEADER_LEN {
            return Err(FrameError::HeaderTooLarge {
                len: bytes.len(),
                limit: MAX_STREAM_HEADER_LEN,
            });
        }
        let limits = CborLimits::DEFAULT.with_max_message_len(MAX_STREAM_HEADER_LEN);
        kr_cbor::from_canonical_slice(bytes, &limits).map_err(FrameError::Cbor)
    }
}

/// A framing failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The declared length exceeds this stream kind's bound. Rejected before allocation.
    PayloadTooLarge {
        /// The declared length.
        len: usize,
        /// The bound for this stream kind.
        limit: usize,
    },
    /// A frame declared a zero-length payload. A KR-CBOR-1 object is at least one byte.
    EmptyPayload,
    /// The buffer ended before the length prefix or the payload was complete.
    Incomplete {
        /// How many more bytes are needed.
        needed: usize,
    },
    /// The stream header exceeds its 1 KiB bound.
    HeaderTooLarge {
        /// The header length.
        len: usize,
        /// The bound.
        limit: usize,
    },
    /// The payload is not canonical KR-CBOR-1.
    Cbor(kr_cbor::CborError),
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PayloadTooLarge { len, limit } => {
                write!(
                    formatter,
                    "frame of {len} bytes exceeds the {limit}-byte limit"
                )
            }
            Self::EmptyPayload => formatter.write_str("a frame payload cannot be empty"),
            Self::Incomplete { needed } => write!(formatter, "{needed} more byte(s) needed"),
            Self::HeaderTooLarge { len, limit } => write!(
                formatter,
                "stream header of {len} bytes exceeds the {limit}-byte limit"
            ),
            Self::Cbor(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// The frame codec for one stream kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameCodec {
    kind: StreamKind,
}

impl FrameCodec {
    /// Creates a codec bound to one stream kind.
    #[must_use]
    pub const fn new(kind: StreamKind) -> Self {
        Self { kind }
    }

    /// Returns the stream kind.
    #[must_use]
    pub const fn kind(self) -> StreamKind {
        self.kind
    }

    /// Returns the maximum payload length for this stream kind.
    #[must_use]
    pub const fn max_payload_len(self) -> usize {
        self.kind.max_payload_len()
    }

    /// Frames one canonical payload.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::EmptyPayload`] for an empty payload and
    /// [`FrameError::PayloadTooLarge`] when it exceeds this stream kind's bound.
    pub fn encode(self, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
        if payload.is_empty() {
            return Err(FrameError::EmptyPayload);
        }
        let limit = self.max_payload_len();
        if payload.len() > limit {
            return Err(FrameError::PayloadTooLarge {
                len: payload.len(),
                limit,
            });
        }
        let mut out = Vec::with_capacity(FRAME_LENGTH_PREFIX_LEN + payload.len());
        let length = u32::try_from(payload.len()).expect("checked against a u32-bounded limit");
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// Serialises a message and frames it.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the message cannot be represented, or a framing error when the
    /// encoding exceeds this stream kind's bound.
    pub fn encode_message<T: serde::Serialize + ?Sized>(
        self,
        message: &T,
    ) -> Result<Vec<u8>, FrameError> {
        let payload = kr_cbor::to_canonical_vec_within(message, &self.kind.cbor_limits())
            .map_err(FrameError::Cbor)?;
        self.encode(&payload)
    }

    /// Validates a length prefix before any payload is read or allocated.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::EmptyPayload`] for a zero length and
    /// [`FrameError::PayloadTooLarge`] when the declared length exceeds this stream kind's bound.
    pub fn decode_length(self, prefix: [u8; FRAME_LENGTH_PREFIX_LEN]) -> Result<usize, FrameError> {
        let declared = u32::from_be_bytes(prefix) as usize;
        if declared == 0 {
            return Err(FrameError::EmptyPayload);
        }
        let limit = self.max_payload_len();
        if declared > limit {
            return Err(FrameError::PayloadTooLarge {
                len: declared,
                limit,
            });
        }
        Ok(declared)
    }

    /// Reads one frame from the front of `buffer`.
    ///
    /// Returns the payload and the number of bytes consumed. The length is validated before the
    /// payload is addressed.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::Incomplete`] when more bytes are needed, or the length failure.
    pub fn decode(self, buffer: &[u8]) -> Result<(&[u8], usize), FrameError> {
        if buffer.len() < FRAME_LENGTH_PREFIX_LEN {
            return Err(FrameError::Incomplete {
                needed: FRAME_LENGTH_PREFIX_LEN - buffer.len(),
            });
        }
        let prefix: [u8; FRAME_LENGTH_PREFIX_LEN] = buffer[..FRAME_LENGTH_PREFIX_LEN]
            .try_into()
            .expect("checked length");
        let declared = self.decode_length(prefix)?;
        let total = FRAME_LENGTH_PREFIX_LEN + declared;
        if buffer.len() < total {
            return Err(FrameError::Incomplete {
                needed: total - buffer.len(),
            });
        }
        Ok((&buffer[FRAME_LENGTH_PREFIX_LEN..total], total))
    }

    /// Reads one frame and deserialises its payload.
    ///
    /// # Errors
    ///
    /// Returns a framing failure, or a CBOR failure when the payload is not a canonical message of
    /// the expected shape.
    pub fn decode_message<T: serde::de::DeserializeOwned + serde::Serialize>(
        self,
        buffer: &[u8],
    ) -> Result<(T, usize), FrameError> {
        let (payload, consumed) = self.decode(buffer)?;
        let message = kr_cbor::from_canonical_slice(payload, &self.kind.cbor_limits())
            .map_err(FrameError::Cbor)?;
        Ok((message, consumed))
    }
}
