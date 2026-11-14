//! The single input lease and the input method group.
//!
//! A session has one input lease with an epoch. A takeover is immediate and linearised: it does
//! not wait for the previous holder's consent, and it invalidates that holder's epoch along with
//! whatever input of theirs had not yet been delivered. Raw input is an ordered stream keyed by
//! connection, epoch and sequence, and a stream that reconnects gets a new identity rather than a
//! replay of old keystrokes.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ProtocolError;
use crate::frame::FRAME_LENGTH_PREFIX_LEN;
use crate::ids::{AttachmentId, ConnectionId, InputLeaseEpoch, InputSequence, SessionId};
use crate::scalars::{Bytes, DurationMs, Nullable, U64};

/// The recogniser deadline for a held paste prefix.
///
/// A prefix is kept only until its original deadline. New frames do not reset it, and the timer
/// runs independently of new input, so a lone Escape never waits for another keystroke.
pub const PASTE_PREFIX_DEADLINE: DurationMs = DurationMs::new(25);

/// The current state of the session's single input lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InputLeaseState {
    /// The current epoch. A takeover advances it and invalidates the previous one.
    pub epoch: InputLeaseEpoch,
    /// The attachment that currently holds input. Null when no attachment holds it.
    pub holder: Nullable<AttachmentId>,
    /// The connection the holder's ordered input stream belongs to.
    pub connection_id: Nullable<ConnectionId>,
    /// The next input sequence the worker expects on that stream.
    pub next_sequence: InputSequence,
}

/// Parameters of `input.acquire`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InputAcquireParams {
    /// The session.
    pub session_id: SessionId,
    /// The attachment that will hold the lease.
    pub attachment_id: AttachmentId,
    /// The epoch the caller believes is current, when it wants the takeover to be conditional.
    pub expected_epoch: Nullable<InputLeaseEpoch>,
}

/// The result of `input.acquire`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InputAcquireResult {
    /// The lease after the takeover.
    pub lease: InputLeaseState,
    /// Undelivered bytes the previous epoch lost. Input an application already processed cannot
    /// be undone; this counts only what was still buffered.
    pub discarded_bytes: U64,
    /// True when the worker closed an open bracketed paste before handing input over, so the
    /// application never sees a paste completed under a different actor's lease.
    pub closed_open_paste: bool,
}

/// Parameters of `input.release`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InputReleaseParams {
    /// The session.
    pub session_id: SessionId,
    /// The attachment releasing the lease.
    pub attachment_id: AttachmentId,
    /// The epoch it holds.
    pub epoch: InputLeaseEpoch,
    /// The typing that must have arrived before this release is applied.
    ///
    /// Absent from the wire when the caller asks for no such order, which is every caller that
    /// sends its typing as requests on this connection: they are handled in the order they were
    /// sent. A request that uses none of the optional members is byte for byte what a worker
    /// built before them reads. A worker refuses a member it does not know, so the member is
    /// sent only to a worker that states the input lane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_input: Option<InputBarrier>,
    /// True when the caller wants the count of bytes this release discarded in the answer.
    ///
    /// Absent from the wire when false, and sent only to a worker that states the input lane, for
    /// the reason `after_input` gives.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub fenced_report: bool,
}

/// Parameters of ordered `input.write`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InputWriteParams {
    /// The session.
    pub session_id: SessionId,
    /// The attachment writing.
    pub attachment_id: AttachmentId,
    /// The lease epoch the input belongs to. A stale epoch is `LEASE_LOST` and never acquires
    /// implicitly.
    pub epoch: InputLeaseEpoch,
    /// The position of this input in this connection's ordered input stream.
    pub sequence: InputSequence,
    /// What is written: raw bytes, or the console's key records.
    pub input: InputContent,
}

/// What one `input.write` carries.
///
/// A write is one or the other, never both: bytes a client has already spelled, or key records the
/// worker spells for the session's terminal. Both go through the same ordered stream, the same
/// paste recogniser and the same bound on what one write may produce.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InputContent {
    /// Raw bytes. They are not decoded, re-encoded or normalised.
    Bytes {
        /// The bytes.
        bytes: Bytes,
    },
    /// Key records from a console, in the order the console reported them. The worker spells them
    /// as the session's terminal asked for, and refuses the write when it cannot.
    ConsoleKeys {
        /// The records.
        keys: Vec<ConsoleKey>,
    },
}

impl InputContent {
    /// Returns the stable wire name of this variant.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Bytes { .. } => "bytes",
            Self::ConsoleKeys { .. } => "console_keys",
        }
    }
}

impl std::fmt::Debug for InputContent {
    /// Which variant it is and how much it holds, never what: a write carries what a person typed.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bytes { bytes } => formatter
                .debug_struct("Bytes")
                .field("len", &bytes.len())
                .finish(),
            Self::ConsoleKeys { keys } => formatter
                .debug_struct("ConsoleKeys")
                .field("count", &keys.len())
                .finish(),
        }
    }
}

/// One key event the way a Windows console reports it.
///
/// The six numbers of a `KEY_EVENT_RECORD`, carried as the console read them. The worker, which
/// knows what the session's backend asked for, decides what they are spelled as; a client never
/// invents a scan code or a spelling here.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsoleKey {
    /// The virtual-key code.
    pub virtual_key: u16,
    /// The scan code the keyboard sent, as the console reported it.
    pub scan_code: u16,
    /// One UTF-16 code unit. A character outside the basic plane arrives as two records, a high
    /// surrogate then a low one.
    pub unicode: u16,
    /// True when the key went down, false when it came up.
    pub key_down: bool,
    /// The console's control-key state bits.
    pub control_keys: u32,
    /// How many times the key repeated in this one record.
    pub repeat: u16,
}

impl std::fmt::Debug for ConsoleKey {
    /// Says only that it is a key record: the numbers are what a person typed.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConsoleKey { .. }")
    }
}

/// The result of `input.write`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InputWriteResult {
    /// The sequence the worker has now consumed.
    pub sequence: InputSequence,
    /// Bytes forwarded to the pseudo-terminal.
    pub forwarded_bytes: U64,
    /// Bytes held as an incomplete paste delimiter prefix, pending the recogniser deadline.
    pub held_prefix_bytes: U64,
}

/// What an interrupt may do.
///
/// The method accepts only the configured native interrupt action. It never accepts arbitrary
/// command bytes, and it bypasses the reader-transition hold.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InterruptAction {
    /// The terminal's configured interrupt character, as the session's line discipline defines it.
    NativeInterrupt,
}

/// Parameters of `input.interrupt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InputInterruptParams {
    /// The session.
    pub session_id: SessionId,
    /// The attachment asking for the interrupt.
    pub attachment_id: AttachmentId,
    /// The lease epoch it holds.
    pub epoch: InputLeaseEpoch,
    /// The action. Only the native interrupt is accepted.
    pub action: InterruptAction,
}

/// The result of `input.interrupt` and `input.release`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InputLeaseResult {
    /// The lease after the operation.
    pub lease: InputLeaseState,
    /// The bytes this release discarded, when the request asked for the count.
    ///
    /// Absent from the wire when the request did not ask, and from every answer of a worker built
    /// before the member, which read as a count that is not known. It is never set for
    /// `input.interrupt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fenced_bytes: Option<U64>,
}

/// The typing that must have arrived at the worker before a request is applied.
///
/// A client that sends its typing on a stream of its own cannot rely on the order of that stream
/// against its requests on the control stream. A request that must come after some typing names
/// the first `count` frames of one lease epoch for one attachment, sequences 0 to `count - 1`,
/// counted over every frame the client has admitted, including frames it has not yet written. The
/// worker applies the request only when it has accepted that many frames of the epoch, and
/// refuses it otherwise. It checks the position and never waits for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InputBarrier {
    /// The attachment whose frames are counted.
    pub attachment_id: AttachmentId,
    /// The lease epoch of those frames.
    pub epoch: InputLeaseEpoch,
    /// How many frames of the epoch must have been accepted.
    pub count: U64,
    /// The client's own number for the launch this barrier belongs to, which the worker echoes
    /// when it has dealt with the launch. Null for a request that is not a launch.
    pub launch: Nullable<u32>,
}

/// The length of the bracketed-paste end delimiter, `ESC [ 2 0 1 ~`.
///
/// A frame's claim includes it, since the worker's paste recogniser can add those bytes when a
/// frame ends inside a paste.
pub const PASTE_END_LEN: usize = 6;

/// What the worker holds for one accepted frame: the entries that it takes in its queue, and the
/// bytes in them. The worker spends and gives back this value, and a host that forwards frames
/// charges the same value, so no part of the credit counts encoded bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputClaim {
    /// Entries in the worker's queue: the frame, and the entry the recogniser can add after it.
    pub frames: usize,
    /// Bytes in those entries.
    pub bytes: usize,
}

/// Returns what a frame of `bytes` key bytes claims.
#[must_use]
pub const fn input_claim(bytes: usize) -> InputClaim {
    InputClaim {
        frames: 2,
        bytes: bytes.saturating_add(PASTE_END_LEN),
    }
}

/// What the widest frame adds to its key bytes on the wire, in bytes.
///
/// The frame is a map of three members: the epoch and the sequence at their widest, nine bytes
/// each, and a byte string long enough to need a three-byte head. A test encodes that frame and
/// holds this number to the result.
pub const INPUT_FRAME_OVERHEAD: usize = 43;

/// Returns the most key bytes one frame may hold when a whole frame, its four-byte length prefix
/// included, may take at most `limit` bytes.
///
/// `limit` is the one the connection negotiated, between 1,024 bytes and
/// [`MAX_INPUT_FRAME_LEN`](crate::limits::MAX_INPUT_FRAME_LEN). The client, the host and the worker
/// use this one function, so a paste is cut into the frames the stream can carry.
#[must_use]
pub const fn max_input_bytes(limit: usize) -> usize {
    limit.saturating_sub(FRAME_LENGTH_PREFIX_LEN + INPUT_FRAME_OVERHEAD)
}

/// One frame of typing on a terminal-input stream, from the client to the host.
///
/// A frame is one batch: the worker accepts all of its bytes or none of them. The sequence counts
/// frames from 0 within an epoch, and a new epoch starts again at 0 on the same stream. The debug
/// form shows how many bytes the frame holds and never what they are: they are what a person typed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InputFrame {
    /// The lease epoch the client holds.
    pub epoch: InputLeaseEpoch,
    /// The position of this frame among the epoch's frames.
    pub sequence: InputSequence,
    /// The bytes to write to the terminal. They are not decoded, re-encoded or normalised.
    pub bytes: Bytes,
}

/// How much the client may have written to a terminal-input stream and not yet had accepted.
///
/// It is fixed for the life of the stream, and it is the client's own quantity: the worker's room
/// for the typing is counted in the worker's own unit and belongs to one lease epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InputWindow {
    /// Frames written and not yet accepted.
    pub frames: u32,
    /// Encoded bytes of those frames.
    pub bytes: U64,
}

/// What the host writes on a terminal-input stream, back to the client.
///
/// The stream ends with a reset and no frame of its own. After a refusal the host forwards no
/// later frame of that epoch and writes no second refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InputAck {
    /// The first thing the host writes, once the stream is admitted and the worker's lane is
    /// bound: how much the client may have outstanding.
    Ready {
        /// The client's window.
        window: InputWindow,
    },
    /// The worker accepted every frame of `epoch` with a sequence up to `through`.
    ///
    /// `through` only increases within an epoch. Acceptance is not delivery: it does not say that
    /// the program read the bytes, and a change of the lease discards accepted bytes that the
    /// worker had not yet written.
    Accepted {
        /// The epoch the frames belong to.
        epoch: InputLeaseEpoch,
        /// The last accepted sequence.
        through: InputSequence,
    },
    /// The first definite refusal of an epoch, from the worker or from the host itself.
    Refused {
        /// The epoch of the refused frame.
        epoch: InputLeaseEpoch,
        /// The refused frame. Every later frame of the epoch is refused as well.
        sequence: InputSequence,
        /// The last sequence accepted before it. Null when nothing of the epoch was accepted.
        accepted_through: Nullable<InputSequence>,
        /// Why.
        error: ProtocolError,
    },
    /// The worker has dealt with the launch that the barrier numbered `launch` belonged to.
    ///
    /// It is written after the `Accepted` that covers every frame before the barrier. It means
    /// that later typing is now ordered by the worker's own fence, or that nothing is left to
    /// order; it says nothing about the launch's result.
    LaunchReserved {
        /// The client's number of the launch.
        launch: u32,
    },
    /// The view no longer holds the lease of `epoch`: another view took control, the view released
    /// it, or the grant behind it ended. It is written even when the client has no frame
    /// outstanding.
    EpochEnded {
        /// The epoch that ended.
        epoch: InputLeaseEpoch,
        /// How many bytes the end discarded, accepted ones the worker had not yet written
        /// included.
        fenced_bytes: U64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_paste_recogniser_deadline_is_twenty_five_milliseconds() {
        assert_eq!(PASTE_PREFIX_DEADLINE.get(), 25);
    }
}
