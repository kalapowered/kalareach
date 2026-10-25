//! The single input lease and the input method group.
//!
//! A session has one input lease with an epoch. A takeover is immediate and linearised: it does
//! not wait for the previous holder's consent, and it invalidates that holder's epoch along with
//! whatever input of theirs had not yet been delivered. Raw input is an ordered stream keyed by
//! connection, epoch and sequence, and a stream that reconnects gets a new identity rather than a
//! replay of old keystrokes.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_paste_recogniser_deadline_is_twenty_five_milliseconds() {
        assert_eq!(PASTE_PREFIX_DEADLINE.get(), 25);
    }
}
