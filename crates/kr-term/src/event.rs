//! The events one lexical pass produces.
//!
//! Section 8 requires a single lexical/sequence parser that "retains original byte spans and emits
//! parsed parameters, D/M/Q/S/X class, and parser-ground boundaries". [`Event`] is that output.
//! The policy layer, the canonical grid reducer, the query broker and the direct-mode forwarder all
//! consume these same events; none of them looks at the bytes again.

use crate::class::SequenceClass;
use crate::span::{ByteSpan, SeqBytes};

/// One CSI parameter item.
///
/// The parameter region of a CSI sequence is a mixed list of numbers and punctuation: `1`, `;`,
/// `:`, `?`, `<`, `=`, `>`. Keeping punctuation in the list (rather than flattening to numbers)
/// preserves the difference between `CSI 4 : 3 m` and `CSI 4 ; 3 m`, which mean different things.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsiParam {
    /// A decimal number. Accumulation saturates rather than wrapping.
    Integer(i64),
    /// A punctuation or intermediate byte.
    Punct(u8),
}

impl CsiParam {
    /// The number, when this item is one.
    #[must_use]
    pub const fn integer(self) -> Option<i64> {
        match self {
            Self::Integer(v) => Some(v),
            Self::Punct(_) => None,
        }
    }

    /// The punctuation byte, when this item is one.
    #[must_use]
    pub const fn punct(self) -> Option<u8> {
        match self {
            Self::Punct(b) => Some(b),
            Self::Integer(_) => None,
        }
    }
}

/// Why a run of bytes became U+FFFD instead of text.
///
/// kr-vt/1 is a UTF-8 profile. Each cause here is pinned by a fixture under `fixtures/terminal/`
/// so the replacement behaviour is a contract rather than an accident of the decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplacementCause {
    /// A scalar was encoded in more bytes than it needs.
    Overlong,
    /// The bytes encode a UTF-16 surrogate half, which is not a scalar value.
    Surrogate,
    /// The bytes encode a value above U+10FFFF.
    OutOfRange,
    /// A continuation byte appeared where a scalar could not continue.
    IsolatedContinuation,
    /// A scalar started but the next byte could not continue it.
    TruncatedScalar,
    /// The stream ended part way through a scalar.
    IncompleteAtClosure,
    /// A byte that can never start a valid UTF-8 scalar.
    InvalidLead,
    /// A well-formed scalar in the C1 range U+0080..=U+009F.
    ///
    /// Section 8 forbids reinterpreting the continuation bytes of a scalar as raw C1, so this is
    /// text, not a control. kr-vt/1 replaces it rather than painting an unprintable cell.
    EncodedC1Scalar,
}

/// Why a control string was discarded whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscardCause {
    /// The string passed its byte bound before its terminator arrived.
    Oversized,
    /// The string was cancelled by CAN or SUB.
    Cancelled,
    /// The stream ended before the string was terminated.
    IncompleteAtClosure,
    /// The string held more `;`-separated parts than the profile represents.
    TooManyParts,
    /// A tmux passthrough envelope nested deeper than the profile allows.
    PassthroughTooDeep,
}

/// Which sequence family a discarded sequence belonged to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceFamily {
    /// Operating system command.
    Osc,
    /// Device control string.
    Dcs,
    /// Application program command.
    Apc,
    /// Privacy message.
    Pm,
    /// Start of string.
    Sos,
    /// An escape or control sequence abandoned before it could be dispatched.
    ControlSequence,
}

/// What one lexed sequence is.
#[derive(Debug, Clone, PartialEq)]
pub enum EventKind {
    /// A run of valid, printable UTF-8 text.
    Text {
        /// Number of scalar values in the run.
        scalars: usize,
    },
    /// Malformed or blocked input rendered as U+FFFD.
    Replacement {
        /// Why the bytes were replaced.
        cause: ReplacementCause,
        /// How many U+FFFD the run becomes.
        count: usize,
    },
    /// A C0 or raw 8-bit C1 control that introduces nothing.
    Control {
        /// The control byte, in its original 7-bit or 8-bit form.
        byte: u8,
    },
    /// An escape sequence: `ESC` plus at most one intermediate plus a final byte.
    Esc {
        /// The intermediate byte, when present.
        intermediate: Option<u8>,
        /// Whether more intermediate bytes followed the first.
        ///
        /// kr-vt/1 qualifies escape sequences with at most one intermediate, so a sequence with
        /// more is an extension rather than a shorter sequence with the extras dropped.
        extra_intermediates: bool,
        /// The final byte.
        final_byte: u8,
    },
    /// A control sequence.
    Csi {
        /// Parameters in source order, with the intermediates appended as punctuation.
        params: Vec<CsiParam>,
        /// Whether the parameter list hit its bound and lost items.
        ///
        /// A truncated list is not a shorter sequence. The dropped items could have carried a mode
        /// the profile refuses, so the whole sequence is an extension.
        truncated: bool,
        /// The final byte.
        final_byte: u8,
    },
    /// A control sequence whose parameter region was ill-formed, so nothing is dispatched.
    CsiIgnored {
        /// The final byte that ended the ignored sequence.
        final_byte: u8,
    },
    /// An operating system command, split on `;` exactly as the profile's parser splits it.
    Osc {
        /// The leading numeric selector, when the first part is a number.
        selector: Option<u32>,
        /// Every `;`-separated part, including the selector.
        parts: Vec<Vec<u8>>,
    },
    /// A device control string.
    Dcs {
        /// Parameters in source order.
        params: Vec<CsiParam>,
        /// Intermediate bytes.
        intermediates: Vec<u8>,
        /// The final byte that selected the string's meaning.
        final_byte: u8,
        /// The string payload, without the introducer or the terminator.
        payload: Vec<u8>,
    },
    /// An application program command, privacy message or start-of-string string.
    OtherString {
        /// Which family.
        family: SequenceFamily,
        /// The string payload, without the introducer or the terminator.
        payload: Vec<u8>,
    },
    /// A control string that was discarded whole rather than executed.
    Discarded {
        /// Which family the string belonged to.
        family: SequenceFamily,
        /// Why it was discarded.
        cause: DiscardCause,
        /// How many payload bytes were seen before the string was abandoned.
        payload_len: usize,
    },
}

impl EventKind {
    /// Whether the original bytes of this event are safe to write to a UTF-8 terminal.
    ///
    /// A control string carries an arbitrary payload, and a payload that is not valid UTF-8, or
    /// that contains a control scalar, would be framed differently by a physical terminal than it
    /// was framed here. Such bytes are never forwarded.
    #[must_use]
    pub fn payload_is_direct_safe(&self) -> bool {
        match self {
            Self::Osc { parts, .. } => parts.iter().all(|part| bytes_are_direct_safe(part)),
            Self::Dcs { payload, .. } | Self::OtherString { payload, .. } => {
                bytes_are_direct_safe(payload)
            }
            _ => true,
        }
    }
}

/// Whether a control-string payload can travel to a physical terminal unchanged.
///
/// It has to be valid UTF-8, because kr-vt/1 is a UTF-8 profile, and it has to be free of control
/// scalars, because a terminal that decodes one would end the string somewhere other than where
/// this engine ended it.
#[must_use]
pub fn bytes_are_direct_safe(bytes: &[u8]) -> bool {
    let Ok(text) = core::str::from_utf8(bytes) else {
        return false;
    };
    !text
        .chars()
        .any(|scalar| scalar.is_control() || ('\u{80}'..='\u{9f}').contains(&scalar))
}

/// How the original bytes of an event may be treated in direct mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectDisposition {
    /// The original bytes go to the attachment unchanged.
    Forward,
    /// The bytes cannot go to a physical terminal: the attachment moves to projected mode at the
    /// preceding safe cursor and the engine renders the result instead.
    RequireProjection,
    /// The bytes stop here. The engine answers, routes or drops them.
    Withhold,
}

/// One lexed sequence: its bytes, its span, its class and its parsed parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// Absolute position of the original bytes in the session output stream.
    pub span: ByteSpan,
    /// The original bytes, retained exactly as they arrived.
    pub bytes: SeqBytes,
    /// What the sequence is.
    pub kind: EventKind,
    /// The normative class from the section 8 table.
    pub class: SequenceClass,
    /// What direct mode may do with the original bytes.
    pub disposition: DirectDisposition,
    /// Whether the parser sits at a ground boundary immediately after this event.
    ///
    /// A transition into live byte forwarding may only happen at a boundary where this is true:
    /// no incomplete UTF-8 scalar and no incomplete control sequence.
    pub ground_after: bool,
    /// How deep inside tmux passthrough envelopes the sequence was found. Zero is the outer stream.
    pub passthrough_depth: u8,
    /// Whether a raw 8-bit C1 byte introduced the sequence rather than its 7-bit `ESC` form.
    ///
    /// Section 8 classifies both forms identically, but a raw C1 byte is not valid UTF-8, so its
    /// bytes never reach a physical terminal.
    pub eight_bit_introducer: bool,
    /// Control bytes that arrived inside the sequence.
    ///
    /// A terminal performs these where they appear and carries on collecting the sequence around
    /// them, so they are kept rather than discarded: the engine performs each one in order before
    /// the sequence itself. The sequence's own bytes stop here, because performing a control twice,
    /// once by this engine and once by a terminal reading the same bytes, is worse than repainting.
    pub embedded: Vec<u8>,
}

impl Event {
    /// The original bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Whether the canonical grid reducer may apply this event.
    #[must_use]
    pub const fn reaches_grid(&self) -> bool {
        self.class.reaches_grid()
    }
}
