//! The one lexical/sequence parser.
//!
//! Section 8 allows exactly one parse of the output stream. This module does it: it frames
//! sequences, validates UTF-8, bounds control strings, decodes tmux passthrough, retains the
//! original bytes and records where the parser stands on ground. Everything downstream, including
//! the canonical grid, consumes [`Event`]s from here and never looks at the bytes again.
//!
//! # Framing rules that differ from a plain VT state machine
//!
//! * **Raw 8-bit C1.** On ground, a byte in `0x80..=0x9F` cannot continue a UTF-8 scalar, so it is
//!   recognised as its C1 control and classified exactly like the 7-bit form. Inside a control
//!   string the same byte is ambiguous (`Ü` is `0xC3 0x9C`), so kr-vt/1 requires the 7-bit `ESC \`
//!   there and never treats `0x9C` as a string terminator. A string whose payload carries such a
//!   byte still reaches the canonical grid, but its bytes never reach a terminal that would frame
//!   them differently.
//! * **Escape doubling belongs to tmux.** `ESC ESC` is one escape of payload only inside a
//!   recognised tmux passthrough envelope, which doubles escapes for exactly that reason. Anywhere
//!   else an `ESC` not followed by `\` abandons the string and starts a new sequence, which is what
//!   a physical terminal does. A general doubling rule would let a payload hide a sequence that the
//!   terminal on the other side would execute.
//! * **Oversized strings never resynchronise on a byte count.** Past its bound a string stops being
//!   collected and starts being discarded in constant memory. It ends at a real terminator, at
//!   `CAN`/`SUB`, or at the end of the stream. An elapsed byte count does not establish a sequence
//!   boundary, so the parser never invents one: the suffix of an oversized payload must never
//!   execute.
//! * **Embedded C0 does not abandon a sequence.** A control byte inside a control-sequence prelude
//!   is consumed and ignored, so the sequence still completes with the parameters it collected.
//! * **Bounded retention.** Every non-ground state bounds the bytes it retains. Past the bound the
//!   parser keeps the framing state and the span length only, and the sequence becomes an
//!   extension.
//!
//! # Splitting across reads
//!
//! Classification spans arbitrary read boundaries, and so does the result. An incomplete scalar or
//! sequence stays pending until the next [`Lexer::feed`], and the event that eventually comes out
//! carries the whole original span.
//!
//! A text run also holds back its final scalar, because the next read may carry a combining mark
//! that belongs to it. Without that, identical bytes would produce different canonical screens
//! depending on where the kernel happened to split the read. [`Lexer::flush_tail`] releases it, and
//! the engine calls that whenever it needs a settled screen.

use crate::event::{
    CsiParam, DirectDisposition, DiscardCause, Event, EventKind, ReplacementCause, SequenceFamily,
};
use crate::span::{ByteSpan, SeqBytes};

/// Bounds the lexer applies before it allocates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LexLimits {
    /// Byte bound on one control string, except OSC 52.
    pub max_control_string: usize,
    /// Byte bound on one OSC 52 string.
    pub max_osc52_string: usize,
    /// Byte bound on the retained bytes of one escape or control sequence.
    ///
    /// A well-formed sequence is far shorter than this. Past the bound the parser keeps its framing
    /// state and the span length and stops retaining bytes, so a stream of digits after `CSI`
    /// cannot make it allocate, and the sequence becomes an extension.
    pub max_sequence_bytes: usize,
    /// Maximum number of parameter items in one control sequence.
    pub max_params: usize,
    /// Maximum number of intermediate bytes in one control sequence.
    pub max_intermediates: usize,
    /// Maximum number of `;`-separated parts in one operating system command.
    pub max_osc_parts: usize,
    /// Maximum tmux passthrough nesting.
    pub max_passthrough_depth: u8,
    /// Byte bound on one text event. A longer run becomes several events.
    pub max_text_run: usize,
    /// Byte bound on one grapheme cluster, which is the content of one cell.
    ///
    /// Section 8 requires per-cell encoded content to be limited so that repeated combining
    /// characters cannot allocate without bound. Past the bound a cluster ends and the next scalar
    /// starts a new one, which the projection shows as a separate cell.
    pub max_cluster_bytes: usize,
}

impl LexLimits {
    /// The kr-vt/1 bounds: 64 KiB control strings, 1 MiB for OSC 52, passthrough depth four.
    pub const DEFAULT: Self = Self {
        max_control_string: 64 * 1024,
        max_osc52_string: 1024 * 1024,
        max_sequence_bytes: 256,
        max_params: 256,
        max_intermediates: 2,
        max_osc_parts: 64,
        max_passthrough_depth: 4,
        max_text_run: 64 * 1024,
        max_cluster_bytes: 64,
    };
}

impl Default for LexLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ground,
    Utf8,
    Escape,
    EscapeIntermediate,
    CsiEntry,
    CsiParam,
    CsiIntermediate,
    CsiIgnore,
    DcsEntry,
    DcsParam,
    DcsIntermediate,
    DcsIgnore,
    DcsPassthrough,
    String(SequenceFamily),
}

impl State {
    /// Whether this state is collecting a sequence prelude rather than a string payload.
    const fn is_prelude(self) -> bool {
        matches!(
            self,
            Self::Escape
                | Self::EscapeIntermediate
                | Self::CsiEntry
                | Self::CsiParam
                | Self::CsiIntermediate
                | Self::CsiIgnore
                | Self::DcsEntry
                | Self::DcsParam
                | Self::DcsIntermediate
                | Self::DcsIgnore
        )
    }
}

/// The single lexical/sequence parser for one session's output stream.
#[derive(Debug)]
pub struct Lexer {
    limits: LexLimits,
    depth: u8,
    state: State,
    /// Offset of the next byte to read.
    offset: u64,
    /// Retained bytes of the sequence under construction, bounded by `max_sequence_bytes`.
    pending: Vec<u8>,
    /// Offset of the first byte of the sequence under construction.
    pending_start: u64,
    /// Total length of the sequence under construction, which may exceed the retained bytes.
    pending_len: u64,
    /// Whether retention stopped because the sequence passed its byte bound.
    pending_truncated: bool,
    /// Bytes of the text run under construction.
    text: Vec<u8>,
    text_start: u64,
    text_scalars: usize,
    /// Byte index in `text` where the final grapheme cluster begins.
    text_cluster: usize,
    /// The scalar before the one being appended, which decides whether a cluster continues.
    text_previous: Option<char>,
    /// UTF-8 decoding state.
    utf8_needed: u8,
    utf8_seen: u8,
    utf8_acc: u32,
    utf8_lead: u8,
    /// Control-sequence accumulation.
    params: Vec<CsiParam>,
    current_param: Option<i64>,
    intermediates: Vec<u8>,
    extra_intermediates: bool,
    truncated: bool,
    /// Control-string accumulation.
    string_buf: Vec<u8>,
    string_parts: Vec<Vec<u8>>,
    string_limit: usize,
    string_seen: usize,
    string_discarding: Option<DiscardCause>,
    string_saw_esc: bool,
    /// Whether a raw 8-bit introducer opened the sequence under construction.
    eight_bit: bool,
    dcs_final: u8,
}

impl Lexer {
    /// Builds a lexer for the outer stream with the kr-vt/1 bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(LexLimits::DEFAULT)
    }

    /// Builds a lexer with explicit bounds.
    #[must_use]
    pub fn with_limits(limits: LexLimits) -> Self {
        Self::nested(limits, 0)
    }

    fn nested(limits: LexLimits, depth: u8) -> Self {
        Self {
            limits,
            depth,
            state: State::Ground,
            offset: 0,
            pending: Vec::new(),
            pending_start: 0,
            pending_len: 0,
            pending_truncated: false,
            text: Vec::new(),
            text_start: 0,
            text_scalars: 0,
            text_cluster: 0,
            text_previous: None,
            utf8_needed: 0,
            utf8_seen: 0,
            utf8_acc: 0,
            utf8_lead: 0,
            params: Vec::new(),
            current_param: None,
            intermediates: Vec::new(),
            extra_intermediates: false,
            truncated: false,
            string_buf: Vec::new(),
            string_parts: Vec::new(),
            string_limit: 0,
            string_seen: 0,
            string_discarding: None,
            string_saw_esc: false,
            eight_bit: false,
            dcs_final: 0,
        }
    }

    /// The bounds in force.
    #[must_use]
    pub const fn limits(&self) -> LexLimits {
        self.limits
    }

    /// Offset of the next byte the lexer will read.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Whether the parser stands on ground: no incomplete scalar and no incomplete sequence.
    ///
    /// A held text tail does not stop the parser being on ground. It is complete output waiting to
    /// see whether the next scalar belongs to it, and [`Lexer::flush_tail`] releases it.
    #[must_use]
    pub fn at_ground(&self) -> bool {
        self.state == State::Ground && self.pending.is_empty()
    }

    /// Number of bytes of an incomplete scalar or sequence the lexer is holding.
    #[must_use]
    pub const fn pending_len(&self) -> u64 {
        self.pending_len
    }

    /// Whether a completed text scalar is being held back for a possible combining mark.
    #[must_use]
    pub fn holds_text_tail(&self) -> bool {
        !self.text.is_empty()
    }

    /// Lexes `input`, appending every finished event to `out`.
    ///
    /// The final scalar of a trailing text run is held back until the next read, so that a
    /// combining mark arriving in the next read still joins the scalar it belongs to.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<Event>) {
        for &byte in input {
            self.byte(byte, out);
        }
        self.flush_text(out, true);
    }

    /// Releases a held text tail.
    ///
    /// The engine calls this whenever it needs a settled screen: before a snapshot, and when the
    /// stream has gone quiet.
    pub fn flush_tail(&mut self, out: &mut Vec<Event>) {
        self.flush_text(out, false);
    }

    /// Closes the stream.
    ///
    /// An incomplete scalar becomes one U+FFFD and an incomplete control string is discarded, both
    /// with the closure cause, so nothing is left dangling at the end of a session.
    pub fn close(&mut self, out: &mut Vec<Event>) {
        self.flush_text(out, false);
        let state = self.state;
        if state == State::Utf8 {
            self.emit_replacement(ReplacementCause::IncompleteAtClosure, 1, out);
        } else if state.is_prelude() {
            let len = usize::try_from(self.pending_len).unwrap_or(usize::MAX);
            self.emit_discard(
                SequenceFamily::ControlSequence,
                DiscardCause::IncompleteAtClosure,
                len,
                out,
            );
        } else if let State::String(family) = state {
            let seen = self.string_seen;
            self.emit_discard(family, DiscardCause::IncompleteAtClosure, seen, out);
        } else if state == State::DcsPassthrough {
            let seen = self.string_seen;
            self.emit_discard(
                SequenceFamily::Dcs,
                DiscardCause::IncompleteAtClosure,
                seen,
                out,
            );
        }
        self.reset_to_ground();
    }

    fn byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match self.state {
            State::Ground => self.ground_byte(byte, out),
            State::Utf8 => self.utf8_byte(byte, out),
            State::Escape => self.escape_byte(byte, out),
            State::EscapeIntermediate => self.escape_intermediate_byte(byte, out),
            State::CsiEntry | State::CsiParam => self.csi_param_byte(byte, out),
            State::CsiIntermediate => self.csi_intermediate_byte(byte, out),
            State::CsiIgnore => self.csi_ignore_byte(byte, out),
            State::DcsEntry | State::DcsParam => self.dcs_param_byte(byte, out),
            State::DcsIntermediate => self.dcs_intermediate_byte(byte, out),
            State::DcsIgnore => self.dcs_ignore_byte(byte, out),
            State::DcsPassthrough => self.string_byte(byte, SequenceFamily::Dcs, out),
            State::String(family) => self.string_byte(byte, family, out),
        }
    }

    // ---------------------------------------------------------------- ground

    fn ground_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x1b => {
                self.flush_text(out, false);
                self.begin_pending(byte);
                self.enter_escape();
            }
            0x00..=0x1f | 0x7f => {
                self.flush_text(out, false);
                self.emit_single(byte, EventKind::Control { byte }, out);
            }
            0x20..=0x7e => {
                if self.text_would_overflow(1) {
                    self.flush_text(out, false);
                }
                self.push_text(byte);
            }
            // Raw 8-bit C1. Section 8 byte policy: recognised as controls on ground.
            0x80..=0x9f => {
                self.flush_text(out, false);
                self.c1_byte(byte, out);
            }
            0xa0..=0xbf => {
                self.flush_text(out, false);
                self.emit_single_replacement(byte, ReplacementCause::IsolatedContinuation, out);
            }
            0xc0 | 0xc1 => {
                self.flush_text(out, false);
                self.emit_single_replacement(byte, ReplacementCause::Overlong, out);
            }
            0xc2..=0xf4 => {
                self.begin_utf8(byte);
            }
            0xf5..=0xff => {
                self.flush_text(out, false);
                self.emit_single_replacement(byte, ReplacementCause::InvalidLead, out);
            }
        }
    }

    fn c1_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        // The 7-bit escape final that this C1 byte stands for.
        let equivalent = match byte {
            0x84 => Some(b'D'),
            0x85 => Some(b'E'),
            0x86 => Some(b'F'),
            0x87 => Some(b'G'),
            0x88 => Some(b'H'),
            0x8d => Some(b'M'),
            0x8e => Some(b'N'),
            0x8f => Some(b'O'),
            _ => None,
        };
        if let Some(final_byte) = equivalent {
            self.begin_pending(byte);
            self.eight_bit = true;
            self.finish_pending(
                EventKind::Esc {
                    intermediate: None,
                    extra_intermediates: false,
                    final_byte,
                },
                out,
            );
            return;
        }
        self.begin_pending(byte);
        self.eight_bit = true;
        match byte {
            0x90 => self.enter_dcs(),
            0x9b => self.enter_csi(),
            0x9d => self.enter_string(SequenceFamily::Osc),
            0x98 => self.enter_string(SequenceFamily::Sos),
            0x9e => self.enter_string(SequenceFamily::Pm),
            0x9f => self.enter_string(SequenceFamily::Apc),
            // 0x9C is a stray string terminator on ground; every other C1 byte is unassigned.
            _ => self.finish_pending(EventKind::Control { byte }, out),
        }
    }

    // ------------------------------------------------------------------ text

    /// Appends one printable ASCII byte. Printable ASCII always starts a cluster.
    fn push_text(&mut self, byte: u8) {
        if self.text.is_empty() {
            self.text_start = self.offset;
        }
        self.text_cluster = self.text.len();
        self.text_previous = Some(char::from(byte));
        self.text.push(byte);
        self.text_scalars += 1;
        self.offset += 1;
    }

    /// Appends one multi-byte scalar, remembering where its cluster began.
    ///
    /// A cluster that has grown past its bound starts a new one whatever the scalar says. That is
    /// what stops an unbounded run of combining marks from becoming one unbounded cell.
    fn push_text_bytes(&mut self, bytes: &[u8], scalar: char) {
        if self.text.is_empty() {
            self.text_start = self.offset;
        }
        let cluster_len = self.text.len() - self.text_cluster;
        let continues = crate::unicode::continues_cluster(self.text_previous, scalar)
            && cluster_len + bytes.len() <= self.limits.max_cluster_bytes;
        if !continues {
            self.text_cluster = self.text.len();
        }
        self.text_previous = Some(scalar);
        self.text.extend_from_slice(bytes);
        self.text_scalars += 1;
        self.offset += bytes.len() as u64;
    }

    /// Emits the text run under construction.
    ///
    /// With `hold_tail`, the final scalar stays behind so that a combining mark in the next read
    /// can still join it.
    fn flush_text(&mut self, out: &mut Vec<Event>, hold_tail: bool) {
        if self.text.is_empty() {
            return;
        }
        // With `hold_tail`, everything from the last cluster starter onward stays behind, because
        // the next read may carry more of that cluster.
        let split = if hold_tail {
            self.text_cluster
        } else {
            self.text.len()
        };
        if split == 0 {
            return;
        }
        // The emitted run is copied out and the held tail is moved to the front of the same buffer.
        // Splitting the vector instead would allocate once per control sequence in the stream.
        let bytes = SeqBytes::new(&self.text[..split]);
        let tail_len = self.text.len() - split;
        self.text.copy_within(split.., 0);
        self.text.truncate(tail_len);
        let scalars = if hold_tail {
            let remaining = count_scalars(&self.text);
            let emitted = self.text_scalars.saturating_sub(remaining);
            self.text_scalars = remaining;
            emitted
        } else {
            core::mem::take(&mut self.text_scalars)
        };
        let span = ByteSpan::new(self.text_start, split as u64);
        self.text_start += split as u64;
        self.text_cluster = 0;
        if self.text.is_empty() {
            self.text_previous = None;
        }
        // A finished text run leaves the parser on ground unless a scalar or a sequence is still
        // being collected, which is exactly the condition a live-forwarding handoff tests.
        let ground_after = self.state == State::Ground && self.pending.is_empty();
        let event = self.build(span, bytes, EventKind::Text { scalars }, ground_after, true);
        out.push(event);
    }

    fn text_would_overflow(&self, extra: usize) -> bool {
        !self.text.is_empty() && self.text.len() + extra > self.limits.max_text_run
    }

    // ------------------------------------------------------------------ utf8

    fn begin_utf8(&mut self, lead: u8) {
        self.begin_pending(lead);
        self.utf8_lead = lead;
        self.utf8_seen = 1;
        match lead {
            0xc2..=0xdf => {
                self.utf8_needed = 2;
                self.utf8_acc = u32::from(lead & 0x1f);
            }
            0xe0..=0xef => {
                self.utf8_needed = 3;
                self.utf8_acc = u32::from(lead & 0x0f);
            }
            _ => {
                self.utf8_needed = 4;
                self.utf8_acc = u32::from(lead & 0x07);
            }
        }
        self.state = State::Utf8;
    }

    fn utf8_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        let valid = match (self.utf8_lead, self.utf8_seen) {
            (0xe0, 1) => (0xa0..=0xbf).contains(&byte),
            (0xed, 1) => (0x80..=0x9f).contains(&byte),
            (0xf0, 1) => (0x90..=0xbf).contains(&byte),
            (0xf4, 1) => (0x80..=0x8f).contains(&byte),
            _ => (0x80..=0xbf).contains(&byte),
        };
        if !valid {
            let cause = match (self.utf8_lead, self.utf8_seen, byte) {
                (0xe0, 1, 0x80..=0x9f) | (0xf0, 1, 0x80..=0x8f) => ReplacementCause::Overlong,
                (0xed, 1, 0xa0..=0xbf) => ReplacementCause::Surrogate,
                (0xf4, 1, 0x90..=0xbf) => ReplacementCause::OutOfRange,
                _ => ReplacementCause::TruncatedScalar,
            };
            self.emit_replacement(cause, 1, out);
            self.state = State::Ground;
            self.ground_byte(byte, out);
            return;
        }
        self.retain(byte);
        self.utf8_acc = (self.utf8_acc << 6) | u32::from(byte & 0x3f);
        self.utf8_seen += 1;
        if self.utf8_seen < self.utf8_needed {
            return;
        }
        let scalar = self.utf8_acc;
        let bytes = core::mem::take(&mut self.pending);
        let start = self.pending_start;
        self.pending_len = 0;
        self.pending_truncated = false;
        self.state = State::Ground;
        if (0x80..=0x9f).contains(&scalar) {
            // Section 8: a scalar is never reinterpreted as raw C1, and kr-vt/1 does not print it.
            let span = ByteSpan::new(start, bytes.len() as u64);
            self.flush_text(out, false);
            let event = self.build(
                span,
                SeqBytes::from_vec(bytes),
                EventKind::Replacement {
                    cause: ReplacementCause::EncodedC1Scalar,
                    count: 1,
                },
                true,
                true,
            );
            out.push(event);
            return;
        }
        if self.text_would_overflow(bytes.len()) {
            self.flush_text(out, false);
        }
        // `offset` already counted these bytes while they were pending.
        self.offset -= bytes.len() as u64;
        let scalar = char::from_u32(scalar).unwrap_or(char::REPLACEMENT_CHARACTER);
        self.push_text_bytes(&bytes, scalar);
    }

    // ---------------------------------------------------------------- escape

    fn enter_escape(&mut self) {
        self.params.clear();
        self.current_param = None;
        self.intermediates.clear();
        self.extra_intermediates = false;
        self.truncated = false;
        self.state = State::Escape;
    }

    fn escape_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x20..=0x2f => {
                self.retain(byte);
                self.intermediates.push(byte);
                self.state = State::EscapeIntermediate;
            }
            b'[' => {
                self.retain(byte);
                self.enter_csi();
            }
            b']' => {
                self.retain(byte);
                self.enter_string(SequenceFamily::Osc);
            }
            b'P' => {
                self.retain(byte);
                self.enter_dcs();
            }
            b'X' => {
                self.retain(byte);
                self.enter_string(SequenceFamily::Sos);
            }
            b'^' => {
                self.retain(byte);
                self.enter_string(SequenceFamily::Pm);
            }
            b'_' => {
                self.retain(byte);
                self.enter_string(SequenceFamily::Apc);
            }
            0x30..=0x7e => {
                self.retain(byte);
                self.finish_pending(
                    EventKind::Esc {
                        intermediate: None,
                        extra_intermediates: false,
                        final_byte: byte,
                    },
                    out,
                );
            }
            _ => self.prelude_other(byte, out),
        }
    }

    fn escape_intermediate_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x20..=0x2f => {
                self.retain(byte);
                if self.intermediates.len() < self.limits.max_intermediates {
                    self.intermediates.push(byte);
                }
                self.extra_intermediates = true;
            }
            0x30..=0x7e => {
                self.retain(byte);
                let intermediate = self.intermediates.first().copied();
                let extra = self.extra_intermediates;
                self.finish_pending(
                    EventKind::Esc {
                        intermediate,
                        extra_intermediates: extra,
                        final_byte: byte,
                    },
                    out,
                );
            }
            _ => self.prelude_other(byte, out),
        }
    }

    // ------------------------------------------------------------------- csi

    fn enter_csi(&mut self) {
        self.params.clear();
        self.current_param = None;
        self.intermediates.clear();
        self.extra_intermediates = false;
        self.truncated = false;
        self.state = State::CsiEntry;
    }

    fn csi_param_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x30..=0x39 => {
                self.retain(byte);
                self.state = State::CsiParam;
                self.accumulate_digit(byte);
            }
            0x3a..=0x3f => {
                self.retain(byte);
                self.state = State::CsiParam;
                self.finish_param();
                self.push_param(CsiParam::Punct(byte));
            }
            0x20..=0x2f => {
                self.retain(byte);
                self.state = State::CsiIntermediate;
                self.intermediates.push(byte);
            }
            0x40..=0x7e => {
                self.retain(byte);
                self.dispatch_csi(byte, out);
            }
            _ => self.prelude_other(byte, out),
        }
    }

    fn csi_intermediate_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x20..=0x2f => {
                self.retain(byte);
                if self.intermediates.len() < self.limits.max_intermediates {
                    self.intermediates.push(byte);
                } else {
                    self.truncated = true;
                }
            }
            0x30..=0x3f => {
                // A parameter byte after an intermediate is ill-formed; nothing is dispatched.
                self.retain(byte);
                self.state = State::CsiIgnore;
            }
            0x40..=0x7e => {
                self.retain(byte);
                self.dispatch_csi(byte, out);
            }
            _ => self.prelude_other(byte, out),
        }
    }

    fn csi_ignore_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x40..=0x7e => {
                self.retain(byte);
                self.finish_pending(EventKind::CsiIgnored { final_byte: byte }, out);
            }
            0x20..=0x3f => self.retain(byte),
            _ => self.prelude_other(byte, out),
        }
    }

    fn accumulate_digit(&mut self, byte: u8) {
        let digit = i64::from(byte - b'0');
        let next = self
            .current_param
            .unwrap_or(0)
            .saturating_mul(10)
            .saturating_add(digit);
        self.current_param = Some(next);
    }

    fn finish_param(&mut self) {
        if let Some(value) = self.current_param.take() {
            self.push_param(CsiParam::Integer(value));
        }
    }

    fn push_param(&mut self, param: CsiParam) {
        if self.params.len() < self.limits.max_params {
            self.params.push(param);
        } else {
            self.truncated = true;
        }
    }

    fn dispatch_csi(&mut self, final_byte: u8, out: &mut Vec<Event>) {
        self.finish_param();
        let intermediates = core::mem::take(&mut self.intermediates);
        for byte in intermediates {
            self.push_param(CsiParam::Punct(byte));
        }
        let params = core::mem::take(&mut self.params);
        let truncated = self.truncated || self.extra_intermediates || self.pending_truncated;
        self.finish_pending(
            EventKind::Csi {
                params,
                truncated,
                final_byte,
            },
            out,
        );
    }

    // ------------------------------------------------------------------- dcs

    fn enter_dcs(&mut self) {
        self.params.clear();
        self.current_param = None;
        self.intermediates.clear();
        self.extra_intermediates = false;
        self.truncated = false;
        self.state = State::DcsEntry;
    }

    fn dcs_param_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x30..=0x39 => {
                self.retain(byte);
                self.state = State::DcsParam;
                self.accumulate_digit(byte);
            }
            0x3a..=0x3f => {
                self.retain(byte);
                self.state = State::DcsParam;
                self.finish_param();
                self.push_param(CsiParam::Punct(byte));
            }
            0x20..=0x2f => {
                self.retain(byte);
                self.state = State::DcsIntermediate;
                self.intermediates.push(byte);
            }
            0x40..=0x7e => {
                self.retain(byte);
                self.hook_dcs(byte);
            }
            _ => self.prelude_other(byte, out),
        }
    }

    fn dcs_intermediate_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x20..=0x2f => {
                self.retain(byte);
                if self.intermediates.len() < self.limits.max_intermediates {
                    self.intermediates.push(byte);
                } else {
                    self.truncated = true;
                }
            }
            0x30..=0x3f => {
                self.retain(byte);
                self.state = State::DcsIgnore;
            }
            0x40..=0x7e => {
                self.retain(byte);
                self.hook_dcs(byte);
            }
            _ => self.prelude_other(byte, out),
        }
    }

    fn dcs_ignore_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        // An ill-formed DCS prelude still has a string body that must be consumed, not executed.
        match byte {
            0x40..=0x7e => {
                self.retain(byte);
                self.hook_dcs(byte);
                self.string_discarding = Some(DiscardCause::Cancelled);
            }
            0x20..=0x3f => self.retain(byte),
            _ => self.prelude_other(byte, out),
        }
    }

    fn hook_dcs(&mut self, final_byte: u8) {
        self.finish_param();
        self.dcs_final = final_byte;
        self.string_buf.clear();
        self.string_parts.clear();
        self.string_limit = self.limits.max_control_string;
        self.string_seen = 0;
        self.string_discarding = None;
        self.string_saw_esc = false;
        self.state = State::DcsPassthrough;
    }

    // ---------------------------------------------------------------- string

    fn enter_string(&mut self, family: SequenceFamily) {
        self.string_buf.clear();
        self.string_parts.clear();
        self.string_limit = self.limits.max_control_string;
        self.string_seen = 0;
        self.string_discarding = None;
        self.string_saw_esc = false;
        self.state = State::String(family);
    }

    /// Whether `ESC ESC` currently means one escape of payload.
    ///
    /// Only inside a recognised tmux passthrough envelope, which doubles escapes so that its
    /// contents cannot end the string early.
    fn escape_doubling_applies(&self) -> bool {
        self.state == State::DcsPassthrough
            && self.dcs_final == b't'
            && self.string_buf.starts_with(b"mux;")
    }

    fn string_byte(&mut self, byte: u8, family: SequenceFamily, out: &mut Vec<Event>) {
        if self.string_saw_esc {
            self.string_saw_esc = false;
            if byte == b'\\' {
                self.retain(byte);
                self.terminate_string(family, out);
                return;
            }
            if byte == 0x1b && self.escape_doubling_applies() {
                self.retain(byte);
                self.push_string_payload(0x1b, family);
                self.push_string_payload(0x1b, family);
                return;
            }
            if self.string_discarding.is_some() {
                // Never let the suffix of an oversized payload execute.
                self.retain(byte);
                self.string_seen = self.string_seen.saturating_add(1);
                return;
            }
            // ESC followed by anything else abandons the string and starts a new sequence.
            let seen = self.string_seen;
            self.unretain_escape();
            self.emit_discard(family, DiscardCause::Cancelled, seen, out);
            self.begin_pending(0x1b);
            self.enter_escape();
            self.byte(byte, out);
            return;
        }
        match byte {
            0x1b => {
                self.retain(byte);
                self.string_saw_esc = true;
            }
            0x07 if family == SequenceFamily::Osc => {
                self.retain(byte);
                self.terminate_string(family, out);
            }
            0x18 | 0x1a => {
                self.retain(byte);
                let seen = self.string_seen;
                self.emit_discard(family, DiscardCause::Cancelled, seen, out);
            }
            _ => {
                self.retain(byte);
                self.push_string_payload(byte, family);
            }
        }
    }

    /// Adds one payload byte, applying the string's bounds.
    fn push_string_payload(&mut self, byte: u8, family: SequenceFamily) {
        self.string_seen = self.string_seen.saturating_add(1);
        if self.string_discarding.is_some() {
            return;
        }
        if family == SequenceFamily::Osc && byte == b';' {
            if self.string_parts.len() >= self.limits.max_osc_parts {
                self.begin_discarding(DiscardCause::TooManyParts);
                return;
            }
            let part = core::mem::take(&mut self.string_buf);
            if self.string_parts.is_empty() && part == b"52" {
                // Section 8 gives OSC 52 its own, larger bound.
                self.string_limit = self.limits.max_osc52_string;
            }
            self.string_parts.push(part);
            return;
        }
        if self.string_seen > self.string_limit {
            self.begin_discarding(DiscardCause::Oversized);
            return;
        }
        self.string_buf.push(byte);
    }

    /// Stops collecting a string and starts discarding it in constant memory.
    fn begin_discarding(&mut self, cause: DiscardCause) {
        self.string_discarding = Some(cause);
        self.string_buf.clear();
        self.string_buf.shrink_to_fit();
        self.string_parts.clear();
        self.string_parts.shrink_to_fit();
    }

    fn terminate_string(&mut self, family: SequenceFamily, out: &mut Vec<Event>) {
        if let Some(cause) = self.string_discarding.take() {
            let seen = self.string_seen;
            self.emit_discard(family, cause, seen, out);
            return;
        }
        let payload = core::mem::take(&mut self.string_buf);
        match family {
            SequenceFamily::Osc => {
                let mut parts = core::mem::take(&mut self.string_parts);
                parts.push(payload);
                let selector = parts
                    .first()
                    .and_then(|p| core::str::from_utf8(p).ok())
                    .and_then(|p| p.parse::<u32>().ok());
                self.finish_pending(EventKind::Osc { selector, parts }, out);
            }
            SequenceFamily::Dcs => {
                let params = core::mem::take(&mut self.params);
                let intermediates = core::mem::take(&mut self.intermediates);
                let final_byte = self.dcs_final;
                self.finish_dcs(params, intermediates, final_byte, payload, out);
            }
            other => {
                self.finish_pending(
                    EventKind::OtherString {
                        family: other,
                        payload,
                    },
                    out,
                );
            }
        }
    }

    fn finish_dcs(
        &mut self,
        params: Vec<CsiParam>,
        intermediates: Vec<u8>,
        final_byte: u8,
        payload: Vec<u8>,
        out: &mut Vec<Event>,
    ) {
        // A tmux passthrough envelope is framing, not content: decode it and lex the payload with
        // the same parser and the same policy, one level deeper.
        if final_byte == b't'
            && params.is_empty()
            && intermediates.is_empty()
            && payload.starts_with(b"mux;")
        {
            if self.depth + 1 > self.limits.max_passthrough_depth {
                self.emit_discard(
                    SequenceFamily::Dcs,
                    DiscardCause::PassthroughTooDeep,
                    payload.len(),
                    out,
                );
                return;
            }
            let span = self.pending_span();
            self.pending.clear();
            self.pending_len = 0;
            self.pending_truncated = false;
            self.state = State::Ground;
            let decoded = undouble_escapes(&payload[4..]);
            let mut inner = Lexer::nested(self.limits, self.depth + 1);
            let mut nested = Vec::new();
            inner.feed(&decoded, &mut nested);
            inner.close(&mut nested);
            let decoded_any = !nested.is_empty();
            for mut event in nested {
                event.span = span;
                event.disposition = match event.disposition {
                    DirectDisposition::Forward => DirectDisposition::RequireProjection,
                    other => other,
                };
                event.ground_after = false;
                out.push(event);
            }
            if decoded_any && let Some(last) = out.last_mut() {
                last.ground_after = true;
            }
            return;
        }
        self.finish_pending(
            EventKind::Dcs {
                params,
                intermediates,
                final_byte,
                payload,
            },
            out,
        );
    }

    // ----------------------------------------------------------- event build

    fn begin_pending(&mut self, byte: u8) {
        self.pending.clear();
        self.pending_start = self.offset;
        self.pending.push(byte);
        self.pending_len = 1;
        self.pending_truncated = false;
        self.offset += 1;
        self.eight_bit = false;
    }

    /// Keeps one more byte of the sequence in flight, inside the retention bound.
    fn retain(&mut self, byte: u8) {
        self.pending_len = self.pending_len.saturating_add(1);
        self.offset += 1;
        if self.pending.len() < self.limits.max_sequence_bytes {
            self.pending.push(byte);
        } else {
            self.pending_truncated = true;
        }
    }

    /// Removes the trailing `ESC` that turned out not to start a terminator.
    fn unretain_escape(&mut self) {
        if !self.pending_truncated {
            self.pending.pop();
        }
        self.pending_len = self.pending_len.saturating_sub(1);
        self.offset -= 1;
    }

    /// A byte that cannot appear where it appeared, inside a sequence prelude.
    ///
    /// `CAN` and `SUB` cancel the sequence and `ESC` restarts it. Every other control byte is
    /// consumed and ignored, so the sequence still completes with the parameters it collected. A
    /// byte at or above `0x80` cannot appear in a well-formed prelude, so it cancels.
    fn prelude_other(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x1b => {
                self.abandon(out);
                self.begin_pending(byte);
                self.enter_escape();
            }
            0x18 | 0x1a => {
                self.retain(byte);
                self.abandon(out);
            }
            0x00..=0x17 | 0x19 | 0x1c..=0x1f | 0x7f => self.retain(byte),
            _ => {
                self.abandon(out);
                self.ground_byte(byte, out);
            }
        }
    }

    fn pending_span(&self) -> ByteSpan {
        ByteSpan::new(self.pending_start, self.pending_len)
    }

    fn finish_pending(&mut self, kind: EventKind, out: &mut Vec<Event>) {
        let span = self.pending_span();
        let bytes = core::mem::take(&mut self.pending);
        let truncated = self.pending_truncated;
        self.pending_len = 0;
        self.pending_truncated = false;
        self.state = State::Ground;
        let direct_safe = !truncated && kind.payload_is_direct_safe();
        let event = self.build(span, SeqBytes::from_vec(bytes), kind, true, direct_safe);
        out.push(event);
    }

    fn emit_discard(
        &mut self,
        family: SequenceFamily,
        cause: DiscardCause,
        payload_len: usize,
        out: &mut Vec<Event>,
    ) {
        self.string_buf.clear();
        self.string_parts.clear();
        self.string_discarding = None;
        self.string_saw_esc = false;
        self.finish_pending(
            EventKind::Discarded {
                family,
                cause,
                payload_len,
            },
            out,
        );
    }

    fn emit_replacement(&mut self, cause: ReplacementCause, count: usize, out: &mut Vec<Event>) {
        self.flush_text(out, false);
        self.finish_pending(EventKind::Replacement { cause, count }, out);
    }

    fn emit_single(&mut self, byte: u8, kind: EventKind, out: &mut Vec<Event>) {
        self.begin_pending(byte);
        self.finish_pending(kind, out);
    }

    fn emit_single_replacement(&mut self, byte: u8, cause: ReplacementCause, out: &mut Vec<Event>) {
        self.emit_single(byte, EventKind::Replacement { cause, count: 1 }, out);
    }

    /// Abandons the sequence in flight as an `X` event.
    fn abandon(&mut self, out: &mut Vec<Event>) {
        let len = usize::try_from(self.pending_len).unwrap_or(usize::MAX);
        self.params.clear();
        self.current_param = None;
        self.intermediates.clear();
        self.extra_intermediates = false;
        self.truncated = false;
        self.finish_pending(
            EventKind::Discarded {
                family: SequenceFamily::ControlSequence,
                cause: DiscardCause::Cancelled,
                payload_len: len,
            },
            out,
        );
    }

    fn reset_to_ground(&mut self) {
        self.state = State::Ground;
        self.pending.clear();
        self.pending_len = 0;
        self.pending_truncated = false;
        self.text.clear();
        self.text_scalars = 0;
        self.text_cluster = 0;
        self.text_previous = None;
        self.params.clear();
        self.current_param = None;
        self.intermediates.clear();
        self.extra_intermediates = false;
        self.string_buf.clear();
        self.string_parts.clear();
        self.string_discarding = None;
        self.string_saw_esc = false;
    }

    fn build(
        &self,
        span: ByteSpan,
        bytes: SeqBytes,
        kind: EventKind,
        ground_after: bool,
        direct_safe: bool,
    ) -> Event {
        let class = crate::classify::classify(&kind);
        let disposition =
            crate::classify::disposition(&kind, class, self.eight_bit || !direct_safe);
        Event {
            span,
            bytes,
            kind,
            class,
            disposition,
            ground_after,
            passthrough_depth: self.depth,
            eight_bit_introducer: self.eight_bit,
        }
    }
}

impl Default for Lexer {
    fn default() -> Self {
        Self::new()
    }
}

/// Counts the scalars in a run of valid UTF-8.
fn count_scalars(bytes: &[u8]) -> usize {
    bytes.iter().filter(|byte| (**byte & 0xc0) != 0x80).count()
}

/// Undoes the `ESC ESC` doubling a tmux passthrough envelope applies to its payload.
#[must_use]
pub fn undouble_escapes(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len());
    let mut index = 0;
    while index < payload.len() {
        let byte = payload[index];
        out.push(byte);
        if byte == 0x1b && payload.get(index + 1) == Some(&0x1b) {
            index += 2;
        } else {
            index += 1;
        }
    }
    out
}
