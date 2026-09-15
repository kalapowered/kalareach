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
//!   there and never treats `0x9C` as a string terminator.
//! * **Oversized strings.** Once a control string passes its bound the lexer stops collecting and
//!   starts discarding. While discarding, `ESC` no longer ends the string and starts a fresh
//!   sequence: the suffix of an oversized payload must never execute. The string ends at a real
//!   terminator, at `CAN`/`SUB`, or when the resynchronisation window runs out.
//! * **Malformed preludes.** A byte that cannot appear where it appears abandons the sequence. The
//!   abandoned sequence becomes an `X` event, so it is consumed and never handed to the reducer.
//!
//! # Splitting across reads
//!
//! Classification spans arbitrary read boundaries. An incomplete scalar or sequence stays in
//! [`Lexer::pending`] until the next [`Lexer::feed`], and the event that eventually comes out
//! carries the whole original span, not just its tail. [`Lexer::at_ground`] is false while anything
//! is pending, which is what the 250 ms live-forwarding boundary rule tests.

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
    /// Extra bytes the lexer will read looking for the terminator of an oversized string.
    pub resync_window: usize,
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
}

impl LexLimits {
    /// The kr-vt/1 bounds: 64 KiB control strings, 1 MiB for OSC 52, passthrough depth four.
    pub const DEFAULT: Self = Self {
        max_control_string: 64 * 1024,
        max_osc52_string: 1024 * 1024,
        resync_window: 64 * 1024,
        max_params: 256,
        max_intermediates: 2,
        max_osc_parts: 64,
        max_passthrough_depth: 4,
        max_text_run: 64 * 1024,
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

/// The single lexical/sequence parser for one session's output stream.
#[derive(Debug)]
pub struct Lexer {
    limits: LexLimits,
    depth: u8,
    state: State,
    /// Offset of the next byte to read.
    offset: u64,
    /// Original bytes of the sequence under construction.
    pending: Vec<u8>,
    /// Offset of `pending[0]`.
    pending_start: u64,
    /// Bytes of the text run under construction.
    text: Vec<u8>,
    text_start: u64,
    text_scalars: usize,
    /// UTF-8 decoding state.
    utf8_needed: u8,
    utf8_seen: u8,
    utf8_acc: u32,
    utf8_lead: u8,
    /// Control-sequence accumulation.
    params: Vec<CsiParam>,
    current_param: Option<i64>,
    intermediates: Vec<u8>,
    truncated: bool,
    /// Control-string accumulation.
    string_buf: Vec<u8>,
    string_parts: Vec<Vec<u8>>,
    string_limit: usize,
    string_seen: usize,
    string_discarding: Option<DiscardCause>,
    string_resync: usize,
    string_saw_esc: bool,
    eight_bit: bool,
    /// Whether a raw 8-bit introducer opened the current string.
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
            text: Vec::new(),
            text_start: 0,
            text_scalars: 0,
            utf8_needed: 0,
            utf8_seen: 0,
            utf8_acc: 0,
            utf8_lead: 0,
            params: Vec::new(),
            current_param: None,
            intermediates: Vec::new(),
            truncated: false,
            string_buf: Vec::new(),
            string_parts: Vec::new(),
            string_limit: 0,
            string_seen: 0,
            string_discarding: None,
            string_resync: 0,
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
    /// A transition into live byte forwarding is only allowed where this is true.
    #[must_use]
    pub fn at_ground(&self) -> bool {
        self.state == State::Ground && self.pending.is_empty() && self.text.is_empty()
    }

    /// Number of bytes of an incomplete scalar or sequence the lexer is holding.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Lexes `input`, appending every finished event to `out`.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<Event>) {
        for &byte in input {
            self.byte(byte, out);
        }
        self.flush_text(out);
    }

    /// Closes the stream.
    ///
    /// An incomplete scalar becomes one U+FFFD and an incomplete control string is discarded, both
    /// with the closure cause, so nothing is left dangling at the end of a session.
    pub fn close(&mut self, out: &mut Vec<Event>) {
        self.flush_text(out);
        match self.state {
            State::Ground => {}
            State::Utf8 => {
                self.emit_replacement(ReplacementCause::IncompleteAtClosure, 1, out);
            }
            State::Escape
            | State::EscapeIntermediate
            | State::CsiEntry
            | State::CsiParam
            | State::CsiIntermediate
            | State::CsiIgnore
            | State::DcsEntry
            | State::DcsParam
            | State::DcsIntermediate
            | State::DcsIgnore => {
                self.emit_discard(
                    SequenceFamily::ControlSequence,
                    DiscardCause::IncompleteAtClosure,
                    self.pending.len(),
                    out,
                );
            }
            State::DcsPassthrough => {
                let seen = self.string_seen;
                self.emit_discard(
                    SequenceFamily::Dcs,
                    DiscardCause::IncompleteAtClosure,
                    seen,
                    out,
                );
            }
            State::String(family) => {
                let seen = self.string_seen;
                self.emit_discard(family, DiscardCause::IncompleteAtClosure, seen, out);
            }
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
                self.flush_text(out);
                self.begin_pending(byte);
                self.state = State::Escape;
            }
            0x00..=0x1f | 0x7f => {
                self.flush_text(out);
                self.emit_single(byte, EventKind::Control { byte }, out);
            }
            0x20..=0x7e => {
                if self.text_would_overflow(1) {
                    self.flush_text(out);
                }
                self.push_text(byte, 1);
            }
            // Raw 8-bit C1. Section 8 byte policy: recognised as controls on ground.
            0x80..=0x9f => {
                self.flush_text(out);
                self.c1_byte(byte, out);
            }
            0xa0..=0xbf => {
                self.flush_text(out);
                self.emit_single_replacement(byte, ReplacementCause::IsolatedContinuation, out);
            }
            0xc0 | 0xc1 => {
                self.flush_text(out);
                self.emit_single_replacement(byte, ReplacementCause::Overlong, out);
            }
            0xc2..=0xf4 => {
                self.begin_utf8(byte);
            }
            0xf5..=0xff => {
                self.flush_text(out);
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
                    final_byte,
                },
                out,
            );
            return;
        }
        match byte {
            0x90 => {
                self.begin_pending(byte);
                self.eight_bit = true;
                self.enter_dcs();
            }
            0x9b => {
                self.begin_pending(byte);
                self.eight_bit = true;
                self.enter_csi();
            }
            0x9d => {
                self.begin_pending(byte);
                self.eight_bit = true;
                self.enter_string(SequenceFamily::Osc);
            }
            0x98 => {
                self.begin_pending(byte);
                self.eight_bit = true;
                self.enter_string(SequenceFamily::Sos);
            }
            0x9e => {
                self.begin_pending(byte);
                self.eight_bit = true;
                self.enter_string(SequenceFamily::Pm);
            }
            0x9f => {
                self.begin_pending(byte);
                self.eight_bit = true;
                self.enter_string(SequenceFamily::Apc);
            }
            // 0x9C is a stray string terminator on ground; every other C1 byte is unassigned.
            _ => {
                self.begin_pending(byte);
                self.eight_bit = true;
                self.finish_pending(EventKind::Control { byte }, out);
            }
        }
    }

    // ------------------------------------------------------------------ text

    fn push_text(&mut self, byte: u8, scalars: usize) {
        if self.text.is_empty() {
            self.text_start = self.offset;
        }
        self.text.push(byte);
        self.text_scalars += scalars;
        self.offset += 1;
    }

    fn push_text_bytes(&mut self, bytes: &[u8]) {
        if self.text.is_empty() {
            self.text_start = self.offset;
        }
        self.text.extend_from_slice(bytes);
        self.text_scalars += 1;
        self.offset += bytes.len() as u64;
    }

    fn flush_text(&mut self, out: &mut Vec<Event>) {
        if self.text.is_empty() {
            return;
        }
        let bytes = core::mem::take(&mut self.text);
        let scalars = core::mem::take(&mut self.text_scalars);
        let span = ByteSpan::new(self.text_start, bytes.len() as u64);
        // A finished text run leaves the parser on ground unless a scalar or a sequence is still
        // being collected, which is exactly the condition a live-forwarding handoff tests.
        let ground_after = self.state == State::Ground && self.pending.is_empty();
        let event = self.build(
            span,
            SeqBytes::from_vec(bytes),
            EventKind::Text { scalars },
            ground_after,
        );
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
        self.pending.push(byte);
        self.offset += 1;
        self.utf8_acc = (self.utf8_acc << 6) | u32::from(byte & 0x3f);
        self.utf8_seen += 1;
        if self.utf8_seen < self.utf8_needed {
            return;
        }
        let scalar = self.utf8_acc;
        let bytes = core::mem::take(&mut self.pending);
        self.state = State::Ground;
        if (0x80..=0x9f).contains(&scalar) {
            // Section 8: a scalar is never reinterpreted as raw C1, and kr-vt/1 does not print it.
            let span = ByteSpan::new(self.pending_start, bytes.len() as u64);
            self.flush_text(out);
            let event = self.build(
                span,
                SeqBytes::from_vec(bytes),
                EventKind::Replacement {
                    cause: ReplacementCause::EncodedC1Scalar,
                    count: 1,
                },
                true,
            );
            out.push(event);
            return;
        }
        if self.text_would_overflow(bytes.len()) {
            self.flush_text(out);
        }
        // `offset` already counted these bytes while they were pending.
        self.offset -= bytes.len() as u64;
        self.push_text_bytes(&bytes);
    }

    // ---------------------------------------------------------------- escape

    fn escape_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x20..=0x2f => {
                self.pending.push(byte);
                self.offset += 1;
                self.intermediates.push(byte);
                self.state = State::EscapeIntermediate;
            }
            b'[' => {
                self.pending.push(byte);
                self.offset += 1;
                self.enter_csi();
            }
            b']' => {
                self.pending.push(byte);
                self.offset += 1;
                self.enter_string(SequenceFamily::Osc);
            }
            b'P' => {
                self.pending.push(byte);
                self.offset += 1;
                self.enter_dcs();
            }
            b'X' => {
                self.pending.push(byte);
                self.offset += 1;
                self.enter_string(SequenceFamily::Sos);
            }
            b'^' => {
                self.pending.push(byte);
                self.offset += 1;
                self.enter_string(SequenceFamily::Pm);
            }
            b'_' => {
                self.pending.push(byte);
                self.offset += 1;
                self.enter_string(SequenceFamily::Apc);
            }
            0x30..=0x7e => {
                self.pending.push(byte);
                self.offset += 1;
                self.finish_pending(
                    EventKind::Esc {
                        intermediate: None,
                        final_byte: byte,
                    },
                    out,
                );
            }
            0x1b => {
                // A fresh ESC abandons the one in flight.
                self.abandon(out);
                self.begin_pending(byte);
                self.state = State::Escape;
            }
            _ => self.abandon_and_reprocess(byte, out),
        }
    }

    fn escape_intermediate_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x20..=0x2f => {
                self.pending.push(byte);
                self.offset += 1;
                if self.intermediates.len() < self.limits.max_intermediates {
                    self.intermediates.push(byte);
                } else {
                    self.truncated = true;
                }
            }
            0x30..=0x7e => {
                self.pending.push(byte);
                self.offset += 1;
                let intermediate = self.intermediates.first().copied();
                self.finish_pending(
                    EventKind::Esc {
                        intermediate,
                        final_byte: byte,
                    },
                    out,
                );
            }
            0x1b => {
                self.abandon(out);
                self.begin_pending(byte);
                self.state = State::Escape;
            }
            _ => self.abandon_and_reprocess(byte, out),
        }
    }

    // ------------------------------------------------------------------- csi

    fn enter_csi(&mut self) {
        self.params.clear();
        self.current_param = None;
        self.intermediates.clear();
        self.truncated = false;
        self.state = State::CsiEntry;
    }

    fn csi_param_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x30..=0x39 => {
                self.pending.push(byte);
                self.offset += 1;
                self.state = State::CsiParam;
                let digit = i64::from(byte - b'0');
                let next = self
                    .current_param
                    .unwrap_or(0)
                    .saturating_mul(10)
                    .saturating_add(digit);
                self.current_param = Some(next);
            }
            0x3a..=0x3f => {
                self.pending.push(byte);
                self.offset += 1;
                self.state = State::CsiParam;
                self.finish_param();
                self.push_param(CsiParam::Punct(byte));
            }
            0x20..=0x2f => {
                self.pending.push(byte);
                self.offset += 1;
                self.state = State::CsiIntermediate;
                self.intermediates.push(byte);
            }
            0x40..=0x7e => {
                self.pending.push(byte);
                self.offset += 1;
                self.dispatch_csi(byte, out);
            }
            0x1b => {
                self.abandon(out);
                self.begin_pending(byte);
                self.state = State::Escape;
            }
            _ => self.abandon_and_reprocess(byte, out),
        }
    }

    fn csi_intermediate_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x20..=0x2f => {
                self.pending.push(byte);
                self.offset += 1;
                if self.intermediates.len() < self.limits.max_intermediates {
                    self.intermediates.push(byte);
                } else {
                    self.truncated = true;
                }
            }
            0x30..=0x3f => {
                // A parameter byte after an intermediate is ill-formed; nothing is dispatched.
                self.pending.push(byte);
                self.offset += 1;
                self.state = State::CsiIgnore;
            }
            0x40..=0x7e => {
                self.pending.push(byte);
                self.offset += 1;
                self.dispatch_csi(byte, out);
            }
            0x1b => {
                self.abandon(out);
                self.begin_pending(byte);
                self.state = State::Escape;
            }
            _ => self.abandon_and_reprocess(byte, out),
        }
    }

    fn csi_ignore_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x40..=0x7e => {
                self.pending.push(byte);
                self.offset += 1;
                self.finish_pending(EventKind::CsiIgnored { final_byte: byte }, out);
            }
            0x1b => {
                self.abandon(out);
                self.begin_pending(byte);
                self.state = State::Escape;
            }
            0x20..=0x3f => {
                self.pending.push(byte);
                self.offset += 1;
            }
            _ => self.abandon_and_reprocess(byte, out),
        }
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
        let truncated = self.truncated;
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
        self.truncated = false;
        self.state = State::DcsEntry;
    }

    fn dcs_param_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x30..=0x39 => {
                self.pending.push(byte);
                self.offset += 1;
                self.state = State::DcsParam;
                let digit = i64::from(byte - b'0');
                let next = self
                    .current_param
                    .unwrap_or(0)
                    .saturating_mul(10)
                    .saturating_add(digit);
                self.current_param = Some(next);
            }
            0x3a..=0x3f => {
                self.pending.push(byte);
                self.offset += 1;
                self.state = State::DcsParam;
                self.finish_param();
                self.push_param(CsiParam::Punct(byte));
            }
            0x20..=0x2f => {
                self.pending.push(byte);
                self.offset += 1;
                self.state = State::DcsIntermediate;
                self.intermediates.push(byte);
            }
            0x40..=0x7e => {
                self.pending.push(byte);
                self.offset += 1;
                self.hook_dcs(byte);
            }
            0x1b => {
                self.abandon(out);
                self.begin_pending(byte);
                self.state = State::Escape;
            }
            _ => self.abandon_and_reprocess(byte, out),
        }
    }

    fn dcs_intermediate_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        match byte {
            0x20..=0x2f => {
                self.pending.push(byte);
                self.offset += 1;
                if self.intermediates.len() < self.limits.max_intermediates {
                    self.intermediates.push(byte);
                } else {
                    self.truncated = true;
                }
            }
            0x30..=0x3f => {
                self.pending.push(byte);
                self.offset += 1;
                self.state = State::DcsIgnore;
            }
            0x40..=0x7e => {
                self.pending.push(byte);
                self.offset += 1;
                self.hook_dcs(byte);
            }
            0x1b => {
                self.abandon(out);
                self.begin_pending(byte);
                self.state = State::Escape;
            }
            _ => self.abandon_and_reprocess(byte, out),
        }
    }

    fn dcs_ignore_byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        // An ill-formed DCS prelude still has a string body that must be consumed, not executed.
        match byte {
            0x40..=0x7e => {
                self.pending.push(byte);
                self.offset += 1;
                self.hook_dcs(byte);
                self.string_discarding = Some(DiscardCause::Cancelled);
            }
            0x1b => {
                self.abandon(out);
                self.begin_pending(byte);
                self.state = State::Escape;
            }
            _ => {
                self.pending.push(byte);
                self.offset += 1;
            }
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
        self.string_resync = 0;
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
        self.string_resync = 0;
        self.string_saw_esc = false;
        self.state = State::String(family);
    }

    fn string_byte(&mut self, byte: u8, family: SequenceFamily, out: &mut Vec<Event>) {
        if self.string_saw_esc {
            self.string_saw_esc = false;
            if byte == b'\\' {
                self.pending.push(byte);
                self.offset += 1;
                self.terminate_string(family, out);
                return;
            }
            if byte == 0x1b {
                // `ESC ESC` is one escape inside the payload. A tmux passthrough envelope doubles
                // every escape exactly so that its contents cannot end the string early.
                self.pending.push(byte);
                self.offset += 1;
                self.string_seen += 2;
                if self.string_discarding.is_some() {
                    self.string_resync += 2;
                    self.check_resync(family, out);
                    return;
                }
                if self.string_seen > self.string_limit {
                    self.string_discarding = Some(DiscardCause::Oversized);
                    self.string_buf.clear();
                    self.string_buf.shrink_to_fit();
                    self.string_parts.clear();
                    self.string_parts.shrink_to_fit();
                    return;
                }
                self.string_buf.push(0x1b);
                self.string_buf.push(0x1b);
                return;
            }
            if self.string_discarding.is_some() {
                // Never let the suffix of an oversized payload execute.
                self.pending.push(byte);
                self.offset += 1;
                self.string_resync += 1;
                self.check_resync(family, out);
                return;
            }
            // ESC followed by anything else abandons the string and starts a new sequence.
            let seen = self.string_seen;
            self.pending.pop();
            self.offset -= 1;
            self.emit_discard(family, DiscardCause::Cancelled, seen, out);
            self.begin_pending(0x1b);
            self.state = State::Escape;
            self.byte(byte, out);
            return;
        }
        match byte {
            0x1b => {
                self.pending.push(byte);
                self.offset += 1;
                self.string_saw_esc = true;
            }
            0x07 if family == SequenceFamily::Osc => {
                self.pending.push(byte);
                self.offset += 1;
                self.terminate_string(family, out);
            }
            0x18 | 0x1a => {
                self.pending.push(byte);
                self.offset += 1;
                let seen = self.string_seen;
                self.emit_discard(family, DiscardCause::Cancelled, seen, out);
            }
            _ => {
                self.pending.push(byte);
                self.offset += 1;
                self.string_seen += 1;
                if self.string_discarding.is_some() {
                    self.string_resync += 1;
                    self.check_resync(family, out);
                    return;
                }
                if family == SequenceFamily::Osc && byte == b';' {
                    if self.string_parts.len() >= self.limits.max_osc_parts {
                        self.string_discarding = Some(DiscardCause::TooManyParts);
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
                    self.string_discarding = Some(DiscardCause::Oversized);
                    self.string_buf.clear();
                    self.string_buf.shrink_to_fit();
                    self.string_parts.clear();
                    self.string_parts.shrink_to_fit();
                    return;
                }
                self.string_buf.push(byte);
            }
        }
    }

    fn check_resync(&mut self, family: SequenceFamily, out: &mut Vec<Event>) {
        if self.string_resync > self.limits.resync_window {
            let cause = self.string_discarding.unwrap_or(DiscardCause::Oversized);
            let seen = self.string_seen;
            self.emit_discard(family, cause, seen, out);
        }
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
        self.offset += 1;
        self.eight_bit = false;
    }

    fn pending_span(&self) -> ByteSpan {
        ByteSpan::new(self.pending_start, self.pending.len() as u64)
    }

    fn finish_pending(&mut self, kind: EventKind, out: &mut Vec<Event>) {
        let span = self.pending_span();
        let bytes = core::mem::take(&mut self.pending);
        self.state = State::Ground;
        let event = self.build(span, SeqBytes::from_vec(bytes), kind, true);
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
        self.string_resync = 0;
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
        self.flush_text(out);
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
        let len = self.pending.len();
        self.params.clear();
        self.current_param = None;
        self.intermediates.clear();
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

    fn abandon_and_reprocess(&mut self, byte: u8, out: &mut Vec<Event>) {
        self.abandon(out);
        self.ground_byte(byte, out);
    }

    fn reset_to_ground(&mut self) {
        self.state = State::Ground;
        self.pending.clear();
        self.text.clear();
        self.text_scalars = 0;
        self.params.clear();
        self.current_param = None;
        self.intermediates.clear();
        self.string_buf.clear();
        self.string_parts.clear();
        self.string_discarding = None;
        self.string_resync = 0;
        self.string_saw_esc = false;
    }

    fn build(&self, span: ByteSpan, bytes: SeqBytes, kind: EventKind, ground_after: bool) -> Event {
        let class = crate::classify::classify(&kind);
        let disposition = crate::classify::disposition(&kind, class, self.eight_bit);
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
