//! The input lease, its epochs, and paste-delimiter framing.
//!
//! One session has one lease. A takeover is immediate and linearised: the new holder gets a new
//! epoch, the old holder's undelivered bytes are dropped, and nothing waits for the previous
//! holder to agree. What has already reached the application cannot be recalled, so the count of
//! discarded bytes is the honest limit of what a takeover can undo.
//!
//! # Why paste framing exists here
//!
//! A bracketed paste is `ESC[200~`, the pasted text, then `ESC[201~`. Those delimiters can arrive
//! split across frames. If the worker did not track them it could hand the second half of a paste
//! to a different controller's lease, and the application would see a paste that begins under one
//! actor and ends under another.
//!
//! The rules are narrow on purpose:
//!
//! * A prefix is held only while bracketed-paste mode is on, or while a paste is already open. A
//!   lone Escape in an ordinary terminal is forwarded immediately.
//! * A held prefix keeps its **original** 25 ms deadline. A later frame does not extend it, and
//!   the timer runs whether or not another byte ever arrives.
//! * On expiry the held bytes are forwarded unchanged. They were never modified, only delayed.
//! * A takeover that interrupts an open paste closes it with `ESC[201~` before the new lease
//!   writes, so the application never sees a paste finished by someone else.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use kr_protocol::ids::{AttachmentId, ConnectionId, InputLeaseEpoch, InputSequence};
use kr_protocol::input::InputLeaseState;
use kr_protocol::scalars::Nullable;
use kr_term::modes::{KITTY_QUALIFIED_FLAGS, KeyboardEncoding};

/// The Kitty flag that asks for the shifted and base forms of a key beside the one pressed.
pub const KITTY_ALTERNATE_KEYS: u8 = 0b0000_0100;

/// What one controller's input path can put on the wire.
///
/// Section 8 makes this a precondition of the lease rather than a hope: a controller holds input
/// only while it can supply the encoding the application has negotiated, and one that cannot is
/// refused so it never sends an encoding it merely advertises. The comparison is
/// [`Encoders::supplies`], and it is made again whenever the application changes the negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Encoders {
    /// The highest `modifyOtherKeys` level this controller can deliver. Zero for none.
    pub modify_other_keys: u8,
    /// The Kitty keyboard flags this controller can deliver.
    pub kitty_flags: u8,
}

impl Encoders {
    /// A controller that builds each key from the logical key and its modifiers.
    ///
    /// It produces whichever protocol it is declared for, because it encodes from the source
    /// information rather than passing on whatever a terminal happened to send. What it may not do
    /// is invent what the source does not contain - a key release, a modifier or a scan code that
    /// was never reported - and that obligation belongs to the encoder itself.
    ///
    /// Alternate-key reporting is **not** among the flags. That flag asks a controller to report
    /// the shifted and base forms of a key alongside the one that was pressed, and
    /// `kr_client::encoder` carries the base key but reports no alternates, so claiming it would
    /// advertise an encoding this build's own encoder does not produce.
    pub const TYPED: Self = Self {
        modify_other_keys: 2,
        kitty_flags: KITTY_QUALIFIED_FLAGS & !KITTY_ALTERNATE_KEYS,
    };

    /// A terminal that implements neither enhanced protocol.
    ///
    /// Every terminal sends the ordinary encoding, so this still controls an application that has
    /// negotiated nothing. It is what a declared terminal outside [`KEYBOARD_PROTOCOLS`] offers.
    pub const LEGACY_ONLY: Self = Self {
        modify_other_keys: 0,
        kitty_flags: 0,
    };

    /// Returns whether this controller can deliver `required`.
    ///
    /// The ordinary encoding is always deliverable: it is what a terminal sends when nothing has
    /// been installed into it. `modifyOtherKeys` is a level, so a controller at level 2 serves an
    /// application that asked for level 1. The Kitty flags are a set, so every flag the
    /// application turned on has to be one this controller produces; a controller that reports
    /// only key presses cannot serve an application that asked for event types.
    #[must_use]
    pub const fn supplies(self, required: KeyboardEncoding) -> bool {
        match required {
            KeyboardEncoding::Legacy => true,
            KeyboardEncoding::ModifyOtherKeys(level) => self.modify_other_keys >= level,
            KeyboardEncoding::Kitty(flags) => self.kitty_flags & flags == flags,
        }
    }

    /// Describes what this controller offers, for the refusal a caller reads.
    #[must_use]
    pub fn describe(self) -> String {
        match (self.modify_other_keys, self.kitty_flags) {
            (0, 0) => "the ordinary terminal encoding only".to_owned(),
            (0, flags) => format!("the Kitty keyboard protocol with flags {flags}"),
            (level, 0) => format!("modifyOtherKeys up to level {level}"),
            (level, flags) => format!(
                "modifyOtherKeys up to level {level} and the Kitty keyboard protocol with flags \
                 {flags}"
            ),
        }
    }
}

/// The keyboard protocols each terminal this build has measured is known to implement.
///
/// What a *presentation* needs is a different question from what a keyboard needs, so this is a
/// different list from [`crate::attachments::QUALIFIED_TERMINALS`]. A terminal outside this one is
/// not refused the keys: it is taken to send the ordinary encoding, which every terminal sends, and
/// it holds the lease while that is what the application reads.
///
/// What the list rests on is stated rather than implied. Each row is what that terminal's own
/// documentation says it implements, and a `TERM` name is the client's claim about which terminal
/// it is rather than a measurement of it - the same limit [`crate::attachments::QUALIFIED_TERMINALS`]
/// carries. So the rows are conservative: a protocol a terminal implements only under a setting, or
/// only by passing it through to something else, is not claimed here, because a controller that
/// advertised it and then sent something else is exactly what section 8 refuses to allow.
pub const KEYBOARD_PROTOCOLS: &[TerminalKeyboard] = &[
    // xterm defines `modifyOtherKeys` and implements no Kitty protocol.
    TerminalKeyboard::new("xterm-256color", 2, 0),
    // The Kitty protocol is kitty's own, and an application turns it on with a sequence rather
    // than a setting.
    TerminalKeyboard::new("xterm-kitty", 0, KITTY_QUALIFIED_FLAGS),
    // WezTerm implements the Kitty protocol behind a configuration option that is off by default
    // (`enable_kitty_keyboard`), so an application that turns it on reaches a terminal that may
    // simply not answer. Nothing claims it here: what is claimed is what an unconfigured terminal
    // of that name does.
    TerminalKeyboard::new("wezterm", 2, 0),
    // Alacritty implements the Kitty protocol and not `modifyOtherKeys`.
    TerminalKeyboard::new("alacritty", 0, KITTY_QUALIFIED_FLAGS),
    TerminalKeyboard::new("foot", 2, KITTY_QUALIFIED_FLAGS),
    TerminalKeyboard::new("ghostty", 2, KITTY_QUALIFIED_FLAGS),
    // tmux is a multiplexer rather than a terminal: what it forwards depends on its own
    // extended-keys setting and on whatever is outside it, and neither is established by the name.
    // So it claims nothing beyond the ordinary encoding.
    TerminalKeyboard::new("tmux-256color", 0, 0),
    // GNU screen implements neither.
    TerminalKeyboard::new("screen-256color", 0, 0),
];

/// One terminal's keyboard protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalKeyboard {
    /// The terminfo name a client declares.
    pub name: &'static str,
    /// The encoders that name is known to offer.
    pub encoders: Encoders,
}

impl TerminalKeyboard {
    const fn new(name: &'static str, modify_other_keys: u8, kitty_flags: u8) -> Self {
        Self {
            name,
            encoders: Encoders {
                modify_other_keys,
                kitty_flags,
            },
        }
    }
}

/// Returns what a declared terminal offers.
///
/// A name this build has not measured still sends the ordinary encoding, so it is
/// [`Encoders::LEGACY_ONLY`] rather than nothing at all. Withholding the declaration entirely is
/// the case that offers nothing, and that is decided by the caller rather than here.
#[must_use]
pub fn terminal_encoders(name: &str) -> Encoders {
    KEYBOARD_PROTOCOLS
        .iter()
        .find(|terminal| terminal.name == name)
        .map_or(Encoders::LEGACY_ONLY, |terminal| terminal.encoders)
}

/// The bracketed-paste start delimiter.
pub const PASTE_START: &[u8] = b"\x1b[200~";

/// The bracketed-paste end delimiter.
pub const PASTE_END: &[u8] = b"\x1b[201~";

/// How long an incomplete delimiter prefix is held.
pub const RECOGNISER_DEADLINE: Duration = Duration::from_millis(25);

/// Tracks bracketed-paste framing on the byte stream going to the pseudo-terminal.
#[derive(Clone, Debug)]
pub struct PasteFramer {
    bracketed_paste_enabled: bool,
    paste_open: bool,
    held: Vec<u8>,
    held_since: Option<Instant>,
}

/// What one push produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramingOutcome {
    /// Bytes to forward now, unchanged.
    pub forward: Vec<u8>,
    /// How many bytes are held as an incomplete delimiter prefix.
    pub held: usize,
    /// When the held prefix must be forwarded even if nothing else arrives.
    pub deadline: Option<Instant>,
    /// True when this push completed a paste start delimiter.
    pub paste_started: bool,
    /// True when this push completed a paste end delimiter.
    pub paste_ended: bool,
    /// Where every delimiter this push completed sits in `forward`, in order.
    ///
    /// A writer that delivers only part of a batch needs to know which delimiters went with the
    /// part it delivered, and whether it stopped in the middle of one. Booleans about the batch as
    /// a whole cannot say either.
    pub delimiters: Vec<Delimiter>,
}

/// One paste delimiter, and where it ends in the bytes being forwarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delimiter {
    /// The offset just past its last byte.
    pub end: u32,
    /// True for a paste start, false for a paste end.
    pub opens: bool,
}

impl Delimiter {
    /// The length of every delimiter this recogniser knows, in bytes.
    pub const LEN: u32 = PASTE_START.len() as u32;

    /// Returns the offset of its first byte.
    #[must_use]
    pub const fn start(self) -> u32 {
        self.end.saturating_sub(Self::LEN)
    }
}

impl Default for PasteFramer {
    fn default() -> Self {
        Self::new()
    }
}

impl PasteFramer {
    /// Builds a framer with bracketed-paste mode off.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bracketed_paste_enabled: false,
            paste_open: false,
            held: Vec::new(),
            held_since: None,
        }
    }

    /// Records whether the application has enabled canonical bracketed-paste mode.
    ///
    /// Returns bytes to forward now. Section 8 tracks framing only while the mode is enabled, and
    /// beyond that only until an already-open paste is safely terminated, so an application that
    /// turns the mode off while a mere delimiter prefix is held has left nothing to protect: those
    /// bytes are released at once rather than waiting out a deadline that now guards nothing. A
    /// prefix held inside an open paste stays held, because that paste still has to be closed.
    pub fn set_bracketed_paste(&mut self, enabled: bool) -> Vec<u8> {
        self.bracketed_paste_enabled = enabled;
        if enabled || self.paste_open {
            return Vec::new();
        }
        self.held_since = None;
        std::mem::take(&mut self.held)
    }

    /// Returns true when a paste has started and not yet ended.
    #[must_use]
    pub const fn paste_open(&self) -> bool {
        self.paste_open
    }

    /// Returns how many bytes are currently held.
    #[must_use]
    pub const fn held_len(&self) -> usize {
        self.held.len()
    }

    /// Returns the deadline of the held prefix, if any.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        self.held_since.map(|since| since + RECOGNISER_DEADLINE)
    }

    /// Feeds bytes through the recogniser.
    ///
    /// The returned bytes are exactly the input, possibly delayed. Nothing is decoded, re-encoded
    /// or rewritten.
    pub fn push(&mut self, bytes: &[u8], now: Instant) -> FramingOutcome {
        // A prefix that has run out of time is forwarded before anything else is looked at. Two
        // bytes that arrive twenty-six milliseconds apart are not a delimiter, however well they
        // would read as one, and completing one here would make the deadline decorative.
        let mut expired = Vec::new();
        if self
            .held_since
            .is_some_and(|since| now.duration_since(since) >= RECOGNISER_DEADLINE)
        {
            expired = std::mem::take(&mut self.held);
            self.held_since = None;
        }
        let mut pending = std::mem::take(&mut self.held);
        // Where the bytes that were already held end. A prefix that starts inside them is the same
        // prefix continued and keeps its original deadline; one that starts after them is a new
        // prefix of its own, and giving it the old deadline would expire it early - which for the
        // second half of a delimiter means never recognising it at all.
        let prior = pending.len();
        let held_since = self.held_since.take();
        pending.extend_from_slice(bytes);

        let mut forward: Vec<u8> = Vec::with_capacity(pending.len());
        let mut paste_started = false;
        let mut paste_ended = false;
        let mut delimiters: Vec<Delimiter> = Vec::new();
        let mut index = 0;

        while index < pending.len() {
            let rest = &pending[index..];
            if self.tracking() {
                if let Some(delimiter) = complete_delimiter(rest) {
                    // A completed delimiter is emitted exactly once, and processing continues with
                    // the bytes after it.
                    if delimiter == PASTE_START {
                        self.paste_open = true;
                        paste_started = true;
                    } else {
                        self.paste_open = false;
                        paste_ended = true;
                    }
                    forward.extend_from_slice(delimiter);
                    delimiters.push(Delimiter {
                        end: u32::try_from(forward.len()).unwrap_or(u32::MAX),
                        opens: delimiter == PASTE_START,
                    });
                    index += delimiter.len();
                    continue;
                }
                if is_proper_prefix(rest) {
                    // Hold the tail. A prefix continued from the bytes already held keeps its
                    // original deadline, because a new frame never buys the recogniser more time;
                    // a prefix that begins after them has not been held before and starts its own.
                    self.held = rest.to_vec();
                    self.held_since = Some(if index < prior {
                        held_since.unwrap_or(now)
                    } else {
                        now
                    });
                    break;
                }
            }
            forward.push(pending[index]);
            index += 1;
        }

        let prefix = expired.len();
        if !expired.is_empty() {
            // The expired prefix goes first, because it arrived first.
            expired.extend_from_slice(&forward);
            forward = expired;
        }
        FramingOutcome {
            forward,
            held: self.held.len(),
            deadline: self.deadline(),
            paste_started,
            paste_ended,
            // The offsets are into what is forwarded, so an expired prefix that went in front of it
            // moves them along with it.
            delimiters: delimiters
                .into_iter()
                .map(|delimiter| Delimiter {
                    end: delimiter
                        .end
                        .saturating_add(u32::try_from(prefix).unwrap_or(u32::MAX)),
                    opens: delimiter.opens,
                })
                .collect(),
        }
    }

    /// Forwards a held prefix once its deadline has passed.
    ///
    /// The deadline is checked against the clock, not against the arrival of more input, so a lone
    /// Escape never waits for another keystroke.
    pub fn expire(&mut self, now: Instant) -> Option<Vec<u8>> {
        let deadline = self.deadline()?;
        if now < deadline {
            return None;
        }
        self.held_since = None;
        Some(std::mem::take(&mut self.held))
    }

    /// Ends framing for a lease that is going away.
    ///
    /// Returns the bytes to write before the next lease's input: an undelivered delimiter prefix
    /// is discarded rather than forwarded, and an open paste is closed so the application never
    /// sees it finished under another actor.
    pub fn close_for_takeover(&mut self) -> TakeoverFraming {
        let discarded = std::mem::take(&mut self.held);
        self.held_since = None;
        let terminator = if self.paste_open {
            self.paste_open = false;
            Some(PASTE_END)
        } else {
            None
        };
        TakeoverFraming {
            discarded_prefix: discarded,
            terminator,
        }
    }

    const fn tracking(&self) -> bool {
        self.bracketed_paste_enabled || self.paste_open
    }
}

/// What a lease change does to paste framing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TakeoverFraming {
    /// The incomplete delimiter prefix that was discarded. Its delivery was never completed, so
    /// the interruption is reported rather than hidden.
    pub discarded_prefix: Vec<u8>,
    /// The terminator written to close an open paste, if one was open.
    pub terminator: Option<&'static [u8]>,
}

fn complete_delimiter(bytes: &[u8]) -> Option<&'static [u8]> {
    if bytes.starts_with(PASTE_START) {
        return Some(PASTE_START);
    }
    if bytes.starts_with(PASTE_END) {
        return Some(PASTE_END);
    }
    None
}

fn is_proper_prefix(bytes: &[u8]) -> bool {
    let candidate = |delimiter: &[u8]| {
        bytes.len() < delimiter.len() && delimiter.starts_with(bytes) && !bytes.is_empty()
    };
    candidate(PASTE_START) || candidate(PASTE_END)
}

/// Why a write was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseRefusal {
    /// The writer's epoch is not the current one. A stale epoch never acquires the lease
    /// implicitly.
    LeaseLost,
    /// The sequence repeated or went backwards on this connection's ordered stream.
    OutOfOrder {
        /// The sequence the worker expects next.
        expected: u64,
        /// The sequence that arrived.
        received: u64,
    },
}

/// The session's single input lease.
#[derive(Clone, Debug)]
pub struct InputLease {
    epoch: u64,
    holder: Option<AttachmentId>,
    connection: Option<ConnectionId>,
    next_sequence: u64,
    queued: VecDeque<QueuedInput>,
    queued_bytes: usize,
}

#[derive(Clone, Debug)]
struct QueuedInput {
    epoch: u64,
    bytes: Vec<u8>,
}

impl Default for InputLease {
    fn default() -> Self {
        Self::new()
    }
}

impl InputLease {
    /// Builds an unheld lease at epoch zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            epoch: 0,
            holder: None,
            connection: None,
            next_sequence: 0,
            queued: VecDeque::new(),
            queued_bytes: 0,
        }
    }

    /// Returns the current epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the current holder.
    #[must_use]
    pub const fn holder(&self) -> Option<AttachmentId> {
        self.holder
    }

    /// Takes the lease for an attachment, advancing the epoch.
    ///
    /// Returns the bytes the previous epoch lost. A takeover does not wait for consent, and it
    /// cannot undo input an application has already read.
    pub fn acquire(&mut self, attachment_id: AttachmentId, connection: ConnectionId) -> u64 {
        let discarded = self.discard_queued();
        self.epoch += 1;
        self.holder = Some(attachment_id);
        self.connection = Some(connection);
        self.next_sequence = 0;
        discarded
    }

    /// Releases the lease held by this attachment at this epoch.
    ///
    /// Returns the bytes the released epoch lost, or `None` when the caller does not hold it.
    pub fn release(&mut self, attachment_id: AttachmentId, epoch: u64) -> Option<u64> {
        if self.holder != Some(attachment_id) || self.epoch != epoch {
            return None;
        }
        let discarded = self.discard_queued();
        self.epoch += 1;
        self.holder = None;
        self.connection = None;
        self.next_sequence = 0;
        Some(discarded)
    }

    /// Removes the lease if this attachment holds it, as part of a detach.
    pub fn release_attachment(&mut self, attachment_id: AttachmentId) -> u64 {
        if self.holder != Some(attachment_id) {
            return 0;
        }
        let discarded = self.discard_queued();
        self.epoch += 1;
        self.holder = None;
        self.connection = None;
        self.next_sequence = 0;
        discarded
    }

    /// Checks a write against the lease and its ordered stream.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseRefusal::LeaseLost`] for a stale epoch or a caller that does not hold the
    /// lease, and [`LeaseRefusal::OutOfOrder`] when the sequence does not follow.
    pub fn accept_write(
        &mut self,
        attachment_id: AttachmentId,
        epoch: u64,
        sequence: u64,
    ) -> Result<(), LeaseRefusal> {
        if self.holder != Some(attachment_id) || self.epoch != epoch {
            return Err(LeaseRefusal::LeaseLost);
        }
        if sequence != self.next_sequence {
            return Err(LeaseRefusal::OutOfOrder {
                expected: self.next_sequence,
                received: sequence,
            });
        }
        self.next_sequence += 1;
        Ok(())
    }

    /// Queues bytes for the pseudo-terminal under the current epoch.
    pub fn enqueue(&mut self, bytes: Vec<u8>) {
        self.queued_bytes += bytes.len();
        self.queued.push_back(QueuedInput {
            epoch: self.epoch,
            bytes,
        });
    }

    /// Takes the next queued write.
    pub fn dequeue(&mut self) -> Option<Vec<u8>> {
        let entry = self.queued.pop_front()?;
        self.queued_bytes -= entry.bytes.len();
        Some(entry.bytes)
    }

    /// Returns the bytes waiting to reach the pseudo-terminal.
    #[must_use]
    pub const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Renders the lease for the wire.
    #[must_use]
    pub fn to_wire(&self) -> InputLeaseState {
        InputLeaseState {
            epoch: InputLeaseEpoch::new(self.epoch),
            holder: Nullable(self.holder),
            connection_id: Nullable(self.connection),
            next_sequence: InputSequence::new(self.next_sequence),
        }
    }

    fn discard_queued(&mut self) -> u64 {
        let current = self.epoch;
        let mut discarded = 0_u64;
        self.queued.retain(|entry| {
            if entry.epoch == current {
                discarded += entry.bytes.len() as u64;
                false
            } else {
                true
            }
        });
        self.queued_bytes -= usize::try_from(discarded).unwrap_or(0);
        discarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-REQ-08.60: the check is against what the application negotiated, not against a label.
    #[test]
    fn a_controller_supplies_an_encoding_only_when_it_produces_every_part_of_it() {
        let xterm = terminal_encoders("xterm-256color");
        assert!(xterm.supplies(KeyboardEncoding::Legacy));
        assert!(xterm.supplies(KeyboardEncoding::ModifyOtherKeys(1)));
        assert!(xterm.supplies(KeyboardEncoding::ModifyOtherKeys(2)));
        assert!(
            !xterm.supplies(KeyboardEncoding::Kitty(0b0001)),
            "xterm implements no Kitty protocol"
        );

        let kitty = terminal_encoders("xterm-kitty");
        assert!(kitty.supplies(KeyboardEncoding::Kitty(KITTY_QUALIFIED_FLAGS)));
        assert!(kitty.supplies(KeyboardEncoding::Kitty(0b0101)));
        assert!(
            !kitty.supplies(KeyboardEncoding::ModifyOtherKeys(1)),
            "and nothing claims modifyOtherKeys for it"
        );

        // A flag the controller does not produce is not covered by the flags it does.
        let partial = Encoders {
            modify_other_keys: 0,
            kitty_flags: 0b0001,
        };
        assert!(partial.supplies(KeyboardEncoding::Kitty(0b0001)));
        assert!(
            !partial.supplies(KeyboardEncoding::Kitty(0b0011)),
            "a controller that reports no event types cannot serve one that asked for them"
        );
    }

    /// KR-REQ-08.60: a name this build has not measured still sends the ordinary encoding.
    #[test]
    fn an_unmeasured_terminal_offers_the_ordinary_encoding_and_no_more() {
        let unknown = terminal_encoders("vt100");
        assert_eq!(unknown, Encoders::LEGACY_ONLY);
        assert!(unknown.supplies(KeyboardEncoding::Legacy));
        assert!(!unknown.supplies(KeyboardEncoding::ModifyOtherKeys(1)));
        assert!(!unknown.supplies(KeyboardEncoding::Kitty(0b0001)));
    }

    /// KR-REQ-08.60: the typed encoder produces what it is declared for, and no more.
    #[test]
    fn the_typed_encoder_supplies_what_this_builds_encoder_actually_produces() {
        for required in [
            KeyboardEncoding::Legacy,
            KeyboardEncoding::ModifyOtherKeys(1),
            KeyboardEncoding::ModifyOtherKeys(2),
            KeyboardEncoding::Kitty(0b0000_0001),
            KeyboardEncoding::Kitty(0b0000_0011),
            KeyboardEncoding::Kitty(0b0000_1011),
        ] {
            assert!(Encoders::TYPED.supplies(required), "{required:?}");
        }
        assert!(
            !Encoders::TYPED.supplies(KeyboardEncoding::Kitty(KITTY_ALTERNATE_KEYS)),
            "alternate-key reporting is a flag this build's encoder does not produce, so nothing \
             claims it and an application that asks for it refuses the typed controller too"
        );
        assert!(
            !Encoders::TYPED.supplies(KeyboardEncoding::Kitty(KITTY_QUALIFIED_FLAGS)),
            "and the whole qualified set includes it"
        );
        assert!(
            !Encoders::TYPED.supplies(KeyboardEncoding::Kitty(0b0001_0000)),
            "text association is outside the profile, so nothing advertises it"
        );
    }

    /// KR-REQ-08.60: every name a presentation may be direct for has a keyboard row as well, so a
    /// terminal can never be handed the stream by one table and left unexplained by the other.
    #[test]
    fn every_qualified_terminal_has_a_keyboard_row() {
        for name in crate::attachments::QUALIFIED_TERMINALS {
            assert!(
                KEYBOARD_PROTOCOLS
                    .iter()
                    .any(|terminal| terminal.name == *name),
                "{name} is qualified for a direct presentation and has no keyboard row"
            );
        }
        for terminal in KEYBOARD_PROTOCOLS {
            assert_eq!(
                terminal.encoders.kitty_flags & !KITTY_QUALIFIED_FLAGS,
                0,
                "{} claims a Kitty flag outside the profile",
                terminal.name
            );
            assert!(
                terminal.encoders.modify_other_keys <= 2,
                "{} claims a modifyOtherKeys level above the protocol's",
                terminal.name
            );
        }
    }

    /// KR-REQ-08.64: a completed delimiter is emitted once, and the writer is told where it sits.
    #[test]
    fn every_delimiter_is_reported_with_where_it_sits() {
        let mut framer = PasteFramer::new();
        framer.set_bracketed_paste(true);
        // Ordinary bytes, a whole paste, more ordinary bytes, and a second whole paste.
        let outcome = framer.push(
            b"ab\x1b[200~xy\x1b[201~cd\x1b[200~z\x1b[201~",
            Instant::now(),
        );
        let ends: Vec<_> = outcome
            .delimiters
            .iter()
            .map(|delimiter| (delimiter.end, delimiter.opens))
            .collect();
        assert_eq!(ends, vec![(8, true), (16, false), (24, true), (31, false)]);
        assert_eq!(
            outcome.delimiters[0].start(),
            2,
            "and where each one begins"
        );
    }

    /// KR-REQ-08.64: an expired prefix is forwarded unchanged, in front of what followed it.
    #[test]
    fn a_prefix_that_expired_moves_the_offsets_along_with_it() {
        let mut framer = PasteFramer::new();
        framer.set_bracketed_paste(true);
        let start = Instant::now();
        // A lone escape is held, and its deadline passes before the next bytes arrive.
        let held = framer.push(b"\x1b", start);
        assert_eq!(held.held, 1);
        let outcome = framer.push(b"\x1b[200~", start + RECOGNISER_DEADLINE);
        assert_eq!(outcome.forward, b"\x1b\x1b[200~".to_vec());
        assert_eq!(
            outcome.delimiters.first().map(|delimiter| delimiter.end),
            Some(7),
            "the delimiter ends where it ends in what is forwarded"
        );
    }

    use kr_protocol::scalars::Uuid;

    fn attachment(byte: u8) -> AttachmentId {
        AttachmentId::new(Uuid::from_bytes([byte; 16]))
    }

    fn connection(byte: u8) -> ConnectionId {
        ConnectionId::new(Uuid::from_bytes([byte; 16]))
    }

    /// KR-REQ-08.64: with the mode off and no paste open, an Escape gets no prefix hold.
    #[test]
    fn an_escape_is_forwarded_at_once_when_bracketed_paste_is_off() {
        let mut framer = PasteFramer::new();
        let outcome = framer.push(b"\x1b", Instant::now());
        assert_eq!(outcome.forward, b"\x1b");
        assert_eq!(outcome.held, 0);
        assert!(outcome.deadline.is_none());
    }

    /// KR-REQ-08.64, KR-PERF-002: the expiry runs on the clock, not on the next keystroke.
    #[test]
    fn a_lone_escape_is_held_and_then_expires_without_another_key() {
        let mut framer = PasteFramer::new();
        framer.set_bracketed_paste(true);
        let start = Instant::now();
        let outcome = framer.push(b"\x1b", start);
        assert!(outcome.forward.is_empty());
        assert_eq!(outcome.held, 1);
        assert_eq!(outcome.deadline, Some(start + RECOGNISER_DEADLINE));
        assert!(framer.expire(start + Duration::from_millis(24)).is_none());
        assert_eq!(
            framer.expire(start + RECOGNISER_DEADLINE),
            Some(b"\x1b".to_vec())
        );
    }

    /// KR-REQ-08.64, KR-PERF-002: recognition runs over the held prefix plus the new bytes.
    #[test]
    fn a_delimiter_split_across_frames_is_recognised_once_with_its_payload_kept() {
        let mut framer = PasteFramer::new();
        framer.set_bracketed_paste(true);
        let start = Instant::now();
        let first = framer.push(b"\x1b[20", start);
        assert!(first.forward.is_empty());
        assert_eq!(first.held, 4);
        let second = framer.push(b"0~hello", start + Duration::from_millis(5));
        assert_eq!(second.forward, b"\x1b[200~hello");
        assert!(second.paste_started);
        assert_eq!(second.held, 0);
        assert!(framer.paste_open());
    }

    /// KR-REQ-08.64: a new frame does not buy a held prefix more time.
    #[test]
    fn a_later_frame_does_not_extend_the_original_deadline() {
        let mut framer = PasteFramer::new();
        framer.set_bracketed_paste(true);
        let start = Instant::now();
        framer.push(b"\x1b", start);
        // Another byte that still does not complete a delimiter keeps the first deadline.
        let outcome = framer.push(b"[", start + Duration::from_millis(20));
        assert_eq!(outcome.deadline, Some(start + RECOGNISER_DEADLINE));
    }

    /// KR-REQ-08.64, KR-PERF-002: every prefix length is held, not only the first.
    #[test]
    fn every_prefix_length_of_the_start_delimiter_is_held() {
        for length in 1..PASTE_START.len() {
            let mut framer = PasteFramer::new();
            framer.set_bracketed_paste(true);
            let outcome = framer.push(&PASTE_START[..length], Instant::now());
            assert!(outcome.forward.is_empty(), "prefix of length {length}");
            assert_eq!(outcome.held, length);
        }
    }

    /// KR-REQ-08.64: bytes that match no delimiter are forwarded unchanged.
    #[test]
    fn bytes_that_match_no_delimiter_are_forwarded_unchanged() {
        let mut framer = PasteFramer::new();
        framer.set_bracketed_paste(true);
        let outcome = framer.push(b"\x1b[A\x1bOB", Instant::now());
        assert_eq!(outcome.forward, b"\x1b[A\x1bOB");
        assert_eq!(outcome.held, 0);
    }

    /// KR-REQ-08.64: an open paste is closed before the next lease's input.
    #[test]
    fn an_open_paste_is_closed_before_the_next_lease_writes() {
        let mut framer = PasteFramer::new();
        framer.set_bracketed_paste(true);
        framer.push(b"\x1b[200~part", Instant::now());
        assert!(framer.paste_open());
        let framing = framer.close_for_takeover();
        assert_eq!(framing.terminator, Some(PASTE_END));
        assert!(!framer.paste_open());
    }

    /// KR-REQ-08.64: an undelivered delimiter is discarded on source loss, not forwarded.
    #[test]
    fn an_incomplete_delimiter_is_discarded_on_takeover_rather_than_forwarded() {
        let mut framer = PasteFramer::new();
        framer.set_bracketed_paste(true);
        framer.push(b"\x1b[20", Instant::now());
        let framing = framer.close_for_takeover();
        assert_eq!(framing.discarded_prefix, b"\x1b[20");
        assert_eq!(framing.terminator, None);
        assert_eq!(framer.held_len(), 0);
    }

    /// KR-REQ-08.64: framing is tracked until an already-open paste is safely terminated.
    #[test]
    fn a_paste_end_is_still_recognised_after_the_mode_is_disabled_mid_paste() {
        let mut framer = PasteFramer::new();
        framer.set_bracketed_paste(true);
        framer.push(b"\x1b[200~text", Instant::now());
        framer.set_bracketed_paste(false);
        let outcome = framer.push(b"\x1b[201~", Instant::now());
        assert!(outcome.paste_ended);
        assert!(!framer.paste_open());
    }

    /// KR-REQ-08.62: a takeover advances the epoch and drops what the old lease had not delivered.
    /// KR-REQ-08.64: a prefix that begins after a completed delimiter starts its own deadline.
    #[test]
    fn a_new_prefix_after_a_completed_delimiter_gets_its_own_deadline() {
        let mut framer = PasteFramer::new();
        framer.set_bracketed_paste(true);
        let start = Instant::now();
        // A lone Escape is held. Twenty milliseconds later the rest of the start delimiter arrives,
        // completes it, and is followed by the first byte of another delimiter.
        framer.push(b"\x1b", start);
        let outcome = framer.push(b"[200~text\x1b", start + Duration::from_millis(20));
        assert!(outcome.paste_started);
        assert_eq!(outcome.held, 1);
        assert_eq!(
            outcome.deadline,
            Some(start + Duration::from_millis(20) + RECOGNISER_DEADLINE),
            "the new prefix has its own deadline: the first one's would expire it in five \
             milliseconds and the rest of a delimiter arriving after that would never be recognised"
        );
        // And the rest of that delimiter, ten milliseconds later, still completes it.
        let ending = framer.push(b"[201~", start + Duration::from_millis(30));
        assert!(ending.paste_ended, "{ending:?}");
        assert_eq!(ending.forward, b"\x1b[201~".to_vec());
    }

    /// KR-REQ-08.64: framing stops when the mode goes off and there is no paste to terminate.
    #[test]
    fn turning_the_mode_off_releases_a_prefix_that_now_guards_nothing() {
        let mut framer = PasteFramer::new();
        framer.set_bracketed_paste(true);
        let outcome = framer.push(b"\x1b[20", Instant::now());
        assert_eq!(outcome.held, 4);
        // The application turns canonical bracketed paste off. Nothing is open, so those bytes were
        // being held for framing that no longer exists.
        let released = framer.set_bracketed_paste(false);
        assert_eq!(released, b"\x1b[20".to_vec());
        assert_eq!(framer.held_len(), 0);
        assert!(framer.deadline().is_none());
        // A prefix held inside an open paste is a different case: that paste still has to be
        // closed, so tracking continues.
        let mut framer = PasteFramer::new();
        framer.set_bracketed_paste(true);
        framer.push(b"\x1b[200~text\x1b[20", Instant::now());
        assert!(framer.paste_open());
        assert!(
            framer.set_bracketed_paste(false).is_empty(),
            "nothing is released while a paste is still open"
        );
        assert_eq!(framer.held_len(), 4);
    }

    #[test]
    fn a_takeover_advances_the_epoch_and_drops_undelivered_input() {
        let mut lease = InputLease::new();
        lease.acquire(attachment(1), connection(1));
        assert_eq!(lease.epoch(), 1);
        lease
            .accept_write(attachment(1), 1, 0)
            .expect("first write");
        lease.enqueue(b"hello".to_vec());
        let discarded = lease.acquire(attachment(2), connection(2));
        assert_eq!(discarded, 5);
        assert_eq!(lease.epoch(), 2);
        assert_eq!(lease.holder(), Some(attachment(2)));
        assert_eq!(lease.queued_bytes(), 0);
    }

    /// KR-REQ-08.63: a stale epoch is refused and never acquires the lease.
    #[test]
    fn a_stale_epoch_is_refused_and_does_not_acquire_implicitly() {
        let mut lease = InputLease::new();
        lease.acquire(attachment(1), connection(1));
        lease.acquire(attachment(2), connection(2));
        assert_eq!(
            lease.accept_write(attachment(1), 1, 0),
            Err(LeaseRefusal::LeaseLost)
        );
        assert_eq!(lease.holder(), Some(attachment(2)));
    }

    /// KR-REQ-23.36: input sequences are acknowledged per connection and never replayed.
    #[test]
    fn input_sequences_must_follow_on_one_connection() {
        let mut lease = InputLease::new();
        lease.acquire(attachment(1), connection(1));
        lease.accept_write(attachment(1), 1, 0).expect("first");
        assert_eq!(
            lease.accept_write(attachment(1), 1, 0),
            Err(LeaseRefusal::OutOfOrder {
                expected: 1,
                received: 0
            })
        );
        lease.accept_write(attachment(1), 1, 1).expect("second");
    }

    /// KR-REQ-23.36: a reconnecting holder gets a new stream identity rather than a replay.
    #[test]
    fn a_reconnecting_holder_starts_a_new_stream_rather_than_replaying() {
        let mut lease = InputLease::new();
        lease.acquire(attachment(1), connection(1));
        lease.accept_write(attachment(1), 1, 0).expect("first");
        // The same attachment on a new connection acquires again and starts from zero.
        lease.acquire(attachment(1), connection(2));
        lease
            .accept_write(attachment(1), 2, 0)
            .expect("fresh stream");
    }
}
