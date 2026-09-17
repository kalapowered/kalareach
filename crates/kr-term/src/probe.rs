//! Physical-terminal probes for the attach client.
//!
//! A probe is a small, bounded, synchronous conversation with the terminal a person is sitting in
//! front of, and it happens once, before the application gets any input. Everything about it is
//! designed so that no answer can arrive later and be mistaken for something the person typed.
//!
//! * The set of questions is fixed and short. There is nothing here that asks the operating system
//!   and calls back.
//! * The last question is always primary device attributes, because every qualified terminal
//!   answers it and answers it last. That answer is the terminator: once it arrives, every earlier
//!   answer has either arrived or is never coming.
//! * The whole exchange has one second. A missing answer or a missing terminator fails the attach
//!   with [`crate::error::ProbeFailure`], restores the outer terminal's modes and reports
//!   `TERMINAL_PROBE_FAILED`. It never gives up quietly and starts forwarding on the same stream,
//!   because a late answer on that stream would go to the application as keystrokes.
//! * After a failure the same stream is not clean any more. Retrying needs a fresh input context,
//!   and choosing `--no-probe` afterwards does not make the old answers disappear.

use std::collections::BTreeMap;

use crate::error::{ProbeFailure, Result, TermError};
use crate::event::{Event, EventKind};
use crate::lexer::Lexer;
use crate::palette::{Palette, PaletteSource, Rgb};

/// A mode of the outer terminal that an attachment changes and therefore owes back.
///
/// Section 8 asks a detach to restore the outer terminal's input modes, mouse modes and cursor
/// visibility. None of those is described by termios and none of them can be inferred: a terminal
/// whose mouse reporting was already on before the attachment began is owed it back, and one whose
/// cursor was hidden is owed that. So they are *read* where a terminal answers for them, and where
/// one does not the documented default is used and the attachment says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SavedMode {
    /// DEC mode 25, cursor visibility.
    CursorVisible,
    /// DEC mode 1000, mouse click reporting.
    MouseClicks,
    /// DEC mode 1002, button-event mouse reporting.
    MouseDrag,
    /// DEC mode 1003, any-event mouse reporting.
    MouseMotion,
    /// DEC mode 1006, the SGR mouse encoding.
    SgrMouse,
    /// DEC mode 2004, bracketed paste.
    BracketedPaste,
}

impl SavedMode {
    /// Every mode an attachment reads and restores, in the order they are asked about.
    pub const ALL: &'static [Self] = &[
        Self::CursorVisible,
        Self::MouseClicks,
        Self::MouseDrag,
        Self::MouseMotion,
        Self::SgrMouse,
        Self::BracketedPaste,
    ];

    /// The DEC private mode number.
    #[must_use]
    pub const fn number(self) -> u16 {
        match self {
            Self::CursorVisible => 25,
            Self::MouseClicks => 1000,
            Self::MouseDrag => 1002,
            Self::MouseMotion => 1003,
            Self::SgrMouse => 1006,
            Self::BracketedPaste => 2004,
        }
    }

    /// The state a terminal is in when nothing has changed it.
    ///
    /// What a restoration falls back to for a terminal that does not answer for the mode: the
    /// cursor is shown and everything else is off, which is a terminal nobody has touched.
    #[must_use]
    pub const fn documented_default(self) -> bool {
        matches!(self, Self::CursorVisible)
    }

    /// What the mode is, in words, for a report a person reads.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::CursorVisible => "whether the cursor is shown",
            Self::MouseClicks => "mouse click reporting",
            Self::MouseDrag => "button-event mouse reporting",
            Self::MouseMotion => "any-event mouse reporting",
            Self::SgrMouse => "the SGR mouse encoding",
            Self::BracketedPaste => "bracketed paste",
        }
    }

    /// The mode this number names, for a reply that arrived.
    #[must_use]
    pub const fn from_number(number: u16) -> Option<Self> {
        match number {
            25 => Some(Self::CursorVisible),
            1000 => Some(Self::MouseClicks),
            1002 => Some(Self::MouseDrag),
            1003 => Some(Self::MouseMotion),
            1006 => Some(Self::SgrMouse),
            2004 => Some(Self::BracketedPaste),
            _ => None,
        }
    }
}

/// One question a probe may ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProbeItem {
    /// The terminal's own identity string.
    Version,
    /// The terminal's default foreground.
    Foreground,
    /// The terminal's default background.
    Background,
    /// Which Kitty keyboard flags the terminal supports.
    KittyKeyboard,
    /// Which `modifyOtherKeys` level the terminal has negotiated.
    ModifyOtherKeys,
    /// Whether the terminal reports synchronised output.
    SynchronisedOutput,
    /// What one of the modes this attachment will change is set to now.
    Mode(SavedMode),
    /// Primary device attributes, which is always asked last and always terminates the exchange.
    DeviceAttributes,
}

impl ProbeItem {
    /// The bytes that ask this question.
    #[must_use]
    pub const fn request(self) -> &'static [u8] {
        match self {
            Self::Version => b"\x1b[>0q",
            Self::Foreground => b"\x1b]10;?\x1b\\",
            Self::Background => b"\x1b]11;?\x1b\\",
            Self::KittyKeyboard => b"\x1b[?u",
            Self::ModifyOtherKeys => b"\x1b[?4m",
            Self::SynchronisedOutput => b"\x1b[?2026$p",
            Self::Mode(SavedMode::CursorVisible) => b"\x1b[?25$p",
            Self::Mode(SavedMode::MouseClicks) => b"\x1b[?1000$p",
            Self::Mode(SavedMode::MouseDrag) => b"\x1b[?1002$p",
            Self::Mode(SavedMode::MouseMotion) => b"\x1b[?1003$p",
            Self::Mode(SavedMode::SgrMouse) => b"\x1b[?1006$p",
            Self::Mode(SavedMode::BracketedPaste) => b"\x1b[?2004$p",
            Self::DeviceAttributes => b"\x1b[c",
        }
    }

    /// Whether an exchange that asked this question fails when the terminal does not answer it.
    ///
    /// Section 8 ends the handshake with the device-attributes terminator "after collecting every
    /// requested reply", and a missing reply fails that attach attempt. That is what this is: a
    /// question whose answer decides what the attachment *does* must be answered, and a question a
    /// terminal might not answer must not be asked.
    ///
    /// A report of a mode this attachment restores is the one kind of question that is neither. Its
    /// answer is a state the mode already has a documented default for, so a terminal that stays
    /// silent has not left the attachment without an answer - it has left it with the default, which
    /// is what every attachment used before any of these were asked. The terminator still proves
    /// that the silence is final rather than late. So a terminal is asked about the modes this
    /// attachment is going to change, is restored to whatever it reported, and is never refused an
    /// attach for saying nothing.
    ///
    /// Synchronised output is not one of them: it is a capability the session is told about rather
    /// than a state the attachment puts back, so a profile that promises it owes the answer.
    #[must_use]
    pub const fn answer_is_required(self) -> bool {
        !matches!(self, Self::Mode(_))
    }
}

/// The questions this build's own profile asks, in the order they are written.
///
/// Device attributes is last and is the terminator; nothing may be added after it. A caller passes
/// the subset its qualified profile needs — any subset of [`ProbeItem`], not only of this list —
/// and every question it asks must be answered: a terminal that stays silent on one of them is not
/// probe-qualified for that profile and belongs on the `--no-probe` path with a saved or
/// conservative profile. A reply to something the caller did not ask is still recorded, because a
/// terminal that volunteers one has told the truth about itself either way.
pub const PROBE_SET: &[ProbeItem] = &[
    ProbeItem::Version,
    ProbeItem::Foreground,
    ProbeItem::Background,
    ProbeItem::KittyKeyboard,
    ProbeItem::SynchronisedOutput,
    ProbeItem::DeviceAttributes,
];

/// The total time one probe exchange has.
pub const PROBE_DEADLINE_MS: u64 = 1_000;

/// The largest reply buffer a probe will hold.
pub const MAX_REPLY_BYTES: usize = 4 * 1024;

/// What the attach client knows about the outer terminal's input stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputContext {
    /// The stream is fresh: nothing has been written to the terminal that could still answer.
    Clean,
    /// A previous probe failed on this stream, so a late answer cannot be ruled out.
    Contaminated,
}

/// One answer a probe collected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeAnswer {
    /// The terminal's identity string.
    Version(String),
    /// A colour.
    Colour(Rgb),
    /// Kitty keyboard flags.
    KittyFlags(u8),
    /// The `modifyOtherKeys` level.
    ModifyOtherKeysLevel(u8),
    /// A mode report status.
    ModeStatus(u16),
    /// Primary device attributes parameters.
    DeviceAttributes(Vec<i64>),
}

/// How far a probe has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeProgress {
    /// Still collecting.
    Collecting,
    /// The terminator arrived and the exchange is complete.
    Complete,
}

/// A probe exchange in flight.
#[derive(Debug)]
pub struct ProbeSession {
    deadline_ms: u64,
    asked: Vec<ProbeItem>,
    answers: BTreeMap<ProbeItem, ProbeAnswer>,
    lexer: Lexer,
    buffered: usize,
    complete: bool,
    typed: Vec<u8>,
}

impl ProbeSession {
    /// Starts a probe, returning the exact bytes to write to the outer terminal.
    ///
    /// # Errors
    ///
    /// Refuses to start on a stream that a previous failed probe contaminated. Calling
    /// `--no-probe` on that stream does not clean it either; only a fresh input context does.
    pub fn start(
        now_ms: u64,
        context: InputContext,
        questions: &[ProbeItem],
    ) -> Result<(Self, Vec<u8>)> {
        if context == InputContext::Contaminated {
            return Err(TermError::ProbeFailed {
                reason: ProbeFailure::ContaminatedInput,
            });
        }
        let mut asked: Vec<ProbeItem> = questions
            .iter()
            .copied()
            .filter(|item| *item != ProbeItem::DeviceAttributes)
            .collect();
        asked.push(ProbeItem::DeviceAttributes);
        let mut request = Vec::new();
        for item in &asked {
            request.extend_from_slice(item.request());
        }
        let session = Self {
            deadline_ms: now_ms + PROBE_DEADLINE_MS,
            asked,
            answers: BTreeMap::new(),
            lexer: Lexer::new(),
            buffered: 0,
            complete: false,
            typed: Vec::new(),
        };
        Ok((session, request))
    }

    /// Feeds bytes read from the outer terminal.
    ///
    /// These bytes never reach the PTY. The attach client buffers anything the person types
    /// separately, and delivers it only once the exchange has finished.
    ///
    /// # Errors
    ///
    /// Fails the attach when the deadline passes, when an answer is malformed, or when more bytes
    /// arrive than a probe exchange could possibly need.
    pub fn observe(&mut self, bytes: &[u8], now_ms: u64) -> Result<ProbeProgress> {
        if now_ms > self.deadline_ms {
            return Err(TermError::ProbeFailed {
                reason: ProbeFailure::DeadlinePassed,
            });
        }
        if self.complete {
            // The exchange is over. Everything after the terminator is the person's, whole bytes
            // and half sequences alike, and it is kept as it arrived rather than run through a
            // lexer that would hold the incomplete tail of a key they are part way through
            // pressing.
            self.typed.extend_from_slice(bytes);
            return Ok(ProbeProgress::Complete);
        }
        self.buffered += bytes.len();
        if self.buffered > MAX_REPLY_BYTES {
            return Err(TermError::ProbeFailed {
                reason: ProbeFailure::UnexpectedAnswer,
            });
        }
        let mut events = Vec::new();
        self.lexer.feed(bytes, &mut events);
        for event in &events {
            let Some((item, answer)) = interpret(event) else {
                // Not an answer to anything this exchange asked, which makes it the person's. It is
                // kept, in the order it arrived, rather than discarded or passed off as a reply:
                // section 8 requires the replies never to enter the application's input and the
                // person's own typing never to be mistaken for one, so the two are separated here
                // instead of by scanning the stream afterwards for anything reply-shaped.
                self.typed.extend_from_slice(event.bytes.as_ref());
                continue;
            };
            // Nothing after the terminator is an answer. The terminator is what proves no earlier
            // answer is still in flight, so anything that arrives behind it is a reply to something
            // else or a terminal answering out of order, and neither is evidence about a
            // capability.
            if self.complete {
                self.typed.extend_from_slice(event.bytes.as_ref());
                continue;
            }
            self.answers.insert(item, answer);
            if item == ProbeItem::DeviceAttributes {
                self.complete = true;
            }
        }
        if self.complete {
            // The exchange ended in this read, so whatever the lexer is still holding arrived
            // after the terminator and belongs to the person: a key half pressed is still a key
            // pressed. Until the terminator arrives the lexer keeps what it is holding, because a
            // terminal is free to answer across two reads and taking the held bytes here would
            // throw away the first half of an answer still in flight.
            self.typed
                .extend_from_slice(self.lexer.take_pending().as_ref());
        }
        Ok(if self.complete {
            ProbeProgress::Complete
        } else {
            ProbeProgress::Collecting
        })
    }

    /// Finishes the exchange.
    ///
    /// # Errors
    ///
    /// Fails when the terminator never arrived, which is the only thing that proves no further
    /// answer is in flight, and when any question the probe asked went unanswered.
    pub fn finish(self, now_ms: u64) -> Result<ProbeOutcome> {
        if !self.complete {
            // The typing is still readable through [`ProbeSession::typed`] on the session the
            // caller still holds, because a failed exchange does not make somebody's keystrokes
            // nobody's.
            return Err(TermError::ProbeFailed {
                reason: if now_ms > self.deadline_ms {
                    ProbeFailure::DeadlinePassed
                } else {
                    ProbeFailure::NoTerminator
                },
            });
        }
        let missing: Vec<ProbeItem> = self
            .asked
            .iter()
            .copied()
            .filter(|item| item.answer_is_required() && !self.answers.contains_key(item))
            .collect();
        if !missing.is_empty() {
            return Err(TermError::ProbeFailed {
                reason: ProbeFailure::MissingAnswer,
            });
        }
        Ok(ProbeOutcome {
            answers: self.answers,
            typed: self.typed,
        })
    }

    /// What the person typed while the terminal was being asked, in the order they typed it.
    ///
    /// Available on a failed exchange too, because a failure does not make their keystrokes
    /// somebody else's.
    #[must_use]
    pub fn typed(&self) -> &[u8] {
        &self.typed
    }

    /// How many bytes of the person's typing this exchange is holding.
    ///
    /// For a caller that has to report what a failed exchange cost rather than deliver it: an
    /// attach that fails delivers nothing anywhere, and the person is owed the number if not the
    /// keys.
    #[must_use]
    pub fn typing_len(&self) -> usize {
        self.typed.len().saturating_add(self.lexer.held_len())
    }

    /// Takes the person's typing from an exchange that did not finish.
    ///
    /// A failed exchange does not make somebody's keystrokes nobody's, and the lexer may still be
    /// holding the half of a key they were pressing when the deadline passed.
    #[must_use]
    pub fn into_typing(mut self) -> Vec<u8> {
        let held = self.lexer.take_pending();
        let mut typed = self.typed;
        typed.extend_from_slice(&held);
        typed
    }

    /// Whether the terminator has arrived.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Checks the deadline without feeding any bytes.
    ///
    /// # Errors
    ///
    /// Fails once the one-second bound has passed with the exchange unfinished.
    pub const fn check_deadline(&self, now_ms: u64) -> Result<()> {
        if !self.complete && now_ms > self.deadline_ms {
            return Err(TermError::ProbeFailed {
                reason: ProbeFailure::DeadlinePassed,
            });
        }
        Ok(())
    }
}

/// What a completed probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    answers: BTreeMap<ProbeItem, ProbeAnswer>,
    typed: Vec<u8>,
}

impl ProbeOutcome {
    /// One answer.
    #[must_use]
    pub fn answer(&self, item: ProbeItem) -> Option<&ProbeAnswer> {
        self.answers.get(&item)
    }

    /// Every answer.
    #[must_use]
    pub fn answers(&self) -> &BTreeMap<ProbeItem, ProbeAnswer> {
        &self.answers
    }

    /// The questions this exchange asked, all of which were answered.
    #[must_use]
    pub fn asked(&self) -> Vec<ProbeItem> {
        self.answers.keys().copied().collect()
    }

    /// What the person typed while the terminal was being asked, in the order they typed it.
    ///
    /// These are the first bytes the attachment forwards. They never entered the terminal's input
    /// and they were never mistaken for a reply.
    #[must_use]
    pub fn typed(&self) -> &[u8] {
        &self.typed
    }

    /// Takes the person's typing, leaving the answers.
    #[must_use]
    pub fn into_typed(self) -> Vec<u8> {
        self.typed
    }

    /// The session palette this probe supports, when the terminal shared its colours.
    ///
    /// A probe is evidence about the client's own colours, and adopting them is an explicit choice
    /// made at creation. The source is recorded either way, so a later query describes the session
    /// and can say where the session got its palette.
    #[must_use]
    pub fn adopt_palette(&self) -> Option<Palette> {
        let (Some(ProbeAnswer::Colour(foreground)), Some(ProbeAnswer::Colour(background))) = (
            self.answers.get(&ProbeItem::Foreground),
            self.answers.get(&ProbeItem::Background),
        ) else {
            return None;
        };
        Some(Palette::from_client_preference(*foreground, *background))
    }
}

/// The profile a `--no-probe` attach uses.
///
/// The choice is made before any byte is written, which is the only time it can be made honestly.
/// Calling it after a probe has gone out does not unsend the questions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoProbeProfile {
    /// A qualified profile saved from an earlier, successful probe of this terminal.
    Saved {
        /// The qualified profile identifier.
        id: String,
        /// The palette preset chosen for the session.
        palette: PaletteSource,
    },
    /// The conservative projected profile, which asks the terminal nothing at all.
    ConservativeProjected {
        /// The palette preset chosen for the session.
        palette: PaletteSource,
    },
}

impl NoProbeProfile {
    /// The palette a `--no-probe` session starts with.
    #[must_use]
    pub fn palette(&self) -> Palette {
        match self {
            Self::Saved { palette, .. } | Self::ConservativeProjected { palette } => {
                Palette::new(*palette)
            }
        }
    }
}

fn interpret(event: &Event) -> Option<(ProbeItem, ProbeAnswer)> {
    match &event.kind {
        EventKind::Csi {
            params,
            final_byte,
            truncated,
        } => {
            // A reply the parser could not keep whole is not a shorter reply: the part it dropped
            // could have carried the rest of the number this would be recorded as.
            if *truncated {
                return None;
            }
            let csi = crate::classify::CsiView::with_truncation(params, *final_byte, *truncated);
            if !csi.intermediates.is_empty() && csi.intermediates != *b"$" {
                return None;
            }
            // A sublist belongs to ordinary SGR and to nothing this asks about, so a reply carrying
            // one is not a reply to this question.
            if csi.sub_parameters {
                return None;
            }
            match (csi.private, csi.final_byte) {
                (Some(b'?'), b'c') if csi.intermediates.is_empty() => {
                    // A device-attributes reply names at least one attribute. An empty one is not
                    // a terminal saying it has none: it is a reply this profile does not recognise,
                    // and accepting it as the terminator would end the exchange on nothing.
                    let attributes: Vec<i64> =
                        csi.numbers.iter().filter_map(|slot| *slot).collect();
                    if attributes.is_empty() {
                        return None;
                    }
                    Some((
                        ProbeItem::DeviceAttributes,
                        ProbeAnswer::DeviceAttributes(attributes),
                    ))
                }
                (Some(b'?'), b'u') if csi.intermediates.is_empty() => {
                    // The qualified flags are the five the profile advertises.
                    let flags = csi.number(0).unwrap_or(0);
                    if !(0..=0x1f).contains(&flags) || csi.numbers.len() > 1 {
                        return None;
                    }
                    Some((
                        ProbeItem::KittyKeyboard,
                        ProbeAnswer::KittyFlags(u8::try_from(flags).unwrap_or(0)),
                    ))
                }
                // xterm answers `CSI ? 4 m` with `CSI > 4 ; level m`.
                (Some(b'>'), b'm') if csi.intermediates.is_empty() => {
                    if csi.number(0) != Some(4) || csi.numbers.len() != 2 {
                        return None;
                    }
                    let level = csi.number(1)?;
                    // The protocol defines three levels. Anything else is not a level this profile
                    // can record, and guessing one would mean encoding keys the application does
                    // not read.
                    if !(0..=2).contains(&level) {
                        return None;
                    }
                    Some((
                        ProbeItem::ModifyOtherKeys,
                        ProbeAnswer::ModifyOtherKeysLevel(u8::try_from(level).unwrap_or(0)),
                    ))
                }
                // A DECRQM reply is DECRPM: `CSI ? mode ; status $ y`.
                (Some(b'?'), b'y') if csi.intermediates == *b"$" => {
                    let mode = u16::try_from(csi.number(0)?).ok()?;
                    let item = if mode == crate::classify::MODE_SYNCHRONISED_OUTPUT {
                        ProbeItem::SynchronisedOutput
                    } else {
                        ProbeItem::Mode(SavedMode::from_number(mode)?)
                    };
                    // DECRPM has five defined statuses. Anything else is not a status this
                    // profile can record as a capability.
                    let status = csi.number(1)?;
                    if !(0..=4).contains(&status) || csi.numbers.len() != 2 {
                        return None;
                    }
                    Some((
                        item,
                        ProbeAnswer::ModeStatus(u16::try_from(status).unwrap_or(0)),
                    ))
                }
                _ => None,
            }
        }
        EventKind::Osc { selector, parts } => {
            let item = match selector {
                Some(10) => ProbeItem::Foreground,
                Some(11) => ProbeItem::Background,
                _ => return None,
            };
            // A colour reply is the selector and one colour. Anything after that is not part of the
            // answer to this question, so the whole reply is not one.
            if parts.len() != 2 {
                return None;
            }
            let spec = parts.get(1)?;
            let colour = Rgb::parse(core::str::from_utf8(spec).ok()?)?;
            Some((item, ProbeAnswer::Colour(colour)))
        }
        EventKind::Dcs {
            params,
            intermediates,
            final_byte,
            payload,
            ..
        } => {
            // XTVERSION answers as `DCS > | <identity> ST`: one private marker, no intermediates and
            // nothing else. A reply with parameters of its own is a different sequence.
            let is_version = *final_byte == b'|'
                && intermediates.is_empty()
                && params.len() == 1
                && params
                    .first()
                    .and_then(|param| param.punct())
                    .is_some_and(|byte| byte == b'>');
            if !is_version || payload.is_empty() {
                return None;
            }
            Some((
                ProbeItem::Version,
                ProbeAnswer::Version(String::from_utf8_lossy(payload).into_owned()),
            ))
        }
        _ => None,
    }
}
