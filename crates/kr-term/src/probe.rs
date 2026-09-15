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
    /// Whether the terminal reports synchronised output.
    SynchronisedOutput,
    /// Primary device attributes, which is always asked last and always terminates the exchange.
    DeviceAttributes,
}

/// Whether an unanswered question fails the attach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeRequirement {
    /// The attach fails without this answer.
    Required,
    /// Silence is an answer: the terminal does not have the feature.
    ///
    /// This is safe only because the terminator comes last. Once primary device attributes arrive,
    /// every earlier answer has either arrived or is never coming, so an unanswered optional
    /// question is a fact about the terminal rather than a reply still in flight.
    Optional,
}

impl ProbeItem {
    /// Whether the attach fails without this answer.
    #[must_use]
    pub const fn requirement(self) -> ProbeRequirement {
        match self {
            Self::DeviceAttributes => ProbeRequirement::Required,
            _ => ProbeRequirement::Optional,
        }
    }

    /// The bytes that ask this question.
    #[must_use]
    pub const fn request(self) -> &'static [u8] {
        match self {
            Self::Version => b"\x1b[>0q",
            Self::Foreground => b"\x1b]10;?\x1b\\",
            Self::Background => b"\x1b]11;?\x1b\\",
            Self::KittyKeyboard => b"\x1b[?u",
            Self::SynchronisedOutput => b"\x1b[?2026$p",
            Self::DeviceAttributes => b"\x1b[c",
        }
    }
}

/// The complete probe set, in the order it is written.
///
/// Device attributes is last and is the terminator. Nothing may be added after it.
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
    answers: BTreeMap<ProbeItem, ProbeAnswer>,
    lexer: Lexer,
    buffered: usize,
    complete: bool,
}

impl ProbeSession {
    /// Starts a probe, returning the exact bytes to write to the outer terminal.
    ///
    /// # Errors
    ///
    /// Refuses to start on a stream that a previous failed probe contaminated. Calling
    /// `--no-probe` on that stream does not clean it either; only a fresh input context does.
    pub fn start(now_ms: u64, context: InputContext) -> Result<(Self, Vec<u8>)> {
        if context == InputContext::Contaminated {
            return Err(TermError::ProbeFailed {
                reason: ProbeFailure::ContaminatedInput,
            });
        }
        let mut request = Vec::new();
        for item in PROBE_SET {
            request.extend_from_slice(item.request());
        }
        let session = Self {
            deadline_ms: now_ms + PROBE_DEADLINE_MS,
            answers: BTreeMap::new(),
            lexer: Lexer::new(),
            buffered: 0,
            complete: false,
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
        self.buffered += bytes.len();
        if self.buffered > MAX_REPLY_BYTES {
            return Err(TermError::ProbeFailed {
                reason: ProbeFailure::UnexpectedAnswer,
            });
        }
        let mut events = Vec::new();
        self.lexer.feed(bytes, &mut events);
        for event in &events {
            if let Some((item, answer)) = interpret(event) {
                self.answers.insert(item, answer);
                if item == ProbeItem::DeviceAttributes {
                    self.complete = true;
                }
            }
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
    /// answer is in flight, and when a required answer is missing.
    pub fn finish(self, now_ms: u64) -> Result<ProbeOutcome> {
        if !self.complete {
            return Err(TermError::ProbeFailed {
                reason: if now_ms > self.deadline_ms {
                    ProbeFailure::DeadlinePassed
                } else {
                    ProbeFailure::NoTerminator
                },
            });
        }
        let missing: Vec<ProbeItem> = PROBE_SET
            .iter()
            .copied()
            .filter(|item| !self.answers.contains_key(item))
            .collect();
        if missing
            .iter()
            .any(|item| item.requirement() == ProbeRequirement::Required)
        {
            return Err(TermError::ProbeFailed {
                reason: ProbeFailure::NoTerminator,
            });
        }
        Ok(ProbeOutcome {
            answers: self.answers,
            unanswered: missing,
        })
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
    unanswered: Vec<ProbeItem>,
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

    /// The optional questions the terminal did not answer.
    ///
    /// Each one is a feature the saved profile must not claim. Silence here is evidence, because
    /// the terminator arrived after it.
    #[must_use]
    pub fn unanswered(&self) -> &[ProbeItem] {
        &self.unanswered
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
            params, final_byte, ..
        } => {
            let csi = crate::classify::CsiView::new(params, *final_byte);
            match (csi.private, csi.final_byte) {
                (Some(b'?'), b'c') => Some((
                    ProbeItem::DeviceAttributes,
                    ProbeAnswer::DeviceAttributes(
                        csi.numbers.iter().filter_map(|slot| *slot).collect(),
                    ),
                )),
                (Some(b'?'), b'u') => Some((
                    ProbeItem::KittyKeyboard,
                    ProbeAnswer::KittyFlags(
                        u8::try_from(csi.first_or(0).clamp(0, i64::from(u8::MAX))).unwrap_or(0),
                    ),
                )),
                // A DECRQM reply is DECRPM: `CSI ? mode ; status $ y`.
                (Some(b'?'), b'y') if csi.intermediates == *b"$" => {
                    if csi.number(0) != Some(i64::from(crate::classify::MODE_SYNCHRONISED_OUTPUT)) {
                        return None;
                    }
                    let status = csi.number(1).unwrap_or(0);
                    Some((
                        ProbeItem::SynchronisedOutput,
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
            let spec = parts.get(1)?;
            let colour = Rgb::parse(core::str::from_utf8(spec).ok()?)?;
            Some((item, ProbeAnswer::Colour(colour)))
        }
        EventKind::Dcs {
            params,
            final_byte,
            payload,
            ..
        } => {
            // XTVERSION answers as `DCS > | <identity> ST`.
            let is_version = *final_byte == b'|'
                && params
                    .first()
                    .and_then(|param| param.punct())
                    .is_some_and(|byte| byte == b'>');
            if !is_version {
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
