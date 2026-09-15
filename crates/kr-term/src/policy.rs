//! The policy layer.
//!
//! Between the lexer and everything else sits one decision per event. The canonical grid reducer
//! only ever sees an event this layer approved, which is the concrete form of "the reducer cannot
//! apply a sequence that policy rejected": approval is a separate step with its own result, not an
//! assumption baked into the class.
//!
//! The layer also decodes the side effects, because that is where the bounds belong. A clipboard
//! write is checked against its own limit and rejected whole; it is never truncated into a shorter
//! secret and handed on.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::class::SequenceClass;
use crate::classify::CsiView;
use crate::diag::DiagnosticKind;
use crate::event::{DirectDisposition, DiscardCause, Event, EventKind, SequenceFamily};
use crate::sideeffect::{
    ClipboardReadPolicy, ClipboardSelection, ClipboardWritePolicy, Progress, SideEffectKind,
    SideEffectPolicy, SideEffectRefusal,
};

/// Which backend owns the PTY on the other side of the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// A Unix pseudo-terminal.
    UnixPty,
    /// A Windows ConPTY.
    ConPty,
}

/// The policy in force for one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// What side effects may do.
    pub side_effects: SideEffectPolicy,
    /// Which backend owns the PTY.
    pub backend: Backend,
}

impl Policy {
    /// The kr-vt/1 defaults on a Unix pseudo-terminal.
    pub const DEFAULT: Self = Self {
        side_effects: SideEffectPolicy::DEFAULT,
        backend: Backend::UnixPty,
    };
}

impl Default for Policy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What the policy layer decided about one event.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// Whether the engine updates its own session state from the event.
    ///
    /// Usually this moves together with [`Self::apply_to_grid`]. It does not for the ConPTY win32
    /// input mode, which the worker records for the backend that owns it while the sequence itself
    /// goes no further.
    pub track: bool,
    /// Whether the canonical grid reducer may apply the event.
    pub apply_to_grid: bool,
    /// Whether the query broker should answer it.
    pub answer: bool,
    /// The side effect to route, when policy accepted one.
    pub side_effect: Option<SideEffectKind>,
    /// Why a side effect was refused, when one was.
    pub refusal: Option<SideEffectRefusal>,
    /// A reply the engine owes without consulting any client, such as an empty clipboard read.
    pub immediate_reply: Option<Vec<u8>>,
    /// The diagnostic to record, when one is owed.
    pub diagnostic: Option<(DiagnosticKind, String)>,
    /// What direct mode may do with the original bytes.
    pub disposition: DirectDisposition,
}

impl Outcome {
    fn withheld(disposition: DirectDisposition) -> Self {
        Self {
            track: false,
            apply_to_grid: false,
            answer: false,
            side_effect: None,
            refusal: None,
            immediate_reply: None,
            diagnostic: None,
            disposition,
        }
    }
}

impl Policy {
    /// Decides what happens to one event.
    #[must_use]
    pub fn decide(&self, event: &Event) -> Outcome {
        match event.class {
            SequenceClass::Display | SequenceClass::Mode => self.decide_grid(event),
            // A query is answered here and travels no further. It is still tracked, because a
            // colour request may pair mutations with its questions and the mutations are real.
            SequenceClass::Query => Outcome {
                track: true,
                answer: true,
                diagnostic: Some((DiagnosticKind::QueryAnswered, describe(event))),
                ..Outcome::withheld(DirectDisposition::Withhold)
            },
            SequenceClass::SideEffect => self.decide_side_effect(event),
            SequenceClass::Extension => Outcome {
                diagnostic: Some(extension_diagnostic(event)),
                ..Outcome::withheld(DirectDisposition::Withhold)
            },
        }
    }

    fn decide_grid(&self, event: &Event) -> Outcome {
        let mut diagnostic = None;
        // The ConPTY win32 input mode is real on the backend that owns it and meaningless anywhere
        // else. Either way the classifier has already marked its bytes as stopping here, so the
        // rest of a combined request keeps working while this one mode goes no further.
        if self.backend == Backend::UnixPty && requests_win32_input(event) {
            diagnostic = Some((
                DiagnosticKind::UnclassifiedSequence,
                "win32 input mode has no meaning on a Unix backend".to_owned(),
            ));
        }
        if event.eight_bit_introducer {
            diagnostic = Some((DiagnosticKind::RawC1Control, describe(event)));
        } else if matches!(event.kind, EventKind::Replacement { .. }) {
            diagnostic = Some((DiagnosticKind::MalformedUtf8, describe(event)));
        }
        Outcome {
            track: true,
            apply_to_grid: true,
            answer: false,
            side_effect: None,
            refusal: None,
            immediate_reply: None,
            diagnostic,
            disposition: event.disposition,
        }
    }

    fn decide_side_effect(&self, event: &Event) -> Outcome {
        match &event.kind {
            EventKind::Control { byte: 0x07 } => {
                if self.side_effects.bell {
                    Outcome {
                        side_effect: Some(SideEffectKind::Bell),
                        ..Outcome::withheld(DirectDisposition::Withhold)
                    }
                } else {
                    Outcome {
                        refusal: Some(SideEffectRefusal::PolicyDenied),
                        ..Outcome::withheld(DirectDisposition::Withhold)
                    }
                }
            }
            EventKind::Osc { selector, parts } => self.decide_osc_side_effect(*selector, parts),
            _ => Outcome::withheld(DirectDisposition::Withhold),
        }
    }

    fn decide_osc_side_effect(&self, selector: Option<u32>, parts: &[Vec<u8>]) -> Outcome {
        match selector {
            Some(52) => self.decide_clipboard(parts),
            Some(9) => self.decide_osc9(parts),
            Some(99) => self.decide_notification(kitty_notification(parts)),
            Some(777) => self.decide_notification(rxvt_notification(parts)),
            _ => Outcome::withheld(DirectDisposition::Withhold),
        }
    }

    fn decide_clipboard(&self, parts: &[Vec<u8>]) -> Outcome {
        let selection = parts
            .get(1)
            .map_or(Some(ClipboardSelection::Clipboard), |spec| {
                ClipboardSelection::parse(spec)
            });
        let Some(selection) = selection else {
            return Outcome {
                refusal: Some(SideEffectRefusal::Malformed),
                ..Outcome::withheld(DirectDisposition::Withhold)
            };
        };
        let payload = parts.get(2).map_or(&[][..], Vec::as_slice);
        if payload == b"?" {
            return match self.side_effects.clipboard_read {
                ClipboardReadPolicy::EmptyResponse => Outcome {
                    // The answer is empty and comes from here, so no client is consulted and no
                    // clipboard content leaves any device.
                    immediate_reply: Some(
                        format!("\x1b]52;{};\x1b\\", char::from(selection.code())).into_bytes(),
                    ),
                    ..Outcome::withheld(DirectDisposition::Withhold)
                },
                ClipboardReadPolicy::LeaseHolder => Outcome {
                    side_effect: Some(SideEffectKind::ClipboardRead { selection }),
                    ..Outcome::withheld(DirectDisposition::Withhold)
                },
            };
        }
        if self.side_effects.clipboard_write == ClipboardWritePolicy::Deny {
            return Outcome {
                refusal: Some(SideEffectRefusal::PolicyDenied),
                diagnostic: Some((
                    DiagnosticKind::ClipboardWriteRejected,
                    "host policy denies clipboard writes".to_owned(),
                )),
                ..Outcome::withheld(DirectDisposition::Withhold)
            };
        }
        if payload.len() > self.side_effects.max_clipboard_encoded {
            return Outcome {
                refusal: Some(SideEffectRefusal::TooLarge {
                    encoded_len: payload.len(),
                    limit: self.side_effects.max_clipboard_encoded,
                }),
                diagnostic: Some((
                    DiagnosticKind::ClipboardWriteRejected,
                    format!(
                        "{} encoded bytes exceeds the {}-byte limit; rejected whole",
                        payload.len(),
                        self.side_effects.max_clipboard_encoded
                    ),
                )),
                ..Outcome::withheld(DirectDisposition::Withhold)
            };
        }
        let Ok(content) = STANDARD.decode(payload) else {
            return Outcome {
                refusal: Some(SideEffectRefusal::Malformed),
                diagnostic: Some((
                    DiagnosticKind::ClipboardWriteRejected,
                    "payload is not base64".to_owned(),
                )),
                ..Outcome::withheld(DirectDisposition::Withhold)
            };
        };
        Outcome {
            side_effect: Some(SideEffectKind::ClipboardWrite { selection, content }),
            ..Outcome::withheld(DirectDisposition::Withhold)
        }
    }

    fn decide_osc9(&self, parts: &[Vec<u8>]) -> Outcome {
        // OSC 9 carries two unrelated conventions: a progress report when the first part is `4`,
        // and a notification body otherwise.
        if parts.get(1).map(Vec::as_slice) == Some(b"4") {
            if !self.side_effects.progress {
                return Outcome {
                    refusal: Some(SideEffectRefusal::PolicyDenied),
                    ..Outcome::withheld(DirectDisposition::Withhold)
                };
            }
            let state = parts.get(2).and_then(|p| parse_u8(p)).unwrap_or(0);
            let value = parts.get(3).and_then(|p| parse_u8(p)).unwrap_or(0);
            let progress = match state {
                1 => Progress::Percent(value.min(100)),
                2 => Progress::Error(value.min(100)),
                3 => Progress::Indeterminate,
                4 => Progress::Paused(value.min(100)),
                _ => Progress::None,
            };
            return Outcome {
                side_effect: Some(SideEffectKind::Progress { progress }),
                ..Outcome::withheld(DirectDisposition::Withhold)
            };
        }
        let body = parts[1..]
            .iter()
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect::<Vec<_>>()
            .join(";");
        self.decide_notification(Some((None, body)))
    }

    fn decide_notification(&self, parsed: Option<(Option<String>, String)>) -> Outcome {
        let Some((title, body)) = parsed else {
            return Outcome {
                refusal: Some(SideEffectRefusal::Malformed),
                ..Outcome::withheld(DirectDisposition::Withhold)
            };
        };
        if !self.side_effects.notifications {
            return Outcome {
                refusal: Some(SideEffectRefusal::PolicyDenied),
                ..Outcome::withheld(DirectDisposition::Withhold)
            };
        }
        Outcome {
            side_effect: Some(SideEffectKind::Notification { title, body }),
            ..Outcome::withheld(DirectDisposition::Withhold)
        }
    }
}

/// Whether an event asks for the ConPTY win32 input mode.
fn requests_win32_input(event: &Event) -> bool {
    let EventKind::Csi {
        params, final_byte, ..
    } = &event.kind
    else {
        return false;
    };
    let csi = CsiView::new(params, *final_byte);
    csi.private == Some(b'?')
        && matches!(csi.final_byte, b'h' | b'l')
        && csi
            .numbers
            .contains(&Some(i64::from(crate::classify::MODE_WIN32_INPUT)))
}

fn parse_u8(part: &[u8]) -> Option<u8> {
    core::str::from_utf8(part).ok()?.parse::<u8>().ok()
}

/// `OSC 99 ; <metadata> ; <payload>`: the body is the payload, the metadata is not a title.
fn kitty_notification(parts: &[Vec<u8>]) -> Option<(Option<String>, String)> {
    let body = parts.get(2)?;
    Some((None, String::from_utf8_lossy(body).into_owned()))
}

/// `OSC 777 ; notify ; <title> ; <body>`.
fn rxvt_notification(parts: &[Vec<u8>]) -> Option<(Option<String>, String)> {
    if parts.get(1).map(Vec::as_slice) != Some(b"notify") {
        return None;
    }
    let title = parts
        .get(2)
        .map(|p| String::from_utf8_lossy(p).into_owned());
    let body = parts
        .get(3)
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_default();
    Some((title, body))
}

fn extension_diagnostic(event: &Event) -> (DiagnosticKind, String) {
    let kind = match &event.kind {
        EventKind::Discarded { cause, family, .. } => match cause {
            DiscardCause::Oversized | DiscardCause::TooManyParts => {
                DiagnosticKind::OversizedControlString
            }
            DiscardCause::PassthroughTooDeep => DiagnosticKind::PassthroughTooDeep,
            DiscardCause::Cancelled | DiscardCause::IncompleteAtClosure => {
                let _ = family;
                DiagnosticKind::AbandonedControlString
            }
        },
        EventKind::Dcs { final_byte, .. } if *final_byte == b'q' => {
            DiagnosticKind::ImageSequenceDisabled
        }
        EventKind::OtherString {
            family: SequenceFamily::Apc,
            ..
        } => DiagnosticKind::ImageSequenceDisabled,
        EventKind::Csi {
            params, final_byte, ..
        } => {
            let csi = CsiView::new(params, *final_byte);
            let physical = matches!(csi.final_byte, b't')
                || (csi.private == Some(b'?')
                    && matches!(csi.final_byte, b'h' | b'l')
                    && csi.numbers.contains(&Some(3)));
            if physical {
                DiagnosticKind::PhysicalWindowRequest
            } else {
                DiagnosticKind::UnclassifiedSequence
            }
        }
        _ => DiagnosticKind::UnclassifiedSequence,
    };
    (kind, describe(event))
}

/// A short, bounded description of an event for a diagnostic.
fn describe(event: &Event) -> String {
    let raw = event.raw();
    let shown = &raw[..raw.len().min(32)];
    format!("{:?}", crate::span::EscapedBytes(shown))
}
