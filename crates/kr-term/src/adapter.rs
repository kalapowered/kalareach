//! The qualified adapter between the engine's parse and the canonical grid.
//!
//! Section 8 forbids trusting two independent parses to agree. This adapter removes the second
//! parse rather than reconciling it: the engine frames and classifies a sequence once, and the
//! grid library is handed the already-decoded action. The library never sees a byte of the output
//! stream, so it cannot frame anything differently, and it never sees a sequence the policy layer
//! withheld.
//!
//! What remains to qualify is the mapping itself, and it is qualified by measurement. The library
//! marks a sequence it does not understand as unspecified, so when the engine classifies something
//! as display or mode and the library shrugs, [`Adapted::unrecognised`] says so and the conformance
//! fixtures fail. The two halves therefore have to agree about every sequence in the corpus, and
//! they agree by construction about where every sequence begins and ends.

use vtparse::CsiParam as VtCsiParam;
use wezterm_escape_parser::csi::CSI;
use wezterm_escape_parser::esc::Esc;
use wezterm_escape_parser::osc::OperatingSystemCommand;
use wezterm_escape_parser::{Action, ControlCode};

use crate::classify::CsiView;
use crate::event::{CsiParam, Event, EventKind};

/// The result of adapting one event.
#[derive(Debug, Clone, Default)]
pub struct Adapted {
    /// The actions to apply, in order.
    pub actions: Vec<Action>,
    /// Whether the grid library failed to recognise a sequence the engine classified as `D` or `M`.
    pub unrecognised: bool,
}

/// The replacement character malformed input becomes.
const REPLACEMENT: &str = "\u{fffd}";

/// Maps a `D` or `M` event to the actions the canonical grid applies.
///
/// Returns nothing for any other class, so a caller that passes a `Q`, `S` or `X` event by mistake
/// changes no state. That is the second half of "the reducer cannot apply a sequence that policy
/// rejected": the policy layer does not offer it, and the adapter would refuse it anyway.
#[must_use]
pub fn adapt(event: &Event) -> Adapted {
    if !event.class.reaches_grid() || profile_owned(&event.kind) {
        return Adapted::default();
    }
    match &event.kind {
        EventKind::Text { .. } => {
            let Ok(text) = core::str::from_utf8(event.raw()) else {
                // The lexer only produces text events for validated scalars, so this cannot happen;
                // treating it as replacement keeps the grid consistent if it ever did.
                return Adapted {
                    actions: vec![Action::PrintString(REPLACEMENT.to_owned())],
                    unrecognised: true,
                };
            };
            Adapted {
                actions: vec![Action::PrintString(text.to_owned())],
                unrecognised: false,
            }
        }
        EventKind::Replacement { count, .. } => Adapted {
            actions: vec![Action::PrintString(REPLACEMENT.repeat(*count))],
            unrecognised: false,
        },
        EventKind::Control { byte } => Adapted {
            actions: control_code(*byte)
                .map(|code| vec![Action::Control(code)])
                .unwrap_or_default(),
            unrecognised: false,
        },
        EventKind::Esc {
            intermediate,
            final_byte,
        } => {
            let esc = Esc::parse(*intermediate, *final_byte);
            let unrecognised = matches!(esc, Esc::Unspecified { .. });
            Adapted {
                actions: vec![Action::Esc(esc)],
                unrecognised,
            }
        }
        EventKind::Csi {
            params,
            truncated,
            final_byte,
        } => {
            let vt: Vec<VtCsiParam> = params.iter().copied().map(to_vt).collect();
            let actions: Vec<Action> = CSI::parse(&vt, *truncated, char::from(*final_byte))
                .map(Action::CSI)
                .collect();
            let unrecognised = actions.is_empty()
                || actions
                    .iter()
                    .any(|action| matches!(action, Action::CSI(CSI::Unspecified(_))));
            Adapted {
                actions,
                unrecognised,
            }
        }
        EventKind::Osc { parts, .. } => {
            let borrowed: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            let osc = OperatingSystemCommand::parse(&borrowed);
            let unrecognised = matches!(osc, OperatingSystemCommand::Unspecified(_));
            Adapted {
                actions: vec![Action::OperatingSystemCommand(Box::new(osc))],
                unrecognised,
            }
        }
        // No device-control, application-program or discarded sequence is ever `D` or `M` in
        // kr-vt/1, so none of them reaches the grid.
        EventKind::Dcs { .. }
        | EventKind::OtherString { .. }
        | EventKind::Discarded { .. }
        | EventKind::CsiIgnored { .. } => Adapted::default(),
    }
}

/// Whether the profile owns this sequence outright, so the grid library is not expected to know it.
///
/// The virtual title stack is the session's own, and OSC 633 is a shell-integration convention the
/// grid library does not model. Handing either to the library would only produce an unrecognised
/// action, which would look like a disagreement where there is none.
fn profile_owned(kind: &EventKind) -> bool {
    match kind {
        EventKind::Csi {
            params,
            final_byte: b't',
            ..
        } => matches!(CsiView::new(params, b't').first_or(0), 22 | 23),
        EventKind::Osc {
            selector: Some(633),
            ..
        } => true,
        _ => false,
    }
}

fn to_vt(param: CsiParam) -> VtCsiParam {
    match param {
        CsiParam::Integer(value) => VtCsiParam::Integer(value),
        CsiParam::Punct(byte) => VtCsiParam::P(byte),
    }
}

/// The control codes kr-vt/1 forwards to the grid.
///
/// The list is explicit rather than a numeric conversion, because the class table names exactly
/// these. `DEL` is classified as display and has no grid effect, which is what the state machine
/// does with it, so it maps to no action at all.
const fn control_code(byte: u8) -> Option<ControlCode> {
    match byte {
        0x00 => Some(ControlCode::Null),
        0x08 => Some(ControlCode::Backspace),
        0x09 => Some(ControlCode::HorizontalTab),
        0x0a => Some(ControlCode::LineFeed),
        0x0b => Some(ControlCode::VerticalTab),
        0x0c => Some(ControlCode::FormFeed),
        0x0d => Some(ControlCode::CarriageReturn),
        0x0e => Some(ControlCode::ShiftOut),
        0x0f => Some(ControlCode::ShiftIn),
        _ => None,
    }
}
