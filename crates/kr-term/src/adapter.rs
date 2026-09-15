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
use wezterm_escape_parser::csi::{CSI, DecPrivateMode, Mode, TerminalMode};
use wezterm_escape_parser::esc::Esc;
use wezterm_escape_parser::osc::OperatingSystemCommand;
use wezterm_escape_parser::{Action, ControlCode};

use crate::classify::{CsiView, MAX_CSI_PARAM};
use crate::event::{CsiParam, Event, EventKind};

/// The result of adapting one event.
#[derive(Debug, Clone, Default)]
pub struct Adapted {
    /// The actions to apply, in order.
    pub actions: Vec<Action>,
    /// Whether the grid library failed to recognise a sequence the engine classified as `D` or `M`.
    pub unrecognised: bool,
    /// Whether a parameter was reduced to the largest value the grid could act on.
    ///
    /// A clamped sequence does what it can rather than what it said, so its original bytes are not
    /// forwarded: a physical terminal would take the unclamped value and end up somewhere else.
    pub clamped: bool,
}

/// What the canonical grid can act on, which bounds the parameters it is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptContext {
    /// Canonical rows.
    pub rows: u32,
    /// Canonical columns.
    pub cols: u32,
}

impl AdaptContext {
    /// The largest parameter `final_byte` can meaningfully carry.
    ///
    /// A cursor movement, an insertion or a scroll cannot do more than fill the screen, so a larger
    /// value asks for work with no effect. A repeat can wrap and scroll, so it is bounded by the
    /// whole grid instead of one dimension. Everything else keeps the general bound.
    ///
    /// Only counts and coordinates are bounded here. A parameter that selects which operation to
    /// perform, as the erase and tab-clear sequences use, means something different at every value:
    /// reducing it would quietly perform a different operation rather than a smaller one. Those
    /// values are checked against their own allowed set in the class table instead.
    #[must_use]
    pub fn limit_for(self, final_byte: u8) -> i64 {
        let dimension = i64::from(self.rows.max(self.cols)).max(1);
        match final_byte {
            b'@' | b'A' | b'B' | b'C' | b'D' | b'E' | b'F' | b'G' | b'I' | b'L' | b'M' | b'P'
            | b'S' | b'T' | b'X' | b'Z' | b'`' | b'a' | b'd' | b'e' => dimension,
            b'b' => i64::from(self.rows).max(1) * i64::from(self.cols).max(1),
            _ => MAX_CSI_PARAM,
        }
    }
}

/// The replacement character malformed input becomes.
const REPLACEMENT: &str = "\u{fffd}";

/// Maps a `D` or `M` event to the actions the canonical grid applies.
///
/// Returns nothing for any other class, so a caller that passes a `Q`, `S` or `X` event by mistake
/// changes no state. That is the second half of "the reducer cannot apply a sequence that policy
/// rejected": the policy layer does not offer it, and the adapter would refuse it anyway.
#[must_use]
pub fn adapt(event: &Event, context: AdaptContext) -> Adapted {
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
                    clamped: false,
                };
            };
            Adapted {
                actions: vec![Action::PrintString(text.to_owned())],
                ..Adapted::default()
            }
        }
        EventKind::Replacement { count, .. } => Adapted {
            actions: vec![Action::PrintString(REPLACEMENT.repeat(*count))],
            ..Adapted::default()
        },
        EventKind::Control { byte } => Adapted {
            actions: control_code(*byte)
                .map(|code| vec![Action::Control(code)])
                .unwrap_or_default(),
            ..Adapted::default()
        },
        EventKind::Esc {
            intermediate,
            final_byte,
            ..
        } => {
            let esc = Esc::parse(*intermediate, *final_byte);
            let unrecognised = matches!(esc, Esc::Unspecified { .. });
            Adapted {
                actions: vec![Action::Esc(esc)],
                unrecognised,
                clamped: false,
            }
        }
        EventKind::Csi {
            params,
            truncated,
            final_byte,
        } => {
            let limit = context.limit_for(*final_byte);
            let mut clamped = false;
            let mut vt: Vec<VtCsiParam> = params
                .iter()
                .copied()
                .map(|param| to_vt(param, limit, &mut clamped))
                .collect();
            normalise(&mut vt, *final_byte);
            let parsed: Vec<Action> = CSI::parse(&vt, *truncated, char::from(*final_byte))
                .map(Action::CSI)
                .collect();
            let empty = parsed.is_empty();
            // A mode the profile owns is dropped rather than handed on. The engine tracks it, and
            // the grid has nothing to do with it.
            let actions: Vec<Action> = parsed
                .into_iter()
                .filter(|action| !is_profile_owned_mode(action))
                .collect();
            let unrecognised = empty || actions.iter().any(action_is_unrecognised);
            Adapted {
                actions,
                unrecognised,
                clamped,
            }
        }
        EventKind::Osc { selector, parts } => {
            // The payload is rendered, so it is sanitised before the grid sees it: invalid UTF-8
            // becomes U+FFFD and a control scalar is dropped. The original bytes are still never
            // forwarded, because a terminal would frame them differently than this engine did.
            let parts = regroup(*selector, parts);
            let mut sanitised: Vec<Vec<u8>> = parts.iter().map(|part| sanitise(part)).collect();
            bound_title(*selector, &mut sanitised);
            let borrowed: Vec<&[u8]> = sanitised.iter().map(Vec::as_slice).collect();
            let osc = OperatingSystemCommand::parse(&borrowed);
            let unrecognised = matches!(osc, OperatingSystemCommand::Unspecified(_));
            Adapted {
                actions: vec![Action::OperatingSystemCommand(Box::new(osc))],
                unrecognised,
                clamped: false,
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

/// DEC private modes the profile owns rather than the canonical grid.
///
/// Each of these changes what a keyboard or mouse encoder produces and nothing about the screen:
/// 66 is the numeric keypad mode, 67 decides what the backarrow key sends, 1007 decides whether
/// wheel events become arrow keys on the alternate screen, and 1034 decides whether a meta key
/// sends an escape prefix. The profile advertises them, tracks them and hands them to the input
/// encoders, which is what section 8 asks for, so the grid library is not expected to know them.
pub const PROFILE_OWNED_DEC_MODES: &[u16] = &[66, 67, 1007, 1034];

/// Whether the profile owns this sequence outright, so the grid library is not expected to know it.
///
/// The virtual title stack is the session's own, OSC 633 is a shell-integration convention the grid
/// library does not model, and the palette belongs to the session. Handing any of them to the
/// library would give it a second owner, or produce an unrecognised action that looks like a
/// disagreement where there is none.
fn profile_owned(kind: &EventKind) -> bool {
    match kind {
        EventKind::Csi {
            params,
            final_byte: b't',
            ..
        } => matches!(CsiView::new(params, b't').first_or(0), 22 | 23),
        // Keyboard negotiation is an input semantic with one owner: the engine tracks it and the
        // input encoders read it. Handing it to the grid as well would give it a second owner that
        // disagrees about resets, pops and defaults.
        EventKind::Csi {
            params,
            final_byte: b'm',
            ..
        } => CsiView::new(params, b'm').private == Some(b'>'),
        EventKind::Csi {
            params,
            final_byte: b'u',
            ..
        } => matches!(CsiView::new(params, b'u').private, Some(b'>' | b'<' | b'=')),
        EventKind::Osc {
            selector: Some(633),
            ..
        } => true,
        // The palette is the session's. The engine applies every colour operation in the order the
        // request wrote them and answers every question from the same palette, so handing the
        // request to the grid as well would give the colours a second owner and would let the grid
        // library generate a reply of its own.
        EventKind::Osc {
            selector: Some(4 | 5 | 104 | 105),
            ..
        } => true,
        EventKind::Osc {
            selector: Some(selector),
            ..
        } => matches!(selector, 10..=19 | 110..=119),
        _ => false,
    }
}

/// Fills in the defaults the grid library does not supply for itself.
///
/// A trailing empty parameter slot means "use the default", and the library reads `CSI 2 ; r` as a
/// sequence it does not know rather than as a top margin with a default bottom. SGR is the
/// exception: there a trailing empty slot is a reset, not an omission.
fn normalise(params: &mut Vec<VtCsiParam>, final_byte: u8) {
    if final_byte != b'm' {
        while matches!(params.last(), Some(VtCsiParam::P(b';'))) {
            params.pop();
        }
    }
    // DECSCUSR with no parameter selects the default cursor style.
    if final_byte == b'q' && params.as_slice() == [VtCsiParam::P(b' ')] {
        params.insert(0, VtCsiParam::Integer(0));
    }
}

/// Puts back the separators that belong to one field rather than between fields.
///
/// A hyperlink target is a URI, and a URI may contain a semicolon: `OSC 8 ; ; https://host/a;b` is
/// three fields, not four. Splitting on every separator would leave the target truncated at the
/// first semicolon, and the link would be dropped as malformed. The parameter field before it is
/// colon-separated, so it is not affected.
fn regroup(selector: Option<u32>, parts: &[Vec<u8>]) -> Vec<Vec<u8>> {
    if selector != Some(8) || parts.len() <= 3 {
        return parts.to_vec();
    }
    let mut out: Vec<Vec<u8>> = parts[..2].to_vec();
    out.push(parts[2..].join(&b';'));
    out
}

/// Cuts a title payload to the length a session holds, before the grid sees it.
///
/// The grid keeps its own copy of the window title and the icon title, and it keeps whatever it is
/// given: without this it would hold as much as a control string may carry, which is far more than
/// a title may be, and the session and the grid would disagree about what the window is called. A
/// title may contain the separator, so everything after the selector is the title and it becomes
/// one part, which is the same string the session keeps.
fn bound_title(selector: Option<u32>, parts: &mut Vec<Vec<u8>>) {
    if !matches!(selector, Some(0..=2)) || parts.len() < 2 {
        return;
    }
    let title: String = parts[1..]
        .iter()
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect::<Vec<_>>()
        .join(";");
    parts.truncate(1);
    parts.push(crate::title::truncated(&title).into_bytes());
}

/// Makes a control-string payload safe to render.
///
/// Invalid UTF-8 becomes U+FFFD, which is what the byte policy says malformed text renders as, and
/// a control scalar is dropped rather than painted. A payload that needed sanitising is one whose
/// original bytes are never forwarded, so the two halves cannot diverge.
fn sanitise(part: &[u8]) -> Vec<u8> {
    if crate::event::bytes_are_direct_safe(part) {
        return part.to_vec();
    }
    String::from_utf8_lossy(part)
        .chars()
        .filter(|scalar| !scalar.is_control() && !('\u{80}'..='\u{9f}').contains(scalar))
        .collect::<String>()
        .into_bytes()
}

/// Whether an action is a set or reset of a mode the profile owns.
fn is_profile_owned_mode(action: &Action) -> bool {
    let Action::CSI(CSI::Mode(mode)) = action else {
        return false;
    };
    let (Mode::SetDecPrivateMode(value) | Mode::ResetDecPrivateMode(value)) = mode else {
        return false;
    };
    match value {
        DecPrivateMode::Unspecified(code) => PROFILE_OWNED_DEC_MODES.contains(code),
        DecPrivateMode::Code(_) => false,
    }
}

/// Whether the grid library failed to understand an action, at any nesting.
///
/// Checking only the outer action would miss a recognised container holding an unspecified value,
/// which is exactly how an unsupported mode reaches the reducer looking like a supported one.
fn action_is_unrecognised(action: &Action) -> bool {
    match action {
        Action::CSI(CSI::Unspecified(_)) => true,
        Action::CSI(CSI::Mode(mode)) => match mode {
            Mode::SetDecPrivateMode(value)
            | Mode::ResetDecPrivateMode(value)
            | Mode::SaveDecPrivateMode(value)
            | Mode::RestoreDecPrivateMode(value)
            | Mode::QueryDecPrivateMode(value) => {
                matches!(value, DecPrivateMode::Unspecified(_))
            }
            Mode::SetMode(value) | Mode::ResetMode(value) | Mode::QueryMode(value) => {
                matches!(value, TerminalMode::Unspecified(_))
            }
            Mode::XtermKeyMode { .. } => false,
        },
        Action::Esc(Esc::Unspecified { .. }) => true,
        Action::OperatingSystemCommand(osc) => {
            matches!(**osc, OperatingSystemCommand::Unspecified(_))
        }
        _ => false,
    }
}

/// Clamps a parameter to the largest value the canonical grid can act on.
///
/// The reducer loops once per unit for repeats, tabs and insertions, so an unclamped parameter
/// turns five bytes of input into hours of work.
fn to_vt(param: CsiParam, limit: i64, clamped: &mut bool) -> VtCsiParam {
    match param {
        CsiParam::Integer(value) => {
            let bounded = value.clamp(0, limit);
            if bounded != value {
                *clamped = true;
            }
            VtCsiParam::Integer(bounded)
        }
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
