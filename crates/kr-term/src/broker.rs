//! The query broker: the one thing in the system that answers a terminal query.
//!
//! Section 8 allows exactly one responder. The worker is it. No query is forwarded to an attached
//! terminal, no attached terminal is asked what it can do on the application's behalf, and no
//! answer describes anything except the virtual profile and the session's own canonical state.
//! That is what makes two attachments from two different terminals safe: the application gets the
//! same answers either way, and neither terminal ever sees the question.
//!
//! Every reply is built here and built in 7-bit form. kr-vt/1 never emits an 8-bit C1 introducer,
//! and no byte of a request is ever copied into a reply, so a reply is always valid UTF-8 and
//! always something this engine produced rather than something an application chose.

use crate::classify::CsiView;
use crate::event::{Event, EventKind};
use crate::lane::{Response, ResponseKind};
use crate::modes::{ModeKind, ModeState};
use crate::palette::{DynamicColour, Palette, Rgb};
use crate::profile::{DA1_PARAMS, DA2_PARAMS, DA3_UNIT_ID, XTVERSION_IDENTITY};
use crate::terminfo;

/// The canonical state a reply may describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalReport {
    /// Cursor row, one-based and absolute.
    pub cursor_row: u32,
    /// Cursor column, one-based and absolute.
    pub cursor_col: u32,
    /// Canonical rows.
    pub rows: u32,
    /// Canonical columns.
    pub cols: u32,
    /// Top margin, one-based.
    pub margin_top: u32,
    /// Bottom margin, one-based.
    pub margin_bottom: u32,
    /// Left margin, one-based.
    pub margin_left: u32,
    /// Right margin, one-based.
    pub margin_right: u32,
    /// Whether origin mode is on, which makes a cursor report relative to the margins.
    pub origin_mode: bool,
    /// The DECSCUSR style number.
    pub cursor_style: u32,
}

impl CanonicalReport {
    /// The cursor as a report should state it.
    ///
    /// With origin mode on, the application is working in a coordinate space that starts at the
    /// margins, so a report in absolute screen coordinates would send it to the wrong place.
    #[must_use]
    pub const fn reported_cursor(&self) -> (u32, u32) {
        if self.origin_mode {
            (
                self.cursor_row.saturating_sub(self.margin_top - 1),
                self.cursor_col.saturating_sub(self.margin_left - 1),
            )
        } else {
            (self.cursor_row, self.cursor_col)
        }
    }
}

/// Everything a reply is allowed to read.
#[derive(Debug, Clone, Copy)]
pub struct BrokerState<'a> {
    /// The tracked modes.
    pub modes: &'a ModeState,
    /// The canonical palette.
    pub palette: &'a Palette,
    /// The canonical grid state a reply may describe.
    pub report: CanonicalReport,
    /// The current graphic rendition, already rendered as SGR parameters.
    pub sgr: &'a str,
}

/// The query broker.
#[derive(Debug, Clone, Copy, Default)]
pub struct QueryBroker;

impl QueryBroker {
    /// Builds a broker.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Answers one `Q`-class event.
    ///
    /// Returns the replies in the order they must be written. An empty result means the profile's
    /// answer is silence, which several sequences specify; it never means the query was passed on.
    #[must_use]
    pub fn answer(&self, event: &Event, state: &BrokerState<'_>) -> Vec<Response> {
        let at = event.span.start();
        match &event.kind {
            EventKind::Control { byte: 0x05 } => Vec::new(),
            EventKind::Esc {
                intermediate: None,
                final_byte: b'Z',
                ..
            } => vec![Response::new(ResponseKind::DeviceAttributes1, at, da1())],
            EventKind::Csi {
                params,
                truncated,
                final_byte,
            } => self.answer_csi(
                &CsiView::with_truncation(params, *final_byte, *truncated),
                state,
                at,
            ),
            EventKind::Osc { selector, parts } => answer_osc(*selector, parts, event, state, at),
            EventKind::Dcs {
                intermediates,
                final_byte,
                payload,
                ..
            } => answer_dcs(intermediates, *final_byte, payload, state, at),
            _ => Vec::new(),
        }
    }

    fn answer_csi(&self, csi: &CsiView, state: &BrokerState<'_>, at: u64) -> Vec<Response> {
        match (csi.private, csi.intermediates.as_slice(), csi.final_byte) {
            (None, [], b'c') => vec![Response::new(ResponseKind::DeviceAttributes1, at, da1())],
            (Some(b'>'), [], b'c') => {
                vec![Response::new(ResponseKind::DeviceAttributes2, at, da2())]
            }
            (Some(b'='), [], b'c') => {
                vec![Response::new(ResponseKind::DeviceAttributes3, at, da3())]
            }
            (None, [], b'n') => answer_dsr(csi, state, at),
            (Some(b'?'), [], b'n') => answer_dec_dsr(csi, state, at),
            (None, [b'$'], b'p') => answer_decrqm(csi, state, ModeKind::Ansi, at),
            (Some(b'?'), [b'$'], b'p') => answer_decrqm(csi, state, ModeKind::Dec, at),
            (None, [], b't') => answer_window(csi, state, at),
            (Some(b'>'), [], b'q') => vec![Response::new(ResponseKind::Version, at, xtversion())],
            (Some(b'?'), [], b'm') => vec![Response::new(
                ResponseKind::KeyboardProtocol(0),
                at,
                format!("\x1b[>4;{}m", state.modes.modify_other_keys()).into_bytes(),
            )],
            (Some(b'?'), [], b'u') => vec![Response::new(
                ResponseKind::KeyboardProtocol(1),
                at,
                format!("\x1b[?{}u", state.modes.kitty_flags().unwrap_or(0)).into_bytes(),
            )],
            _ => Vec::new(),
        }
    }
}

fn joined(values: &[u16]) -> String {
    values
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(";")
}

fn da1() -> Vec<u8> {
    format!("\x1b[?{}c", joined(DA1_PARAMS)).into_bytes()
}

fn da2() -> Vec<u8> {
    format!("\x1b[>{}c", joined(DA2_PARAMS)).into_bytes()
}

fn da3() -> Vec<u8> {
    format!("\x1bP!|{DA3_UNIT_ID}\x1b\\").into_bytes()
}

fn xtversion() -> Vec<u8> {
    format!("\x1bP>|{XTVERSION_IDENTITY}\x1b\\").into_bytes()
}

fn answer_dsr(csi: &CsiView, state: &BrokerState<'_>, at: u64) -> Vec<Response> {
    match csi.first_or(0) {
        // Operating status: kr-vt/1 is always ready.
        5 => vec![Response::new(
            ResponseKind::DeviceStatus(5),
            at,
            b"\x1b[0n".to_vec(),
        )],
        6 => {
            let (row, col) = state.report.reported_cursor();
            vec![Response::new(
                ResponseKind::CursorPosition,
                at,
                format!("\x1b[{row};{col}R").into_bytes(),
            )]
        }
        // Anything else has no defined reply in this profile, and the sequence's own contract is
        // that an unsupported report is silent.
        _ => Vec::new(),
    }
}

fn answer_dec_dsr(csi: &CsiView, state: &BrokerState<'_>, at: u64) -> Vec<Response> {
    match csi.first_or(0) {
        // Extended cursor position, which adds the page number. kr-vt/1 has one page.
        6 => {
            let (row, col) = state.report.reported_cursor();
            vec![Response::new(
                ResponseKind::CursorPosition,
                at,
                format!("\x1b[?{row};{col};1R").into_bytes(),
            )]
        }
        // No printer.
        15 => vec![Response::new(
            ResponseKind::DeviceStatus(15),
            at,
            b"\x1b[?13n".to_vec(),
        )],
        // User-defined keys are locked; kr-vt/1 has none.
        25 => vec![Response::new(
            ResponseKind::DeviceStatus(25),
            at,
            b"\x1b[?20n".to_vec(),
        )],
        // Keyboard: North American layout, ready, unknown keyboard type.
        26 => vec![Response::new(
            ResponseKind::DeviceStatus(26),
            at,
            b"\x1b[?27;1;0;0n".to_vec(),
        )],
        _ => Vec::new(),
    }
}

fn answer_decrqm(csi: &CsiView, state: &BrokerState<'_>, kind: ModeKind, at: u64) -> Vec<Response> {
    let Some(mode) = csi.number(0) else {
        return Vec::new();
    };
    let Ok(mode) = u16::try_from(mode) else {
        return Vec::new();
    };
    let status = state.modes.report(kind, mode).status();
    let prefix = match kind {
        ModeKind::Ansi => "",
        ModeKind::Dec => "?",
    };
    vec![Response::new(
        ResponseKind::ModeReport(mode),
        at,
        format!("\x1b[{prefix}{mode};{status}$y").into_bytes(),
    )]
}

fn answer_window(csi: &CsiView, state: &BrokerState<'_>, at: u64) -> Vec<Response> {
    let report = state.report;
    let operation = csi.first_or(0);
    let bytes = match operation {
        // Never iconified: the session has no window to iconify.
        11 => b"\x1b[1t".to_vec(),
        // No window position.
        13 => b"\x1b[3;0;0t".to_vec(),
        // kr-vt/1 has no pixel geometry. Raster graphics are disabled, so nothing needs one, and
        // reporting invented pixel sizes would be worse than reporting none.
        14 => b"\x1b[4;0;0t".to_vec(),
        15 => b"\x1b[5;0;0t".to_vec(),
        16 => b"\x1b[6;0;0t".to_vec(),
        18 => format!("\x1b[8;{};{}t", report.rows, report.cols).into_bytes(),
        19 => format!("\x1b[9;{};{}t", report.rows, report.cols).into_bytes(),
        _ => return Vec::new(),
    };
    let key = u16::try_from(operation).unwrap_or(0);
    vec![Response::new(ResponseKind::GeometryReport(key), at, bytes)]
}

/// The string terminator an OSC reply should use, matching the request.
fn osc_terminator(event: &Event) -> &'static [u8] {
    match event.raw().last() {
        Some(0x07) => b"\x07",
        _ => b"\x1b\\",
    }
}

/// One operation inside an OSC colour string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColourOperation {
    /// Set a colour.
    Set {
        /// Which colour: an OSC selector, or [`INDEXED_BASE`] plus a palette index.
        selector: u32,
        /// The value.
        colour: Rgb,
    },
    /// Report a colour.
    Query {
        /// Which colour.
        selector: u32,
    },
}

/// Selectors at or above this base name an indexed palette entry rather than a dynamic colour.
pub const INDEXED_BASE: u32 = 0x1000;

/// Decodes an OSC colour string into the operations it asks for, in order.
///
/// A request may mix mutations and questions: `OSC 4 ; 1 ; #ff0000 ; 2 ; ?` sets one colour and asks
/// about another. Treating the whole string as a question would silently drop the mutation, so both
/// halves are decoded here and the caller applies and answers each in turn.
#[must_use]
pub fn colour_operations(selector: u32, parts: &[Vec<u8>]) -> Vec<ColourOperation> {
    let mut out = Vec::new();
    if selector == 4 {
        let mut index = 1;
        while index + 1 < parts.len() {
            if let Some(slot) = parse_index(&parts[index]) {
                let key = INDEXED_BASE + u32::from(slot);
                if parts[index + 1].as_slice() == b"?" {
                    out.push(ColourOperation::Query { selector: key });
                } else if let Ok(text) = core::str::from_utf8(&parts[index + 1])
                    && let Some(colour) = Rgb::parse(text)
                {
                    out.push(ColourOperation::Set {
                        selector: key,
                        colour,
                    });
                }
            }
            index += 2;
        }
        return out;
    }
    // A dynamic-colour request addresses consecutive selectors: `OSC 10 ; fg ; bg` sets both.
    for (offset, part) in parts.iter().skip(1).enumerate() {
        let Ok(offset) = u32::try_from(offset) else {
            break;
        };
        let key = selector + offset;
        if DynamicColour::from_selector(key).is_none() {
            break;
        }
        if part.as_slice() == b"?" {
            out.push(ColourOperation::Query { selector: key });
        } else if let Ok(text) = core::str::from_utf8(part)
            && let Some(colour) = Rgb::parse(text)
        {
            out.push(ColourOperation::Set {
                selector: key,
                colour,
            });
        }
    }
    out
}

fn answer_osc(
    selector: Option<u32>,
    parts: &[Vec<u8>],
    event: &Event,
    state: &BrokerState<'_>,
    at: u64,
) -> Vec<Response> {
    let Some(selector) = selector else {
        return Vec::new();
    };
    if !matches!(selector, 4 | 10..=19) {
        return Vec::new();
    }
    let terminator = osc_terminator(event);
    colour_operations(selector, parts)
        .into_iter()
        .filter_map(|operation| {
            let ColourOperation::Query { selector: key } = operation else {
                return None;
            };
            let (prefix, colour) = if key >= INDEXED_BASE {
                let index = u8::try_from(key - INDEXED_BASE).ok()?;
                (format!("\x1b]4;{index};"), state.palette.indexed(index))
            } else {
                let which = DynamicColour::from_selector(key)?;
                (format!("\x1b]{key};"), state.palette.dynamic(which))
            };
            let mut bytes = format!("{prefix}{}", colour.to_report()).into_bytes();
            bytes.extend_from_slice(terminator);
            Some(Response::new(ResponseKind::Colour(key), at, bytes))
        })
        .collect()
}

fn parse_index(part: &[u8]) -> Option<u8> {
    core::str::from_utf8(part).ok()?.parse::<u8>().ok()
}

fn answer_dcs(
    intermediates: &[u8],
    final_byte: u8,
    payload: &[u8],
    state: &BrokerState<'_>,
    at: u64,
) -> Vec<Response> {
    match (intermediates, final_byte) {
        ([b'$'], b'q') => vec![Response::new(
            ResponseKind::SettingReport(ResponseKind::name_key(payload)),
            at,
            decrqss(payload, state),
        )],
        ([b'+'], b'q') => terminfo::xtgettcap_replies(payload)
            .into_iter()
            .map(|reply| {
                Response::new(
                    ResponseKind::Capability(ResponseKind::name_key(reply.name.as_bytes())),
                    at,
                    reply.bytes,
                )
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Answers DECRQSS for the settings kr-vt/1 reports.
///
/// A setting the profile does not report gets the defined failure reply, not silence and not a
/// guess. An application that reads the failure knows to stop asking.
fn decrqss(request: &[u8], state: &BrokerState<'_>) -> Vec<u8> {
    let report = state.report;
    let body = match request {
        b"m" => Some(format!("{}m", state.sgr)),
        b"r" => Some(format!("{};{}r", report.margin_top, report.margin_bottom)),
        b"s" => Some(format!("{};{}s", report.margin_left, report.margin_right)),
        b" q" => Some(format!("{} q", report.cursor_style)),
        // Conformance level: VT220 with 7-bit controls, which is what the profile emits.
        b"\"p" => Some("62;1\"p".to_owned()),
        b"t" => Some(format!("{}t", report.rows)),
        _ => None,
    };
    match body {
        Some(body) => format!("\x1bP1$r{body}\x1b\\").into_bytes(),
        None => b"\x1bP0$r\x1b\\".to_vec(),
    }
}
