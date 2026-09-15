//! The query broker: the one thing in the system that answers a terminal query.
//!
//! Section 8 allows exactly one responder. The worker is it. No query is forwarded to an attached
//! terminal, no attached terminal is asked what it can do on the application's behalf, and no
//! answer describes anything except the virtual profile and the session's own canonical state.
//! That is what makes two attachments from two different terminals safe: the application gets the
//! same answers either way, and neither terminal ever sees the question.
//!
//! Every reply is built in 7-bit form. kr-vt/1 never emits an 8-bit C1 introducer, so a reply is
//! always valid UTF-8 and always safe to write into a UTF-8 stream.

use crate::classify::CsiView;
use crate::event::{Event, EventKind};
use crate::lane::{Response, ResponseKind};
use crate::modes::{ModeKind, ModeState};
use crate::palette::{DynamicColour, Palette};
use crate::profile::{DA1_PARAMS, DA2_PARAMS, DA3_UNIT_ID, XTVERSION_IDENTITY};
use crate::terminfo;

/// The canonical state a reply may describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalReport {
    /// Cursor row, one-based.
    pub cursor_row: u32,
    /// Cursor column, one-based.
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
    /// The DECSCUSR style number.
    pub cursor_style: u32,
    /// The DECSCA protection attribute.
    pub protection: u32,
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
            } => vec![response(ResponseKind::DeviceAttributes1, at, da1())],
            EventKind::Csi {
                params, final_byte, ..
            } => self.answer_csi(&CsiView::new(params, *final_byte), state, at),
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
            (None, [], b'c') => vec![response(ResponseKind::DeviceAttributes1, at, da1())],
            (Some(b'>'), [], b'c') => vec![response(ResponseKind::DeviceAttributes2, at, da2())],
            (Some(b'='), [], b'c') => vec![response(ResponseKind::DeviceAttributes3, at, da3())],
            (None, [], b'n') => answer_dsr(csi, state, at),
            (Some(b'?'), [], b'n') => answer_dec_dsr(csi, state, at),
            (None, [b'$'], b'p') => answer_decrqm(csi, state, ModeKind::Ansi, at),
            (Some(b'?'), [b'$'], b'p') => answer_decrqm(csi, state, ModeKind::Dec, at),
            (None, [], b't') => answer_window(csi, state, at),
            (Some(b'>'), [], b'q') => vec![response(ResponseKind::Version, at, xtversion())],
            (Some(b'?'), [], b'm') => vec![response(
                ResponseKind::KeyboardProtocol,
                at,
                format!("\x1b[>4;{}m", state.modes.modify_other_keys()).into_bytes(),
            )],
            (Some(b'?'), [], b'u') => vec![response(
                ResponseKind::KeyboardProtocol,
                at,
                format!("\x1b[?{}u", state.modes.kitty_flags().unwrap_or(0)).into_bytes(),
            )],
            _ => Vec::new(),
        }
    }
}

fn response(kind: ResponseKind, query_at: u64, bytes: Vec<u8>) -> Response {
    Response {
        bytes,
        kind,
        query_at,
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
        5 => vec![response(
            ResponseKind::DeviceStatus,
            at,
            b"\x1b[0n".to_vec(),
        )],
        6 => vec![response(
            ResponseKind::CursorPosition,
            at,
            format!(
                "\x1b[{};{}R",
                state.report.cursor_row, state.report.cursor_col
            )
            .into_bytes(),
        )],
        // Anything else has no defined reply in this profile, and the sequence's own contract is
        // that an unsupported report is silent.
        _ => Vec::new(),
    }
}

fn answer_dec_dsr(csi: &CsiView, state: &BrokerState<'_>, at: u64) -> Vec<Response> {
    match csi.first_or(0) {
        // Extended cursor position, which adds the page number. kr-vt/1 has one page.
        6 => vec![response(
            ResponseKind::CursorPosition,
            at,
            format!(
                "\x1b[?{};{};1R",
                state.report.cursor_row, state.report.cursor_col
            )
            .into_bytes(),
        )],
        // No printer.
        15 => vec![response(
            ResponseKind::DeviceStatus,
            at,
            b"\x1b[?13n".to_vec(),
        )],
        // User-defined keys are locked; kr-vt/1 has none.
        25 => vec![response(
            ResponseKind::DeviceStatus,
            at,
            b"\x1b[?20n".to_vec(),
        )],
        // Keyboard: North American layout, ready, unknown keyboard type.
        26 => vec![response(
            ResponseKind::DeviceStatus,
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
    vec![response(
        ResponseKind::ModeReport,
        at,
        format!("\x1b[{prefix}{mode};{status}$y").into_bytes(),
    )]
}

fn answer_window(csi: &CsiView, state: &BrokerState<'_>, at: u64) -> Vec<Response> {
    let report = state.report;
    let bytes = match csi.first_or(0) {
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
    vec![response(ResponseKind::GeometryReport, at, bytes)]
}

/// The string terminator an OSC reply should use, matching the request.
fn osc_terminator(event: &Event) -> &'static [u8] {
    match event.raw().last() {
        Some(0x07) => b"\x07",
        _ => b"\x1b\\",
    }
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
    let terminator = osc_terminator(event);
    match selector {
        // OSC 4 asks about indexed colours; the request may pair several index/value items.
        4 => {
            let mut out = Vec::new();
            let mut index = 1;
            while index + 1 < parts.len() {
                if parts[index + 1].as_slice() == b"?"
                    && let Some(colour) =
                        parse_index(&parts[index]).map(|slot| state.palette.indexed(slot))
                {
                    let mut bytes = format!(
                        "\x1b]4;{};{}",
                        parts_text(&parts[index]),
                        colour.to_report()
                    )
                    .into_bytes();
                    bytes.extend_from_slice(terminator);
                    out.push(response(ResponseKind::Colour, at, bytes));
                }
                index += 2;
            }
            out
        }
        10..=19 => {
            let Some(which) = DynamicColour::from_selector(selector) else {
                return Vec::new();
            };
            if parts.get(1).map(Vec::as_slice) != Some(b"?") {
                return Vec::new();
            }
            let mut bytes = format!(
                "\x1b]{selector};{}",
                state.palette.dynamic(which).to_report()
            )
            .into_bytes();
            bytes.extend_from_slice(terminator);
            vec![response(ResponseKind::Colour, at, bytes)]
        }
        _ => Vec::new(),
    }
}

fn parse_index(part: &[u8]) -> Option<u8> {
    core::str::from_utf8(part).ok()?.parse::<u8>().ok()
}

fn parts_text(part: &[u8]) -> String {
    String::from_utf8_lossy(part).into_owned()
}

fn answer_dcs(
    intermediates: &[u8],
    final_byte: u8,
    payload: &[u8],
    state: &BrokerState<'_>,
    at: u64,
) -> Vec<Response> {
    match (intermediates, final_byte) {
        ([b'$'], b'q') => vec![response(
            ResponseKind::SettingReport,
            at,
            decrqss(payload, state),
        )],
        ([b'+'], b'q') => terminfo::xtgettcap_replies(payload)
            .into_iter()
            .map(|bytes| response(ResponseKind::Capability, at, bytes))
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
        b"\"q" => Some(format!("{}\"q", report.protection)),
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
