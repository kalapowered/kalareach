//! The normative sequence-class table, implemented row by row.
//!
//! Every function here answers one question about one lexed sequence and nothing else, so the
//! table in section 8 and the code below can be read side by side. The order of the functions
//! follows the order of the rows.
//!
//! Three rules hold everywhere:
//!
//! * A sequence that no row names is `X`. An unknown CSI set/reset/SGR final is not "probably
//!   harmless"; it is consumed until a profile revision gives it a class.
//! * Recognising a final byte or an OSC number is not enough. A row covers the *qualified* forms of
//!   its sequence, so an unsupported parameter, subcommand, resource or flag falls through to `X`
//!   rather than travelling on inside a sequence that looks familiar.
//! * A class never depends on who is attached, what the physical terminal is, or what was observed
//!   earlier in the stream. Routing and policy depend on those; classification does not.

use crate::class::SequenceClass;
use crate::event::{CsiParam, DirectDisposition, EventKind};

/// The largest value a control-sequence parameter may carry into the canonical grid.
///
/// A parameter is a repeat count, a column, a row or a tab stop, and the grid is at most 2,048 by
/// 1,024. A larger value cannot mean more work that anyone wants done, but a reducer that loops
/// once per unit would happily try: `CSI 4294967295 I` is five bytes of input and billions of
/// iterations of work. Clamping bounds that before anything reaches the grid.
pub const MAX_CSI_PARAM: i64 = 65_535;

/// The parts of a control sequence the table is written in terms of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsiView {
    /// The leading private-marker byte: `<`, `=`, `>` or `?`.
    pub private: Option<u8>,
    /// The intermediate bytes, in source order.
    pub intermediates: Vec<u8>,
    /// The numeric parameter slots, `None` where a slot was left empty.
    ///
    /// A slot holds the *leading* value of its colon sublist, because that is the one the table is
    /// written in terms of. [`Self::sub_parameters`] says whether any sublist was present at all.
    pub numbers: Vec<Option<i64>>,
    /// Whether any slot carried a colon sublist or a misplaced private marker.
    pub sub_parameters: bool,
    /// Whether the parser dropped part of the sequence before it could be classified.
    pub truncated: bool,
    /// The final byte.
    pub final_byte: u8,
}

impl CsiView {
    /// Splits a parameter list into the shape the table is written in.
    #[must_use]
    pub fn new(params: &[CsiParam], final_byte: u8) -> Self {
        Self::with_truncation(params, final_byte, false)
    }

    /// Splits a parameter list, carrying through whether the parser truncated the sequence.
    #[must_use]
    pub fn with_truncation(params: &[CsiParam], final_byte: u8, truncated: bool) -> Self {
        let mut rest = params;
        let mut private = None;
        if let Some(CsiParam::Punct(byte @ 0x3c..=0x3f)) = rest.first() {
            private = Some(*byte);
            rest = &rest[1..];
        }
        let mut intermediates = Vec::new();
        while let Some(CsiParam::Punct(byte @ 0x20..=0x2f)) = rest.last() {
            intermediates.insert(0, *byte);
            rest = &rest[..rest.len() - 1];
        }
        let mut numbers = Vec::new();
        let mut slot: Option<i64> = None;
        let mut slot_open = false;
        let mut sub_parameters = false;
        for param in rest {
            match param {
                CsiParam::Integer(value) => {
                    // The leading value of a slot is the one the table names. A later value in the
                    // same slot belongs to a colon sublist and never replaces it.
                    if slot.is_none() {
                        slot = Some(*value);
                    }
                    slot_open = true;
                }
                CsiParam::Punct(b';') => {
                    numbers.push(slot.take());
                    slot_open = false;
                }
                // A colon sublist, or a private marker somewhere other than the front.
                CsiParam::Punct(_) => {
                    sub_parameters = true;
                    slot_open = true;
                }
            }
        }
        if slot_open || !numbers.is_empty() {
            numbers.push(slot);
        }
        Self {
            private,
            intermediates,
            numbers,
            sub_parameters,
            truncated,
            final_byte,
        }
    }

    /// The numeric slot at `index`, treating an empty slot as absent.
    #[must_use]
    pub fn number(&self, index: usize) -> Option<i64> {
        self.numbers.get(index).copied().flatten()
    }

    /// The first numeric slot, or `default` when the sequence carries none.
    #[must_use]
    pub fn first_or(&self, default: i64) -> i64 {
        self.number(0).unwrap_or(default)
    }
}

/// The DEC private modes kr-vt/1 tracks as class `M`.
///
/// Section 8 lists these explicitly. Mode 1034 is here because the profile advertises the matching
/// terminfo capability and therefore owes it real input semantics; the section requires exactly
/// that rather than advertising a capability and dropping it at the prompt.
pub const TRACKED_DEC_MODES: &[u16] = &[
    1, 5, 6, 7, 8, 12, 25, 45, 66, 67, 69, 1000, 1002, 1003, 1004, 1005, 1006, 1007, 1034, 1047,
    1048, 1049, 2004, 2026,
];

/// The ANSI modes kr-vt/1 tracks as class `M`: IRM (4) and LNM (20).
pub const TRACKED_ANSI_MODES: &[u16] = &[4, 20];

/// DEC mode 2027, grapheme clustering. kr-vt/1 reports it unsupported and never applies it.
pub const MODE_GRAPHEME_CLUSTERING: u16 = 2027;
/// DEC mode 2048, in-band resize notification. kr-vt/1 reports it unsupported.
pub const MODE_INBAND_RESIZE: u16 = 2048;
/// DEC mode 9001, the ConPTY win32 input mode, terminated at its own boundary.
pub const MODE_WIN32_INPUT: u16 = 9001;
/// DEC mode 3, DECCOLM. Geometry belongs to the size owner, so a set or reset is `X`.
pub const MODE_DECCOLM: u16 = 3;
/// DEC mode 2026, synchronised output, which the profile advertises and a probe asks about.
pub const MODE_SYNCHRONISED_OUTPUT: u16 = 2026;

/// The `modifyOtherKeys` resource kr-vt/1 qualifies. xterm defines several; only this one is input.
pub const MODIFY_OTHER_KEYS_RESOURCE: i64 = 4;

/// Assigns the normative class of one lexed sequence.
#[must_use]
pub fn classify(kind: &EventKind) -> SequenceClass {
    match kind {
        // Row 1: valid UTF-8 text.
        EventKind::Text { .. } => SequenceClass::Display,
        // Byte policy: malformed input renders as U+FFFD, which is still display.
        EventKind::Replacement { .. } => SequenceClass::Display,
        EventKind::Control { byte } => classify_control(*byte),
        EventKind::Esc {
            intermediate,
            extra_intermediates,
            final_byte,
        } => {
            if *extra_intermediates {
                SequenceClass::Extension
            } else {
                classify_esc(*intermediate, *final_byte)
            }
        }
        EventKind::Csi {
            params,
            truncated,
            final_byte,
        } => classify_csi(&CsiView::with_truncation(params, *final_byte, *truncated)),
        EventKind::Osc { selector, parts } => classify_osc(*selector, parts),
        EventKind::Dcs {
            params,
            intermediates,
            final_byte,
            ..
        } => classify_dcs(params, intermediates, *final_byte),
        // Last table row: every other APC, PM and SOS string.
        EventKind::OtherString { .. } => SequenceClass::Extension,
        EventKind::CsiIgnored { .. } | EventKind::Discarded { .. } => SequenceClass::Extension,
    }
}

/// Row 1 (`BS, HT, LF, VT, FF, CR`) and the BEL row, plus the C0 controls kr-vt/1 names.
#[must_use]
pub fn classify_control(byte: u8) -> SequenceClass {
    match byte {
        // NUL is stream padding and DEL is discarded by the state machine. Both are display
        // no-ops; naming them keeps them out of the diagnostic stream.
        0x00 | 0x7f => SequenceClass::Display,
        // ENQ asks for the answerback string. kr-vt/1 has none, so the broker answers with silence
        // rather than letting the request travel onwards.
        0x05 => SequenceClass::Query,
        0x07 => SequenceClass::SideEffect,
        0x08..=0x0d => SequenceClass::Display,
        0x0e | 0x0f => SequenceClass::Display,
        _ => SequenceClass::Extension,
    }
}

/// Row 1 (saved cursors, character sets) and row 3 (RIS, keypad, tab stops).
#[must_use]
pub fn classify_esc(intermediate: Option<u8>, final_byte: u8) -> SequenceClass {
    match (intermediate, final_byte) {
        // DEC character sets. Only G0 and G1 are designated: the canonical grid implements those
        // two, and a G2 or G3 designation it would ignore is an extension, not a display change.
        (Some(b'(' | b')'), 0x30..=0x7e) => SequenceClass::Display,
        // DECALN, the screen alignment pattern.
        (Some(b'#'), b'8') => SequenceClass::Display,
        // ESC % G selects UTF-8, which kr-vt/1 already is. Any other designation would leave the
        // profile's encoding, so it is refused rather than tracked.
        (Some(b'%'), b'G') => SequenceClass::Mode,
        (None, b'7' | b'8') => SequenceClass::Display,
        (None, b'D' | b'E' | b'M') => SequenceClass::Display,
        // Row 3: HTS, RIS, DECKPAM and DECKPNM.
        (None, b'H') => SequenceClass::Mode,
        (None, b'c') => SequenceClass::Mode,
        (None, b'=' | b'>') => SequenceClass::Mode,
        // DECID is the obsolete spelling of DA1.
        (None, b'Z') => SequenceClass::Query,
        _ => SequenceClass::Extension,
    }
}

/// The control-sequence rows of the table.
#[must_use]
pub fn classify_csi(csi: &CsiView) -> SequenceClass {
    // A sequence the parser could not keep whole is not a shorter sequence. The part it dropped
    // could have carried a mode the profile refuses.
    if csi.truncated {
        return SequenceClass::Extension;
    }
    // A colon sublist belongs to ordinary SGR and nowhere else in this profile. `CSI ? 3 : 7 h` is
    // not a request to set mode 7, and `CSI > 4 : 99 m` is not a modifyOtherKeys level: the private
    // forms of `m` are keyboard negotiation, which has no sublist of its own.
    if csi.sub_parameters && (csi.final_byte != b'm' || csi.private.is_some()) {
        return SequenceClass::Extension;
    }
    match (csi.private, csi.intermediates.as_slice(), csi.final_byte) {
        // Row: DA1, DA2 and DA3.
        (None, [], b'c') | (Some(b'>' | b'='), [], b'c') => SequenceClass::Query,
        // Row: DSR and CPR, in both the ANSI and the DEC spelling.
        (None | Some(b'?'), [], b'n') => SequenceClass::Query,
        // Row: DECRQM, in both spellings.
        (None | Some(b'?'), [b'$'], b'p') => SequenceClass::Query,
        // Row: XTVERSION.
        (Some(b'>'), [], b'q') => SequenceClass::Query,
        // Row: SM and RM.
        (None, [], b'h' | b'l') => ansi_mode_class(csi),
        // Row: DECSET and DECRST, including the modes with their own rows.
        (Some(b'?'), [], b'h' | b'l') => dec_mode_class(csi),
        // Row: window manipulation. Geometry reports are Q, the title stack is M, and every
        // physical resize or window request is X.
        (None, [], b't') => window_op_class(csi),
        // Row: modifyOtherKeys. Only resource 4 at level 0, 1 or 2 is qualified input; any other
        // resource is an xterm setting this profile does not implement.
        (Some(b'>'), [], b'm') => modify_other_keys_class(csi),
        (Some(b'?'), [], b'm') => SequenceClass::Query,
        // Row: Kitty keyboard negotiation. Push, pop and set are M; the query is Q.
        (Some(b'>' | b'<' | b'='), [], b'u') => kitty_class(csi),
        (Some(b'?'), [], b'u') => SequenceClass::Query,
        // Row 1: cursor movement, erasure, insertion, deletion, scrolling and SGR.
        (
            None,
            [],
            b'@' | b'A' | b'B' | b'C' | b'D' | b'E' | b'F' | b'G' | b'H' | b'I' | b'L' | b'M'
            | b'P' | b'S' | b'X' | b'Z' | b'`' | b'a' | b'b' | b'd' | b'e' | b'f' | b'm',
        ) => SequenceClass::Display,
        // Erasing takes a selector rather than a count: 0 to the end, 1 from the start, 2 the
        // whole area, and for ED 3 the scrollback as well. Another value is a different operation,
        // not a larger one.
        (None, [], b'J') => {
            if matches!(csi.first_or(0), 0..=3) {
                SequenceClass::Display
            } else {
                SequenceClass::Extension
            }
        }
        (None, [], b'K') => {
            if matches!(csi.first_or(0), 0..=2) {
                SequenceClass::Display
            } else {
                SequenceClass::Extension
            }
        }
        // SD shares its final byte with xterm's highlight mouse tracking, which kr-vt/1 does not
        // advertise. One parameter is the scroll; more parameters are the tracking request.
        (None, [], b'T') => {
            if csi.numbers.len() <= 1 {
                SequenceClass::Display
            } else {
                SequenceClass::Extension
            }
        }
        // Row 1: saved cursors and margins.
        (None, [], b'r' | b's' | b'u') => SequenceClass::Display,
        // Row 3: tab stops. Only "clear this stop" and "clear every stop" are implemented.
        (None, [], b'g') => {
            if matches!(csi.first_or(0), 0 | 3) {
                SequenceClass::Mode
            } else {
                SequenceClass::Extension
            }
        }
        // Row 3: DECSTR, the soft reset.
        (None, [b'!'], b'p') => SequenceClass::Mode,
        // Row 1: DECSCUSR.
        (None, [b' '], b'q') => SequenceClass::Display,
        _ => SequenceClass::Extension,
    }
}

fn ansi_mode_class(csi: &CsiView) -> SequenceClass {
    if csi.numbers.is_empty() {
        return SequenceClass::Extension;
    }
    for slot in &csi.numbers {
        let Some(value) = slot else {
            return SequenceClass::Extension;
        };
        let Ok(mode) = u16::try_from(*value) else {
            return SequenceClass::Extension;
        };
        if !TRACKED_ANSI_MODES.contains(&mode) {
            return SequenceClass::Extension;
        }
    }
    SequenceClass::Mode
}

fn dec_mode_class(csi: &CsiView) -> SequenceClass {
    if csi.numbers.is_empty() {
        return SequenceClass::Extension;
    }
    for slot in &csi.numbers {
        let Some(value) = slot else {
            return SequenceClass::Extension;
        };
        let Ok(mode) = u16::try_from(*value) else {
            return SequenceClass::Extension;
        };
        // Its own row: mode 9001 is a real mode, but it stops at the ConPTY boundary that owns it.
        if mode == MODE_WIN32_INPUT {
            continue;
        }
        // Their own rows: DECCOLM, grapheme clustering and in-band resize are all X on set/reset.
        if !TRACKED_DEC_MODES.contains(&mode) {
            return SequenceClass::Extension;
        }
    }
    SequenceClass::Mode
}

fn modify_other_keys_class(csi: &CsiView) -> SequenceClass {
    match csi.numbers.len() {
        // `CSI > m` resets every resource to its initial value.
        0 => SequenceClass::Mode,
        // `CSI > Pp m` resets one resource.
        1 => {
            if csi.number(0) == Some(MODIFY_OTHER_KEYS_RESOURCE) {
                SequenceClass::Mode
            } else {
                SequenceClass::Extension
            }
        }
        2 => {
            let resource = csi.number(0);
            let level = csi.number(1).unwrap_or(0);
            if resource == Some(MODIFY_OTHER_KEYS_RESOURCE) && (0..=2).contains(&level) {
                SequenceClass::Mode
            } else {
                SequenceClass::Extension
            }
        }
        _ => SequenceClass::Extension,
    }
}

fn kitty_class(csi: &CsiView) -> SequenceClass {
    let qualified = i64::from(crate::modes::KITTY_QUALIFIED_FLAGS);
    match csi.private {
        // Push: one flag set, and only flags the profile advertises. A flag the input encoders
        // cannot produce must not reach the application or the terminal.
        Some(b'>') => {
            if csi.numbers.len() <= 1 && csi.first_or(0) & !qualified == 0 {
                SequenceClass::Mode
            } else {
                SequenceClass::Extension
            }
        }
        // Pop: a count.
        Some(b'<') => {
            if csi.numbers.len() <= 1 {
                SequenceClass::Mode
            } else {
                SequenceClass::Extension
            }
        }
        // Set: flags plus the set, or, and mode.
        Some(b'=') => {
            let flags_ok = csi.first_or(0) & !qualified == 0;
            let mode_ok = matches!(csi.number(1).unwrap_or(1), 1..=3);
            if csi.numbers.len() <= 2 && flags_ok && mode_ok {
                SequenceClass::Mode
            } else {
                SequenceClass::Extension
            }
        }
        _ => SequenceClass::Extension,
    }
}

fn window_op_class(csi: &CsiView) -> SequenceClass {
    match csi.first_or(0) {
        // Geometry and window-state reports.
        11 | 13 | 14 | 15 | 16 | 18 | 19 => SequenceClass::Query,
        // The virtualised title stack. The second parameter selects which title: 0 for both, 1 for
        // the icon name and 2 for the window title. Nothing else is a title.
        22 | 23 => {
            let target = csi.numbers.get(1).copied().flatten().unwrap_or(0);
            if csi.numbers.len() <= 2 && matches!(target, 0..=2) {
                SequenceClass::Mode
            } else {
                SequenceClass::Extension
            }
        }
        // Everything else asks for a physical window change, or reports a title.
        _ => SequenceClass::Extension,
    }
}

/// Whether an OSC 133 subcommand is one of the documented prompt and command boundaries.
fn osc133_class(parts: &[Vec<u8>]) -> SequenceClass {
    let Some(sub) = parts.get(1) else {
        return SequenceClass::Extension;
    };
    match sub.as_slice() {
        b"A" | b"B" | b"C" | b"D" => SequenceClass::Display,
        // The property form carries one documented key. An unknown property is an extension.
        b"P" => match parts.get(2) {
            Some(property) if property.starts_with(b"Cwd=") => SequenceClass::Display,
            _ => SequenceClass::Extension,
        },
        _ => SequenceClass::Extension,
    }
}

/// Whether an OSC 633 subcommand is one of the documented shell-integration boundaries.
fn osc633_class(parts: &[Vec<u8>]) -> SequenceClass {
    let Some(sub) = parts.get(1) else {
        return SequenceClass::Extension;
    };
    match sub.as_slice() {
        b"A" | b"B" | b"C" | b"D" | b"E" => SequenceClass::Display,
        b"P" => match parts.get(2) {
            Some(property)
                if property.starts_with(b"Cwd=")
                    || property.starts_with(b"IsWindows=")
                    || property.starts_with(b"Task=")
                    || property.starts_with(b"ContinuationPrompt=") =>
            {
                SequenceClass::Display
            }
            _ => SequenceClass::Extension,
        },
        _ => SequenceClass::Extension,
    }
}

/// Whether an OSC 1337 subcommand is one of the documented metadata keys.
fn osc1337_is_documented(body: &[u8]) -> bool {
    body == b"SetMark"
        || body.starts_with(b"CurrentDir=")
        || body.starts_with(b"RemoteHost=")
        || body.starts_with(b"ShellIntegrationVersion=")
}

/// OSC 9 carries two conventions: a progress report under subcommand `4`, and a notification body
/// otherwise. Any other numeric subcommand belongs to a convention kr-vt/1 has not qualified.
/// A numeric parameter that may be omitted or empty, but not malformed.
///
/// `None` is the answer for a value that is present and is not a number, which is a different thing
/// from a value that was left out.
fn optional_number(part: Option<&Vec<u8>>) -> Option<u32> {
    match part {
        None => Some(0),
        Some(part) if part.is_empty() => Some(0),
        Some(part) => core::str::from_utf8(part)
            .ok()
            .and_then(|text| text.parse::<u32>().ok()),
    }
}

/// Whether OSC 99 notification metadata is inside the qualified subset.
///
/// The metadata is a colon-separated list of `key=value` pairs. Only the keys below are qualified,
/// and each one's value is checked: an unknown key, or a known key with a value outside its set, is
/// an extension rather than a notification with an unread instruction in it.
fn osc99_metadata_qualified(metadata: &[u8]) -> bool {
    if metadata.is_empty() {
        return true;
    }
    metadata.split(|byte| *byte == b':').all(|pair| {
        let mut halves = pair.splitn(2, |byte| *byte == b'=');
        let Some(key) = halves.next() else {
            return false;
        };
        let value = halves.next().unwrap_or(b"");
        match key {
            // The notification identifier, which groups the parts of one notification.
            b"i" | b"g" => {
                !value.is_empty()
                    && value.len() <= 64
                    && value
                        .iter()
                        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
            }
            // Which part of the notification the payload is.
            b"p" => matches!(value, b"title" | b"body"),
            // The payload's encoding.
            b"e" => matches!(value, b"0" | b"1"),
            // Whether the notification is complete. This profile delivers a notification when it
            // arrives, so a part that says more is coming is an extension rather than the first of
            // a pair that nothing will assemble.
            b"d" => value == b"1",
            b"u" => matches!(value, b"0" | b"1" | b"2"),
            // When the notification is shown.
            b"o" => matches!(value, b"always" | b"unfocused" | b"invisible"),
            _ => false,
        }
    })
}

/// The OSC 99 notification row.
fn osc99_class(parts: &[Vec<u8>]) -> SequenceClass {
    let Some(metadata) = parts.get(1) else {
        return SequenceClass::Extension;
    };
    if parts.len() < 3 || !osc99_metadata_qualified(metadata) {
        return SequenceClass::Extension;
    }
    SequenceClass::SideEffect
}

fn osc9_class(parts: &[Vec<u8>]) -> SequenceClass {
    let Some(sub) = parts.get(1) else {
        return SequenceClass::Extension;
    };
    if sub.as_slice() == b"4" {
        // States 0 to 4: none, determinate, error, indeterminate and paused. An omitted state is
        // the documented default; a state that is present and is not one of those is not the same
        // thing, and must not take the omitted form's answer.
        let Some(state) = optional_number(parts.get(2)) else {
            return SequenceClass::Extension;
        };
        if state > 4 {
            return SequenceClass::Extension;
        }
        // The determinate form carries a percentage.
        let Some(progress) = optional_number(parts.get(3)) else {
            return SequenceClass::Extension;
        };
        if progress > 100 {
            return SequenceClass::Extension;
        }
        return SequenceClass::SideEffect;
    }
    let numeric = !sub.is_empty() && sub.iter().all(u8::is_ascii_digit);
    if numeric {
        SequenceClass::Extension
    } else {
        SequenceClass::SideEffect
    }
}

/// Whether an OSC colour selector names a colour the canonical palette represents.
///
/// The Tektronix colours do not, so asking about one or setting one is an extension rather than a
/// colour the session owns and could answer for.
fn osc_colour_is_qualified(selector: u32) -> bool {
    crate::palette::DynamicColour::from_selector(selector).is_some()
}

/// The operating-system-command rows of the table.
#[must_use]
pub fn classify_osc(selector: Option<u32>, parts: &[Vec<u8>]) -> SequenceClass {
    let Some(selector) = selector else {
        return SequenceClass::Extension;
    };
    let has_query = parts.iter().skip(1).any(|part| part.as_slice() == b"?");
    match selector {
        // Row: OSC 0, 1 and 2 track the application title.
        0..=2 => SequenceClass::Mode,
        // Row: OSC 7, the untrusted working-directory observation.
        7 => SequenceClass::Display,
        // Row: OSC 8 hyperlinks.
        8 => SequenceClass::Display,
        // Row: OSC 9, 99 and 777 notifications and progress. Each subcommand is recognised
        // explicitly; an unknown one is X rather than a side effect of unknown shape.
        9 => osc9_class(parts),
        99 => osc99_class(parts),
        777 => {
            if parts.get(1).map(Vec::as_slice) == Some(b"notify") {
                SequenceClass::SideEffect
            } else {
                SequenceClass::Extension
            }
        }
        // Row: the palette. `?` asks, a colour this palette understands mutates, and a field that
        // is neither makes the whole request an extension. A request may pair several.
        4 => {
            if crate::broker::colour_request_is_qualified(4, parts) {
                if has_query {
                    SequenceClass::Query
                } else {
                    SequenceClass::Mode
                }
            } else {
                SequenceClass::Extension
            }
        }
        // Row: the dynamic colours.
        10..=19 => {
            if !osc_colour_is_qualified(selector)
                || !crate::broker::colour_request_is_qualified(selector, parts)
            {
                SequenceClass::Extension
            } else if has_query {
                SequenceClass::Query
            } else {
                SequenceClass::Mode
            }
        }
        // Row: OSC 52 clipboard access.
        52 => SequenceClass::SideEffect,
        // Row: the palette and dynamic-colour resets.
        104 => SequenceClass::Mode,
        110..=119 => {
            if osc_colour_is_qualified(selector - 100) {
                SequenceClass::Mode
            } else {
                SequenceClass::Extension
            }
        }
        // Row: OSC 133 shell integration.
        133 => osc133_class(parts),
        // Row: OSC 633 shell integration.
        633 => osc633_class(parts),
        // Row: OSC 1337 metadata. File, clipboard, launch and proprietary queries are X.
        1337 => match parts.get(1) {
            Some(body) if osc1337_is_documented(body) => SequenceClass::Display,
            _ => SequenceClass::Extension,
        },
        _ => SequenceClass::Extension,
    }
}

/// The device-control rows of the table.
#[must_use]
pub fn classify_dcs(params: &[CsiParam], intermediates: &[u8], final_byte: u8) -> SequenceClass {
    match (intermediates, final_byte) {
        // Row: DECRQSS and XTGETTCAP. Neither takes parameters.
        ([b'$'], b'q') | ([b'+'], b'q') if params.is_empty() => SequenceClass::Query,
        // Row: sixel and every other device-control string, including DECUDK.
        _ => SequenceClass::Extension,
    }
}

/// What the profile does with a sequence it handles itself rather than passing on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopsHere {
    /// Nothing special: the ordinary rules decide.
    No,
    /// The sequence goes no further, and nothing else needs to happen.
    Withhold,
    /// The sequence goes no further, but it changed the canonical screen, so the attachment has to
    /// project to see the result.
    Projection,
}

/// Whether a sequence is one the profile handles itself rather than passing on.
///
/// The virtualised title stack is the clearest case. Section 8 requires push and pop to be
/// virtualised so that they cannot consume the attach client's saved outer title, and forwarding
/// the raw bytes would do exactly that. The ConPTY win32 input mode is the other: it stops at the
/// backend that owns it and is never broadcast to a remote client. A request that names mode 9001
/// alongside other modes still stops here, so the attachment projects rather than falling out of
/// step over the modes that did apply.
///
/// Keyboard negotiation is deliberately not here. It is a mode, and a mode is forwarded live: a
/// direct terminal that did not see the negotiation would keep sending the old encoding, which is
/// exactly the mismatch the negotiation exists to prevent. The profile still tracks it and still
/// keeps it away from the canonical grid, which has nothing to do with key encodings.
fn stops_here(kind: &EventKind) -> StopsHere {
    // A colour request that both asks and changes is answered here, so its bytes stop here too.
    // The change went into the canonical palette and a physical terminal never saw it, which it
    // has to be told about rather than left to drift.
    if let EventKind::Osc {
        selector: Some(selector),
        parts,
    } = kind
        && matches!(selector, 4 | 10..=19)
    {
        // For the palette the fields alternate index and value, and only a value can be a change.
        let step = usize::from(*selector == 4) + 1;
        let values = parts
            .iter()
            .enumerate()
            .skip(1)
            .filter_map(|(index, part)| (step == 1 || index % 2 == 0).then_some(part.as_slice()));
        let asks = parts.iter().skip(1).any(|part| part.as_slice() == b"?");
        let changes = values.clone().any(|part| part != b"?" && !part.is_empty());
        return if asks && changes {
            StopsHere::Projection
        } else {
            StopsHere::No
        };
    }
    let EventKind::Csi {
        params,
        truncated,
        final_byte,
    } = kind
    else {
        return StopsHere::No;
    };
    let csi = CsiView::with_truncation(params, *final_byte, *truncated);
    match csi.final_byte {
        b't' if matches!(csi.first_or(0), 22 | 23) => StopsHere::Withhold,
        b'h' | b'l'
            if csi.private == Some(b'?')
                && csi.numbers.contains(&Some(i64::from(MODE_WIN32_INPUT))) =>
        {
            if csi.numbers.len() > 1 {
                StopsHere::Projection
            } else {
                StopsHere::Withhold
            }
        }
        _ => StopsHere::No,
    }
}

/// What direct mode may do with the original bytes of an event.
///
/// The byte policy has three reasons to withhold bytes from a physical terminal: the engine
/// answered or consumed the sequence, the profile handles the sequence itself, or the bytes are not
/// something a UTF-8 terminal would frame the way this engine framed them.
#[must_use]
pub fn disposition(
    kind: &EventKind,
    class: SequenceClass,
    needs_projection: bool,
) -> DirectDisposition {
    // What the profile handles itself is decided first, because a sequence can be answered here and
    // still have changed the canonical screen on the way.
    match stops_here(kind) {
        StopsHere::Withhold => return DirectDisposition::Withhold,
        StopsHere::Projection => return DirectDisposition::RequireProjection,
        StopsHere::No => {}
    }
    if !class.reaches_grid() {
        return DirectDisposition::Withhold;
    }
    if needs_projection || matches!(kind, EventKind::Replacement { .. }) {
        return DirectDisposition::RequireProjection;
    }
    DirectDisposition::Forward
}
