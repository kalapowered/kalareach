//! What the engine holds true of every stream, as checks over what a run shows.
//!
//! Each check takes the observed run as a value, so a test can hand it a forwarded set the engine
//! did not produce and see that the check names what is wrong with it.

use std::collections::BTreeSet;

use kr_term::budget::GridSize;
use kr_term::event::{DirectDisposition, Event, EventKind};
use kr_term::sideeffect::SideEffectKind;

use crate::generator::{Oversized, Stream, Tag, cuts};
use crate::observe::{self, QUEUE_BOUND, Seen, index};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invariant {
    /// The forwarded bytes lie in events the lexer lets a direct attachment have.
    Forwardable,
    /// The forwarded stream, read again, is forwarded whole and does nothing else.
    FixedPoint,
    /// The forwarded bytes are safe for a physical terminal, by a scan of their own.
    ByteSafety,
    /// A query, a side effect or a graphics string is never forwarded, and is dealt with.
    Tagged,
    /// Where a read is cut changes nothing the engine shows.
    ReadSplit,
    /// The events cover the stream once.
    Coverage,
    /// The engine ends on ground, the grid library wrote nothing and the lane holds its bound.
    Bounds,
    /// Nothing past the bound of a control string acts, and what is outside it does.
    Oversized,
}

#[derive(Clone, Debug)]
pub struct Violation {
    pub invariant: Invariant,
    pub detail: String,
}

fn violation(invariant: Invariant, detail: impl Into<String>) -> Violation {
    Violation {
        invariant,
        detail: detail.into(),
    }
}

/// Whether the lexer lets a direct attachment have the bytes of this event.
pub fn forwardable(event: &Event) -> bool {
    event.disposition == DirectDisposition::Forward
        && matches!(event.class.letter(), 'D' | 'M')
        && !matches!(
            event.kind,
            EventKind::Replacement { .. }
                | EventKind::Discarded { .. }
                | EventKind::CsiIgnored { .. }
        )
}

/// Invariant 1.
pub fn forwarded_lies_in_forwardable_events(
    bytes: &[u8],
    events: &[Event],
    seen: &Seen,
) -> Vec<Violation> {
    let mut allowed = vec![false; bytes.len()];
    for event in events
        .iter()
        .filter(|event| event.passthrough_depth == 0 && forwardable(event))
    {
        for slot in allowed
            .iter_mut()
            .take(index(event.span.end()))
            .skip(index(event.span.start()))
        {
            *slot = true;
        }
    }
    for &(start, end) in &seen.forwarded {
        if let Some(at) = (start..end).find(|at| !allowed.get(index(*at)).copied().unwrap_or(false))
        {
            return vec![violation(
                Invariant::Forwardable,
                format!("byte {at} is forwarded and lies in no forwardable event"),
            )];
        }
    }
    Vec::new()
}

/// Invariant 2.
pub fn forward_is_a_fixed_point(forward: &[u8], size: GridSize) -> Vec<Violation> {
    let mut found = Vec::new();
    if let Some(event) = observe::lex(forward)
        .iter()
        .find(|event| !forwardable(event))
    {
        found.push(violation(
            Invariant::FixedPoint,
            format!(
                "the forwarded stream lexes to {:?}, class {}, {:?}",
                event.kind,
                event.class.letter(),
                event.disposition
            ),
        ));
    }
    let again = observe::feed_whole(forward, size);
    if again.forward != forward {
        found.push(violation(
            Invariant::FixedPoint,
            "the forwarded stream is not forwarded whole by a new engine",
        ));
    }
    if again.unrecognised != 0 {
        found.push(violation(
            Invariant::FixedPoint,
            format!(
                "{} unrecognised in the forwarded stream",
                again.unrecognised
            ),
        ));
    }
    if !again.replies.is_empty() || !again.side_effects.is_empty() || again.refusals != 0 {
        found.push(violation(
            Invariant::FixedPoint,
            "the forwarded stream asks a question or acts",
        ));
    }
    found
}

/// Invariant 3, by a scan that reads neither the lexer nor the class table.
pub fn forward_is_safe_for_a_terminal(forward: &[u8]) -> Vec<Violation> {
    let mut found = Vec::new();
    match std::str::from_utf8(forward) {
        Err(error) => found.push(violation(
            Invariant::ByteSafety,
            format!("not valid UTF-8 at byte {}", error.valid_up_to()),
        )),
        Ok(text) => {
            if let Some((at, scalar)) = text
                .char_indices()
                .find(|(_, scalar)| ('\u{80}'..='\u{9f}').contains(scalar))
            {
                found.push(violation(
                    Invariant::ByteSafety,
                    format!("the C1 scalar U+{:04X} at byte {at}", u32::from(scalar)),
                ));
            }
        }
    }
    // What a terminal would answer, do or end differently, found by a scan that reads neither the
    // lexer nor the class table. A control string runs from its introducer to its terminator and
    // holds no control byte but the terminator, so that a terminal ends it where this engine did.
    // kr-vt/1 forwards no control string but an operating system command, and of those none that
    // acts (a clipboard, a notification, a progress report) or asks (a part that is a bare `?`).
    let mut at = 0;
    while at < forward.len() {
        let byte = forward[at];
        if byte != 0x1b {
            flag_a_control_that_acts(byte, at, &mut found);
            at += 1;
            continue;
        }
        let introducer = skip_controls(forward, at + 1, &mut found);
        match forward.get(introducer) {
            Some(b'Z') => {
                found.push(violation(
                    Invariant::ByteSafety,
                    format!("ESC Z, which asks the terminal to identify itself, at {at}"),
                ));
                at = introducer + 1;
            }
            Some(b'[') => at = scan_csi(forward, at, introducer + 1, &mut found),
            Some(b']' | b'P' | b'_' | b'^' | b'X') => {
                at = scan_string(forward, at, introducer, &mut found);
            }
            _ => at = introducer,
        }
    }
    found
}

/// Whether a terminal performs this byte where it stands inside a sequence, or discards it, and
/// goes on collecting the sequence around it. CAN and SUB end the sequence, and ESC begins another.
const fn is_carried_past(byte: u8) -> bool {
    matches!(byte, 0x00..=0x17 | 0x19 | 0x1c..=0x1f | 0x7f)
}

/// Names ENQ and BEL, which a terminal answers or sounds on its own wherever they stand.
fn flag_a_control_that_acts(byte: u8, at: usize, found: &mut Vec<Violation>) {
    if byte == 0x05 || byte == 0x07 {
        found.push(violation(
            Invariant::ByteSafety,
            format!("the control byte {byte:#04x} at {at} outside a string"),
        ));
    }
}

/// Returns where the sequence goes on from `at`, past the controls a terminal carries past.
fn skip_controls(forward: &[u8], mut at: usize, found: &mut Vec<Violation>) -> usize {
    while let Some(&byte) = forward.get(at).filter(|byte| is_carried_past(**byte)) {
        flag_a_control_that_acts(byte, at, found);
        at += 1;
    }
    at
}

/// Checks one control sequence for a question, and returns where it ends.
///
/// `at` is where its escape stands and `start` its first byte after the bracket. A terminal
/// carries on collecting the sequence around the controls it performs, and around NUL and DEL,
/// which it discards. Only CAN, SUB and ESC end it, and the scan goes on from them.
fn scan_csi(forward: &[u8], at: usize, start: usize, found: &mut Vec<Violation>) -> usize {
    let mut end = start;
    let mut parameters = Vec::new();
    let mut intermediates = Vec::new();
    let last = loop {
        match forward.get(end) {
            Some(&byte) if is_carried_past(byte) => flag_a_control_that_acts(byte, end, found),
            Some(byte @ 0x30..=0x3f) if intermediates.is_empty() => parameters.push(*byte),
            Some(byte @ 0x20..=0x2f) => intermediates.push(*byte),
            Some(byte @ 0x40..=0x7e) => break *byte,
            _ => return end,
        }
        end += 1;
    };
    let first_number = parameters
        .split(|byte| *byte == b';')
        .next()
        .and_then(|part| std::str::from_utf8(part).ok())
        .and_then(|part| {
            part.trim_start_matches(['?', '>', '=', '<'])
                .parse::<u32>()
                .ok()
        });
    let marker = parameters.first().copied();
    let intermediate = |wanted: u8| intermediates.contains(&wanted);
    let asks = match last {
        b'c' | b'n' | b'x' => true,
        b'p' | b'w' | b'u' if intermediate(b'$') => true,
        b'p' => false,
        b'q' => marker == Some(b'>'),
        b'u' | b'm' => marker == Some(b'?'),
        b'S' => marker == Some(b'?'),
        b't' => first_number.is_some_and(|number| (11..=21).contains(&number)),
        b'y' => intermediate(b'*'),
        b'|' => intermediate(b'#'),
        b'v' => intermediate(b'"'),
        _ => false,
    };
    if asks {
        found.push(violation(
            Invariant::ByteSafety,
            format!(
                "the control sequence ending {:?} at {at} asks the terminal a question",
                char::from(last)
            ),
        ));
    }
    end + 1
}

/// Checks one control string, and returns where it ends.
fn scan_string(forward: &[u8], at: usize, introducer: usize, found: &mut Vec<Violation>) -> usize {
    let family = forward[introducer];
    let osc = family == b']';
    if !osc {
        found.push(violation(
            Invariant::ByteSafety,
            format!(
                "the {} string at byte {at}, which kr-vt/1 forwards none of",
                char::from(family)
            ),
        ));
    }
    let mut end = introducer + 1;
    loop {
        match forward.get(end) {
            None => {
                found.push(violation(
                    Invariant::ByteSafety,
                    format!("the control string at byte {at} is not ended"),
                ));
                return end;
            }
            Some(0x07) if osc => break,
            Some(0x1b) if forward.get(end + 1) == Some(&b'\\') => break,
            Some(byte) if *byte < 0x20 => {
                found.push(violation(
                    Invariant::ByteSafety,
                    format!(
                        "the control string at byte {at} holds the control byte {byte:#04x} at {end}"
                    ),
                ));
                return end;
            }
            Some(_) => end += 1,
        }
    }
    if osc {
        let payload = &forward[introducer + 1..end];
        let parts: Vec<&[u8]> = payload.split(|byte| *byte == b';').collect();
        let selector = parts
            .first()
            .and_then(|part| std::str::from_utf8(part).ok())
            .and_then(|part| part.parse::<u32>().ok());
        // A bare `?` asks only where a terminal answers it: the palette and the colours, the
        // dynamic colour and the clipboard. Elsewhere it is text, as in a title.
        let asks = matches!(selector, Some(4 | 5 | 10..=19 | 50))
            && parts.iter().skip(1).any(|part| *part == b"?")
            || selector == Some(21) && parts.iter().any(|part| part.ends_with(b"=?"));
        if matches!(selector, Some(9 | 52 | 99 | 777)) || asks {
            found.push(violation(
                Invariant::ByteSafety,
                format!("the operating system command at byte {at} acts or asks"),
            ));
        }
    }
    if forward[end] == 0x07 {
        end + 1
    } else {
        end + 2
    }
}

/// How many tagged atoms the lexer framed as one event at ground, by what they were.
#[derive(Default, Debug, Clone, Copy)]
pub struct Framed {
    pub queries: usize,
    pub side_effects: usize,
    pub graphics: usize,
    /// Sequences the class table approves and the grid library does not implement, which the
    /// engine consumes. They break no invariant; the figure is how often a stream reaches one.
    pub unrecognised: u64,
}

impl Framed {
    pub fn add(&mut self, other: Self) {
        self.queries += other.queries;
        self.side_effects += other.side_effects;
        self.graphics += other.graphics;
        self.unrecognised += other.unrecognised;
    }
}

/// Invariant 4: an atom the generator knows to be a query, a side effect or a graphics string, and
/// which the lexer framed as one event, is never forwarded, and is dealt with where it stood.
pub fn tagged_atoms_are_withheld(
    stream: &Stream,
    events: &[Event],
    seen: &Seen,
) -> (Vec<Violation>, Framed) {
    let spans: BTreeSet<(u64, u64)> = events
        .iter()
        .filter(|event| event.passthrough_depth == 0)
        .map(|event| (event.span.start(), event.span.end()))
        .collect();
    let mut found = Vec::new();
    let mut framed = Framed::default();
    let mut unacted = 0;
    for mark in &stream.marks {
        let (start, end) = (mark.start as u64, mark.end as u64);
        if !spans.contains(&(start, end)) {
            continue;
        }
        if seen
            .forwarded
            .iter()
            .any(|&(from, to)| from < end && start < to)
        {
            found.push(violation(
                Invariant::Tagged,
                format!("{:?} at {start}..{end} is forwarded", mark.tag),
            ));
        }
        match mark.tag {
            Tag::Query => {
                framed.queries += 1;
                if !seen.degraded && !seen.replies.iter().any(|(at, _)| *at == start) {
                    found.push(violation(
                        Invariant::Tagged,
                        format!("the query at {start}..{end} is not answered"),
                    ));
                }
            }
            Tag::SideEffect => {
                framed.side_effects += 1;
                if !seen.side_effects.iter().any(|(_, at)| *at == start) {
                    unacted += 1;
                }
            }
            Tag::Graphics => framed.graphics += 1,
        }
    }
    // A side effect that policy refused leaves a refusal and no offset.
    if unacted > seen.refusals {
        found.push(violation(
            Invariant::Tagged,
            format!(
                "{unacted} side effects came to nothing and only {} were refused",
                seen.refusals
            ),
        ));
    }
    (found, framed)
}

fn merged(spans: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &(start, end) in spans {
        match out.last_mut() {
            Some(last) if last.1 == start => last.1 = end,
            _ => out.push((start, end)),
        }
    }
    out
}

/// Invariant 5: a run read in pieces shows what the same run read at once shows.
pub fn read_split_changes_nothing(whole: &Seen, split: &Seen, how: u64) -> Vec<Violation> {
    let mut found = Vec::new();
    let mut differ = |what: &str| {
        found.push(violation(
            Invariant::ReadSplit,
            format!("{what} differ with the read split (kind {how})"),
        ));
    };
    if merged(&whole.forwarded) != merged(&split.forwarded) {
        differ(&format!(
            "the forwarded bytes {:?} against {:?}",
            merged(&whole.forwarded),
            merged(&split.forwarded)
        ));
    }
    if whole.side_effects != split.side_effects {
        differ("the side effects");
    }
    if !whole.degraded && !split.degraded && whole.replies != split.replies {
        differ("the replies");
    }
    if whole.projection_at != split.projection_at {
        differ(&format!(
            "the first projection {:?} against {:?}",
            whole.projection_at, split.projection_at
        ));
    }
    if whole.snapshot != split.snapshot {
        let (a, b) = (&whole.snapshot, &split.snapshot);
        let mut fields = Vec::new();
        macro_rules! field {
            ($($name:ident),*) => {$(
                if a.$name != b.$name {
                    fields.push(stringify!($name));
                }
            )*};
        }
        field!(
            projection_generation,
            output_cursor,
            active_buffer,
            dimensions,
            viewport,
            cursor,
            saved_cursors,
            margins,
            rendition,
            tab_stops,
            charsets,
            modes,
            keypad_application,
            keyboard,
            title,
            title_stack,
            hyperlinks,
            hyperlink,
            palette,
            rows,
            inactive_rows,
            oldest_retained_row,
            evicted,
            inactive_oldest_retained_row,
            inactive_evicted
        );
        differ(&format!("the screen in {fields:?}"));
    }
    found
}

/// Invariants 5 and 7 of a run read in pieces: it shows what the same run read at once shows, and
/// the engine ends it on ground, with the grid library silent and the lane inside its bound, as
/// it ends the run read at once.
pub fn a_read_in_pieces_holds(whole: &Seen, split: &Seen, how: u64) -> Vec<Violation> {
    let mut found = read_split_changes_nothing(whole, split, how);
    found.extend(the_engine_is_in_its_bounds(split));
    found
}

/// The length of the empty tmux envelope at the start of `bytes`, if one is there: an envelope
/// whose payload, with its doubled escapes undone, is nothing or only empty envelopes within the
/// nesting bound, so that it makes no event.
fn empty_envelope(bytes: &[u8], depth: u8) -> Option<usize> {
    let opener = if bytes.starts_with(b"\x1bPtmux;") {
        7
    } else if bytes.starts_with(b"\x90tmux;") {
        6
    } else {
        return None;
    };
    if depth >= 4 {
        return None;
    }
    let mut payload = Vec::new();
    let mut at = opener;
    let end = loop {
        match (bytes.get(at), bytes.get(at + 1)) {
            (Some(0x1b), Some(0x1b)) => {
                payload.push(0x1b);
                at += 2;
            }
            (Some(0x1b), Some(b'\\')) => break at + 2,
            (Some(byte), _) => {
                payload.push(*byte);
                at += 1;
            }
            (None, _) => return None,
        }
    };
    let mut rest = payload.as_slice();
    while !rest.is_empty() {
        rest = &rest[empty_envelope(rest, depth + 1)?..];
    }
    Some(end)
}

/// Whether `gap` is empty envelopes and nothing else.
fn is_empty_envelopes(mut gap: &[u8]) -> bool {
    while !gap.is_empty() {
        match empty_envelope(gap, 0) {
            Some(length) => gap = &gap[length..],
            None => return false,
        }
    }
    true
}

/// Invariant 6: the events cover the stream once. An event of the outer stream is counted as it is,
/// so two events for the same bytes overlap; the inner events of a tmux envelope all carry the
/// envelope's span and are counted once for it. Bytes in no event are only those of an envelope that
/// decodes to nothing.
pub fn events_cover_the_stream(bytes: &[u8], events: &[Event]) -> Vec<Violation> {
    let mut spans: Vec<(u64, u64, u8)> = Vec::new();
    for event in events {
        let (start, end) = (event.span.start(), event.span.end());
        if start == end {
            continue;
        }
        if event.passthrough_depth > 0
            && spans
                .last()
                .is_some_and(|last| last.2 > 0 && (last.0, last.1) == (start, end))
        {
            continue;
        }
        spans.push((start, end, event.passthrough_depth));
    }
    let mut next = 0u64;
    for (start, end, _) in spans {
        if start < next {
            return vec![violation(
                Invariant::Coverage,
                format!(
                    "an event at {start}..{end} overlaps the one before it, which ended at {next}"
                ),
            )];
        }
        if start > next && !is_empty_envelopes(&bytes[index(next)..index(start)]) {
            return vec![violation(
                Invariant::Coverage,
                format!("bytes {next}..{start} are in no event"),
            )];
        }
        next = end;
    }
    if index(next) < bytes.len() && !is_empty_envelopes(&bytes[index(next)..]) {
        return vec![violation(
            Invariant::Coverage,
            format!("bytes {next}.. are in no event"),
        )];
    }
    Vec::new()
}

/// Invariant 7.
pub fn the_engine_is_in_its_bounds(seen: &Seen) -> Vec<Violation> {
    let mut found = Vec::new();
    if !seen.ground {
        found.push(violation(Invariant::Bounds, "not on ground after close"));
    }
    if seen.grid_writes != 0 {
        found.push(violation(
            Invariant::Bounds,
            format!("the grid library wrote {} bytes", seen.grid_writes),
        ));
    }
    if seen.queue_peak > QUEUE_BOUND {
        found.push(violation(
            Invariant::Bounds,
            format!("the lane held {} bytes", seen.queue_peak),
        ));
    }
    found
}

/// Invariant 7, for a flood: it is reported, no query is forwarded, and its text is.
pub fn a_flood_is_bounded_and_forwards_only_its_text(text: &[u8], seen: &Seen) -> Vec<Violation> {
    let mut found = the_engine_is_in_its_bounds(seen);
    if !seen.degraded {
        found.push(violation(Invariant::Bounds, "the flood is not reported"));
    }
    if seen.forward != text {
        found.push(violation(
            Invariant::Bounds,
            format!(
                "{} bytes forwarded, and the flood's text is {}",
                seen.forward.len(),
                text.len()
            ),
        ));
    }
    found
}

/// Invariant 8: exactly the queries outside the string are answered, and a clipboard write happens
/// only for a string that is whole and inside its bound.
pub fn nothing_past_the_bound_acts(case: &Oversized, seen: &Seen) -> Vec<Violation> {
    let mut found = Vec::new();
    for offset in &case.inside {
        if seen.replies.iter().any(|(at, _)| at == offset) {
            found.push(violation(
                Invariant::Oversized,
                format!("the query at {offset}, inside the string, is answered"),
            ));
        }
    }
    if !seen.degraded {
        let mut answered: Vec<u64> = seen.replies.iter().map(|(at, _)| *at).collect();
        answered.sort_unstable();
        if answered != case.answered {
            found.push(violation(
                Invariant::Oversized,
                format!(
                    "{answered:?} are answered, and {:?} are outside the string",
                    case.answered
                ),
            ));
        }
    }
    let writes: Vec<u64> = seen
        .side_effects
        .iter()
        .filter(|(kind, _)| matches!(kind, SideEffectKind::ClipboardWrite { .. }))
        .map(|(_, at)| *at)
        .collect();
    let expected: Vec<u64> = if case.writes {
        vec![case.string_at]
    } else {
        Vec::new()
    };
    if writes != expected {
        found.push(violation(
            Invariant::Oversized,
            format!("clipboard writes at {writes:?}, expected {expected:?}"),
        ));
    }
    if !case.writes && !seen.side_effects.is_empty() {
        found.push(violation(
            Invariant::Oversized,
            format!(
                "{} side effects from a stream that has none",
                seen.side_effects.len()
            ),
        ));
    }
    found
}

/// Every check that holds of the forwarded set, on a run.
pub fn forwarded_set_is_safe(
    stream: &Stream,
    events: &[Event],
    seen: &Seen,
    size: GridSize,
) -> (Vec<Violation>, Framed) {
    let mut found = forwarded_lies_in_forwardable_events(&stream.bytes, events, seen);
    found.extend(forward_is_a_fixed_point(&seen.forward, size));
    found.extend(forward_is_safe_for_a_terminal(&seen.forward));
    let (tagged, framed) = tagged_atoms_are_withheld(stream, events, seen);
    found.extend(tagged);
    (found, framed)
}

/// How many times the read of a stream is cut to cut it: the whole stream, a byte at a time, and
/// two random widths. A stream over this many bytes skips the byte at a time.
pub const BYTE_AT_A_TIME_LIMIT: usize = 128 * 1024;

/// Every check on a stream and a grid, with the stream read at once and in each split.
pub fn check_stream(stream: &Stream, size: GridSize) -> (Vec<Violation>, Framed) {
    let bytes = &stream.bytes;
    let events = observe::lex(bytes);
    let whole = observe::feed_whole(bytes, size);
    let (mut found, mut framed) = forwarded_set_is_safe(stream, &events, &whole, size);
    framed.unrecognised = whole.unrecognised;
    found.extend(events_cover_the_stream(bytes, &events));
    found.extend(the_engine_is_in_its_bounds(&whole));
    for how in 1..crate::generator::SPLITS {
        if how == 1 && bytes.len() > BYTE_AT_A_TIME_LIMIT {
            continue;
        }
        let split = observe::feed_in(bytes, &cuts(stream.seed, bytes.len(), how), size);
        found.extend(a_read_in_pieces_holds(&whole, &split, how));
    }
    (found, framed)
}
