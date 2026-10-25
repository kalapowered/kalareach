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
    // A control string runs from its introducer to its terminator and holds no control byte but the
    // terminator, so that a terminal ends it where this engine did.
    let mut at = 0;
    while at < forward.len() {
        let introduces = forward[at] == 0x1b
            && matches!(forward.get(at + 1), Some(b']' | b'P' | b'_' | b'^' | b'X'));
        if !introduces {
            at += 1;
            continue;
        }
        let osc = forward[at + 1] == b']';
        let mut end = at + 2;
        loop {
            match forward.get(end) {
                None => {
                    found.push(violation(
                        Invariant::ByteSafety,
                        format!("the control string at byte {at} is not ended"),
                    ));
                    break;
                }
                Some(0x07) if osc => {
                    end += 1;
                    break;
                }
                Some(0x1b) if forward.get(end + 1) == Some(&b'\\') => {
                    end += 2;
                    break;
                }
                Some(byte) if *byte < 0x20 => {
                    found.push(violation(
                        Invariant::ByteSafety,
                        format!("the control string at byte {at} holds the control byte {byte:#04x} at {end}"),
                    ));
                    break;
                }
                Some(_) => end += 1,
            }
        }
        at = end.max(at + 2);
    }
    found
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

/// Invariant 6: the events, a tmux envelope's inner events counted once, cover the stream without
/// overlap. An envelope that decodes to nothing makes no event.
pub fn events_cover_the_stream(bytes: &[u8], events: &[Event]) -> Vec<Violation> {
    let spans: BTreeSet<(u64, u64)> = events
        .iter()
        .map(|event| (event.span.start(), event.span.end()))
        .filter(|(start, end)| start != end)
        .collect();
    let mut next = 0u64;
    for (start, end) in spans {
        if start < next {
            return vec![violation(
                Invariant::Coverage,
                format!(
                    "an event at {start}..{end} overlaps the one before it, which ended at {next}"
                ),
            )];
        }
        if start > next {
            let gap = &bytes[index(next)..index(start)];
            let envelope = gap.starts_with(b"\x1bPtmux;") || gap.starts_with(b"\x90tmux;");
            if !envelope {
                return vec![violation(
                    Invariant::Coverage,
                    format!("bytes {next}..{start} are in no event"),
                )];
            }
        }
        next = end;
    }
    if (next as usize) < bytes.len() {
        let gap = &bytes[index(next)..];
        if !(gap.starts_with(b"\x1bPtmux;") || gap.starts_with(b"\x90tmux;")) {
            return vec![violation(
                Invariant::Coverage,
                format!("bytes {next}.. are in no event"),
            )];
        }
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
        found.extend(read_split_changes_nothing(&whole, &split, how));
    }
    (found, framed)
}
