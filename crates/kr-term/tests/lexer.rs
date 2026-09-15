//! The single lexical pass: spans, ground boundaries, bounds and the byte policy.
//!
//! These are the properties a fixture diff cannot show, because they are about the lexer's
//! behaviour over time: what happens when a sequence is split across reads, what happens when a
//! control string never ends, and what happens at the end of the stream.

use kr_term::class::SequenceClass;
use kr_term::event::{
    DirectDisposition, DiscardCause, Event, EventKind, ReplacementCause, SequenceFamily,
};
use kr_term::lexer::{LexLimits, Lexer, undouble_escapes};

fn lex(input: &[u8]) -> Vec<Event> {
    let mut lexer = Lexer::new();
    let mut events = Vec::new();
    lexer.feed(input, &mut events);
    lexer.close(&mut events);
    events
}

/// Feeds `input` one byte at a time, which is the worst read boundary there is.
fn lex_byte_by_byte(input: &[u8]) -> Vec<Event> {
    let mut lexer = Lexer::new();
    let mut events = Vec::new();
    for byte in input {
        lexer.feed(&[*byte], &mut events);
    }
    lexer.close(&mut events);
    events
}

fn classes(events: &[Event]) -> String {
    events.iter().map(|event| event.class.letter()).collect()
}

fn spans_cover(input: &[u8], events: &[Event]) {
    let mut next = 0u64;
    for event in events {
        if event.passthrough_depth > 0 {
            // Passthrough events all carry the envelope's span; the envelope covers the bytes.
            continue;
        }
        assert_eq!(
            event.span.start(),
            next,
            "gap before {event:?} while lexing {input:?}"
        );
        assert_eq!(
            event.span.len() as usize,
            event.raw().len(),
            "span length does not match the retained bytes for {event:?}"
        );
        next = event.span.end();
    }
    assert_eq!(next, input.len() as u64, "spans do not cover the input");
}

#[test]
fn spans_cover_every_byte_exactly_once() {
    for input in [
        &b"hello world"[..],
        b"\x1b[1;31mred\x1b[0m",
        b"\x1b]0;title\x07text",
        b"\xc3\xa9\xe4\xb8\xad\xf0\x9f\x98\x80",
        b"\x1b[?1049h\x1b[2J\x1b[H",
        b"\x9b31m",
        b"a\xa9b",
    ] {
        spans_cover(input, &lex(input));
    }
}

/// A control sequence split across reads still produces one event carrying the whole span.
///
/// Text behaves differently on purpose: a run ends at the end of a read, because holding it back
/// would delay the person's output for no benefit. So the comparison is over the control sequences
/// and over the text content, not over the number of text events.
#[test]
fn a_sequence_split_across_reads_lexes_once() {
    let input = b"\x1b[38;5;208mX\x1b]8;;https://example.invalid/\x1b\\link\x1b]8;;\x1b\\";
    let whole = lex(input);
    let split = lex_byte_by_byte(input);

    let controls = |events: &[Event]| -> Vec<(Vec<u8>, EventKind)> {
        events
            .iter()
            .filter(|event| !matches!(event.kind, EventKind::Text { .. }))
            .map(|event| (event.raw().to_vec(), event.kind.clone()))
            .collect()
    };
    assert_eq!(controls(&whole), controls(&split));

    let text = |events: &[Event]| -> Vec<u8> {
        events
            .iter()
            .filter(|event| matches!(event.kind, EventKind::Text { .. }))
            .flat_map(|event| event.raw().to_vec())
            .collect()
    };
    assert_eq!(text(&whole), text(&split));
    spans_cover(input, &split);
}

#[test]
fn a_multi_byte_scalar_split_across_reads_is_one_text_event() {
    let mut lexer = Lexer::new();
    let mut events = Vec::new();
    lexer.feed(b"\xe4", &mut events);
    assert!(events.is_empty(), "an incomplete scalar produces no event");
    assert!(!lexer.at_ground(), "the parser is not on ground mid-scalar");
    lexer.feed(b"\xb8", &mut events);
    lexer.feed(b"\xad", &mut events);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].raw(), "\u{4e2d}".as_bytes());
    assert!(lexer.at_ground());
}

#[test]
fn ground_is_false_inside_an_incomplete_sequence() {
    let mut lexer = Lexer::new();
    let mut events = Vec::new();
    lexer.feed(b"text\x1b[1;", &mut events);
    assert!(!lexer.at_ground());
    assert_eq!(lexer.pending_len(), 4);
    lexer.feed(b"31m", &mut events);
    assert!(lexer.at_ground());
    assert_eq!(classes(&events), "DD");
}

#[test]
fn an_incomplete_scalar_at_closure_becomes_one_replacement() {
    let events = lex(b"ok\xe2\x82");
    assert_eq!(classes(&events), "DD");
    assert!(matches!(
        events[1].kind,
        EventKind::Replacement {
            cause: ReplacementCause::IncompleteAtClosure,
            count: 1
        }
    ));
    assert_eq!(events[1].disposition, DirectDisposition::RequireProjection);
}

#[test]
fn an_incomplete_control_string_at_closure_is_discarded() {
    let events = lex(b"\x1b]0;never ends");
    assert_eq!(classes(&events), "X");
    assert!(matches!(
        events[0].kind,
        EventKind::Discarded {
            family: SequenceFamily::Osc,
            cause: DiscardCause::IncompleteAtClosure,
            ..
        }
    ));
}

/// A scalar's continuation bytes are never reinterpreted as raw C1.
#[test]
fn a_continuation_byte_inside_a_scalar_is_not_a_control() {
    // U+00DC is 0xC3 0x9C. The second byte is the 8-bit string terminator.
    let events = lex("\u{00dc}ber".as_bytes());
    assert_eq!(classes(&events), "D");
    assert_eq!(events[0].raw(), "\u{00dc}ber".as_bytes());
    assert_eq!(events[0].disposition, DirectDisposition::Forward);
}

/// The same byte inside a title does not end the string either.
#[test]
fn raw_string_terminator_inside_a_title_is_payload() {
    let events = lex("\x1b]2;\u{00dc}ber\x1b\\".as_bytes());
    assert_eq!(classes(&events), "M");
    let EventKind::Osc { parts, .. } = &events[0].kind else {
        panic!("expected an OSC event");
    };
    assert_eq!(parts[1], "\u{00dc}ber".as_bytes());
}

/// A raw 8-bit introducer is classified like its 7-bit form but never forwarded.
#[test]
fn raw_c1_is_classified_but_never_forwarded() {
    let eight = lex(b"\x9b31m");
    let seven = lex(b"\x1b[31m");
    assert_eq!(classes(&eight), classes(&seven));
    assert_eq!(eight[0].disposition, DirectDisposition::RequireProjection);
    assert_eq!(seven[0].disposition, DirectDisposition::Forward);
    assert!(eight[0].eight_bit_introducer);
}

#[test]
fn an_encoded_c1_scalar_is_replaced_and_never_executed() {
    // 0xC2 0x9B is a well-formed scalar whose value is the C1 CSI introducer.
    let events = lex(b"\xc2\x9b31m");
    assert!(matches!(
        events[0].kind,
        EventKind::Replacement {
            cause: ReplacementCause::EncodedC1Scalar,
            ..
        }
    ));
    // What follows is ordinary text, not a control sequence.
    assert!(matches!(events[1].kind, EventKind::Text { .. }));
    assert_eq!(events[1].raw(), b"31m");
}

#[test]
fn malformed_utf8_becomes_one_replacement_per_subpart() {
    for (input, cause) in [
        (&b"\xc0\xaf"[..], ReplacementCause::Overlong),
        (b"\xe0\x80\xaf", ReplacementCause::Overlong),
        (b"\xed\xa0\x80", ReplacementCause::Surrogate),
        (b"\xf4\x90\x80\x80", ReplacementCause::OutOfRange),
        (b"\xf8", ReplacementCause::InvalidLead),
        (b"\xa9", ReplacementCause::IsolatedContinuation),
    ] {
        let events = lex(input);
        let EventKind::Replacement { cause: seen, .. } = events[0].kind else {
            panic!("expected a replacement for {input:?}, got {:?}", events[0]);
        };
        assert_eq!(seen, cause, "wrong cause for {input:?}");
        assert_eq!(events[0].disposition, DirectDisposition::RequireProjection);
    }
}

#[test]
fn an_oversized_control_string_is_discarded_whole() {
    let mut input = b"\x1b]0;".to_vec();
    input.extend(std::iter::repeat_n(b'a', 70_000));
    input.extend_from_slice(b"\x1b\\");
    let events = lex(&input);
    assert_eq!(classes(&events), "X");
    assert!(matches!(
        events[0].kind,
        EventKind::Discarded {
            cause: DiscardCause::Oversized,
            ..
        }
    ));
    assert_eq!(events[0].disposition, DirectDisposition::Withhold);
}

/// The suffix of an oversized payload never executes as a fresh control sequence.
#[test]
fn an_oversized_payload_suffix_does_not_execute() {
    let mut input = b"\x1b]0;".to_vec();
    input.extend(std::iter::repeat_n(b'a', 70_000));
    // An escape sequence buried in the oversized payload.
    input.extend_from_slice(b"\x1b[2J\x1b[31m");
    input.extend_from_slice(b"\x1b\\after");
    let events = lex(&input);
    assert_eq!(
        classes(&events),
        "XD",
        "only the discard and the trailing text should appear"
    );
    assert_eq!(events[1].raw(), b"after");
}

#[test]
fn osc52_has_its_own_larger_bound() {
    // 200 KiB is over the 64 KiB control-string bound but under the 1 MiB OSC 52 bound.
    let mut input = b"\x1b]52;c;".to_vec();
    input.extend(std::iter::repeat_n(b'A', 200_000));
    input.extend_from_slice(b"\x1b\\");
    let events = lex(&input);
    assert_eq!(classes(&events), "S", "a 200 KiB OSC 52 is still an OSC 52");

    let mut oversized = b"\x1b]52;c;".to_vec();
    oversized.extend(std::iter::repeat_n(b'A', 1_100_000));
    oversized.extend_from_slice(b"\x1b\\");
    let events = lex(&oversized);
    assert_eq!(classes(&events), "X", "past its own bound it is discarded");
}

#[test]
fn a_string_with_no_terminator_stops_at_the_resynchronisation_window() {
    let limits = LexLimits {
        max_control_string: 32,
        resync_window: 64,
        ..LexLimits::DEFAULT
    };
    let mut lexer = Lexer::with_limits(limits);
    let mut events = Vec::new();
    let payload: Vec<u8> = std::iter::repeat_n(b'x', 500).collect();
    lexer.feed(b"\x1b]0;", &mut events);
    lexer.feed(&payload, &mut events);
    assert_eq!(
        events[0].class,
        SequenceClass::Extension,
        "the string gave up inside the window"
    );
    assert!(matches!(
        events[0].kind,
        EventKind::Discarded {
            cause: DiscardCause::Oversized,
            ..
        }
    ));
    // Giving up resynchronises to ground, so what follows is ordinary output rather than more of a
    // string that was never going to end. The discarded payload is not re-injected.
    assert!(lexer.at_ground());
    assert!(
        events[1..]
            .iter()
            .all(|event| matches!(event.kind, EventKind::Text { .. }))
    );
}

#[test]
fn cancel_and_substitute_abort_a_string() {
    for terminator in [0x18u8, 0x1a] {
        let mut input = b"\x1b]0;partial".to_vec();
        input.push(terminator);
        input.extend_from_slice(b"text");
        let events = lex(&input);
        assert_eq!(classes(&events), "XD");
        assert_eq!(events[1].raw(), b"text");
    }
}

#[test]
fn tmux_passthrough_is_decoded_and_reclassified() {
    let events = lex(b"\x1bPtmux;\x1b\x1b[31mred\x1b\\");
    assert_eq!(classes(&events), "DD");
    for event in &events {
        assert_eq!(event.passthrough_depth, 1);
        assert_eq!(event.disposition, DirectDisposition::RequireProjection);
    }
    assert_eq!(events[1].raw(), b"red");
}

#[test]
fn a_query_inside_passthrough_is_still_answered_here() {
    let events = lex(b"\x1bPtmux;\x1b\x1b[c\x1b\\");
    assert_eq!(classes(&events), "Q");
    assert_eq!(events[0].passthrough_depth, 1);
    assert_eq!(events[0].disposition, DirectDisposition::Withhold);
}

#[test]
fn passthrough_stops_at_depth_four() {
    fn wrap(inner: &[u8]) -> Vec<u8> {
        let mut out = b"\x1bPtmux;".to_vec();
        for byte in inner {
            if *byte == 0x1b {
                out.push(0x1b);
            }
            out.push(*byte);
        }
        out.extend_from_slice(b"\x1b\\");
        out
    }
    let mut payload = b"\x1b[31m".to_vec();
    for depth in 1..=5u8 {
        payload = wrap(&payload);
        let events = lex(&payload);
        if depth <= 4 {
            assert_eq!(
                classes(&events),
                "D",
                "depth {depth} should still decode to the inner sequence"
            );
            assert_eq!(events[0].passthrough_depth, depth);
        } else {
            assert_eq!(classes(&events), "X", "depth {depth} is beyond the bound");
            assert!(matches!(
                events[0].kind,
                EventKind::Discarded {
                    cause: DiscardCause::PassthroughTooDeep,
                    ..
                }
            ));
        }
    }
}

#[test]
fn escape_doubling_round_trips() {
    assert_eq!(undouble_escapes(b"\x1b\x1b[31m"), b"\x1b[31m");
    assert_eq!(undouble_escapes(b"plain"), b"plain");
    assert_eq!(undouble_escapes(b"\x1b\x1b\x1b\x1b"), b"\x1b\x1b");
}

#[test]
fn an_ill_formed_control_sequence_dispatches_nothing() {
    // A parameter byte after an intermediate is ill-formed.
    let events = lex(b"\x1b[ 1m");
    assert_eq!(classes(&events), "X");
    assert!(matches!(events[0].kind, EventKind::CsiIgnored { .. }));
}

#[test]
fn an_escape_abandons_the_sequence_in_flight() {
    let events = lex(b"\x1b[1;2\x1b[31m");
    assert_eq!(classes(&events), "XD");
    assert_eq!(events[0].raw(), b"\x1b[1;2");
    assert_eq!(events[1].raw(), b"\x1b[31m");
}

#[test]
fn text_runs_are_bounded() {
    let limits = LexLimits {
        max_text_run: 16,
        ..LexLimits::DEFAULT
    };
    let mut lexer = Lexer::with_limits(limits);
    let mut events = Vec::new();
    let text: Vec<u8> = std::iter::repeat_n(b'x', 100).collect();
    lexer.feed(&text, &mut events);
    lexer.close(&mut events);
    assert!(events.len() > 1, "a long run splits into several events");
    for event in &events {
        assert_eq!(event.class, SequenceClass::Display);
    }
    let total: usize = events.iter().map(|event| event.raw().len()).sum();
    assert_eq!(total, 100);
}

#[test]
fn the_parameter_list_keeps_punctuation() {
    let events = lex(b"\x1b[38:2::12:34:56m");
    let EventKind::Csi { params, .. } = &events[0].kind else {
        panic!("expected a control sequence");
    };
    let punctuation = params.iter().filter(|p| p.punct().is_some()).count();
    assert_eq!(punctuation, 5, "the colon sublist survives lexing");
}

#[test]
fn ground_after_marks_a_safe_handoff_point() {
    let events = lex(b"a\x1b[31mb");
    assert!(events.iter().all(|event| event.ground_after));
    let mut lexer = Lexer::new();
    let mut partial = Vec::new();
    lexer.feed(b"a\x1b[3", &mut partial);
    assert!(partial.iter().all(|event| event.ground_after));
    assert!(
        !lexer.at_ground(),
        "the trailing partial sequence is pending"
    );
}
