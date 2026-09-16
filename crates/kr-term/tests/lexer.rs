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

/// The text of every text event, concatenated.
///
/// A text run ends at the end of a read and holds its last scalar back for a possible combining
/// mark, so the number of text events depends on where the reads fell. The content does not.
fn text(events: &[Event]) -> Vec<u8> {
    events
        .iter()
        .filter(|event| matches!(event.kind, EventKind::Text { .. }))
        .flat_map(|event| event.raw().to_vec())
        .collect()
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
    assert!(
        events.is_empty(),
        "the scalar is held back in case a combining mark follows"
    );
    assert!(lexer.at_ground(), "a held tail is still a ground boundary");
    lexer.flush_tail(&mut events);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].raw(), "\u{4e2d}".as_bytes());
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
    assert_eq!(text(&events), b"ok");
    let last = events.last().expect("an event");
    assert!(matches!(
        last.kind,
        EventKind::Replacement {
            cause: ReplacementCause::IncompleteAtClosure,
            count: 1
        }
    ));
    assert_eq!(last.disposition, DirectDisposition::RequireProjection);
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
    assert_eq!(text(&events), "\u{00dc}ber".as_bytes());
    assert!(
        events
            .iter()
            .all(|event| event.disposition == DirectDisposition::Forward)
    );
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
    assert_eq!(text(&events), b"31m");
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
    assert!(matches!(events[0].kind, EventKind::Discarded { .. }));
    assert!(
        events[1..]
            .iter()
            .all(|event| matches!(event.kind, EventKind::Text { .. })),
        "only the discard and the trailing text should appear"
    );
    assert_eq!(text(&events), b"after");
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
fn an_unterminated_oversized_string_never_executes_its_payload() {
    let limits = LexLimits {
        max_control_string: 32,
        ..LexLimits::DEFAULT
    };
    let mut lexer = Lexer::with_limits(limits);
    let mut events = Vec::new();
    lexer.feed(b"\x1b]0;", &mut events);
    // Past the bound the string is discarded in constant memory. A control sequence buried in the
    // payload is payload, not a sequence: an elapsed byte count does not make a safe boundary, so
    // the parser never invents one.
    let mut payload: Vec<u8> = std::iter::repeat_n(b'x', 200).collect();
    payload.extend_from_slice(b"\x1b[2J\x1b]52;c;c2VjcmV0");
    payload.extend(std::iter::repeat_n(b'x', 200));
    lexer.feed(&payload, &mut events);
    assert!(
        events.is_empty(),
        "the string has not ended, so nothing has been dispatched"
    );
    assert!(!lexer.at_ground());

    // It ends where the application says it ends, and the payload was payload throughout.
    lexer.feed(b"\x1b\\after", &mut events);
    lexer.close(&mut events);
    assert!(matches!(
        events[0].kind,
        EventKind::Discarded {
            cause: DiscardCause::Oversized,
            ..
        }
    ));
    assert_eq!(events[0].class, SequenceClass::Extension);
    assert_eq!(text(&events), b"after");
    assert!(
        events[1..]
            .iter()
            .all(|event| matches!(event.kind, EventKind::Text { .. })),
        "nothing from the discarded payload was executed"
    );
}

#[test]
fn cancel_and_substitute_abort_a_string() {
    for terminator in [0x18u8, 0x1a] {
        let mut input = b"\x1b]0;partial".to_vec();
        input.push(terminator);
        input.extend_from_slice(b"text");
        let events = lex(&input);
        assert!(matches!(events[0].kind, EventKind::Discarded { .. }));
        assert_eq!(text(&events), b"text");
    }
}

#[test]
fn tmux_passthrough_is_decoded_and_reclassified() {
    let events = lex(b"\x1bPtmux;\x1b\x1b[31mred\x1b\\");
    assert!(
        events
            .iter()
            .all(|event| event.class == SequenceClass::Display)
    );
    for event in &events {
        assert_eq!(event.passthrough_depth, 1);
        assert_eq!(event.disposition, DirectDisposition::RequireProjection);
    }
    assert_eq!(text(&events), b"red");
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

/// A printable run is cut at the same places whether it arrives whole or a piece at a time.
///
/// The run bound is what a text event may hold, and where a run passes it the run is emitted and
/// the next one starts. The lexer finds a printable run and appends it whole, so this pins the
/// lengths it produces: a bound of sixteen over forty bytes, spans that adjoin, and the last
/// scalar held back for a combining mark until the stream closes.
#[test]
fn a_printable_run_is_cut_at_its_bound_wherever_the_reads_fall() {
    let bounded = LexLimits {
        max_text_run: 16,
        ..LexLimits::DEFAULT
    };
    let run: Vec<u8> = std::iter::repeat_n(b'x', 40).collect();

    let whole = {
        let mut lexer = Lexer::with_limits(bounded);
        let mut events = Vec::new();
        lexer.feed(&run, &mut events);
        lexer.close(&mut events);
        events
    };
    let lengths: Vec<usize> = whole.iter().map(|event| event.raw().len()).collect();
    assert_eq!(lengths, vec![16, 16, 7, 1]);
    assert!(
        whole
            .iter()
            .all(|event| event.class == SequenceClass::Display)
    );
    assert_eq!(whole[0].span.start(), 0);
    for pair in whole.windows(2) {
        assert!(
            pair[0].span.adjoins(pair[1].span),
            "the runs have to cover the stream without a gap"
        );
    }

    // In pieces, with the pieces cutting across the bound in both directions.
    let mut lexer = Lexer::with_limits(bounded);
    let mut pieces = Vec::new();
    for chunk in [&run[..5], &run[5..20], &run[20..21], &run[21..]] {
        lexer.feed(chunk, &mut pieces);
    }
    lexer.close(&mut pieces);
    assert_eq!(
        pieces.iter().map(|event| event.raw().len()).sum::<usize>(),
        40
    );
    assert!(
        pieces
            .iter()
            .all(|event| event.raw().len() <= 16 && event.class == SequenceClass::Display)
    );
    assert_eq!(text(&pieces), run);
}

/// A printable run that ends at a control, and one that starts after it.
#[test]
fn a_printable_run_ends_where_the_printable_bytes_end() {
    let events = lex(b"abc\rdef\x1b[31mghi");
    assert_eq!(classes(&events), "DDDDDD");
    assert_eq!(events[0].raw(), b"abc");
    assert_eq!(events[1].raw(), b"\r");
    assert_eq!(events[2].raw(), b"def");
    assert_eq!(events[3].raw(), b"\x1b[31m");
    assert_eq!(events[4].raw(), b"gh");
    assert_eq!(events[5].raw(), b"i");
    assert_eq!(text(&events), b"abcdefghi");
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

// ------------------------------------------------- framing the review found wrong

/// `ESC ESC` is payload only inside a tmux envelope.
///
/// A general doubling rule would let a title hide a clipboard write: the engine would frame the
/// whole thing as one title and forward its bytes, and the terminal on the other side would end
/// the title at the escape and run the clipboard write.
#[test]
fn escape_doubling_outside_tmux_abandons_the_string() {
    let events = lex(b"\x1b]2;x\x1b\x1b]52;c;c2VjcmV0\x07");
    assert_eq!(
        classes(&events),
        "XS",
        "the title is abandoned, and the clipboard write is routed on its own"
    );
    assert!(
        events
            .iter()
            .all(|event| event.disposition != DirectDisposition::Forward),
        "nothing here reaches a terminal"
    );
}

/// A control-string payload a terminal would frame differently is never forwarded.
#[test]
fn a_payload_that_is_not_plain_text_requires_projection() {
    for input in [
        &b"\x1b]2;x\x9c\x9b6n\x07"[..],
        b"\x1b]2;x\x0cy\x07",
        b"\x1b]2;x\xff\x07",
    ] {
        let events = lex(input);
        assert_eq!(
            events[0].disposition,
            DirectDisposition::RequireProjection,
            "{input:?} must not travel to a terminal"
        );
    }
    // A payload that is plain text still travels.
    let events = lex("\x1b]2;\u{00dc}ber\x07".as_bytes());
    assert_eq!(events[0].disposition, DirectDisposition::Forward);
}

/// An incomplete prelude is bounded: past the retention bound the parser stops keeping bytes.
#[test]
fn an_incomplete_prelude_is_bounded() {
    let limits = LexLimits {
        max_sequence_bytes: 64,
        ..LexLimits::DEFAULT
    };
    let mut lexer = Lexer::with_limits(limits);
    let mut events = Vec::new();
    lexer.feed(b"\x1b[", &mut events);
    let digits: Vec<u8> = std::iter::repeat_n(b'1', 100_000).collect();
    lexer.feed(&digits, &mut events);
    assert!(events.is_empty(), "the sequence has not ended");
    assert_eq!(
        lexer.pending_len(),
        100_002,
        "the span still covers every byte"
    );
    lexer.feed(b"m", &mut events);
    assert_eq!(events.len(), 1);
    assert!(
        events[0].raw().len() <= 64,
        "retained {} bytes, which is past the bound",
        events[0].raw().len()
    );
    assert_eq!(events[0].span.len(), 100_003);
    assert_eq!(
        events[0].class,
        SequenceClass::Extension,
        "a sequence the parser could not keep whole is an extension"
    );
}

/// A control byte inside a prelude is consumed, and the sequence still completes.
#[test]
fn an_embedded_control_byte_does_not_abandon_a_sequence() {
    let events = lex(b"\x1b[5\x00;3H");
    assert_eq!(classes(&events), "D");
    let EventKind::Csi { params, .. } = &events[0].kind else {
        panic!("expected a control sequence");
    };
    let numbers: Vec<i64> = params.iter().filter_map(|p| p.integer()).collect();
    assert_eq!(numbers, vec![5, 3], "the parameters survived the NUL");
}

/// Escape intermediates do not leak from one sequence into the next.
#[test]
fn escape_intermediates_do_not_leak() {
    let events = lex(b"\x1b(B\x1b)0");
    assert_eq!(events.len(), 2);
    assert!(matches!(
        events[0].kind,
        EventKind::Esc {
            intermediate: Some(b'('),
            final_byte: b'B',
            ..
        }
    ));
    assert!(
        matches!(
            events[1].kind,
            EventKind::Esc {
                intermediate: Some(b')'),
                final_byte: b'0',
                ..
            }
        ),
        "the second designation is G1, not another G0: {:?}",
        events[1].kind
    );
}

/// A colon sublist is SGR and nowhere else, so it never turns one mode into another.
#[test]
fn a_colon_sublist_outside_sgr_is_an_extension() {
    // The leading value is mode 3, which the profile refuses. Reading the trailing value instead
    // would turn a refused mode into an approved one.
    let events = lex(b"\x1b[?3:7h");
    assert_eq!(classes(&events), "X");
    // SGR keeps its sublists.
    let events = lex(b"\x1b[4:3m");
    assert_eq!(classes(&events), "D");
}

/// Text lands in the same cells however the reads fall.
#[test]
fn clustering_does_not_depend_on_read_boundaries() {
    struct Case {
        cols: u32,
        rows: u32,
        setup: &'static [u8],
        text: &'static str,
        cells: u32,
    }

    fn screen(case: &Case, chunks: &[&[u8]], settle_between: bool) -> (u32, Vec<String>) {
        let mut engine = kr_term::engine::Engine::new(kr_term::engine::EngineConfig {
            size: kr_term::budget::GridSize::new(case.cols, case.rows),
            ..kr_term::engine::EngineConfig::DEFAULT
        })
        .expect("engine");
        if !case.setup.is_empty() {
            engine.feed(case.setup, 0);
            engine.quiesce(0);
        }
        for chunk in chunks {
            engine.feed(chunk, 0);
            if settle_between {
                engine.quiesce(0);
            }
        }
        engine.quiesce(0);
        let view = kr_term::snapshot::Viewport {
            top_row: 0,
            rows: case.rows,
            left_col: 0,
            cols: case.cols,
        };
        let (snapshot, _) = engine.snapshot(view, 0);
        let rows = snapshot
            .rows
            .iter()
            .map(|row| row.runs.iter().map(|run| run.text.as_str()).collect())
            .collect();
        (snapshot.cursor.col, rows)
    }

    // `cells` is where the cursor ends up, which is the number of cells the text took under the
    // pinned legacy codepoint-width model: every scalar with a width of its own gets a cell, and
    // only a zero-width scalar joins the cell before it.
    let cases = [
        Case {
            cols: 20,
            rows: 3,
            setup: b"",
            text: "e\u{0301}X",
            cells: 2,
        },
        Case {
            cols: 20,
            rows: 3,
            setup: b"",
            text: "a\u{0308}\u{0323}b",
            cells: 2,
        },
        // A woman, a joiner and a laptop: three scalars, two of which are wide, then ASCII.
        Case {
            cols: 20,
            rows: 3,
            setup: b"",
            text: "\u{1f469}\u{200d}\u{1f4bb}X",
            cells: 5,
        },
        // An emoji and a skin-tone modifier, which the library would fold into one cell.
        Case {
            cols: 20,
            rows: 3,
            setup: b"",
            text: "\u{1f44d}\u{1f3fb}X",
            cells: 5,
        },
        // Two Hangul initial jamo, which the library would fold into one syllable block.
        Case {
            cols: 20,
            rows: 3,
            setup: b"",
            text: "\u{1100}\u{1100}ZX",
            cells: 6,
        },
        // A regional-indicator pair, which the library would fold into one flag. The pinned table
        // gives each indicator one cell, so the pair is two cells rather than the flag's two.
        Case {
            cols: 20,
            rows: 3,
            setup: b"",
            text: "\u{1f1ff}\u{1f1e6}X",
            cells: 3,
        },
        // A keycap sequence: a digit, a variation selector and an enclosing mark.
        Case {
            cols: 20,
            rows: 3,
            setup: b"",
            text: "1\u{fe0f}\u{20e3}X",
            cells: 2,
        },
        // A mark that belongs to a cell the row wrapped after.
        Case {
            cols: 4,
            rows: 3,
            setup: b"",
            text: "abcde\u{0301}X",
            cells: 2,
        },
        // A mark arriving while insert mode is on, which must not shift the row.
        Case {
            cols: 10,
            rows: 3,
            setup: b"ABCDE\x1b[H\x1b[4h",
            text: "e\u{0301}X",
            cells: 2,
        },
        // A mark on a cell the row wrapped to, where the row above ends in the same character.
        Case {
            cols: 4,
            rows: 3,
            setup: b"",
            text: "abcdd\u{0301}",
            cells: 1,
        },
        // A designated character set, which changes what a cell holds but not which cell it is.
        Case {
            cols: 20,
            rows: 3,
            setup: b"\x1b(0",
            text: "q\u{0301}X",
            cells: 2,
        },
        // A zero-width space, which the library drops if it reaches it on its own.
        Case {
            cols: 20,
            rows: 3,
            setup: b"",
            text: "a\u{200b}X",
            cells: 2,
        },
        // A wrap inside a scroll region, where the cursor comes back to the column it left.
        Case {
            cols: 2,
            rows: 3,
            setup: b"\x1b[2;3r\x1b[3;1H",
            text: "abX\u{0301}",
            cells: 1,
        },
        // The same on the alternate buffer.
        Case {
            cols: 2,
            rows: 3,
            setup: b"\x1b[?1049h\x1b[3;1H",
            text: "abX\u{0301}",
            cells: 1,
        },
        // More marks than a cell can hold: the ones that fit are kept either way.
        Case {
            cols: 20,
            rows: 3,
            setup: b"\x1b(0",
            text: "q\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}X",
            cells: 2,
        },
    ];

    for case in &cases {
        let whole = case.text.as_bytes();
        let together = screen(case, &[whole], false);
        assert_eq!(
            together.0, case.cells,
            "{:?} does not take the cells the width model gives it",
            case.text
        );
        for split in 1..whole.len() {
            for settle in [false, true] {
                let apart = screen(case, &[&whole[..split], &whole[split..]], settle);
                assert_eq!(
                    together, apart,
                    "splitting {:?} at {split} (settling: {settle}) changed the screen",
                    case.text
                );
            }
        }
        // One byte at a time, with the screen settled after every one, is the hardest case: every
        // cell has already been drawn before the scalar that belongs to it arrives.
        let bytes: Vec<&[u8]> = (0..whole.len())
            .map(|index| &whole[index..=index])
            .collect();
        assert_eq!(
            together,
            screen(case, &bytes, true),
            "{:?} byte by byte",
            case.text
        );
    }
}

/// A prelude the parser could not keep whole never becomes a shorter sequence.
#[test]
fn a_truncated_prelude_is_an_extension_whatever_follows_it() {
    for tail in [
        b"]2;hello\x07".as_slice(),
        b"c".as_slice(),
        b"P0;1|x\x1b\\".as_slice(),
        b"[1;31m".as_slice(),
    ] {
        let mut input = vec![0x1b];
        input.extend(std::iter::repeat_n(0u8, 300));
        input.extend_from_slice(tail);
        let events = lex(&input);
        assert_eq!(classes(&events), "X", "{tail:?} survived a lost prelude");
        assert!(
            events
                .iter()
                .all(|event| event.disposition == DirectDisposition::Withhold),
            "{tail:?} reached a terminal"
        );
    }
}

/// A row keeps its cells while it is on screen, which is where the width model has to hold.
///
/// Once a row scrolls the library stores it in its compact form, which works out where the cells
/// are by clustering the row's text again and loses the columns the joined scalars held. That is
/// the narrow patch recorded in `kr_term::unicode::LIBRARY`; this pins what the profile does do,
/// so a change either way is visible.
#[test]
fn a_row_keeps_its_cells_while_it_is_on_screen() {
    for (text, cells) in [
        ("\u{1f469}\u{200d}\u{1f4bb}X", 5u32),
        ("\u{1100}\u{1100}ZX", 6),
        ("\u{1f44d}\u{1f3fb}X", 5),
    ] {
        let mut engine = kr_term::engine::Engine::new(kr_term::engine::EngineConfig {
            size: kr_term::budget::GridSize::new(20, 3),
            ..kr_term::engine::EngineConfig::DEFAULT
        })
        .expect("engine");
        engine.feed(text.as_bytes(), 0);
        engine.quiesce(0);
        let live: u32 = engine.grid().visible_rows()[0]
            .runs
            .iter()
            .map(|run| run.cells)
            .sum();
        assert_eq!(live, cells, "{text:?} on screen");

        // Writing more of the same row keeps the cells it already had.
        engine.feed(b"Y", 0);
        engine.quiesce(0);
        let extended: u32 = engine.grid().visible_rows()[0]
            .runs
            .iter()
            .map(|run| run.cells)
            .sum();
        assert_eq!(extended, cells + 1, "{text:?} after more of the row");
    }
}
