//! Snapshots, geometry, budgets, probes and the pinned terminfo database.
//!
//! The recurring theme is that reconnection must put a screen back without making anything happen
//! a second time, and that every bound is checked before the allocation rather than after it.

use kr_term::budget::{BudgetLimits, GridSize, MAX_CELLS, MAX_COLS, MAX_ROWS, SessionBudget};
use kr_term::engine::{Engine, EngineConfig};
use kr_term::error::{ProbeFailure, TermError};
use kr_term::grid::CanonicalGrid;
use kr_term::palette::{PaletteSource, Rgb};
use kr_term::probe::{
    InputContext, NoProbeProfile, PROBE_SET, ProbeItem, ProbeProgress, ProbeSession,
};
use kr_term::snapshot::{
    ActiveBuffer, Delta, HANDOFF_WINDOW_MS, HandoffOutcome, LiveForwardingHandoff, RestoreOp,
    Viewport, restoration_operations,
};
use kr_term::terminfo::{self, Direction};

fn viewport(engine: &Engine) -> Viewport {
    Viewport {
        top_row: 0,
        rows: engine.grid().size().rows,
        left_col: 0,
        cols: engine.grid().size().cols,
    }
}

fn engine() -> Engine {
    Engine::new(EngineConfig::default()).expect("engine")
}

// ---------------------------------------------------------------------- geometry

#[test]
fn all_three_geometry_constraints_apply_at_once() {
    assert!(GridSize::new(MAX_COLS, 1).validate().is_ok());
    assert!(GridSize::new(1, MAX_ROWS).validate().is_ok());
    // The independent maxima are not valid together.
    let error = GridSize::new(MAX_COLS, MAX_ROWS)
        .validate()
        .expect_err("2048 by 1024 is 2,097,152 cells");
    let TermError::Geometry { violated, .. } = error else {
        panic!("expected a geometry error");
    };
    assert_eq!(violated, "cells");

    for (cols, rows, expected) in [
        (0, 24, "columns"),
        (MAX_COLS + 1, 24, "columns"),
        (80, 0, "rows"),
        (80, MAX_ROWS + 1, "rows"),
        (2_000, 200, "cells"),
    ] {
        let error = GridSize::new(cols, rows)
            .validate()
            .expect_err("should be refused");
        let TermError::Geometry { violated, .. } = error else {
            panic!("expected a geometry error");
        };
        assert_eq!(violated, expected, "{cols}x{rows}");
    }
    assert_eq!(GridSize::new(MAX_COLS, 128).cells(), Some(MAX_CELLS));
}

#[test]
fn an_invalid_resize_leaves_the_grid_alone() {
    let mut engine = engine();
    let before = engine.grid().size();
    let error = engine
        .resize(GridSize::new(4_000, 4_000))
        .expect_err("refused");
    assert!(matches!(error, TermError::Geometry { .. }));
    assert_eq!(engine.grid().size(), before);
    engine.resize(GridSize::new(100, 30)).expect("accepted");
    assert_eq!(engine.grid().size(), GridSize::new(100, 30));
}

#[test]
fn the_budget_refuses_before_it_allocates() {
    let limits = BudgetLimits {
        session_bytes: 4 * 1024,
        ..BudgetLimits::DEFAULT
    };
    let mut budget = SessionBudget::with_limits(limits);
    let error = CanonicalGrid::new(
        GridSize::new(200, 50),
        kr_term::grid::GridConfig::DEFAULT,
        &mut budget,
    )
    .expect_err("the screens do not fit");
    assert!(matches!(error, TermError::Budget { .. }));
    assert_eq!(
        budget.usage().total(),
        0,
        "nothing was committed for a refused allocation"
    );
}

#[test]
fn the_row_cache_is_capped_independently_of_the_session_budget() {
    let mut budget = SessionBudget::new();
    let evicted = budget.set_row_cache(BudgetLimits::DEFAULT.row_cache_bytes * 2);
    assert!(evicted, "rows beyond the cache come from the spool");
    assert_eq!(budget.usage().rows, BudgetLimits::DEFAULT.row_cache_bytes);
}

// --------------------------------------------------------------------- snapshots

#[test]
fn a_snapshot_carries_the_state_a_reconnection_needs() {
    let mut engine = engine();
    engine.feed(
        b"\x1b]2;session\x07\x1b[?1049h\x1b[?2004h\x1b[3;12r\x1b=hello",
        0,
    );
    let view = viewport(&engine);
    let snapshot = engine.snapshot(view, 0);
    assert_eq!(snapshot.active_buffer, ActiveBuffer::Alternate);
    assert_eq!(snapshot.title.window, "session");
    assert!(snapshot.keypad_application);
    assert!(
        snapshot
            .modes
            .iter()
            .any(|entry| entry.mode == 2004 && entry.enabled)
    );
    assert_eq!(snapshot.margins.top, 2);
    assert_eq!(snapshot.margins.bottom, 11);
    assert!(!snapshot.tab_stops.is_empty());
    assert_eq!(snapshot.output_cursor, engine.output_cursor());
    assert_eq!(
        snapshot.projection_generation,
        engine.projection_generation()
    );
}

/// Restoration emits rendering operations and nothing that can happen twice.
#[test]
fn restoration_never_replays_a_side_effect() {
    let mut engine = engine();
    // A history full of things that were events when they happened.
    engine.feed(
        b"\x07\x1b]52;c;c2VjcmV0\x1b\\\x1b]9;done\x1b\\\x1b[c\x1b]8;;https://example.invalid/\x1b\\link\x1b]8;;\x1b\\",
        0,
    );
    let view = viewport(&engine);
    let snapshot = engine.snapshot(view, 0);
    let operations = restoration_operations(&snapshot);
    assert!(!operations.is_empty());
    for operation in &operations {
        match operation {
            RestoreOp::ResetProjection { .. }
            | RestoreOp::SetDimensions { .. }
            | RestoreOp::SelectBuffer { .. }
            | RestoreOp::SetPalette { .. }
            | RestoreOp::SetMode { .. }
            | RestoreOp::SetKeypad { .. }
            | RestoreOp::SetKeyboard { .. }
            | RestoreOp::SetTabStops { .. }
            | RestoreOp::SetCharsets { .. }
            | RestoreOp::SetMargins { .. }
            | RestoreOp::PaintRow { .. }
            | RestoreOp::RecordHyperlink { .. }
            | RestoreOp::SetRendition { .. }
            | RestoreOp::SetCursor { .. }
            | RestoreOp::SetSavedCursor { .. }
            | RestoreOp::SetTitle { .. } => {}
        }
    }
    // The hyperlink survives as inert metadata.
    assert!(
        operations
            .iter()
            .any(|op| matches!(op, RestoreOp::RecordHyperlink { .. })),
        "a hyperlink range must survive reconnection"
    );
    // The projection reset comes first and the cursor last.
    assert!(matches!(
        operations.first(),
        Some(RestoreOp::ResetProjection { .. })
    ));
    assert!(matches!(
        operations.last(),
        Some(RestoreOp::SetCursor { .. })
    ));
}

#[test]
fn a_buffer_switch_advances_the_projection_generation() {
    let mut engine = engine();
    let before = engine.projection_generation();
    let outcome = engine.feed(b"\x1b[?1049h", 0);
    assert!(outcome.projection_reset);
    assert!(engine.projection_generation() > before);
}

/// A delta carries what changed since the base the client holds, and refuses a base it has lost.
#[test]
fn a_delta_names_its_base_and_carries_only_what_changed() {
    let mut engine = engine();
    engine.feed(b"first line\r\n", 0);
    let base = engine.output_cursor();

    // Nothing has changed since the base, so the delta is empty but valid.
    let delta: Delta = engine.delta(base).expect("the base is inside the window");
    assert_eq!(delta.base_cursor, base);
    assert!(delta.rows.is_empty());

    // One more line changes one row, and a mode change travels with it.
    engine.feed(b"\x1b[?25lsecond", 0);
    let delta = engine.delta(base).expect("still inside the window");
    assert!(!delta.rows.is_empty(), "the changed row is carried");
    assert!(
        delta
            .modes
            .iter()
            .any(|entry| entry.mode == 25 && !entry.enabled),
        "the mode change travels with it"
    );
    assert_eq!(delta.next_cursor, engine.output_cursor());

    // A base the engine no longer holds is refused.
    let error = engine.delta(base + 1).expect_err("gap");
    assert!(matches!(error, TermError::CursorGap { .. }));

    // So is a base from before a projection reset.
    engine.feed(b"\x1b[?1049h", 0);
    let error = engine.delta(base).expect_err("the projection was reset");
    assert!(matches!(error, TermError::CursorGap { .. }));
}

#[test]
fn a_history_page_stays_inside_both_of_its_bounds() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(40, 6),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let mut input = Vec::new();
    for index in 0..3_000 {
        input.extend_from_slice(format!("row {index} with some content\r\n").as_bytes());
    }
    engine.feed(&input, 0);
    let page = engine.history_page(0);
    let limits = engine.budget().limits();
    assert!(page.rows.len() <= limits.history_page_rows);
    let bytes: usize = page
        .rows
        .iter()
        .flat_map(|row| row.runs.iter().map(|run| run.text.len()))
        .sum();
    assert!(bytes <= limits.history_page_bytes);
    assert!(page.more, "a large history reports that more follows");
    assert!(
        page.oldest_retained_row >= 0,
        "the page states its oldest retained row"
    );
}

/// The 250 ms rule: forwarding starts at a parser-ground boundary or not at all.
#[test]
fn live_forwarding_waits_for_a_ground_boundary() {
    let handoff = LiveForwardingHandoff::start(1_000);
    assert_eq!(handoff.poll(1_000, None), HandoffOutcome::Waiting);
    assert_eq!(
        handoff.poll(1_100, Some(42)),
        HandoffOutcome::Ready { cursor: 42 }
    );
    assert_eq!(
        handoff.poll(1_000 + HANDOFF_WINDOW_MS, None),
        HandoffOutcome::StayProjected,
        "without a boundary the attachment stays projected"
    );
}

#[test]
fn the_engine_reports_a_boundary_only_when_it_has_one() {
    let mut engine = engine();
    engine.feed(b"text", 0);
    assert_eq!(engine.ground_boundary(), Some(engine.output_cursor()));
    engine.feed(b"\x1b[1;", 0);
    assert_eq!(
        engine.ground_boundary(),
        None,
        "never start forwarding inside a sequence"
    );
    engine.feed(b"31m", 0);
    assert_eq!(engine.ground_boundary(), Some(engine.output_cursor()));
}

// ------------------------------------------------------------------------ probes

#[test]
fn the_probe_set_ends_with_device_attributes() {
    assert_eq!(PROBE_SET.last(), Some(&ProbeItem::DeviceAttributes));
    assert!(
        PROBE_SET
            .iter()
            .filter(|item| **item == ProbeItem::DeviceAttributes)
            .count()
            == 1
    );
}

#[test]
fn a_probe_completes_on_its_terminator() {
    let (mut session, request) = ProbeSession::start(0, InputContext::Clean).expect("clean stream");
    assert!(request.ends_with(b"\x1b[c"), "the terminator is asked last");
    assert_eq!(
        session
            .observe(b"\x1bP>|iTerm2 3.5\x1b\\", 10)
            .expect("answer"),
        ProbeProgress::Collecting
    );
    assert_eq!(
        session
            .observe(b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\", 20)
            .expect("answer"),
        ProbeProgress::Collecting
    );
    assert_eq!(
        session
            .observe(b"\x1b]11;rgb:0000/0000/0000\x1b\\", 30)
            .expect("answer"),
        ProbeProgress::Collecting
    );
    assert_eq!(
        session
            .observe(b"\x1b[?62;1;6;22c", 40)
            .expect("terminator"),
        ProbeProgress::Complete
    );
    let outcome = session.finish(50).expect("complete");
    let palette = outcome.adopt_palette().expect("colours were shared");
    assert_eq!(palette.source(), PaletteSource::ClientPreference);
    assert_eq!(
        palette.dynamic(kr_term::palette::DynamicColour::Foreground),
        Rgb::new(0xff, 0xff, 0xff)
    );
}

#[test]
fn a_probe_without_its_terminator_fails_the_attach() {
    let (mut session, _) = ProbeSession::start(0, InputContext::Clean).expect("clean stream");
    session
        .observe(b"\x1b]11;rgb:0000/0000/0000\x1b\\", 10)
        .expect("answer");
    let error = session.finish(500).expect_err("no terminator");
    assert!(matches!(
        error,
        TermError::ProbeFailed {
            reason: ProbeFailure::NoTerminator
        }
    ));
}

#[test]
fn a_probe_that_runs_out_of_time_fails_rather_than_forwarding() {
    let (mut session, _) = ProbeSession::start(0, InputContext::Clean).expect("clean stream");
    let error = session
        .observe(b"\x1b[?62;1;22c", 1_001)
        .expect_err("deadline");
    assert!(matches!(
        error,
        TermError::ProbeFailed {
            reason: ProbeFailure::DeadlinePassed
        }
    ));
    assert!(!session.is_complete());
}

#[test]
fn a_contaminated_stream_cannot_be_probed_again() {
    let error = ProbeSession::start(0, InputContext::Contaminated).expect_err("refused");
    assert!(matches!(
        error,
        TermError::ProbeFailed {
            reason: ProbeFailure::ContaminatedInput
        }
    ));
}

#[test]
fn a_no_probe_attach_asks_the_terminal_nothing() {
    let conservative = NoProbeProfile::ConservativeProjected {
        palette: PaletteSource::DarkPreset,
    };
    assert_eq!(conservative.palette().source(), PaletteSource::DarkPreset);
    let saved = NoProbeProfile::Saved {
        id: "ghostty-1.0-qualified".to_owned(),
        palette: PaletteSource::LightPreset,
    };
    assert_eq!(saved.palette().source(), PaletteSource::LightPreset);
    // The light preset really is a light palette.
    assert_eq!(
        saved
            .palette()
            .dynamic(kr_term::palette::DynamicColour::Background),
        Rgb::new(0xff, 0xff, 0xff)
    );
}

#[test]
fn the_palette_source_is_recorded_and_survives_a_snapshot() {
    let mut engine = Engine::new(EngineConfig {
        palette_source: PaletteSource::LightPreset,
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let view = viewport(&engine);
    let snapshot = engine.snapshot(view, 0);
    assert_eq!(snapshot.palette.source, PaletteSource::LightPreset);
    engine.adopt_palette(kr_term::palette::Palette::from_client_preference(
        Rgb::new(1, 2, 3),
        Rgb::new(4, 5, 6),
    ));
    let view = viewport(&engine);
    let snapshot = engine.snapshot(view, 0);
    assert_eq!(snapshot.palette.source, PaletteSource::ClientPreference);
    assert_eq!(snapshot.palette.foreground, Rgb::new(1, 2, 3));
}

// ---------------------------------------------------------------------- terminfo

/// Every capability the pinned database advertises has a supported class.
#[test]
fn every_advertised_capability_has_a_class() {
    let coverage = terminfo::coverage();
    assert!(!coverage.is_empty());
    let output = coverage
        .iter()
        .filter(|entry| entry.direction == Direction::Output)
        .count();
    assert!(output > 50, "the database advertises real output sequences");
    for entry in &coverage {
        assert!(
            entry.supported,
            "capability {} produced classes {:?}",
            entry.name, entry.classes
        );
    }
}

/// The database matches the responder: `u8` states the reply `u9` actually produces.
#[test]
fn the_database_agrees_with_the_responder() {
    let mut engine = engine();
    engine.feed(b"\x1b[c", 0);
    let replies = engine
        .lane_mut()
        .drain(kr_term::lane::LaneGate::default(), 4096, 0);
    let expected = terminfo::strings()
        .iter()
        .find(|cap| cap.name == "u8")
        .expect("u8 is advertised");
    assert_eq!(replies[0].bytes(), expected.value.as_bytes());

    let u9 = terminfo::strings()
        .iter()
        .find(|cap| cap.name == "u9")
        .expect("u9 is advertised");
    assert_eq!(u9.value.as_bytes(), b"\x1b[c");
}

/// The database does not advertise a feature the profile refuses.
#[test]
fn the_database_advertises_nothing_the_profile_refuses() {
    for cap in terminfo::strings() {
        assert!(
            !cap.value.contains("\x1b[?3l") && !cap.value.contains("\x1b[?3h"),
            "{} touches DECCOLM, which belongs to the geometry owner",
            cap.name
        );
    }
    assert!(
        !terminfo::booleans().contains(&"mc5i"),
        "kr-vt/1 has no printer"
    );
    assert!(terminfo::lookup("mc5").is_none());
    assert!(terminfo::lookup("Tc").is_some(), "truecolour is advertised");
    assert!(terminfo::lookup("Ms").is_some(), "OSC 52 is advertised");
}

#[test]
fn hex_round_trips_through_the_capability_encoding() {
    for text in [&b"TN"[..], b"colors", b"", b"Smulx"] {
        let encoded = terminfo::to_hex(text);
        assert_eq!(
            terminfo::from_hex(encoded.as_bytes()).as_deref(),
            Some(text)
        );
    }
    assert_eq!(terminfo::from_hex(b"abc"), None, "odd length is not hex");
    assert_eq!(terminfo::from_hex(b"zz"), None, "non-hex is not hex");
}

/// A snapshot carries the keyboard negotiation an input encoder has to reproduce.
#[test]
fn a_snapshot_carries_the_keyboard_protocol() {
    let mut engine = engine();
    engine.feed(b"\x1b[>4;2m\x1b[>1u\x1b[>3u", 0);
    let view = viewport(&engine);
    let snapshot = engine.snapshot(view, 0);
    assert_eq!(snapshot.keyboard.modify_other_keys, 2);
    assert_eq!(snapshot.keyboard.kitty_flags, Some(3));
    assert_eq!(
        snapshot.keyboard.kitty_stack.len(),
        2,
        "the flag stack survives with it"
    );
    assert!(
        restoration_operations(&snapshot)
            .iter()
            .any(|op| matches!(op, RestoreOp::SetKeyboard { .. }))
    );
}

/// A snapshot carries the current rendition rather than a default.
#[test]
fn a_snapshot_carries_the_current_rendition() {
    let mut engine = engine();
    engine.feed(b"\x1b[1;4;31mtext", 0);
    let view = viewport(&engine);
    let snapshot = engine.snapshot(view, 0);
    assert!(snapshot.rendition.bold);
    assert_eq!(
        snapshot.rendition.underline,
        kr_term::grid::UnderlineStyle::Single
    );
    assert_eq!(
        snapshot.rendition.foreground,
        kr_term::grid::Colour::Indexed(1)
    );
}

/// A snapshot carries every dynamic colour, not only the foreground and background.
#[test]
fn a_snapshot_carries_the_whole_palette() {
    let mut engine = engine();
    engine.feed(b"\x1b]12;#010203\x1b\\\x1b]17;#040506\x1b\\", 0);
    let view = viewport(&engine);
    let snapshot = engine.snapshot(view, 0);
    assert_eq!(snapshot.palette.cursor, Rgb::new(1, 2, 3));
    assert_eq!(snapshot.palette.selection_background, Rgb::new(4, 5, 6));
}

/// A probe that never answers a required question fails the attach.
#[test]
fn a_probe_without_its_required_answer_fails() {
    // Device attributes is the only required answer, and it is also the terminator, so a probe
    // that finishes without it has already failed on the terminator.
    let required: Vec<ProbeItem> = PROBE_SET
        .iter()
        .copied()
        .filter(|item| item.requirement() == kr_term::probe::ProbeRequirement::Required)
        .collect();
    assert_eq!(required, vec![ProbeItem::DeviceAttributes]);

    // A terminal that answers nothing else still completes, because the terminator proves the
    // silence was an answer.
    let (mut session, _) = ProbeSession::start(0, InputContext::Clean).expect("clean stream");
    session.observe(b"\x1b[?62;22c", 10).expect("terminator");
    let outcome = session.finish(20).expect("complete");
    assert!(
        outcome.unanswered().contains(&ProbeItem::Version),
        "the unanswered questions are named, so the profile does not claim them"
    );
    assert!(outcome.adopt_palette().is_none());
}

/// The synchronised-output probe reads a real DECRPM reply.
#[test]
fn the_probe_reads_a_mode_report_in_its_real_form() {
    let (mut session, _) = ProbeSession::start(0, InputContext::Clean).expect("clean stream");
    session
        .observe(b"\x1b[?2026;2$y\x1b[?62;22c", 10)
        .expect("answers");
    let outcome = session.finish(20).expect("complete");
    assert_eq!(
        outcome.answer(ProbeItem::SynchronisedOutput),
        Some(&kr_term::probe::ProbeAnswer::ModeStatus(2))
    );
}

/// The alert list the grid library fills is bounded.
#[test]
fn the_alert_list_is_bounded() {
    let mut engine = engine();
    let mut input = Vec::new();
    for index in 0..2_000 {
        input.extend_from_slice(format!("\x1b]2;title {index}\x07").as_bytes());
    }
    engine.feed(&input, 0);
    assert!(
        engine.grid().alerts_dropped() > 0,
        "a program that renames itself in a loop cannot grow the list"
    );
}
