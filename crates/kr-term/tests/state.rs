//! Snapshots, geometry, budgets, probes and the pinned terminfo database.
//!
//! The recurring theme is that reconnection must put a screen back without making anything happen
//! a second time, and that every bound is checked before the allocation rather than after it.

use kr_term::budget::{BudgetLimits, GridSize, MAX_CELLS, MAX_COLS, MAX_ROWS, SessionBudget};
use kr_term::engine::{Engine, EngineConfig};
use kr_term::error::{ProbeFailure, TermError};
use kr_term::grid::{CanonicalGrid, Colour};
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

fn text_of(rows: &[kr_term::grid::GridRow]) -> Vec<String> {
    rows.iter()
        .map(|row| row.runs.iter().map(|run| run.text.as_str()).collect())
        .collect()
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
        .resize(GridSize::new(4_000, 4_000), 0)
        .expect_err("refused");
    assert!(matches!(error, TermError::Geometry { .. }));
    assert_eq!(engine.grid().size(), before);
    engine.resize(GridSize::new(100, 30), 0).expect("accepted");
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
    let TermError::Admission {
        cells,
        footprint,
        budget: limit,
        ..
    } = error
    else {
        panic!("a geometry that does not fit is refused as an admission failure: {error}");
    };
    assert_eq!(
        cells, 10_000,
        "the refusal names the cells that were asked for"
    );
    assert!(
        footprint > limit,
        "the refusal names what the cells would cost"
    );
    assert_eq!(
        error.code(),
        kr_protocol::error::ErrorCode::ResourceUnavailable,
        "a geometry the session cannot hold is a resource that is not available"
    );
    assert_eq!(
        budget.committed(),
        0,
        "nothing was committed for a refused allocation"
    );
}

#[test]
fn the_row_cache_is_measured_against_its_own_bound() {
    let mut budget = SessionBudget::new();
    let over = budget.set_row_cache(BudgetLimits::DEFAULT.row_cache_bytes * 2);
    assert!(over, "rows beyond the cache come from the spool");
    assert_eq!(
        budget.usage().rows,
        BudgetLimits::DEFAULT.row_cache_bytes * 2,
        "the measurement is what the rows cost, not what they are allowed to cost"
    );
    assert!(budget.row_cache_over_budget());
    // Eviction is not instant, so the reading stays over until the grid has caught up.
    budget.set_row_cache(BudgetLimits::DEFAULT.row_cache_bytes / 2);
    assert!(!budget.row_cache_over_budget());
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
    let (snapshot, _) = engine.snapshot(view, 0);
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

/// The pending wrap is part of the snapshot, because the same coordinates place the next
/// character in different cells with and without it.
#[test]
fn a_snapshot_carries_the_pending_wrap() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(4, 3),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let view = viewport(&engine);

    engine.feed(b"abc", 0);
    let (snapshot, _) = engine.snapshot(view, 0);
    assert_eq!((snapshot.cursor.col, snapshot.cursor.row), (3, 0));
    assert!(!snapshot.cursor.pending_wrap);

    // The final column is filled and the cursor stays on it.
    engine.feed(b"d", 0);
    let (snapshot, _) = engine.snapshot(view, 0);
    assert_eq!((snapshot.cursor.col, snapshot.cursor.row), (3, 0));
    assert!(snapshot.cursor.pending_wrap);

    // Moving the cursor cancels it, at the same coordinates.
    engine.feed(b"\x1b[1;4H", 0);
    let (snapshot, _) = engine.snapshot(view, 0);
    assert_eq!((snapshot.cursor.col, snapshot.cursor.row), (3, 0));
    assert!(!snapshot.cursor.pending_wrap);
}

/// Each buffer's saved cursor is carried, with the rendition and the character sets that were
/// saved with it. A restoration that carried only positions would put an application back in the
/// wrong colours.
#[test]
fn a_snapshot_carries_both_saved_cursors() {
    let mut engine = engine();
    let view = viewport(&engine);
    let (snapshot, _) = engine.snapshot(view, 0);
    assert_eq!(snapshot.saved_cursors, [None, None]);

    // Bold red with line drawing designated as G1, saved on the primary buffer.
    engine.feed(b"\x1b)0\x1b[1;31m\x1b[2;4H\x1b7", 0);
    // Green on the alternate buffer with ASCII back in G1, saved there.
    engine.feed(b"\x1b[?1047h\x1b)B\x1b[42m\x1b[3;2H\x1b7", 0);

    let (snapshot, _) = engine.snapshot(view, 0);
    let primary = snapshot.saved_cursors[0]
        .as_ref()
        .expect("the primary buffer saved a cursor");
    assert_eq!(primary.buffer, ActiveBuffer::Primary);
    assert_eq!((primary.col, primary.row), (3, 1));
    assert!(primary.rendition.bold);
    assert_eq!(primary.rendition.foreground, Colour::Indexed(1));
    assert_eq!(primary.charsets.g1, "DecLineDrawing");

    let alternate = snapshot.saved_cursors[1]
        .as_ref()
        .expect("the alternate buffer saved a cursor");
    assert_eq!(alternate.buffer, ActiveBuffer::Alternate);
    assert_eq!((alternate.col, alternate.row), (1, 2));
    assert!(!alternate.rendition.bold);
    assert_eq!(alternate.rendition.background, Colour::Indexed(2));
    assert_eq!(alternate.charsets.g1, "Ascii");

    // Both reach a reconnecting client.
    let saved: Vec<_> = restoration_operations(&snapshot)
        .into_iter()
        .filter_map(|op| match op {
            RestoreOp::SetSavedCursor { cursor } => Some(cursor.buffer),
            _ => None,
        })
        .collect();
    assert_eq!(
        saved,
        vec![ActiveBuffer::Primary, ActiveBuffer::Alternate],
        "a restoration puts back the saved cursor of each buffer"
    );
}

/// A snapshot taken while a full-screen application is running carries what the shell left behind,
/// so leaving the application puts the session back where it was.
#[test]
fn a_snapshot_carries_the_buffer_that_is_not_showing() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(12, 3),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let view = viewport(&engine);
    engine.feed(b"shell one\r\nshell two", 0);

    // Before the switch the buffer that is not showing is the empty alternate one.
    let (snapshot, _) = engine.snapshot(view, 0);
    assert_eq!(snapshot.active_buffer, ActiveBuffer::Primary);
    assert_eq!(snapshot.inactive_rows.len(), 3);
    assert!(
        snapshot.inactive_rows.iter().all(|row| row.runs.is_empty()),
        "the alternate buffer has nothing on it yet"
    );

    engine.feed(b"\x1b[?1049h\x1b[2J\x1b[Hediting", 0);
    let (snapshot, _) = engine.snapshot(view, 0);
    assert_eq!(snapshot.active_buffer, ActiveBuffer::Alternate);
    assert_eq!(text_of(&snapshot.rows), ["editing", "", ""]);
    assert_eq!(
        text_of(&snapshot.inactive_rows),
        ["shell one", "shell two", ""]
    );

    // The buffer that is not showing is painted before the one that is.
    let operations = restoration_operations(&snapshot);
    let first_inactive = operations
        .iter()
        .position(|op| matches!(op, RestoreOp::PaintInactiveRow { .. }))
        .expect("the inactive buffer is painted");
    let first_active = operations
        .iter()
        .position(|op| matches!(op, RestoreOp::PaintRow { .. }))
        .expect("the active buffer is painted");
    assert!(first_inactive < first_active);
}

/// A row that scrolls keeps the columns the pinned width model gave it, including for scalars the
/// grid library's own clustering would fold into one cell.
#[test]
fn a_scrolled_row_keeps_its_columns() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(8, 2),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let view = viewport(&engine);
    // A woman-technologist emoji sequence and a Hangul syllable written as jamo: six columns under
    // the pinned model, two under the library's own clustering.
    engine.feed(
        "\u{1f469}\u{200d}\u{1f4bb}\u{1100}\u{1161}\r\nb\r\nc".as_bytes(),
        0,
    );
    let (snapshot, _) = engine.snapshot(view, 0);

    let history = engine.grid().history_rows(snapshot.oldest_retained_row, 8);
    let row = history.first().expect("the first row has scrolled off");
    assert_eq!(
        row.runs.iter().map(|run| run.cells).sum::<u32>(),
        6,
        "a scrolled row keeps the columns it was given"
    );
    assert_eq!(
        row.runs
            .iter()
            .map(|run| run.text.as_str())
            .collect::<String>(),
        "\u{1f469}\u{200d}\u{1f4bb}\u{1100}\u{1161}"
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
    let (snapshot, _) = engine.snapshot(view, 0);
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
            | RestoreOp::PaintInactiveRow { .. }
            | RestoreOp::RecordHyperlink { .. }
            | RestoreOp::SetHyperlink { .. }
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
    let generation = engine.projection_generation();
    let delta: Delta = engine
        .delta(base, generation)
        .expect("the base is inside the window");
    assert_eq!(delta.base_cursor, base);
    assert!(delta.rows.is_empty());

    // One more line changes one row, and a mode change travels with it.
    engine.feed(b"\x1b[?25lsecond", 0);
    let delta = engine
        .delta(base, generation)
        .expect("still inside the window");
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
    let error = engine.delta(base + 1, generation).expect_err("gap");
    assert!(matches!(error, TermError::CursorGap { .. }));

    // So is a base from before a projection reset.
    engine.feed(b"\x1b[?1049h", 0);
    let error = engine
        .delta(base, generation)
        .expect_err("the projection was reset");
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
    // Asking a subset still ends with the terminator, and asks for it only once.
    let (_, request) = ProbeSession::start(
        0,
        InputContext::Clean,
        &[ProbeItem::Version, ProbeItem::DeviceAttributes],
    )
    .expect("clean stream");
    assert!(request.ends_with(b"\x1b[c"));
    assert_eq!(request.windows(4).filter(|w| *w == b"\x1b[0c").count(), 0);
}

#[test]
fn a_probe_completes_on_its_terminator() {
    let (mut session, request) =
        ProbeSession::start(0, InputContext::Clean, PROBE_SET).expect("clean stream");
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
        session.observe(b"\x1b[?0u", 33).expect("answer"),
        ProbeProgress::Collecting
    );
    assert_eq!(
        session.observe(b"\x1b[?2026;2$y", 35).expect("answer"),
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
    let (mut session, _) =
        ProbeSession::start(0, InputContext::Clean, PROBE_SET).expect("clean stream");
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
    let (mut session, _) =
        ProbeSession::start(0, InputContext::Clean, PROBE_SET).expect("clean stream");
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
    let error = ProbeSession::start(0, InputContext::Contaminated, PROBE_SET).expect_err("refused");
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
    let (snapshot, _) = engine.snapshot(view, 0);
    assert_eq!(snapshot.palette.source, PaletteSource::LightPreset);
    engine.adopt_palette(kr_term::palette::Palette::from_client_preference(
        Rgb::new(1, 2, 3),
        Rgb::new(4, 5, 6),
    ));
    let view = viewport(&engine);
    let (snapshot, _) = engine.snapshot(view, 0);
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
    let (snapshot, _) = engine.snapshot(view, 0);
    assert_eq!(snapshot.keyboard.modify_other_keys, 2);
    assert_eq!(snapshot.keyboard.primary.flags, Some(3));
    assert_eq!(
        snapshot.keyboard.primary.stack.len(),
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
    let (snapshot, _) = engine.snapshot(view, 0);
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
    let (snapshot, _) = engine.snapshot(view, 0);
    assert_eq!(snapshot.palette.cursor, Rgb::new(1, 2, 3));
    assert_eq!(snapshot.palette.selection_background, Rgb::new(4, 5, 6));
}

/// A question the probe asked and the terminal did not answer fails the attach.
#[test]
fn a_probe_without_every_answer_fails() {
    // The terminator arrives, so nothing is still in flight, and one question is unanswered. The
    // attach fails rather than recording the silence as a capability the terminal lacks.
    let (mut session, _) =
        ProbeSession::start(0, InputContext::Clean, PROBE_SET).expect("clean stream");
    session.observe(b"\x1b[?62;22c", 10).expect("terminator");
    let error = session.finish(20).expect_err("an unanswered question");
    assert!(matches!(
        error,
        TermError::ProbeFailed {
            reason: ProbeFailure::MissingAnswer
        }
    ));
}

/// A caller that needs less asks less, and every question it did ask is answered.
#[test]
fn a_probe_asks_only_what_its_profile_needs() {
    let (mut session, request) =
        ProbeSession::start(0, InputContext::Clean, &[ProbeItem::DeviceAttributes])
            .expect("clean stream");
    assert_eq!(request, b"\x1b[c".to_vec());
    session.observe(b"\x1b[?62;22c", 10).expect("terminator");
    let outcome = session.finish(20).expect("complete");
    assert_eq!(outcome.asked(), vec![ProbeItem::DeviceAttributes]);
    assert!(outcome.adopt_palette().is_none());
}

/// The synchronised-output probe reads a real DECRPM reply.
#[test]
fn the_probe_reads_a_mode_report_in_its_real_form() {
    let (mut session, _) = ProbeSession::start(
        0,
        InputContext::Clean,
        &[ProbeItem::SynchronisedOutput, ProbeItem::DeviceAttributes],
    )
    .expect("clean stream");
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

// ------------------------------------------------------ what the review round found

/// Two clients reading deltas from two different bases never clear each other's changes.
#[test]
fn a_delta_belongs_to_the_base_it_names() {
    let mut engine = engine();
    engine.feed(b"first\r\n", 0);
    let older = engine.output_cursor();
    engine.feed(b"\x1b]2;renamed\x07", 0);
    let newer = engine.output_cursor();
    engine.feed(b"\x1b[?25l", 0);

    // The client on the newer base sees only the mode change.
    let generation = engine.projection_generation();
    let recent = engine.delta(newer, generation).expect("inside the window");
    assert!(recent.title.is_none(), "the title changed before this base");
    assert!(recent.modes.iter().any(|entry| entry.mode == 25));

    // The client on the older base still sees the title, after the other client read.
    let behind = engine.delta(older, generation).expect("inside the window");
    assert_eq!(
        behind.title.as_ref().map(|entry| entry.window.as_str()),
        Some("renamed"),
        "one client's read does not clear another client's changes"
    );
    assert!(behind.modes.iter().any(|entry| entry.mode == 25));

    // Reading again returns the same answer: nothing was consumed.
    let again = engine.delta(older, generation).expect("inside the window");
    assert_eq!(behind.title, again.title);
}

/// A snapshot settles the held cell and hands back what settling produced.
#[test]
fn a_snapshot_returns_the_output_its_own_settling_made() {
    let mut engine = engine();
    let outcome = engine.feed(b"abc", 0);
    assert!(
        outcome.forward.iter().all(|span| span.end() < 3),
        "the last cell is held until the next read"
    );
    let before = engine.output_cursor();
    let view = viewport(&engine);
    let (snapshot, settled) = engine.snapshot(view, 0);

    // The snapshot's cursor is the committed one, and it includes the settled cell.
    assert_eq!(snapshot.output_cursor, engine.output_cursor());
    assert!(
        snapshot.output_cursor > before,
        "settling committed the cell"
    );
    assert_eq!(
        settled.forward.len(),
        1,
        "a direct attachment is given the bytes the snapshot settled"
    );

    // A delta from the snapshot's own cursor reports nothing outstanding.
    let delta = engine
        .delta(snapshot.output_cursor, snapshot.projection_generation)
        .expect("its own base");
    assert!(delta.rows.is_empty(), "the snapshot already carried it");
}

/// A qualified sequence with omitted parameters acts on its documented defaults.
#[test]
fn omitted_parameters_take_their_documented_defaults() {
    fn after(input: &[u8]) -> kr_term::snapshot::Snapshot {
        let mut session = engine();
        session.feed(input, 0);
        let view = viewport(&session);
        session.snapshot(view, 0).0
    }

    // Both slots omitted: the scroll region becomes the whole screen.
    let snapshot = after(b"\x1b[3;10r\x1b[r");
    assert_eq!(snapshot.margins.top, 0);
    assert_eq!(snapshot.margins.bottom, snapshot.dimensions.rows - 1);

    // The trailing slot omitted: the bottom margin is the last row.
    let snapshot = after(b"\x1b[2;r");
    assert_eq!(snapshot.margins.top, 1);
    assert_eq!(snapshot.margins.bottom, snapshot.dimensions.rows - 1);

    // The leading slot omitted: the top margin is the first row.
    let snapshot = after(b"\x1b[;5r");
    assert_eq!(snapshot.margins.top, 0);
    assert_eq!(snapshot.margins.bottom, 4);

    // Cursor placement with both slots omitted goes home.
    let snapshot = after(b"\x1b[5;5H\x1b[;H");
    assert_eq!((snapshot.cursor.col, snapshot.cursor.row), (0, 0));
}

/// Resident state over a bound is reported as pressure on every feed, not only as a diagnostic.
#[test]
fn resident_pressure_is_reported_while_it_lasts() {
    let mut engine = engine();
    let outcome = engine.feed(b"hello", 0);
    assert!(!outcome.resident_pressure.any());
    assert!(!engine.budget().row_cache_over_budget());
}

/// Keyboard negotiation has one owner: the tracker, the reducer and the broker never disagree.
#[test]
fn keyboard_negotiation_has_one_owner() {
    fn keyboard(input: &[u8]) -> kr_term::snapshot::KeyboardSnapshot {
        let mut session = engine();
        session.feed(input, 0);
        let view = viewport(&session);
        session.snapshot(view, 0).0.keyboard
    }

    // `CSI >m` with no parameters resets modifyOtherKeys to its default.
    assert_eq!(keyboard(b"\x1b[>4;2m").modify_other_keys, 2);
    assert_eq!(keyboard(b"\x1b[>4;2m\x1b[>m").modify_other_keys, 0);
    assert_eq!(keyboard(b"\x1b[>4;2m\x1b[>4m").modify_other_keys, 0);

    // `CSI =u` with no parameters resets the Kitty flags.
    assert_eq!(keyboard(b"\x1b[=3u").primary.flags, Some(3));
    assert_eq!(keyboard(b"\x1b[=3u\x1b[=u").primary.flags, Some(0));

    // `CSI <u` pops one entry; `CSI <0u` pops one as well, because zero means one.
    let one = keyboard(b"\x1b[>1u\x1b[>3u\x1b[<u");
    assert_eq!(one.primary.flags, Some(1));
    let zero = keyboard(b"\x1b[>1u\x1b[>3u\x1b[<0u");
    assert_eq!(zero.primary.flags, one.primary.flags);
    assert_eq!(zero.primary.stack, one.primary.stack);

    // Popping an empty stack leaves the flags alone rather than going negative.
    assert_eq!(keyboard(b"\x1b[<u\x1b[<u\x1b[<u").primary.flags, None);

    // Each screen buffer keeps its own stack, as the protocol says, and a snapshot carries both.
    let split = keyboard(b"\x1b[>1u\x1b[?1049h\x1b[>7u\x1b[?1049l");
    assert_eq!(
        split.primary.flags,
        Some(1),
        "leaving the alternate buffer restores the primary buffer's negotiation"
    );
    assert_eq!(
        split.alternate.flags,
        Some(7),
        "and the alternate buffer's own negotiation is carried too"
    );
}

/// A soft reset and a cursor restore leave the tracker and the grid agreeing about origin mode.
#[test]
fn origin_mode_has_one_answer() {
    let mut after_reset = engine();
    after_reset.feed(b"\x1b[?6h\x1b[!p", 0);
    assert!(!after_reset.grid().origin_mode());
    assert!(!after_reset.modes().is_set(kr_term::modes::ModeKind::Dec, 6));

    let mut after_restore = engine();
    after_restore.feed(b"\x1b[?6h\x1b7\x1b[?6l\x1b8", 0);
    assert!(
        after_restore.grid().origin_mode(),
        "the restore brought it back"
    );
    assert!(
        after_restore
            .modes()
            .is_set(kr_term::modes::ModeKind::Dec, 6),
        "and the tracker followed it"
    );
}

/// A base cursor names one state, and a delta carries everything a repaint needs.
#[test]
fn a_delta_carries_the_presentation_state_that_changed() {
    let mut painted = engine();
    let view = viewport(&painted);
    let (snapshot, _) = painted.snapshot(view, 0);
    painted.feed(
        b"\x1b[2;3r\x1b[31m\x1bH\x1b(0\x1b]8;;https://example.invalid/\x1b\\link",
        0,
    );
    painted.quiesce(0);
    let delta = painted
        .delta(snapshot.output_cursor, snapshot.projection_generation)
        .expect("inside the window");
    assert!(delta.margins.is_some(), "the scroll region changed");
    assert!(delta.rendition.is_some(), "the pen changed");
    assert!(delta.tab_stops.is_some(), "a tab stop was set");
    assert!(delta.charsets.is_some(), "a character set was designated");
    assert!(
        !delta.hyperlinks.is_empty(),
        "the rows carry their hyperlink ranges"
    );

    // A geometry change resets the projection, because every row reflows.
    let mut resized = engine();
    let view = viewport(&resized);
    let (snapshot, _) = resized.snapshot(view, 0);
    resized
        .resize(kr_term::budget::GridSize::new(40, 12), 0)
        .expect("valid geometry");
    resized.quiesce(0);
    let error = resized
        .delta(snapshot.output_cursor, snapshot.projection_generation)
        .expect_err("the base no longer describes anything");
    assert!(matches!(error, TermError::CursorGap { .. }));
}

/// Resident state is measured when it grows, not only every so many reads.
#[test]
fn one_large_read_is_measured_before_the_next_one() {
    let mut engine = Engine::new(EngineConfig {
        size: kr_term::budget::GridSize::new(2048, 3),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let mut input = Vec::new();
    for _ in 0..320 {
        input.extend(std::iter::repeat_n(b'x', 2048));
        input.extend_from_slice(b"\r\n");
    }
    engine.feed(&input, 0);
    assert!(
        engine.budget().usage().rows >= engine.grid().history_bytes(),
        "the budget knows what the rows cost after the read that made them, and never less"
    );
    assert!(
        engine.budget().usage().rows <= kr_term::budget::BudgetLimits::DEFAULT.row_cache_bytes,
        "the rows past the bound are gone, without waiting for more output"
    );
}

/// Printing into an admitted screen is never refused, and never finds more than the geometry
/// reserved for it, however much goes through the same cells.
#[test]
fn printing_into_an_admitted_screen_stays_inside_its_reservation() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(8, 2),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    // True colour, so every cell keeps an allocation of its own for its attributes.
    for _ in 0..128 {
        engine.feed(b"\x1b[H\x1b[38;2;10;20;30mabcdefgh", 0);
        engine.quiesce(0);
        assert_eq!(
            engine.budget().excess(),
            0,
            "a measurement found more than the geometry reserved"
        );
    }
    assert!(
        engine.budget().usage().screens() > 0,
        "the cells hold what was printed"
    );
    assert!(!engine.budget().session_over_budget());
}

/// A measurement never finds more than the reservation charged for, so usage never rises when
/// someone looks.
#[test]
fn a_link_costs_no_more_than_what_was_reserved_for_it() {
    let mut engine = engine();
    let text = "id=one:two=three;https://example.invalid/path";
    engine.feed(format!("\x1b]8;{text}\x1b\\X").as_bytes(), 0);
    engine.quiesce(0);
    let reserved = kr_term::grid::link_cost(text, 2);
    let measured = engine.grid().buffer_bytes().links;
    assert!(measured > 0, "a link on the screen is resident state");
    assert!(
        measured <= reserved,
        "measured {measured} bytes against a reservation of {reserved}"
    );
}

/// A wide cell covers two columns and the grid keeps an allocation for each of them, so a
/// reservation that counted scalars would be below what the measurement finds.
#[test]
fn a_wide_cell_is_reserved_for_the_columns_it_covers() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(8, 2),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    engine.feed("\x1b[38;2;10;20;30m\u{754c}\u{754c}".as_bytes(), 0);
    engine.quiesce(0);
    assert_eq!(
        engine.budget().excess(),
        0,
        "a wide cell measured more than the geometry reserved for its columns"
    );
    assert!(
        engine.budget().usage().screen_content[0] >= 2 * kr_term::grid::CELL_ATTRIBUTE_BYTES,
        "each column of a wide cell keeps its own attribute allocation"
    );
}

/// A cell that keeps an allocation of its own for its attributes costs more than one that does
/// not, so a screen of coloured cells is not charged as a screen of plain ones.
#[test]
fn a_cell_is_charged_for_the_attributes_it_keeps() {
    fn content(input: &[u8]) -> u64 {
        let mut engine = Engine::new(EngineConfig {
            size: GridSize::new(16, 2),
            ..EngineConfig::DEFAULT
        })
        .expect("engine");
        engine.feed(input, 0);
        engine.quiesce(0);
        engine.grid().buffer_bytes().content[0]
    }

    let plain = content(b"abcdefghabcdefgh");
    let coloured = content(b"\x1b[38;2;10;20;30mabcdefghabcdefgh");
    assert!(
        coloured > plain,
        "coloured cells cost {coloured} against {plain} for plain ones"
    );
}

/// The buffer that is not showing still holds what it holds, so its charge is not replaced by the
/// other buffer's.
#[test]
fn each_buffer_keeps_its_own_charge_across_a_switch() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(16, 3),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    engine.feed(b"\x1b[41mfilled with colour", 0);
    engine.quiesce(0);
    assert!(engine.budget().usage().screen_content[0] > 0);
    let primary = engine.budget().usage().screen_content[0];

    engine.feed(b"\x1b[?1049h", 0);
    engine.quiesce(0);
    assert!(
        engine.budget().usage().screen_content[0] >= primary,
        "the primary buffer still holds its rows while the alternate one is showing"
    );
    engine.feed(b"\x1b[44malternate content", 0);
    engine.quiesce(0);
    assert!(
        engine.budget().usage().screen_content[1] > 0,
        "the alternate buffer holds its own rows"
    );
    assert!(
        engine.budget().usage().screen_content[0] >= primary,
        "and the primary buffer is still measured while it is not showing"
    );
    assert_eq!(engine.budget().excess(), 0);
}

/// A reservation and a measurement round a hyperlink's parameter table the same way, so a
/// measurement never finds more than the session was already charged.
#[test]
fn a_link_costs_no_more_than_was_reserved_at_every_table_size() {
    for parameters in [1usize, 3, 4, 7, 8, 14, 15] {
        let mut field: Vec<String> = (0..parameters)
            .map(|index| format!("k{index}=v{index}"))
            .collect();
        // The last key again. A table grows before it looks for the key it is given, so a repeat
        // leaves a table with more room in it than it has entries.
        field.push(format!("k{}=again", parameters - 1));
        let field = field.join(":");
        let text = format!("{field};https://example.invalid/p");
        let mut engine = engine();
        engine.feed(format!("\x1b]8;{text}\x1b\\X").as_bytes(), 0);
        engine.quiesce(0);
        let reserved = kr_term::grid::link_cost(&text, parameters + 1);
        let measured = engine.grid().buffer_bytes().links;
        assert!(
            measured > 0,
            "{parameters} parameters: the link is resident state"
        );
        assert!(
            measured <= reserved,
            "{parameters} parameters: measured {measured} against a reservation of {reserved}"
        );
    }
}

/// A row arriving while the library drops an older one to make room leaves the cache the same
/// length and holding something else, so what is counted is arrivals rather than rows.
#[test]
fn rows_that_replace_older_ones_are_charged() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(2048, 3),
        grid: kr_term::grid::GridConfig {
            scrollback_rows: 8,
            ..kr_term::grid::GridConfig::DEFAULT
        },
        ..EngineConfig::DEFAULT
    })
    .expect("engine");

    // Fill the cache to its row limit with rows that cost almost nothing.
    for _ in 0..16 {
        engine.feed(b"x\r\n", 0);
    }
    engine.quiesce(0);
    let cheap = engine.budget().usage().rows;

    // Two rows of links with long identifiers, then scroll them in. The cache holds the same
    // number of rows afterwards and is holding far more.
    let mut input = Vec::new();
    for row in 0..2u32 {
        for column in 0..512u32 {
            input.extend_from_slice(b"\x1b]8;id=");
            input.extend(std::iter::repeat_n(b'z', 1_900));
            input.extend_from_slice(column.to_string().as_bytes());
            input.extend_from_slice(b";u\x1b\\X\x1b]8;;\x1b\\");
        }
        if row == 0 {
            input.extend_from_slice(b"\r\n");
        }
    }
    engine.feed(&input, 0);
    engine.quiesce(0);
    engine.feed(b"\x1b[2S", 0);

    assert!(
        engine.budget().usage().rows > cheap,
        "the rows that replaced the cheap ones are charged"
    );
    assert!(
        engine.budget().usage().rows <= kr_term::budget::BudgetLimits::DEFAULT.row_cache_bytes,
        "the cache is under its bound: {} bytes",
        engine.budget().usage().rows
    );
}

/// A hyperlink with parameters and no target is a close. The parameters are not kept, because a
/// link nothing can follow is not a link.
#[test]
fn a_hyperlink_with_no_target_keeps_no_parameters() {
    let mut engine = engine();
    let before = engine.budget().usage().links;
    let identifier = "a".repeat(1_000);
    engine.feed(format!("\x1b]8;id={identifier};\x1b\\X").as_bytes(), 0);
    engine.quiesce(0);
    assert!(engine.budget().truncations() > 0);
    assert_eq!(
        engine.budget().usage().links,
        before,
        "the identifier of a link that points nowhere is not kept"
    );
    assert_eq!(
        engine.grid().buffer_bytes().links,
        0,
        "nothing on the screen belongs to a link that points nowhere"
    );

    // The ordinary close still reaches the grid.
    let mut closing = Engine::new(EngineConfig::DEFAULT).expect("engine");
    closing.feed(b"\x1b]8;;https://example.invalid/\x1b\\A\x1b]8;;\x1b\\B", 0);
    closing.quiesce(0);
    assert!(closing.grid().buffer_bytes().links > 0);
}

/// Two rows can carry more than the whole historical cache, so the bound is enforced where they
/// join it rather than at the next measurement.
#[test]
fn rows_that_scroll_off_are_charged_where_they_arrive() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(2048, 3),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");

    // Two rows of separately opened links, each with a two-kilobyte identifier.
    let mut input = Vec::new();
    for row in 0..2u32 {
        for column in 0..2048u32 {
            input.extend_from_slice(b"\x1b]8;id=");
            input.extend(std::iter::repeat_n(b'z', 1_900));
            input.extend_from_slice(column.to_string().as_bytes());
            input.extend_from_slice(b";u\x1b\\X\x1b]8;;\x1b\\");
        }
        if row == 0 {
            input.extend_from_slice(b"\r\n");
        }
    }
    engine.feed(&input, 0);
    engine.quiesce(0);

    // Scroll both rows into the cache in one step, well short of the measurement gate.
    engine.feed(b"\x1b[2S", 0);
    assert!(
        engine.budget().usage().rows <= kr_term::budget::BudgetLimits::DEFAULT.row_cache_bytes,
        "the cache is back under its bound without waiting for another read: {} bytes",
        engine.budget().usage().rows
    );
}

/// A hyperlink costs what the whole link costs, identifier included.
#[test]
fn hyperlink_identifiers_are_counted() {
    let mut counted = engine();
    let mut input = Vec::new();
    for index in 0..8u32 {
        input.extend_from_slice(b"\x1b]8;id=");
        input.extend(std::iter::repeat_n(b'a', 256));
        input.extend_from_slice(index.to_string().as_bytes());
        input.extend_from_slice(b";https://example.invalid/\x1b\\X");
    }
    counted.feed(&input, 0);
    counted.quiesce(0);
    assert!(
        counted.budget().usage().links > 8 * 256,
        "the identifiers are counted, not just the targets"
    );

    // One link is bounded on its own, because every cell inside it holds a reference to it.
    let mut oversized = engine();
    let mut input = b"\x1b]8;id=".to_vec();
    input.extend(std::iter::repeat_n(b'a', 8192));
    input.extend_from_slice(b";https://example.invalid/\x1b\\X");
    let outcome = oversized.feed(&input, 0);
    assert!(outcome.forward.is_empty());
    assert!(oversized.budget().truncations() > 0);
    assert_eq!(oversized.budget().usage().links, 0);
}

/// A cell that reaches its content bound says so rather than losing marks quietly.
#[test]
fn a_full_cell_reports_the_marks_it_dropped() {
    let mut engine = engine();
    let mut input = String::from("e");
    for _ in 0..200 {
        input.push('\u{301}');
    }
    input.push('X');
    let outcome = engine.feed(input.as_bytes(), 0);
    assert!(engine.budget().truncations() > 0);
    assert!(
        outcome.projection_required_at.is_some(),
        "a physical terminal would have kept them, so the screens differ"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|entry| entry.kind == kr_term::diag::DiagnosticKind::ResidentStateTruncated)
    );
}

/// A mark written into a cell after the fact is a change like any other.
#[test]
fn a_mark_added_to_a_settled_cell_reaches_a_delta() {
    let mut engine = engine();
    engine.feed(b"e", 0);
    let view = viewport(&engine);
    let (snapshot, _) = engine.snapshot(view, 0);
    engine.feed("\u{301}".as_bytes(), 0);
    engine.quiesce(0);
    let delta = engine
        .delta(snapshot.output_cursor, snapshot.projection_generation)
        .expect("inside the window");
    assert_eq!(
        delta
            .rows
            .iter()
            .map(|row| row.runs.iter().map(|run| run.text.as_str()).collect())
            .collect::<Vec<String>>(),
        vec!["e\u{301}".to_owned()],
        "the row the mark changed is carried"
    );
}

/// A geometry change reflows the rows, so a mark cannot land on whatever moved into that cell.
#[test]
fn a_mark_after_a_resize_does_not_overwrite_another_cell() {
    let mut engine = Engine::new(EngineConfig {
        size: kr_term::budget::GridSize::new(4, 3),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    engine.feed(b"abcde\r\nZ\x1b[2;1H", 0);
    engine.feed(b"e", 0);
    engine.quiesce(0);
    engine
        .resize(kr_term::budget::GridSize::new(8, 3), 0)
        .expect("valid geometry");
    let before: Vec<String> = engine
        .grid()
        .visible_rows()
        .iter()
        .map(|row| row.runs.iter().map(|run| run.text.as_str()).collect())
        .collect();
    engine.feed("\u{301}".as_bytes(), 0);
    engine.quiesce(0);
    let after: Vec<String> = engine
        .grid()
        .visible_rows()
        .iter()
        .map(|row| row.runs.iter().map(|run| run.text.as_str()).collect())
        .collect();
    assert_eq!(before, after, "the mark reached a cell that had moved");
}

/// A reply that does not fit its form is not an answer.
#[test]
fn a_malformed_reply_does_not_answer_a_probe() {
    // A mode report whose prelude the parser could not keep whole.
    let (mut session, _) = ProbeSession::start(
        0,
        InputContext::Clean,
        &[ProbeItem::SynchronisedOutput, ProbeItem::DeviceAttributes],
    )
    .expect("clean stream");
    let mut input = b"\x1b[?2026;1".to_vec();
    input.extend(std::iter::repeat_n(0u8, 300));
    input.extend_from_slice(b"$y\x1b[?1c");
    session.observe(&input, 10).expect("answers");
    let error = session.finish(20).expect_err("neither reply is an answer");
    assert!(matches!(
        error,
        TermError::ProbeFailed {
            reason: ProbeFailure::MissingAnswer | ProbeFailure::NoTerminator
        }
    ));

    // A device-attributes reply with an intermediate is a different sequence.
    let (mut session, _) =
        ProbeSession::start(0, InputContext::Clean, &[ProbeItem::DeviceAttributes])
            .expect("clean stream");
    session
        .observe(b"\x1b[?1$c", 10)
        .expect("no terminator yet");
    let error = session
        .finish(20)
        .expect_err("the terminator never arrived");
    assert!(matches!(
        error,
        TermError::ProbeFailed {
            reason: ProbeFailure::NoTerminator
        }
    ));
}

/// A history page walks forward through what is retained, whatever was evicted.
#[test]
fn a_history_page_does_not_repeat_rows() {
    let mut engine = Engine::new(EngineConfig {
        size: kr_term::budget::GridSize::new(20, 3),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    engine.feed(&b"x\r\n".repeat(3_600), 0);
    engine.quiesce(0);
    let page = engine.history_page(0);
    let ids: Vec<i64> = page.rows.iter().map(|row| row.stable_id).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(ids.len(), sorted.len(), "a row appeared twice on one page");
    assert!(
        ids.windows(2).all(|pair| pair[1] == pair[0] + 1),
        "the page is one contiguous run of rows"
    );
}

/// A cursor restore leaves the modes a terminal would have kept.
#[test]
fn a_cursor_restore_keeps_the_modes_around_it() {
    let mut newline = Engine::new(EngineConfig {
        size: kr_term::budget::GridSize::new(10, 3),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let outcome = newline.feed(b"\x1b[20h\x1b7\x1b8abc\nd", 0);
    newline.quiesce(0);
    assert!(newline.modes().is_set(kr_term::modes::ModeKind::Ansi, 20));
    assert_eq!(
        newline.grid().cursor(),
        (1, 1),
        "newline mode still turns the line feed into a new line"
    );
    assert!(outcome.projection_required_at.is_none());

    let mut shifted = Engine::new(EngineConfig {
        size: kr_term::budget::GridSize::new(10, 3),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    shifted.feed(b"\x1b)0\x0e\x1b7\x1b8q", 0);
    shifted.quiesce(0);
    assert!(shifted.grid().shift_out(), "the character set survived");
}

/// A session that fills its screen with hyperlinks is bounded by the session budget.
#[test]
fn hyperlinks_on_the_screen_are_counted() {
    let mut engine = Engine::new(EngineConfig {
        size: kr_term::budget::GridSize::new(80, 24),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let one = format!("\x1b]8;id={};u\x1b\\x", "z".repeat(1_000));
    let mut input = String::new();
    for _ in 0..512 {
        input.push_str(&one);
    }
    engine.feed(input.as_bytes(), 0);
    engine.quiesce(0);
    assert!(
        engine.budget().usage().links > 0,
        "the links the rows on screen hold are resident state"
    );
}

/// A hyperlink the session cannot hold ends the one before it rather than extending it.
#[test]
fn a_refused_hyperlink_does_not_extend_the_one_before_it() {
    let mut engine = engine();
    let input = format!(
        "\x1b]8;;https://old.invalid\x1b\\A\x1b]8;;https://new.invalid/{}\x1b\\B",
        "x".repeat(4096)
    );
    let outcome = engine.feed(input.as_bytes(), 0);
    engine.quiesce(0);
    assert!(engine.budget().truncations() > 0);
    assert!(
        outcome.projection_required_at.is_some(),
        "the canonical screen lost a link a terminal would have kept"
    );
    let rows = engine.grid().visible_rows();
    let linked: Vec<Option<String>> = rows[0]
        .runs
        .iter()
        .map(|run| run.hyperlink.clone())
        .collect();
    assert_eq!(
        linked,
        vec![Some("https://old.invalid".to_owned()), None],
        "the text after the refused link is not inside the previous one"
    );
}

/// The cursor style a report gives is the one the grid is using.
#[test]
fn the_cursor_style_follows_a_restore() {
    let mut engine = engine();
    engine.feed(b"\x1b[5 q\x1b7\x1b[2 q\x1b8", 0);
    let view = viewport(&engine);
    let (snapshot, _) = engine.snapshot(view, 0);
    assert_eq!(
        snapshot.cursor.style, 5,
        "the restore put back the style that was saved with the cursor"
    );
}

/// A reply that does not fit the grammar of the question is not an answer.
#[test]
fn a_reply_in_the_wrong_shape_does_not_answer_a_probe() {
    for (item, reply) in [
        (ProbeItem::Version, b"\x1bP>1;2|fake\x1b\\".as_slice()),
        (ProbeItem::Version, b"\x1bP>!|fake\x1b\\".as_slice()),
        (
            ProbeItem::Foreground,
            b"\x1b]10;rgb:ffff/0000/0000;garbage\x1b\\".as_slice(),
        ),
    ] {
        let (mut session, _) =
            ProbeSession::start(0, InputContext::Clean, &[item]).expect("clean stream");
        let mut input = reply.to_vec();
        input.extend_from_slice(b"\x1b[?62;22c");
        session.observe(&input, 10).expect("observed");
        let error = session.finish(20).expect_err("the question is unanswered");
        assert!(matches!(
            error,
            TermError::ProbeFailed {
                reason: ProbeFailure::MissingAnswer
            }
        ));
    }
}

/// A title too long to keep is a truncation, not a quiet loss.
#[test]
fn a_title_that_does_not_fit_says_so() {
    let mut engine = engine();
    let title = "t".repeat(2_048);
    let outcome = engine.feed(format!("\x1b]2;{title}\x07").as_bytes(), 0);
    assert!(engine.budget().truncations() > 0);
    assert!(
        outcome.projection_required_at.is_some(),
        "a terminal reading the same bytes kept the whole title"
    );
    let view = viewport(&engine);
    let (snapshot, _) = engine.snapshot(view, 0);
    assert!(snapshot.title.window.len() < title.len());
}

/// A reset empties both buffers, so what they were holding is no longer charged.
#[test]
fn a_reset_releases_what_the_buffers_held() {
    let mut engine = engine();
    let mut input = String::new();
    for index in 0..64u32 {
        input.push_str(&format!(
            "\x1b]8;id=link{index};https://example.invalid/{index}\x1b\\x"
        ));
    }
    engine.feed(input.as_bytes(), 0);
    engine.quiesce(0);
    assert!(engine.budget().usage().links > 0);
    engine.feed(b"\x1bc", 0);
    engine.quiesce(0);
    assert_eq!(
        engine.budget().usage().links,
        0,
        "both screens were emptied"
    );
}

/// Nothing that arrives after the terminator is an answer.
#[test]
fn a_probe_ignores_answers_behind_its_terminator() {
    let (mut session, _) = ProbeSession::start(
        0,
        InputContext::Clean,
        &[ProbeItem::Foreground, ProbeItem::DeviceAttributes],
    )
    .expect("clean stream");
    session
        .observe(b"\x1b[?62;22c\x1b]10;rgb:ffff/0000/0000\x1b\\", 10)
        .expect("observed");
    let error = session
        .finish(20)
        .expect_err("the colour answered after the terminator");
    assert!(matches!(
        error,
        TermError::ProbeFailed {
            reason: ProbeFailure::MissingAnswer
        }
    ));
}

/// A control inside a sequence can change what a repaint needs, so a delta carries it.
#[test]
fn an_embedded_control_reaches_a_delta() {
    let mut engine = engine();
    engine.feed(b"\x1b)0", 0);
    let view = viewport(&engine);
    let (snapshot, _) = engine.snapshot(view, 0);
    engine.feed(b"\x1b[\x0e6n", 0);
    engine.quiesce(0);
    assert!(engine.grid().shift_out());
    let delta = engine
        .delta(snapshot.output_cursor, snapshot.projection_generation)
        .expect("inside the window");
    assert!(
        delta.charsets.is_some(),
        "the character set the control selected travels with the delta"
    );
}

// ------------------------------------------------------- admission and the charges it replaces

/// A geometry inside the three dimension constraints that this session cannot hold is refused
/// before anything is allocated for it, and the two bounds are told apart by the code they carry.
#[test]
fn the_dimension_bound_and_the_budget_bound_are_told_apart() {
    // Every dimension constraint is satisfied: 2,048 columns, 128 rows, and exactly the 262,144
    // cells section 8 allows. Two buffers of those cells hold far more than the session budget.
    let refused = Engine::new(EngineConfig {
        size: GridSize::new(MAX_COLS, MAX_CELLS / MAX_COLS),
        ..EngineConfig::DEFAULT
    })
    .expect_err("the largest grid the dimensions allow does not fit the budget");
    assert!(matches!(refused, TermError::Admission { cells, .. } if cells == u64::from(MAX_CELLS)));
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::ResourceUnavailable
    );

    let invalid = Engine::new(EngineConfig {
        size: GridSize::new(MAX_COLS, MAX_ROWS),
        ..EngineConfig::DEFAULT
    })
    .expect_err("2,048 by 1,024 is outside the cell bound");
    assert!(matches!(invalid, TermError::Geometry { .. }));
    assert_eq!(
        invalid.code(),
        kr_protocol::error::ErrorCode::InvalidArgument
    );
}

/// A resize the session cannot hold leaves the grid, the reservation and the projection alone.
#[test]
fn a_resize_that_does_not_fit_changes_nothing() {
    let mut engine = engine();
    let before = engine.grid().size();
    let reserved = engine.budget().reserved();
    let error = engine
        .resize(GridSize::new(MAX_COLS, MAX_CELLS / MAX_COLS), 0)
        .expect_err("the new screens do not fit");
    assert_eq!(
        error.code(),
        kr_protocol::error::ErrorCode::ResourceUnavailable
    );
    assert_eq!(engine.grid().size(), before, "the grid is unchanged");
    assert_eq!(
        engine.budget().reserved(),
        reserved,
        "the reservation is unchanged"
    );
}

/// Text arriving for an admitted screen is never refused: every cell can hold what a cell may
/// hold, in both buffers, and the reservation already paid for it.
#[test]
fn text_for_an_admitted_screen_is_never_refused() {
    let size = GridSize::new(24, 6);
    let mut engine = Engine::new(EngineConfig {
        size,
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    // The worst case a cell can reach: true colour, so the cell keeps an allocation of its own,
    // and a cluster at the per-cell content bound, so its text is on the heap.
    let mut cell = String::from("\u{e9}");
    while cell.len() + 2 <= kr_term::grid::GridConfig::DEFAULT.cell_bytes {
        cell.push('\u{301}');
    }
    assert_eq!(cell.len(), kr_term::grid::GridConfig::DEFAULT.cell_bytes);
    let mut input = String::from("\x1b[38;2;10;20;30m");
    for _ in 0..(size.cols * size.rows) {
        input.push_str(&cell);
    }
    // Both buffers, because the reservation covers both.
    for buffer in ["", "\x1b[?1049h"] {
        engine.feed(buffer.as_bytes(), 0);
        engine.feed(input.as_bytes(), 0);
        engine.quiesce(0);
        assert_eq!(
            engine.budget().excess(),
            0,
            "a full screen measured more than the geometry reserved for it"
        );
        assert!(!engine.budget().session_over_budget());
    }
    assert!(
        engine.budget().usage().screens() > 0,
        "both buffers hold what was printed into them"
    );
}

/// A cell whose text is too big to live inside the cell keeps a header on the heap, and the
/// measurement counts it.
#[test]
fn a_cell_with_its_text_on_the_heap_is_charged_for_the_header() {
    fn content(cell: &str) -> u64 {
        let mut engine = Engine::new(EngineConfig {
            size: GridSize::new(4, 2),
            ..EngineConfig::DEFAULT
        })
        .expect("engine");
        engine.feed(cell.as_bytes(), 0);
        engine.quiesce(0);
        engine.grid().buffer_bytes().content[0]
    }

    // One combining mark keeps the cell's text inside the cell; four take it past a machine word.
    let inside = "e\u{301}";
    let on_the_heap = "e\u{301}\u{302}\u{303}\u{304}";
    assert!(on_the_heap.len() >= size_of::<u64>());
    let grew = content(on_the_heap) - content(inside);
    let text = 2 * (on_the_heap.len() - inside.len()) as u64;
    assert_eq!(
        grew,
        text + kr_term::grid::CELL_TEXT_HEAP_BYTES,
        "the header the text keeps on the heap is counted as well as the bytes"
    );
}

/// The array a screen keeps its rows in is reserved with the scrollback slots it can grow to, so
/// an empty row and the slot it sits in are not free.
#[test]
fn the_row_arrays_are_reserved_with_their_scrollback() {
    let budget = SessionBudget::new();
    let grid = kr_term::grid::GridConfig::DEFAULT;
    let footprint = budget.footprint(GridSize::new(80, 24), grid.scrollback_rows, 64);
    assert_eq!(
        footprint.row_arrays,
        (24 + grid.scrollback_rows as u64 + 24) * kr_term::grid::ROW_SLOT_BYTES,
        "the primary buffer's array holds the screen and the scrollback; the alternate keeps no \
         history"
    );
    assert!(
        footprint.cell_content >= 48 * kr_term::grid::ROW_STORAGE_BYTES,
        "every row of both screens allocates for itself whether or not anything is on it"
    );
    let taller = budget.footprint(GridSize::new(80, 48), grid.scrollback_rows, 64);
    assert!(
        taller.row_arrays > footprint.row_arrays,
        "a taller screen has more rows to keep"
    );

    // A session of empty rows still holds the array they sit in, so it is charged for it.
    let engine = Engine::new(EngineConfig {
        size: GridSize::new(80, 24),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    assert!(engine.budget().reserved().row_arrays > 0);
}

/// A title is applied inside room the geometry already reserved, the stack is charged for the room
/// it is holding, and popping an entry gives that room back.
#[test]
fn the_title_stack_is_charged_for_the_room_it_holds() {
    let mut pushed = engine();
    let long = "t".repeat(kr_term::title::MAX_TITLE_BYTES);
    let mut input = String::new();
    for _ in 0..kr_term::title::MAX_DEPTH {
        input.push_str(&format!("\x1b]0;{long}\x07\x1b[22t"));
    }
    pushed.feed(input.as_bytes(), 0);
    pushed.quiesce(0);
    let full = pushed.budget().usage().titles;
    assert!(full > 0, "the titles and the stack are resident state");
    assert!(
        full <= pushed.budget().reserved().titles,
        "a full stack of the longest titles measured {full} against a reservation of {}",
        pushed.budget().reserved().titles
    );
    let slots = kr_term::title::MAX_DEPTH as u64 * size_of::<kr_term::title::SavedTitle>() as u64;
    assert!(
        full >= slots + 2 * kr_term::title::MAX_DEPTH as u64 * long.len() as u64,
        "the stack is charged for the entries it is holding as well as for the room they sit in"
    );

    let mut popping = String::new();
    for _ in 0..kr_term::title::MAX_DEPTH {
        popping.push_str("\x1b[23t");
    }
    pushed.feed(popping.as_bytes(), 0);
    pushed.quiesce(0);
    assert_eq!(pushed.budget().excess(), 0);
    // The room the stack gave back is the room its entries took, and nothing more: the titles the
    // entries held are gone with them, and the array is no bigger than it needs to be.
    let mut fresh = engine();
    fresh.feed(format!("\x1b]0;{long}\x07").as_bytes(), 0);
    fresh.quiesce(0);
    assert_eq!(
        pushed.budget().usage().titles,
        fresh.budget().usage().titles,
        "an emptied stack keeps no more than one that was never pushed"
    );
    assert!(
        pushed.budget().usage().titles < full,
        "the entries the stack held are gone with it"
    );
}

/// A resize moves rows between the screen and the history, and the two are charged to different
/// bounds, so both are measured again where the rows move.
#[test]
fn a_resize_moves_the_charges_with_the_rows() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(40, 8),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    for index in 0..64u32 {
        engine.feed(
            format!("\x1b[41mrow {index} with some content\r\n").as_bytes(),
            0,
        );
    }
    engine.quiesce(0);
    let before = engine.budget().usage().rows;
    assert!(before > 0, "the rows that scrolled off are in the cache");

    // Fewer rows on the screen means more rows in the history, and the cache is charged for them
    // at the resize rather than at whichever read comes next.
    engine.resize(GridSize::new(40, 4), 0).expect("admitted");
    assert_eq!(
        engine.budget().usage().rows,
        engine.grid().history_bytes(),
        "the cache holds what the rows cost immediately after the resize"
    );
    assert!(
        engine.budget().usage().rows > before,
        "the rows the screen gave up are charged to the cache"
    );
    assert_eq!(engine.budget().excess(), 0);

    // And back the other way: a taller screen takes rows out of the history.
    let taller = engine.budget().usage().rows;
    engine.resize(GridSize::new(40, 12), 0).expect("admitted");
    assert_eq!(
        engine.budget().usage().rows,
        engine.grid().history_bytes(),
        "the cache holds what the rows cost immediately after the resize"
    );
    assert!(
        engine.budget().usage().rows < taller,
        "the rows the screen took back are no longer the cache's"
    );
}

/// A hyperlink the pen alone holds, or one a saved cursor carries, is on no row and is still
/// resident state.
#[test]
fn a_link_no_row_holds_is_measured() {
    // Opened over an empty screen: the pen holds it and nothing has been printed inside it.
    let mut pen = engine();
    pen.feed(b"\x1b]8;;https://example.invalid/pen\x1b\\", 0);
    pen.quiesce(0);
    assert!(
        pen.grid().buffer_bytes().links > 0,
        "the link the pen is inside is held by the pen"
    );

    // Saved with the cursor and then closed: no row holds it, and the saved cursor still does.
    let mut saved = engine();
    saved.feed(
        b"\x1b]8;;https://example.invalid/saved\x1b\\\x1b7\x1b]8;;\x1b\\",
        0,
    );
    saved.quiesce(0);
    assert!(
        saved.grid().buffer_bytes().links > 0,
        "the link the saved cursor carries is held by the saved cursor"
    );
    assert_eq!(saved.budget().excess(), 0);
}

/// Eviction lands under the bound in one pass, however unlike the rows are.
#[test]
fn eviction_lands_under_the_bound_in_one_pass() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(2_048, 3),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    // Rows of wildly different sizes, so a row count worked out from their average would land on
    // the wrong side of the bound.
    let mut input = String::new();
    for index in 0..600u32 {
        if index.is_multiple_of(8) {
            input.push_str("\x1b[38;2;10;20;30m");
            for _ in 0..2_048 {
                input.push('\u{754c}');
            }
        } else {
            input.push('x');
        }
        input.push_str("\r\n");
    }
    engine.feed(input.as_bytes(), 0);
    engine.quiesce(0);

    let limit = engine.budget().limits().row_cache_bytes;
    assert!(
        engine.grid().history_bytes() <= limit,
        "the rows left after one pass cost {} bytes against a {limit}-byte bound",
        engine.grid().history_bytes()
    );
    assert_eq!(engine.budget().usage().rows, engine.grid().history_bytes());
    assert!(!engine.budget().row_cache_over_budget());
}

/// The measurement is exact, not an estimate: a screen of identical cells costs what those cells
/// cost, counted one by one.
#[test]
fn a_screen_of_known_cells_measures_what_those_cells_cost() {
    let size = GridSize::new(4, 2);
    let mut engine = Engine::new(EngineConfig {
        size,
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    // One cell, exactly as expensive as a cell is allowed to be: an 'e' with an acute accent and
    // combining marks up to the per-cell content bound, which is far past a machine word, so its
    // text is on the heap behind a header; and a colour the packed form on the cell cannot hold,
    // so the cell keeps an allocation of its own for its attributes.
    let mut cell = String::from("\u{e9}");
    while cell.len() + 2 <= kr_term::grid::GridConfig::DEFAULT.cell_bytes {
        cell.push('\u{301}');
    }
    let cell = cell.as_str();
    assert_eq!(cell.len(), kr_term::grid::GridConfig::DEFAULT.cell_bytes);
    let mut input = String::from("\x1b[38;2;10;20;30m");
    for _ in 0..(size.cols * size.rows) {
        input.push_str(cell);
    }
    // Both buffers, because the reservation covers both.
    engine.feed(input.as_bytes(), 0);
    engine.feed(b"\x1b[?1049h", 0);
    engine.feed(input.as_bytes(), 0);
    engine.quiesce(0);

    let cells = u64::from(size.cols * size.rows);
    let expected = u64::from(size.rows) * kr_term::grid::ROW_STORAGE_BYTES
        + cells
            * (2 * cell.len() as u64
                + kr_term::grid::CELL_ATTRIBUTE_BYTES
                + kr_term::grid::CELL_TEXT_HEAP_BYTES);
    assert_eq!(
        engine.grid().buffer_bytes().content,
        [expected, expected],
        "in both buffers: what each row allocates for itself, the text at twice what it holds, \
         the attribute allocation of every cell, and the header each cell's text keeps on the heap"
    );
    assert_eq!(engine.budget().usage().screen_content, [expected, expected]);
    assert!(
        2 * expected <= engine.budget().reserved().cell_content,
        "two full screens of the most expensive cell there is fit what the geometry reserved"
    );
    assert_eq!(engine.budget().excess(), 0);
}

/// A resize while the alternate buffer is showing still moves rows into the primary buffer's
/// history, and the cache is charged for them where they move.
#[test]
fn a_resize_behind_the_alternate_buffer_still_charges_the_history() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(40, 8),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    for index in 0..64u32 {
        engine.feed(
            format!("\x1b[41mrow {index} with some content\r\n").as_bytes(),
            0,
        );
    }
    engine.feed(b"\x1b[?1049h", 0);
    engine.quiesce(0);
    let before = engine.budget().usage().rows;
    assert!(before > 0, "the primary buffer's history is still there");

    engine.resize(GridSize::new(40, 4), 0).expect("admitted");
    assert_eq!(
        engine.budget().usage().rows,
        engine.grid().history_bytes(),
        "the cache holds what the primary buffer's rows cost, whichever buffer is showing"
    );
    assert!(
        engine.budget().usage().rows > before,
        "the rows the primary screen gave up are charged to the cache"
    );
}

/// A narrower geometry brings the rows back to what it can hold: the reflow builds as many rows as
/// the text needs, and a row of blanks comes back from it at its old width.
#[test]
fn a_narrower_geometry_releases_what_it_cannot_hold() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(2_048, 8),
        grid: kr_term::grid::GridConfig {
            scrollback_rows: 64,
            ..kr_term::grid::GridConfig::DEFAULT
        },
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    // Every row full, so reflowing into one column has 16,000 rows of text to place.
    let mut input = String::from("\x1b[38;2;10;20;30m");
    for _ in 0..8 {
        for _ in 0..2_047 {
            input.push('x');
        }
        input.push_str("\r\n");
    }
    engine.feed(input.as_bytes(), 0);
    engine.quiesce(0);

    engine.resize(GridSize::new(1, 8), 0).expect("admitted");
    engine.quiesce(0);
    let rows = engine.grid().scrollback_rows();
    assert!(
        rows <= 64,
        "the reflow left {rows} rows of history against a 64-row scrollback"
    );
    assert_eq!(
        engine.budget().excess(),
        0,
        "the rows a narrower screen cannot hold are gone rather than charged"
    );

    // A screen of blanks with a background colour is whitespace to the reflow, which hands such a
    // row back whole rather than cutting it to the new width.
    let mut wide = Engine::new(EngineConfig {
        size: GridSize::new(2_048, 8),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    wide.feed(b"\x1b[48;2;10;20;30m\x1b[2J\x1b[8;1H", 0);
    wide.quiesce(0);
    wide.resize(GridSize::new(1, 8), 0).expect("admitted");
    wide.quiesce(0);
    assert_eq!(
        wide.budget().excess(),
        0,
        "a row of coloured blanks is cut to the columns the screen has"
    );
}

/// The alternate buffer keeps no history, so a shorter geometry must leave it holding no rows
/// beyond the ones it shows. Scrolling never drops them, so the resize does.
#[test]
fn a_shorter_geometry_leaves_the_alternate_buffer_no_extra_rows() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(64, 16),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    engine.feed(b"\x1b[?1049h\x1b[48;2;10;20;30m", 0);
    for row in 0..16u32 {
        engine.feed(
            format!("\x1b[{};1Halternate row {row}", row + 1).as_bytes(),
            0,
        );
    }
    engine.quiesce(0);
    let full = engine.budget().usage().screen_content[1];
    assert!(full > 0, "the alternate buffer holds its rows");

    engine.resize(GridSize::new(64, 1), 0).expect("admitted");
    engine.quiesce(0);
    assert!(
        engine.budget().usage().screen_content[1] < full / 8,
        "the rows the new geometry cannot show are gone, not held: {} bytes of {full}",
        engine.budget().usage().screen_content[1]
    );
    assert_eq!(engine.budget().excess(), 0);
    // And the row that is left is the one that was showing: the newest, not the oldest.
    let rows = engine.grid().visible_rows();
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0]
            .runs
            .iter()
            .any(|run| run.text.contains("alternate row 15")),
        "the rows dropped are the ones above the screen"
    );
}

/// A title is held by the session and by the grid, and both hold the same bounded string.
#[test]
fn the_grid_holds_no_more_of_a_title_than_the_session_does() {
    let mut engine = engine();
    let long = "t".repeat(60_000);
    engine.feed(format!("\x1b]2;{long}\x07").as_bytes(), 0);
    engine.quiesce(0);
    assert_eq!(
        engine.grid().title().len(),
        kr_term::title::MAX_TITLE_BYTES,
        "the grid keeps what a session keeps, not what arrived"
    );
    let snapshot = engine.snapshot(viewport(&engine), 0).0;
    assert_eq!(snapshot.title.window, engine.grid().title());
    assert_eq!(engine.budget().excess(), 0);
}

/// A restored title stack is rebuilt rather than adopted, so a snapshot cannot bring room with it.
#[test]
fn a_restored_title_stack_keeps_no_more_room_than_it_may() {
    let mut titles = kr_term::title::TitleState::new();
    let mut stack = Vec::with_capacity(1_000);
    for _ in 0..64 {
        stack.push(kr_term::title::SavedTitle {
            icon: Some("i".repeat(8_000)),
            window: Some("w".repeat(8_000)),
        });
    }
    titles.restore(
        kr_term::title::TitleEntry {
            icon: "i".repeat(8_000),
            window: "w".repeat(8_000),
        },
        stack,
        0,
    );
    assert_eq!(titles.depth(), kr_term::title::MAX_DEPTH);
    assert!(
        titles.resident_bytes() <= kr_term::title::MAX_RESIDENT_BYTES,
        "a restored stack holds {} bytes against a bound of {}",
        titles.resident_bytes(),
        kr_term::title::MAX_RESIDENT_BYTES
    );
    assert_eq!(titles.window().len(), kr_term::title::MAX_TITLE_BYTES);
}

/// A row scrolling off the screen moves no hyperlink object anywhere: one envelope holds every
/// link the grid keeps, wherever the row it is on sits.
#[test]
fn a_row_scrolling_off_moves_no_hyperlink_charge() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(40, 3),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    for row in 0..3u32 {
        engine.feed(
            format!("\x1b]8;;https://example.invalid/{row}\x1b\\link {row}\x1b]8;;\x1b\\\r\n")
                .as_bytes(),
            0,
        );
    }
    engine.quiesce(0);
    let on_screen = engine.budget().usage().links;
    assert!(on_screen > 0, "the links the rows hold are resident state");

    // Scroll every one of them into the retained rows.
    engine.feed(b"\r\n\r\n\r\n", 0);
    engine.quiesce(0);
    assert!(
        engine.grid().scrollback_rows() >= 3,
        "the rows carrying the links are above the screen now"
    );
    assert_eq!(
        engine.budget().usage().links,
        on_screen,
        "the objects are where they were; only the rows moved"
    );
    assert_eq!(engine.budget().excess(), 0);
}

/// A row rebuilt at a narrower width keeps the hyperlinks its cells hold. The library records on
/// the row whether any of its cells is inside a link, and a row built from cells does not carry
/// that record, so the measurement reads the cells rather than the record.
#[test]
fn a_rebuilt_row_still_shows_the_links_its_cells_hold() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(4, 2),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    // Four spaces inside a link: a row that is whitespace and holds a link object all the same.
    engine.feed(
        b"\x1b]8;;https://example.invalid/blank\x1b\\    \x1b]8;;\x1b\\",
        0,
    );
    engine.feed(b"\x1b[2;1H", 0);
    engine.quiesce(0);
    let before = engine.budget().usage().links;
    assert!(before > 0, "the link the row holds is resident state");

    engine.resize(GridSize::new(2, 2), 0).expect("admitted");
    engine.quiesce(0);
    assert_eq!(
        engine.budget().usage().links,
        before,
        "the row was rebuilt at the new width and its link is still held by its cells"
    );
    assert_eq!(engine.budget().excess(), 0);
}

/// The rows a shorter geometry leaves the buffer that is not showing are reported where they are,
/// slots and records included, and they are gone when that buffer comes back.
#[test]
fn rows_the_inactive_buffer_still_holds_are_reported_and_then_released() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(256, 24),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    // Every row of the alternate buffer filled, so none of them is blank and the library's own
    // pruning cannot drop it.
    engine.feed(b"\x1b[?1049h", 0);
    for row in 0..24u32 {
        engine.feed(format!("\x1b[{};1H", row + 1).as_bytes(), 0);
        engine.feed("x".repeat(256).as_bytes(), 0);
    }
    engine.feed(b"\x1b[?1049l", 0);
    engine.quiesce(0);
    assert_eq!(engine.budget().excess(), 0, "nothing is out of place yet");

    engine.resize(GridSize::new(256, 1), 0).expect("admitted");
    engine.quiesce(0);
    let held = engine.budget().usage().cell_slots;
    assert!(
        held > engine.budget().reserved().cell_slots,
        "the rows the alternate buffer still holds are counted where they are: {held} bytes of \
         slots against a reservation of {}",
        engine.budget().reserved().cell_slots
    );
    assert!(
        engine.budget().excess() > 0 && engine.budget().committed() > held,
        "what the session reports is not below what its measurements found"
    );

    // Showing that buffer again settles it, and the rows its geometry cannot hold are gone.
    engine.feed(b"\x1b[?1049h", 0);
    engine.quiesce(0);
    assert_eq!(
        engine.budget().excess(),
        0,
        "the rows were released when the buffer came back"
    );
}

/// Reflowing into fewer columns builds as many rows as the text needs. When the buffer it reflowed
/// is not the one showing, the rows it built are reported until it comes back.
#[test]
fn rows_a_reflow_builds_behind_the_alternate_buffer_are_reported() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(2_048, 8),
        grid: kr_term::grid::GridConfig {
            scrollback_rows: 64,
            ..kr_term::grid::GridConfig::DEFAULT
        },
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let mut input = String::new();
    for _ in 0..8 {
        for _ in 0..2_047 {
            input.push('x');
        }
        input.push_str("\r\n");
    }
    engine.feed(input.as_bytes(), 0);
    engine.feed(b"\x1b[?1049h", 0);
    engine.quiesce(0);

    engine.resize(GridSize::new(1, 8), 0).expect("admitted");
    engine.quiesce(0);
    let records = engine.budget().usage().row_records;
    assert!(
        records > engine.budget().reserved().row_arrays,
        "the rows the reflow built are counted: {records} bytes of records against a reservation \
         of {}",
        engine.budget().reserved().row_arrays
    );
    assert!(engine.budget().committed() > engine.budget().reserved().total());

    engine.feed(b"\x1b[?1049l", 0);
    engine.quiesce(0);
    assert_eq!(
        engine.budget().excess(),
        0,
        "the rows past what the geometry keeps were dropped when the buffer came back"
    );
}
