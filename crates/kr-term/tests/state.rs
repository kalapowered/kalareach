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
    assert!(!primary.charsets.shift_out);

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
        .resize(kr_term::budget::GridSize::new(40, 12))
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
    assert_eq!(
        engine.budget().usage().rows,
        engine.grid().history_bytes(),
        "the budget knows what the rows cost after the read that made them"
    );
    assert!(
        engine.budget().usage().rows <= kr_term::budget::BudgetLimits::DEFAULT.row_cache_bytes,
        "the rows past the bound are gone, without waiting for more output"
    );
}

/// What printing adds is charged as it is applied, so the bound holds between two measurements.
#[test]
fn printing_is_charged_before_anything_measures_it() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(8, 2),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    // True colour, so every cell keeps an allocation of its own for its attributes.
    engine.feed(b"\x1b[38;2;10;20;30mabcdefgh", 0);
    let charged = engine.budget().usage().screen_content[0];
    assert!(
        charged > 0,
        "what was printed is charged before a measurement looks at it"
    );

    // Printing through the same cells cannot charge more than those cells can hold, however much
    // goes through them.
    let ceiling = engine.grid().screen_content_ceiling();
    for _ in 0..128 {
        engine.feed(b"\x1b[H\x1b[38;2;10;20;30mabcdefgh", 0);
        assert!(
            engine.budget().usage().screen_content[0] <= ceiling,
            "a buffer is never charged more than its cells can hold"
        );
    }
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
    let measured = engine.grid().screen_link_bytes();
    assert!(measured > 0, "a link on the screen is resident state");
    assert!(
        measured <= reserved,
        "measured {measured} bytes against a reservation of {reserved}"
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
        engine.grid().screen_content_bytes()
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
    assert!(engine.budget().usage().screen_content[0] > 0);

    engine.feed(b"\x1b[?1049h", 0);
    assert!(
        engine.budget().usage().screen_content[0] > 0,
        "the primary buffer still holds its rows while the alternate one is showing"
    );
    assert_eq!(
        engine.budget().usage().screen_content[1],
        0,
        "the alternate buffer has nothing on it yet"
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
    assert!(
        counted.budget().usage().metadata > 8 * 256,
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
    assert_eq!(oversized.budget().usage().metadata, 0);
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
        .resize(kr_term::budget::GridSize::new(8, 3))
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
        engine.budget().usage().screen_links[0] > 0,
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
    assert!(engine.budget().usage().screen_links[0] > 0);
    engine.feed(b"\x1bc", 0);
    engine.quiesce(0);
    assert_eq!(
        engine.budget().usage().screen_links,
        [0, 0],
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
