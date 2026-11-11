//! Exactly one query responder, with no duplicate answers and no hangs.
//!
//! The dangerous failure here is not a wrong answer. It is a second answer, or none: an application
//! that asked one question and got two replies loses its place in its own input stream, and an
//! application that asked and got nothing waits.

use kr_term::engine::{Engine, EngineConfig};
use kr_term::lane::{LaneGate, LaneLimits};
use kr_term::modes::ModeKind;
use kr_term::profile::{CAPABILITIES, Capability};
use kr_term::snapshot::Viewport;
use kr_term::terminfo;

/// An engine at the profile default size, which is what an invisible session starts at.
fn engine() -> Engine {
    Engine::new(EngineConfig::default()).expect("engine")
}

const DEFAULT_ROWS: u32 = kr_term::budget::DEFAULT_SIZE.rows;
const DEFAULT_COLS: u32 = kr_term::budget::DEFAULT_SIZE.cols;

fn replies(engine: &mut Engine, input: &[u8], now_ms: u64) -> Vec<Vec<u8>> {
    engine.feed(input, now_ms);
    engine
        .lane_mut()
        .drain(LaneGate::default(), 1 << 20, 0)
        .into_iter()
        .map(|response| response.bytes().to_vec())
        .collect()
}

/// KR-REQ-08.48, the sentence "Only the query broker can create them": the device-attribute queries
/// are answered from the broker's lane, and the grid library writes no byte. Not shown here: that
/// nothing in the worker outside the lane queues a reply.
#[test]
fn the_profile_answers_device_attributes_and_never_a_physical_terminal() {
    let mut engine = engine();
    assert_eq!(replies(&mut engine, b"\x1b[c", 0), [b"\x1b[?62;22c"]);
    assert_eq!(replies(&mut engine, b"\x1b[>c", 0), [b"\x1b[>41;1;0c"]);
    assert_eq!(
        replies(&mut engine, b"\x1b[=c", 0),
        [b"\x1bP!|4B520001\x1b\\".to_vec()]
    );
    assert_eq!(
        replies(&mut engine, b"\x1b[>q", 0),
        [b"\x1bP>|KalaReach(kr-vt/1)\x1b\\".to_vec()]
    );
    assert_eq!(
        engine.grid().writer_log().bytes,
        0,
        "only the broker may answer"
    );
}

/// The identity never names the terminal the person is attached from.
#[test]
fn no_reply_carries_a_physical_terminal_identity() {
    let mut engine = engine();
    for query in [&b"\x1b[c"[..], b"\x1b[>c", b"\x1b[=c", b"\x1b[>q"] {
        for reply in replies(&mut engine, query, 0) {
            let text = String::from_utf8_lossy(&reply).to_lowercase();
            for name in ["xterm", "iterm", "ghostty", "wezterm", "vte", "kitty"] {
                assert!(
                    !text.contains(name),
                    "reply to {query:?} mentions {name}: {text}"
                );
            }
        }
    }
}

/// KR-ACC-001, the part about no duplicate answers: each cursor report query is answered by exactly
/// one reply from the broker's lane. Not shown here: a local and a remote client attached together
/// (the controller's network case) and a query that goes unanswered.
#[test]
fn a_cursor_report_describes_the_canonical_grid() {
    let mut engine = engine();
    assert_eq!(replies(&mut engine, b"\x1b[3;7H\x1b[6n", 0), [b"\x1b[3;7R"]);
    assert_eq!(
        replies(&mut engine, b"\x1b[?6n", 0),
        [b"\x1b[?3;7;1R".to_vec()]
    );
}

/// KR-REQ-08.41, the part about features negotiated outside terminfo: a mode query is answered from
/// what the profile tracks, and two features the profile has no capability for (grapheme clustering
/// and in-band resize) are reported as not recognised. Not shown here: a feature the profile has a
/// capability for being reported and honoured, which the next case shows, or any query other than a
/// mode report.
#[test]
fn mode_reports_say_what_the_profile_actually_does() {
    let mut engine = engine();
    // A tracked mode reports its state.
    assert_eq!(replies(&mut engine, b"\x1b[?7$p", 0), [b"\x1b[?7;1$y"]);
    assert_eq!(
        replies(&mut engine, b"\x1b[?7l\x1b[?7$p", 0),
        [b"\x1b[?7;2$y"]
    );
    // Grapheme clustering and in-band resize are not recognised, which is what lets an application
    // fall back rather than assume.
    assert_eq!(
        replies(&mut engine, b"\x1b[?2027$p", 0),
        [b"\x1b[?2027;0$y"]
    );
    assert_eq!(
        replies(&mut engine, b"\x1b[?2048$p", 0),
        [b"\x1b[?2048;0$y"]
    );
    // Columns belong to the geometry owner, permanently.
    assert_eq!(replies(&mut engine, b"\x1b[?3$p", 0), [b"\x1b[?3;4$y"]);
}

/// KR-REQ-08.41, the part about features negotiated outside terminfo: a feature the profile has a
/// capability for is reported and honoured. Bracketed paste, focus reporting, SGR mouse reporting
/// and synchronised output are capabilities the profile advertises, and an application negotiates
/// each as a DEC mode. The mode is reported as recognised before it is set, as set once the
/// application sets it and as reset once it resets it. The engine records it, tells a client of the
/// change in the delta it serves and in a snapshot, and keeps it through a soft reset. The control
/// is a pair of modes the profile has no capability for (grapheme clustering and in-band resize):
/// an application can set them, and they stay unrecognised, unrecorded and untold. Not shown here:
/// what a client's renderer, or the host's input encoding, does with a mode it is told (only the
/// paste framing of 2004 is read back); that the capability and the tracked mode are one list
/// (each mode is in both); a Kitty keyboard flag (which is not a mode report); or any query other
/// than a mode report.
#[test]
fn a_feature_the_profile_has_a_capability_for_is_reported_and_honoured() {
    /// Where a client's screen stands: the cursor and generation it would name as its base.
    fn base(engine: &Engine) -> (u64, u64) {
        (engine.output_cursor(), engine.projection_generation())
    }
    /// What a client is told of `mode` since `base`, in a delta and in a snapshot.
    fn told(engine: &mut Engine, base: (u64, u64), mode: u16) -> (Option<bool>, Option<bool>) {
        let delta = engine.delta(base.0, base.1).expect("inside the window");
        let viewport = Viewport {
            top_row: 0,
            rows: engine.grid().size().rows,
            left_col: 0,
            cols: engine.grid().size().cols,
        };
        let (snapshot, _) = engine.snapshot(viewport, 0);
        let find = |entries: &[kr_term::snapshot::ModeEntry]| {
            entries
                .iter()
                .find(|entry| entry.mode == mode)
                .map(|entry| entry.enabled)
        };
        (find(&delta.modes), find(&snapshot.modes))
    }

    for (capability, mode) in [
        (Capability::BracketedPaste, 2004_u16),
        (Capability::FocusEvents, 1004),
        (Capability::SgrMouse, 1006),
        (Capability::SynchronisedOutput, 2026),
    ] {
        assert!(
            CAPABILITIES.contains(&capability),
            "{capability:?} is a capability of the profile"
        );
        let mut engine = engine();
        engine.feed(b"first line\r\n", 0);
        let ask = format!("\x1b[?{mode}$p").into_bytes();
        let report = |status: u8| vec![format!("\x1b[?{mode};{status}$y").into_bytes()];

        // Recognised before the application sets it: reset, and no change for a client to be told.
        let held = base(&engine);
        assert_eq!(replies(&mut engine, &ask, 0), report(2), "{mode}");
        assert!(!engine.modes().is_set(ModeKind::Dec, mode));
        assert_eq!(
            told(&mut engine, held, mode),
            (None, Some(false)),
            "{mode} is in a snapshot as reset, and a delta carries no change of it"
        );

        // Set by the application: reported as set, recorded, and told to a client both ways.
        let held = base(&engine);
        engine.feed(format!("\x1b[?{mode}h").as_bytes(), 0);
        assert_eq!(replies(&mut engine, &ask, 0), report(1), "{mode}");
        assert!(engine.modes().is_set(ModeKind::Dec, mode), "{mode}");
        assert_eq!(
            told(&mut engine, held, mode),
            (Some(true), Some(true)),
            "{mode} is carried to a client in the delta and in a snapshot"
        );
        if mode == 2004 {
            assert!(engine.bracketed_paste(), "the host frames a paste by it");
        }

        // A soft reset leaves it as the application set it.
        engine.feed(b"\x1b[!p", 0);
        assert_eq!(
            replies(&mut engine, &ask, 0),
            report(1),
            "{mode} after DECSTR"
        );

        // Reset by the application: reported as reset, and told to a client as reset.
        let held = base(&engine);
        engine.feed(format!("\x1b[?{mode}l").as_bytes(), 0);
        assert_eq!(replies(&mut engine, &ask, 0), report(2), "{mode}");
        assert_eq!(
            told(&mut engine, held, mode),
            (Some(false), Some(false)),
            "{mode}"
        );
    }

    // The control: modes the profile has no capability for, set the same way.
    let mut engine = engine();
    engine.feed(b"first line\r\n", 0);
    let held = base(&engine);
    engine.feed(b"\x1b[?2027h\x1b[?2048h", 0);
    assert_eq!(
        replies(&mut engine, b"\x1b[?2027$p\x1b[?2048$p", 0),
        [b"\x1b[?2027;0$y".to_vec(), b"\x1b[?2048;0$y".to_vec()],
        "setting them does not make the profile support them"
    );
    for mode in [2027_u16, 2048] {
        assert!(!engine.modes().is_set(ModeKind::Dec, mode), "{mode}");
        assert_eq!(told(&mut engine, held, mode), (None, None), "{mode}");
    }
}

#[test]
fn geometry_reports_describe_the_canonical_size() {
    let mut engine = engine();
    let text_area = format!("\x1b[8;{DEFAULT_ROWS};{DEFAULT_COLS}t").into_bytes();
    let screen = format!("\x1b[9;{DEFAULT_ROWS};{DEFAULT_COLS}t").into_bytes();
    assert_eq!(replies(&mut engine, b"\x1b[18t", 0), [text_area]);
    assert_eq!(replies(&mut engine, b"\x1b[19t", 0), [screen]);
    // kr-vt/1 has no pixel geometry, and says so rather than inventing one.
    assert_eq!(replies(&mut engine, b"\x1b[14t", 0), [b"\x1b[4;0;0t"]);
    assert_eq!(replies(&mut engine, b"\x1b[11t", 0), [b"\x1b[1t"]);
}

/// A window-resize request is consumed and the canonical size does not move.
#[test]
fn a_resize_request_changes_nothing_but_still_reports_honestly() {
    let mut engine = engine();
    engine.feed(b"\x1b[8;60;200t\x1b[?3h", 0);
    assert_eq!(engine.grid().size().rows, DEFAULT_ROWS);
    assert_eq!(engine.grid().size().cols, DEFAULT_COLS);
    let text_area = format!("\x1b[8;{DEFAULT_ROWS};{DEFAULT_COLS}t").into_bytes();
    assert_eq!(replies(&mut engine, b"\x1b[18t", 0), [text_area]);
}

#[test]
fn setting_reports_come_from_canonical_state() {
    let mut engine = engine();
    assert_eq!(
        replies(&mut engine, b"\x1b[1;4;31mx\x1bP$qm\x1b\\", 0),
        [b"\x1bP1$r0;1;4;31m\x1b\\".to_vec()]
    );
    assert_eq!(
        replies(&mut engine, b"\x1b[3;12r\x1bP$qr\x1b\\", 0),
        [b"\x1bP1$r3;12r\x1b\\".to_vec()]
    );
    // An unsupported setting gets the defined failure, not silence and not a guess.
    assert_eq!(
        replies(&mut engine, b"\x1bP$qZZ\x1b\\", 0),
        [b"\x1bP0$r\x1b\\".to_vec()]
    );
}

#[test]
fn capability_reports_come_from_the_pinned_database() {
    let mut engine = engine();
    // "TN" hex-encoded asks for the terminal name.
    let expected = format!(
        "\x1bP1+r{}={}\x1b\\",
        terminfo::to_hex(b"TN"),
        terminfo::to_hex(terminfo::TERMINAL_NAME.as_bytes())
    );
    assert_eq!(
        replies(&mut engine, b"\x1bP+q544e\x1b\\", 0),
        [expected.into_bytes()]
    );
    // An unknown capability gets the defined failure reply, not silence. The name comes back in
    // the responder's own hex, never as the bytes the request happened to use.
    assert_eq!(
        replies(&mut engine, b"\x1bP+q7a7a7a\x1b\\", 0),
        [b"\x1bP0+r7A7A7A\x1b\\".to_vec()]
    );

    // A name that is not a capability name is answered without being repeated at all, so an
    // application cannot choose the bytes that travel on the trusted lane.
    let reflected = replies(&mut engine, b"\x1bP+q0d0a41424321\x1b\\", 0);
    assert_eq!(reflected, [b"\x1bP0+r\x1b\\".to_vec()]);
    // Several names in one request produce one reply each, in order.
    let many = replies(&mut engine, b"\x1bP+q544e;436f;7a7a\x1b\\", 0);
    assert_eq!(many.len(), 3);
    assert!(many[2].as_slice().starts_with(b"\x1bP0+r"));
}

#[test]
fn colour_reports_describe_the_session_palette() {
    let mut engine = engine();
    assert_eq!(
        replies(
            &mut engine,
            b"\x1b]4;1;rgb:12/34/56\x1b\\\x1b]4;1;?\x1b\\",
            0
        ),
        [b"\x1b]4;1;rgb:1212/3434/5656\x1b\\".to_vec()]
    );
    // The reply matches the terminator the request used.
    assert_eq!(
        replies(&mut engine, b"\x1b]11;?\x07", 0),
        [b"\x1b]11;rgb:0000/0000/0000\x07".to_vec()]
    );
}

#[test]
fn enquiry_is_consumed_and_answered_with_silence() {
    let mut engine = engine();
    let outcome = engine.feed(b"\x05", 0);
    assert!(outcome.forward.is_empty(), "ENQ never travels onwards");
    assert_eq!(outcome.responses, 0, "kr-vt/1 has no answerback string");
}

/// KR-REQ-08.50: a query flood is bounded three ways, says so out of band, and forwards nothing.
#[test]
fn a_query_flood_degrades_instead_of_allocating() {
    let mut engine = engine();
    let mut flood = Vec::new();
    for _ in 0..5_000 {
        flood.extend_from_slice(b"\x1b[c");
    }
    let outcome = engine.feed(&flood, 0);
    assert!(
        outcome.degradation.is_degraded(),
        "a flood must produce explicit degraded status"
    );
    assert!(
        outcome.degradation.over_budget > 0,
        "the per-second budget must bind"
    );
    assert!(
        engine.lane().queued_bytes() <= LaneLimits::DEFAULT.max_queue_bytes,
        "the queue stayed inside its bound"
    );
    assert!(
        outcome.forward.is_empty(),
        "flood handling never forwards a query onwards"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == kr_term::diag::DiagnosticKind::ResponseLaneDegraded),
        "the degradation is reported out of band"
    );
}

/// KR-REQ-08.50: human input is never starved; the lane hands over only what the caller asked for.
#[test]
fn the_lane_respects_the_callers_byte_budget() {
    let mut engine = engine();
    // Ten cursor reports, which the lane never coalesces.
    engine.feed(&b"\x1b[6n".repeat(10), 0);
    assert_eq!(engine.lane().pending(), 10);

    // A budget smaller than one reply takes nothing at all.
    assert!(
        engine
            .lane_mut()
            .drain(LaneGate::default(), 0, 0)
            .is_empty()
    );
    assert!(
        engine
            .lane_mut()
            .drain(LaneGate::default(), 1, 0)
            .is_empty()
    );

    let first = engine.lane_mut().drain(LaneGate::default(), 20, 0);
    assert!(
        !first.is_empty() && first.len() < 10,
        "the drain stopped at the byte budget"
    );
    assert!(engine.lane().pending() > 0, "the rest is still waiting");
}

/// KR-REQ-08.48: a reply never lands inside an unfinished paste or a half-delivered human input
/// frame, unless the backend is qualified to take it inside a paste.
#[test]
fn a_reply_waits_for_the_session_loop() {
    let mut engine = engine();
    engine.feed(b"\x1b[c", 0);

    let paste_open = LaneGate {
        paste_open: true,
        backend_handles_paste_interleave: false,
        human_frame_open: false,
        cursor_report_first: false,
    };
    assert!(engine.lane_mut().drain(paste_open, 4096, 0).is_empty());

    let mid_frame = LaneGate {
        human_frame_open: true,
        ..LaneGate::default()
    };
    assert!(engine.lane_mut().drain(mid_frame, 4096, 0).is_empty());

    let qualified = LaneGate {
        paste_open: true,
        backend_handles_paste_interleave: true,
        human_frame_open: false,
        cursor_report_first: false,
    };
    assert_eq!(engine.lane_mut().drain(qualified, 4096, 0).len(), 1);
}

/// KR-REQ-08.50: nothing the lane has dropped can be written afterwards: a reset leaves no reply
/// pending and none to drain.
///
/// KR-ACC-001, the part about no late duplicate: a reset leaves no reply pending and none to drain,
/// so a reply the lane never delivered is not written afterwards. Not shown here: a local and a
/// remote client attached together.
#[test]
fn undelivered_replies_are_not_replayed_after_a_reset() {
    let mut engine = engine();
    engine.feed(b"\x1b[c\x1b[c", 0);
    assert!(engine.lane().pending() > 0);
    engine.lane_mut().reset();
    assert_eq!(engine.lane().pending(), 0);
    assert!(
        engine
            .lane_mut()
            .drain(LaneGate::default(), 4096, 0)
            .is_empty()
    );
}

/// KR-REQ-08.49: a deferred reply shares the lane's bounded deadline, and one that waited past it
/// is dropped rather than written.
#[test]
fn a_stale_reply_is_dropped_rather_than_written() {
    let mut engine = engine();
    engine.feed(b"\x1b[6n", 0);
    let deadline = LaneLimits::DEFAULT.reply_deadline_ms;
    let replies = engine
        .lane_mut()
        .drain(LaneGate::default(), 4096, deadline + 1);
    assert!(replies.is_empty(), "the answer is no longer worth writing");
    assert!(engine.lane().degradation().expired > 0);
}

/// The gate of a session whose root editor is owed the reply to its cursor question.
fn owed() -> LaneGate {
    LaneGate {
        cursor_report_first: true,
        ..LaneGate::default()
    }
}

fn is_a_cursor_report(reply: &[u8]) -> bool {
    reply.starts_with(b"\x1b[") && reply.ends_with(b"R")
}

/// KR-REQ-08.48, KR-REQ-08.49: the root editor reads the reply to its cursor question from the same
/// input as everything else the terminal sends, and bytes that come ahead of it are read as part of
/// it. While the editor is owed that reply the lane lets the cursor report out first, and the
/// replies to the queries that came before it follow in their own order.
#[test]
fn a_cursor_report_goes_ahead_of_the_replies_that_came_before_it() {
    let mut engine = engine();
    engine.feed(b"\x1b[c\x1b[>c\x1b[6n", 0);
    let drained = engine.lane_mut().drain(owed(), 1 << 20, 0);
    let bytes: Vec<&[u8]> = drained.iter().map(|reply| reply.bytes()).collect();
    assert_eq!(bytes.len(), 3);
    assert!(
        is_a_cursor_report(bytes[0]),
        "the report is first: {bytes:?}"
    );
    assert_eq!(&bytes[1..], [&b"\x1b[?62;22c"[..], b"\x1b[>41;1;0c"]);

    // A session whose editor is owed nothing keeps the order of the queries.
    let mut engine = self::engine();
    engine.feed(b"\x1b[c\x1b[>c\x1b[6n", 0);
    let drained = engine.lane_mut().drain(LaneGate::default(), 1 << 20, 0);
    let bytes: Vec<&[u8]> = drained.iter().map(|reply| reply.bytes()).collect();
    assert_eq!(bytes[0], b"\x1b[?62;22c");
    assert!(
        is_a_cursor_report(bytes[2]),
        "the report is last: {bytes:?}"
    );
}

/// KR-REQ-08.48: a reply the hold keeps waits for the cursor report however long that takes, and is
/// then written, not dropped: it did not age while it was kept.
#[test]
fn a_reply_kept_for_the_cursor_report_is_written_after_it_whatever_it_waited() {
    let mut engine = engine();
    let deadline = LaneLimits::DEFAULT.reply_deadline_ms;
    engine.feed(b"\x1b[c", 0);
    assert!(engine.lane_mut().drain(owed(), 4096, 0).is_empty());
    assert!(
        engine
            .lane_mut()
            .drain(owed(), 4096, 5 * deadline)
            .is_empty()
    );
    assert_eq!(engine.lane().pending(), 1, "kept, not dropped");
    assert_eq!(engine.lane().degradation().expired, 0);

    // The editor's question arrives long after the answer was kept.
    engine.feed(b"\x1b[6n", 5 * deadline);
    let drained = engine.lane_mut().drain(owed(), 4096, 5 * deadline);
    let bytes: Vec<&[u8]> = drained.iter().map(|reply| reply.bytes()).collect();
    assert_eq!(bytes.len(), 2);
    assert!(is_a_cursor_report(bytes[0]));
    assert_eq!(bytes[1], b"\x1b[?62;22c");
    assert_eq!(engine.lane().degradation().expired, 0);
}

/// KR-REQ-08.49: the hold does not lengthen a reply's life when no cursor report ends it. A reply
/// kept while the editor was owed one and still unwritten when the editor is not owed it any more
/// has waited past its deadline, and is dropped as one is behind a paste: an answer that old would
/// reach whatever reads next, which did not ask.
#[test]
fn a_reply_the_hold_ends_without_a_cursor_report_keeps_its_deadline() {
    let mut engine = engine();
    let deadline = LaneLimits::DEFAULT.reply_deadline_ms;
    engine.feed(b"\x1b[c", 0);
    assert!(engine.lane_mut().drain(owed(), 4096, 0).is_empty());
    engine.lane_mut().end_hold();
    let drained = engine
        .lane_mut()
        .drain(LaneGate::default(), 4096, 5 * deadline);
    assert!(drained.is_empty(), "no answer that old is written");
    assert_eq!(engine.lane().degradation().expired, 1);
    assert_eq!(engine.lane().queued_bytes(), 0);
}

/// KR-REQ-08.49: a hold that ended without a cursor report is over, even when no look at the lane
/// with the gate open came between it and the next hold. The time between the two is not time the
/// next report gives back: the reply the first hold kept has waited past its deadline by then and
/// is dropped when the second hold looks at it.
#[test]
fn the_time_between_two_holds_is_not_given_back_to_a_reply_the_first_kept() {
    let mut engine = engine();
    let deadline = LaneLimits::DEFAULT.reply_deadline_ms;
    engine.feed(b"\x1b[c", 0);
    assert!(engine.lane_mut().drain(owed(), 4096, 0).is_empty());

    // The editor stops being owed its report while the gate is shut, and is owed one again.
    engine.lane_mut().end_hold();
    let shut = LaneGate {
        paste_open: true,
        ..owed()
    };
    assert!(engine.lane_mut().drain(shut, 4096, 5 * deadline).is_empty());
    engine.feed(b"\x1b[6n", 6 * deadline);
    let drained = engine.lane_mut().drain(owed(), 4096, 6 * deadline);
    let bytes: Vec<&[u8]> = drained.iter().map(|reply| reply.bytes()).collect();
    assert_eq!(bytes.len(), 1, "only the report: {bytes:?}");
    assert!(is_a_cursor_report(bytes[0]));
    assert_eq!(engine.lane().degradation().expired, 1);
    assert_eq!(engine.lane().queued_bytes(), 0);
}

/// KR-REQ-08.49: a reply that had already waited past its deadline when the hold first kept it is
/// dropped then, as it is at any other look.
#[test]
fn a_reply_already_past_its_deadline_is_not_kept_by_the_hold() {
    let mut engine = engine();
    let deadline = LaneLimits::DEFAULT.reply_deadline_ms;
    engine.feed(b"\x1b[c", 0);
    assert!(
        engine
            .lane_mut()
            .drain(owed(), 4096, deadline + 1)
            .is_empty()
    );
    assert_eq!(engine.lane().pending(), 0);
    assert_eq!(engine.lane().degradation().expired, 1);
    assert_eq!(engine.lane().queued_bytes(), 0);
}

/// KR-REQ-08.49: a cursor report that has waited past its deadline is dropped, as any reply is, and
/// does not carry the replies held behind it out with it.
#[test]
fn a_cursor_report_past_its_deadline_is_dropped_and_releases_nothing() {
    let mut engine = engine();
    let deadline = LaneLimits::DEFAULT.reply_deadline_ms;
    engine.feed(b"\x1b[c", 0);
    assert!(engine.lane_mut().drain(owed(), 4096, 0).is_empty());
    engine.feed(b"\x1b[6n", 1);
    assert!(
        engine
            .lane_mut()
            .drain(owed(), 4096, deadline + 2)
            .is_empty()
    );
    assert_eq!(engine.lane().degradation().expired, 1, "the report lapsed");
    assert_eq!(engine.lane().pending(), 1, "the answer is still kept");
    assert_eq!(
        engine.lane().queued_bytes(),
        b"\x1b[?62;22c".len(),
        "and counted"
    );
}

/// KR-REQ-08.50: a cursor report the caller's byte budget cannot take yet does not let another
/// reply go ahead of it.
#[test]
fn nothing_goes_ahead_of_a_cursor_report_that_does_not_fit_the_budget_yet() {
    let mut engine = engine();
    engine.feed(b"\x1b[c\x1b[6n", 0);
    assert!(engine.lane_mut().drain(owed(), 1, 0).is_empty());
    assert_eq!(engine.lane().pending(), 2);
    let drained = engine.lane_mut().drain(owed(), 4096, 0);
    assert_eq!(drained.len(), 2);
    assert!(is_a_cursor_report(drained[0].bytes()));
}

/// KR-REQ-08.50: the burst budget refills over time rather than granting one burst for the life of
/// the session.
#[test]
fn the_reply_budget_refills() {
    let mut engine = Engine::new(EngineConfig {
        lane: LaneLimits {
            responses_per_second: 4,
            ..LaneLimits::DEFAULT
        },
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let outcome = engine.feed(&b"\x1b[6n".repeat(6), 0);
    assert_eq!(outcome.responses, 4, "the burst is four replies");
    assert!(outcome.degradation.over_budget >= 2);

    let outcome = engine.feed(b"\x1b[6n", 250);
    assert_eq!(outcome.responses, 1, "a quarter second buys one more");
}

/// KR-REQ-08.50: the lane holds replies to the profile's bounds: a qualified response size, a
/// 128 KiB queue and a burst of 256 replies a second. A reply past its size bound is refused and
/// reported rather than queued, and a burst past the budget degrades rather than growing.
#[test]
fn the_lane_holds_its_replies_to_the_profiles_bounds() {
    assert_eq!(LaneLimits::DEFAULT.max_queue_bytes, 128 * 1024);
    assert_eq!(LaneLimits::DEFAULT.responses_per_second, 256);
    const { assert!(LaneLimits::DEFAULT.max_response_bytes <= LaneLimits::DEFAULT.max_queue_bytes) };

    // A thousand cursor reports at one instant, which the lane never coalesces: the burst is
    // answered and the rest is over budget, reported rather than queued.
    let mut engine = engine();
    let outcome = engine.feed(&b"\x1b[6n".repeat(1_000), 0);
    assert_eq!(outcome.responses, 256, "the burst is 256 replies");
    assert_eq!(outcome.degradation.over_budget, 1_000 - 256);
    assert!(outcome.degradation.is_degraded());
    assert!(engine.lane().queued_bytes() <= LaneLimits::DEFAULT.max_queue_bytes);
    assert!(outcome.forward.is_empty(), "no query is forwarded instead");

    // A reply larger than the qualified response size is never queued.
    let mut bounded = Engine::new(EngineConfig {
        lane: LaneLimits {
            max_response_bytes: 4,
            ..LaneLimits::DEFAULT
        },
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let outcome = bounded.feed(b"\x1b[c", 0);
    assert_eq!(outcome.responses, 0);
    assert_eq!(outcome.degradation.oversized, 1);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == kr_term::diag::DiagnosticKind::ResponseLaneDegraded),
        "the refusal is reported out of band"
    );
    assert_eq!(bounded.lane().pending(), 0);
}

/// KR-REQ-08.50: under a full queue the lane coalesces only answers about the same subject. A
/// report about a mode that is already waiting replaces the earlier report about that mode, and the
/// newer answer is the one kept; a report about a different mode never stands in for another one,
/// and is refused and counted instead.
#[test]
fn coalescing_keeps_different_subjects_apart() {
    // A queue that holds two mode reports and not three.
    let config = EngineConfig {
        lane: LaneLimits {
            max_queue_bytes: 24,
            ..LaneLimits::DEFAULT
        },
        ..EngineConfig::DEFAULT
    };
    let drained = |engine: &mut Engine| -> Vec<Vec<u8>> {
        engine
            .lane_mut()
            .drain(LaneGate::default(), 1 << 20, 0)
            .into_iter()
            .map(|reply| reply.bytes().to_vec())
            .collect()
    };

    // Reports about auto-wrap and the cursor's visibility fill the queue. A report about bracketed
    // paste does not fit, and nothing about bracketed paste is waiting to give way to it.
    let mut different = Engine::new(config).expect("engine");
    different.feed(b"\x1b[?7$p\x1b[?25$p\x1b[?2004$p", 0);
    let shed = different.lane().degradation();
    assert_eq!(
        drained(&mut different),
        [b"\x1b[?7;1$y".to_vec(), b"\x1b[?25;1$y".to_vec()],
        "the two reports that fitted are kept, each about its own mode"
    );
    assert_eq!(shed.coalesced, 0, "no report stood in for another mode's");
    assert_eq!(shed.dropped, 1, "the report that did not fit is counted");

    // The same two reports, then auto-wrap is turned off and asked about again. The newer report
    // about auto-wrap replaces the older one, which is the only one that could give way to it.
    let mut same = Engine::new(config).expect("engine");
    same.feed(b"\x1b[?7$p\x1b[?25$p\x1b[?7l\x1b[?7$p", 0);
    let shed = same.lane().degradation();
    assert_eq!(
        drained(&mut same),
        [b"\x1b[?25;1$y".to_vec(), b"\x1b[?7;2$y".to_vec()],
        "the newer answer about auto-wrap is kept, and the report about the cursor is untouched"
    );
    assert_eq!(shed.coalesced, 1, "the older report was coalesced");
    assert_eq!(shed.dropped, 0);
}

/// A colour request that mixes mutations with questions does both.
#[test]
fn a_mixed_colour_request_applies_and_answers() {
    let mut engine = engine();
    let answers = replies(&mut engine, b"\x1b]4;1;#ff0000;2;?\x1b\\", 0);
    assert_eq!(answers.len(), 1, "the question is answered");
    // And the mutation in the same request really happened.
    assert_eq!(
        replies(&mut engine, b"\x1b]4;1;?\x1b\\", 0),
        [b"\x1b]4;1;rgb:ffff/0000/0000\x1b\\".to_vec()]
    );
}

/// A dynamic-colour request addresses consecutive selectors.
#[test]
fn a_dynamic_colour_list_sets_each_colour_in_turn() {
    let mut engine = engine();
    engine.feed(b"\x1b]10;#112233;#445566\x1b\\", 0);
    assert_eq!(
        replies(&mut engine, b"\x1b]10;?\x1b\\", 0),
        [b"\x1b]10;rgb:1111/2222/3333\x1b\\".to_vec()]
    );
    assert_eq!(
        replies(&mut engine, b"\x1b]11;?\x1b\\", 0),
        [b"\x1b]11;rgb:4444/5555/6666\x1b\\".to_vec()]
    );
}

/// KR-REQ-08.30: a reset puts a dynamic colour back to what the session started with. When that
/// was a client's own palette, the reset returns to the palette the client shared and not to the
/// profile's preset, and so does a full reset.
#[test]
fn a_colour_reset_returns_to_the_palette_the_session_adopted() {
    let mut engine = engine();
    engine.adopt_palette(kr_term::palette::Palette::from_client_preference(
        kr_term::palette::Rgb::new(1, 2, 3),
        kr_term::palette::Rgb::new(4, 5, 6),
    ));
    let adopted_foreground = || b"\x1b]10;rgb:0101/0202/0303\x1b\\".to_vec();
    let adopted_background = || b"\x1b]11;rgb:0404/0505/0606\x1b\\".to_vec();

    // An application changes both colours, then resets them one at a time.
    engine.feed(b"\x1b]10;#aabbcc\x1b\\\x1b]11;#ddeeff\x1b\\", 0);
    engine.feed(b"\x1b]110\x1b\\\x1b]111\x1b\\", 0);
    assert_eq!(
        replies(&mut engine, b"\x1b]10;?\x1b\\", 0),
        [adopted_foreground()]
    );
    assert_eq!(
        replies(&mut engine, b"\x1b]11;?\x1b\\", 0),
        [adopted_background()]
    );

    // A full reset undoes an application's changes to the colours as well.
    engine.feed(b"\x1b]10;#aabbcc\x1b\\\x1b]4;1;#112233\x1b\\\x1bc", 0);
    assert_eq!(
        replies(&mut engine, b"\x1b]10;?\x1b\\", 0),
        [adopted_foreground()]
    );
    assert_eq!(
        replies(&mut engine, b"\x1b]4;1;?\x1b\\", 0),
        [b"\x1b]4;1;rgb:cdcd/0000/0000\x1b\\".to_vec()],
        "and the indexed colours are the profile's"
    );
}

/// A cursor report under origin mode is relative to the margins.
#[test]
fn a_cursor_report_honours_origin_mode() {
    let mut engine = engine();
    // Absolute row 3 is origin-relative row 1 once the scroll region starts there.
    assert_eq!(
        replies(&mut engine, b"\x1b[3;12r\x1b[?6h\x1b[H\x1b[6n", 0),
        [b"\x1b[1;1R"]
    );
    // Without origin mode the same screen position reports its absolute coordinates.
    assert_eq!(
        replies(&mut engine, b"\x1b[?6l\x1b[3;1H\x1b[6n", 0),
        [b"\x1b[3;1R"]
    );
}

/// A colour request is executed once, in order, and each answer comes from the palette at that
/// point in the request.
///
/// KR-ACC-001, the part about no duplicate answers: a colour request with two questions is answered
/// by exactly two replies, once each and in order. Not shown here: a local and a remote client
/// attached together, and a query that goes unanswered.
#[test]
fn a_colour_request_answers_from_the_palette_at_each_question() {
    let mut engine = engine();
    replies(&mut engine, b"\x1b]4;1;#112233\x07", 0);
    let answers = replies(&mut engine, b"\x1b]4;1;?;1;#ff0000;1;?\x07", 10);
    assert_eq!(
        answers,
        vec![
            b"\x1b]4;1;rgb:1111/2222/3333\x07".to_vec(),
            b"\x1b]4;1;rgb:ffff/0000/0000\x07".to_vec(),
        ],
        "the first question is about the colour before the change, not after it"
    );
}

/// A request that both asks and changes has changed something a direct terminal never saw.
#[test]
fn a_colour_request_that_also_changes_requires_projection() {
    let mut engine = engine();
    let outcome = engine.feed(b"\x1b]4;1;#ff0000;2;?\x07", 0);
    assert!(outcome.forward.is_empty());
    assert!(
        outcome.projection_required_at.is_some(),
        "the canonical palette changed and the bytes stopped here"
    );
}

/// A colour field that is neither a question nor a colour makes the whole request an extension.
#[test]
fn an_unusable_colour_field_refuses_the_whole_request() {
    for input in [
        b"\x1b]4;1;red\x07".as_slice(),
        b"\x1b]4;1;?\0\x07".as_slice(),
        b"\x1b]4;1\x07".as_slice(),
        b"\x1b]10;chartreuse\x07".as_slice(),
    ] {
        let mut engine = engine();
        let outcome = engine.feed(input, 0);
        assert!(outcome.forward.is_empty(), "{input:?} reached a terminal");
        assert_eq!(outcome.responses, 0, "{input:?} was answered");
        assert_eq!(
            engine.grid().writer_log().bytes,
            0,
            "{input:?} made the grid library write a reply"
        );
    }
}

/// Two capability names never share a reply subject, whatever they hash to.
#[test]
fn two_capability_answers_are_never_collapsed_into_one() {
    let mut engine = Engine::new(EngineConfig {
        lane: LaneLimits {
            max_queue_bytes: 64,
            ..LaneLimits::DEFAULT
        },
        ..EngineConfig::default()
    })
    .expect("engine");
    // These two names collide under a 32-bit FNV-1a hash.
    let request = format!(
        "\x1bP+q{}\x1b\\\x1bP+q{}\x1b\\",
        terminfo::to_hex(b"costarring"),
        terminfo::to_hex(b"liquid")
    );
    let answers = replies(&mut engine, request.as_bytes(), 0);
    assert_eq!(answers.len(), 2, "one answer stood in for the other");
}

/// KR-REQ-01.11: the mouse tracking is one state, as xterm and Terminal.app keep it.
///
/// A set of 1000, 1002 or 1003 makes that one the tracking and clears the other two, and a reset of
/// any of the three turns tracking off whichever of them had set it. What the session answers a
/// mode query with, what a snapshot holds and what a delta carries all follow, so that a terminal
/// that is drawn the screen is put where the application's own terminal would be.
#[test]
fn the_mouse_tracking_is_one_state_as_a_terminal_keeps_it() {
    let tracking_after = |input: &[u8]| {
        let mut engine = engine();
        engine.feed(input, 0);
        [1000_u16, 1002, 1003].map(|mode| engine.modes().is_set(ModeKind::Dec, mode))
    };
    // The application's own history, and the one state its terminal would hold after it.
    assert_eq!(
        tracking_after(b"\x1b[?1000h\x1b[?1002h"),
        [false, true, false]
    );
    assert_eq!(
        tracking_after(b"\x1b[?1003h\x1b[?1000h"),
        [true, false, false]
    );
    assert_eq!(tracking_after(b"\x1b[?1002h\x1b[?1000l"), [false; 3]);
    assert_eq!(
        tracking_after(b"\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1003l"),
        [false; 3]
    );
    // The answer to a mode query says the same: only the tracking in force is set.
    let mut engine = engine();
    engine.feed(b"\x1b[?1000h\x1b[?1002h", 0);
    assert_eq!(
        replies(&mut engine, b"\x1b[?1000$p\x1b[?1002$p\x1b[?1003$p", 0),
        [
            b"\x1b[?1000;2$y".to_vec(),
            b"\x1b[?1002;1$y".to_vec(),
            b"\x1b[?1003;2$y".to_vec()
        ]
    );
    engine.feed(b"\x1b[?1002h\x1b[?1000l", 0);
    assert_eq!(
        replies(&mut engine, b"\x1b[?1000$p\x1b[?1002$p\x1b[?1003$p", 0),
        [
            b"\x1b[?1000;2$y".to_vec(),
            b"\x1b[?1002;2$y".to_vec(),
            b"\x1b[?1003;2$y".to_vec()
        ]
    );
    // A delta carries every flag the change cleared, and a snapshot holds the one state, so a client
    // that applies either is not left holding a flag the session no longer has.
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    engine.feed(b"\x1b[?1000h", 0);
    let base = (engine.output_cursor(), engine.projection_generation());
    engine.feed(b"\x1b[?1002h", 0);
    let delta = engine.delta(base.0, base.1).expect("inside the window");
    let carried: Vec<(u16, bool)> = delta
        .modes
        .iter()
        .filter(|entry| matches!(entry.mode, 1000 | 1002 | 1003))
        .map(|entry| (entry.mode, entry.enabled))
        .collect();
    assert_eq!(carried, [(1000, false), (1002, true), (1003, false)]);
    let (snapshot, _) = engine.snapshot(
        Viewport {
            top_row: 0,
            rows: engine.grid().size().rows,
            left_col: 0,
            cols: engine.grid().size().cols,
        },
        0,
    );
    let held: Vec<(u16, bool)> = snapshot
        .modes
        .iter()
        .filter(|entry| matches!(entry.mode, 1000 | 1002 | 1003))
        .map(|entry| (entry.mode, entry.enabled))
        .collect();
    assert_eq!(held, [(1000, false), (1002, true), (1003, false)]);
}
