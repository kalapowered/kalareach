//! KR-ACC-001: exactly one query responder, with no duplicate answers and no hangs.
//!
//! The dangerous failure here is not a wrong answer. It is a second answer, or none: an application
//! that asked one question and got two replies loses its place in its own input stream, and an
//! application that asked and got nothing waits.

use kr_term::engine::{Engine, EngineConfig};
use kr_term::lane::{LaneGate, LaneLimits};
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

#[test]
fn a_cursor_report_describes_the_canonical_grid() {
    let mut engine = engine();
    assert_eq!(replies(&mut engine, b"\x1b[3;7H\x1b[6n", 0), [b"\x1b[3;7R"]);
    assert_eq!(
        replies(&mut engine, b"\x1b[?6n", 0),
        [b"\x1b[?3;7;1R".to_vec()]
    );
}

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

/// A query flood is bounded three ways and says so out of band.
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

/// Human input is never starved: the lane hands over only what the caller asked for.
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

/// A reply never lands inside an unfinished paste or a half-delivered human input frame.
#[test]
fn a_reply_waits_for_the_session_loop() {
    let mut engine = engine();
    engine.feed(b"\x1b[c", 0);

    let paste_open = LaneGate {
        paste_open: true,
        backend_handles_paste_interleave: false,
        human_frame_open: false,
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
    };
    assert_eq!(engine.lane_mut().drain(qualified, 4096, 0).len(), 1);
}

/// Replies are not history. Nothing pending survives a reconnection.
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

/// A reply that waited past its deadline is dropped rather than written.
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

/// The budget refills over time rather than granting one burst for the life of the session.
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

/// Two answers about different subjects are never collapsed into each other.
#[test]
fn coalescing_keeps_different_subjects_apart() {
    let mut engine = Engine::new(EngineConfig {
        lane: LaneLimits {
            max_queue_bytes: 24,
            ..LaneLimits::DEFAULT
        },
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    // Mode reports about three different modes, in a queue that holds about two of them.
    engine.feed(b"\x1b[?7$p\x1b[?25$p\x1b[?2004$p", 0);
    let replies: Vec<Vec<u8>> = engine
        .lane_mut()
        .drain(LaneGate::default(), 1 << 20, 0)
        .into_iter()
        .map(|reply| reply.bytes().to_vec())
        .collect();
    let subjects: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
    assert!(
        subjects.iter().all(|reply| !reply.starts_with(b"\x1b[?7;")) || subjects.len() > 1,
        "a report about one mode must not stand in for a report about another"
    );
    let mut seen: Vec<Vec<u8>> = subjects.iter().map(|r| (*r).to_vec()).collect();
    seen.sort();
    seen.dedup();
    assert_eq!(
        seen.len(),
        subjects.len(),
        "no two replies are the same answer"
    );
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
