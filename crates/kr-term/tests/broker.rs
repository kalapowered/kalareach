//! KR-ACC-001: exactly one query responder, with no duplicate answers and no hangs.
//!
//! The dangerous failure here is not a wrong answer. It is a second answer, or none: an application
//! that asked one question and got two replies loses its place in its own input stream, and an
//! application that asked and got nothing waits.

use kr_term::engine::{Engine, EngineConfig};
use kr_term::lane::{LaneGate, LaneLimits, Response, ResponseKind, ResponseLane};
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
        .drain(LaneGate::default(), 1 << 20)
        .into_iter()
        .map(|response| response.bytes)
        .collect()
}

#[test]
fn the_profile_answers_device_attributes_and_never_a_physical_terminal() {
    let mut engine = engine();
    assert_eq!(replies(&mut engine, b"\x1b[c", 0), [b"\x1b[?62;1;22c"]);
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
    // An unknown capability gets the defined failure reply, not silence.
    assert_eq!(
        replies(&mut engine, b"\x1bP+q7a7a7a\x1b\\", 0),
        [b"\x1bP0+r7a7a7a\x1b\\".to_vec()]
    );
    // Several names in one request produce one reply each, in order.
    let many = replies(&mut engine, b"\x1bP+q544e;436f;7a7a\x1b\\", 0);
    assert_eq!(many.len(), 3);
    assert!(many[2].starts_with(b"\x1bP0+r"));
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
    let mut lane = ResponseLane::new();
    for index in 0..10u64 {
        assert!(lane.offer(
            Response {
                bytes: vec![b'x'; 100],
                kind: ResponseKind::CursorPosition,
                query_at: index,
            },
            0
        ));
    }
    let first = lane.drain(LaneGate::default(), 250);
    assert!(first.len() <= 3, "the drain stopped at the byte budget");
    assert!(lane.pending() > 0, "the rest is still waiting");
}

/// A reply never lands inside an unfinished bracketed paste unless the backend handles it.
#[test]
fn a_reply_waits_for_an_open_paste_to_close() {
    let mut lane = ResponseLane::new();
    lane.offer(
        Response {
            bytes: b"\x1b[?62;1;22c".to_vec(),
            kind: ResponseKind::DeviceAttributes1,
            query_at: 0,
        },
        0,
    );
    let blocked = LaneGate {
        paste_open: true,
        backend_handles_paste_interleave: false,
    };
    assert!(lane.drain(blocked, 4096).is_empty());
    let qualified = LaneGate {
        paste_open: true,
        backend_handles_paste_interleave: true,
    };
    assert_eq!(lane.drain(qualified, 4096).len(), 1);
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
            .drain(LaneGate::default(), 4096)
            .is_empty()
    );
}

/// The budget refills over time rather than granting one burst for the life of the session.
#[test]
fn the_reply_budget_refills() {
    let mut lane = ResponseLane::with_limits(LaneLimits {
        responses_per_second: 4,
        ..LaneLimits::DEFAULT
    });
    let offer = |lane: &mut ResponseLane, now: u64| {
        lane.offer(
            Response {
                bytes: b"x".to_vec(),
                kind: ResponseKind::CursorPosition,
                query_at: now,
            },
            now,
        )
    };
    for _ in 0..4 {
        assert!(offer(&mut lane, 0));
    }
    assert!(!offer(&mut lane, 0), "the burst is spent");
    assert!(offer(&mut lane, 250), "a quarter second buys one more");
}
