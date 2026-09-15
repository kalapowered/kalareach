//! KR-PERF-007: drain and parse a 5 MiB/s stream without unbounded queues.
//!
//! The target is about two things at once, and the second matters more. Throughput says the engine
//! keeps up with a program that is printing hard. Bounded queues say that when it does not keep up,
//! or when a client is slow, nothing grows without limit and nothing else stalls.
//!
//! Run it on its own to record the numbers:
//!
//! ```text
//! cargo test -p kr-term --release --test perf -- --nocapture
//! ```

use std::time::Instant;

use kr_term::budget::GridSize;
use kr_term::engine::{Engine, EngineConfig};
use kr_term::lane::{LaneGate, LaneLimits};

/// The stream size the benchmark drains, which is one second of the target rate.
const STREAM_BYTES: usize = 5 * 1024 * 1024;

/// The read size, which is the usual order of a PTY read.
const CHUNK_BYTES: usize = 64 * 1024;

/// Builds a stream that looks like real application output rather than one long string of `a`.
///
/// A parser is only interesting where it has to do work, so the mix is deliberate: text runs,
/// colour changes, cursor movement, wide characters, hyperlinks, alternate-screen churn, a title
/// change and a steady trickle of queries the broker has to answer.
fn build_stream(bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 1024);
    let mut counter = 0u32;
    while out.len() < bytes {
        counter = counter.wrapping_add(1);
        match counter % 16 {
            0 => out.extend_from_slice(b"\x1b[1;38;5;208mheading\x1b[0m\r\n"),
            1 => out.extend_from_slice(
                b"the quick brown fox jumps over the lazy dog and keeps going\r\n",
            ),
            2 => {
                out.extend_from_slice("\u{4e2d}\u{6587}\u{6d4b}\u{8bd5} mixed width\r\n".as_bytes())
            }
            3 => out.extend_from_slice(b"\x1b[2K\x1b[1G"),
            4 => out.extend_from_slice(
                b"\x1b]8;;https://example.invalid/path\x1b\\link\x1b]8;;\x1b\\\r\n",
            ),
            5 => out.extend_from_slice(b"\x1b[6n"),
            6 => out.extend_from_slice(b"\x1b[38;2;12;34;56mtruecolour\x1b[39m\r\n"),
            7 => out.extend_from_slice("caf\u{e9} na\u{ef}ve \u{1f600} emoji\r\n".as_bytes()),
            8 => out.extend_from_slice(b"\x1b[?25l\x1b[H\x1b[J"),
            9 => out.extend_from_slice(b"0123456789abcdef0123456789abcdef0123456789abcdef\r\n"),
            10 => out.extend_from_slice(b"\x1b]0;a title that changes\x07"),
            11 => out.extend_from_slice(b"\x1b[?1049h\x1b[2J\x1b[H"),
            12 => out.extend_from_slice(b"\x1b[?1049l"),
            13 => out.extend_from_slice(b"\x1b[4munderlined\x1b[24m and plain text after it\r\n"),
            14 => out.extend_from_slice(b"\x1b[?2027$p"),
            _ => out.extend_from_slice(b"\x1b[?25h\x1b[3;1Hstatus line content here\r\n"),
        }
    }
    out.truncate(bytes);
    out
}

struct Run {
    elapsed_secs: f64,
    mib_per_second: f64,
    events: usize,
    responses: usize,
    peak_lane_bytes: usize,
    peak_pending_events: usize,
    degraded: bool,
    session_bytes: u64,
}

fn drain(stream: &[u8], drain_replies: bool) -> Run {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(120, 40),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");

    let mut events = 0usize;
    let mut responses = 0usize;
    let mut peak_lane_bytes = 0usize;
    let mut peak_pending_events = 0usize;
    let mut degraded = false;
    let mut now_ms = 0u64;

    let started = Instant::now();
    for (index, chunk) in stream.chunks(CHUNK_BYTES).enumerate() {
        // One millisecond of simulated time per chunk keeps the reply budget realistic.
        now_ms = index as u64;
        let outcome = engine.feed(chunk, now_ms);
        events += outcome.events;
        responses += outcome.responses;
        degraded |= outcome.degradation.is_degraded();
        peak_lane_bytes = peak_lane_bytes.max(engine.lane().queued_bytes());
        peak_pending_events = peak_pending_events.max(outcome.events);
        if drain_replies {
            engine.lane_mut().drain(LaneGate::default(), 8 * 1024, 0);
        }
    }
    let elapsed = started.elapsed();
    let _ = now_ms;

    let elapsed_secs = elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    #[expect(
        clippy::cast_precision_loss,
        reason = "the stream is a few megabytes; f64 represents it exactly"
    )]
    let mib = stream.len() as f64 / (1024.0 * 1024.0);
    Run {
        elapsed_secs,
        mib_per_second: mib / elapsed_secs,
        events,
        responses,
        peak_lane_bytes,
        peak_pending_events,
        degraded,
        session_bytes: engine.budget().committed(),
    }
}

/// The throughput target, asserted on an optimised build.
///
/// A debug build is an order of magnitude slower for reasons that have nothing to do with the
/// design, and how much slower depends on what else the machine is doing, so it reports the figure
/// and asserts nothing about it. The bounds this test exists to check are asserted on every build:
/// what matters is that nothing grows without limit, and that holds however slow the run is.
const TARGET_MIB_PER_SECOND: f64 = 5.0;

#[test]
fn drains_five_mebibytes_without_unbounded_queues() {
    let stream = build_stream(STREAM_BYTES);
    let run = drain(&stream, true);

    println!("KR-PERF-007 kr-term output handling");
    println!(
        "  build             {}",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    println!("  stream            {} bytes", stream.len());
    println!("  chunk             {CHUNK_BYTES} bytes");
    println!("  elapsed           {:.3} s", run.elapsed_secs);
    println!("  throughput        {:.2} MiB/s", run.mib_per_second);
    println!("  events            {}", run.events);
    println!("  replies accepted  {}", run.responses);
    println!(
        "  peak lane bytes   {} of {}",
        run.peak_lane_bytes,
        LaneLimits::DEFAULT.max_queue_bytes
    );
    println!("  peak events/chunk {}", run.peak_pending_events);
    println!("  session bytes     {}", run.session_bytes);
    println!("  degraded          {}", run.degraded);

    assert!(
        cfg!(debug_assertions) || run.mib_per_second >= TARGET_MIB_PER_SECOND,
        "throughput {:.2} MiB/s is below the {TARGET_MIB_PER_SECOND:.1} MiB/s target",
        run.mib_per_second
    );
    assert!(
        run.peak_lane_bytes <= LaneLimits::DEFAULT.max_queue_bytes,
        "the response lane grew past its bound"
    );
    assert!(
        run.session_bytes <= kr_term::budget::BudgetLimits::DEFAULT.session_bytes,
        "the session budget was exceeded"
    );
}

/// A client that never reads its replies does not make the engine grow.
#[test]
fn a_slow_reader_does_not_make_the_lane_grow() {
    let stream = build_stream(STREAM_BYTES / 4);
    let run = drain(&stream, false);
    assert!(
        run.peak_lane_bytes <= LaneLimits::DEFAULT.max_queue_bytes,
        "peak {} bytes exceeded the {} byte bound",
        run.peak_lane_bytes,
        LaneLimits::DEFAULT.max_queue_bytes
    );
    assert!(
        run.degraded,
        "an observer that never drains must see explicit degraded status"
    );
}

/// The historical row cache stays inside its own bound under sustained output.
#[test]
fn sustained_output_stays_inside_the_row_cache_bound() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(120, 40),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let stream = build_stream(STREAM_BYTES / 2);
    for (index, chunk) in stream.chunks(CHUNK_BYTES).enumerate() {
        engine.feed(chunk, index as u64);
        engine.lane_mut().drain(LaneGate::default(), 8 * 1024, 0);
    }
    let usage = engine.budget().usage();
    let limits = engine.budget().limits();
    assert!(
        usage.rows <= limits.row_cache_bytes,
        "the row cache grew past {} bytes",
        limits.row_cache_bytes
    );
    assert_eq!(
        engine.budget().excess(),
        0,
        "a measurement found more than the admitted geometry reserved"
    );
    assert!(engine.budget().committed() <= limits.session_bytes);
}
