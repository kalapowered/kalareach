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

/// The operating system a figure was taken on, which section 27 records beside every figure
/// because a rate depends on it.
const HOST_OS: &str = std::env::consts::OS;

/// The architecture, likewise.
const HOST_ARCH: &str = std::env::consts::ARCH;

/// Logical processors available to the measurement. Section 27's reference host has at least four.
fn processors() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// What one rate measurement reports: the host it ran on, every pass, the figure and the verdict.
///
/// One shape for both streams, so the retained record and the step's output say the same thing in
/// the same order whichever of them a reader is looking at.
fn rate_lines(
    stream: &[u8],
    warm: &Run,
    runs: &[Run],
    passes: &[Run],
    sustained: f64,
) -> Vec<String> {
    let best = fastest(runs);
    let (lane, session, cache) = peaks(passes);
    let mut lines = vec![
        format!(
            "  build             {}",
            if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
        ),
        format!("  host              {HOST_OS} {HOST_ARCH}"),
        format!("  processors        {}", processors()),
        format!("  processor         {}", processor_model()),
        format!("  stream            {} bytes", stream.len()),
        format!("  chunk             {CHUNK_BYTES} bytes"),
        format!(
            "  warm-up pass      {:.3} s, {:.2} MiB/s, discarded",
            warm.elapsed_secs, warm.mib_per_second
        ),
    ];
    for (pass, run) in runs.iter().enumerate() {
        lines.push(format!(
            "  pass {pass}            {:.3} s, {:.2} MiB/s",
            run.elapsed_secs, run.mib_per_second
        ));
    }
    lines.push(format!(
        "  sustained         {sustained:.2} MiB/s over every pass, against a \
         {TARGET_MIB_PER_SECOND:.1} MiB/s target"
    ));
    lines.push(format!(
        "  fastest pass      {:.2} MiB/s, observed",
        best.mib_per_second
    ));
    lines.push(format!(
        "  verdict           {}",
        if sustained >= TARGET_MIB_PER_SECOND {
            "the target is met on this host"
        } else if cfg!(debug_assertions) {
            "below the target, and not asserted on an unoptimised build"
        } else {
            "below the target on this host"
        }
    ));
    lines.push(format!("  events            {}", best.events));
    lines.push(format!("  replies accepted  {}", best.responses));
    lines.push(format!("  peak events/chunk {}", best.peak_pending_events));
    lines.push(format!("  degraded          {}", best.degraded));
    lines.push(format!(
        "  peak lane bytes   {lane} of {}, over every pass",
        LaneLimits::DEFAULT.max_queue_bytes
    ));
    lines.push(format!(
        "  peak session      {session} bytes of {}, over every pass",
        kr_term::budget::BudgetLimits::DEFAULT.session_bytes
    ));
    lines.push(format!(
        "  peak row cache    {cache} bytes of {}, over every pass",
        kr_term::budget::BudgetLimits::DEFAULT.row_cache_bytes
    ));
    lines
}

/// Prints one measurement's lines and retains them where a run keeps its evidence.
fn report(measurement: &str, lines: &[String]) {
    println!("{measurement}");
    for line in lines {
        println!("{line}");
    }
    record_evidence(measurement, lines);
}

/// Writes one performance record where a run retains its evidence, and returns the lines it wrote.
///
/// Section 27 asks for the figures to be recorded with the host they were taken on and for a
/// release run's evidence to be kept. `KR_TEST_ARTIFACTS_DIR` is where this build puts that, and a
/// run that has not set it prints the record and keeps nothing. The record is written before the
/// target is asserted, so a run the target failed on retains the figure and the verdict rather
/// than only the panic.
fn record_evidence(measurement: &str, lines: &[String]) {
    let Some(dir) = std::env::var_os("KR_TEST_ARTIFACTS_DIR") else {
        return;
    };
    // A run that asked for its evidence to be kept and could not keep it has no evidence, and a
    // retained directory that happens to hold an earlier record would hide that. So a write that
    // fails fails the run, naming where it was writing and why it could not. The lines are already
    // printed by the time this runs, so nothing measured is lost with the file.
    let dir = std::path::PathBuf::from(dir);
    let mut record = format!("## {measurement}\n\n");
    for line in lines {
        record.push_str(line);
        record.push('\n');
    }
    record.push('\n');
    let path = dir.join("kr-term-output-handling.md");
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        std::fs::create_dir_all(&dir)?;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?
            .write_all(record.as_bytes())
    };
    if let Err(error) = write() {
        panic!(
            "this run could not keep its evidence at {}: {error}",
            path.display()
        );
    }
}

/// What the platform calls this processor, where it says.
///
/// Section 27 records the host beside every figure because a rate depends on it, and two hosts of
/// the same architecture are not the same processor.
fn processor_model() -> String {
    let read = |path: &str, field: &str| -> Option<String> {
        let text = std::fs::read_to_string(path).ok()?;
        let line = text.lines().find(|line| line.starts_with(field))?;
        Some(line.split_once(':')?.1.trim().to_owned())
    };
    if cfg!(target_os = "linux")
        && let Some(model) = read("/proc/cpuinfo", "model name")
    {
        return model;
    }
    if cfg!(target_os = "macos") {
        let output = std::process::Command::new("sysctl")
            .arg("-n")
            .arg("machdep.cpu.brand_string")
            .output();
        if let Ok(output) = output
            && output.status.success()
        {
            return String::from_utf8_lossy(&output.stdout).trim().to_owned();
        }
    }
    "not reported here".to_owned()
}

/// How much of a stream that scrolls is drained.
///
/// Scrolling output is where an unoptimised build is slowest — two orders of magnitude, for
/// reasons that have nothing to do with the design — and the rate is asserted on an optimised
/// build alone, so an unoptimised one drains an eighth. What is asserted on every build is a set
/// of bounds, and a bound holds at any length; an eighth still fills the historical cache several
/// times over.
const fn scrolling_bytes(bytes: usize) -> usize {
    if cfg!(debug_assertions) {
        bytes / 8
    } else {
        bytes
    }
}

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

/// Builds a stream that scrolls, which is what an application printing into a session does.
///
/// [`build_stream`] clears the screen often enough that rows rarely leave it, so it says nothing
/// about what a session pays for the history it keeps. This one only ever adds lines: it fills the
/// screen, scrolls it, and keeps going, so every row it prints ends up in the historical cache and
/// the cache reaches its bound and stays there.
///
/// It ends where a line ends rather than at `bytes` exactly, so the stream is always whole
/// sequences and whole scalars. A stream cut in the middle of one is a different amount of work
/// for the reader that takes it, which is the wrong thing to be measuring.
fn build_scrolling_stream(bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 1024);
    let mut counter = 0u32;
    while out.len() < bytes {
        counter = counter.wrapping_add(1);
        match counter % 8 {
            0 => {
                out.extend_from_slice(b"\x1b[1;38;5;208m2026-09-16 12:00:00 INFO \x1b[0mready\r\n")
            }
            1 => out.extend_from_slice(
                b"the quick brown fox jumps over the lazy dog and keeps going\r\n",
            ),
            2 => {
                out.extend_from_slice("\u{4e2d}\u{6587}\u{6d4b}\u{8bd5} mixed width\r\n".as_bytes())
            }
            3 => out.extend_from_slice(
                b"\x1b]8;;https://example.invalid/path\x1b\\link\x1b]8;;\x1b\\ after it\r\n",
            ),
            4 => out.extend_from_slice(b"\x1b[38;2;12;34;56mtruecolour\x1b[39m and plain\r\n"),
            5 => out.extend_from_slice("caf\u{e9} na\u{ef}ve \u{1f600} emoji\r\n".as_bytes()),
            6 => out.extend_from_slice(b"0123456789abcdef0123456789abcdef0123456789abcdef\r\n"),
            _ => out.extend_from_slice(b"\x1b[4munderlined\x1b[24m and plain text after it\r\n"),
        }
    }
    out
}

#[derive(Clone)]
struct Run {
    bytes: usize,
    elapsed_secs: f64,
    mib_per_second: f64,
    events: usize,
    responses: usize,
    peak_lane_bytes: usize,
    peak_pending_events: usize,
    degraded: bool,
    /// The most the session budget was holding at any read, not the reading at the end. A bound
    /// that was passed halfway through and given back is a bound that was passed. It is the
    /// accounting the engine keeps, sampled between reads: it says nothing about what a single
    /// read held while it was inside one, and nothing about what an allocator was holding.
    peak_session_bytes: u64,
    /// The most the historical row cache was holding at any read, against its own bound, sampled
    /// the same way.
    peak_row_cache_bytes: u64,
}

/// How many measured passes a rate is taken from, after a warm-up pass.
///
/// A rate is a property of the engine, and the first pass through a fresh process is not: it pays
/// for the allocator growing its arena and for the first touch of every page the grid and the row
/// cache end up holding. So the warm-up pass is discarded, each measured pass is printed, and the
/// rate is what the measured passes sustained together. Every bound is checked on every pass, the
/// warm-up included, because a bound holds whatever the machine was doing.
const PASSES: usize = if cfg!(debug_assertions) { 1 } else { 3 };

/// Drains `stream` once to warm the process, then `PASSES` times.
///
/// Returns the warm-up pass and the measured passes separately: the rate comes from the measured
/// ones, and every bound is checked on all of them, the warm-up included.
fn drain_passes(stream: &[u8], drain_replies: bool) -> (Run, Vec<Run>) {
    let warm = drain(stream, drain_replies);
    let measured = (0..PASSES).map(|_| drain(stream, drain_replies)).collect();
    (warm, measured)
}

/// The fastest pass observed, reported beside the sustained figure and deciding nothing.
///
/// It is the fastest of what was measured and no more than that: nothing here establishes that
/// anything interfered with the others, or that this one had the machine to itself.
fn fastest(runs: &[Run]) -> &Run {
    runs.iter()
        .max_by(|left, right| {
            left.mib_per_second
                .partial_cmp(&right.mib_per_second)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .expect("at least one pass")
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
    let mut peak_session_bytes = 0u64;
    let mut peak_row_cache_bytes = 0u64;

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
        peak_session_bytes = peak_session_bytes.max(engine.budget().committed());
        peak_row_cache_bytes = peak_row_cache_bytes.max(engine.budget().usage().rows);
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
        bytes: stream.len(),
        elapsed_secs,
        mib_per_second: mib / elapsed_secs,
        events,
        responses,
        peak_lane_bytes,
        peak_pending_events,
        degraded,
        peak_session_bytes,
        peak_row_cache_bytes,
    }
}

/// What the passes sustained together: every byte they drained over every second they took.
///
/// This is the figure the target is asserted against, because KR-PERF-007 is about sustaining a
/// rate rather than reaching one. The fastest pass is reported beside it as the fastest pass
/// observed, and it decides nothing: three passes at 3, 3 and 6 MiB/s sustained 3.6 MiB/s and
/// would fail, which is the right answer.
fn sustained_mib_per_second(runs: &[Run]) -> f64 {
    let bytes: usize = runs.iter().map(|run| run.bytes).sum();
    let seconds: f64 = runs.iter().map(|run| run.elapsed_secs).sum();
    #[expect(
        clippy::cast_precision_loss,
        reason = "a few passes of a few megabytes each; f64 represents it exactly"
    )]
    let mib = bytes as f64 / (1024.0 * 1024.0);
    mib / seconds.max(f64::MIN_POSITIVE)
}

/// The largest each sampled peak reached across every pass, the warm-up included.
fn peaks(runs: &[Run]) -> (usize, u64, u64) {
    runs.iter().fold((0, 0, 0), |(lane, session, cache), run| {
        (
            lane.max(run.peak_lane_bytes),
            session.max(run.peak_session_bytes),
            cache.max(run.peak_row_cache_bytes),
        )
    })
}

/// Asserts every bound the run had to stay inside, whatever the machine was doing.
fn assert_bounds_held(runs: &[Run]) {
    let limits = kr_term::budget::BudgetLimits::DEFAULT;
    for run in runs {
        assert!(
            run.peak_lane_bytes <= LaneLimits::DEFAULT.max_queue_bytes,
            "the response lane grew to {} bytes, past its {} bound",
            run.peak_lane_bytes,
            LaneLimits::DEFAULT.max_queue_bytes
        );
        assert!(
            run.peak_session_bytes <= limits.session_bytes,
            "the session budget reached {} bytes, past its {} bound",
            run.peak_session_bytes,
            limits.session_bytes
        );
        assert!(
            run.peak_row_cache_bytes <= limits.row_cache_bytes,
            "the row cache reached {} bytes, past its {} bound",
            run.peak_row_cache_bytes,
            limits.row_cache_bytes
        );
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
    let (warm, runs) = drain_passes(&stream, true);
    let sustained = sustained_mib_per_second(&runs);
    // Every pass a bound had to hold through, the discarded warm-up included.
    let passes: Vec<Run> = std::iter::once(warm.clone())
        .chain(runs.iter().cloned())
        .collect();

    report(
        "KR-PERF-007 kr-term output handling",
        &rate_lines(&stream, &warm, &runs, &passes, sustained),
    );

    // Before the rate, so a host too slow for the target still reports whether anything grew
    // without bound. The rate is the figure a host can fail; these are the ones nothing may.
    assert_bounds_held(&passes);
    assert!(
        cfg!(debug_assertions) || sustained >= TARGET_MIB_PER_SECOND,
        "the passes sustained {sustained:.2} MiB/s, below the {TARGET_MIB_PER_SECOND:.1} MiB/s \
         target"
    );
}

/// The target again, on a stream that scrolls.
///
/// [`build_stream`] clears the screen often enough that rows rarely leave it, so it measures the
/// parser and the grid without measuring what the session pays for the history it keeps. An
/// application printing into a session scrolls, every row it prints joins the historical cache,
/// and the cache is enforced on the way. That is the load that has to hold the target too.
#[test]
fn drains_a_scrolling_stream_at_the_target_rate() {
    let stream = build_scrolling_stream(scrolling_bytes(STREAM_BYTES));
    let (warm, runs) = drain_passes(&stream, true);
    let sustained = sustained_mib_per_second(&runs);
    let passes: Vec<Run> = std::iter::once(warm.clone())
        .chain(runs.iter().cloned())
        .collect();

    report(
        "KR-PERF-007 kr-term scrolling output",
        &rate_lines(&stream, &warm, &runs, &passes, sustained),
    );

    // Before the rate, for the reason above.
    let (_, _, cache) = peaks(&passes);
    assert!(
        cache > 0,
        "the rows that scrolled off have to reach the cache for this to say anything"
    );
    assert_bounds_held(&passes);
    assert!(
        cfg!(debug_assertions) || sustained >= TARGET_MIB_PER_SECOND,
        "the passes sustained {sustained:.2} MiB/s, below the {TARGET_MIB_PER_SECOND:.1} MiB/s \
         target"
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
///
/// On a stream that scrolls, so the cache is filled rather than left empty: an application that
/// clears the screen as often as it prints never puts a row into it.
#[test]
fn sustained_output_stays_inside_the_row_cache_bound() {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(120, 40),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let stream = build_scrolling_stream(scrolling_bytes(STREAM_BYTES / 2));
    for (index, chunk) in stream.chunks(CHUNK_BYTES).enumerate() {
        engine.feed(chunk, index as u64);
        engine.lane_mut().drain(LaneGate::default(), 8 * 1024, 0);
    }
    let usage = engine.budget().usage();
    assert!(
        usage.rows > 0,
        "the rows that scrolled off have to be in the cache for this to say anything"
    );
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

/// What one read costs does not grow with the history behind it.
///
/// The historical cache is enforced in bytes, and a row can carry a hundred times what the row
/// beside it carries, so the enforcement cannot be a row count. Working the figure out by walking
/// the rows makes every read cost what the whole history costs, which is what it used to do: a
/// session printing steadily saturated a core and left the host unable to keep up with an
/// application producing a few hundred kibibytes a second.
///
/// So the figure is carried. This feeds the same bytes to two sessions doing the same work, one
/// whose history is emptied before every read and one whose history is at its bound and evicting
/// on every row. Same read, same parsing, same printing, same scrolling; the only difference is
/// how much is behind the screen. The two therefore take about the same time.
#[test]
fn a_read_costs_the_same_whatever_the_history_holds() {
    /// The read being timed.
    ///
    /// Small enough that a read into an emptied history leaves a short one: at this geometry it is
    /// about seventy rows, against the thousands the bound holds. One whole read, built once and
    /// fed again and again, so every read of both phases is the same bytes and every one of them
    /// begins and ends at a parser-ground boundary.
    const READ_BYTES: usize = 4 * 1024;
    /// Reads per measurement.
    const READS: usize = if cfg!(debug_assertions) { 16 } else { 64 };
    /// Measurements per phase; the fastest is the one with the least noise on it.
    const ROUNDS: usize = if cfg!(debug_assertions) { 2 } else { 5 };
    /// How many reads the deep phase may take to reach the bound before the test gives up.
    const FILL_LIMIT: usize = 4_096;
    /// How much further apart the two phases may be before the cost is growing with the history.
    ///
    /// Walking the history made the deep phase sixty times the shallow one, so this is wide enough
    /// to be quiet on a loaded machine and still far inside what a walk would produce.
    const TOLERANCE: f64 = 4.0;

    let read = build_scrolling_stream(READ_BYTES);
    let session = || {
        Engine::new(EngineConfig {
            size: GridSize::new(120, 40),
            ..EngineConfig::DEFAULT
        })
        .expect("engine")
    };
    let mut now_ms = 0u64;

    // Emptied before every read, so each one is timed against a history of nothing.
    let mut shallow_engine = session();
    let mut shallow_rows = 0usize;
    let mut shallow = f64::MAX;
    for _ in 0..ROUNDS {
        let mut elapsed = 0.0;
        for _ in 0..READS {
            now_ms += 1;
            assert!(
                shallow_engine.at_ground(),
                "the read has to end where a sequence ends, or the clear would cancel one"
            );
            shallow_engine.feed(b"\x1b[3J", now_ms);
            shallow_engine
                .lane_mut()
                .drain(LaneGate::default(), 8 * 1024, 0);
            let started = Instant::now();
            shallow_engine.feed(&read, now_ms);
            elapsed += started.elapsed().as_secs_f64();
            shallow_rows = shallow_rows.max(shallow_engine.grid().scrollback_rows());
            shallow_engine
                .lane_mut()
                .drain(LaneGate::default(), 8 * 1024, 0);
        }
        shallow = shallow.min(elapsed / READS as f64);
    }

    // Filled until eviction is running, so every read of the second phase is evicting behind a
    // history of thousands of rows.
    let mut deep_engine = session();
    let limit = deep_engine.budget().limits().row_cache_bytes;
    let mut evicted = false;
    let mut fills = 0usize;
    while !evicted && fills < FILL_LIMIT {
        now_ms += 1;
        fills += 1;
        let outcome = deep_engine.feed(&read, now_ms);
        evicted |= outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.detail.contains("cache bound"));
        deep_engine
            .lane_mut()
            .drain(LaneGate::default(), 8 * 1024, 0);
    }
    assert!(
        evicted,
        "the deep phase has to be evicting, and {fills} reads did not make it so"
    );
    let deep_rows = deep_engine.grid().scrollback_rows();
    let deep_bytes = deep_engine.grid().history_bytes();
    let mut deep = f64::MAX;
    for _ in 0..ROUNDS {
        let mut elapsed = 0.0;
        for _ in 0..READS {
            now_ms += 1;
            let started = Instant::now();
            deep_engine.feed(&read, now_ms);
            elapsed += started.elapsed().as_secs_f64();
            deep_engine
                .lane_mut()
                .drain(LaneGate::default(), 8 * 1024, 0);
        }
        deep = deep.min(elapsed / READS as f64);
    }

    println!("KR-PERF-007 read cost against history depth");
    println!("  read              {} bytes", read.len());
    println!("  reads to fill     {fills}");
    println!("  shallow history   at most {shallow_rows} rows");
    println!("  shallow read      {:.4} ms", shallow * 1_000.0);
    println!("  deep history      {deep_rows} rows, {deep_bytes} of {limit} bytes");
    println!("  deep read         {:.4} ms", deep * 1_000.0);
    println!("  ratio             {:.2}", deep / shallow);

    assert!(
        deep_rows > shallow_rows * 10,
        "the two phases have to differ in depth: {deep_rows} rows against at most {shallow_rows}"
    );
    assert!(
        deep_bytes > limit * 9 / 10,
        "the deep phase has to sit at its bound: {deep_bytes} of {limit} bytes"
    );
    assert!(
        deep <= shallow * TOLERANCE,
        "a read behind {deep_rows} rows took {:.4} ms against {:.4} ms behind at most \
         {shallow_rows}; the cost is growing with the history",
        deep * 1_000.0,
        shallow * 1_000.0
    );
}

/// How many rows a read reads is a property of the geometry, not of the history behind the screen.
///
/// The timing above says the two cost about the same; this says why, in a figure a loaded machine
/// cannot move. Every resident figure but one is read from the rows that are showing, from how many
/// rows there are, or from what the account carries. The one that has to be found wherever it sits
/// is what the hyperlink objects cost, because an object is shared and a row that is not showing can
/// be the only place one sits; that reads every row of both buffers, and it is taken on its own
/// schedule rather than on every read.
///
/// So a session whose history is at its bound reads a few more rows over a run than one whose
/// history is empty — the scheduled measurements are wider — and not hundreds of times more. Before
/// the account carried what the retained rows cost, every read read every retained row.
#[test]
fn a_read_reads_as_many_rows_as_the_geometry_has() {
    /// Reads per session, over several of the scheduled measurement's intervals.
    const READS: usize = 200;
    /// How much further apart the two may be before the reading is growing with the history.
    ///
    /// The scheduled measurement reads every row of both buffers, so a deep session's scheduled
    /// reads are wider than a shallow one's by the rows it is holding. Over this many reads that is
    /// a few intervals' worth against a screen's worth on every read, and a read that read the
    /// history would be twenty times the shallow figure rather than under twice it.
    const TOLERANCE: u64 = 2;

    let read = build_scrolling_stream(4 * 1024);
    let session = || {
        Engine::new(EngineConfig {
            size: GridSize::new(120, 40),
            ..EngineConfig::DEFAULT
        })
        .expect("engine")
    };
    let mut now_ms = 0u64;

    // Emptied at the start of every read, so the history behind each one is nothing. The clear
    // travels with the read rather than in a read of its own, so both sessions take the same number
    // of reads and the figures below compare like with like.
    let mut cleared = b"\x1b[3J".to_vec();
    cleared.extend_from_slice(&read);
    let mut shallow = session();
    let mut shallow_rows = 0usize;
    for _ in 0..READS {
        now_ms += 1;
        shallow.feed(&cleared, now_ms);
        shallow_rows = shallow_rows.max(shallow.grid().scrollback_rows());
    }
    let shallow_read = shallow.grid().rows_read();

    // Filled until eviction is running, then read the same bytes the same number of times.
    let mut deep = session();
    let limit = deep.budget().limits().row_cache_bytes;
    let mut fills = 0usize;
    while deep.grid().history_bytes() <= limit * 9 / 10 && fills < 4_096 {
        now_ms += 1;
        fills += 1;
        deep.feed(&read, now_ms);
    }
    let filled = deep.grid().rows_read();
    let deep_rows = deep.grid().scrollback_rows();
    for _ in 0..READS {
        now_ms += 1;
        deep.feed(&read, now_ms);
    }
    let deep_read = deep.grid().rows_read() - filled;

    println!("KR-PERF-007 rows read against history depth");
    println!("  reads             {READS}");
    println!("  shallow history   at most {shallow_rows} rows");
    println!("  shallow rows read {shallow_read}");
    println!(
        "  deep history      {deep_rows} rows, {} bytes",
        deep.grid().history_bytes()
    );
    println!("  deep rows read    {deep_read}");

    assert!(
        deep_rows > shallow_rows * 10,
        "the two sessions have to differ in depth: {deep_rows} rows against at most {shallow_rows}"
    );
    assert!(
        deep_read <= shallow_read.saturating_mul(TOLERANCE),
        "a session holding {deep_rows} rows read {deep_read} rows over {READS} reads against \
         {shallow_read} behind at most {shallow_rows}; the reading is growing with the history"
    );
}

/// The hyperlink envelope is never passed, and a link is refused only against a measurement.
///
/// Every link is charged what it will cost where it arrives, because one read can carry a session's
/// worth of them. What is charged is at or above what the object turns out to hold, and a row that
/// is dropped gives nothing back until the objects on it are measured again, so the charged figure
/// drifts above the truth while a session prints. The engine reads the truth before it charges a
/// link the drifted figure says would not fit, so a session that has scrolled its links away keeps
/// admitting them; and it reads before it charges rather than between the object's charge and the
/// table entry's, because a measurement replaces the account with what the grid is holding and the
/// object being admitted is not on a row yet.
#[test]
fn the_link_envelope_holds_across_a_measurement() {
    /// Links opened, printed into and closed, one to a read, each with a target of its own.
    ///
    /// Enough of them to fill both the envelope and the table of distinct targets a session keeps,
    /// so the reading that decides a refusal is taken and the refusals after it are taken against
    /// it. The same count on every build, because what it checks is a bound rather than a rate.
    const READS: u32 = 4_352;
    /// Characters of target, which with the parameter field and the scheme is the most one link may
    /// hold, so the envelope is reached in the fewest reads.
    const TARGET_CHARS: usize = 2_000;

    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(120, 40),
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let envelope = engine.budget().reserved().links;
    let target: String = std::iter::repeat_n('a', TARGET_CHARS).collect();
    let mut admitted = 0usize;
    let mut refused = 0usize;
    let mut seen = 0u64;
    let mut peak = 0u64;

    // One target for every read, so the table of distinct targets fills as well as the envelope,
    // and the cells of every link scroll off the screen so the objects on them are given up.
    for index in 0..READS {
        let input = format!("\x1b]8;;https://{index:05}/{target}\x1b\\link\x1b]8;;\x1b\\ text\r\n");
        engine.feed(input.as_bytes(), u64::from(index));
        // Counted from the truncations the budget records rather than from the diagnostics, which
        // are rate limited: a refusal that was suppressed is still a refusal.
        let truncations = engine.budget().truncations();
        if truncations > seen {
            refused += 1;
            seen = truncations;
        } else {
            admitted += 1;
        }
        let links = engine.budget().usage().links;
        peak = peak.max(links);
        assert!(
            links <= envelope,
            "the hyperlink state reached {links} bytes against a {envelope}-byte envelope at read \
             {index}"
        );
        assert_eq!(
            engine.budget().excess(),
            0,
            "a measurement found more than the admitted geometry reserved at read {index}"
        );
    }
    engine.quiesce(u64::from(READS));

    println!("KR-PERF-007 hyperlink admission across a measurement");
    println!("  reads             {READS}");
    println!("  links admitted    {admitted}");
    println!("  links refused     {refused}");
    println!("  envelope          {envelope} bytes");
    println!("  peak holding      {peak} bytes");
    println!(
        "  settled holding   {} bytes",
        engine.budget().usage().links
    );

    assert_eq!(
        engine.budget().excess(),
        0,
        "the settled session holds more than the admitted geometry reserved"
    );
    assert!(
        engine.budget().usage().links <= envelope,
        "the settled session holds {} bytes of hyperlink state against a {envelope}-byte envelope",
        engine.budget().usage().links
    );
    assert!(
        peak > envelope - envelope / 16,
        "the run has to reach the part of the envelope where a reading decides something: {peak} \
         bytes of {envelope}"
    );
    assert!(
        refused > 0,
        "the run has to reach a refusal, which is the decision a reading is taken for"
    );
    assert!(
        admitted > READS as usize / 4,
        "a session that scrolls its links away has to keep admitting them: {admitted} admitted, \
         {refused} refused"
    );
}
