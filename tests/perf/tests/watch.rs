//! Checks on the reading of other work: that this machine's counts are read in the units they are
//! kept in, and that `kr-perf-watch` bounds work outside a run, reads a run that has gone as unread,
//! and stops when asked.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use kr_perf::machine::Machine;
use kr_perf::other_work::{Process, Reading, Row};

const WATCH: &str = env!("CARGO_BIN_EXE_kr-perf-watch");

/// Keeps one processor busy until `stop` is set.
fn burn(stop: &AtomicBool) {
    let mut value: u64 = 1;
    while !stop.load(Ordering::Relaxed) {
        for _ in 0..10_000 {
            value = std::hint::black_box(
                value
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1),
            );
        }
    }
}

/// Keeps one processor busy in this process for `length`.
fn burn_for(length: Duration) {
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| burn(&stop));
        std::thread::sleep(length);
        stop.store(true, Ordering::Relaxed);
    });
}

fn row(reading: &Reading, pid: u32) -> &Process {
    reading
        .rows
        .iter()
        .find_map(|row| match row {
            Row::Read(process) if process.pid == pid => Some(process),
            _ => None,
        })
        .unwrap_or_else(|| panic!("the reading cannot read process {pid}"))
}

/// A process outside this one's work, standing for a run.
fn stand_in(seconds: &str) -> Child {
    Command::new("sleep")
        .arg(seconds)
        .stdin(Stdio::null())
        .spawn()
        .expect("start a process to stand for the run")
}

fn summary(output: &str) -> (f64, f64) {
    let mut numbers = output.split_whitespace().map(str::parse::<f64>);
    match (
        numbers.next(),
        numbers.next(),
        numbers.next(),
        numbers.next(),
    ) {
        (Some(Ok(bound)), Some(Ok(average)), Some(Ok(allowance)), None)
            if (0.0..=bound).contains(&allowance) =>
        {
            (bound, average)
        }
        _ => panic!("the watcher printed `{output}`"),
    }
}

#[test]
fn the_machine_counts_this_processs_work_as_busy_in_seconds() {
    let pid = std::process::id();
    let mut machine = Machine::open().expect("open this machine for reading");
    let before = machine.reading().expect("read this machine");
    let mut child = stand_in("30");
    // Half a second of this process's own time, however long a busy machine takes to give it.
    let deadline = Instant::now() + Duration::from_secs(30);
    let after = loop {
        burn_for(Duration::from_millis(500));
        let after = machine.reading().expect("read this machine");
        if row(&after, pid).own - row(&before, pid).own >= 0.5 || Instant::now() >= deadline {
            break after;
        }
    };
    let child_pid = child.id();
    let child_row = row(&after, child_pid).clone();
    child.kill().ok();
    child.wait().ok();
    for reading in [&before, &after] {
        assert!(
            reading.rows.iter().any(|row| row.pid() == 1),
            "the reading does not list the system's first process"
        );
    }
    assert_eq!(
        child_row.parent, pid,
        "the child's row names this process as its parent"
    );
    assert!(
        child_row.start >= row(&after, pid).start,
        "the child started no earlier than this process"
    );
    let own = row(&after, pid).own - row(&before, pid).own;
    let elapsed = after.ended - before.began;
    let all = f64::from(after.processors) * elapsed;
    let idle = after.idle_after - before.idle_before;
    let busy = all - idle + after.idle_resolution;
    assert!(
        own >= 0.5,
        "this process used {own} s in the thirty seconds it burned"
    );
    // The idle count cannot exceed every processor idle for the whole time, and what it leaves
    // busy holds this process's work: a count in the wrong unit fails one or the other.
    assert!(
        (0.0..=all + after.idle_resolution).contains(&idle),
        "the machine counted {idle} s idle in {elapsed} s on {} processors",
        after.processors
    );
    assert!(
        busy >= own,
        "the machine counted {busy} s busy while this process used {own} s"
    );
}

#[test]
fn work_outside_the_run_is_read_as_other_work() {
    let mut run = stand_in("30");
    let stop = Arc::new(AtomicBool::new(false));
    let burner = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || burn(&stop))
    };
    let output = Command::new(WATCH)
        .args(["--run", &run.id().to_string(), "--for", "6", "--every", "1"])
        .output()
        .expect("run the watcher");
    stop.store(true, Ordering::Relaxed);
    burner.join().expect("stop burning");
    run.kill().ok();
    run.wait().ok();
    let output = String::from_utf8_lossy(&output.stdout);
    let (bound, average) = summary(output.trim());
    // One processor was busy in this process, outside the run, the whole time.
    assert!(
        bound >= 0.9,
        "the bound read {bound} with one processor busy outside the run"
    );
    assert!(
        average >= 0.8,
        "the average read {average} with one processor busy outside the run"
    );
}

#[test]
fn a_run_whose_process_has_gone_is_unread() {
    let mut run = stand_in("1");
    let output = Command::new(WATCH)
        .args([
            "--run",
            &run.id().to_string(),
            "--for",
            "4",
            "--every",
            "0.5",
        ])
        .output()
        .expect("run the watcher");
    run.wait().ok();
    let output = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.starts_with("unread: ") && output.contains("the run's own process"),
        "the watcher printed `{output}`"
    );
}

#[test]
fn the_watcher_is_ready_after_its_first_reading_and_stops_when_asked() {
    let directory = tempfile::tempdir().expect("make a directory for the watcher's files");
    let ready = directory.path().join("ready");
    let until = directory.path().join("until");
    let mut run = stand_in("30");
    let watcher = Command::new(WATCH)
        .args(["--run", &run.id().to_string(), "--every", "0.5"])
        .arg("--until")
        .arg(&until)
        .arg("--ready")
        .arg(&ready)
        .stdout(Stdio::piped())
        .spawn()
        .expect("start the watcher");
    wait_for(&ready, Duration::from_secs(10));
    std::thread::sleep(Duration::from_secs(2));
    std::fs::write(&until, b"").expect("ask the watcher to stop");
    let asked = Instant::now();
    let output = watcher.wait_with_output().expect("wait for the watcher");
    let stopped = asked.elapsed();
    run.kill().ok();
    run.wait().ok();
    assert!(
        output.status.success(),
        "the watcher ended with {}",
        output.status
    );
    assert!(
        stopped < Duration::from_secs(3),
        "the watcher took {stopped:?} to stop"
    );
    summary(String::from_utf8_lossy(&output.stdout).trim());
}

fn wait_for(file: &Path, longest: Duration) {
    let deadline = Instant::now() + longest;
    while !file.exists() {
        assert!(
            Instant::now() < deadline,
            "{} did not appear",
            file.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
