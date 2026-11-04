//! The benchmark runs the model the way the product does, in a description process of its own, so
//! that the terminal workload it measures that process beside keeps the class an ordinary terminal
//! has.
//!
//! On macOS the background class is a process's, not a thread's: every thread of a process in it,
//! those it starts later included, runs at the lowest priority the scheduler gives. A benchmark
//! that put its model in its own process's class put its terminal workload there too, and measured
//! the terminal at background priority. The case starts the benchmark against the real weights,
//! where this host has them, and reads from outside the base priority the kernel holds for every
//! thread of the benchmark's process, where the workload runs, and of the description process it
//! started.
#![cfg(target_os = "macos")]

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use kr_ipc::background::{BACKGROUND_THREAD_PRIORITY, thread_priorities_of};

mod support;

/// How long the case waits for the benchmark to have its workload running and the model in the
/// class. The case decides by what the benchmark prints; this ends a benchmark that never prints
/// it.
const STARTED_BOUND: Duration = Duration::from_secs(900);

/// How long the description process has to end once the benchmark that started it has been ended.
const LEAVE_BOUND: Duration = Duration::from_secs(120);

/// A benchmark the case started, ended and collected when the case ends.
struct Benchmark(Child);

impl Drop for Benchmark {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Whether the system has a process with this identifier.
fn exists(pid: u32) -> bool {
    let pid = sysinfo::Pid::from_u32(pid);
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).is_some()
}

/// The terminal workload runs in a process the background class does not hold, while the model runs
/// in a process of its own that it does: every thread of the benchmark's process reads above the
/// background priority, and every thread of the description process at it or below.
#[test]
fn the_terminal_workload_runs_outside_the_class_of_the_model_process() {
    const CASE: &str = "the_terminal_workload_runs_outside_the_class_of_the_model_process";
    let Some(support::Weights {
        profile,
        path: cached,
    }) = support::weights(CASE)
    else {
        return;
    };
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    // The benchmark's cache holds the weights and nothing else; the benchmark writes beside them.
    let cache = directory.path().join("cache");
    std::fs::create_dir_all(&cache).expect("the cache directory");
    let weights = profile
        .assets()
        .iter()
        .find(|asset| asset.role == "weights")
        .expect("the profile names its weights");
    std::os::unix::fs::symlink(&cached, cache.join(&weights.file_name)).expect("the weights");
    // Both programs on the internal disk, each started once so that the system's check of a new
    // executable is paid before the case waits for anything.
    let benchmark = directory.path().join("kr-describe-bench");
    let inference = directory.path().join("kr-describe-inference");
    kr_ipc::testing::place_and_start_once(
        Path::new(env!("CARGO_BIN_EXE_kr-describe-bench")),
        &benchmark,
        &["--manifest"],
    );
    kr_ipc::testing::place_and_start_once(
        Path::new(env!("CARGO_BIN_EXE_kr-describe-inference")),
        &inference,
        &["--version"],
    );

    let errors = directory.path().join("benchmark-errors.txt");
    let mut command = Command::new(&benchmark);
    command
        .args(["--run", "--cache"])
        .arg(&cache)
        .arg("--inference")
        .arg(&inference)
        .current_dir(directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(
            std::fs::File::create(&errors).expect("a file for the benchmark's errors"),
        ));
    // A case run under `taskpolicy -b` is in the class, and so is what it starts: the benchmark
    // starts outside it, as it does from a terminal.
    let outside = support::OutsideTheClass::enter();
    let started = command.spawn().expect("the benchmark starts");
    drop(outside);
    let mut benchmark = Benchmark(started);
    let output = benchmark.0.stdout.take().expect("the benchmark's output");
    let (tell, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines().map_while(Result::ok) {
            if tell.send(line).is_err() {
                return;
            }
        }
    });

    let mut printed: Vec<String> = Vec::new();
    let mut workload_runs = false;
    let mut model_in_the_class = false;
    let mut model_pid: Option<u32> = None;
    let give_up = Instant::now() + STARTED_BOUND;
    while !(workload_runs && model_in_the_class) {
        let line = match lines.recv_timeout(give_up.saturating_duration_since(Instant::now())) {
            Ok(line) => line,
            Err(why) => {
                let errors = std::fs::read_to_string(&errors).unwrap_or_default();
                // The service pauses inference on a host without the free memory the policy asks
                // for, and then no process is started: this host cannot run the case now.
                if errors.contains("this host pauses inference") {
                    support::did_not_run(CASE, errors.trim());
                    return;
                }
                panic!(
                    "the benchmark did not get as far as running its workload with the model in \
                     the class ({why}): {printed:#?}\n{errors}"
                );
            }
        };
        workload_runs |= line.starts_with("terminal_workload_cpu_centis:");
        model_in_the_class |= line.starts_with("background priority:");
        if let Some(rest) = line.strip_prefix("description_process: pid ") {
            model_pid = rest
                .split_whitespace()
                .next()
                .and_then(|pid| pid.parse().ok());
        }
        printed.push(line);
    }

    let own = thread_priorities_of(benchmark.0.id())
        .expect("the kernel lists the threads of the benchmark's process");
    eprintln!(
        "the kernel's base priorities: benchmark process {own:?}, description process {:?} \
         (the background priority is {BACKGROUND_THREAD_PRIORITY})",
        model_pid.and_then(thread_priorities_of)
    );
    assert!(
        own.iter()
            .all(|priority| *priority > BACKGROUND_THREAD_PRIORITY),
        "a thread of the benchmark's own process, where its terminal workload runs, is in the \
         background class (the background priority is {BACKGROUND_THREAD_PRIORITY}): {own:?}"
    );
    let model_pid = model_pid.expect("the benchmark started a description process of its own");
    let model = thread_priorities_of(model_pid)
        .expect("the kernel lists the threads of the description process");
    assert!(
        model
            .iter()
            .all(|priority| *priority <= BACKGROUND_THREAD_PRIORITY),
        "a thread of the description process is outside the background class: {model:?}"
    );

    // The benchmark goes, and the description process it started goes with it: its input ends.
    drop(benchmark);
    let leave = Instant::now() + LEAVE_BOUND;
    while exists(model_pid) && Instant::now() < leave {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !exists(model_pid),
        "the description process outlived the benchmark that started it"
    );
}
