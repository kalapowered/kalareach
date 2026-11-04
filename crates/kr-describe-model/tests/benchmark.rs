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
//! started: once the process has said it is in the class and the workload runs, and again after the
//! model has loaded and run its first job.
#![cfg(target_os = "macos")]

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use kr_ipc::background::{BACKGROUND_THREAD_PRIORITY, thread_priorities_of};

mod support;

/// How long the case waits for each of the benchmark's lines. The case decides by what the
/// benchmark prints; this ends a benchmark that never prints it.
const LINE_BOUND: Duration = Duration::from_secs(900);

/// How long the description process has to end once the benchmark that started it has been ended.
const LEAVE_BOUND: Duration = Duration::from_secs(120);

/// A benchmark the case started: ended and collected when the case ends, and the description
/// process it started waited for.
struct Benchmark {
    child: Child,
    model_pid: Option<u32>,
}

impl Drop for Benchmark {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The description process ends when its input does. A case that fails early waits for that
        // too, and leaves a process that does not end for the case's failure to name.
        if let Some(pid) = self.model_pid {
            let leave = Instant::now() + LEAVE_BOUND;
            while exists(pid) && Instant::now() < leave {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Whether the system has a process with this identifier.
fn exists(pid: u32) -> bool {
    let pid = sysinfo::Pid::from_u32(pid);
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).is_some()
}

/// Reads the benchmark's next line, or says what the benchmark had printed and wrote to its error
/// output when it ended or took too long. `None` is a host that cannot run the case now: the
/// service pauses inference on a host without the free memory the policy asks for, and then no
/// process is started.
fn next_line(
    lines: &Receiver<String>,
    printed: &[String],
    errors: &Path,
    case: &str,
) -> Option<String> {
    match lines.recv_timeout(LINE_BOUND) {
        Ok(line) => Some(line),
        Err(why) => {
            let errors = std::fs::read_to_string(errors).unwrap_or_default();
            if errors.contains("this host pauses inference") {
                support::did_not_run(case, errors.trim());
                return None;
            }
            panic!("the benchmark ended or stopped printing ({why}): {printed:#?}\n{errors}");
        }
    }
}

/// Asserts what the kernel reports for every thread of the benchmark's process and of the
/// description process it started.
fn assert_classes(benchmark_pid: u32, model_pid: u32, when: &str) {
    let own = thread_priorities_of(benchmark_pid)
        .expect("the kernel lists the threads of the benchmark's process");
    let model = thread_priorities_of(model_pid)
        .expect("the kernel lists the threads of the description process");
    eprintln!(
        "the kernel's base priorities {when}: benchmark process {own:?}, description process \
         {model:?} (the background priority is {BACKGROUND_THREAD_PRIORITY})"
    );
    assert!(
        own.iter()
            .all(|priority| *priority > BACKGROUND_THREAD_PRIORITY),
        "a thread of the benchmark's own process, where its terminal workload runs, is in the \
         background class {when} (the background priority is {BACKGROUND_THREAD_PRIORITY}): {own:?}"
    );
    assert!(
        model
            .iter()
            .all(|priority| *priority <= BACKGROUND_THREAD_PRIORITY),
        "a thread of the description process is outside the background class {when}: {model:?}"
    );
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
    let mut benchmark = Benchmark {
        child: started,
        model_pid: None,
    };
    let output = benchmark
        .child
        .stdout
        .take()
        .expect("the benchmark's output");
    let (tell, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines().map_while(Result::ok) {
            if tell.send(line).is_err() {
                return;
            }
        }
    });

    // The workload runs from the start, and the description process says it is in the class.
    let mut printed: Vec<String> = Vec::new();
    let mut workload_runs = false;
    let mut model_in_the_class = false;
    while !(workload_runs && model_in_the_class) {
        let Some(line) = next_line(&lines, &printed, &errors, CASE) else {
            return;
        };
        workload_runs |= line.starts_with("terminal_workload_cpu_centis:");
        if line.starts_with("background priority:") {
            assert!(
                line.contains("(cpu true,"),
                "the description process does not report the class it was to be in: {line}"
            );
            model_in_the_class = true;
        }
        if let Some(rest) = line.strip_prefix("description_process: pid ") {
            benchmark.model_pid = rest
                .split_whitespace()
                .next()
                .and_then(|pid| pid.parse().ok());
        }
        printed.push(line);
    }
    let benchmark_pid = benchmark.child.id();
    // A benchmark that is not given a description process of its own has no pid to read: its own
    // process is then read first, which is where it fails.
    let model_pid = benchmark.model_pid.unwrap_or(benchmark_pid);
    assert_classes(
        benchmark_pid,
        model_pid,
        "when the process has said it is in the class",
    );
    assert!(
        benchmark.model_pid.is_some(),
        "the benchmark started a description process of its own"
    );

    // The model loads and runs its first job, with the workload beside it, and the classes are the
    // same: a class applied to the benchmark's own process after that would show here. The process
    // to read is the one running now, which is another one if the first was ended and started
    // again.
    while !printed.iter().any(|line| line.starts_with("warm_up_job:")) {
        let Some(line) = next_line(&lines, &printed, &errors, CASE) else {
            return;
        };
        if let Some(rest) = line.strip_prefix("description_process: pid ") {
            benchmark.model_pid = rest
                .split_whitespace()
                .next()
                .and_then(|pid| pid.parse().ok());
        }
        printed.push(line);
    }
    assert!(
        printed
            .iter()
            .any(|line| line.starts_with("cold_start_load_ms:")),
        "the first job ended with no model loaded: {printed:#?}"
    );
    let model_pid = benchmark
        .model_pid
        .expect("the benchmark started a description process of its own");
    if exists(model_pid) {
        assert_classes(benchmark_pid, model_pid, "after the first job");
    } else {
        // A process the service ended for the job and has not started again has no threads to read.
        eprintln!(
            "the description process had ended by the end of the first job, so the classes are \
             read once"
        );
    }

    // The benchmark goes, and the description process it started goes with it: its input ends.
    drop(benchmark);
    assert!(
        !exists(model_pid),
        "the description process outlived the benchmark that started it"
    );
}
