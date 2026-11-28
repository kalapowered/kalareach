//! A parked PSReadLine reader on a Windows pseudo-console, woken with nothing typed.
//!
//! Measures what the editor's idle tick does for a request that arrives on a named pipe: how long
//! the answer takes, which thread runs the subscriber, whether a subscriber of the person's keeps
//! running beside it, whether a launched line runs when an idle subscriber accepts it, and when a
//! key the probe queues at the start of a read runs. Nothing is typed into the console: the
//! terminal's own cursor-position answers are the only bytes written to its input, and they are
//! counted.

#![cfg(windows)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::{Child, CommandBuilder, PtySize, native_pty_system};

const PINGS: usize = 200;
const LAUNCHES: usize = 10;
const SESSION_BUDGET: Duration = Duration::from_secs(420);

fn probe_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("pwsh_idle_spike")
        .join("idle-probe.ps1")
}

/// One answer line of the probe, as the test reads it.
struct Answer {
    line: String,
    rtt: Duration,
}

impl Answer {
    fn field(&self, name: &str) -> Option<String> {
        let prefix = format!("{name}=");
        self.line
            .split('|')
            .find_map(|part| part.strip_prefix(prefix.as_str()).map(str::to_owned))
    }

    fn number(&self, name: &str) -> u64 {
        self.field(name)
            .and_then(|value| value.parse().ok())
            .unwrap_or(u64::MAX)
    }
}

struct Session {
    child: Arc<Mutex<Box<dyn Child + Send + Sync>>>,
    output: Arc<Mutex<Vec<u8>>>,
    terminal_answers: Arc<Mutex<u32>>,
    pipe: File,
    pending: Vec<u8>,
    report: PathBuf,
    folder: tempfile::TempDir,
    done: Arc<AtomicBool>,
    // The console's two ends stay open until the session is dropped.
    _master: Box<dyn portable_pty::MasterPty + Send>,
}

impl Session {
    fn start(label: &str, start_step: bool) -> Self {
        let folder = tempfile::tempdir().expect("a temporary folder");
        let report = folder.path().join("report.txt");
        let pipe_name = format!("kr-spike-{label}-{}", std::process::id());
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 30,
                cols: 120,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("a pseudo-console");
        let command_text = format!(
            ". '{}' -Pipe '{}' -Report '{}'{}",
            probe_script().display(),
            pipe_name,
            report.display(),
            if start_step { " -StartStep" } else { "" }
        );
        let mut command = CommandBuilder::new("pwsh.exe");
        command.args(["-NoLogo", "-NoProfile", "-NoExit", "-Command", &command_text]);
        command.cwd(folder.path());
        let child = pair
            .slave
            .spawn_command(command)
            .expect("PowerShell 7 starts in the pseudo-console");
        drop(pair.slave);
        let child: Arc<Mutex<Box<dyn Child + Send + Sync>>> = Arc::new(Mutex::new(child));

        let output = Arc::new(Mutex::new(Vec::new()));
        let terminal_answers = Arc::new(Mutex::new(0_u32));
        {
            let mut reader = pair.master.try_clone_reader().expect("a console reader");
            let mut writer = pair.master.take_writer().expect("a console writer");
            let output = Arc::clone(&output);
            let answers = Arc::clone(&terminal_answers);
            std::thread::spawn(move || {
                let mut buffer = [0_u8; 8192];
                while let Ok(count) = reader.read(&mut buffer) {
                    if count == 0 {
                        break;
                    }
                    let chunk = &buffer[..count];
                    if chunk.windows(4).any(|window| window == b"\x1b[6n") {
                        // The console asks where the cursor is; a terminal answers.
                        if writer.write_all(b"\x1b[1;1R").is_ok() {
                            let _ = writer.flush();
                            *answers.lock().expect("the answer count") += 1;
                        }
                    }
                    let mut held = output.lock().expect("the output");
                    if held.len() < 1_000_000 {
                        held.extend_from_slice(chunk);
                    }
                }
            });
        }

        // The budget ends only this session's own child, by the handle it was started with.
        let done = Arc::new(AtomicBool::new(false));
        {
            let done = Arc::clone(&done);
            let child = Arc::clone(&child);
            std::thread::spawn(move || {
                let end = Instant::now() + SESSION_BUDGET;
                while Instant::now() < end {
                    if done.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
                eprintln!("the session budget ran out: ending the session's own shell");
                let _ = child.lock().expect("the child").kill();
            });
        }

        let pipe_path = format!(r"\\.\pipe\{pipe_name}");
        let give_up = Instant::now() + Duration::from_secs(90);
        let pipe = loop {
            match OpenOptions::new().read(true).write(true).open(&pipe_path) {
                Ok(file) => break file,
                Err(error) => {
                    assert!(
                        Instant::now() < give_up,
                        "the probe's pipe never opened: {error}\n{}",
                        report_text(&report)
                    );
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        };
        let session = Self {
            child,
            output,
            terminal_answers,
            pipe,
            pending: Vec::new(),
            report,
            folder,
            done,
            _master: pair.master,
        };
        session.wait_for_report("prompt 1 ", Duration::from_secs(60));
        // The first prompt is parked and has ticked a few times.
        std::thread::sleep(Duration::from_millis(1500));
        session
    }

    fn wait_for_report(&self, text: &str, within: Duration) {
        let end = Instant::now() + within;
        while Instant::now() < end {
            if report_text(&self.report).contains(text) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "the report never held {text:?}:\n{}\n{}",
            report_text(&self.report),
            self.screen_tail()
        );
    }

    fn screen_tail(&self) -> String {
        let held = self.output.lock().expect("the output");
        let start = held.len().saturating_sub(800);
        format!("console tail: {:?}", String::from_utf8_lossy(&held[start..]))
    }

    fn send(&mut self, id: &str, kind: &str, payload: &str) -> Instant {
        let sent = Instant::now();
        self.pipe
            .write_all(format!("{id}|{kind}|{payload}\n").as_bytes())
            .unwrap_or_else(|error| panic!("the request was written: {error}"));
        sent
    }

    fn read_line(&mut self) -> String {
        loop {
            if let Some(index) = self.pending.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = self.pending.drain(..=index).collect();
                return String::from_utf8_lossy(&line).trim_end().to_owned();
            }
            let mut buffer = [0_u8; 4096];
            let count = self.pipe.read(&mut buffer).unwrap_or_else(|error| {
                panic!(
                    "the answer was read: {error}\n{}\n{}",
                    report_text(&self.report),
                    self.screen_tail()
                )
            });
            assert!(
                count > 0,
                "the probe closed its pipe\n{}\n{}",
                report_text(&self.report),
                self.screen_tail()
            );
            self.pending.extend_from_slice(&buffer[..count]);
        }
    }

    fn ask(&mut self, id: &str, kind: &str, payload: &str) -> Answer {
        let sent = self.send(id, kind, payload);
        let line = self.read_line();
        Answer {
            line,
            rtt: sent.elapsed(),
        }
    }

    /// Ends the shell the way a person's last command does, and otherwise by its own handle.
    fn finish(mut self) -> String {
        let _ = self.send("exit", "L", "exit");
        let _ = self.read_line();
        let end = Instant::now() + Duration::from_secs(20);
        let mut ended = false;
        while Instant::now() < end {
            if matches!(self.child.lock().expect("the child").try_wait(), Ok(Some(_))) {
                ended = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !ended {
            println!("the shell did not end on its own; ending the session's own child");
            let _ = self.child.lock().expect("the child").kill();
        }
        self.done.store(true, Ordering::SeqCst);
        format!(
            "shell ended on its own: {ended}; terminal answers written: {}",
            self.terminal_answers.lock().expect("the answers")
        )
    }
}

fn report_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn percentile(sorted: &[u64], fraction: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() as f64 * fraction).ceil() as usize).clamp(1, sorted.len()) - 1;
    sorted[index]
}

/// Prints the distribution of `values` under `name`, in the unit the values are in.
fn distribution(label: &str, name: &str, unit: &str, mut values: Vec<u64>) -> u64 {
    values.sort_unstable();
    let p95 = percentile(&values, 0.95);
    println!(
        "SPIKE {label} {name} n={} min={}{unit} p50={}{unit} p95={}{unit} p99={}{unit} max={}{unit}",
        values.len(),
        values.first().copied().unwrap_or(0),
        percentile(&values, 0.50),
        p95,
        percentile(&values, 0.99),
        values.last().copied().unwrap_or(0),
    );
    p95
}

struct Outcome {
    p95_rtt_ms: u64,
    answered: usize,
    on_the_reader_thread: usize,
    off_the_pool: usize,
    person_ticks_never_went_back: bool,
}

fn measure(label: &str, start_step: bool) -> Outcome {
    let mut session = Session::start(label, start_step);
    println!(
        "SPIKE {label} host: {}",
        report_text(&session.report).lines().next().unwrap_or("")
    );

    // Phase 1: requests at varied offsets within the tick, with nothing typed.
    let mut answers = Vec::new();
    for index in 0..PINGS {
        std::thread::sleep(Duration::from_millis(((index * 53) % 311) as u64));
        answers.push(session.ask(&index.to_string(), "P", ""));
    }
    let rtts: Vec<u64> = answers.iter().map(|a| a.rtt.as_millis() as u64).collect();
    let p95_rtt_ms = distribution(label, "request-to-answer", "ms", rtts);
    distribution(
        label,
        "arrival-to-service",
        "ms",
        answers.iter().map(|a| a.number("waited_us") / 1000).collect(),
    );
    let on_the_reader_thread = answers
        .iter()
        .filter(|a| a.field("reader") == a.field("action"))
        .count();
    let off_the_pool = answers
        .iter()
        .filter(|a| a.field("pool").as_deref() == Some("False"))
        .count();
    let ticks: Vec<u64> = answers.iter().map(|a| a.number("person_ticks")).collect();
    let person_ticks_never_went_back = ticks.windows(2).all(|pair| pair[1] >= pair[0])
        && ticks.last().copied().unwrap_or(0) > ticks.first().copied().unwrap_or(0);
    println!(
        "SPIKE {label} threads: on the reader's thread {on_the_reader_thread} of {}, off the pool {off_the_pool} of {}, the person's subscriber ticks {} to {} (monotonic: {person_ticks_never_went_back})",
        answers.len(),
        answers.len(),
        ticks.first().copied().unwrap_or(0),
        ticks.last().copied().unwrap_or(0),
    );
    println!("SPIKE {label} first answer: {}", answers[0].line);

    // Phase 2: a launched line, accepted by the idle subscriber, with nothing typed.
    let mut ran = Vec::new();
    for index in 0..LAUNCHES {
        let marker = session.folder.path().join(format!("ran{index}.txt"));
        let line = format!("Add-Content -LiteralPath '{}' -Value ran", marker.display());
        let sent = session.send(&format!("L{index}"), "L", &line);
        let _answer = session.read_line();
        let end = Instant::now() + Duration::from_secs(10);
        let mut seen = None;
        while Instant::now() < end {
            if marker.exists() {
                seen = Some(sent.elapsed());
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        match seen {
            Some(elapsed) => ran.push(elapsed.as_millis() as u64),
            None => {
                println!(
                    "SPIKE {label} launch {index}: the line did not run within 10 s\n{}",
                    report_text(&session.report)
                );
                break;
            }
        }
        // Once, and not again.
        std::thread::sleep(Duration::from_millis(700));
        let runs = std::fs::read_to_string(&marker).unwrap_or_default().lines().count();
        if runs != 1 {
            println!("SPIKE {label} launch {index}: the line ran {runs} times");
        }
    }
    println!(
        "SPIKE {label} launches run with nothing typed: {} of {LAUNCHES}",
        ran.len()
    );
    if !ran.is_empty() {
        distribution(label, "launch-to-effect", "ms", ran);
    }
    let report = report_text(&session.report);
    println!("SPIKE {label} accept lines: {:?}", report.lines().filter(|l| l.starts_with("accept")).collect::<Vec<_>>());
    let starts: Vec<u64> = report
        .lines()
        .filter(|l| l.starts_with("start_step "))
        .filter_map(|l| l.rsplit("since_prompt_us=").next()?.trim().parse::<u64>().ok())
        .collect();
    println!(
        "SPIKE {label} start steps: {} for {} prompts",
        starts.len(),
        report.lines().filter(|l| l.starts_with("prompt ")).count()
    );
    if !starts.is_empty() {
        distribution(label, "prompt-to-start-step", "us", starts);
    }
    let ending = session.finish();
    println!("SPIKE {label} {ending}");
    Outcome {
        p95_rtt_ms,
        answered: answers.len(),
        on_the_reader_thread,
        off_the_pool,
        person_ticks_never_went_back,
    }
}

#[test]
#[ignore = "measurement on a Windows runner: starts PowerShell in a pseudo-console"]
fn a_parked_reader_is_woken_by_the_idle_tick_and_answers_on_its_own_thread() {
    let tick = measure("tick", false);
    let start = measure("start", true);
    println!(
        "SPIKE decision: tick p95 {} ms, start-step session p95 {} ms; over 200 ms: {}",
        tick.p95_rtt_ms,
        start.p95_rtt_ms,
        tick.p95_rtt_ms > 200
    );
    for (name, outcome) in [("tick", &tick), ("start", &start)] {
        assert_eq!(outcome.answered, PINGS, "{name}: every request is answered");
        assert_eq!(
            outcome.on_the_reader_thread, PINGS,
            "{name}: every answer is written on the reader's own thread"
        );
        assert_eq!(
            outcome.off_the_pool, PINGS,
            "{name}: no answer is written on a pool thread"
        );
        assert!(
            outcome.person_ticks_never_went_back,
            "{name}: the person's own idle subscriber keeps running"
        );
    }
}
