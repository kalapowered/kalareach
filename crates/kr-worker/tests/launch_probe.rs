//! Running a package's launch probe.
//!
//! A package can declare how to read the mode its application will run in: the application's own
//! diagnostic, run before a launch with the options of the launch that decide which configuration
//! it reads. The probe is a program the package chose, run on this host, so what it may cost is
//! bounded: no input, no shell, a deadline, a cap on what it prints, and a job (a process group)
//! that ends with it, so nothing it started outlives the answer. The stand-in for the application
//! is a real program the platform has: `sh` on Unix and Windows PowerShell on Windows, each given
//! the script a test needs.
//!
//! | Row | What is checked here |
//! | --- | --- |
//! | KR-REQ-07.64 | The mode is read from what the program prints, and a nonzero exit status does not change that; the program runs in the launch's directory with no input; one that prints too much or never finishes records no mode and is ended with everything it started; one that cannot start says so; a program is held to the deadline it is given, and an answer after it is not taken; the probe runs in the environment it is given and in no other; one that is created after the deadline is ended by the thread that created it, and the call returns at the deadline; one that prints and keeps running, or whose descendant holds the output, is ended within the cleanup bound; the whole call, a wait for a thread included, takes no longer than the deadline and the cleanup bound |

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_plugin_sdk::launch_probe::LaunchProbe;
use kr_worker::broker::probe::{self, ProbeRun, Probed, ThreadEnd};

/// How long a probe is given in the tests that do not test the deadline.
const GENEROUS: Duration = Duration::from_secs(60);

/// One platform's stand-in for the application: the program and the arguments that run `script`.
struct Standin {
    program: PathBuf,
    arguments: Vec<String>,
    /// The modes its package says it cannot run with in a Windows service session.
    refused: Vec<String>,
}

/// Windows PowerShell reads a script it is given encoded as base64 of its UTF-16 text, which
/// carries no quotation or escaping for the command line to disturb.
#[cfg(windows)]
fn encoded(script: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let word = u32::from(chunk[0]) << 16
            | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            if index <= chunk.len() {
                text.push(char::from(
                    ALPHABET[(word >> (18 - 6 * index) & 63) as usize],
                ));
            } else {
                text.push('=');
            }
        }
    }
    text
}

impl Standin {
    /// A program that runs the script written for this platform.
    #[cfg(unix)]
    fn running(unix: &str, _windows: &str) -> Self {
        Self {
            program: PathBuf::from("/bin/sh"),
            arguments: vec!["-c".to_owned(), unix.to_owned()],
            refused: vec!["elevated".to_owned()],
        }
    }

    #[cfg(windows)]
    fn running(_unix: &str, windows: &str) -> Self {
        Self {
            program: Path::new(&std::env::var_os("SystemRoot").expect("a system directory"))
                .join(r"System32\WindowsPowerShell\v1.0\powershell.exe"),
            arguments: [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
            ]
            .iter()
            .map(|argument| (*argument).to_owned())
            .chain(std::iter::once(encoded(windows)))
            .collect(),
            refused: vec!["elevated".to_owned()],
        }
    }

    /// The probe a package declares for it: its own arguments, and the mode at `/mode`.
    fn probe(&self, carried: &[&str]) -> LaunchProbe {
        LaunchProbe {
            arguments: self.arguments.clone(),
            carried_options: carried.iter().map(|option| (*option).to_owned()).collect(),
            mode: "/mode".to_owned(),
            refused_in_service_session: self.refused.clone(),
            grant_statement: kr_plugin_sdk::text::Summary::new("Reads the mode for a launch")
                .expect("a literal summary"),
        }
    }

    fn run(&self, directory: &Path) -> Probed {
        probe::run_within(
            &self.program,
            &self.probe(&[]),
            &[],
            directory,
            &given(&[]),
            &ProbeRun::within(GENEROUS),
            probe::MAX_OUTPUT_BYTES,
        )
    }
}

fn directory() -> tempfile::TempDir {
    tempfile::tempdir().expect("a directory")
}

/// KR-REQ-07.64: the mode is what the program prints at the declared pointer, and an application's
/// diagnostic exits nonzero for a problem it reports in that output, so the exit status is not the
/// answer.
#[test]
fn kr_req_07_64_the_mode_is_read_from_what_the_program_prints_whatever_it_exits_with() {
    let standin = Standin::running(
        r#"printf '{"mode":"elevated"}'; exit 1"#,
        r#"[Console]::Out.Write('{"mode":"elevated"}'); exit 1"#,
    );
    let probed = standin.run(directory().path());
    assert_eq!(probed.mode.as_deref(), Some("elevated"), "{probed:?}");
    assert_eq!(probed.unread, None);
}

/// The variables a stand-in needs to start at all, and `extra` beside them: the whole environment a
/// probe is given, since it is given no other.
fn given(extra: &[(&str, &str)]) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    ["PATH", "SystemRoot", "windir"]
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|value| ((*name).into(), value)))
        .chain(
            extra
                .iter()
                .map(|(name, value)| ((*name).into(), (*value).into())),
        )
        .collect()
}

/// KR-REQ-07.64: the probe runs in the environment it is given and in no other: a variable of this
/// process that is not in the set is absent, and one that is in it is present.
#[test]
fn kr_req_07_64_the_probe_runs_in_the_environment_it_is_given() {
    // `CARGO_MANIFEST_DIR` is a variable of this test program, which the set does not hold.
    let standin = Standin::running(
        r#"printf '{"mode":"%s|%s"}' "${KR_PROBE_GIVEN:-none}" "${CARGO_MANIFEST_DIR:-none}""#,
        r#"[Console]::Out.Write('{"mode":"' + $(if ($env:KR_PROBE_GIVEN) { $env:KR_PROBE_GIVEN } else { 'none' }) + '|' + $(if ($env:CARGO_MANIFEST_DIR) { $env:CARGO_MANIFEST_DIR } else { 'none' }) + '"}')"#,
    );
    assert!(
        std::env::var_os("CARGO_MANIFEST_DIR").is_some(),
        "this program has a variable that the set below does not"
    );
    let probed = probe::run_within(
        &standin.program,
        &standin.probe(&[]),
        &[],
        directory().path(),
        &given(&[("KR_PROBE_GIVEN", "yes")]),
        &ProbeRun::within(GENEROUS),
        probe::MAX_OUTPUT_BYTES,
    );
    assert_eq!(probed.mode.as_deref(), Some("yes|none"), "{probed:?}");
}

/// KR-REQ-07.64: the program runs in the directory the launch runs in and is given no input, so a
/// diagnostic that reads its input is at the end of it and never waits for one.
#[test]
fn kr_req_07_64_the_program_runs_in_the_launch_directory_and_is_given_no_input() {
    let here = directory();
    let name = here
        .path()
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .expect("a name")
        .to_owned();
    let standin = Standin::running(
        r#"read line; printf '{"mode":"%s|%s"}' "$(basename "$PWD")" "${line:-end}""#,
        r#"$line = [Console]::In.ReadLine(); if ($null -eq $line) { $line = 'end' }; [Console]::Out.Write('{"mode":"' + (Split-Path -Leaf $PWD) + '|' + $line + '"}')"#,
    );
    let probed = standin.run(here.path());
    assert_eq!(probed.mode, Some(format!("{name}|end")), "{probed:?}");
}

/// KR-REQ-07.64: what the program prints that the declaration cannot read records no mode and says
/// why: not JSON, and a string that is not a mode.
#[test]
fn kr_req_07_64_output_the_declaration_cannot_read_records_no_mode() {
    let not_json = Standin::running("printf 'not json'", "[Console]::Out.Write('not json')");
    let probed = not_json.run(directory().path());
    assert_eq!(probed.mode, None);
    assert!(probed.unread.is_some(), "{probed:?}");
    assert!(
        !probed.late,
        "it answered, with nothing a mode can be read from"
    );
    let not_a_string = Standin::running(
        r#"printf '{"mode":7}'"#,
        r#"[Console]::Out.Write('{"mode":7}')"#,
    );
    assert_eq!(not_a_string.run(directory().path()).mode, None);
}

/// KR-REQ-07.64: a program that prints more than the cap records no mode and is not read further.
#[test]
fn kr_req_07_64_a_program_that_prints_more_than_the_cap_records_no_mode() {
    let standin = Standin::running(
        r"head -c 20000 /dev/zero | tr '\0' x",
        "[Console]::Out.Write('x' * 20000)",
    );
    let probed = probe::run_within(
        &standin.program,
        &standin.probe(&[]),
        &[],
        directory().path(),
        &given(&[]),
        &ProbeRun::within(GENEROUS),
        1000,
    );
    assert_eq!(probed.mode, None);
    assert!(
        probed
            .unread
            .as_deref()
            .is_some_and(|why| why.contains("more than 1000 bytes")),
        "{probed:?}"
    );
    assert!(!probed.late, "it printed, and printed too much");
}

/// The process identifier a stand-in wrote to `file` in `directory`, once it has written all of it.
fn written_pid(directory: &Path, file: &str) -> Option<u32> {
    std::fs::read_to_string(directory.join(file))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// KR-REQ-07.64: a program that never finishes is ended when its deadline passes, with what it
/// started, and records no mode. Neither the program nor its child is left running.
///
/// The deadline has to pass after the program has started what it starts, and how soon it does that
/// is the machine's to say. So the probe is given a longer deadline, up to `GENEROUS`, each time
/// the program is found not to have started it yet, and what is decided is the state of the
/// processes once a probe that the program was running in has been ended.
#[test]
fn kr_req_07_64_a_program_that_never_finishes_is_ended_with_everything_it_started() {
    let mut deadline = if cfg!(windows) {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(3)
    };
    let (here, probed) = loop {
        let here = directory();
        let standin = Standin::running(
            r#"echo $$ > main.pid; sleep 600 & echo $! > child.pid; wait"#,
            r#"$PID | Out-File -Encoding ascii main.pid; $child = Start-Process "$env:SystemRoot\System32\ping.exe" -ArgumentList '-n','600','127.0.0.1' -PassThru -WindowStyle Hidden; $child.Id | Out-File -Encoding ascii child.pid; Start-Sleep 600"#,
        );
        let probed = probe::run_within(
            &standin.program,
            &standin.probe(&[]),
            &[],
            here.path(),
            &given(&[]),
            &ProbeRun::within(deadline),
            probe::MAX_OUTPUT_BYTES,
        );
        if ["main.pid", "child.pid"]
            .iter()
            .all(|file| written_pid(here.path(), file).is_some())
        {
            break (here, probed);
        }
        assert!(
            deadline < GENEROUS,
            "the program had not started what it starts within {deadline:?}: {probed:?}"
        );
        deadline = (deadline * 2).min(GENEROUS);
    };
    assert_eq!(probed.mode, None);
    assert!(
        probed
            .unread
            .as_deref()
            .is_some_and(|why| why.contains("did not finish")),
        "{probed:?}"
    );
    assert!(probed.late, "a probe that never finishes is late");
    let end = thread_end(&probed);
    assert!(
        end.collected_in_bound,
        "the probe was ended and collected within the cleanup bound: {end:?}"
    );
    assert!(
        end.took <= deadline + probe::CLEANUP_BOUND + SLACK,
        "the thread's total, cleanup included: {:?}",
        end.took
    );
    let left = survivors(here.path(), &["main.pid", "child.pid"]);
    assert!(
        left.is_empty(),
        "left running after the thread ended: {left:?}"
    );
}

/// KR-REQ-07.64: a program that cannot be started says so, by what it was.
#[test]
fn kr_req_07_64_a_program_that_cannot_start_records_no_mode_and_says_so() {
    let standin = Standin::running("true", "exit 0");
    let missing = directory().path().join("no-such-application");
    let probed = probe::run_within(
        &missing,
        &standin.probe(&[]),
        &[],
        directory().path(),
        &given(&[]),
        &ProbeRun::within(GENEROUS),
        probe::MAX_OUTPUT_BYTES,
    );
    assert_eq!(probed.mode, None);
    assert!(
        probed
            .unread
            .as_deref()
            .is_some_and(|why| why.contains("could not be started")),
        "{probed:?}"
    );
    assert!(!probed.late, "it never ran, so it was not late");
}

/// A digest of the names and bytes under `root`, to tell a tree that a probe ran in from one it
/// changed.
fn tree_state(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(directory: &Path, found: &mut Vec<(PathBuf, Vec<u8>)>) {
        let mut paths: Vec<_> = std::fs::read_dir(directory)
            .expect("lists the directory")
            .map(|entry| entry.expect("an entry").path())
            .collect();
        paths.sort();
        for path in paths {
            if path.is_dir() {
                found.push((path.clone(), Vec::new()));
                walk(&path, found);
            } else {
                let bytes = std::fs::read(&path).expect("reads the file");
                found.push((path, bytes));
            }
        }
    }
    let mut found = Vec::new();
    walk(root, &mut found);
    found
}

/// How long the slow stand-in takes to print its answer, in seconds.
const SLOW_SECONDS: u64 = 10;

/// KR-REQ-07.64: a probe is held to the deadline it is given. An answer that comes after the
/// deadline is not taken, and the same program is read under a deadline longer than it takes.
///
/// The stand-in names a mode, but only after `SLOW_SECONDS`. Given a deadline of two seconds, the
/// runner returns late with no mode, though the answer the stand-in would give names one. Given
/// `GENEROUS`, the runner reads that same answer, so what ended the first run is the deadline it
/// was given and not a refusal of the stand-in's answer. A runner that keeps a bound of its own,
/// whatever deadline it is given, fails one of the two runs: one at or past the stand-in's answer
/// takes the answer in the first, and a shorter one gives up in the second. A bound that exceeds
/// the given deadline by less than the stand-in's delay is not told apart from the deadline here.
///
/// The case decides by the two results and by no measured time. The stand-ins write nothing, so a
/// change to the directory the runner ran in after either run is the runner's own.
#[test]
fn kr_req_07_64_a_probe_is_held_to_the_deadline_it_is_given_and_a_late_answer_is_not_taken() {
    let tree = kr_ipc::testing::PrivateTempDir::create();
    let root = tree.path();
    std::fs::create_dir_all(root.join("projects").join("notes")).expect("makes the directories");
    std::fs::write(root.join("projects").join("notes").join("a.txt"), b"a file").expect("a file");
    std::fs::write(root.join("top.txt"), b"another file").expect("another file");
    let before = tree_state(root);

    let slow = Standin::running(
        &format!(r#"sleep {SLOW_SECONDS}; printf '{{"mode":"elevated"}}'"#),
        &format!(r#"Start-Sleep {SLOW_SECONDS}; [Console]::Out.Write('{{"mode":"elevated"}}')"#),
    );
    let within = |deadline: Duration| {
        probe::run_within(
            &slow.program,
            &slow.probe(&[]),
            &[],
            root,
            &given(&[]),
            &ProbeRun::within(deadline),
            probe::MAX_OUTPUT_BYTES,
        )
    };

    let late = within(Duration::from_secs(2));
    assert_eq!(
        late.mode, None,
        "the answer that comes after the deadline is not taken: {late:?}"
    );
    assert!(late.late, "{late:?}");
    assert_eq!(
        tree_state(root),
        before,
        "the directory is as it was after a late probe"
    );

    let read = within(GENEROUS);
    assert_eq!(
        read.mode.as_deref(),
        Some("elevated"),
        "the same program is read under a deadline longer than it takes: {read:?}"
    );
    assert!(!read.late, "{read:?}");
    assert_eq!(
        tree_state(root),
        before,
        "the directory is as it was after an answered probe"
    );
}

/// How long a case waits for the probe's own thread to end after the call has returned.
const THREAD_PATIENCE: Duration = Duration::from_secs(30);

/// How much later than its bound a call may be for a loaded machine's scheduling.
const SLACK: Duration = Duration::from_millis(1500);

/// How the probe's thread ended, waited for until it has.
fn thread_end(probed: &Probed) -> ThreadEnd {
    let started = Instant::now();
    loop {
        if let Some(end) = probed.thread.get() {
            return *end;
        }
        assert!(
            started.elapsed() < THREAD_PATIENCE,
            "the probe's thread never ended"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The time the probe's thread took in all, waited for until it has ended.
fn thread_total(probed: &Probed) -> Duration {
    thread_end(probed).took
}

/// The processes a stand-in wrote to `files` that are still there `SLACK` after the probe's thread
/// has ended.
fn survivors(directory: &Path, files: &[&str]) -> Vec<String> {
    let started = Instant::now();
    let mut left = Vec::new();
    for file in files {
        let pid = written_pid(directory, file).unwrap_or_else(|| panic!("{file} was not written"));
        while kr_ipc::identity::process_start_identity(pid).is_ok() {
            if started.elapsed() >= SLACK {
                left.push(format!("{file} ({pid})"));
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    left
}

/// How long a stand-in is given to start what it starts, where a case needs that to have happened.
fn start_allowance() -> Duration {
    if cfg!(windows) {
        Duration::from_secs(15)
    } else {
        Duration::from_secs(5)
    }
}

/// How long the case of a late create holds the create back.
const LATE_CREATE: Duration = Duration::from_secs(5);

/// KR-REQ-07.64: a process created after the deadline is ended by the thread that created it, at
/// once, and the call has returned at the deadline without waiting for the create.
///
/// The create is held back for `LATE_CREATE`, which is far longer than the deadline and the slack a
/// call may take, so that a call that waited for the create would be seen on a machine of any speed.
/// The stand-in would write `ran.txt` a second after it starts, and it never does, because it is
/// ended as it is made.
#[test]
fn kr_req_07_64_a_probe_created_after_the_deadline_is_ended_by_its_creator() {
    let here = directory();
    let standin = Standin::running(
        "sleep 1; echo ran > ran.txt; sleep 600",
        "Start-Sleep 1; 'ran' | Out-File ran.txt; Start-Sleep 600",
    );
    let deadline = Duration::from_secs(1);
    probe::seams::delay_at(probe::seams::Point::Create, here.path(), Some(LATE_CREATE));
    let run = ProbeRun::within(deadline);
    let probed = probe::run_within(
        &standin.program,
        &standin.probe(&[]),
        &[],
        here.path(),
        &given(&[]),
        &run,
        probe::MAX_OUTPUT_BYTES,
    );
    probe::seams::delay_at(probe::seams::Point::Create, here.path(), None);
    assert!(probed.late, "{probed:?}");
    assert_eq!(probed.mode, None);
    assert!(
        probed.took >= deadline && probed.took < deadline + SLACK,
        "the call returned at the deadline, not when the create did: {:?}",
        probed.took
    );
    let total = thread_total(&probed);
    assert!(
        total < LATE_CREATE + probe::CLEANUP_BOUND + SLACK,
        "the thread ended what it made at once: {total:?}"
    );
    // Longer than the stand-in's own second, and than a Windows shell takes to begin.
    std::thread::sleep(Duration::from_secs(if cfg!(windows) { 8 } else { 3 }));
    assert!(
        !here.path().join("ran.txt").exists(),
        "a probe created after the deadline ran"
    );
}

/// KR-REQ-07.64: a probe that prints a mode and goes on running is late, is ended within the cleanup
/// bound after the deadline, and nothing it ran is left.
#[test]
fn kr_req_07_64_a_probe_that_prints_and_keeps_running_is_ended_within_the_cleanup_bound() {
    let here = directory();
    let standin = Standin::running(
        r#"echo $$ > main.pid; printf '{"mode":"elevated"}'; sleep 600"#,
        r#"$PID | Out-File -Encoding ascii main.pid; [Console]::Out.Write('{"mode":"elevated"}'); Start-Sleep 600"#,
    );
    let deadline = start_allowance();
    let run = ProbeRun::within(deadline);
    let probed = probe::run_within(
        &standin.program,
        &standin.probe(&[]),
        &[],
        here.path(),
        &given(&[]),
        &run,
        probe::MAX_OUTPUT_BYTES,
    );
    assert!(probed.late, "its output had not ended: {probed:?}");
    assert!(
        probed.took <= deadline + probe::CLEANUP_BOUND + SLACK,
        "{:?}",
        probed.took
    );
    let end = thread_end(&probed);
    assert!(
        end.collected_in_bound,
        "the probe was ended and collected within the cleanup bound: {end:?}"
    );
    assert!(
        end.took <= deadline + probe::CLEANUP_BOUND + SLACK,
        "the thread's total, cleanup included: {:?}",
        end.took
    );
    let left = survivors(here.path(), &["main.pid"]);
    assert!(
        left.is_empty(),
        "left running after the thread ended: {left:?}"
    );
}

/// KR-REQ-07.64: the whole call, a wait for a thread before it included, is bounded by the deadline
/// and the cleanup bound, and a call whose deadline passed in the wait starts nothing.
#[test]
fn kr_req_07_64_the_total_time_is_bounded_by_the_deadline_plus_the_cleanup_bound() {
    let here = directory();
    let standin = Standin::running(
        "echo $$ > main.pid; sleep 600",
        "$PID | Out-File -Encoding ascii main.pid; Start-Sleep 600",
    );
    let deadline = start_allowance();
    let run = ProbeRun::within(deadline);
    // A queue: a second of the deadline goes before the call is made.
    std::thread::sleep(Duration::from_secs(1));
    let probed = probe::run_within(
        &standin.program,
        &standin.probe(&[]),
        &[],
        here.path(),
        &given(&[]),
        &run,
        probe::MAX_OUTPUT_BYTES,
    );
    assert!(probed.late, "{probed:?}");
    assert!(
        probed.took >= deadline && probed.took <= deadline + probe::CLEANUP_BOUND + SLACK,
        "from the caller's first instant, the wait included: {:?}",
        probed.took
    );
    let total = thread_total(&probed);
    assert!(
        total <= deadline + probe::CLEANUP_BOUND + SLACK,
        "the thread's total, cleanup included: {total:?}"
    );
    let end = thread_end(&probed);
    assert!(
        end.collected_in_bound,
        "the probe was ended and collected within the cleanup bound: {end:?}"
    );
    let left = survivors(here.path(), &["main.pid"]);
    assert!(
        left.is_empty(),
        "left running after the thread ended: {left:?}"
    );

    let queued = directory();
    let standin = Standin::running(
        "echo ran > ran.txt; sleep 600",
        "'ran' | Out-File ran.txt; Start-Sleep 600",
    );
    let run = ProbeRun::within(Duration::from_millis(200));
    std::thread::sleep(Duration::from_millis(400));
    let probed = probe::run_within(
        &standin.program,
        &standin.probe(&[]),
        &[],
        queued.path(),
        &given(&[]),
        &run,
        probe::MAX_OUTPUT_BYTES,
    );
    assert!(probed.late, "{probed:?}");
    std::thread::sleep(Duration::from_secs(if cfg!(windows) { 6 } else { 2 }));
    assert!(
        probed.thread.get().is_none(),
        "a call whose deadline passed in the queue started a thread, and so a process"
    );
}

/// KR-REQ-07.64: a descendant that holds the output open after the probe has printed and ended does
/// not hold the call: it returns at the deadline, and the descendant is ended with the probe.
#[test]
fn kr_req_07_64_a_probe_whose_descendant_holds_the_output_does_not_hold_the_call() {
    let here = directory();
    let standin = Standin::running(
        r#"(sleep 600 & echo $! > child.pid); printf '{"mode":"elevated"}'; exit 0"#,
        r#"$child = Start-Process "$env:SystemRoot\System32\ping.exe" -ArgumentList '-n','600','127.0.0.1' -PassThru -NoNewWindow; $child.Id | Out-File -Encoding ascii child.pid; [Console]::Out.Write('{"mode":"elevated"}')"#,
    );
    let deadline = start_allowance();
    let run = ProbeRun::within(deadline);
    let probed = probe::run_within(
        &standin.program,
        &standin.probe(&[]),
        &[],
        here.path(),
        &given(&[]),
        &run,
        probe::MAX_OUTPUT_BYTES,
    );
    assert!(probed.late, "the output had not ended: {probed:?}");
    assert!(
        probed.took <= deadline + probe::CLEANUP_BOUND + SLACK,
        "{:?}",
        probed.took
    );
    let end = thread_end(&probed);
    assert!(
        end.collected_in_bound,
        "the probe was ended and collected within the cleanup bound: {end:?}"
    );
    assert!(
        end.took <= deadline + probe::CLEANUP_BOUND + SLACK,
        "the thread's total, cleanup included: {:?}",
        end.took
    );
    let left = survivors(here.path(), &["child.pid"]);
    assert!(
        left.is_empty(),
        "left running after the thread ended: {left:?}"
    );
}

/// Whether the process table still holds `pid`, a process that has ended and has not been collected
/// included.
#[cfg(unix)]
fn in_process_table(pid: u32) -> bool {
    i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .is_some_and(|pid| rustix::process::test_kill_process(pid).is_ok())
}

/// KR-REQ-07.64: on Unix a probe that the kernel has not let go of within the cleanup bound is
/// collected later by the thread that owns it, and the call keeps its bound.
///
/// The case holds the probe's collection back for four seconds, past the deadline of two and the
/// bound of one. The probe is ended at the deadline, so that it is a process that has ended and is
/// not yet collected until the hold is over.
#[cfg(unix)]
#[test]
fn kr_req_07_64_a_probe_not_collected_within_the_bound_is_collected_later() {
    let here = directory();
    let standin = Standin::running("echo $$ > main.pid; sleep 600", "");
    let deadline = Duration::from_secs(2);
    let hold = Duration::from_secs(4);
    probe::seams::hold_collection(here.path(), Some(hold));
    let run = ProbeRun::within(deadline);
    let probed = probe::run_within(
        &standin.program,
        &standin.probe(&[]),
        &[],
        here.path(),
        &given(&[]),
        &run,
        probe::MAX_OUTPUT_BYTES,
    );
    probe::seams::hold_collection(here.path(), None);
    assert!(probed.late, "{probed:?}");
    assert!(
        probed.took >= deadline && probed.took <= deadline + probe::CLEANUP_BOUND + SLACK,
        "the caller keeps its deadline: {:?}",
        probed.took
    );
    let pid = written_pid(here.path(), "main.pid").expect("main.pid was written");
    assert!(
        in_process_table(pid),
        "the premise: the probe has ended and is not yet collected"
    );
    let end = thread_end(&probed);
    assert!(
        !end.collected_in_bound,
        "the collection was held past the bound: {end:?}"
    );
    assert!(
        end.took >= hold,
        "the thread kept the probe until it collected it: {end:?}"
    );
    assert!(
        !in_process_table(pid),
        "the probe was collected, not left to the end of this process"
    );
}

/// KR-REQ-07.64: a start that fails after the process was created, and cannot end it, gives up on
/// ending it within the cleanup bound and not after the launch's own longer wait.
///
/// The start is made to fail after its create, with a handle that cannot end the process, so the
/// process shows no sign of ending. A launch waits ten seconds for that; the probe's one second is
/// what the call and its thread keep.
#[cfg(windows)]
#[test]
fn kr_req_07_64_a_start_that_fails_after_the_create_is_ended_within_the_cleanup_bound() {
    let here = directory();
    let standin = Standin::running("", "Start-Sleep 600");
    kr_worker::windows::launch::seams::fail_start_in(Some(here.path()));
    let probed = probe::run_within(
        &standin.program,
        &standin.probe(&[]),
        &[],
        here.path(),
        &given(&[]),
        &ProbeRun::within(start_allowance()),
        probe::MAX_OUTPUT_BYTES,
    );
    kr_worker::windows::launch::seams::fail_start_in(None);
    let why = probed.unread.as_deref().unwrap_or_default();
    assert!(
        why.contains("could not be ended either"),
        "the premise: the process could not be ended: {probed:?}"
    );
    assert!(
        probed.took < probe::CLEANUP_BOUND + SLACK,
        "the call gave up on the end within the cleanup bound: {:?}",
        probed.took
    );
    let total = thread_total(&probed);
    assert!(
        total < probe::CLEANUP_BOUND + SLACK,
        "the thread gave up on the end within the cleanup bound: {total:?}"
    );
}

/// KR-REQ-07.64: an answer whose output ended after the deadline is late, however soon the call has
/// it: the call's wait is held back past the deadline, so that it takes the thread's answer after the
/// moment it ought to have given up.
///
/// The stand-in prints a mode at once. A control run under the same deadline reads it. Then the
/// thread is held back after its final read, past the deadline, and the call is held back before it
/// waits, until the deadline has passed. The call then has the answer in hand, and the answer is
/// late all the same.
#[test]
fn kr_req_07_64_an_answer_that_ended_after_the_deadline_is_late_though_the_call_has_it() {
    let here = directory();
    let standin = Standin::running(
        r#"printf '{"mode":"elevated"}'"#,
        r#"[Console]::Out.Write('{"mode":"elevated"}')"#,
    );
    let deadline = if cfg!(windows) {
        start_allowance()
    } else {
        Duration::from_secs(2)
    };
    let within = || {
        probe::run_within(
            &standin.program,
            &standin.probe(&[]),
            &[],
            here.path(),
            &given(&[]),
            &ProbeRun::within(deadline),
            probe::MAX_OUTPUT_BYTES,
        )
    };
    let control = within();
    assert_eq!(
        control.mode.as_deref(),
        Some("elevated"),
        "the premise: the program prints its mode within the deadline: {control:?}"
    );
    assert!(!control.late, "{control:?}");

    probe::seams::delay_at(
        probe::seams::Point::FinalRead,
        here.path(),
        Some(deadline + Duration::from_millis(300)),
    );
    probe::seams::delay_at(
        probe::seams::Point::Receive,
        here.path(),
        Some(deadline + Duration::from_millis(100)),
    );
    let probed = within();
    probe::seams::delay_at(probe::seams::Point::FinalRead, here.path(), None);
    probe::seams::delay_at(probe::seams::Point::Receive, here.path(), None);
    assert!(
        probed.late,
        "an answer that ended after the deadline is late: {probed:?}"
    );
    assert_eq!(probed.mode, None, "{probed:?}");
}
