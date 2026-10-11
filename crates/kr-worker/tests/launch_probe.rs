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
//! | KR-REQ-07.64 | The mode is read from what the program prints, and a nonzero exit status does not change that; the program runs in the launch's directory with no input; one that prints too much or never finishes records no mode and is ended with everything it started; one that cannot start says so |

use std::path::{Path, PathBuf};
use std::time::Duration;

use kr_plugin_sdk::launch_probe::LaunchProbe;
use kr_worker::broker::probe::{self, Probed};

mod common;

use common::LIVENESS_DEADLINE;

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
            GENEROUS,
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
        GENEROUS,
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
            deadline,
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
    for file in ["main.pid", "child.pid"] {
        let pid = written_pid(here.path(), file).expect("a process identifier");
        let started = std::time::Instant::now();
        while kr_ipc::identity::process_start_identity(pid).is_ok() {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "process {pid} ({file}) outlived the probe"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
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
        GENEROUS,
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
