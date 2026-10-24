//! `scripts/android-app-launch.sh` on a device whose application's process ends.
//!
//! The script is run as committed against `adb` and a debugging endpoint that
//! `tests/fixtures/android-launch/device.py` stands in for: no emulator starts, and the script's
//! own steps, its page check over the debugging protocol and its reading of the screen all run. The
//! logs a device wrote as the application's process ended are real ones, each cut to the end of the
//! process and to 300 columns a line (one leaves out the tombstone the crash wrote in its middle):
//! two from hosted runners, whose low-memory killer ended the application and its web view's
//! renderer, and two from an emulator, where the application crashed, so what the script says of
//! how a process ended is held to the real thing. Every case decides by what the script says and
//! keeps, never by how long it took: the deadline is long, so a script that waits out a process
//! that is gone fails on its message.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/android-launch")
}

/// The debugging endpoint of the stand-in device, stopped when it goes out of scope.
struct Endpoint(Child);

impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// What a run of the script said and kept.
struct Launch {
    output: String,
    status: Option<i32>,
    screenshot: PathBuf,
    _directory: TempDir,
}

impl Launch {
    /// The width and height the screenshot's PNG header states, when it is a PNG.
    fn picture(&self) -> Option<(u32, u32)> {
        let bytes = fs::read(&self.screenshot).ok()?;
        if bytes.get(..8)? != b"\x89PNG\r\n\x1a\n" {
            return None;
        }
        let number = |from: usize| {
            Some(u32::from_be_bytes(
                bytes.get(from..from + 4)?.try_into().ok()?,
            ))
        };
        Some((number(16)?, number(20)?))
    }
}

/// Runs the script on a device whose application has the process `pid`, which ends at `ends` (see
/// `device.py`) with the lines of `ending_log` in the device's log.
fn launch(pid: &str, ending_log: &str, ends: &str) -> Launch {
    launch_with(pid, ending_log, ends, &[])
}

/// The same, on a device with the further state files `state_files` name, each with its contents
/// (see `device.py`).
fn launch_with(pid: &str, ending_log: &str, ends: &str, state_files: &[(&str, &str)]) -> Launch {
    let directory = TempDir::new().expect("a directory");
    let root = directory.path();
    let state = root.join("state");
    let tools = root.join("tools");
    fs::create_dir_all(&state).expect("a directory");
    fs::create_dir_all(&tools).expect("a directory");
    fs::write(state.join("pid"), pid).expect("a process");
    fs::write(state.join("ends"), ends).expect("an end");
    fs::copy(fixtures().join(ending_log), state.join("ending.log")).expect("the log");
    fs::write(root.join("application.apk"), "").expect("a package");
    for (name, contents) in state_files {
        fs::write(state.join(name), contents).expect("a state file");
    }

    let device = fixtures().join("device.py");
    let adb = tools.join("adb");
    fs::write(
        &adb,
        format!("#!/bin/sh\nexec python3 \"{}\" \"$@\"\n", device.display()),
    )
    .expect("a stand-in");
    fs::set_permissions(&adb, fs::Permissions::from_mode(0o755)).expect("executable");

    let _endpoint = Endpoint(
        Command::new("python3")
            .arg(&device)
            .arg("serve")
            .env("KR_FAKE_DEVICE_DIR", &state)
            .stdout(Stdio::null())
            .spawn()
            .expect("the endpoint starts"),
    );
    let started = Instant::now();
    while !state.join("port").exists() {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the endpoint did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let screenshot = root.join("evidence/launch.png");
    let inherited = std::env::var("PATH").unwrap_or_default();
    let output = Command::new("bash")
        .arg(repository().join("scripts/android-app-launch.sh"))
        .arg(root.join("application.apk"))
        .arg(&screenshot)
        .args(["--serial", "emulator-5554"])
        .env("PATH", format!("{}:{inherited}", tools.display()))
        .env("KR_FAKE_DEVICE_DIR", &state)
        .env("KR_LAUNCH_DEADLINE", "60")
        .env("NO_PROXY", "*")
        .env_remove("ANDROID_SERIAL")
        .output()
        .expect("the script runs");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Launch {
        output: text,
        status: output.status.code(),
        screenshot,
        _directory: directory,
    }
}

/// An application whose process lives through every check passes, and the picture it keeps is the
/// frame the script found to show the page.
#[test]
fn an_application_that_stays_up_passes_and_keeps_the_frame_it_checked() {
    let run = launch("7072", "application-killed.log", "never");
    assert_eq!(run.status, Some(0), "{}", run.output);
    assert_eq!(run.picture(), Some((64, 128)), "{}", run.output);
}

/// A process the system ended while the script waits for the web view's document is named when it
/// ends, with how, and is not waited for until the deadline: the log of a hosted runner whose
/// low-memory killer ended the application itself.
#[test]
fn a_process_that_ends_while_the_script_waits_is_named_and_not_waited_out() {
    let run = launch("7072", "application-killed.log", "socket");
    assert_eq!(run.status, Some(1), "{}", run.output);
    assert!(
        run.output
            .contains("ended while waiting for the web view to list the interface's own document"),
        "{}",
        run.output
    );
    assert!(
        run.output
            .contains("low-memory killer of the system ended the application"),
        "{}",
        run.output
    );
    assert!(!run.output.contains("gave up waiting"), "{}", run.output);
}

/// A frame read from a screen whose application is gone is not taken for the page: the run fails
/// with how the process ended, and the frame is kept as the evidence. The log is a hosted runner's
/// whose low-memory killer ended the web view's renderer, which ended the application with it.
#[test]
fn a_process_gone_when_the_screen_was_read_is_named_and_the_frame_is_kept() {
    let run = launch("8161", "renderer-lost.log", "screen");
    assert_eq!(run.status, Some(1), "{}", run.output);
    assert!(
        run.output.contains("ended when the screen was read"),
        "{}",
        run.output
    );
    assert!(
        run.output.contains(
            "ended the renderer of the web view and the web view then ended the application"
        ),
        "{}",
        run.output
    );
    assert_eq!(run.picture(), Some((64, 128)), "{}", run.output);
}

/// A process that ends after the page was drawn, while the script reads the log, fails the run
/// with how it ended, and the screenshot of the page stays.
#[test]
fn a_process_that_ends_after_the_page_was_drawn_fails_the_run_with_its_cause() {
    let run = launch("7072", "application-killed.log", "log");
    assert_eq!(run.status, Some(1), "{}", run.output);
    assert!(
        run.output.contains("ended after the log was read"),
        "{}",
        run.output
    );
    assert!(
        run.output
            .contains("low-memory killer of the system ended the application"),
        "{}",
        run.output
    );
    assert_eq!(run.picture(), Some((64, 128)), "{}", run.output);
}

/// A crash is named as one, with the lines the system logged for it, whether the application's own
/// code threw (an exception its main thread did not catch) or its web view's renderer crashed and
/// the web view crashed the application with it. The logs are an emulator's.
#[test]
fn a_crash_of_the_application_is_named_as_a_crash_with_the_lines_that_show_it() {
    for (pid, log, shown) in [
        ("2347", "application-crashed.log", "FATAL EXCEPTION: main"),
        (
            "2605",
            "renderer-crash-ends-application.log",
            "Fatal signal 5 (SIGTRAP)",
        ),
    ] {
        let run = launch(pid, log, "socket");
        assert_eq!(run.status, Some(1), "{}", run.output);
        assert!(
            run.output.contains("the application crashed"),
            "{}",
            run.output
        );
        assert!(run.output.contains(shown), "{}", run.output);
    }
}

/// A screen in a pixel format the script does not read stops the run at once with the format named,
/// and not at the deadline with a screen that is said not to show the page.
#[test]
fn a_screen_in_another_pixel_format_stops_the_run_with_the_format_named() {
    let run = launch_with("7072", "application-killed.log", "never", &[("format", "")]);
    assert_eq!(run.status, Some(1), "{}", run.output);
    assert!(run.output.contains("pixel format 4"), "{}", run.output);
    assert!(!run.output.contains("gave up waiting"), "{}", run.output);
}

/// A capture that failed writes its error text where the frame would be, and the text is not a
/// screen in some pixel format: the screen is read again, and the run goes on to keep the frame
/// that shows the page.
#[test]
fn a_capture_that_failed_is_read_again_and_not_taken_for_a_pixel_format() {
    let run = launch_with(
        "7072",
        "application-killed.log",
        "never",
        &[("unreadable-screens", "2")],
    );
    assert_eq!(run.status, Some(0), "{}", run.output);
    assert!(!run.output.contains("pixel format"), "{}", run.output);
    assert_eq!(run.picture(), Some((64, 128)), "{}", run.output);
}
