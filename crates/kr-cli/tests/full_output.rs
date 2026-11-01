//! What `kr` does when a stream it writes to has no room left.
//!
//! KR-REQ-27.05, full disks: `/dev/full` answers every write with ENOSPC, the error a full
//! filesystem gives, so a command whose standard output or standard error is that device meets the
//! refusal at the write it makes. Each case runs the built `kr` as a process, once with room as the
//! control and once with the stream on the device.
//!
//! Linux only: `/dev/full` is a Linux device.

#![cfg(target_os = "linux")]

use std::process::{Command, Output, Stdio};

use kr_cli::bridge::pipe;
use kr_protocol::identity::BridgeFrame;

mod support;

/// The exit status a command ends with when it could not write to the terminal.
const TERMINAL_FAILURE: i32 = 6;

/// The exit status of a command line that names no command.
const USAGE_FAILURE: i32 = 2;

/// The exit status of a command the host or the peer refused.
const REFUSED: i32 = 8;

/// The device that takes no byte.
fn full() -> Stdio {
    Stdio::from(
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("opens the device that has no room"),
    )
}

/// Runs the built `kr` with `line`, from the root directory, with the directories of `temp`.
fn run(temp: &kr_ipc::testing::TempHost, line: &[&str], stdout: Stdio, stderr: Stdio) -> Output {
    Command::new(support::kr())
        .args(line)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", temp.root())
        .env("KR_RUNTIME_DIR", temp.paths().runtime_root())
        .env("KR_STATE_DIR", temp.paths().state_root())
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .output()
        .expect("kr runs")
}

/// Runs the built `kr` with `line`, hands it `input` on standard input and closes it, and collects
/// standard output, with standard error on `stderr`.
fn run_fed(temp: &kr_ipc::testing::TempHost, line: &[&str], input: &[u8], stderr: Stdio) -> Output {
    use std::io::Write as _;

    let mut child = Command::new(support::kr())
        .args(line)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", temp.root())
        .env("KR_RUNTIME_DIR", temp.paths().runtime_root())
        .env("KR_STATE_DIR", temp.paths().state_root())
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(stderr)
        .spawn()
        .expect("kr starts");
    // The command may end before it has read everything it was given.
    let _ = child
        .stdin
        .take()
        .expect("standard input is piped")
        .write_all(input);
    child.wait_with_output().expect("kr ends")
}

/// The frames `output` holds, read with the bridge's own codec. A byte that is not part of a whole
/// frame, a line of text among them, fails here.
fn frames_of(output: &[u8]) -> Vec<BridgeFrame> {
    let mut cursor = std::io::Cursor::new(output);
    let mut frames = Vec::new();
    while usize::try_from(cursor.position()).is_ok_and(|read| read < output.len()) {
        frames.push(
            pipe::read_frame(&mut cursor)
                .expect("standard output holds whole frames and nothing else"),
        );
    }
    frames
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A command that has succeeded and cannot write its answer to a full standard output says so on
/// standard error and ends with the failure for the terminal, whichever of the program's three ways
/// of writing a line the answer takes: `--version` is a word of the program's own, `shell remove
/// --dry-run` is a set of composed lines and `--json` writes a document.
#[test]
fn a_command_whose_standard_output_has_no_room_says_so_on_standard_error_and_fails() {
    let temp = kr_ipc::testing::TempHost::create();
    for line in [
        &["--version"][..],
        &["shell", "remove", "--dry-run"][..],
        &["--json", "shell", "remove", "--dry-run"][..],
    ] {
        let control = run(&temp, line, Stdio::piped(), Stdio::piped());
        assert_eq!(
            control.status.code(),
            Some(0),
            "kr {line:?} with room: {}",
            text(&control.stderr)
        );
        assert!(
            !control.stdout.is_empty(),
            "kr {line:?} writes its answer on standard output"
        );

        let refused = run(&temp, line, full(), Stdio::piped());
        assert_eq!(
            refused.status.code(),
            Some(TERMINAL_FAILURE),
            "kr {line:?} with a full standard output: {}",
            text(&refused.stderr)
        );
        assert!(
            text(&refused.stderr).contains("standard output"),
            "kr {line:?} names the stream it could not write: {}",
            text(&refused.stderr)
        );
    }
}

/// A command that has failed and cannot write the document that says so to a full standard output
/// says what it could not write on standard error and ends with its own failure.
#[test]
fn a_failure_document_that_a_full_standard_output_refuses_is_said_on_standard_error() {
    let temp = kr_ipc::testing::TempHost::create();
    let line = ["--json", "no-such-command"];
    let control = run(&temp, &line, Stdio::piped(), Stdio::piped());
    assert_eq!(control.status.code(), Some(USAGE_FAILURE));
    assert!(
        text(&control.stdout).contains("\"ok\": false"),
        "the failure is a document on standard output: {}",
        text(&control.stdout)
    );

    let refused = run(&temp, &line, full(), Stdio::piped());
    assert_eq!(
        refused.status.code(),
        Some(USAGE_FAILURE),
        "the command ends with its own failure: {}",
        text(&refused.stderr)
    );
    assert!(
        text(&refused.stderr).contains("standard output"),
        "and says what it could not write: {}",
        text(&refused.stderr)
    );
}

/// A command that fails and cannot write its failure to a full standard error says so on standard
/// output, where it still can, and ends with its own failure.
#[test]
fn a_failure_that_a_full_standard_error_refuses_is_said_on_standard_output() {
    let temp = kr_ipc::testing::TempHost::create();
    let line = ["no-such-command"];
    let control = run(&temp, &line, Stdio::piped(), Stdio::piped());
    assert_eq!(control.status.code(), Some(USAGE_FAILURE));
    assert!(
        !control.stderr.is_empty(),
        "the failure is said on standard error"
    );

    let refused = run(&temp, &line, Stdio::piped(), full());
    assert_eq!(
        refused.status.code(),
        Some(USAGE_FAILURE),
        "the command ends with its own failure: {}",
        text(&refused.stdout)
    );
    assert!(
        text(&refused.stdout).contains("standard error"),
        "and says what it could not write: {}",
        text(&refused.stdout)
    );
}

/// A command whose standard output is a protocol's frames takes no line of text on it, whatever
/// else fails: a bridge handed an opening frame it cannot read answers with a refusal frame and
/// says why on standard error, and with standard error full there is nowhere to say that, so the
/// invoker reads exactly the frame it read with room and the command ends with the status it
/// ended with then.
#[test]
fn a_bridge_whose_standard_error_has_no_room_writes_no_text_among_its_frames() {
    let temp = kr_ipc::testing::TempHost::create();
    let line = ["bridge", "--stdio"];
    // The length of a frame, and four bytes that are not a bridge frame.
    let unreadable = [0_u8, 0, 0, 4, 0xff, 0xff, 0xff, 0xff];
    let control = run_fed(&temp, &line, &unreadable, Stdio::piped());
    assert!(
        !control.stderr.is_empty(),
        "with room, the command says on standard error why it ended"
    );
    assert!(
        matches!(
            frames_of(&control.stdout).as_slice(),
            [BridgeFrame::Refused(_)]
        ),
        "with room, the invoker reads one refusal frame"
    );
    assert_eq!(control.status.code(), Some(REFUSED));

    let refused = run_fed(&temp, &line, &unreadable, full());
    assert!(
        matches!(
            frames_of(&refused.stdout).as_slice(),
            [BridgeFrame::Refused(_)]
        ),
        "with standard error full, the invoker reads the same one frame and no text"
    );
    assert_eq!(
        refused.stdout, control.stdout,
        "and the bytes are the ones it read with room"
    );
    assert_eq!(
        refused.status.code(),
        control.status.code(),
        "and the command ends as it ended with room"
    );
}

/// The same holds for a command line that is a mistake: the tool server and the bridge name the
/// stream they own before the line is read, so a usage failure whose diagnostic standard error
/// refuses leaves the stream with nothing on it, and the status is the usage failure's.
#[test]
fn a_usage_mistake_on_a_protocol_line_writes_no_text_when_standard_error_has_no_room() {
    let temp = kr_ipc::testing::TempHost::create();
    for command in ["bridge", "agent-tools"] {
        let line = [command, "--stdio", "--no-such-option"];
        let control = run_fed(&temp, &line, b"", Stdio::piped());
        assert_eq!(control.status.code(), Some(USAGE_FAILURE), "kr {line:?}");
        assert!(
            !control.stderr.is_empty(),
            "kr {line:?} says on standard error that the line is a mistake"
        );
        assert!(
            control.stdout.is_empty(),
            "kr {line:?} writes nothing on its protocol stream"
        );

        let refused = run_fed(&temp, &line, b"", full());
        assert_eq!(
            refused.status.code(),
            Some(USAGE_FAILURE),
            "kr {line:?} with a full standard error ends with the usage failure"
        );
        assert!(
            refused.stdout.is_empty(),
            "kr {line:?} with a full standard error writes no text on its protocol stream: {}",
            text(&refused.stdout)
        );
    }
}
