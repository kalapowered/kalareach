//! Asking the platform about an enrolled environment, and starting one.
//!
//! Each command here is the one [`crate::bridge::launch`] names, run as an argument vector. The
//! observations are read from what the platform printed; nothing is inferred from an exit status
//! alone, because a runtime that is not installed and a container that is stopped both exit
//! non-zero and mean different things.

use std::process::{Command, Stdio};

use kr_protocol::identity::{EnvironmentAccess, EnvironmentEnrolment, EnvironmentPresence};

use crate::bridge::launch::{self, CONTAINER_RUNTIME, Observation};
use crate::bridge::store::Observer;
use crate::error::{ControllerError, Result};

/// The observer that runs the platform's own commands.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformObserver;

/// Asks the platform whether one destination is running, before there is a record naming it.
///
/// Enrolment needs this: asking a destination which environment it is means running the helper
/// inside it, and running anything inside a stopped distribution starts it. Observing starts
/// nothing, so the question can be put first.
///
/// # Errors
///
/// Returns an invalid-argument failure for an access class that is not a process bridge, and a
/// supervision failure when the platform's own command could not be run.
pub fn destination_state(
    access: EnvironmentAccess,
    target: &str,
    os_user: &str,
    helper_path: &str,
) -> Result<EnvironmentPresence> {
    let enrolment = EnvironmentEnrolment {
        // The identity is what enrolment is about to learn. Nothing below reads it: the platform is
        // asked about the target, which is the name it knows.
        environment_id: kr_protocol::ids::EnvironmentId::new(
            kr_protocol::scalars::Uuid::from_bytes([0; 16]),
        ),
        access,
        label: target.to_owned(),
        target: target.to_owned(),
        os_user: os_user.to_owned(),
        helper_path: helper_path.to_owned(),
        clipboard_destination: kr_protocol::scalars::Nullable::null(),
        approved_at_ms: kr_protocol::scalars::TimestampMs::new(0),
    };
    PlatformObserver.observe(&enrolment)
}

impl Observer for PlatformObserver {
    fn observe(&self, enrolment: &EnvironmentEnrolment) -> Result<EnvironmentPresence> {
        let observation = launch::observe(enrolment)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        match observation {
            Observation::Listings {
                registered,
                running,
            } => {
                let registered = run(&registered.program, &registered.arguments)?;
                let running = run(&running.program, &running.arguments)?;
                Ok(wsl_state(&registered, &running, &enrolment.target))
            }
            Observation::Inspection(command) => {
                let output = run(&command.program, &command.arguments)?;
                Ok(container_state(&output))
            }
        }
    }

    fn start(&self, enrolment: &EnvironmentEnrolment) -> Result<()> {
        let command = launch::start(enrolment)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let output = run(&command.program, &command.arguments)?;
        if output.code == Some(0) {
            return Ok(());
        }
        Err(ControllerError::supervision(format!(
            "{} could not be started: {}",
            enrolment.label,
            output.text.trim()
        )))
    }
}

/// What one platform command produced.
#[derive(Clone, Debug)]
pub struct CommandOutput {
    /// The exit code, where the platform reported one.
    pub code: Option<i32>,
    /// Standard output and standard error together, as text.
    pub text: String,
}

/// Decodes process output bytes, reading UTF-16LE (with or without a byte order mark) and UTF-8.
///
/// `wsl.exe` writes UTF-16LE with no byte order mark when its output is not a console. What tells
/// that from UTF-8 is where the zero bytes are: a UTF-16LE text of any script has its line endings'
/// zero bytes in the odd places, and a text that is UTF-8 has none. The first two letters are not
/// asked to be Latin, because a distribution is named by the person who made it.
#[must_use]
pub fn decode_output(bytes: &[u8]) -> String {
    // The zero bytes at every second place, counting from `first`.
    let zeros_from = |first: usize| {
        bytes
            .iter()
            .skip(first)
            .step_by(2)
            .filter(|byte| **byte == 0)
            .count()
    };
    let bom = bytes.starts_with(&[0xff, 0xfe]);
    if bom || zeros_from(1) > zeros_from(0) {
        let wide = if bom { &bytes[2..] } else { bytes };
        let u16s: Vec<u16> = wide
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        return char::decode_utf16(u16s)
            .map(|result| result.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect();
    }
    String::from_utf8_lossy(bytes).into_owned()
}

/// How long a platform command is given before this host gives up on it.
///
/// These run while the enrolment record is locked, so a command that never returns would hold a
/// listing as well as the refresh that started it. Starting a distribution is the slowest of them
/// and takes seconds, not minutes.
pub const PLATFORM_LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

/// The most output one platform command's answer may take up, in bytes.
///
/// These answers are listings of a few lines. A launcher that keeps printing has nothing this host
/// can use, and reading it to its end would let it fill this process's memory well inside the time
/// limit.
const PLATFORM_OUTPUT_LIMIT: usize = 1024 * 1024;

/// Reads one pipe on a thread of its own, handing over at most the answer's limit.
///
/// The pieces cross a channel rather than being returned from the thread, because the caller has a
/// deadline and this thread may not: a descendant that inherited the pipe holds it open after the
/// child has gone, and a read to the end of it would never return. The caller drops the receiving
/// end when it has waited long enough, and the next hand-over ends the thread.
///
/// What crosses the channel is bounded here rather than where it is collected, because a child
/// that keeps printing would otherwise fill this process's memory for as long as the deadline
/// lasts. Past the limit the pipe is still read and what it carries is dropped, so this host never
/// blocks the child it is ending.
fn read_in_the_background<R: std::io::Read + Send + 'static>(
    stream: Option<R>,
) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let Some(mut stream) = stream else { return };
        let mut buffer = [0_u8; 8192];
        let mut handed_over = 0_usize;
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => return,
                Ok(read) => {
                    if handed_over < PLATFORM_OUTPUT_LIMIT {
                        let keeping = read.min(PLATFORM_OUTPUT_LIMIT - handed_over);
                        if sender.send(buffer[..keeping].to_vec()).is_err() {
                            return;
                        }
                        handed_over += keeping;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
    });
    receiver
}

/// Collects what one reader hands over, until the pipe ends or the deadline passes.
fn collect_until(
    pieces: &std::sync::mpsc::Receiver<Vec<u8>>,
    deadline: std::time::Instant,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    while bytes.len() < PLATFORM_OUTPUT_LIMIT {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match pieces.recv_timeout(remaining) {
            Ok(piece) => bytes.extend_from_slice(&piece),
            // The pipe ended, or the deadline did. Either way this is the whole answer.
            Err(_) => break,
        }
    }
    bytes.truncate(PLATFORM_OUTPUT_LIMIT);
    bytes
}

/// How long ending a child is given here before the waiting is handed to a thread of its own.
const KILL_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Ends a child this call started and collects it without waiting on it here.
///
/// A caller of this module holds the enrolment record while it runs, so nothing it does may wait
/// without a bound. Ending a process is ordinarily immediate, and a system that refuses the
/// killing, or a child that takes its time going, is given the grace above and then left to a
/// thread that holds nothing.
fn end_and_reap(mut child: std::process::Child) -> bool {
    let _ = child.kill();
    let grace = std::time::Instant::now() + KILL_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            // Either the child has not gone yet or this host cannot tell. Both are the same
            // decision here: the waiting is somebody else's, and this caller says only what it
            // knows, which is that the ending was not seen.
            Ok(None) | Err(_) => {
                if std::time::Instant::now() >= grace {
                    std::thread::spawn(move || {
                        let _ = child.wait();
                    });
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }
}

/// How one run of a platform command came to an end.
enum Ending {
    /// The child exited on its own, with this status.
    Exited(std::process::ExitStatus),
    /// The deadline passed while it was still running.
    Deadline,
    /// This host could not tell whether it was still running.
    Unknown(String),
}

/// Runs one argument vector, ending it when it outlasts `limit`.
///
/// The child and the reading are both bounded by one deadline. The output is read on threads of its
/// own, because a child that fills a pipe while nobody reads it would wait for a reader that is
/// itself waiting for the child; and what those threads have read is collected through a channel
/// rather than by joining them, because a descendant that inherited the pipe keeps it open after
/// the child has gone, whether the child exited or was ended. What arrived by the deadline is the
/// answer, and a thread still waiting on a pipe nobody closed ends with that pipe.
fn run_bounded(
    program: &str,
    arguments: &[String],
    limit: std::time::Duration,
) -> Result<std::process::Output> {
    let deadline = std::time::Instant::now() + limit;
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            ControllerError::supervision(format!("{program} could not be run: {error}"))
        })?;
    let reading_out = read_in_the_background(child.stdout.take());
    let reading_err = read_in_the_background(child.stderr.take());

    let ending = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ending::Exited(status),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    break Ending::Deadline;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            // A child whose state cannot be read is still a child this call started, so it is
            // ended and collected like one rather than left behind with the failure.
            Err(error) => break Ending::Unknown(error.to_string()),
        }
    };
    // Only the child this call started, and by the handle it holds. Ending it says whether the
    // ending was seen, because a report of it has to say what happened rather than what was asked
    // for.
    let ended = match &ending {
        Ending::Exited(_) => true,
        _ => end_and_reap(child),
    };
    let stdout = collect_until(&reading_out, deadline);
    let stderr = collect_until(&reading_err, deadline);
    match ending {
        Ending::Exited(status) => Ok(std::process::Output {
            status,
            stdout,
            stderr,
        }),
        Ending::Deadline => Err(ControllerError::supervision(format!(
            "{program} said nothing for {} seconds and {}",
            limit.as_secs(),
            if ended {
                "was ended"
            } else {
                "could not be ended"
            }
        ))),
        Ending::Unknown(error) => Err(ControllerError::supervision(format!(
            "{program} could not be waited for: {error}"
        ))),
    }
}

/// Runs one argument vector and collects what it printed.
///
/// # Errors
///
/// Returns a resource failure when the program is not installed or could not be run. A program
/// that runs and exits non-zero is not a failure here: its output is what says what it found.
pub fn run(program: &str, arguments: &[String]) -> Result<CommandOutput> {
    let output = run_bounded(program, arguments, PLATFORM_LIMIT)?;
    let mut text = decode_output(&output.stdout);
    let stderr = decode_output(&output.stderr);
    if !stderr.is_empty() {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&stderr);
    }
    // Retain any remaining non-null characters to guard against stray nulls.
    text.retain(|character| character != '\0');
    Ok(CommandOutput {
        code: output.status.code(),
        text,
    })
}

/// Returns whether this host has the container runtime an enrolled container needs.
///
/// A host without it can still list and forget its enrolled containers: what it cannot do is
/// observe or start one, and the answer says so by name rather than reporting the container
/// stopped.
#[must_use]
pub fn container_runtime_present() -> bool {
    Command::new(CONTAINER_RUNTIME)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Reads one distribution's state out of the two listings of names `wsl.exe` prints.
///
/// Each listing is one name to a line and nothing else, so the answer does not depend on the
/// language the host's Windows prints in, which `wsl.exe --list --verbose` does: its state is a
/// word of that language. A name that is not in the registered listing is not registered, which is
/// reported as stale rather than as stopped: this host has not observed it at all. A listing that
/// failed has observed nothing either, whatever text it printed.
fn wsl_state(
    registered: &CommandOutput,
    running: &CommandOutput,
    target: &str,
) -> EnvironmentPresence {
    if !lists(registered, target) || running.code != Some(0) {
        return EnvironmentPresence::Stale;
    }
    if lists(running, target) {
        EnvironmentPresence::Running
    } else {
        EnvironmentPresence::EnvironmentStopped
    }
}

/// Returns whether a listing of names, which exited cleanly, names `target` on a line of its own.
///
/// The whole line is the name, so a name that is the start of another is not matched and a name
/// with spaces in it is read as it is written. The platform compares names without regard to
/// ASCII case, and so does this.
fn lists(listing: &CommandOutput, target: &str) -> bool {
    listing.code == Some(0)
        && listing
            .text
            .lines()
            .map(str::trim)
            .any(|name| !name.is_empty() && (name == target || name.eq_ignore_ascii_case(target)))
}

/// Reads a container's state out of `podman container inspect --format {{.State.Running}}`.
///
/// A container that exists answers `true` or `false`. A container that does not exist makes the
/// runtime exit non-zero, and this host has then observed nothing about the identity it enrolled,
/// which is stale rather than stopped.
fn container_state(output: &CommandOutput) -> EnvironmentPresence {
    if output.code != Some(0) {
        return EnvironmentPresence::Stale;
    }
    match output.text.trim() {
        "true" => EnvironmentPresence::Running,
        "false" => EnvironmentPresence::EnvironmentStopped,
        _ => EnvironmentPresence::Stale,
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn a_platform_command_that_never_returns_is_ended_rather_than_waited_for() {
        // `sleep` stands in for a launcher that has stopped answering. The record lock is held
        // while these run, so a wait with no end would hold a listing as well.
        let started = std::time::Instant::now();
        let error = super::run_bounded(
            "/bin/sleep",
            &["600".to_owned()],
            std::time::Duration::from_millis(200),
        )
        .expect_err("the command is ended");
        assert!(error.to_string().contains("was ended"), "{error}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "it returned after {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_descendant_that_holds_a_pipe_does_not_hold_the_answer() {
        // The command exits at once and leaves a descendant holding its standard output. Reading
        // that pipe to its end would never return, so the bound covers the reading too, and what
        // the command printed before the deadline is still the answer.
        let started = std::time::Instant::now();
        let output = super::run_bounded(
            "/bin/sh",
            &[
                "-c".to_owned(),
                "sleep 600 & echo answered; exit 0".to_owned(),
            ],
            std::time::Duration::from_millis(300),
        )
        .expect("the command exited, so it has an answer");
        assert_eq!(output.status.code(), Some(0));
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("answered"),
            "{:?}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "it returned after {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_command_that_keeps_printing_is_held_to_the_answer_limit() {
        // A launcher that prints without stopping has nothing this host can use. What it prints is
        // kept only to the limit, and the rest is read and dropped rather than collected, so the
        // memory one of these costs never depends on how long the deadline is.
        let output = super::run_bounded(
            "/bin/sh",
            &[
                "-c".to_owned(),
                "while :; do printf 'noise noise noise noise noise noise noise noise'; done"
                    .to_owned(),
            ],
            std::time::Duration::from_millis(500),
        )
        .expect_err("the command never ends, so it is ended");
        assert!(output.to_string().contains("was ended"), "{output}");
    }

    #[cfg(unix)]
    #[test]
    fn output_past_the_limit_is_not_kept() {
        // The same bound seen through an answer: a command that prints more than the limit and
        // then exits is answered with exactly the limit.
        let output = super::run_bounded(
            "/bin/sh",
            &[
                "-c".to_owned(),
                format!(
                    "head -c {} /dev/zero | tr '\\0' 'x'",
                    super::PLATFORM_OUTPUT_LIMIT + 4096
                ),
            ],
            std::time::Duration::from_secs(10),
        )
        .expect("the command exits");
        assert_eq!(output.stdout.len(), super::PLATFORM_OUTPUT_LIMIT);
    }

    #[cfg(unix)]
    #[test]
    fn a_command_that_is_ended_does_not_wait_on_a_descendant_that_holds_its_pipe() {
        // The same pipe, held across a kill rather than across an exit. The record lock is held
        // for the length of this call either way.
        let started = std::time::Instant::now();
        let error = super::run_bounded(
            "/bin/sh",
            &["-c".to_owned(), "sleep 600 & sleep 600".to_owned()],
            std::time::Duration::from_millis(300),
        )
        .expect_err("the command is ended");
        assert!(error.to_string().contains("was ended"), "{error}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "it returned after {:?}",
            started.elapsed()
        );
    }

    use super::*;

    /// A listing `wsl.exe` printed and exited cleanly after.
    fn printed(text: &str) -> CommandOutput {
        CommandOutput {
            code: Some(0),
            text: text.to_owned(),
        }
    }

    /// What `wsl.exe --list --quiet` prints on a host with three distributions, and what
    /// `--list --running --quiet` prints when the first of them is the only one running.
    fn the_host() -> (CommandOutput, CommandOutput) {
        (
            printed("Ubuntu-24.04\r\nDebian\r\nMy Distro\r\n"),
            printed("Ubuntu-24.04\r\n"),
        )
    }

    #[test]
    fn a_running_distribution_is_read_from_the_listings() {
        let (registered, running) = the_host();
        assert_eq!(
            wsl_state(&registered, &running, "Ubuntu-24.04"),
            EnvironmentPresence::Running
        );
    }

    #[test]
    fn a_stopped_distribution_is_reported_as_stopped_rather_than_absent() {
        let (registered, running) = the_host();
        assert_eq!(
            wsl_state(&registered, &running, "Debian"),
            EnvironmentPresence::EnvironmentStopped
        );
        // Nothing running prints nothing at all, and exits cleanly.
        assert_eq!(
            wsl_state(&registered, &printed(""), "Ubuntu-24.04"),
            EnvironmentPresence::EnvironmentStopped
        );
    }

    #[test]
    fn a_distribution_that_is_not_registered_is_stale_rather_than_stopped() {
        // This host has observed nothing about it. Reporting it stopped would claim an
        // observation that was never made.
        let (registered, running) = the_host();
        assert_eq!(
            wsl_state(&registered, &running, "Fedora"),
            EnvironmentPresence::Stale
        );
    }

    #[test]
    fn a_name_that_is_a_prefix_of_another_is_not_matched() {
        let (registered, running) = the_host();
        assert_eq!(
            wsl_state(&registered, &running, "Ubuntu"),
            EnvironmentPresence::Stale
        );
    }

    #[test]
    fn a_distribution_with_spaces_in_its_name_is_read_as_it_is_written() {
        let registered = printed("Ubuntu-24.04\r\nMy  Distro\r\nDebian Work\r\n");
        let running = printed("My  Distro\r\n");
        assert_eq!(
            wsl_state(&registered, &running, "My  Distro"),
            EnvironmentPresence::Running
        );
        assert_eq!(
            wsl_state(&registered, &running, "My Distro"),
            EnvironmentPresence::Stale,
            "one space is not two"
        );
        assert_eq!(
            wsl_state(&registered, &running, "Debian Work"),
            EnvironmentPresence::EnvironmentStopped
        );
    }

    #[test]
    fn the_platform_compares_names_without_regard_to_case_and_so_does_this() {
        let (registered, running) = the_host();
        assert_eq!(
            wsl_state(&registered, &running, "ubuntu-24.04"),
            EnvironmentPresence::Running
        );
    }

    #[test]
    fn a_listing_that_failed_has_observed_nothing_whatever_it_printed() {
        let (registered, running) = the_host();
        let failed = |text: &str| CommandOutput {
            code: Some(1),
            text: text.to_owned(),
        };
        // The text of a failure is in the host's language and may be anything, including a name.
        assert_eq!(
            wsl_state(&failed("Ubuntu-24.04\r\n"), &running, "Ubuntu-24.04"),
            EnvironmentPresence::Stale
        );
        assert_eq!(
            wsl_state(&registered, &failed("Ubuntu-24.04\r\n"), "Ubuntu-24.04"),
            EnvironmentPresence::Stale
        );
        // A host with no distribution says so in its own words and exits with a failure.
        assert_eq!(
            wsl_state(
                &failed(
                    "Das Windows-Subsystem f\u{fc}r Linux hat keine installierten Distributionen."
                ),
                &failed(""),
                "Ubuntu-24.04"
            ),
            EnvironmentPresence::Stale
        );
    }

    #[test]
    fn what_wsl_writes_is_read_whatever_script_the_name_is_in() {
        // The encoding `wsl.exe` uses when it is not writing to a console: UTF-16LE, with no byte
        // order mark. The first letters are not Latin in the second and third names.
        let wide =
            |text: &str| -> Vec<u8> { text.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        for names in [
            "Ubuntu-24.04\r\nDebian\r\n",
            "\u{420}\u{430}\u{431}\u{43e}\u{447}\u{430}\u{44f}\r\nDebian\r\n",
            "\u{6d4b}\u{8bd5}\r\nDebian\r\n",
            "\u{6d4b}\u{8bd5}\r\n",
        ] {
            assert_eq!(decode_output(&wide(names)), names, "{names:?}");
            let mut with_mark = vec![0xff, 0xfe];
            with_mark.extend(wide(names));
            assert_eq!(
                decode_output(&with_mark),
                names,
                "{names:?} with a byte order mark"
            );
        }
        // Text that is UTF-8 stays UTF-8, accents and all.
        assert_eq!(
            decode_output("Ubuntu-24.04 \u{e9}\u{e8}\r\n".as_bytes()),
            "Ubuntu-24.04 \u{e9}\u{e8}\r\n"
        );
        assert_eq!(decode_output(b""), "");
    }

    #[test]
    fn a_distribution_named_in_another_script_is_read_from_what_wsl_wrote() {
        let wide =
            |text: &str| -> Vec<u8> { text.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let name = "\u{420}\u{430}\u{431}\u{43e}\u{447}\u{430}\u{44f}";
        let registered = printed(&decode_output(&wide(&format!(
            "Ubuntu-24.04\r\n{name}\r\n"
        ))));
        let running = printed(&decode_output(&wide(&format!("{name}\r\n"))));
        assert_eq!(
            wsl_state(&registered, &running, name),
            EnvironmentPresence::Running
        );
        assert_eq!(
            wsl_state(&registered, &running, "Ubuntu-24.04"),
            EnvironmentPresence::EnvironmentStopped
        );
    }

    #[test]
    fn a_container_answers_running_stopped_or_nothing_at_all() {
        let running = CommandOutput {
            code: Some(0),
            text: "true\n".to_owned(),
        };
        let stopped = CommandOutput {
            code: Some(0),
            text: "false\n".to_owned(),
        };
        let absent = CommandOutput {
            code: Some(125),
            text: "no such container\n".to_owned(),
        };
        assert_eq!(container_state(&running), EnvironmentPresence::Running);
        assert_eq!(
            container_state(&stopped),
            EnvironmentPresence::EnvironmentStopped
        );
        assert_eq!(container_state(&absent), EnvironmentPresence::Stale);
    }
}
