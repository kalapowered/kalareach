//! Asking the platform about an enrolled environment, and starting one.
//!
//! Each command here is the one [`crate::bridge::launch`] names, run as an argument vector. The
//! observations are read from what the platform printed; nothing is inferred from an exit status
//! alone, because a runtime that is not installed and a container that is stopped both exit
//! non-zero and mean different things.

use std::process::{Command, Stdio};

use kr_protocol::identity::{EnvironmentAccess, EnvironmentEnrolment, EnvironmentPresence};

use crate::bridge::launch::{self, Observation};
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
/// supervision failure, naming the call, when the platform's own command could not be run, did not
/// end in its time, ended without saying that it knows no such container, or answered a question
/// about a container with something other than `true` or `false`.
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
    observe_enrolment(&enrolment, true)
}

impl Observer for PlatformObserver {
    fn observe(&self, enrolment: &EnvironmentEnrolment) -> Result<EnvironmentPresence> {
        observe_enrolment(enrolment, false)
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

/// Observes one enrolment. A container whose inspection ended non-zero is observed as stale, which
/// is what a daemon records of an identity it could observe nothing about; a caller that is about
/// to act on the answer (`strict`) is told instead when the runtime failed for any reason but not
/// knowing the container, since a runtime that is failing has shown nothing of the container.
fn observe_enrolment(
    enrolment: &EnvironmentEnrolment,
    strict: bool,
) -> Result<EnvironmentPresence> {
    let observation = launch::observe(enrolment)
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
    match observation {
        Observation::Listings {
            registered,
            running,
        } => {
            let registered = run_within(&registered.program, &registered.arguments, LISTING_LIMIT)?;
            let running = run_within(&running.program, &running.arguments, LISTING_LIMIT)?;
            Ok(wsl_state(&registered, &running, &enrolment.target))
        }
        Observation::Inspection(command) => {
            let output = run(&command.program, &command.arguments)?;
            if strict {
                presence_after_inspection(&named(&command.program, &command.arguments), &output)
            } else {
                Ok(container_state(&output))
            }
        }
    }
}

/// What an inspection that is acted on shows: a container the runtime says it does not know is
/// stale, and an inspection that ended non-zero in any other way, or that ended well with an answer
/// that is neither `true` nor `false`, is the failure of the call, which is named and not read as a
/// container that is not running.
fn presence_after_inspection(call: &str, output: &CommandOutput) -> Result<EnvironmentPresence> {
    if output.code != Some(0) && !says_there_is_no_such_container(&output.text) {
        let ended = output.code.map_or_else(
            || "without an exit status".to_owned(),
            |code| format!("with exit status {code}"),
        );
        return Err(ControllerError::supervision(format!(
            "{call} ended {ended}"
        )));
    }
    if output.code == Some(0) && !matches!(output.stdout.trim(), "true" | "false") {
        return Err(ControllerError::supervision(format!(
            "{call} ended well and answered neither true nor false"
        )));
    }
    Ok(container_state(output))
}

/// What one platform command produced.
#[derive(Clone, Debug)]
pub struct CommandOutput {
    /// The exit code, where the platform reported one.
    pub code: Option<i32>,
    /// Standard output and standard error together, as text.
    pub text: String,
    /// Standard output alone, as text: what a command answers, apart from what it says of itself
    /// (a runtime's warnings are on standard error).
    pub stdout: String,
}

/// Decodes process output bytes, reading UTF-16LE (with or without a byte order mark) and UTF-8.
///
/// `wsl.exe` writes UTF-16LE with no byte order mark when its output is not a console, and
/// everything else this host runs writes UTF-8. Text in UTF-8 has no zero byte in it, and text in
/// UTF-16LE has one wherever a character below U+0100 stands, which every line ending is. So a byte
/// order mark, or a zero byte anywhere, is what makes the answer UTF-16LE. What a name begins with
/// is not asked, because a name is given by the person who made it.
#[must_use]
pub fn decode_output(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.contains(&0) {
        let wide = bytes.strip_prefix(&[0xff, 0xfe]).unwrap_or(bytes);
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

/// How long each of the two listings that make one observation of a distribution is given, which
/// is half of [`PLATFORM_LIMIT`]: the observation as a whole is held to that bound, and each
/// listing has the time the bound allows it whatever the other took.
const LISTING_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

/// The most output one platform command's answer may take up, in bytes.
///
/// These answers are listings of a few lines. A launcher that keeps printing has nothing this host
/// can use, and reading it to its end would let it fill this process's memory well inside the time
/// limit.
const PLATFORM_OUTPUT_LIMIT: usize = 1024 * 1024;

/// Starts a thread that runs `body`, or says why it could not be started. A caller of this module
/// may be a destructor (a harness removing what its test made), and a thread that cannot be made
/// must not panic there: the failure is the call's, and is told as one.
fn spawn_thread(body: impl FnOnce() + Send + 'static) -> std::io::Result<()> {
    #[cfg(test)]
    if tests::threads_are_refused() {
        return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
    }
    std::thread::Builder::new().spawn(body).map(drop)
}

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
///
/// # Errors
///
/// Returns why the thread could not be started.
fn read_in_the_background<R: std::io::Read + Send + 'static>(
    stream: Option<R>,
) -> std::io::Result<std::sync::mpsc::Receiver<Vec<u8>>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    spawn_thread(move || {
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
    })?;
    Ok(receiver)
}

/// Collects what one reader hands over, until the pipe ends or the deadline passes.
fn collect_until(
    pieces: &std::sync::mpsc::Receiver<Vec<u8>>,
    deadline: std::time::Instant,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    while bytes.len() < PLATFORM_OUTPUT_LIMIT {
        // What has already arrived is taken whatever the clock says: a stream read after the
        // deadline has passed, because the other one held the time, is not an empty one.
        if let Ok(piece) = pieces.try_recv() {
            bytes.extend_from_slice(&piece);
            continue;
        }
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
                    // Where no thread can be made nobody waits, and the child is collected when
                    // this process ends: the caller is told all the same that it was not seen.
                    let _ = spawn_thread(move || {
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
    Unknown(std::io::Error),
}

/// Why a call run within a limit gave no answer. Each names the call by its program and verbs, as
/// [`named`] says, and none repeats a value after them.
#[derive(Debug)]
pub enum CallFailure {
    /// The program could not be started, or could not be given a thread to read what it prints,
    /// in which case it was ended.
    NotRun {
        /// The call.
        call: String,
        /// What the operating system said.
        error: std::io::Error,
    },
    /// The limit passed while the call was still running, and it was ended.
    Deadline {
        /// The call.
        call: String,
        /// The limit it was given.
        limit: std::time::Duration,
        /// Whether the ending was seen.
        ended: bool,
    },
    /// This host could not tell whether the call was still running.
    Unknown {
        /// The call.
        call: String,
        /// What the operating system said.
        error: std::io::Error,
    },
}

impl std::fmt::Display for CallFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRun { call, error } => write!(formatter, "{call} could not be run: {error}"),
            Self::Deadline { call, limit, ended } => write!(
                formatter,
                "{call} said nothing for {} seconds and {}",
                limit.as_secs(),
                if *ended {
                    "was ended"
                } else {
                    "could not be ended"
                }
            ),
            Self::Unknown { call, error } => {
                write!(formatter, "{call} could not be waited for: {error}")
            }
        }
    }
}

impl std::error::Error for CallFailure {}

impl From<CallFailure> for ControllerError {
    fn from(failure: CallFailure) -> Self {
        Self::supervision(failure.to_string())
    }
}

/// What a refusal names a call by: the program and the words after it up to the first option,
/// which say what it was asked to do (`podman container inspect`), and none of the values after
/// that (a name, a user, a path). A call made of options only is named by its first.
fn named(program: &str, arguments: &[String]) -> String {
    let mut words: Vec<&str> = arguments
        .iter()
        .map(String::as_str)
        .take_while(|argument| !argument.starts_with('-'))
        .collect();
    if words.is_empty() {
        words.extend(arguments.first().map(String::as_str));
    }
    std::iter::once(program)
        .chain(words)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Runs one argument vector, ending it when it outlasts `limit`, and returns what it printed on
/// each stream. A refusal names the call.
///
/// The child and the reading are both bounded by one deadline. The output is read on threads of its
/// own, because a child that fills a pipe while nobody reads it would wait for a reader that is
/// itself waiting for the child; and what those threads have read is collected through a channel
/// rather than by joining them, because a descendant that inherited the pipe keeps it open after
/// the child has gone, whether the child exited or was ended. What arrived by the deadline is the
/// answer, and a thread still waiting on a pipe nobody closed ends with that pipe.
///
/// # Errors
///
/// Returns the failure, naming the call, when the program could not be run, could not be waited
/// for, or did not end within `limit` and was ended.
pub fn run_bounded(
    program: &str,
    arguments: &[String],
    limit: std::time::Duration,
) -> std::result::Result<std::process::Output, CallFailure> {
    let deadline = std::time::Instant::now() + limit;
    let call = named(program, arguments);
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| CallFailure::NotRun {
            call: call.clone(),
            error,
        })?;
    let reading_out = read_in_the_background(child.stdout.take());
    let reading_err = read_in_the_background(child.stderr.take());
    let (reading_out, reading_err) = match (reading_out, reading_err) {
        (Ok(out), Ok(err)) => (out, err),
        // The program is running, and nothing can read what it prints: it is ended, and the call
        // is told as one that could not be run.
        (Err(error), _) | (_, Err(error)) => {
            end_and_reap(child);
            return Err(CallFailure::NotRun { call, error });
        }
    };

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
            Err(error) => break Ending::Unknown(error),
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
        Ending::Deadline => Err(CallFailure::Deadline { call, limit, ended }),
        Ending::Unknown(error) => Err(CallFailure::Unknown { call, error }),
    }
}

/// Runs one argument vector and collects what it printed.
///
/// # Errors
///
/// Returns a resource failure when the program is not installed or could not be run. A program
/// that runs and exits non-zero is not a failure here: its output is what says what it found.
pub fn run(program: &str, arguments: &[String]) -> Result<CommandOutput> {
    run_within(program, arguments, platform_limit())
}

/// The time a platform command is given: [`PLATFORM_LIMIT`], or what a suite gave its daemon in its
/// place, for a suite whose subject is not that bound and whose runtime is slower than the bound
/// allows.
fn platform_limit() -> std::time::Duration {
    #[cfg(any(test, feature = "testing"))]
    if let Some(limit) = crate::testing::platform_commands_limit() {
        return limit;
    }
    PLATFORM_LIMIT
}

/// [`run`], with the time it is given named.
fn run_within(
    program: &str,
    arguments: &[String],
    limit: std::time::Duration,
) -> Result<CommandOutput> {
    let output = run_bounded(program, arguments, limit)?;
    let mut stdout = decode_output(&output.stdout);
    let stderr = decode_output(&output.stderr);
    // Retain any remaining non-null characters to guard against stray nulls.
    stdout.retain(|character| character != '\0');
    let mut text = stdout.clone();
    if !stderr.is_empty() {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&stderr);
    }
    text.retain(|character| character != '\0');
    Ok(CommandOutput {
        code: output.status.code(),
        text,
        stdout,
    })
}

/// Whether what a container runtime printed says that it knows no such container, in the form the
/// runtimes say it: a diagnostic one of whose parts, set off by a colon, begins with the words and
/// ends there or goes on with a word of its own (`podman`: `Error: no such container "x"`;
/// `docker`: `Error response from daemon: No such container: x`). The words anywhere else, or as
/// the start of a name, as in the path of a file that could not be read (`reading config: no such
/// container/storage.conf: permission denied`), are another failure that names a path. The text is
/// read and not repeated.
#[must_use]
pub fn says_there_is_no_such_container(printed: &str) -> bool {
    printed.lines().any(|line| {
        line.to_lowercase().split(": ").any(|part| {
            let part = part.trim_start();
            ["no such container", "no such object"]
                .into_iter()
                .filter_map(|words| part.strip_prefix(words))
                .any(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
        })
    })
}

/// Reads one distribution's state out of the two listings of names `wsl.exe` prints.
///
/// Each listing is one name to a line and nothing else, so the answer does not depend on the
/// column layout or the words of `wsl.exe --list --verbose`, which prints each state as a word
/// that a host may print in its own language. A name that is not in the registered listing is not
/// registered, which is reported as stale rather than as stopped: this host has not observed it at
/// all. A listing that failed has observed nothing either, whatever text it printed. The listings
/// are asked with `--quiet`, which makes a host with nothing running answer with no text and a
/// success, where without it the answer is a message in the host's language and a failure.
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
/// A container that exists answers `true` or `false` on standard output, whatever the runtime also
/// says of itself on standard error. A container that does not exist makes the runtime exit
/// non-zero, and this host has then observed nothing about the identity it enrolled, which is
/// stale rather than stopped.
fn container_state(output: &CommandOutput) -> EnvironmentPresence {
    if output.code != Some(0) {
        return EnvironmentPresence::Stale;
    }
    match output.stdout.trim() {
        "true" => EnvironmentPresence::Running,
        "false" => EnvironmentPresence::EnvironmentStopped,
        _ => EnvironmentPresence::Stale,
    }
}

#[cfg(test)]
mod tests {
    thread_local! {
        /// Whether the thread that asks refuses to start the threads this module makes.
        static THREADS_REFUSED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Whether this test thread has the threads of the module under test refused.
    pub(super) fn threads_are_refused() -> bool {
        THREADS_REFUSED.with(std::cell::Cell::get)
    }

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
            error.to_string().contains("/bin/sleep 600 said nothing"),
            "the refusal names the call: {error}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "it returned after {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_refusal_names_the_call_by_what_it_asked_and_repeats_no_value() {
        // The words after the first option are what the call was given to work on: a name, a user,
        // a path. They are the person's, and a refusal is shown and logged.
        let error = super::run_bounded(
            "/bin/sh",
            &[
                "-c".to_owned(),
                "exec sleep 600".to_owned(),
                "a-value-the-person-typed".to_owned(),
            ],
            std::time::Duration::from_millis(200),
        )
        .expect_err("the command is ended");
        assert!(
            matches!(error, super::CallFailure::Deadline { ended: true, .. }),
            "{error}"
        );
        assert!(
            error.to_string().contains("/bin/sh -c said nothing"),
            "{error}"
        );
        assert!(
            !error.to_string().contains("a-value-the-person-typed"),
            "{error}"
        );
        assert!(!error.to_string().contains("exec sleep"), "{error}");
    }

    /// An inspection that is acted on is read as a container that is not there only when the
    /// runtime says so; any other non-zero ending is the call's failure, named, with no value.
    #[test]
    fn an_inspection_that_failed_for_another_reason_is_the_calls_failure() {
        let ended = |code: Option<i32>, said: &str| super::CommandOutput {
            code,
            text: said.to_owned(),
            stdout: String::new(),
        };
        let answered = |stdout: &str| super::CommandOutput {
            code: Some(0),
            text: stdout.to_owned(),
            stdout: stdout.to_owned(),
        };
        let call = "podman container inspect";
        assert_eq!(
            super::presence_after_inspection(call, &answered("true\n")).expect("answered"),
            super::EnvironmentPresence::Running
        );
        assert_eq!(
            super::presence_after_inspection(call, &answered("false\n")).expect("answered"),
            super::EnvironmentPresence::EnvironmentStopped
        );
        assert_eq!(
            super::presence_after_inspection(call, &ended(Some(125), "Error: no such container x"))
                .expect("a container the runtime does not know"),
            super::EnvironmentPresence::Stale
        );
        for failed in [
            ended(Some(125), "Error: cannot connect to the store of a-value"),
            ended(Some(1), ""),
            ended(None, ""),
            // Well ended, and the answer is neither of the two a container gives.
            answered(""),
            answered("a-value\n"),
        ] {
            let error = super::presence_after_inspection(call, &failed)
                .expect_err("a failing runtime has shown nothing of the container");
            let said = error.to_string();
            assert!(said.contains(call) && said.contains("ended"), "{said}");
            assert!(!said.contains("a-value"), "{said}");
        }
    }

    /// The runtimes' own form of the diagnostic is the one read; the words in a path are not.
    #[test]
    fn a_runtime_that_knows_no_such_container_is_read_by_its_own_form_of_saying_so() {
        for said in [
            "Error: no such container \"abc\"",
            "Error: error inspecting object: no such object: \"abc\"",
            "Error response from daemon: No such container: abc",
            "Error: No such object: abc",
            "Warning: something\nError: no such container abc\n",
            // A diagnostic on a line of its own, and one set off by more than one space.
            "Warning: something\nno such container abc",
            "Error:  no such container abc",
        ] {
            assert!(super::says_there_is_no_such_container(said), "{said}");
        }
        for said in [
            "Error: reading /tmp/no such container/storage.conf: permission denied",
            "Error: cannot connect to the store",
            "Error: open /var/lib/no such object: permission denied",
            // A name that begins with the words, after a colon, is a name and not a diagnostic.
            "Error: reading config: no such container/storage.conf: permission denied",
            "Error: open /tmp/cache: no such container/storage.conf: permission denied",
            "Error: no such objects directory: permission denied",
            "",
        ] {
            assert!(!super::says_there_is_no_such_container(said), "{said}");
        }
    }

    /// What a stream has already delivered is the answer whatever the clock says: a stream read
    /// after the deadline, because the other one held the time, is not an empty one. The channel
    /// is filled and its sender kept, as the pipe of a command whose descendant still holds it is,
    /// and the deadline is the moment it is asked, so nothing here waits for anything or depends
    /// on how soon a process runs.
    #[test]
    fn what_a_stream_has_delivered_is_kept_when_the_deadline_has_passed() {
        let (sender, pieces) = std::sync::mpsc::channel();
        sender.send(b"said ".to_vec()).expect("the first piece");
        sender
            .send(b"on standard error".to_vec())
            .expect("the second piece");
        let kept = super::collect_until(&pieces, std::time::Instant::now());
        assert_eq!(String::from_utf8_lossy(&kept), "said on standard error");
        // The sender is still there: the pipe was never closed.
        drop(sender);
    }

    #[cfg(unix)]
    #[test]
    fn a_program_that_is_not_there_is_not_run_and_the_failure_says_so() {
        let error = super::run_bounded(
            "/nonexistent-runtime/podman",
            &["--version".to_owned()],
            std::time::Duration::from_secs(5),
        )
        .expect_err("there is nothing to run");
        let super::CallFailure::NotRun { error: why, .. } = &error else {
            panic!("the program was not run: {error}");
        };
        assert_eq!(why.kind(), std::io::ErrorKind::NotFound, "{error}");
    }

    /// A program that cannot be given a thread to read what it prints is ended, and the call is
    /// refused as one that could not be run. Where this panicked instead, a destructor that made a
    /// call on a machine out of threads ended the whole test binary.
    #[cfg(unix)]
    #[test]
    fn a_call_whose_output_cannot_be_read_for_want_of_a_thread_is_ended_and_refused() {
        // A program of no other test and no other run: nothing else has this in its arguments.
        let marker = format!("sleep 120.{}", std::process::id());
        THREADS_REFUSED.with(|refused| refused.set(true));
        let result = super::run_bounded(
            "/bin/sh",
            &["-c".to_owned(), format!("exec {marker}")],
            std::time::Duration::from_secs(60),
        );
        THREADS_REFUSED.with(|refused| refused.set(false));
        let error = result.expect_err("nothing can read what the program prints");
        assert!(
            matches!(error, super::CallFailure::NotRun { .. }),
            "{error}"
        );
        assert!(
            error.to_string().contains("/bin/sh -c could not be run"),
            "{error}"
        );
        let listing = std::process::Command::new("ps")
            .args(["-A", "-o", "command="])
            .output()
            .expect("lists the processes");
        assert!(
            !String::from_utf8_lossy(&listing.stdout).contains(&marker),
            "the program was left running"
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
            stdout: text.to_owned(),
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
    fn two_listings_together_are_held_to_the_bound_of_one_platform_command() {
        assert!(LISTING_LIMIT * 2 <= PLATFORM_LIMIT);
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
            stdout: text.to_owned(),
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
        // A host that cannot list says so in its own words and exits with a failure.
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
            // As many zero bytes in the even places as in the odd ones: two Latin letters and then
            // characters whose low byte is zero.
            "AB\u{4e00}\u{4e00}\u{4e00}\u{4e00}\r\n",
            "A\u{4e00}\u{4e00}\u{4e00}\r\n",
            // More in the even places than in the odd ones.
            "\u{4e00}\u{4e00}\u{4e00}\u{4e00}\u{4e00}\r\n",
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
            stdout: "true\n".to_owned(),
        };
        let stopped = CommandOutput {
            code: Some(0),
            text: "false\n".to_owned(),
            stdout: "false\n".to_owned(),
        };
        let absent = CommandOutput {
            code: Some(125),
            text: "no such container\n".to_owned(),
            stdout: String::new(),
        };
        assert_eq!(container_state(&running), EnvironmentPresence::Running);
        assert_eq!(
            container_state(&stopped),
            EnvironmentPresence::EnvironmentStopped
        );
        assert_eq!(container_state(&absent), EnvironmentPresence::Stale);
    }

    /// A runtime that warns on standard error while it answers `true` on standard output has a
    /// running container: the answer is what is read, whatever else the runtime says of itself.
    #[cfg(unix)]
    #[test]
    fn a_running_container_is_read_as_running_whatever_its_runtime_warns() {
        let output = run_within(
            "/bin/sh",
            &[
                "-c".to_owned(),
                "echo 'WARN[0000] a warning of the runtime' >&2; echo true".to_owned(),
            ],
            std::time::Duration::from_secs(60),
        )
        .expect("the command ends");
        assert!(output.text.contains("WARN"), "{output:?}");
        assert_eq!(container_state(&output), EnvironmentPresence::Running);
        assert_eq!(
            presence_after_inspection("podman container inspect", &output)
                .expect("an inspection that answered"),
            EnvironmentPresence::Running
        );
    }
}
