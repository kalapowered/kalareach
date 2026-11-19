//! The rule that a Mac test run loads nothing into the account's own launchd unless it asks.
//!
//! A run asks by setting [`VARIABLE`] to exactly `1`. A test program built with a crate's
//! `testing` feature that would run a `launchctl` command which loads, starts or removes a job
//! refuses unless the run asked, and a read (`print`, `list`) is always allowed. The decision is
//! [`refusal_given`], which takes the program, its arguments and whether the run asked, so that it
//! is shown without a process. The seams of the controller and of the command line call it before
//! they start a program, and every test source that runs `launchctl` itself runs it through
//! [`launchctl`].
//!
//! Only `launchctl` is held. A test run's Linux service manager is the test's own, and the other
//! programs the same runners start are none of this rule's concern.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The variable through which a run asks for the account's own launchd.
pub const VARIABLE: &str = "KR_ALLOW_ACCOUNT_LAUNCHD";

/// The program every launchd command is run through.
pub const LAUNCHCTL: &str = "/bin/launchctl";

/// What a refused `launchctl` command says. It is one constant, so that the check of the shipped
/// programs can search for its bytes.
pub const REFUSAL: &str = "this run did not ask for the account's own launchd, so this launchctl \
                           command is refused: set KR_ALLOW_ACCOUNT_LAUNCHD=1 where that account \
                           is a test account or a hosted runner's";

/// Whether a value of [`VARIABLE`] asks: only exactly `1` does.
#[must_use]
pub fn asked_given(value: Option<&OsStr>) -> bool {
    value == Some(OsStr::new("1"))
}

/// Whether this process's own run asked.
#[must_use]
pub fn asked() -> bool {
    asked_given(std::env::var_os(VARIABLE).as_deref())
}

/// Why `program` run with `arguments` is refused, when it is.
///
/// Only a program whose file name is `launchctl` (in any letter case, since the file system a Mac
/// test run is on does not tell them apart) is decided. Its first argument is its verb: `print` and
/// `list` read, and every other first argument, or none, changes the manager and is refused unless
/// the run asked. No option is skipped, so a later argument that is a read word never lets a change
/// through. Every other program is allowed, whatever its arguments.
#[must_use]
pub fn refusal_given(asked: bool, program: &Path, arguments: &[&str]) -> Option<&'static str> {
    let is_launchctl = program
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.eq_ignore_ascii_case("launchctl"));
    if asked || !is_launchctl {
        return None;
    }
    if matches!(arguments.first().copied(), Some("print" | "list")) {
        None
    } else {
        Some(REFUSAL)
    }
}

/// Runs `program` as `launchctl` with `arguments`, unless `asked` is false and the command changes
/// the manager.
///
/// # Errors
///
/// A refused command is an error of kind `PermissionDenied` whose message is [`REFUSAL`], and no
/// program starts. A program that cannot be started is the error of the start.
pub fn launchctl_given(asked: bool, program: &Path, arguments: &[&str]) -> std::io::Result<Output> {
    if let Some(refusal) = refusal_given(asked, program, arguments) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            refusal,
        ));
    }
    Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
}

/// Runs `program` as `launchctl` with `arguments` as [`launchctl_given`] does, for the run this
/// process belongs to.
///
/// # Errors
///
/// As [`launchctl_given`].
pub fn launchctl_at(program: &Path, arguments: &[&str]) -> std::io::Result<Output> {
    launchctl_given(asked(), program, arguments)
}

/// Gives `command` the run's asking, as `value` holds it, for a program started with a cleared
/// environment: the value exactly, when there is one, and no variable when there is none.
///
/// A program the test starts that runs `kr` against the service manager (and, through the job
/// definition, a daemon the manager starts) asks only if it holds the variable, and a cleared
/// environment does not.
pub fn pass_the_ask_from<'a>(command: &'a mut Command, value: Option<&OsStr>) -> &'a mut Command {
    match value {
        Some(value) => command.env(VARIABLE, value),
        None => command.env_remove(VARIABLE),
    }
}

/// Gives `command` this process's own value of [`VARIABLE`], as [`pass_the_ask_from`] does.
pub fn pass_the_ask(command: &mut Command) -> &mut Command {
    pass_the_ask_from(command, std::env::var_os(VARIABLE).as_deref())
}

/// The command that runs `/bin/launchctl` with `arguments`, for a test source that starts it itself
/// and keeps what it started (a bounded run, a status, an output).
///
/// A command that changes the manager, in a run that did not ask, is not `/bin/launchctl`: it is
/// a shell that says [`REFUSAL`] on its error output and ends with status 1, so that the case
/// reads a refused command as a failed one and no job is touched. A read is `/bin/launchctl`.
#[must_use]
pub fn command(arguments: &[&str]) -> Command {
    if refusal_given(asked(), Path::new(LAUNCHCTL), arguments).is_some() {
        let mut refused = Command::new("/bin/sh");
        refused.args(["-c", "echo \"$0\" >&2; exit 1", REFUSAL]);
        return refused;
    }
    let mut run = Command::new(LAUNCHCTL);
    run.args(arguments);
    run
}

/// Runs `/bin/launchctl` with `arguments` as [`launchctl_at`] does.
///
/// # Errors
///
/// As [`launchctl_at`].
pub fn launchctl(arguments: &[&str]) -> std::io::Result<Output> {
    launchctl_at(Path::new(LAUNCHCTL), arguments)
}

/// Places a program named `launchctl` in `folder` that writes the file `ran` beside itself when it
/// is run, and returns the program and that file's path.
///
/// A case that must see whether a command reached `launchctl` runs this one, so that no real
/// `launchctl` runs on any host.
///
/// # Panics
///
/// Panics when the program cannot be placed.
#[cfg(unix)]
#[must_use]
pub fn place_fake_in(folder: &Path) -> (PathBuf, PathBuf) {
    let program = folder.join("launchctl");
    crate::testing::place_script(&program, "#!/bin/sh\n: > \"${0%/*}/ran\"\n");
    (program, folder.join("ran"))
}

/// What a fixture run by [`run_fixture`] did.
#[derive(Debug)]
pub struct FixtureRun {
    /// Whether the program ended with success and ran exactly one test that passed.
    pub passed: bool,
    /// What the program printed, both streams, for the case's message.
    pub log: String,
}

/// Runs one `#[ignore]`d fixture of this test program in a child of its own, and says what it did.
///
/// The child has [`VARIABLE`] removed, or set to `asked` when that is given. A test program cannot
/// change its own environment (the workspace forbids the unsafe calls), so a case whose claim is
/// about a run that did or did not ask puts its assertions in a fixture, and asserts the result
/// here. `name` is the fixture's path as `concat!(module_path!(), "::<name>")` gives it; the crate's own name at its start is dropped, as the test program does not show it.
/// The run is one test at a time, and it counts as passed only when the program reports that it ran
/// one test and that test passed, so that a name that matches nothing is no pass.
///
/// # Panics
///
/// Panics when the program cannot be started.
#[must_use]
pub fn run_fixture(name: &str, asked: Option<&str>) -> FixtureRun {
    // The program names a test without its crate: `module_path!()` begins with the crate's name.
    let name = name.split_once("::").map_or(name, |(_, rest)| rest);
    let mut command = Command::new(std::env::current_exe().expect("this test program's path"));
    command
        .args(["--ignored", "--exact", name, "--test-threads=1"])
        .stdin(Stdio::null());
    match asked {
        Some(value) => command.env(VARIABLE, value),
        None => command.env_remove(VARIABLE),
    };
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("the fixture {name} could not be started: {error}"));
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    FixtureRun {
        passed: output.status.success() && log.contains("test result: ok. 1 passed;"),
        log,
    }
}
