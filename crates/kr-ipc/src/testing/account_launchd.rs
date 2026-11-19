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
//!
//! A test program that runs the shipped bytes of a daemon or of `kr` holds nothing itself, so the
//! functions that start one guard it. A case that would load a job begins with [`stands_down`],
//! which prints one line saying why it did not run and returns; the function that starts the launch
//! calls [`require`] (or one of the wrappers that read a command), which refuses a run that did not
//! ask, so that a case without its head fails before any job loads.

use std::ffi::OsStr;
use std::io::Write as _;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
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

/// What `launchctl print` says about the worker job in `domain` whose process is `pid`: the job is
/// the one of the jobs the manager lists, labelled `kr-worker-..`, that `print` shows running that
/// process.
///
/// Both commands read, so a run that did not ask may run them; no job is loaded or changed.
///
/// # Panics
///
/// Panics when `launchctl list` cannot be started.
#[cfg(target_os = "macos")]
#[must_use]
pub fn worker_job_of(domain: &str, pid: u64) -> Option<String> {
    let listed = command(&["list"])
        .output()
        .expect("launchctl lists the jobs");
    String::from_utf8_lossy(&listed.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().nth(2))
        .filter(|label| label.starts_with("kr-worker-"))
        .find_map(|label| {
            let printed = command(&["print", &format!("{domain}/{label}")])
                .output()
                .ok()?;
            let text = String::from_utf8_lossy(&printed.stdout).into_owned();
            text.lines()
                .any(|line| line.trim() == format!("pid = {pid}"))
                .then_some(text)
        })
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
/// here. `name` is the fixture's path as `concat!(module_path!(), "::<name>")` gives it; the crate's
/// own name at its start is dropped, as the test program does not show it. The run is one test at a
/// time, and it counts as passed only when the program reports that it ran one test and that test
/// passed, so that a name that matches nothing is no pass.
///
/// # Panics
///
/// Panics when the program cannot be started.
#[must_use]
pub fn run_fixture(name: &str, asked: Option<&str>) -> FixtureRun {
    run_fixture_with(name, asked, &[])
}

/// [`run_fixture`] with `options` given to the test program besides the ones that pick the fixture
/// (`--show-output`, for a run that shows what passing cases printed).
///
/// # Panics
///
/// Panics when the program cannot be started.
#[must_use]
pub fn run_fixture_with(name: &str, asked: Option<&str>, options: &[&str]) -> FixtureRun {
    // The program names a test without its crate: `module_path!()` begins with the crate's name.
    let name = name.split_once("::").map_or(name, |(_, rest)| rest);
    let mut command = Command::new(std::env::current_exe().expect("this test program's path"));
    command
        .args(["--ignored", "--exact", name, "--test-threads=1"])
        .args(options)
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

/// Whether a case that needs the account's own launchd stands down: on a Mac, when `value` of
/// [`VARIABLE`] does not ask. `macos` is a parameter so that the decision is shown on any host.
#[must_use]
pub fn stands_down_given(value: Option<&OsStr>, macos: bool) -> bool {
    macos && !asked_given(value)
}

/// The one line a stood-down case prints: `case` is its whole name and `what` says what would have
/// loaded a job. It ends in one newline and holds no other.
#[must_use]
pub fn notice(case: &str, what: &str) -> String {
    format!(
        "stood down {case}: {what} needs the account's own launchd, and this run did not ask for \
         it ({VARIABLE}=1 asks)\n"
    )
}

/// Prints [`notice`] for the case that runs on this thread, on standard error, in one write.
///
/// The test program does not capture a write made this way, so a run's log shows the line whether or
/// not it shows the output of passing cases. A thread with no name, or the main thread, is
/// `an unnamed case`, which the reader of the log refuses to tie to one case.
pub fn announce(what: &str) {
    let thread = std::thread::current();
    let case = thread
        .name()
        .filter(|name| *name != "main")
        .unwrap_or("an unnamed case");
    let line = notice(case, what);
    // A notice that cannot be written changes nothing: the case still returns.
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}

/// Says whether the case that calls this stands down, and when it does prints its notice. `what`
/// says what would load a job. A case begins `if stands_down("..") { return; }`.
#[must_use]
pub fn stands_down(what: &str) -> bool {
    let down = stands_down_given(
        std::env::var_os(VARIABLE).as_deref(),
        cfg!(target_os = "macos"),
    );
    if down {
        announce(what);
    }
    down
}

/// Why a launch of `what` is refused, as a sentence.
fn refusal_of(what: &str) -> String {
    format!(
        "{what} would load a job into the account's own launchd, and this run did not ask for it: \
         set {VARIABLE}=1 where that account is a test account or a hosted runner's, and begin the \
         case with account_launchd::stands_down so that it stands down where the run did not ask"
    )
}

/// Refuses a launch of `what` where [`stands_down_given`] holds.
///
/// # Errors
///
/// The refusal, which names the variable and the head a case begins with.
pub fn require_given(value: Option<&OsStr>, macos: bool, what: &str) -> Result<(), String> {
    if stands_down_given(value, macos) {
        Err(refusal_of(what))
    } else {
        Ok(())
    }
}

/// Refuses a launch of `what` in a run that did not ask on a Mac. The function that starts a launch
/// calls this first.
///
/// # Panics
///
/// Panics with the refusal, naming the variable, when the run did not ask on a Mac.
pub fn require(what: &str) {
    if let Err(refusal) = require_given(
        std::env::var_os(VARIABLE).as_deref(),
        cfg!(target_os = "macos"),
        what,
    ) {
        panic!("{refusal}");
    }
}

/// Whether a `kr` command word makes a session or runs a workflow: `new`, its alias `n`, `workflow`.
fn makes_a_session(command_word: Option<&str>) -> bool {
    matches!(command_word, Some("new" | "n" | "workflow"))
}

/// The command word of `kr`'s arguments: the first that does not begin with `-`.
fn command_word<'a>(mut arguments: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    arguments.find(|argument| !argument.starts_with('-'))
}

/// Whether `program` run with `arguments` makes a session or runs a workflow: the program's stem is
/// `kr` and its command word is `new`, `n` or `workflow`.
#[must_use]
pub fn creates_a_session(program: &Path, arguments: &[&str]) -> bool {
    program.file_stem().and_then(OsStr::to_str) == Some("kr")
        && makes_a_session(command_word(arguments.iter().copied()))
}

/// Whether shell text runs `kr` to make a session: a word that is `kr` or ends in `/kr`, then, after
/// the words that begin with `-`, `new`, `n` or `workflow`.
#[must_use]
pub fn creates_in_text(command: &str) -> bool {
    let words: Vec<&str> = command.split_whitespace().collect();
    words.iter().enumerate().any(|(at, word)| {
        (*word == "kr" || word.ends_with("/kr"))
            && makes_a_session(command_word(words[at + 1..].iter().copied()))
    })
}

/// [`require`] for a launch of `program` with `arguments`, only where that makes a session.
pub fn require_for_command(what: &str, program: &Path, arguments: &[&str]) {
    if creates_a_session(program, arguments) {
        require(what);
    }
}

/// [`require`] for a launch of `kr` with `arguments`, only where that makes a session.
pub fn require_for_arguments(what: &str, arguments: &[&str]) {
    if makes_a_session(command_word(arguments.iter().copied())) {
        require(what);
    }
}

/// [`require`] for shell text, only where it runs `kr` to make a session.
pub fn require_for_text(what: &str, command: &str) {
    if creates_in_text(command) {
        require(what);
    }
}
