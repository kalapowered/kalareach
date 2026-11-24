//! A stand-in for `launchctl`, for a test run that must reach no launchd of the account it runs in.
//!
//! `kr` and the control daemon are given this program in the place of `launchctl` by the seam of
//! `kr_ipc::testing::manager_stand_in`. It answers the commands `kr` puts to a launchd user domain:
//! `print`, `bootstrap`, `kickstart -p`, and the `bootout` the test's own teardown makes. It loads the
//! definition `kr` wrote as written, starts the daemon it names as that definition says, keeps one
//! record of each job, and writes down every call with its status. A command it does not know, a key
//! of the definition it does not apply (it accepts `ProcessType` as `Interactive` and applies none),
//! and a path outside the test's own folders are refused with status 64. A call is not written down
//! when the path of its record lies outside the test's own folders.
//!
//! Each process it starts is written down with the label of its job, as soon as it is started and
//! before the record that names it is kept. `bootout` ends every process written down for the job,
//! each with the members of the group it leads. One gap remains: a stand-in that is ended after it
//! starts a process and before it writes the process down leaves that process running, and
//! `bootout` does not find it. A write that fails ends the process it was for.
//!
//! What it cannot show: that real launchd accepts the file, that these answers are the real tool's
//! (they are copied from what `kr` reads), the session and the keychain a real job runs in, the
//! scheduling a process type asks for (the one value it accepts is the value `kr` writes, and it
//! applies none), launchd's restart policy, and what a logout does.
#![cfg(unix)]

pub mod plist;

use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use kr_ipc::identity::{
    ProcessState, Stop, ended_process_identity, process_state, processes_in_group,
    started_process_identity, stop_process,
};
use kr_protocol::identity::ProcessStartIdentity;
use rustix::process::Pid;
use serde::{Deserialize, Serialize};

use plist::Definition;

/// The variable that names this program to the processes it starts.
pub const VARIABLE: &str = "KR_MANAGER_STAND_IN";

/// The status of a command the stand-in refuses.
pub const REFUSED: i32 = 64;

/// What `launchctl print` exits with for a domain the user does not have.
const NO_SUCH_DOMAIN: i32 = 112;

/// What `launchctl print` exits with for a job the domain does not have.
const NOT_LOADED: i32 = 113;

/// What `launchctl bootstrap` exits with for a label already loaded.
const ALREADY_LOADED: i32 = 5;

/// The file, in the folder of the record, in which every process this program starts is written
/// down, one line each, with the label of the job it was started for. A line is written as soon as
/// the process is started and before the record that names it is kept, so that `bootout` and a
/// test's cleanup hold each process whatever came of the record.
pub const STARTED_FILE: &str = "started.jsonl";

/// One line of [`STARTED_FILE`]: a process this program started, and the label of its job.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Started {
    /// The label of the job the process was started for.
    pub label: String,
    /// The process.
    pub identity: ProcessStartIdentity,
}

/// The starts written down in `file`, in the order they were made; none when the file is not
/// there. A line that cannot be read is an error and is never skipped, since whose it is is not
/// known.
///
/// # Errors
///
/// The file cannot be read, or a line of it is not a start.
pub fn read_started(file: &Path) -> Result<Vec<Started>, String> {
    let text = match std::fs::read_to_string(file) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("{} cannot be read: {error}", file.display())),
    };
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line).map_err(|error| {
                format!(
                    "line {} of {} is not a start: {error}",
                    index + 1,
                    file.display()
                )
            })
        })
        .collect()
}

/// How long a daemon is given to end after it is asked to, and again after it is made to.
const END_BOUND: Duration = Duration::from_secs(15);

/// How long a call waits for the lock on its record. A call that holds it can take two
/// [`END_BOUND`]s to end a daemon, so this is longer than both.
const LOCK_BOUND: Duration = Duration::from_secs(60);

/// How long a command this program runs (`ps`, `lsof`) is given to end.
const COMMAND_BOUND: Duration = Duration::from_secs(20);

/// How much a command is read for on each stream. A listing of every process is far below it.
const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;

/// The variables the definition may not set: the harness's own.
const PROTECTED: [&str; 6] = [
    "HOME",
    "TMPDIR",
    "PATH",
    kr_ipc::paths::RUNTIME_DIR_VARIABLE,
    kr_ipc::paths::STATE_DIR_VARIABLE,
    VARIABLE,
];

/// What the stand-in keeps of one loaded job.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Job {
    /// The label.
    pub label: String,
    /// The domain it is loaded into.
    pub domain: String,
    /// The file it was loaded from.
    pub plist_path: String,
    /// What the file said when it was loaded: a later edit of the file is not seen.
    pub definition: String,
    /// The program, the arguments, the directory, the mask and the log, as the definition says.
    pub program: String,
    /// The arguments, the program first.
    pub arguments: Vec<String>,
    /// The working directory.
    pub working_directory: String,
    /// The file mode mask.
    pub umask: u32,
    /// The file standard output and error go to.
    pub log: String,
    /// The names of the variables of the daemon's environment, which the case compares.
    pub environment_keys: Vec<String>,
    /// How many times the job was started.
    pub starts: u32,
    /// The daemon's process, once started.
    pub identity: Option<ProcessStartIdentity>,
}

/// What a call knows of where it runs.
struct Context {
    /// The folder of this program, which also holds the installation's marker.
    own: PathBuf,
    /// The folders a path of a definition may lie in: the test's own tree and the installation.
    roots: Vec<PathBuf>,
    /// Where the record of the jobs and the calls is kept.
    store: PathBuf,
    /// The user whose domains these are: the owner of the installation's folder.
    uid: u32,
}

impl Context {
    /// Where this program stands and which test tree it serves, from its own folder and from the
    /// state directory the caller names.
    fn new() -> Result<Self, String> {
        let program = std::env::current_exe()
            .and_then(|path| path.canonicalize())
            .map_err(|error| format!("this program cannot be placed: {error}"))?;
        let own = program
            .parent()
            .ok_or("this program has no folder")?
            .to_path_buf();
        let state = std::env::var_os(kr_ipc::paths::STATE_DIR_VARIABLE)
            .map(PathBuf::from)
            .ok_or("the caller names no state directory, so there is no test tree to serve")?;
        let state = state
            .canonicalize()
            .map_err(|error| format!("the state directory cannot be placed: {error}"))?;
        let tree = state
            .parent()
            .ok_or("the state directory has no folder")?
            .to_path_buf();
        let uid = std::fs::metadata(&own)
            .map_err(|error| format!("the installation cannot be read: {error}"))?
            .uid();
        Ok(Self {
            store: state.join("manager-stand-in"),
            roots: vec![tree, own.clone()],
            own,
            uid,
        })
    }

    /// Whether `path` lies in one of the roots once every link it holds is resolved. A path that
    /// does not exist yet is judged by the folder it will be made in.
    fn bounded(&self, path: &Path) -> Result<PathBuf, String> {
        if !path.is_absolute() {
            return Err(format!("{} is not an absolute path", path.display()));
        }
        let resolved = match path.canonicalize() {
            Ok(resolved) => resolved,
            Err(_) => {
                // A link that leads nowhere would be followed when a file is made through it, so
                // what a path ends in is never a link unless it leads to an existing file.
                if std::fs::symlink_metadata(path).is_ok() {
                    return Err(format!("{} is a link that leads nowhere", path.display()));
                }
                path.parent()
                    .ok_or_else(|| format!("{} has no folder", path.display()))?
                    .canonicalize()
                    .map_err(|error| format!("{} cannot be placed: {error}", path.display()))?
                    .join(
                        path.file_name()
                            .ok_or_else(|| format!("{} names no file", path.display()))?,
                    )
            }
        };
        if self.roots.iter().any(|root| resolved.starts_with(root)) {
            Ok(resolved)
        } else {
            Err(format!(
                "{} is outside the folders of this test",
                path.display()
            ))
        }
    }

    /// A path of the store, once every link it holds is resolved and found inside the roots.
    fn in_store(&self, relative: &str) -> Result<PathBuf, String> {
        self.bounded(&self.store.join(relative))
    }

    /// The path of the record of the job `label`. A label that is a path or names none is an error,
    /// before any path is made of it.
    fn job_path(&self, label: &str) -> Result<PathBuf, String> {
        if !names_one_record(label) {
            return Err(format!(
                "the label {label:?} is a path or names none, and a label names one record"
            ));
        }
        self.in_store(&format!("jobs/{label}.json"))
    }

    /// The job `label` holds, if it is loaded.
    fn job(&self, label: &str) -> Result<Option<Job>, String> {
        match std::fs::read_to_string(self.job_path(label)?) {
            Ok(text) => serde_json::from_str(&text)
                .map(Some)
                .map_err(|error| format!("the record of {label} cannot be read: {error}")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("the record of {label} cannot be read: {error}")),
        }
    }

    /// Keeps `job`, whole or not at all.
    fn keep(&self, job: &Job) -> Result<(), String> {
        let path = self.job_path(&job.label)?;
        let text = serde_json::to_string_pretty(job).map_err(|error| error.to_string())?;
        let aside = self.in_store(&format!("jobs/{}.json.new", job.label))?;
        std::fs::write(&aside, text)
            .and_then(|()| std::fs::rename(&aside, &path))
            .map_err(|error| format!("the record of {} cannot be kept: {error}", job.label))
    }
}

/// Whether `label` can name one record of the store: it holds no separator and is not a folder.
fn names_one_record(label: &str) -> bool {
    !label.is_empty() && label != "." && label != ".." && !label.contains(['/', '\\', '\0'])
}

/// What one call came to.
struct Answer {
    status: i32,
    stdout: String,
    stderr: String,
}

impl Answer {
    fn said(stdout: impl Into<String>) -> Self {
        Self {
            status: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn failed(status: i32, stderr: impl Into<String>) -> Self {
        Self {
            status,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    fn refused(why: impl std::fmt::Display) -> Self {
        Self::failed(
            REFUSED,
            format!("the stand-in refuses this command: {why}\n"),
        )
    }
}

/// Splits a target `<domain>/<label>` into its parts, where the domain is `<kind>/<uid>`.
fn split_target(target: &str) -> Option<(String, &str)> {
    let mut parts = target.splitn(3, '/');
    let (kind, uid, label) = (parts.next()?, parts.next()?, parts.next()?);
    Some((format!("{kind}/{uid}"), label))
}

/// The status and the text that `launchctl` gives for a domain the user does not have, which the
/// stand-in gives for every command that names one.
#[must_use]
pub fn absent_domain(domain: &str) -> (i32, String) {
    (
        NO_SUCH_DOMAIN,
        format!("Could not find domain for {domain}\n"),
    )
}

/// The answer to a command that names a domain the user does not have.
fn domain_absent(domain: &str) -> Answer {
    let (status, said) = absent_domain(domain);
    Answer::failed(status, said)
}

/// The domain and the label of a job target, where the domain is the user's own: any other domain,
/// the graphical one included, is one the user does not have, and every command that names it gets
/// the answer for an absent domain, as `print` gives for `gui/<uid>` itself.
fn job_target<'a>(context: &Context, target: &'a str) -> Result<(String, &'a str), Answer> {
    let Some((domain, label)) = split_target(target) else {
        return Err(domain_absent(target));
    };
    if domain == format!("user/{}", context.uid) {
        Ok((domain, label))
    } else {
        Err(domain_absent(&domain))
    }
}

/// The job `label` loaded in `domain`: a job that is loaded in the other domain is not there, as
/// launchd answers.
fn job_in(context: &Context, domain: &str, label: &str) -> Result<Option<Job>, String> {
    Ok(context.job(label)?.filter(|job| job.domain == domain))
}

/// Runs the stand-in's own command line and returns the status it exits with.
#[must_use]
pub fn run(arguments: &[String]) -> i32 {
    let context = match Context::new() {
        Ok(context) => context,
        Err(why) => {
            let _ = writeln!(std::io::stderr(), "the stand-in cannot start: {why}");
            return REFUSED;
        }
    };
    // The store's own folders, files and links are judged as a definition's are, before anything is
    // made through them: a link that leads out of the test's folders is refused.
    let made = context.bounded(&context.store).and_then(|store| {
        std::fs::create_dir_all(store.join("jobs")).map_err(|error| error.to_string())
    });
    let paths = made.and_then(|()| {
        Ok((
            context.in_store("jobs")?,
            context.in_store("lock")?,
            context.in_store("calls.jsonl")?,
        ))
    });
    let lock_path = match paths {
        Ok((_, lock_path, _)) => lock_path,
        Err(why) => {
            let _ = writeln!(
                std::io::stderr(),
                "the stand-in cannot keep its record: {why}"
            );
            return REFUSED;
        }
    };
    let lock = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&lock_path)
    {
        Ok(lock) => lock,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr(),
                "the stand-in cannot lock its record: {error}"
            );
            return REFUSED;
        }
    };
    if let Err(error) = lock_within(&lock, LOCK_BOUND) {
        let _ = writeln!(
            std::io::stderr(),
            "the stand-in cannot lock its record: {error}"
        );
        return REFUSED;
    }
    let answer = answer(&context, arguments);
    let _ = std::io::stdout().write_all(answer.stdout.as_bytes());
    let _ = std::io::stderr().write_all(answer.stderr.as_bytes());
    // Written under the lock this call took, so a line is never torn by another call's.
    record(&context, arguments, answer.status);
    answer.status
}

/// Takes the exclusive lock on `lock`, waiting for it at most `bound`.
fn lock_within(lock: &std::fs::File, bound: Duration) -> Result<(), String> {
    let deadline = Instant::now() + bound;
    loop {
        match rustix::fs::flock(lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(()),
            Err(rustix::io::Errno::WOULDBLOCK) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("not taken within {bound:?}: {error}")),
        }
    }
}

/// Waits for `child` to end for at most `bound`, and says whether it was seen to.
pub fn reap_within(child: &mut Child, bound: Duration) -> bool {
    let deadline = Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) | Err(_) => return false,
        }
    }
}

/// Ends `child` and says what came of it, for a command that `name` started.
fn ended_after(child: &mut Child, name: &str, why: &str) -> String {
    let _ = child.kill();
    if reap_within(child, END_BOUND) {
        format!("{name} {why}, and was ended")
    } else {
        format!("{name} {why}, and was not seen to end")
    }
}

/// Reads `stream` on a thread of its own, for at most [`OUTPUT_LIMIT`] bytes and one more, which
/// shows that there was more.
fn read_aside(
    stream: Option<impl std::io::Read + Send + 'static>,
) -> std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        let read = match stream {
            Some(stream) => stream
                .take(OUTPUT_LIMIT as u64 + 1)
                .read_to_end(&mut held)
                .map(|_| held),
            None => Ok(held),
        };
        let _ = sender.send(read);
    });
    receiver
}

/// Runs `command` with no input and returns what it printed. The command is given `bound` to end
/// and is ended when it does not, and each stream is read for at most [`OUTPUT_LIMIT`] bytes. A
/// command that cannot be started, outlasts its bound, leaves its output open, or prints more than
/// the limit is an error, and an error never leaves the command unended without saying so.
///
/// # Errors
///
/// Says why the command did not give a bounded answer.
pub fn bounded_output(command: &mut Command, bound: Duration) -> Result<Output, String> {
    let name = command.get_program().to_string_lossy().into_owned();
    let deadline = Instant::now() + bound;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{name} cannot be started: {error}"))?;
    let out = read_aside(child.stdout.take());
    let err = read_aside(child.stderr.take());
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                return Err(ended_after(
                    &mut child,
                    &name,
                    &format!("did not end within {bound:?}"),
                ));
            }
            Err(error) => {
                return Err(ended_after(
                    &mut child,
                    &name,
                    &format!("cannot be waited for: {error}"),
                ));
            }
        }
    };
    let collect = |receiver: std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>, what: &str| {
        let left = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_secs(1));
        let held = receiver
            .recv_timeout(left)
            .map_err(|_| format!("{name}: its {what} was not closed in time"))?
            .map_err(|error| format!("{name}: its {what} cannot be read: {error}"))?;
        if held.len() > OUTPUT_LIMIT {
            return Err(format!(
                "{name} printed more than {OUTPUT_LIMIT} bytes on its {what}"
            ));
        }
        Ok(held)
    };
    Ok(Output {
        status,
        stdout: collect(out, "output")?,
        stderr: collect(err, "error output")?,
    })
}

/// Writes one line of the call log: its number, who called, the exact arguments and the status.
fn record(context: &Context, arguments: &[String], status: i32) {
    let Ok(log) = context.in_store("calls.jsonl") else {
        let _ = writeln!(
            std::io::stderr(),
            "the stand-in cannot record this call: its log is outside the folders of this test"
        );
        return;
    };
    let number = std::fs::read_to_string(&log).map_or(1, |text| text.lines().count() + 1);
    let parent = rustix::process::getppid().map_or(0, |pid| pid.as_raw_nonzero().get());
    let program = bounded_output(
        Command::new("/bin/ps").args(["-o", "comm=", "-p", &parent.to_string()]),
        COMMAND_BOUND,
    )
    .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    .unwrap_or_default();
    let mut keys: Vec<String> = std::env::vars_os()
        .filter_map(|(name, _)| name.into_string().ok())
        .collect();
    keys.sort();
    let line = serde_json::json!({
        "number": number,
        "caller": { "pid": parent, "program": program },
        "arguments": arguments,
        "status": status,
        "environment": keys,
    });
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
    {
        let _ = writeln!(file, "{line}");
    }
}

/// What the command `arguments` is answered with.
fn answer(context: &Context, arguments: &[String]) -> Answer {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["print", target] => print(context, target),
        ["bootstrap", domain, plist] => bootstrap(context, domain, Path::new(plist)),
        ["kickstart", "-p", target] => kickstart(context, target),
        ["bootout", target] => bootout(context, target),
        other => Answer::refused(format!("{other:?} is not a command it knows")),
    }
}

/// `print`: the graphical domain is absent, the background domain is there, and a job is described
/// as `Loaded::read` of `kr` reads it.
fn print(context: &Context, target: &str) -> Answer {
    let uid = context.uid;
    if target == format!("gui/{uid}") {
        return domain_absent(target);
    }
    if target == format!("user/{uid}") {
        return Answer::said(format!("{target} = {{\n\ttype = user\n}}\n"));
    }
    let (domain, label) = match job_target(context, target) {
        Ok(found) => found,
        Err(absent) => return absent,
    };
    match job_in(context, &domain, label) {
        Err(why) => Answer::refused(why),
        Ok(None) => Answer::failed(
            NOT_LOADED,
            format!("Could not find service \"{label}\" in domain for {domain}\n"),
        ),
        Ok(Some(job)) => Answer::said(describe(&job)),
    }
}

/// The description of a loaded job, in the lines `kr` reads: one tab in for a field, two for an
/// argument, and no `keepalive` among its properties.
fn describe(job: &Job) -> String {
    let running = job
        .identity
        .as_ref()
        .is_some_and(|identity| process_state(identity) == ProcessState::Running);
    let mut text = format!(
        "{}/{} = {{\n\tactive count = {}\n\tpath = {}\n\ttype = LaunchAgent\n\tstate = {}\n\tprogram = {}\n\targuments = {{\n",
        job.domain,
        job.label,
        u32::from(running),
        job.plist_path,
        if running { "running" } else { "not running" },
        job.program
    );
    for argument in &job.arguments {
        text.push_str(&format!("\t\t{argument}\n"));
    }
    text.push_str(&format!(
        "\t}}\n\tworking directory = {}\n\tproperties = interactive | supports transactions\n",
        job.working_directory
    ));
    if let Some(identity) = job.identity.as_ref().filter(|_| running) {
        text.push_str(&format!("\tpid = {}\n", identity.pid.get()));
    }
    text.push_str("}\n");
    text
}

/// What is wrong with a path argument of the definition, or its resolved form.
fn bound_arguments(context: &Context, definition: &Definition) -> Result<(), String> {
    let program = Path::new(&definition.arguments[0]);
    context.bounded(program)?;
    if plist_names_a_manager(program) {
        return Err(format!(
            "{} is a service-manager program",
            program.display()
        ));
    }
    context.bounded(Path::new(&definition.working_directory))?;
    context.bounded(Path::new(&definition.standard_out))?;
    bound_path_arguments(context, &definition.arguments[1..])
}

/// What is wrong with the arguments after the program: the value of `--runtime-dir` and of
/// `--state-dir`, in the form of two arguments and in the form `--state-dir=<path>`, is bounded like
/// every other path; any other argument that may name a path is refused, since a path that is not
/// read as one is not bounded.
fn bound_path_arguments(context: &Context, arguments: &[String]) -> Result<(), String> {
    let mut at = 0;
    while at < arguments.len() {
        let argument = arguments[at].as_str();
        let value = if matches!(argument, "--runtime-dir" | "--state-dir") {
            at += 1;
            let value = arguments
                .get(at)
                .ok_or_else(|| format!("the argument {argument} has no value"))?;
            Some(value.as_str())
        } else {
            argument
                .strip_prefix("--runtime-dir=")
                .or_else(|| argument.strip_prefix("--state-dir="))
        };
        match value {
            Some(path) => {
                context.bounded(Path::new(path))?;
            }
            None if may_name_a_path(argument) => {
                return Err(format!(
                    "the argument {argument} may name a path, and only the values of --runtime-dir \
                     and --state-dir are bounded"
                ));
            }
            None => {}
        }
        at += 1;
    }
    Ok(())
}

/// Whether an argument may be read as a path: it holds a separator, or is a folder or a home.
fn may_name_a_path(argument: &str) -> bool {
    argument.contains('/') || argument.starts_with('~') || matches!(argument, "." | "..")
}

/// Whether a program is a service manager by its file name, in any letter case.
fn plist_names_a_manager(program: &Path) -> bool {
    program
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| {
            name.eq_ignore_ascii_case("systemctl")
                || name.to_ascii_lowercase().starts_with("launch")
                    && name.to_ascii_lowercase().ends_with("ctl")
        })
}

/// `bootstrap`: loads the file as it is now, into the background domain, and starts nothing.
fn bootstrap(context: &Context, domain: &str, plist: &Path) -> Answer {
    if domain != format!("user/{}", context.uid) {
        return domain_absent(domain);
    }
    let plist = match context.bounded(plist) {
        Ok(plist) => plist,
        Err(why) => return Answer::refused(why),
    };
    let text = match std::fs::read_to_string(&plist) {
        Ok(text) => text,
        Err(error) => {
            return Answer::refused(format!("{} cannot be read: {error}", plist.display()));
        }
    };
    let definition = match Definition::read(&text) {
        Ok(definition) => definition,
        Err(why) => return Answer::refused(why),
    };
    if definition.session_type != "Background" {
        return Answer::refused(format!(
            "the session type {} does not belong in {domain}",
            definition.session_type
        ));
    }
    if definition.run_at_load || definition.keep_alive {
        return Answer::refused("the stand-in starts nothing at load and restarts nothing");
    }
    if definition.standard_out != definition.standard_error {
        return Answer::refused("output and error go to different files");
    }
    // Every variable of the product's own prefix is the harness's: the ask for the account's
    // launchd, the stand-in's and the directories' are all among them.
    if let Some((name, _)) = definition
        .environment
        .iter()
        .find(|(name, _)| PROTECTED.contains(&name.as_str()) || name.starts_with("KR_"))
    {
        return Answer::refused(format!(
            "the definition sets the variable {name}, which the harness owns"
        ));
    }
    if let Err(why) = bound_arguments(context, &definition) {
        return Answer::refused(why);
    }
    match context.job(&definition.label) {
        Err(why) => return Answer::refused(why),
        Ok(Some(_)) => {
            return Answer::failed(
                ALREADY_LOADED,
                format!(
                    "Bootstrap failed: 5: Input/output error ({} is loaded)\n",
                    definition.label
                ),
            );
        }
        Ok(None) => {}
    }
    let job = Job {
        label: definition.label.clone(),
        domain: domain.to_owned(),
        plist_path: plist.display().to_string(),
        definition: text,
        program: definition.arguments[0].clone(),
        arguments: definition.arguments.clone(),
        working_directory: definition.working_directory.clone(),
        umask: definition.umask,
        log: definition.standard_out.clone(),
        environment_keys: Vec::new(),
        starts: 0,
        identity: None,
    };
    match context.keep(&job) {
        Ok(()) => Answer::said(String::new()),
        Err(why) => Answer::refused(why),
    }
}

/// `kickstart -p`: starts the loaded job once as its definition says and prints the process; a job
/// that runs is not started again and its process is printed.
fn kickstart(context: &Context, target: &str) -> Answer {
    let (domain, label) = match job_target(context, target) {
        Ok(found) => found,
        Err(absent) => return absent,
    };
    let mut job = match job_in(context, &domain, label) {
        Err(why) => return Answer::refused(why),
        Ok(None) => {
            return Answer::failed(
                NOT_LOADED,
                format!("Could not find service \"{label}\" in domain for {domain}\n"),
            );
        }
        Ok(Some(job)) => job,
    };
    if let Some(identity) = &job.identity
        && process_state(identity) == ProcessState::Running
    {
        return Answer::said(format!("{}\n", identity.pid.get()));
    }
    let definition = match Definition::read(&job.definition) {
        Ok(definition) => definition,
        Err(why) => return Answer::refused(why),
    };
    match start(context, &job.label, &definition) {
        Err(why) => Answer::refused(why),
        Ok((identity, keys)) => {
            let pid = identity.pid.get();
            job.identity = Some(identity);
            job.environment_keys = keys;
            job.starts += 1;
            match context.keep(&job) {
                Ok(()) => Answer::said(format!("{pid}\n")),
                Err(why) => Answer::refused(why),
            }
        }
    }
}

/// Starts the daemon as `definition` says: its arguments, its directory, its mask, its log as both
/// outputs, no input, a process group of its own, a session of its own where this program can start
/// one, and an environment of a system path, the home, temporary, state and runtime directories of
/// the caller, the definition's own entries and the name of this program. launchd's defaults also
/// hold `USER`, `LOGNAME` and `SHELL`, which this program does not set.
fn start(
    context: &Context,
    label: &str,
    definition: &Definition,
) -> Result<(ProcessStartIdentity, Vec<String>), String> {
    // A session of its own, so that the daemon has no controlling terminal from the test that
    // started it. The call fails when this process leads a process group, and the daemon then keeps
    // the session it was started in, controlling terminal included.
    let _ = rustix::process::setsid();
    bound_arguments(context, definition)?;
    // The paths are resolved again here, so that a link made after the definition was loaded is
    // judged as it is now, and what is opened and entered is the resolved path, not the written one.
    let log_path = context.bounded(Path::new(&definition.standard_out))?;
    let directory = context.bounded(Path::new(&definition.working_directory))?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| format!("the log {} cannot be opened: {error}", log_path.display()))?;
    let error_log = log
        .try_clone()
        .map_err(|error| format!("the log cannot be shared: {error}"))?;
    let mut environment: Vec<(String, std::ffi::OsString)> = vec![
        ("PATH".to_owned(), "/usr/bin:/bin:/usr/sbin:/sbin".into()),
        (
            VARIABLE.to_owned(),
            context.own.join("kr-manager-stand-in").into(),
        ),
    ];
    // The caller's own directories ride along, so that the daemon's own reads of the service
    // manager reach this program's record of the same tree.
    for name in [
        "HOME",
        "TMPDIR",
        kr_ipc::paths::STATE_DIR_VARIABLE,
        kr_ipc::paths::RUNTIME_DIR_VARIABLE,
    ] {
        if let Some(value) = std::env::var_os(name) {
            environment.push((name.to_owned(), value));
        }
    }
    for (name, value) in &definition.environment {
        environment.push((name.clone(), value.into()));
    }
    let mask = rustix::fs::Mode::from_bits_truncate(definition.umask as rustix::fs::RawMode);
    rustix::process::umask(mask);
    let mut command = Command::new(&definition.arguments[0]);
    command
        .args(&definition.arguments[1..])
        .current_dir(&directory)
        .env_clear()
        .envs(environment.iter().map(|(name, value)| (name, value)))
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(error_log))
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|error| format!("{} cannot be started: {error}", definition.arguments[0]))?;
    let identity = match started_process_identity(child.id()) {
        Ok(identity) => identity,
        Err(error) => {
            let seen = ended_after_failure(&mut child);
            return Err(format!(
                "the process {} cannot be identified, {seen}: {error}",
                child.id()
            ));
        }
    };
    if let Err(why) = write_down_start(context, label, &identity) {
        let seen = ended_after_failure(&mut child);
        return Err(format!(
            "the start of the process {} cannot be written down, {seen}: {why}",
            child.id()
        ));
    }
    let mut keys: Vec<String> = environment.into_iter().map(|(name, _)| name).collect();
    keys.sort();
    Ok((identity, keys))
}

/// What is said of a start that failed after the process began, once it and its group are ended.
fn ended_after_failure(child: &mut Child) -> &'static str {
    if end_started(child, &Tools::system()) {
        "and it and its group were ended"
    } else {
        "and it and its group were killed, but not all seen to end"
    }
}

/// How a process's identity is read: by the kernel, or, in a case, by a reader that gives another
/// answer the second time.
type ReadIdentity<'a> = &'a dyn Fn(u32) -> Result<ProcessStartIdentity, String>;

/// The identity of the process `pid`, as the kernel reads it.
fn identity_of(pid: u32) -> Result<ProcessStartIdentity, String> {
    started_process_identity(pid).map_err(|error| error.to_string())
}

/// What the reading of a group reads the system with: the way it reads an identity and the way it
/// lists a group, so that a case can put a reader that gives another identity the second time, or
/// a list that fails, in their place.
struct Tools<'a> {
    identity: ReadIdentity<'a>,
    group: &'a dyn Fn(u32) -> Result<Vec<u32>, String>,
}

impl Tools<'static> {
    /// The system's own.
    fn system() -> Self {
        Self {
            identity: &identity_of,
            group: &listed_in_group,
        }
    }
}

/// The processes the kernel lists in the group `group`.
fn listed_in_group(group: u32) -> Result<Vec<u32>, String> {
    processes_in_group(group)
        .map_err(|error| format!("the group {group} cannot be listed: {error}"))
}

/// What a process whose identity cannot be read is said to be.
fn unreadable(pid: u32, why: &str) -> String {
    format!("the process {pid} cannot be identified: {why}")
}

/// What a process whose state is not known is said to be.
fn unknown(identity: &ProcessStartIdentity, detail: &str) -> String {
    format!(
        "whether the process {} still runs is not known ({detail})",
        identity.pid.get()
    )
}

/// The identity of the process `pid` when `proof` holds of it and it is the same process throughout.
///
/// A number names whichever process holds it when it is looked at. So the identity is read before
/// the proof and again after it, and a process is held only when both readings are one identity: a
/// process that had ended at the first reading, or was another process at the second, is not held,
/// and a proof is never made of one process and acted on for another.
fn held_through(
    pid: u32,
    read: ReadIdentity<'_>,
    proof: &mut dyn FnMut(&ProcessStartIdentity) -> Result<bool, String>,
) -> Result<Option<ProcessStartIdentity>, String> {
    let before = read(pid).map_err(|why| unreadable(pid, &why))?;
    if before == ended_process_identity(pid) || !proof(&before)? {
        return Ok(None);
    }
    let after = read(pid).map_err(|why| unreadable(pid, &why))?;
    Ok((after == before).then_some(before))
}

/// The number of the group the process `identity` leads, which a daemon the stand-in started does:
/// its descendants are in it. No other process holds the number while a process of the group runs.
fn group_of(identity: &ProcessStartIdentity) -> Result<Pid, String> {
    i32::try_from(identity.pid.get())
        .ok()
        .and_then(Pid::from_raw)
        .ok_or_else(|| format!("the process {} has no group number", identity.pid.get()))
}

/// The processes in the group `leader` leads, now, each held by identity as a member of it: its
/// identity is read, its group is read, and its identity is read again, and a process that does not
/// give the same identity both times, or is not in the group, is left out. A group that cannot be
/// listed or read is an error, which is not an empty group.
///
/// The group's number is the leader's. While the leader runs, or a member does, no other process
/// holds the number. Once both have ended, another process can be given it and lead a group of its
/// own, so the number is read before the list and after it: where another process holds it, the
/// group has ended, and nothing in the list is the leader's to end.
fn members_of(
    leader: &ProcessStartIdentity,
    group: Pid,
    tools: &Tools<'_>,
) -> Result<Vec<ProcessStartIdentity>, String> {
    let number = group.as_raw_pid().unsigned_abs();
    let number_is_the_groups = || -> Result<bool, String> {
        let holder = (tools.identity)(number).map_err(|why| unreadable(number, &why))?;
        Ok(holder == *leader || holder == ended_process_identity(number))
    };
    if !number_is_the_groups()? {
        return Ok(Vec::new());
    }
    let members = members_listed(group, tools)?;
    Ok(if number_is_the_groups()? {
        members
    } else {
        Vec::new()
    })
}

/// The processes the kernel lists in the group `group`, each held by identity as a member of it:
/// its identity is read, its group is read, and its identity is read again, and a process that does
/// not give the same identity both times, is not in the group, or has ended, is left out. A group
/// that cannot be listed or read is an error. The number of the group is not judged here: whoever
/// calls this holds it.
fn members_listed(group: Pid, tools: &Tools<'_>) -> Result<Vec<ProcessStartIdentity>, String> {
    let number = group.as_raw_pid().unsigned_abs();
    let mut members = Vec::new();
    for pid in (tools.group)(number)? {
        if pid == std::process::id() {
            continue;
        }
        let mut in_group = |_: &ProcessStartIdentity| match i32::try_from(pid)
            .ok()
            .and_then(Pid::from_raw)
            .map(|process| rustix::process::getpgid(Some(process)))
        {
            Some(Ok(found)) => Ok(found == group),
            Some(Err(rustix::io::Errno::SRCH)) => Ok(false),
            Some(Err(error)) => Err(format!(
                "the group of the process {pid} cannot be read: {error}"
            )),
            None => Ok(false),
        };
        // A member that has ended and is not yet collected is listed, and is not a member.
        members.extend(
            held_through(pid, tools.identity, &mut in_group)?
                .filter(|member| process_state(member) != ProcessState::Ended),
        );
    }
    Ok(members)
}

/// Ends the process `child`, which this program has just started, and every process of the group it
/// leads, and collects it. The child is this program's own and is not collected yet, so its number
/// is still its and the number of its group is held until it is collected: the members are listed
/// and ended, each by identity, before the child is collected. Says whether the group was shown
/// to have ended and the child to be collected, each within [`END_BOUND`].
fn end_started(child: &mut Child, tools: &Tools<'_>) -> bool {
    let _ = child.kill();
    let mut ended = false;
    if let Some(group) = i32::try_from(child.id()).ok().and_then(Pid::from_raw) {
        let deadline = Instant::now() + END_BOUND;
        while !ended && Instant::now() < deadline {
            match members_listed(group, tools) {
                Ok(members) if members.is_empty() => ended = true,
                Ok(members) => {
                    for member in &members {
                        let _ = stop_process(member, Stop::Kill);
                    }
                }
                Err(_) => {}
            }
            if !ended {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    reap_within(child, END_BOUND) && ended
}

/// The processes in the group the process `leader` leads, now, each held by identity as a member of
/// it, as `bootout` reads them: a test's cleanup reads a group no other way.
///
/// # Errors
///
/// A group that cannot be listed or read is an error, which is not an empty group.
pub fn members_of_group(
    leader: &ProcessStartIdentity,
) -> Result<Vec<ProcessStartIdentity>, String> {
    members_of(leader, group_of(leader)?, &Tools::system())
}

/// Writes `identity` down as a process this program started for the job `label`.
fn write_down_start(
    context: &Context,
    label: &str,
    identity: &ProcessStartIdentity,
) -> Result<(), String> {
    let path = context.in_store(STARTED_FILE)?;
    let line = serde_json::to_string(&Started {
        label: label.to_owned(),
        identity: identity.clone(),
    })
    .map_err(|error| error.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("{} cannot be opened: {error}", path.display()))?;
    writeln!(file, "{line}")
        .map_err(|error| format!("{} cannot be written: {error}", path.display()))
}

/// Whether the process `identity` and every process of its group are shown to have ended within
/// `bound`. A state or a group that is not known is an error and not an end.
fn ended_within(
    identity: &ProcessStartIdentity,
    group: Pid,
    state: &dyn Fn(&ProcessStartIdentity) -> ProcessState,
    tools: &Tools<'_>,
    bound: Duration,
) -> Result<bool, String> {
    let over = || match state(identity) {
        ProcessState::Running => Ok(false),
        ProcessState::Unknown { detail } => Err(unknown(identity, &detail)),
        ProcessState::Ended => Ok(members_of(identity, group, tools)?.is_empty()),
    };
    let deadline = Instant::now() + bound;
    while Instant::now() < deadline {
        if over()? {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    over()
}

/// Ends every process of `identities` and of the groups they lead, asking first and then making
/// sure, each within `bound`. A leader that has ended does not end the duty to its group: its
/// members are ended by identity before the end is reported. A signal goes to a process only by its identity, and to the members of
/// a group only as members found and held by identity just before: never to a number, which can name
/// another process or group by the time a signal arrives. A process whose state is not known, and a
/// process or group that is not shown to have ended after it was made to, is an error: nothing is
/// called ended that was not seen to end.
fn end_all(
    identities: &[ProcessStartIdentity],
    state: &dyn Fn(&ProcessStartIdentity) -> ProcessState,
    tools: &Tools<'_>,
    bound: Duration,
) -> Result<(), String> {
    for identity in identities {
        if let ProcessState::Unknown { detail } = state(identity) {
            return Err(unknown(identity, &detail));
        }
        let group = group_of(identity)?;
        let mut ended = false;
        for stop in [Stop::Terminate, Stop::Kill] {
            let _ = stop_process(identity, stop);
            for member in members_of(identity, group, tools)? {
                let _ = stop_process(&member, stop);
            }
            if ended_within(identity, group, state, tools, bound)? {
                ended = true;
                break;
            }
        }
        if !ended {
            return Err(format!("the process {} did not end", identity.pid.get()));
        }
    }
    Ok(())
}

/// The processes written down for the job `label`.
fn written_down_for(context: &Context, label: &str) -> Result<Vec<ProcessStartIdentity>, String> {
    Ok(read_started(&context.in_store(STARTED_FILE)?)?
        .into_iter()
        .filter(|started| started.label == label)
        .map(|started| started.identity)
        .collect())
}

/// Ends every process written down for `job` and the one its record names, each with the members of
/// the group it leads. A line of the file that cannot be read is an error.
fn end_job(context: &Context, job: &Job) -> Result<(), String> {
    let mut identities: Vec<ProcessStartIdentity> = job.identity.clone().into_iter().collect();
    identities.extend(written_down_for(context, &job.label)?);
    identities.sort();
    identities.dedup();
    end_all(&identities, &process_state, &Tools::system(), END_BOUND)
}

/// `bootout`: ends every process written down for the job and the one its record names, each with
/// the members of the group it leads, each by its own identity, asking first and then making sure,
/// and unloads the job. Nothing is signalled by a number, so a process that holds a number now that
/// another process held is left alone. A process that is not shown to have ended, and a line of
/// the file of starts that cannot be read, keep the job loaded and are reported as a failure.
fn bootout(context: &Context, target: &str) -> Answer {
    let (domain, label) = match job_target(context, target) {
        Ok(found) => found,
        Err(absent) => return absent,
    };
    let job = match job_in(context, &domain, label) {
        Err(why) => return Answer::refused(why),
        Ok(None) => {
            return Answer::failed(
                NOT_LOADED,
                format!("Could not find service \"{label}\" in domain for {target}\n"),
            );
        }
        Ok(Some(job)) => job,
    };
    if let Err(why) = end_job(context, &job) {
        return Answer::failed(REFUSED, format!("{why}, and the job is kept\n"));
    }
    let record = match context.job_path(label) {
        Ok(record) => record,
        Err(why) => return Answer::refused(why),
    };
    match std::fs::remove_file(record) {
        Ok(()) => Answer::said(String::new()),
        Err(error) => Answer::refused(format!("the record of {label} cannot be removed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_ipc::testing::PrivateTempDir;

    /// A label names one record: an absolute label, a label with a parent component, a label with a
    /// separator, a folder and an empty label are errors before any path is made of them.
    #[test]
    fn a_label_that_is_a_path_is_refused_before_any_record_is_looked_up() {
        let folder = PrivateTempDir::create();
        let root = folder.path().canonicalize().expect("a folder");
        std::fs::create_dir_all(root.join("store/jobs")).expect("a store");
        let context = Context {
            own: root.clone(),
            roots: vec![root.clone()],
            store: root.join("store"),
            uid: 0,
        };
        for label in ["/abs/x", "../escape", "a/b", "..", ".", "", "a\\b", "a\0b"] {
            assert!(context.job_path(label).is_err(), "{label:?}");
            assert!(context.job(label).is_err(), "{label:?}");
        }
        assert!(context.job_path("kr-controller-x").is_ok());
        assert!(context.job("kr-controller-x").expect("no record").is_none());
    }

    /// A path argument is bounded or refused in every form: the values of `--runtime-dir` and
    /// `--state-dir` as two arguments and as one, inside the roots or not, and any other argument
    /// that may name a path.
    #[test]
    fn a_path_argument_in_every_form_is_bounded_or_refused() {
        let folder = PrivateTempDir::create();
        let root = folder.path().canonicalize().expect("a folder");
        let context = Context {
            own: root.clone(),
            roots: vec![root.clone()],
            store: root.join("store"),
            uid: 0,
        };
        let inside = root.display().to_string();
        let words = |arguments: &[&str]| {
            bound_path_arguments(
                &context,
                &arguments
                    .iter()
                    .map(|word| (*word).to_owned())
                    .collect::<Vec<_>>(),
            )
        };
        for held in [
            vec!["--runtime-dir", inside.as_str()],
            vec!["--state-dir", inside.as_str()],
            vec!["--secret-store", "file", "30"],
        ] {
            assert_eq!(words(&held), Ok(()), "{held:?}");
        }
        let equals = [
            format!("--runtime-dir={inside}"),
            format!("--state-dir={inside}"),
        ];
        for held in &equals {
            assert_eq!(words(&[held.as_str()]), Ok(()), "{held}");
        }
        for refused in [
            vec!["--state-dir", "/outside"],
            vec!["--runtime-dir", "/outside"],
            vec!["--state-dir=/outside"],
            vec!["--runtime-dir=/outside"],
            vec!["--state-dir"],
            vec!["--secret-store=/outside"],
            vec!["/outside"],
            vec!["../x"],
            vec!["~/x"],
            vec![".."],
            vec!["a/b"],
        ] {
            assert!(words(&refused).is_err(), "{refused:?}");
        }
    }

    /// Ends the child it holds when it is dropped.
    struct Held(std::process::Child);

    impl Drop for Held {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = reap_within(&mut self.0, Duration::from_secs(10));
        }
    }

    /// Runs `call` on a thread of its own and gives it `limit` to return, or says that it did not.
    fn within<T: Send + 'static>(
        limit: Duration,
        call: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(call());
        });
        receiver.recv_timeout(limit).ok()
    }

    /// A command that outlasts its bound is ended and is an error, within the bound and a little
    /// more, and a command that ends in time gives what it printed.
    #[test]
    fn a_command_that_outlasts_its_bound_is_ended_and_is_an_error() {
        let started = Instant::now();
        let slow = bounded_output(
            Command::new("/bin/sleep").arg("5"),
            Duration::from_millis(300),
        );
        assert!(
            slow.as_ref()
                .is_err_and(|why| why.contains("did not end within")),
            "{slow:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the command was given its bound and no more"
        );
        let quick = bounded_output(
            Command::new("/bin/echo").arg("said"),
            Duration::from_secs(20),
        )
        .expect("a command that ends in time");
        assert_eq!(String::from_utf8_lossy(&quick.stdout).trim(), "said");
    }

    /// A command that prints more than the limit is an error, and is not read without end.
    #[test]
    fn a_command_that_prints_past_the_limit_is_an_error() {
        let flood = bounded_output(&mut Command::new("/usr/bin/yes"), Duration::from_secs(20));
        assert!(
            flood.as_ref().is_err_and(|why| why.contains("more than")),
            "{:?}",
            flood.map(|output| output.stdout.len())
        );
    }

    /// A lock that another holder keeps is an error within the bound, and a free lock is taken.
    #[test]
    fn a_lock_that_is_kept_is_an_error_within_its_bound() {
        let folder = PrivateTempDir::create();
        let path = folder.path().join("lock");
        let kept = std::fs::File::create(&path).expect("a lock file");
        rustix::fs::flock(&kept, rustix::fs::FlockOperation::LockExclusive).expect("a lock");
        let other = std::fs::File::open(&path).expect("the lock file again");
        let waited = within(Duration::from_secs(10), move || {
            lock_within(&other, Duration::from_millis(300))
        });
        match waited {
            None => panic!("the wait for the lock has no bound"),
            Some(taken) => assert!(taken.is_err(), "a lock that is kept was taken"),
        }
        drop(kept);
        let free = std::fs::File::open(&path).expect("the lock file once more");
        assert_eq!(lock_within(&free, Duration::from_secs(10)), Ok(()));
    }

    /// A child that has not ended is waited for at most its bound, and is not ended by the wait.
    #[test]
    fn a_child_that_does_not_end_is_waited_for_within_its_bound_only() {
        let mut held = Held(
            Command::new("/bin/sleep")
                .arg("3")
                .spawn()
                .expect("a process that runs"),
        );
        let started = Instant::now();
        assert!(!reap_within(&mut held.0, Duration::from_millis(200)));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(held.0.try_wait().expect("its state"), None, "still running");
    }

    /// A process whose state is not known is not an end: ending it is an error, and nothing was
    /// signalled to the process that runs.
    #[test]
    fn a_process_whose_state_is_not_known_is_not_an_end() {
        let mut held = Held(
            Command::new("/bin/sleep")
                .arg("30")
                .spawn()
                .expect("a process that runs"),
        );
        let identity = started_process_identity(held.0.id()).expect("its identity");
        let not_known = |_: &ProcessStartIdentity| ProcessState::Unknown {
            detail: "the system did not answer".to_owned(),
        };
        let ended = end_all(
            std::slice::from_ref(&identity),
            &not_known,
            &Tools::system(),
            Duration::from_secs(1),
        );
        assert!(
            ended.as_ref().is_err_and(|why| why.contains("not known")),
            "{ended:?}"
        );
        assert_eq!(
            held.0.try_wait().expect("its state"),
            None,
            "nothing was signalled to the process"
        );
    }

    /// A process is held only when it is the same process before and after its proof: one that had
    /// ended at the first reading, one that is another process at the second, and one whose
    /// identity cannot be read are not held, and the last is an error and not an absence.
    #[test]
    fn a_process_is_held_only_when_it_is_the_same_one_before_and_after_its_proof() {
        let own = kr_ipc::identity::current_process_start_identity().expect("an identity");
        let other = ProcessStartIdentity::new(
            own.pid.get(),
            own.source,
            own.start_value.get().wrapping_add(1),
        );
        let pid = u32::try_from(own.pid.get()).expect("a number");
        let proven = |_: &ProcessStartIdentity| Ok(true);
        let same = |_: u32| Ok(own.clone());
        assert_eq!(
            held_through(pid, &same, &mut { proven }).expect("read"),
            Some(own.clone())
        );
        let calls = std::cell::Cell::new(0_u32);
        let replaced = |_: u32| {
            calls.set(calls.get() + 1);
            Ok(if calls.get() == 1 {
                own.clone()
            } else {
                other.clone()
            })
        };
        assert_eq!(
            held_through(pid, &replaced, &mut { proven }).expect("read"),
            None,
            "a process that is another at the second reading is not held"
        );
        let ended = |read_pid: u32| Ok(ended_process_identity(read_pid));
        let mut proof_made = false;
        let held = held_through(pid, &ended, &mut |_| {
            proof_made = true;
            Ok(true)
        })
        .expect("read");
        assert_eq!(held, None, "a process that had ended is not held");
        assert!(!proof_made, "no proof is made of a process that had ended");
        let refused = |_: u32| Err("the system refused".to_owned());
        let unread = held_through(pid, &refused, &mut { proven });
        assert!(
            unread
                .as_ref()
                .is_err_and(|why| why.contains("cannot be identified") && why.contains("refused")),
            "{unread:?}"
        );
    }

    /// Ends the process it holds by its identity when it is dropped.
    struct Ended(ProcessStartIdentity);

    impl Drop for Ended {
        fn drop(&mut self) {
            let _ = stop_process(&self.0, Stop::Kill);
        }
    }

    /// A shell that leads a group of its own and waits for a `sleep` it started, the shell and the
    /// identity of the `sleep`.
    fn a_leader_with_a_member() -> (Held, ProcessStartIdentity, Ended) {
        let leader = Held(
            Command::new("/bin/sh")
                .args(["-c", "sleep 60 & wait"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .expect("a shell"),
        );
        let identity = started_process_identity(leader.0.id()).expect("its identity");
        let deadline = Instant::now() + Duration::from_secs(20);
        let member = loop {
            let found = processes_in_group(leader.0.id())
                .expect("a group")
                .into_iter()
                .find(|pid| *pid != leader.0.id());
            if let Some(pid) = found {
                break started_process_identity(pid).expect("the member's identity");
            }
            assert!(Instant::now() < deadline, "the shell started no process");
            std::thread::sleep(Duration::from_millis(20));
        };
        (leader, identity, Ended(member))
    }

    /// A member of a group is signalled only when it is held as the same process at both of its
    /// readings: a member whose number another process holds at the second reading is left running.
    #[test]
    fn a_group_member_that_is_another_process_at_its_second_reading_is_not_signalled() {
        let (mut leader, identity, member) = a_leader_with_a_member();
        let calls = std::cell::Cell::new(0_u32);
        let swapped = |pid: u32| {
            let read = identity_of(pid)?;
            if u64::from(pid) != member.0.pid.get() {
                return Ok(read);
            }
            calls.set(calls.get() + 1);
            Ok(if calls.get() % 2 == 1 {
                read
            } else {
                ProcessStartIdentity::new(
                    read.pid.get(),
                    read.source,
                    read.start_value.get().wrapping_add(1),
                )
            })
        };
        end_all(
            std::slice::from_ref(&identity),
            &process_state,
            &Tools {
                identity: &swapped,
                ..Tools::system()
            },
            Duration::from_secs(5),
        )
        .expect("the leader ends");
        assert!(reap_within(&mut leader.0, Duration::from_secs(5)));
        assert!(calls.get() >= 2, "the member was read");
        assert_eq!(
            process_state(&member.0),
            ProcessState::Running,
            "a member that was another process at its second reading was signalled"
        );
    }

    /// No signal goes to a number: every one goes to a process held by its identity, so no call that
    /// signals by number is in the program.
    #[test]
    fn no_signal_is_sent_to_a_number() {
        let source = include_str!("lib.rs");
        for call in [concat!("kill_", "process"), concat!("Signal", "::")] {
            assert!(
                !source.contains(call),
                "the program signals by number with {call}"
            );
        }
    }

    /// A group whose leader has ended is still ended: the members it left are ended by identity
    /// before the end is reported.
    #[test]
    fn the_members_a_leader_left_are_ended_when_the_leader_has_ended() {
        let (mut leader, identity, member) = a_leader_with_a_member();
        let _ = leader.0.kill();
        assert!(reap_within(&mut leader.0, Duration::from_secs(5)));
        assert_eq!(process_state(&identity), ProcessState::Ended);
        assert_eq!(process_state(&member.0), ProcessState::Running);
        end_all(
            std::slice::from_ref(&identity),
            &process_state,
            &Tools::system(),
            Duration::from_secs(5),
        )
        .expect("the group ends");
        assert_eq!(
            process_state(&member.0),
            ProcessState::Ended,
            "the member the leader left was not ended"
        );
    }

    /// A start that fails after the process began ends the process and the members of the group it
    /// leads, and collects the process: the members are ended while the process is not yet collected
    /// and its number is still its.
    #[test]
    fn a_start_that_failed_ends_the_process_and_the_members_of_its_group() {
        let (mut leader, identity, member) = a_leader_with_a_member();
        assert!(
            end_started(&mut leader.0, &Tools::system()),
            "the process and its group were not shown to have ended"
        );
        assert_eq!(
            process_state(&member.0),
            ProcessState::Ended,
            "the member of the group was not ended"
        );
        assert_eq!(process_state(&identity), ProcessState::Ended);
        assert!(
            leader.0.try_wait().expect("the process").is_some(),
            "the process was not collected"
        );
    }

    /// A group whose number another process holds has ended: nothing the process that holds the
    /// number leads is the group's to end, whatever the kernel lists under the number.
    #[test]
    fn a_number_that_another_process_holds_is_not_the_group_of_the_leader_that_had_it() {
        let (_leader, identity, member) = a_leader_with_a_member();
        let stranger = |pid: u32| {
            let read = identity_of(pid)?;
            Ok(if u64::from(pid) == identity.pid.get() {
                ProcessStartIdentity::new(
                    read.pid.get(),
                    read.source,
                    read.start_value.get().wrapping_add(1),
                )
            } else {
                read
            })
        };
        let tools = Tools {
            identity: &stranger,
            ..Tools::system()
        };
        let group = group_of(&identity).expect("a group number");
        assert!(
            members_of(&identity, group, &tools)
                .expect("a list")
                .is_empty(),
            "the group of a leader that is another process now was listed"
        );
        let own = Tools::system();
        assert!(
            members_of(&identity, group, &own)
                .expect("a list")
                .contains(&member.0),
            "the group of the leader that runs lists its member"
        );
    }

    /// A group that cannot be listed is not known to be empty: ending it is an error, whether or not
    /// its leader has ended.
    #[test]
    fn a_group_that_cannot_be_listed_is_not_known_and_is_an_error() {
        let mut held = Held(
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .spawn()
                .expect("a process that runs"),
        );
        let identity = started_process_identity(held.0.id()).expect("its identity");
        let tools = Tools {
            group: &|group| Err(format!("the group {group} cannot be listed: refused")),
            ..Tools::system()
        };
        let running = end_all(
            std::slice::from_ref(&identity),
            &process_state,
            &tools,
            Duration::from_secs(1),
        );
        assert!(
            running
                .as_ref()
                .is_err_and(|why| why.contains("cannot be listed")),
            "{running:?}"
        );
        let _ = held.0.kill();
        assert!(reap_within(&mut held.0, Duration::from_secs(5)));
        let ended = end_all(
            std::slice::from_ref(&identity),
            &process_state,
            &tools,
            Duration::from_secs(1),
        );
        assert!(
            ended
                .as_ref()
                .is_err_and(|why| why.contains("cannot be listed")),
            "an ended leader's group that cannot be listed is not an end: {ended:?}"
        );
    }
}
