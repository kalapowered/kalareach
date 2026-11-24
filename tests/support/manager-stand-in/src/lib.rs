//! A stand-in for `launchctl`, for a test run that must reach no launchd of the account it runs in.
//!
//! `kr` and the control daemon are given this program in the place of `launchctl` by the seam of
//! `kr_ipc::testing::manager_stand_in`. It answers the commands `kr` puts to a launchd user domain:
//! `print`, `bootstrap`, `kickstart -p`, and the `bootout` the test's own teardown makes. It loads the
//! definition `kr` wrote as written, starts the daemon it names as that definition says, keeps one
//! record of each job, and writes down every call. A command it does not know, a key of the
//! definition it does not apply, and a path outside the test's own folders are refused with status 64
//! and recorded as such.
//!
//! What it cannot show: that real launchd accepts the file, that these answers are the real tool's
//! (they are copied from what `kr` reads), the session and the keychain a real job runs in, launchd's
//! restart policy, and what a logout does.
#![cfg(unix)]

pub mod plist;

use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kr_ipc::identity::{ProcessState, Stop, process_state, started_process_identity, stop_process};
use kr_protocol::identity::ProcessStartIdentity;
use serde::{Deserialize, Serialize};

use plist::Definition;

/// The variable that names this program to the processes it starts.
pub const VARIABLE: &str = "KR_MANAGER_STAND_IN";

/// The variable of the daemon's environment that ties its process to the job and the start that
/// made it, so that a start that was never recorded can still be found by what its environment says.
pub const JOB_VARIABLE: &str = "KR_MANAGER_STAND_IN_JOB";

/// The status of a command the stand-in refuses.
pub const REFUSED: i32 = 64;

/// What `launchctl print` exits with for a domain the user does not have.
const NO_SUCH_DOMAIN: i32 = 112;

/// What `launchctl print` exits with for a job the domain does not have.
const NOT_LOADED: i32 = 113;

/// What `launchctl bootstrap` exits with for a label already loaded.
const ALREADY_LOADED: i32 = 5;

/// How long a daemon is given to end after it is asked to, and again after it is made to.
const END_BOUND: Duration = Duration::from_secs(15);

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
    /// The nonce of a start whose process was not recorded yet.
    pub pending: Option<String>,
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

    /// The path of the record of the job `label`.
    fn job_path(&self, label: &str) -> PathBuf {
        self.store.join("jobs").join(format!("{label}.json"))
    }

    /// The job `label` holds, if it is loaded.
    fn job(&self, label: &str) -> Result<Option<Job>, String> {
        match std::fs::read_to_string(self.job_path(label)) {
            Ok(text) => serde_json::from_str(&text)
                .map(Some)
                .map_err(|error| format!("the record of {label} cannot be read: {error}")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("the record of {label} cannot be read: {error}")),
        }
    }

    /// Keeps `job`, whole or not at all.
    fn keep(&self, job: &Job) -> Result<(), String> {
        let path = self.job_path(&job.label);
        let text = serde_json::to_string_pretty(job).map_err(|error| error.to_string())?;
        let aside = path.with_extension("json.new");
        std::fs::write(&aside, text)
            .and_then(|()| std::fs::rename(&aside, &path))
            .map_err(|error| format!("the record of {} cannot be kept: {error}", job.label))
    }
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
    if let Err(error) = std::fs::create_dir_all(context.store.join("jobs")) {
        let _ = writeln!(
            std::io::stderr(),
            "the stand-in cannot keep its record: {error}"
        );
        return REFUSED;
    }
    let lock = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(context.store.join("lock"))
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
    if let Err(error) = rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive) {
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

/// Writes one line of the call log: its number, who called, the exact arguments and the status.
fn record(context: &Context, arguments: &[String], status: i32) {
    let log = context.store.join("calls.jsonl");
    let number = std::fs::read_to_string(&log).map_or(1, |text| text.lines().count() + 1);
    let parent = rustix::process::getppid().map_or(0, |pid| pid.as_raw_nonzero().get());
    let program = Command::new("/bin/ps")
        .args(["-o", "comm=", "-p", &parent.to_string()])
        .stdin(Stdio::null())
        .output()
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
        return Answer::failed(
            NO_SUCH_DOMAIN,
            format!("Could not find domain for {target}\n"),
        );
    }
    if target == format!("user/{uid}") {
        return Answer::said(format!("{target} = {{\n\ttype = user\n}}\n"));
    }
    let Some((domain, label)) = split_target(target) else {
        return Answer::failed(
            NO_SUCH_DOMAIN,
            format!("Could not find domain for {target}\n"),
        );
    };
    if domain != format!("user/{uid}") && domain != format!("gui/{uid}") {
        return Answer::failed(
            NO_SUCH_DOMAIN,
            format!("Could not find domain for {domain}\n"),
        );
    }
    match context.job(label) {
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
    for pair in definition.arguments.windows(2) {
        if matches!(pair[0].as_str(), "--runtime-dir" | "--state-dir") {
            context.bounded(Path::new(&pair[1]))?;
        }
    }
    Ok(())
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
        return Answer::failed(
            NO_SUCH_DOMAIN,
            format!("Could not find domain for {domain}\n"),
        );
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
        pending: None,
    };
    match context.keep(&job) {
        Ok(()) => Answer::said(String::new()),
        Err(why) => Answer::refused(why),
    }
}

/// A fresh random token, as hexadecimal text.
fn nonce() -> String {
    let mut bytes = [0_u8; 16];
    let read = std::fs::File::open("/dev/urandom").and_then(|mut file| {
        use std::io::Read as _;
        file.read_exact(&mut bytes)
    });
    if read.is_err() {
        bytes = u128::from(std::process::id()).to_le_bytes();
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `kickstart -p`: starts the loaded job once as its definition says and prints the process; a job
/// that runs is not started again and its process is printed.
fn kickstart(context: &Context, target: &str) -> Answer {
    let Some((domain, label)) = split_target(target) else {
        return Answer::failed(
            NO_SUCH_DOMAIN,
            format!("Could not find domain for {target}\n"),
        );
    };
    let mut job = match context.job(label) {
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
    let token = nonce();
    job.pending = Some(token.clone());
    if let Err(why) = context.keep(&job) {
        return Answer::refused(why);
    }
    match start(context, &definition, label, &token) {
        Err(why) => Answer::refused(why),
        Ok((identity, keys)) => {
            let pid = identity.pid.get();
            job.identity = Some(identity);
            job.environment_keys = keys;
            job.starts += 1;
            job.pending = None;
            match context.keep(&job) {
                Ok(()) => Answer::said(format!("{pid}\n")),
                Err(why) => Answer::refused(why),
            }
        }
    }
}

/// Starts the daemon as `definition` says: its arguments, its directory, its mask, its log as both
/// outputs, no input, a session and a process group of its own, and exactly launchd's defaults for
/// the environment (the test's home and temporary directory, the system path), the definition's
/// own entries, the name of this program, and the token that ties the process to this start.
fn start(
    context: &Context,
    definition: &Definition,
    label: &str,
    token: &str,
) -> Result<(ProcessStartIdentity, Vec<String>), String> {
    // A session of its own, so that the daemon has no controlling terminal whatever started the
    // test; where this process already leads one, it already has none to give.
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
        (JOB_VARIABLE.to_owned(), format!("{label}/{token}").into()),
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
            // The process is this program's own child, so ending it needs no identity.
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "the process {} cannot be identified, and was ended: {error}",
                child.id()
            ));
        }
    };
    let mut keys: Vec<String> = environment.into_iter().map(|(name, _)| name).collect();
    keys.sort();
    Ok((identity, keys))
}

/// Waits for the process `identity` to end, for at most [`END_BOUND`].
fn ended_within(identity: &ProcessStartIdentity) -> bool {
    let deadline = Instant::now() + END_BOUND;
    while Instant::now() < deadline {
        if process_state(identity) == ProcessState::Ended {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    process_state(identity) == ProcessState::Ended
}

/// The processes of a start that was never recorded: those whose environment holds its token, which
/// is what a daemon holds once the wrapper that started it has run, and those whose command line
/// holds the arguments of the definition after its program, which are the paths of this test's own
/// tree and are what a process is still given while the platform's own shell reads the wrapper (an
/// environment that the system keeps from a program of its own is not shown).
fn found_unrecorded(label: &str, token: &str, arguments: &[String]) -> Vec<u32> {
    let needle = format!("{JOB_VARIABLE}={label}/{token}");
    let given = arguments.get(1..).unwrap_or_default().join(" ");
    let Ok(output) = Command::new("/bin/ps")
        // Twice `w`: a line is not cut at a width, and the environment is the end of it.
        .args(["-axEww", "-o", "pid=,command="])
        .stdin(Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains(&needle) || (!given.is_empty() && line.contains(&given)))
        .filter_map(|line| line.split_whitespace().next()?.parse().ok())
        .filter(|pid| *pid != std::process::id())
        .collect()
}

/// `bootout`: ends the daemon by the identity recorded for it, asking first and then making sure,
/// and unloads the job. A start that was not recorded is found by its token or its arguments. The identity is checked
/// by the signalling itself, so a number that belongs to another process now is left alone.
fn bootout(context: &Context, target: &str) -> Answer {
    let Some((_, label)) = split_target(target) else {
        return Answer::failed(
            NO_SUCH_DOMAIN,
            format!("Could not find domain for {target}\n"),
        );
    };
    let job = match context.job(label) {
        Err(why) => return Answer::refused(why),
        Ok(None) => {
            return Answer::failed(
                NOT_LOADED,
                format!("Could not find service \"{label}\" in domain for {target}\n"),
            );
        }
        Ok(Some(job)) => job,
    };
    let mut identities: Vec<ProcessStartIdentity> = job.identity.clone().into_iter().collect();
    if let Some(token) = &job.pending {
        for pid in found_unrecorded(label, token, &job.arguments) {
            if let Ok(identity) = started_process_identity(pid) {
                identities.push(identity);
            }
        }
    }
    for identity in &identities {
        if process_state(identity) != ProcessState::Running {
            continue;
        }
        let _ = stop_process(identity, Stop::Terminate);
        if !ended_within(identity) {
            let _ = stop_process(identity, Stop::Kill);
            if !ended_within(identity) {
                return Answer::failed(
                    REFUSED,
                    format!(
                        "the process {} did not end, and the job is kept\n",
                        identity.pid.get()
                    ),
                );
            }
        }
    }
    match std::fs::remove_file(context.job_path(label)) {
        Ok(()) => Answer::said(String::new()),
        Err(error) => Answer::refused(format!("the record of {label} cannot be removed: {error}")),
    }
}
