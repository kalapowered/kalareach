//! What the command tests launch `kr` from.
//!
//! Three of these suites run the command as a real process on a real terminal, and all three need
//! the same thing: the command binaries somewhere the operating system will let a launched process
//! run them from.

// Each test binary compiles this module on its own and uses the part of it that it needs, so a
// helper another binary uses is dead code from this one's point of view.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};
#[cfg(unix)]
use std::time::Duration;

/// What every one of these directories is called, before what tells one run's from every other's.
const PREFIX: &str = "kalareach-command-tests-";

/// The command binaries, on the internal disk.
///
/// The build directory is on the external volume this workspace lives on, and a process a test
/// launches is its own privacy identity to the operating system: a binary run from there makes
/// macOS ask whether it may read that volume, and the launch waits on the answer. Nothing a test
/// waits for arrives while that is on screen. So the binaries are copied to a directory the
/// operating system does not guard, and every test launches them from there. Both are copied
/// together and keep their names, because `kr` looks for its restoration guard beside itself.
///
/// The directory belongs to this run alone, and it goes when this run does. Half a gigabyte of
/// copied binaries left behind by every run of every one of these suites is what filled a build
/// machine's temporary filesystem, and a directory nobody owns any more is nobody's to remove.
/// What owns this one is the process that made it, for exactly as long as it is running.
///
/// On Unix the directory is named once, with every link in it resolved, because a test compares
/// these paths with what the system says about a process started from them. macOS reaches the
/// per-user temporary directory through `/var`, a link to `/private/var`, and names a program run
/// from `/var/...` as `/private/var/...` in the image the program reads about itself. A command
/// builds the path of a program it starts beside itself from that image, so the process it starts
/// is listed under the resolved form, never with the link left in. On Windows a program reads its
/// image as it always has, so the directory stays as the system gave it.
pub fn command_binaries() -> &'static Path {
    static COPIED: OnceLock<PathBuf> = OnceLock::new();
    COPIED.get_or_init(|| {
        let temporary = std::env::temp_dir();
        #[cfg(unix)]
        let temporary = std::fs::canonicalize(&temporary)
            .expect("the temporary directory is there and resolves");
        let root = temporary.join(this_runs_name());
        std::fs::create_dir(&root).expect("a directory of this run's own for the command binaries");
        take_it_away_when_this_run_ends(&root);
        // After this run's own directory exists, because a directory this run certainly made is
        // what says which user the sweep may act for.
        #[cfg(unix)]
        remove_what_earlier_runs_left(&temporary, &root);
        for source in [
            Path::new(env!("CARGO_BIN_EXE_kr")),
            Path::new(env!("CARGO_BIN_EXE_kr-attach-guard")),
        ] {
            let name = source.file_name().expect("the binary has a name");
            // Run once, here, where nothing is being timed. The operating system checks each newly
            // written executable on its first run, and that check takes seconds where the run
            // itself takes milliseconds. A test that paid it inside a wait would be measuring the
            // check.
            kr_ipc::testing::place_and_start_once(source, &root.join(name), &["--version"]);
        }
        root
    })
}

/// What this run calls its directory: the suite, the process, and a token of this run's own.
///
/// The token keeps a later run from wanting an earlier run's name. A process number comes round
/// again: the operating system gives it to a later process, which would then want a name an earlier
/// one had already used, and a name two runs can both want is a name one of them can take away from
/// the other. The token is the time the name is made, in nanoseconds on the system clock every
/// platform has, and a value the standard library draws for this process from the operating system.
/// Neither is certain to differ between two runs: a clock can tick more coarsely than a nanosecond
/// or be set back, and a drawn value can repeat. Both repeating along with the process number is
/// too unlikely to plan for, and even then nothing is shared: `create_dir` refuses a name that is
/// already there, and the test that asked for the directory fails.
///
/// The number stays in the name because the sweep below reads it, and the suite's name stays in it
/// because a person looking at a temporary directory should be able to see which test made what.
fn this_runs_name() -> String {
    use std::hash::{BuildHasher, Hasher};

    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let drawn = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    format!(
        "{PREFIX}{}-{}-{:x}{drawn:016x}",
        env!("CARGO_CRATE_NAME"),
        std::process::id(),
        started.as_nanos(),
    )
}

/// A shell function that ends every process running a program from inside the directory it is
/// given, and returns when none is left.
///
/// What a run launches from its directory is its own: the directory's name carries a token no other
/// run has. The processes are asked to end, given up to ten seconds to, and then killed. A worker
/// is detached from the test that had its session made and from the daemon that started it, so
/// nothing ends it but a session's closure, and a run that ended before its sessions were closed
/// leaves it running its shell until the machine restarts.
///
/// A process runs a program from inside the directory when the command `ps` lists for it begins
/// with the directory's path and a slash. The whole command is compared, so a path with spaces in
/// it matches as any other does, and the directory reaches `awk` through the environment, which
/// reads no escape sequence in it. What is killed is listed again just before it is, so a number
/// that was a worker's and has been given to another process in the meantime is not signalled for
/// a list that is older than the signal.
const END_WHAT_RUNS_FROM: &str = r#"
running_from() {
  /bin/ps axww -o pid=,command= | KR_DIR="$1" /usr/bin/awk '
    BEGIN { dir = ENVIRON["KR_DIR"] "/" }
    { pid = $1; sub(/^ *[0-9]+ +/, ""); if (index($0, dir) == 1) print pid }'
}
end_what_runs_from() {
  pids=$(running_from "$1")
  [ -n "$pids" ] || return 0
  kill $pids 2>/dev/null
  tries=0
  while [ "$tries" -lt 100 ]; do
    pids=$(running_from "$1")
    [ -n "$pids" ] || return 0
    tries=$((tries + 1))
    sleep 0.1
  done
  pids=$(running_from "$1")
  [ -z "$pids" ] || kill -9 $pids 2>/dev/null
  return 0
}
"#;

/// Starts the watcher of `root`, and returns the end of the pipe it reads: when that end closes, the
/// watcher ends what runs from `root` and removes it.
///
/// It is in a process group of its own, so that a harness that ends a run by ending the group it
/// started does not end the watcher with it.
pub fn watch(root: &Path) -> Option<std::process::ChildStdin> {
    let mut command = std::process::Command::new("sh");
    command
        .arg("-c")
        .arg(format!(
            "{END_WHAT_RUNS_FROM}\ncat >/dev/null && end_what_runs_from \"${{1:?}}\" && rm -rf -- \"${{1:?}}\""
        ))
        .arg("sh")
        .arg(root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        command.process_group(0);
    }
    command.spawn().ok()?.stdin.take()
}

/// Arranges for `root` to be taken away when this process ends, however it ends.
///
/// A run cannot remove its own directory on the way out: it is launching binaries out of it until
/// it ends, the harness that runs these tests ends the process itself rather than returning
/// through anything this module could hook, and a run that is killed reaches no ending of its own
/// at all. So the ending is watched from outside. A small process is started that reads from a
/// pipe this one holds the other end of and does nothing else; when this process ends, every
/// descriptor it held closes, the read reaches its end, and the directory goes. That is true of
/// every way a process can end, including being killed, and it does not depend on recognising this
/// process afterwards by a number that may by then belong to something else.
///
/// What still runs from the directory goes first, because it is a worker the run started: see
/// [`END_WHAT_RUNS_FROM`].
///
/// The end this run holds is kept for the life of the process on purpose, and every end this
/// process ever holds is kept: dropping one would be telling its watcher to remove a directory
/// these tests are still launching binaries from.
///
/// The removal follows the read rather than merely coming after it. A shell that could not run the
/// read at all, or whose read was ended by a signal, has learned nothing about this process, and a
/// watcher that has learned nothing leaves the directory for a later run to answer for. The path it
/// is given has to be there and has to say something: a removal is never asked for with an empty
/// or missing path, and the shell refuses to run one rather than working out what that would mean.
///
/// The watcher is a POSIX shell found on `PATH` on every platform. On Windows that is the one Git
/// for Windows installs, which the CI runner has on `PATH`; a Windows machine without one on `PATH`
/// keeps each run's directory in its own temporary directory, because the sweep below is Unix only.
fn take_it_away_when_this_run_ends(root: &Path) {
    static HELD: Mutex<Vec<std::process::ChildStdin>> = Mutex::new(Vec::new());

    // Nothing to do about a watcher that did not start. On Unix the sweep below is what answers for
    // a run whose ending nothing watched.
    if let Some(end) = watch(root) {
        HELD.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(end);
    }
}

/// Removes what runs whose ending nothing watched left behind in `temporary`, given `ours`, the
/// directory this run made.
///
/// Only names of the form above are considered, and nothing else in the temporary directory is
/// touched. That is what makes this safe to do while other runs are going on: a name carrying a
/// run's token belongs to the one run whose `create_dir` made it, so a directory found under one
/// either belongs to a run that is still going - and is left alone - or to one that has ended. The
/// directories that earlier versions of these suites left under a name of a process number alone
/// are not this sweep's to judge, because a number comes round again and a name two runs can both
/// want is one this could take from under a living run.
///
/// Two things are established before anything is removed.
///
/// * It is a directory, read without following a symbolic link, and the user who owns it is the
///   user who owns `ours` - which is a directory this process made, so that user is this
///   process's. This also settles what a shared temporary directory's sticky bit would leave
///   half-done.
/// * No process holds the number in its name. The question goes to the kernel rather than to a
///   command, because what has to be told apart is "no such process" from "that process is not
///   yours to signal", and a command reports both as a failure.
///
/// Unix only. Both questions are Unix ones, an owner's user number and a signal, and their Windows
/// counterparts are calls into the operating system that this crate's tests do not make.
#[cfg(unix)]
pub fn remove_what_earlier_runs_left(temporary: &Path, ours: &Path) {
    use std::os::unix::fs::MetadataExt;

    let Ok(us) = std::fs::metadata(ours) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(temporary) else {
        return;
    };
    for entry in entries.flatten() {
        // Never the one this run is about to launch binaries out of.
        if entry.path() == ours {
            continue;
        }
        let name = entry.file_name();
        let Some(owner) = name.to_str().and_then(one_of_ours) else {
            continue;
        };
        let Ok(about) = entry.metadata() else {
            continue;
        };
        if !about.is_dir() || about.uid() != us.uid() {
            continue;
        }
        if !nothing_holds(owner) {
            continue;
        }
        // What an ended run launched is its own, and a worker among it outlives the run that
        // started it.
        end_what_runs_from(&entry.path());
        let _ = std::fs::remove_dir_all(entry.path());
    }
}

/// The process number in `name`, when `name` is one of the directories this module makes.
///
/// It is the prefix, then a suite, then a number, then a token: four parts, and the last two are
/// what this reads. A name of fewer parts is one an earlier version of these suites made and is
/// not answered for here, and neither is one whose number or token is not what it should be.
fn one_of_ours(name: &str) -> Option<i32> {
    let rest = name.strip_prefix(PREFIX)?;
    let mut parts = rest.rsplitn(3, '-');
    let token = parts.next()?;
    let number = parts.next()?;
    let suite = parts.next()?;
    let known = !suite.is_empty()
        && token.len() >= 16
        && token.bytes().all(|byte| byte.is_ascii_hexdigit());
    known.then(|| number.parse().ok())?
}

/// Ends what runs a program from inside `directory`, and returns when none is left.
#[cfg(unix)]
pub fn end_what_runs_from(directory: &Path) {
    let _ = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "{END_WHAT_RUNS_FROM}\nend_what_runs_from \"${{1:?}}\""
        ))
        .arg("sh")
        .arg(directory)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Whether no process holds `number`.
///
/// `kill(number, 0)` sends nothing and answers with the kernel's own error, which is the only
/// thing that tells "no such process" apart from "that process is not yours to signal". A command
/// reports both as a failure, and reports a question it could not ask as one too, so the syscall
/// is what is asked. Anything but "no such process" is read as something holding the number, which
/// leaves the directory where it is.
#[cfg(unix)]
fn nothing_holds(number: i32) -> bool {
    let Some(pid) = rustix::process::Pid::from_raw(number) else {
        // Not a number any process can hold, and not one this module ever wrote.
        return false;
    };
    matches!(
        rustix::process::test_kill_process(pid),
        Err(rustix::io::Errno::SRCH)
    )
}

/// How long the workers of a host are given to end by themselves once its sessions are closed.
///
/// A worker ends as soon as its session's closure is done, which takes the closure's own grace and
/// drain and a margin for a busy machine, so a wait for it ends the moment the last one has. The
/// bound only says that a worker which is still there after it is not going to end.
#[cfg(unix)]
const WORKERS_END_WITHIN: Duration = Duration::from_secs(120);

/// A worker process of a host tree, as `ps` lists it.
#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Worker {
    pub pid: i32,
    pub command: String,
}

/// A process as `ps` lists it: its number and the time it started, which together name one process
/// for as long as the system does not give the number to another one that starts in the same
/// second.
#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub pid: i32,
    pub started: String,
}

/// Reads the number and the start time from the front of a `ps` line, and returns them with the
/// rest of the line: `ps -o pid=,lstart=,...` gives the number, then the start as five words (the
/// weekday, the month, the day, the time and the year), then what was asked for after them.
#[cfg(unix)]
fn listed_front(line: &str) -> Option<(Listed, &str)> {
    let mut rest = line.trim_start();
    let (pid, after) = rest.split_once(char::is_whitespace)?;
    rest = after.trim_start();
    let mut started = Vec::new();
    for _ in 0..5 {
        let (word, after) = rest.split_once(char::is_whitespace)?;
        started.push(word);
        rest = after.trim_start();
    }
    Some((
        Listed {
            pid: pid.parse().ok()?,
            started: started.join(" "),
        },
        rest,
    ))
}

/// The processes `listing`, which is `ps axww -o pid=,lstart=,stat=,comm=`, shows running with a
/// program called `kr-worker`.
///
/// `comm` is the program alone, which is what tells it from its arguments: the path of the program
/// where the system gives one (macOS, with any spaces in it), and its name where it gives only that
/// (Linux). It is the rest of the line after the number, the start and the state, so nothing about
/// it is guessed from where an argument seems to begin. A process that has ended and has not been
/// waited for is listed, with a state that begins with `Z`, and is not a process that runs.
#[cfg(unix)]
pub fn worker_programs_in(listing: &str) -> Vec<Listed> {
    listing
        .lines()
        .filter_map(|line| {
            let (listed, rest) = listed_front(line)?;
            let (state, program) = rest.split_once(char::is_whitespace)?;
            let named = Path::new(program.trim())
                .file_name()
                .is_some_and(|name| name == "kr-worker");
            (named && !state.starts_with('Z')).then_some(listed)
        })
        .collect()
}

/// What the processes in `listing`, which is `ps -ww -o pid=,lstart=,args=`, were started with,
/// each with the number and the start time it was listed under.
#[cfg(unix)]
pub fn arguments_in(listing: &str) -> Vec<(Listed, String)> {
    listing
        .lines()
        .filter_map(|line| {
            let (listed, arguments) = listed_front(line)?;
            Some((listed, arguments.trim_end().to_owned()))
        })
        .collect()
}

/// Whether the arguments of a process, as `ps -o args=` lists them, name the host tree called
/// `host`: its runtime and state directories are inside it, and its name is a token of its own that
/// no other host has.
#[cfg(unix)]
pub fn names_host(arguments: &str, host: &str) -> bool {
    arguments.contains(&format!("/{host}/"))
}

/// The workers among `programs` whose arguments, in `arguments`, name the host tree called `host`.
///
/// What a process was started with is asked in a second listing, so a number that was a worker's
/// when the first was made and is another process's when the second is must not carry the worker's
/// program over to the other's arguments: a process is a worker only when the number and the start
/// time are the same in both.
#[cfg(unix)]
pub fn workers_among(
    programs: &[Listed],
    arguments: &[(Listed, String)],
    host: &str,
) -> Vec<Worker> {
    programs
        .iter()
        .filter_map(|program| {
            let (_, command) = arguments.iter().find(|(listed, _)| listed == program)?;
            names_host(command, host).then(|| Worker {
                pid: program.pid,
                command: command.clone(),
            })
        })
        .collect()
}

/// Runs `ps` with `arguments`, and says what it wrote.
///
/// `ps` ends with 0 when it listed a process, and with 1 when it kept none: no number it was asked
/// about has a process, or it failed, and its status does not say which. So only 0 is an answer,
/// and every listing here is made to list at least one process (`ax` lists `ps` itself, and a list
/// of numbers has this process's own among them), which makes any other status a failure to list,
/// returned with what `ps` said, so that a worker is never taken to be gone because `ps` did not
/// answer. The time is written by the C locale on both systems: macOS formats it in the caller's
/// own locale, which does not always give five words.
#[cfg(unix)]
fn ps(arguments: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("/bin/ps")
        .args(arguments)
        .env("LC_ALL", "C")
        .output()
        .map_err(|error| format!("ps could not be run: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "ps ended with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The workers of the host tree at `root` that are running now.
///
/// # Errors
///
/// Returns why the processes could not be listed.
#[cfg(unix)]
pub fn workers_of(root: &Path) -> Result<Vec<Worker>, String> {
    let host = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} does not end in a name", root.display()))?;
    let programs = worker_programs_in(&ps(&["axww", "-o", "pid=,lstart=,stat=,comm="])?);
    if programs.is_empty() {
        return Ok(Vec::new());
    }
    // This process's own number is in the list so that `ps` always has one to list: it ends with 1
    // when it has none, which a candidate that ended since the first listing would otherwise cause.
    let numbers = programs
        .iter()
        .map(|listed| listed.pid)
        .chain(std::iter::once(
            i32::try_from(std::process::id()).map_err(|error| error.to_string())?,
        ))
        .map(|pid| pid.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let arguments = arguments_in(&ps(&["-ww", "-o", "pid=,lstart=,args=", "-p", &numbers])?);
    Ok(workers_among(&programs, &arguments, host))
}

/// Waits until no worker of the host tree at `root` runs, and ends any that goes on running past
/// [`WORKERS_END_WITHIN`], so that none can outlive the test that started it.
///
/// A host closes the sessions it created, and each worker ends with its session. A worker that did
/// not, because a close was refused, a daemon had stopped, or a session was made that the test did
/// not record, is not a worker anything will close later: it is detached from the test and from its
/// daemon, and runs its shell until the machine restarts. A host asks this when it ends, with its
/// daemon no longer serving, so nothing starts one after the look.
///
/// # Errors
///
/// Returns the workers that were still running and are now ended by force, or why the processes
/// could not be listed. A worker is never left running without this saying so.
#[cfg(unix)]
pub fn leave_no_worker_of(root: &Path) -> Result<(), String> {
    leave_no_worker_of_within(root, WORKERS_END_WITHIN)
}

/// [`leave_no_worker_of`] with the time the workers are given to end by themselves stated.
///
/// # Errors
///
/// As [`leave_no_worker_of`].
#[cfg(unix)]
pub fn leave_no_worker_of_within(root: &Path, within: Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + within;
    let mut left = workers_of(root)?;
    while !left.is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        left = workers_of(root)?;
    }
    if left.is_empty() {
        return Ok(());
    }
    for worker in &left {
        // The number comes from the two listings made just before the check that found it, with no
        // wait between them and the signal, and was kept only where its start time was the same in
        // both. That protects the pairing of the two listings, not the signal: a worker that ends
        // after the second listing and before the signal could have its number given to any
        // process, whatever its start time, and that process would be signalled. The system gives
        // numbers out in turn and does not promise against it, so the window is made as short as
        // two `ps` runs allow, and is not nothing.
        if let Some(pid) = rustix::process::Pid::from_raw(worker.pid) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
    }
    Err(format!(
        "{} workers of {} were still running {within:?} after the sessions were closed, and were \
         ended by force: {}",
        left.len(),
        root.display(),
        left.iter()
            .map(|worker| format!("{} ({})", worker.pid, worker.command))
            .collect::<Vec<_>>()
            .join("; ")
    ))
}

/// The `kr` these tests launch.
pub fn kr() -> PathBuf {
    command_binaries().join(format!("kr{}", std::env::consts::EXE_SUFFIX))
}

/// The restoration guard this test's `kr` launches, which is beside it.
pub fn kr_attach_guard() -> PathBuf {
    command_binaries().join(format!("kr-attach-guard{}", std::env::consts::EXE_SUFFIX))
}
