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
pub fn command_binaries() -> &'static Path {
    static COPIED: OnceLock<PathBuf> = OnceLock::new();
    COPIED.get_or_init(|| {
        let temporary = std::env::temp_dir();
        let root = temporary.join(this_runs_name());
        std::fs::create_dir(&root).expect("a directory of this run's own for the command binaries");
        take_it_away_when_this_run_ends(&root);
        // After this run's own directory exists, because a directory this run certainly made is
        // what says which user the sweep may act for.
        remove_what_earlier_runs_left(&temporary, &root);
        for source in [
            Path::new(env!("CARGO_BIN_EXE_kr")),
            Path::new(env!("CARGO_BIN_EXE_kr-attach-guard")),
        ] {
            let name = source.file_name().expect("the binary has a name");
            let destination = root.join(name);
            std::fs::copy(source, &destination).expect("copies a command binary");
            // Run it once, here, where nothing is being timed. The operating system checks a binary
            // it has not seen before on its first run and remembers it afterwards, and that check
            // takes seconds where the run itself takes milliseconds. A test that paid it inside a
            // wait would be measuring the check.
            let _ = std::process::Command::new(&destination)
                .arg("--version")
                .current_dir(&root)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        root
    })
}

/// What this run calls its directory: the suite, the process, and a token of this run's own.
///
/// The token is what makes the name this run's and no other's. A process number comes round again:
/// the operating system gives it to a later process, which would then want a name an earlier one
/// had already used, and a name two runs can both want is a name one of them can take away from
/// the other. The token is a reading of the clock that only ever goes forward, which separates runs
/// on one machine, and a value the standard library draws for this process from the operating
/// system, which separates the rest. A machine restarted between two runs begins that clock again,
/// and the drawn value is what makes the repetition harmless.
///
/// The number stays in the name because the sweep below reads it, and the suite's name stays in it
/// because a person looking at a temporary directory should be able to see which test made what.
fn this_runs_name() -> String {
    use std::hash::{BuildHasher, Hasher};

    let started = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let drawn = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    format!(
        "{PREFIX}{}-{}-{:x}{:x}{drawn:016x}",
        env!("CARGO_CRATE_NAME"),
        std::process::id(),
        started.tv_sec,
        started.tv_nsec,
    )
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
/// The end this run holds is kept for the life of the process on purpose, and every end this
/// process ever holds is kept: dropping one would be telling its watcher to remove a directory
/// these tests are still launching binaries from.
///
/// The removal follows the read rather than merely coming after it. A shell that could not run the
/// read at all, or whose read was ended by a signal, has learned nothing about this process, and a
/// watcher that has learned nothing leaves the directory for a later run to answer for. The path it
/// is given has to be there and has to say something: a removal is never asked for with an empty
/// or missing path, and the shell refuses to run one rather than working out what that would mean.
fn take_it_away_when_this_run_ends(root: &Path) {
    static HELD: Mutex<Vec<std::process::ChildStdin>> = Mutex::new(Vec::new());

    let Ok(mut watching) = std::process::Command::new("sh")
        .arg("-c")
        .arg(r#"cat >/dev/null && rm -rf -- "${1:?}""#)
        .arg("sh")
        .arg(root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        // Nothing to do about it here. The sweep below is what answers for a run whose ending
        // nothing watched.
        return;
    };
    if let Some(end) = watching.stdin.take() {
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
/// token of one run's own is a name no other run can ever produce, so a directory found under one
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
fn remove_what_earlier_runs_left(temporary: &Path, ours: &Path) {
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

/// Whether no process holds `number`.
///
/// `kill(number, 0)` sends nothing and answers with the kernel's own error, which is the only
/// thing that tells "no such process" apart from "that process is not yours to signal". A command
/// reports both as a failure, and reports a question it could not ask as one too, so the syscall
/// is what is asked. Anything but "no such process" is read as something holding the number, which
/// leaves the directory where it is.
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

/// The `kr` these tests launch.
pub fn kr() -> PathBuf {
    command_binaries().join("kr")
}

/// The restoration guard this test's `kr` launches, which is beside it.
pub fn kr_attach_guard() -> PathBuf {
    command_binaries().join("kr-attach-guard")
}
