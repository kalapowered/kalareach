//! What the command tests launch `kr` from.
//!
//! Three of these suites run the command as a real process on a real terminal, and all three need
//! the same thing: the command binaries somewhere the operating system will let a launched process
//! run them from.

// Each test binary compiles this module on its own and uses the part of it that it needs, so a
// helper another binary uses is dead code from this one's point of view.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// What every one of these directories is called, before what tells one run's from another's.
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
/// The directory belongs to this process, because two runs of two different builds sharing one
/// would each be launching the other's binaries. A directory named after a process nobody is
/// running was nobody's to remove, so each run of each of these suites left half a gigabyte of
/// copied binaries where it fell, and a machine that runs them all day filled its temporary
/// filesystem with them. A run still leaves its own behind - it is launching binaries out of it
/// until it ends, and a run that is killed never reaches its own end - so what changed is that
/// each run takes away the ones the runs before it left, at the one moment when whether they are
/// still in use can be asked rather than guessed.
pub fn command_binaries() -> &'static Path {
    static COPIED: OnceLock<PathBuf> = OnceLock::new();
    COPIED.get_or_init(|| {
        let temporary = std::env::temp_dir();
        let root = make_our_own(&temporary);
        // After this run's own directory exists, because a directory this run certainly made is
        // what says which user "ours" means below.
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

/// Makes this run's own directory under `temporary` and returns it.
///
/// Two things about the name. It is created rather than opened, so what comes back is a directory
/// this process made and therefore owns, which is what lets the sweep below decide whose a
/// directory is. And it carries the moment it was made as well as the number of the process that
/// made it, so no two runs of these suites ever want the same name - a number on its own comes
/// round again, and a sweep that had decided to remove the name a dead run left could otherwise
/// remove a live run that had since been given the same number and made the same name. The number
/// still ends the name, because that is the part the sweep reads.
///
/// # Panics
///
/// Panics when no directory can be made, which is not something these tests can go on without.
fn make_our_own(temporary: &Path) -> PathBuf {
    const ATTEMPTS: usize = 100;

    let pid = std::process::id();
    for _ in 0..ATTEMPTS {
        let made_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        let root = temporary.join(format!("{PREFIX}{made_at}-{pid}"));
        match std::fs::create_dir(&root) {
            Ok(()) => return root,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!(
                "a directory for the command binaries at {}: {error}",
                root.display()
            ),
        }
    }
    panic!(
        "a directory for the command binaries under {}",
        temporary.display()
    );
}

/// Removes the directories that earlier runs of these suites left in `temporary`, given `ours`,
/// the one this run made.
///
/// A candidate's name is the prefix above and then, at its end, the number of the process that made
/// it. Whether the name of a test binary or the moment of a run stands between the two makes no
/// difference: those are the forms this helper has used, and every directory left behind is in one
/// of them, so a sweep that knew only the newest form would tidy nothing that is actually there.
///
/// Four things are then established before anything is removed, and each of them answers a way
/// this could take away something it should not.
///
/// * It is a directory, read without following a symbolic link, and the user who owns it is the
///   user who owns `ours` - which is a directory this process made, so that user is this process's.
///   This is also what settles what a shared temporary directory's sticky bit would leave
///   half-done.
/// * It was last written to before `ours` was made. A directory that has been touched since this
///   run began is one something else is using, and this is what keeps a sweep from reaching a run
///   that took a name back while this one was deciding about it. Everything genuinely left behind
///   is older than this run.
/// * `ps` cannot find the number. That question is whether a process exists, not whether this one
///   may signal it.
/// * `kill -0` cannot signal the number. That question is the other one, and it is asked because
///   the first can answer no about a process that is plainly there: a `ps` that does not take
///   `-p`, one that was ended by a signal, a `/proc` mounted so that it shows fewer processes than
///   are running. Between them, a process this user is running is invisible to both only if it is
///   hidden and out of reach at once.
///
/// Both questions must be answered, and answered plainly: only an exit code of one counts, so a
/// question that could not be asked at all and a question whose asker was ended both leave the
/// directory where it is. A number since given to another process keeps a directory for as long as
/// that process lives, which on a machine that has been up for weeks can be a long time; that is
/// the safe direction to err in, and the directories it holds are the few whose numbers came round
/// again.
fn remove_what_earlier_runs_left(temporary: &Path, ours: &Path) {
    use std::os::unix::fs::MetadataExt;

    let Ok(us) = std::fs::metadata(ours) else {
        return;
    };
    let Ok(began) = us.modified() else {
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
        let Some(rest) = name.to_str().and_then(|name| name.strip_prefix(PREFIX)) else {
            continue;
        };
        let owner = rest.rsplit('-').next().unwrap_or_default();
        if owner.is_empty() || !owner.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let Ok(about) = entry.metadata() else {
            continue;
        };
        if !about.is_dir() || about.uid() != us.uid() {
            continue;
        }
        if !about.modified().is_ok_and(|written| written < began) {
            continue;
        }
        if !nothing_holds(owner) {
            continue;
        }
        let _ = std::fs::remove_dir_all(entry.path());
    }
}

/// Whether both of the questions above answer that no process holds `number`.
///
/// Each is put to a command, and only a plain exit code of one is taken for an answer: that is
/// `ps` finding nothing and `kill` refusing the number. Anything else - a command that could not
/// be started, one that was ended by a signal, any other exit - is not an answer, and one
/// unanswered question is enough to leave the directory alone.
fn nothing_holds(number: &str) -> bool {
    let asked = [vec!["-p", number, "-o", "pid="], vec!["-0", number]];
    for (command, arguments) in ["ps", "kill"].into_iter().zip(asked) {
        let Ok(answer) = std::process::Command::new(command)
            .args(arguments)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
        else {
            return false;
        };
        if answer.code() != Some(1) {
            return false;
        }
    }
    true
}

/// The `kr` these tests launch.
pub fn kr() -> PathBuf {
    command_binaries().join("kr")
}

/// The restoration guard this test's `kr` launches, which is beside it.
pub fn kr_attach_guard() -> PathBuf {
    command_binaries().join("kr-attach-guard")
}
