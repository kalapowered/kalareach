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

/// What every one of these directories is called, before the process that owns it.
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
        let root = temporary.join(format!("{PREFIX}{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("a directory for the command binaries");
        // After this run's own directory exists, because it is what says who "ours" is.
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

/// Removes the directories that earlier runs of these suites left in `temporary`, given `ours`,
/// the one this run made.
///
/// A directory is one of ours if it is a directory, if the user who owns it is the user who owns
/// `ours`, and if its name is the prefix above followed by the number of the process that made it.
/// Whether the name of a test binary stands between the two makes no difference: that is the form
/// each suite used while it kept a copy of this helper of its own, and it is the form of every
/// directory those runs left behind, so a run that swept only its own form would tidy nothing that
/// is actually there.
///
/// The three conditions are what make a removal safe rather than merely likely. The owner decides
/// what `kill -0` means: for a process of one's own user it answers yes while the process lives
/// and no once it is gone, where for somebody else's it can also answer no because the question
/// was not ours to ask. A question that could not be put at all - `kill` missing, a process table
/// that cannot be read - is not an answer either, and leaves the directory alone. Confining the
/// sweep to one user's own directories also settles what a shared temporary directory's sticky bit
/// would otherwise leave half-done.
///
/// Whether the owner is running is asked of the operating system rather than assumed from an age:
/// a suite of these can take minutes, and a directory whose owner is still launching binaries out
/// of it is not one to take away. The cost of asking is that a number the operating system has
/// since given to some other process keeps a directory for as long as that process lives, which on
/// a machine that has been up for weeks can be a long time; it is the safe direction to err in,
/// and the directories it holds are the few whose numbers came round again.
fn remove_what_earlier_runs_left(temporary: &Path, ours: &Path) {
    use std::os::unix::fs::MetadataExt;

    let Ok(mine) = std::fs::metadata(ours).map(|data| data.uid()) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(temporary) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(rest) = name.to_str().and_then(|name| name.strip_prefix(PREFIX)) else {
            continue;
        };
        let owner = rest.rsplit('-').next().unwrap_or_default();
        if owner.is_empty() || !owner.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        // Not followed through a symbolic link, and not somebody else's.
        let Ok(about) = entry.metadata() else {
            continue;
        };
        if !about.is_dir() || about.uid() != mine {
            continue;
        }
        let Ok(answer) = std::process::Command::new("kill")
            .arg("-0")
            .arg(owner)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
        else {
            continue;
        };
        if !answer.success() {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// The `kr` these tests launch.
pub fn kr() -> PathBuf {
    command_binaries().join("kr")
}

/// The restoration guard this test's `kr` launches, which is beside it.
pub fn kr_attach_guard() -> PathBuf {
    command_binaries().join("kr-attach-guard")
}
