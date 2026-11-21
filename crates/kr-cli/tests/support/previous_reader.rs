//! One earlier release's release matrix reader: its tree extracted from the repository, the pin
//! replaced by a key a run made, the program built and run against a matrix.
//!
//! Declared by `release_candidate.rs` alone, so no other test target compiles it.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where a release's matrix client keeps the key it pins.
pub const MATRIX_SOURCE: &str = "crates/kr-client/src/services/matrix.rs";

/// The program's own crate, which a release that predates the program does not have.
pub const READER_CRATE: &str = "crates/kr-release-matrix-check";

/// The declaration of the pinned keys in the matrix client.
const PIN_DECLARATION: &str = "pub const PRODUCTION_PINS";

/// The text with the declaration of the pinned keys replaced by one that pins `key`, and nothing
/// else changed: the first revision a build reads stays what the release set it to.
///
/// The declaration has to appear exactly once, so a release that moved or doubled it is not read
/// with its own key left in.
pub fn replace_pins(source: &str, key: &str) -> Result<String, String> {
    let starts: Vec<usize> = source
        .match_indices(PIN_DECLARATION)
        .map(|(at, _)| at)
        .collect();
    let [start] = starts[..] else {
        return Err(format!(
            "the pin declaration appears {} times in the matrix client, not once",
            starts.len()
        ));
    };
    // The type holds a semicolon of its own (`[&str; 1]`), so the statement ends at the first one
    // after its `=`.
    let equals = source[start..]
        .find('=')
        .map(|at| start + at)
        .ok_or("the pin declaration has no value")?;
    let end = source[equals..]
        .find(';')
        .map(|at| equals + at + 1)
        .ok_or("the pin declaration does not end")?;
    Ok(format!(
        "{}{PIN_DECLARATION}: [&str; 1] = [\"{key}\"];{}",
        &source[..start],
        &source[end..]
    ))
}

/// The lock on the cache, taken for one run at a time and held until the guard is dropped.
pub struct CacheGuard {
    file: File,
}

impl CacheGuard {
    /// Takes the cache, or says it is in use. It does not wait: a second run would block until the
    /// first ended.
    pub fn take(cache: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(cache).map_err(|error| format!("{}: {error}", cache.display()))?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(cache.join(".lock"))
            .map_err(|error| format!("the cache's lock: {error}"))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(format!(
                "The core readers' cache {} is in use by another run. Wait for that run to end, then run the readers again.",
                cache.display()
            )),
            Err(std::fs::TryLockError::Error(error)) => {
                Err(format!("the cache's lock could not be taken: {error}"))
            }
        }
    }

    /// The locked file, for a case that gives a child process a copy of the descriptor.
    pub const fn handle(&self) -> &File {
        &self.file
    }
}

impl Drop for CacheGuard {
    /// Releases the lock explicitly. A lock belongs to the open file, so a program started while
    /// the guard was held keeps it until it exits when the descriptor is only closed here.
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Whether `name` is the name of a folder this producer makes in the cache: a commit's, in 40
/// hexadecimal digits. The cache may be a folder a person named, so nothing else in it is ours.
pub fn is_a_commit_name(name: &str) -> bool {
    name.len() == 40 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The output of `git -C <repository> <arguments>`, or what it said when it failed.
pub fn git(repository: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|error| format!("git did not start: {error}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "git {} said {}: {}",
            arguments.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Whether the commit holds the release matrix program. The commit is verified and its tree is
/// read before an absent crate counts as no reader, so a commit this checkout does not hold, or a
/// tree that cannot be read, is a refusal and never a release that has no reader.
pub fn has_reader(repository: &Path, commit: &str) -> Result<bool, String> {
    git(
        repository,
        &["cat-file", "-e", &format!("{commit}^{{commit}}")],
    )
    .map_err(|why| {
        if why.starts_with("git did not start") {
            why
        } else {
            format!(
                "The commit {commit} is not in this checkout. Fetch it, then run the readers again."
            )
        }
    })?;
    let listed = git(
        repository,
        &[
            "ls-tree",
            "--name-only",
            commit,
            "--",
            &format!("{READER_CRATE}/Cargo.toml"),
        ],
    )?;
    Ok(!listed.trim().is_empty())
}

/// The commit's tree as the repository holds it, extracted once under the cache and kept
/// unpatched: a stamp is written last, so an extraction that did not finish is made again.
pub fn extract(repository: &Path, commit: &str, cache: &Path) -> Result<PathBuf, String> {
    if !is_a_commit_name(commit) {
        return Err(format!("{commit} is not a commit's 40 hexadecimal digits"));
    }
    let place = cache.join(commit);
    let tree = place.join("tree");
    if std::fs::read_to_string(place.join("stamp")).is_ok_and(|kept| kept == commit) {
        return Ok(tree);
    }
    if place.exists() {
        std::fs::remove_dir_all(&place).map_err(|error| format!("{}: {error}", place.display()))?;
    }
    std::fs::create_dir_all(&tree).map_err(|error| format!("{}: {error}", tree.display()))?;
    let mut archive = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["archive", "--format=tar", commit])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("git archive did not start: {error}"))?;
    let stdout = archive.stdout.take().ok_or("git archive gave no output")?;
    tar::Archive::new(stdout)
        .unpack(&tree)
        .map_err(|error| format!("the tree of {commit} is not unpacked: {error}"))?;
    let status = archive
        .wait()
        .map_err(|error| format!("git archive did not end: {error}"))?;
    if !status.success() {
        return Err(format!("git archive {commit} said {status}"));
    }
    std::fs::write(place.join("stamp"), commit).map_err(|error| format!("the stamp: {error}"))?;
    Ok(tree)
}

/// Writes the commit's matrix client into `tree` with `key` as its one pin. The text is the
/// repository's, not the tree's, so no run depends on what an earlier run left.
pub fn write_patched(
    repository: &Path,
    commit: &str,
    tree: &Path,
    key: &str,
) -> Result<(), String> {
    let source = git(repository, &["show", &format!("{commit}:{MATRIX_SOURCE}")])?;
    let patched = replace_pins(&source, key).map_err(|why| format!("{commit}: {why}"))?;
    std::fs::write(tree.join(MATRIX_SOURCE), patched)
        .map_err(|error| format!("the patched matrix client: {error}"))
}

/// What a build step is given: the tree to build, the target directory it keeps, the commit.
pub struct Job<'a> {
    /// The commit's tree, its matrix client already patched.
    pub tree: &'a Path,
    /// The release's own target directory, kept between runs.
    pub target: &'a Path,
    /// The commit.
    pub commit: &'a str,
}

/// A build step: the path of the program built.
pub type Build<'a> = dyn Fn(&Job) -> Result<PathBuf, String> + 'a;

/// The program's build by cargo, as the real run makes it.
///
/// The environment is this process's without what a test run sets for this tree, so the older tree
/// builds with its own settings and the toolchain it pins.
pub fn cargo_build(job: &Job) -> Result<PathBuf, String> {
    let carried = ["CARGO_HOME", "CARGO_NET", "CARGO_HTTP", "CARGO_REGISTR"];
    let status = Command::new("cargo")
        .current_dir(job.tree)
        .env_clear()
        .envs(std::env::vars_os().filter(|(name, _)| {
            let name = name.to_string_lossy();
            (!name.starts_with("CARGO") || carried.iter().any(|kept| name.starts_with(kept)))
                && !["RUSTFLAGS", "RUSTUP_TOOLCHAIN", "RUSTC_WRAPPER"].contains(&&*name)
        }))
        .env("CARGO_TARGET_DIR", job.target)
        .args(["build", "--locked", "-p", "kr-release-matrix-check"])
        .status()
        .map_err(|error| format!("cargo did not start: {error}"))?;
    if !status.success() {
        return Err(format!("cargo build of {} said {status}", job.commit));
    }
    Ok(job.target.join("debug/kr-release-matrix-check"))
}

/// What one reader answered.
pub struct Reading {
    /// The package version the program says it reads for.
    pub version: String,
    /// The revision it read.
    pub revision: String,
    /// `compatible`, `later` or `unsupported`.
    pub verdict: &'static str,
}

/// The program's answer as the verdict it states, from its exit status and its output. Any other
/// answer is not a verdict.
pub fn read_answer(code: Option<i32>, stdout: &str) -> Result<Reading, String> {
    // The three lines the program prints, each with the exit status it goes with: the version it
    // reads for, the text between that and the revision, and the verdict the line states.
    const LINES: [(i32, &str, &str, &str, &str); 3] = [
        (
            0,
            "release ",
            ": served by the compatible tier of the release matrix, revision ",
            "compatible",
            "",
        ),
        (
            0,
            "::warning::release ",
            " is served only by a later tier of the release matrix, revision ",
            "later",
            ":",
        ),
        (
            1,
            "::error::release ",
            " is in no tier of the release matrix at revision ",
            "unsupported",
            ":",
        ),
    ];
    for line in stdout.lines() {
        for (status, prefix, middle, verdict, end) in LINES {
            if code == Some(status)
                && let Some(rest) = line.strip_prefix(prefix)
                && let Some((version, tail)) = rest.split_once(middle)
            {
                let revision = if end.is_empty() {
                    tail
                } else {
                    tail.split(end).next().unwrap_or("")
                };
                return Ok(Reading {
                    version: version.to_owned(),
                    revision: revision.trim().to_owned(),
                    verdict,
                });
            }
        }
    }
    let first = stdout.lines().next().unwrap_or("it printed nothing");
    Err(format!("it exited with {code:?}: {first}"))
}

/// Runs a reader program with `--origin`, and returns its exit status and its output.
pub fn run_program(program: &Path, origin: &str) -> Result<(Option<i32>, String), String> {
    let output = Command::new(program)
        .args(["--origin", origin])
        .env_clear()
        .output()
        .map_err(|error| format!("{} did not start: {error}", program.display()))?;
    Ok((
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    ))
}
