//! KR-REQ-27.03: the readers of `KR_TEST_ARTIFACTS_DIR` for shell and for PowerShell.
//!
//! Section 27 puts every screenshot and evidence file of a release run in one directory, set under
//! a temporary folder for the build. Each language reads the variable only through its one reader,
//! and the reader refuses a value outside the platform's temporary roots where the value is used.
//! Each case here runs the real reader in a real shell, with the variable set in the environment
//! the way a build sets it, and asserts what the reader answers: the same cases for both readers.
//! (The Rust reader's and the TypeScript reader's cases are in their own packages, and the source
//! case in `ci_evidence.rs` holds that nothing reads the variable beside the readers.)

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

const VARIABLE: &str = "KR_TEST_ARTIFACTS_DIR";

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the repository")
        .to_owned()
}

/// What a reader answered for one environment.
#[derive(Debug)]
struct Reading {
    succeeded: bool,
    /// The directory the reader named.
    directory: Option<PathBuf>,
    /// What `KR_TEST_ARTIFACTS_DIR` was once the reader had run.
    exported: Option<PathBuf>,
    /// Everything the reader said on its error stream.
    words: String,
}

#[derive(Clone, Copy, Debug)]
enum Reader {
    Shell,
    PowerShell,
}

/// The program that runs PowerShell here, or `None` where none is installed and the run is not a
/// hosted one. A hosted run has PowerShell on every platform, so there its absence fails.
fn powershell() -> Option<&'static str> {
    let candidates: &[&str] = if cfg!(windows) {
        &["pwsh", "powershell"]
    } else {
        &["pwsh"]
    };
    for candidate in candidates {
        let ran = Command::new(candidate)
            .args(["-NoProfile", "-Command", "exit 0"])
            .output();
        if ran.is_ok_and(|output| output.status.success()) {
            return Some(candidate);
        }
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "a hosted run has PowerShell, and none was found"
    );
    eprintln!("no PowerShell is installed here: its reader's cases are not run");
    None
}

fn readers() -> Vec<Reader> {
    let mut readers = Vec::new();
    if cfg!(unix) {
        readers.push(Reader::Shell);
    }
    if powershell().is_some() {
        readers.push(Reader::PowerShell);
    }
    readers
}

impl Reader {
    /// Runs the reader with `value` as the variable (or with none) and `temporary` as the
    /// temporary folder (or the machine's own).
    fn read(self, value: Option<&OsStr>, temporary: Option<&Path>) -> Reading {
        self.read_in(value, temporary, None)
    }

    /// As [`Reader::read`], with `directory` as the reader's working directory.
    fn read_in(
        self,
        value: Option<&OsStr>,
        temporary: Option<&Path>,
        directory: Option<&Path>,
    ) -> Reading {
        let root = repository();
        let mut run = match self {
            Reader::Shell => {
                let mut run = Command::new("bash");
                run.args([
                    "-c",
                    r#". "$1"
                    kr_artifacts_dir
                    printf 'directory=%s\nexported=%s\n' "$kr_artifacts" "$KR_TEST_ARTIFACTS_DIR""#,
                    "bash",
                ])
                .arg(root.join("scripts").join("lib").join("artifacts-dir.sh"));
                run
            }
            Reader::PowerShell => {
                let mut run = Command::new(powershell().expect("PowerShell is installed"));
                run.args([
                    "-NoProfile",
                    "-Command",
                    r#"$ErrorView = 'NormalView'
                    $directory = & $env:KR_READER_SCRIPT
                    "directory=$directory"
                    "exported=$env:KR_TEST_ARTIFACTS_DIR""#,
                ])
                .env(
                    "KR_READER_SCRIPT",
                    root.join("scripts").join("artifacts-dir.ps1"),
                );
                run
            }
        };
        run.env_remove(VARIABLE).env("NO_COLOR", "1");
        if let Some(directory) = directory {
            run.current_dir(directory);
        }
        if let Some(value) = value {
            run.env(VARIABLE, value);
        }
        if let Some(temporary) = temporary {
            run.env("TMPDIR", temporary)
                .env("TEMP", temporary)
                .env("TMP", temporary);
        }
        let output = run.output().expect("runs the reader");
        let text = String::from_utf8_lossy(&output.stdout);
        let line = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
                .map(|rest| PathBuf::from(rest.trim()))
        };
        Reading {
            succeeded: output.status.success(),
            directory: line("directory"),
            exported: line("exported"),
            words: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

/// A path as the platform resolves it, in the ordinary form on Windows.
fn real(path: &Path) -> PathBuf {
    let real = std::fs::canonicalize(path).expect("resolves");
    match real.to_str().and_then(|text| text.strip_prefix(r"\\?\")) {
        Some(rest) if cfg!(windows) => PathBuf::from(rest),
        _ => real,
    }
}

/// Whether two paths are the same, ignoring letter case on Windows.
fn same(left: &Path, right: &Path) -> bool {
    if cfg!(windows) {
        left.to_string_lossy().to_lowercase() == right.to_string_lossy().to_lowercase()
    } else {
        left == right
    }
}

/// Asserts that the reader refused `what` in words that name the variable, the roots and `why`.
fn assert_refused(reader: Reader, reading: &Reading, what: &str, why: &str) {
    assert!(
        !reading.succeeded,
        "{reader:?} accepted {what}: {reading:?}"
    );
    assert!(
        reading.words.contains(VARIABLE) && reading.words.contains("temporary roots"),
        "{reader:?} refused {what} without naming the variable and the roots: {}",
        reading.words
    );
    assert!(
        reading.words.contains(why),
        "{reader:?} refused {what} for another reason than {why:?}: {}",
        reading.words
    );
    assert!(
        reading.directory.is_none(),
        "{reader:?} named a directory for {what}: {reading:?}"
    );
}

const OUTSIDE: &str = "not inside a temporary root";

fn elsewhere() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\Windows\kr-evidence")
    } else {
        PathBuf::from("/etc/kr-evidence")
    }
}

#[test]
fn a_value_outside_the_temporary_roots_is_refused_with_its_words() {
    for reader in readers() {
        let outside = elsewhere();
        assert_refused(
            reader,
            &reader.read(Some(outside.as_os_str()), None),
            "a folder outside the roots",
            OUTSIDE,
        );
        assert!(!outside.exists(), "a refused directory is never made");
    }
}

#[test]
fn a_value_inside_a_root_is_accepted_and_handed_on_resolved() {
    for reader in readers() {
        let temporary = tempfile::tempdir().expect("a temporary folder");
        let value = temporary.path().join("evidence").join("screenshots");
        let reading = reader.read(Some(value.as_os_str()), None);
        let expected = real(temporary.path()).join("evidence").join("screenshots");
        assert!(reading.succeeded, "{reader:?}: {reading:?}");
        let directory = reading.directory.as_deref().expect("a directory");
        assert!(same(directory, &expected), "{reader:?}: {directory:?}");
        let exported = reading.exported.as_deref().expect("an exported value");
        assert!(same(exported, &expected), "{reader:?}: {exported:?}");
        assert!(
            !value.exists(),
            "the reader makes nothing for a given value"
        );
    }
}

#[test]
fn a_run_without_the_variable_gets_a_directory_of_its_own_that_exists() {
    for reader in readers() {
        let reading = reader.read(None, None);
        assert!(reading.succeeded, "{reader:?}: {reading:?}");
        let directory = reading.directory.clone().expect("a directory");
        assert!(directory.is_dir(), "{reader:?}: {}", directory.display());
        assert!(
            reading
                .exported
                .as_deref()
                .is_some_and(|exported| same(exported, &directory)),
            "{reader:?}: {reading:?}"
        );
        assert!(
            reading.words.contains(&directory.display().to_string()),
            "{reader:?} does not say where the directory is: {}",
            reading.words
        );
        std::fs::remove_dir(&directory).expect("removes the directory the run made");
    }
}

#[test]
fn a_name_that_only_begins_like_a_root_a_relative_value_and_an_empty_value_are_refused() {
    for reader in readers() {
        let temporary = real(&std::env::temp_dir());
        let lookalike = PathBuf::from(format!("{}foo", temporary.display())).join("evidence");
        let mut values: Vec<(PathBuf, &str)> = vec![
            (lookalike, OUTSIDE),
            (PathBuf::from("evidence"), "not an absolute path"),
            (PathBuf::from("./evidence"), "not an absolute path"),
            (PathBuf::new(), "it is empty"),
        ];
        if cfg!(unix) {
            values.push((PathBuf::from("/tmpfoo"), OUTSIDE));
        }
        for (value, why) in values {
            let reading = reader.read(Some(value.as_os_str()), None);
            assert_refused(reader, &reading, &format!("{value:?}"), why);
        }
    }
}

#[test]
fn a_step_up_is_refused_even_when_it_ends_inside_a_root() {
    for reader in readers() {
        let temporary = tempfile::tempdir().expect("a temporary folder");
        let value = temporary
            .path()
            .join("evidence")
            .join("..")
            .join("evidence");
        let reading = reader.read(Some(value.as_os_str()), None);
        assert_refused(
            reader,
            &reading,
            "a path with a step up",
            "steps up a directory",
        );
    }
}

#[test]
fn a_relative_value_that_names_a_folder_under_the_working_directory_is_still_refused() {
    for reader in readers() {
        let temporary = tempfile::tempdir().expect("a temporary folder");
        std::fs::create_dir(temporary.path().join("sub")).expect("makes a folder to name");
        let reading = reader.read_in(Some(OsStr::new("sub")), None, Some(temporary.path()));
        assert_refused(
            reader,
            &reading,
            "a relative folder that exists",
            "not an absolute path",
        );
    }
}

#[cfg(unix)]
#[test]
fn a_link_inside_a_root_that_leads_out_of_it_is_refused() {
    for reader in readers() {
        let temporary = tempfile::tempdir().expect("a temporary folder");
        std::os::unix::fs::symlink("/etc", temporary.path().join("escape")).expect("a link");
        let value = temporary.path().join("escape").join("kr-evidence");
        let reading = reader.read(Some(value.as_os_str()), None);
        assert_refused(
            reader,
            &reading,
            "a path through a link out of the root",
            OUTSIDE,
        );
        assert!(!Path::new("/etc/kr-evidence").exists());
    }
}

#[cfg(unix)]
#[test]
fn a_temporary_folder_behind_a_link_is_honoured_and_its_neighbours_are_not() {
    // The folder sits outside every platform root, so only the root the case names can admit it.
    let parent = tempfile::Builder::new()
        .prefix("artifacts-readers-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("a folder beside the build");
    let target = parent.path().join("target");
    let link = parent.path().join("link");
    let neighbour = parent.path().join("neighbour");
    std::fs::create_dir(&target).expect("makes the target");
    std::fs::create_dir(&neighbour).expect("makes the neighbour");
    std::os::unix::fs::symlink(&target, &link).expect("a link");
    for reader in readers() {
        for value in [link.join("evidence"), target.join("evidence")] {
            let reading = reader.read(Some(value.as_os_str()), Some(&link));
            assert!(reading.succeeded, "{reader:?}: {value:?}: {reading:?}");
            let expected = real(&target).join("evidence");
            let directory = reading.directory.as_deref().expect("a directory");
            assert!(same(directory, &expected), "{reader:?}: {directory:?}");
        }
        let reading = reader.read(Some(neighbour.join("evidence").as_os_str()), Some(&link));
        assert_refused(
            reader,
            &reading,
            "a folder beside the temporary folder",
            OUTSIDE,
        );
    }
}

#[cfg(unix)]
#[test]
fn a_report_that_only_looks_makes_nothing_where_the_variable_is_not_set() {
    let script = r#". "$1"
        kr_artifacts_dir_if_set
        printf 'directory=[%s]\n' "$kr_artifacts""#;
    let run = |value: Option<&OsStr>| {
        let mut run = Command::new("bash");
        run.args(["-c", script, "bash"])
            .arg(
                repository()
                    .join("scripts")
                    .join("lib")
                    .join("artifacts-dir.sh"),
            )
            .env_remove(VARIABLE);
        if let Some(value) = value {
            run.env(VARIABLE, value);
        }
        run.output().expect("runs the reader")
    };
    let unset = run(None);
    assert!(unset.status.success());
    assert_eq!(
        String::from_utf8_lossy(&unset.stdout).trim(),
        "directory=[]"
    );
    assert!(String::from_utf8_lossy(&unset.stderr).is_empty());
    let refused = run(Some(OsStr::new("/etc/kr-evidence")));
    assert!(!refused.status.success());
}
