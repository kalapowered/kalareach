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

/// On Windows, Git Bash processes that run together have been seen to read `/tmp` as the top of a
/// drive when one of them was given that top as its temporary folder: the processes of one user
/// appear to share one table of mounts, which the first of them makes from its own temporary
/// folder. The cases therefore run one Git Bash at a time, so that each reads the `/tmp` that its
/// own environment makes. The lock holds for the cases of this test binary only.
#[cfg(windows)]
static ONE_GIT_BASH: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    /// What the shell that ran the reader says `/tmp` is, as Windows writes it (`C:\`,
    /// `\\server\share`); `None` for PowerShell and wherever the shell has no `cygpath`.
    #[cfg_attr(not(windows), allow(dead_code))]
    slash_tmp: Option<PathBuf>,
    /// Whether the shell's `nocasematch` option was set once the reader had run; `None` for
    /// PowerShell and where the reader ended the shell.
    #[cfg_attr(not(unix), allow(dead_code))]
    caseless_after: Option<bool>,
    /// Everything the reader said on its error stream.
    words: String,
}

#[derive(Clone, Copy, Debug)]
enum Reader {
    /// The first bash of the search path (on Windows, Git's own `bash.exe`).
    Shell,
    /// The system's own bash, `/bin/bash`, which is bash 3.2 on a Mac and the first bash of a
    /// hosted macOS runner's search path, where a developer's Mac usually has a newer one first.
    SystemShell,
    /// Git's own `bash.exe` started as a login shell (`--login`), whose profile sets the shell's
    /// temporary variables before the reader runs. Windows only.
    #[cfg_attr(not(windows), allow(dead_code))]
    LoginShell,
    PowerShell,
}

impl Reader {
    fn is_shell(self) -> bool {
        !matches!(self, Reader::PowerShell)
    }
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

/// The program that runs the shell reader: `bash` on Unix, and Git's own `bash.exe` on Windows,
/// where the `bash` on the path may be the Linux subsystem's launcher. `None` where Git Bash is not
/// installed and the run is not a hosted one; a hosted run has it, so there its absence fails.
fn shell() -> Option<PathBuf> {
    if cfg!(unix) {
        return Some(PathBuf::from("bash"));
    }
    let found = ["ProgramFiles", "ProgramW6432"]
        .iter()
        .filter_map(std::env::var_os)
        .map(|folder| PathBuf::from(folder).join(r"Git\bin\bash.exe"))
        .find(|path| path.is_file());
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "a hosted run has Git Bash, and none was found"
    );
    if found.is_none() {
        eprintln!("no Git Bash is installed here: the shell reader's cases are not run");
    }
    found
}

/// The system's own bash (`/bin/bash`), where the system has one. A script that starts with
/// `#!/usr/bin/env bash` gets it wherever it is the first bash of the search path, as on a hosted
/// macOS runner; this Mac's own first bash is a newer one.
fn system_shell() -> Option<PathBuf> {
    let path = PathBuf::from("/bin/bash");
    (cfg!(unix) && path.is_file()).then_some(path)
}

/// A path Git Bash printed (`/c/Users/x`) as Windows writes it (`C:\Users\x`); a path of any other
/// form, and every path off Windows, as it is.
fn from_bash(text: &str) -> PathBuf {
    let bytes = text.as_bytes();
    if cfg!(windows)
        && bytes.len() >= 3
        && bytes[0] == b'/'
        && bytes[1].is_ascii_alphabetic()
        && bytes[2] == b'/'
    {
        let drive = char::from(bytes[1].to_ascii_uppercase());
        PathBuf::from(format!("{drive}:{}", text[2..].replace('/', "\\")))
    } else {
        PathBuf::from(text)
    }
}

/// `path` as the reader is given it so that it reaches the reader as written: Git Bash on Windows
/// is given `/c/Users/x`, since it settles a `C:\Users\x` before the reader sees it.
fn spelled_for(reader: Reader, path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    let bytes = text.as_bytes();
    if cfg!(windows)
        && reader.is_shell()
        && bytes.len() >= 3
        && bytes[1] == b':'
        && bytes[0].is_ascii_alphabetic()
    {
        let drive = char::from(bytes[0].to_ascii_lowercase());
        PathBuf::from(format!("/{drive}{}", text[2..].replace('\\', "/")))
    } else {
        path.to_owned()
    }
}

fn readers() -> Vec<Reader> {
    let mut readers = Vec::new();
    if shell().is_some() {
        readers.push(Reader::Shell);
    }
    if powershell().is_some() {
        readers.push(Reader::PowerShell);
    }
    readers
}

/// The readers of [`readers`], and the shell reader run by the system's own bash where there is
/// one, for the cases that bash 3.2 and a newer bash may read differently.
fn readers_and_system_shell() -> Vec<Reader> {
    let mut readers = readers();
    if system_shell().is_some() {
        readers.push(Reader::SystemShell);
    }
    readers
}

/// `folder` as a platform may set a temporary variable: with a separator at its end, as macOS sets
/// `TMPDIR` (`/var/folders/…/T/`).
fn with_final_separator(folder: &Path) -> PathBuf {
    let mut text = folder.as_os_str().to_owned();
    text.push(std::path::MAIN_SEPARATOR_STR);
    PathBuf::from(text)
}

impl Reader {
    /// Runs the reader with `value` as the variable (or with none) and `temporary` as the
    /// temporary folder (or the machine's own).
    fn read(self, value: Option<&OsStr>, temporary: Option<&Path>) -> Reading {
        self.read_in(value, temporary, None)
    }

    /// As [`Reader::read`], with `named` as further variables of the reader's environment; a
    /// variable named with an empty value is removed from it (Windows passes an empty one on as a
    /// value of its own).
    fn read_with(
        self,
        value: Option<&OsStr>,
        temporary: Option<&Path>,
        named: &[(&str, &OsStr)],
    ) -> Reading {
        self.read_all(value, temporary, None, named)
    }

    /// As [`Reader::read`], with `directory` as the reader's working directory.
    fn read_in(
        self,
        value: Option<&OsStr>,
        temporary: Option<&Path>,
        directory: Option<&Path>,
    ) -> Reading {
        self.read_all(value, temporary, directory, &[])
    }

    /// The reader run with everything a case can set: the runner's temporary folder is not
    /// inherited, so only a case that names it has one.
    fn read_all(
        self,
        value: Option<&OsStr>,
        temporary: Option<&Path>,
        directory: Option<&Path>,
        named: &[(&str, &OsStr)],
    ) -> Reading {
        let root = repository();
        let mut run = match self {
            Reader::Shell | Reader::SystemShell | Reader::LoginShell => {
                let program = match self {
                    Reader::SystemShell => system_shell().expect("the system has a bash"),
                    _ => shell().expect("a shell is installed"),
                };
                let mut run = Command::new(program);
                if matches!(self, Reader::LoginShell) {
                    run.arg("--login");
                }
                run.args([
                    "-c",
                    r#". "$1"
                    [ -z "${KR_READER_CALLER_OPTION:-}" ] || shopt -s "$KR_READER_CALLER_OPTION"
                    [ -z "${KR_READER_TMPDIR:-}" ] || export TMPDIR="$KR_READER_TMPDIR"
                    printf 'slash_tmp=%s\n' "$(cygpath -w /tmp 2>/dev/null)"
                    kr_artifacts_dir
                    printf 'nocasematch=%s\n' "$(shopt -q nocasematch && echo on || echo off)"
                    printf 'directory=%s\nexported=%s\n' "$kr_artifacts" "$(printenv KR_TEST_ARTIFACTS_DIR)""#,
                    "bash",
                ])
                // With forward slashes, which Git Bash reads and a Windows path's backslashes it
                // would take for escapes.
                .arg(
                    root.join("scripts")
                        .join("lib")
                        .join("artifacts-dir.sh")
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
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
                    "exported=$([System.Environment]::GetEnvironmentVariable('KR_TEST_ARTIFACTS_DIR'))""#,
                ])
                .env(
                    "KR_READER_SCRIPT",
                    root.join("scripts").join("artifacts-dir.ps1"),
                );
                run
            }
        };
        run.env_remove(VARIABLE)
            .env_remove("RUNNER_TEMP")
            .env("NO_COLOR", "1");
        for (name, value) in named {
            if value.is_empty() {
                run.env_remove(name);
            } else {
                run.env(name, value);
            }
        }
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
        #[cfg(windows)]
        let _alone = self
            .is_shell()
            .then(|| ONE_GIT_BASH.lock().unwrap_or_else(|held| held.into_inner()));
        let output = run.output().expect("runs the reader");
        let text = String::from_utf8_lossy(&output.stdout);
        let line = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
                .map(|rest| match self {
                    Reader::PowerShell => PathBuf::from(rest.trim()),
                    _ => from_bash(rest.trim()),
                })
        };
        Reading {
            succeeded: output.status.success(),
            directory: line("directory"),
            exported: line("exported"),
            slash_tmp: line("slash_tmp").filter(|path| !path.as_os_str().is_empty()),
            caseless_after: text
                .lines()
                .find_map(|line| line.strip_prefix("nocasematch="))
                .map(|state| state.trim() == "on"),
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

/// Whether two paths are the same, ignoring letter case and the kind of slash on Windows.
fn same(left: &Path, right: &Path) -> bool {
    let folded = |path: &Path| path.to_string_lossy().to_lowercase().replace('/', "\\");
    if cfg!(windows) {
        folded(left) == folded(right)
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

/// The temporary variable is written as a platform writes it, with the separator at its end
/// (macOS's `TMPDIR`) and without, and the shell reader is run by the system's own bash as well as
/// by the first bash of the search path.
#[test]
fn a_run_without_the_variable_gets_a_directory_of_its_own_that_exists() {
    for reader in readers_and_system_shell() {
        // The temporary folder is named here, with one folder for TMPDIR, TEMP and TMP, so that the
        // case does not depend on how the machine's own variables stand to each other.
        let temporary = tempfile::tempdir().expect("a temporary folder");
        for named in [
            temporary.path().to_owned(),
            with_final_separator(temporary.path()),
        ] {
            let reading = reader.read(None, Some(&named));
            assert!(reading.succeeded, "{reader:?} with {named:?}: {reading:?}");
            let directory = reading.directory.clone().expect("a directory");
            assert!(directory.is_dir(), "{reader:?}: {}", directory.display());
            assert!(
                same(
                    directory.parent().expect("a parent"),
                    &real(temporary.path())
                ),
                "{reader:?} with {named:?}: the directory is made under the temporary folder: {}",
                directory.display()
            );
            assert!(
                same(&real(&directory), &directory),
                "{reader:?}: the directory is given resolved: {}",
                directory.display()
            );
            assert!(
                reading
                    .exported
                    .as_deref()
                    .is_some_and(|exported| same(exported, &directory)),
                "{reader:?}: {reading:?}"
            );
            // By its own name: Git Bash writes the rest of the path as `/c/Users/...`.
            let name = directory.file_name().expect("a name").to_string_lossy();
            assert!(
                reading.words.contains(&*name),
                "{reader:?} does not say where the directory is: {}",
                reading.words
            );
            std::fs::remove_dir(&directory).expect("removes the directory the run made");
        }
    }
}

/// A value written under a temporary variable that ends with a separator, as a script writes it
/// (`$TMPDIR/evidence` has two slashes in a row), names the folder under that temporary folder,
/// whatever bash reads it.
#[test]
fn a_value_under_a_temporary_folder_that_ends_with_a_separator_is_read_as_that_folder() {
    for reader in readers_and_system_shell() {
        let temporary = tempfile::tempdir().expect("a temporary folder");
        let folder = with_final_separator(temporary.path());
        let written = PathBuf::from(format!("{}/evidence", folder.display()));
        let value = spelled_for(reader, &written);
        let reading = reader.read(Some(value.as_os_str()), Some(&folder));
        assert!(
            reading.succeeded,
            "{reader:?} refused {value:?} under {folder:?}: {reading:?}"
        );
        let expected = real(temporary.path()).join("evidence");
        let directory = reading.directory.as_deref().expect("a directory");
        assert!(
            same(directory, &expected),
            "{reader:?}: {directory:?}, not {expected:?}"
        );
        let exported = reading.exported.as_deref().expect("an exported value");
        assert!(
            same(exported, &expected),
            "{reader:?}: {exported:?}, not {expected:?}"
        );
    }
}

#[test]
fn a_name_that_only_begins_like_a_root_a_relative_value_and_an_empty_value_are_refused() {
    for reader in readers() {
        let temporary = real(&std::env::temp_dir());
        let lookalike = PathBuf::from(format!("{}foo", temporary.display())).join("evidence");
        let mut values: Vec<(PathBuf, &str)> = vec![
            (PathBuf::from("evidence"), "not an absolute path"),
            (PathBuf::from("./evidence"), "not an absolute path"),
            (PathBuf::new(), "it is empty"),
        ];
        if cfg!(unix) {
            // `/tmp` is a root on every Unix, whatever TMPDIR names, so a folder beside the
            // temporary folder can lie inside it; the root itself and a name that only begins
            // like it are outside.
            values.push((real(Path::new("/tmp")), OUTSIDE));
            values.push((PathBuf::from("/tmpfoo"), OUTSIDE));
        } else {
            values.push((temporary.clone(), OUTSIDE));
            values.push((lookalike, OUTSIDE));
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
        // Git Bash makes a Windows-style value into a Unix-style one and settles a step up while
        // it does, so the value is given in the form it leaves alone.
        let value = spelled_for(reader, &value);
        let reading = reader.read(Some(value.as_os_str()), None);
        assert_refused(
            reader,
            &reading,
            "a path with a step up",
            "steps up a directory",
        );
    }
}

/// The top of a drive, or of the file system, is no evidence folder: a value that is one is
/// refused by the shell reader (run by either bash) and by PowerShell, spelled with one slash or
/// with two.
#[test]
fn a_filesystem_root_as_the_value_is_refused() {
    for reader in readers_and_system_shell() {
        let tops: &[&str] = if cfg!(windows) {
            &[r"C:\", "C:/"]
        } else {
            &["/", "//"]
        };
        for top in tops {
            let value = spelled_for(reader, Path::new(top));
            let reading = reader.read(Some(value.as_os_str()), None);
            assert_refused(reader, &reading, &format!("{top:?}"), OUTSIDE);
        }
    }
}

/// A line feed at the end of a value is not part of the value to a shell that reads it with a
/// command substitution, so a `..` before it is the value's last name, and a step up.
#[test]
fn a_step_up_before_a_final_line_feed_is_refused_by_the_shell_reader() {
    for reader in readers()
        .into_iter()
        .filter(|reader| matches!(reader, Reader::Shell))
    {
        let temporary = tempfile::tempdir().expect("a temporary folder");
        std::fs::create_dir(temporary.path().join("evidence")).expect("a folder");
        let mut value =
            spelled_for(reader, &temporary.path().join("evidence").join("..")).into_os_string();
        value.push("\n");
        let reading = reader.read(Some(value.as_os_str()), None);
        assert_refused(
            reader,
            &reading,
            "a path with a step up and a final line feed",
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

/// A temporary folder whose name holds line feeds is read as it is named, and a root that the shell
/// reader would cut at a line feed (an empty root between two halves, or a folder that is not the
/// temporary folder) admits nothing: no value outside the other roots is accepted.
#[cfg(unix)]
#[test]
fn a_temporary_folder_whose_name_holds_line_feeds_admits_nothing_outside_the_roots() {
    for reader in readers() {
        let parent = beside_the_build();
        let inside = parent.path().join("kr-root\n\nleaf");
        std::fs::create_dir(&inside).expect("a folder with line feeds in its name");
        let outside = elsewhere();
        assert_refused(
            reader,
            &reader.read(Some(outside.as_os_str()), Some(&inside)),
            "a folder outside the roots when the temporary folder's name holds line feeds",
            OUTSIDE,
        );
        // The temporary folder ends with a line feed, and the folder named without it is another
        // one that is no root.
        let trailing = parent.path().join("kr-trailing\n");
        let other = parent.path().join("kr-trailing");
        std::fs::create_dir(&trailing).expect("a folder with a line feed at the end of its name");
        std::fs::create_dir(&other).expect("the folder without it");
        let value = other.join("evidence");
        assert_refused(
            reader,
            &reader.read(Some(value.as_os_str()), Some(&trailing)),
            "a folder beside a temporary folder whose name ends with a line feed",
            OUTSIDE,
        );
        // The temporary folder is a link with a plain name to each of those folders: the line
        // feeds are in the folder that the link resolves to.
        let to_inside = parent.path().join("kr-link");
        let to_trailing = parent.path().join("kr-link-trailing");
        std::os::unix::fs::symlink(&inside, &to_inside).expect("a link");
        std::os::unix::fs::symlink(&trailing, &to_trailing).expect("a link");
        let cut = parent.path().join("kr-root");
        std::fs::create_dir(&cut).expect("the folder that the name is cut to");
        let beside = cut.join("evidence");
        for value in [&outside, &beside] {
            assert_refused(
                reader,
                &reader.read(Some(value.as_os_str()), Some(&to_inside)),
                "a folder outside a temporary folder link to a name with line feeds",
                OUTSIDE,
            );
        }
        assert_refused(
            reader,
            &reader.read(Some(value.as_os_str()), Some(&to_trailing)),
            "a folder beside the target of a temporary folder link whose name ends with a line feed",
            OUTSIDE,
        );
    }
}

/// A runner folder written with a line feed at its end names no folder, so it is no root, though the
/// same name without the line feed is a folder (a shell that drops the line feed would take it).
#[test]
fn a_runner_folder_with_a_line_feed_at_its_end_names_no_folder_and_so_no_root() {
    for reader in readers() {
        let runner = beside_the_build();
        let mut named = runner.path().as_os_str().to_owned();
        named.push("\n");
        let value = spelled_for(reader, &runner.path().join("evidence"));
        assert_refused(
            reader,
            &reader.read_with(
                Some(value.as_os_str()),
                None,
                &[("RUNNER_TEMP", named.as_os_str())],
            ),
            "a folder under a runner folder written with a line feed at its end",
            OUTSIDE,
        );
    }
}

/// A temporary folder that is no root is left as it was: the reader checks it before it makes the
/// run's own directory in it.
#[cfg(unix)]
#[test]
fn a_temporary_folder_that_is_no_root_is_left_without_a_directory_of_the_runs_own() {
    for reader in readers() {
        let working = tempfile::tempdir().expect("a working directory");
        std::fs::create_dir(working.path().join("kr-no-root")).expect("a folder");
        // A relative name is no root, though the folder exists under the working directory.
        let reading = reader.read_in(None, Some(Path::new("kr-no-root")), Some(working.path()));
        assert!(!reading.succeeded, "{reader:?}: {reading:?}");
        assert!(
            reading.words.contains("temporary roots"),
            "{reader:?} refused without naming the roots: {}",
            reading.words
        );
        // No variable was set, so the words name the temporary folder and why it is refused, and do
        // not tell the caller to leave the variable unset.
        assert!(
            reading.words.contains("kr-no-root") && reading.words.contains("not an absolute path"),
            "{reader:?} refused without naming the temporary folder and why: {}",
            reading.words
        );
        assert!(
            !reading.words.contains("leave it unset"),
            "{reader:?} tells a run that set nothing to leave it unset: {}",
            reading.words
        );
        let left = std::fs::read_dir(working.path().join("kr-no-root"))
            .expect("reads the folder")
            .count();
        assert_eq!(left, 0, "{reader:?} made a directory in a refused folder");
    }
}

#[cfg(unix)]
#[test]
fn a_relative_temporary_folder_is_no_root_though_it_exists_under_the_working_directory() {
    // The repository's own `scripts` folder, named the way a relative TMPDIR names a folder.
    for reader in readers() {
        let value = repository().join("scripts").join("evidence");
        let reading = reader.read_in(
            Some(value.as_os_str()),
            Some(Path::new("scripts")),
            Some(&repository()),
        );
        assert_refused(
            reader,
            &reading,
            "a folder under a relative temporary folder",
            OUTSIDE,
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

/// The store script's device leg keeps its output under the store's own folder, which is outside
/// every temporary root, and runs the release check with an evidence folder its reader accepts.
/// The temporary folder ends with a separator, as macOS's does, and the system's own bash runs the
/// helper.
#[cfg(unix)]
#[test]
fn the_store_legs_release_check_keeps_its_evidence_under_the_temporary_folder() {
    let outside = tempfile::Builder::new()
        .prefix("store-leg-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("a folder beside the build");
    let case = tempfile::tempdir().expect("a folder for the case");
    let tree = case.path().join("tree");
    let scratch = case.path().join("scratch");
    std::fs::create_dir_all(tree.join("scripts/lib")).expect("makes the tree");
    std::fs::create_dir_all(&scratch).expect("makes the temporary folder");
    std::fs::copy(
        repository().join("scripts/lib/artifacts-dir.sh"),
        tree.join("scripts/lib/artifacts-dir.sh"),
    )
    .expect("copies the reader");
    // The release check as far as the evidence goes: it reads the directory through the reader and
    // keeps a file in it, as the real one does.
    std::fs::write(
        tree.join("scripts/e2e-android-release.sh"),
        r#". "$(dirname "$0")/lib/artifacts-dir.sh"
kr_artifacts_dir
mkdir -p "$kr_artifacts/release-tls-android"
printf '%s\n' "$KR_RELEASE_APK" >"$kr_artifacts/release-tls-android/run.log"
"#,
    )
    .expect("writes the check");
    let leg = outside.path().join("device").join("leg");
    std::fs::create_dir_all(&leg).expect("makes the leg");
    let run = Command::new(system_shell().unwrap_or_else(|| PathBuf::from("bash")))
        .args([
            "-c",
            r#". "$1"; kr_store_release_tls "$2" "$3" "$4""#,
            "bash",
        ])
        .arg(repository().join("scripts/lib/store-build.sh"))
        .arg(&tree)
        .arg("universal.apk")
        .arg(&leg)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", case.path())
        .env("TMPDIR", with_final_separator(&scratch))
        .output()
        .expect("runs the helper");
    let log = std::fs::read_to_string(leg.join("e2e-release.log")).unwrap_or_default();
    assert!(
        run.status.success(),
        "the release check ended with {:?}: {log}",
        run.status
    );
    assert_eq!(
        std::fs::read_to_string(leg.join("e2e/release-tls-android/run.log")).unwrap_or_default(),
        "universal.apk\n",
        "the leg did not get the check's evidence: {log}"
    );
    let left: Vec<_> = std::fs::read_dir(&scratch)
        .expect("reads the temporary folder")
        .collect();
    assert!(
        left.is_empty(),
        "the evidence folder was left behind: {left:?}"
    );
}

/// A folder beside the build, outside every platform root.
fn beside_the_build() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("artifacts-readers-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("a folder beside the build")
}

#[test]
fn the_runners_temporary_folder_is_a_root_of_a_run_that_names_it_and_of_no_other() {
    for reader in readers() {
        let runner = beside_the_build();
        let value = runner.path().join("evidence");
        let named = reader.read_with(
            Some(value.as_os_str()),
            None,
            &[("RUNNER_TEMP", runner.path().as_os_str())],
        );
        assert!(named.succeeded, "{reader:?}: {named:?}");
        let directory = named.directory.as_deref().expect("a directory");
        assert!(
            same(directory, &real(runner.path()).join("evidence")),
            "{reader:?}: {directory:?}"
        );
        assert_refused(
            reader,
            &reader.read(Some(value.as_os_str()), None),
            "a folder under a runner folder that was not named",
            OUTSIDE,
        );
    }
}

#[cfg(unix)]
#[test]
fn slash_tmp_is_a_root_where_the_temporary_folder_names_another() {
    for reader in readers() {
        let other = beside_the_build();
        let value = PathBuf::from(format!(
            "/tmp/kr-artifacts-readers-{}/evidence",
            std::process::id()
        ));
        let reading = reader.read(Some(value.as_os_str()), Some(other.path()));
        assert!(reading.succeeded, "{reader:?}: {reading:?}");
        assert!(
            !value.exists(),
            "{reader:?}: the reader makes nothing for a given value"
        );
    }
}

/// The top of the file system is no root, whatever way a temporary variable spells it: bash keeps a
/// leading `//` as it is, so the shell reader meets `//` and `//.` as the top itself.
#[test]
fn a_temporary_folder_that_is_a_filesystem_root_admits_nothing_beside_the_other_roots() {
    let tops: &[&str] = if cfg!(windows) {
        &[r"C:\"]
    } else {
        &["/", "//", "//."]
    };
    for reader in readers() {
        for top in tops {
            let top = Path::new(top);
            let outside = if cfg!(windows) {
                PathBuf::from(r"C:\Windows\kr-evidence")
            } else {
                PathBuf::from("/usr/kr-evidence")
            };
            let reading = reader.read_with(
                Some(outside.as_os_str()),
                Some(top),
                &[("RUNNER_TEMP", top.as_os_str())],
            );
            assert_refused(
                reader,
                &reading,
                &format!("a folder outside the roots when the temporary folder is {top:?}"),
                OUTSIDE,
            );
            // The top of the file system is no root, so the words do not list it among them.
            if cfg!(unix) {
                for listed in [
                    "(/,", ", /,", ", /)", "(/)", "(//,", ", //,", ", //)", "(//)", "(//.,",
                    ", //.,", ", //.)", "(//.)",
                ] {
                    assert!(
                        !reading.words.contains(listed),
                        "{reader:?} lists the top of the file system as a root ({top:?}): {}",
                        reading.words
                    );
                }
            }
        }
    }
}

/// A temporary folder that is a link to the top of the file system, with its target written `//`,
/// is no root: a value through the link names a folder at the top of the disk, which no reader
/// admits.
#[cfg(unix)]
#[test]
fn a_temporary_folder_that_is_a_link_to_the_top_of_the_file_system_admits_nothing() {
    for reader in readers() {
        let parent = beside_the_build();
        let link = parent.path().join("top");
        std::os::unix::fs::symlink("//", &link).expect("a link whose target is written //");
        // A name that is not at the top of the disk, so that only the top itself could admit it.
        let name = format!("kr-evidence-{}", std::process::id());
        let value = link.join(&name);
        let reading = reader.read_with(
            Some(value.as_os_str()),
            Some(&link),
            &[("RUNNER_TEMP", link.as_os_str())],
        );
        assert_refused(
            reader,
            &reading,
            "a folder at the top of the disk through a link to //",
            OUTSIDE,
        );
        assert!(
            !Path::new("/").join(&name).exists(),
            "{reader:?} made a folder at the top of the disk"
        );
    }
}

/// A folder written with a second slash in front (a path built as `/` and an absolute path) is that
/// folder, and so is a link whose target is written that way: the shell reader does not take `//`
/// at the front of a real path for another place.
#[cfg(unix)]
#[test]
fn a_leading_double_slash_is_read_as_the_folder_it_names() {
    for reader in readers() {
        let runner = beside_the_build();
        let real_runner = real(runner.path());
        let doubled = |path: &Path| PathBuf::from(format!("/{}", path.display()));
        // The runner's folder written with a second slash.
        let value = real_runner.join("evidence");
        let reading = reader.read_with(
            Some(value.as_os_str()),
            None,
            &[("RUNNER_TEMP", doubled(&real_runner).as_os_str())],
        );
        assert!(reading.succeeded, "{reader:?}: {reading:?}");
        let directory = reading.directory.as_deref().expect("a directory");
        assert!(same(directory, &value), "{reader:?}: {directory:?}");
        // A link inside the runner folder whose target is written with a second slash.
        let inner = real_runner.join("inner");
        std::fs::create_dir(&inner).expect("a folder");
        std::os::unix::fs::symlink(doubled(&inner), real_runner.join("double"))
            .expect("a link whose target is written with a second slash");
        let through = real_runner.join("double").join("evidence");
        let reading = reader.read_with(
            Some(through.as_os_str()),
            None,
            &[("RUNNER_TEMP", real_runner.as_os_str())],
        );
        assert!(reading.succeeded, "{reader:?}: {reading:?}");
        let directory = reading.directory.as_deref().expect("a directory");
        assert!(
            same(directory, &inner.join("evidence")),
            "{reader:?}: {directory:?}"
        );
    }
}

/// The shell reader compares by exact letters whatever options its caller set, and puts the
/// caller's `nocasematch` back as it was. The second holds on every disk, and the case checks it
/// there. The first needs two folders that differ in case alone, so a disk that keeps them as one
/// (the Mac's usual one) cannot show it, and the case says so.
#[cfg(unix)]
#[test]
fn the_shell_reader_compares_exact_letters_whatever_the_callers_nocasematch_is() {
    let parent = beside_the_build();
    let root = parent.path().join("root");
    std::fs::create_dir(&root).expect("a folder");
    let inside = root.join("evidence");
    for reader in readers_and_system_shell()
        .into_iter()
        .filter(|reader| reader.is_shell())
    {
        for option in ["", "nocasematch"] {
            let named = [
                ("RUNNER_TEMP", root.as_os_str()),
                ("KR_READER_CALLER_OPTION", OsStr::new(option)),
            ];
            let reading = reader.read_with(Some(inside.as_os_str()), None, &named);
            assert!(reading.succeeded, "{reader:?} with {option:?}: {reading:?}");
            assert_eq!(
                reading.caseless_after,
                Some(option == "nocasematch"),
                "{reader:?} left the caller's nocasematch as it was not set ({option:?})"
            );
        }
    }
    if parent.path().join("ROOT").exists() {
        eprintln!(
            "the disk under {} keeps /root and /ROOT as one folder: the letters are not compared here",
            parent.path().display()
        );
        return;
    }
    let other = parent.path().join("ROOT");
    std::fs::create_dir(&other).expect("the folder that differs in letter case alone");
    for option in ["", "nocasematch"] {
        let named = [
            ("RUNNER_TEMP", root.as_os_str()),
            ("KR_READER_CALLER_OPTION", OsStr::new(option)),
        ];
        let outside = other.join("evidence");
        let reading = Reader::Shell.read_with(Some(outside.as_os_str()), None, &named);
        assert_refused(
            Reader::Shell,
            &reading,
            &format!("a folder that differs from the root in letter case alone ({option:?})"),
            OUTSIDE,
        );
    }
}

/// Two temporary roots that differ in letter case alone are two roots where the disk keeps them
/// apart, and a value under the second is inside a root. A disk that keeps them as one (the Mac's
/// usual one) cannot show it, and the case says so.
#[cfg(unix)]
#[test]
fn a_second_root_that_differs_in_letter_case_alone_is_a_root_where_the_disk_tells_them_apart() {
    let parent = beside_the_build();
    let lower = parent.path().join("tmp");
    std::fs::create_dir(&lower).expect("a folder");
    if parent.path().join("TMP").exists() {
        eprintln!(
            "the disk under {} keeps /tmp and /TMP as one folder: the case says nothing here",
            parent.path().display()
        );
        return;
    }
    let upper = parent.path().join("TMP");
    std::fs::create_dir(&upper).expect("the folder that differs in letter case alone");
    let value = upper.join("evidence");
    let expected = real(&upper).join("evidence");
    for reader in readers_and_system_shell() {
        let reading = reader.read_with(
            Some(value.as_os_str()),
            Some(&lower),
            &[("RUNNER_TEMP", upper.as_os_str())],
        );
        assert!(
            reading.succeeded,
            "{reader:?} refused a value under a root that differs from the other in letter case alone: {reading:?}"
        );
        let directory = reading.directory.as_deref().expect("a directory");
        assert!(same(directory, &expected), "{reader:?}: {directory:?}");
    }
}

/// The words of every reader's refusal of a backslash off Windows.
#[cfg(unix)]
const BACKSLASH: &str = "a backslash is not taken in the folder's path on this platform";

/// Off Windows a value of the variable that holds a backslash is refused by every reader, in the
/// same words, before any other read of it. PowerShell's own path commands read a backslash as a
/// separator on every platform, so no PowerShell caller can keep such a folder as written, and a
/// value that the readers cannot read as one folder is refused by all of them. The first three
/// values are the ones that the readers read four ways: a step up behind a backslash (after a
/// slash and with none), and a backslash behind a link that leads out of a root.
#[cfg(unix)]
#[test]
fn a_backslash_in_a_value_is_refused_by_every_reader_off_windows() {
    for reader in readers_and_system_shell() {
        let temporary = tempfile::tempdir().expect("a temporary folder");
        let root = real(temporary.path());
        let outside = Path::new("/etc/kr-evidence");
        std::os::unix::fs::symlink("/etc", root.join("out")).expect("a link out of the root");
        for (what, value) in [
            (
                "a step up behind a backslash, after a slash",
                format!(r"{}/a\..\..\kr-letters", root.display()),
            ),
            (
                "a step up behind a backslash, with no slash after the folder",
                format!(r"{}\a\..\..\kr-letters", root.display()),
            ),
            (
                "a backslash behind a link that leads out of the root",
                format!(r"{}/out\kr-evidence", root.display()),
            ),
            (
                "a name with a backslash in it, inside the root",
                format!(r"{}/a\b", root.display()),
            ),
            ("backslashes only", r"\private\tmp\kr-evidence".to_owned()),
        ] {
            let reading = reader.read(Some(OsStr::new(&value)), None);
            assert_refused(reader, &reading, what, BACKSLASH);
            assert!(!outside.exists(), "{reader:?}: {what}");
        }
    }
}

/// A temporary variable that holds a backslash is passed over as a root off Windows, whatever
/// folders the readers could make of it: the shell reader reads it as a letter of a name and
/// PowerShell reads it as a separator. The run's own directory is then made under the next root.
#[cfg(unix)]
#[test]
fn a_temporary_variable_with_a_backslash_is_passed_over_as_a_root_off_windows() {
    for reader in readers_and_system_shell() {
        let parent = beside_the_build();
        let root = real(parent.path());
        // One folder that the backslash names as a letter, and one that it names as a separator,
        // and a link that leads to the first.
        let lettered = root.join("a\\b");
        std::fs::create_dir_all(&lettered).expect("a folder with a backslash in its name");
        std::fs::create_dir_all(root.join("a").join("b")).expect("the folder it reads as");
        std::os::unix::fs::symlink(&lettered, root.join("link")).expect("a link");
        for (what, value) in [
            (
                "a folder that a backslash read as a separator names",
                root.join("a").join("b").join("evidence"),
            ),
            (
                "a folder behind a link to a folder with a backslash in its name",
                root.join("link").join("evidence"),
            ),
        ] {
            let reading = reader.read(Some(value.as_os_str()), Some(&lettered));
            assert_refused(reader, &reading, what, OUTSIDE);
            assert!(
                !reading.words.contains("a\\b"),
                "{reader:?} lists a root that holds a backslash: {}",
                reading.words
            );
        }
        // The runner's folder is the one root that is left beside /tmp.
        let runner = beside_the_build();
        let value = runner.path().join("evidence");
        let reading = reader.read_with(
            Some(value.as_os_str()),
            Some(&lettered),
            &[("RUNNER_TEMP", runner.path().as_os_str())],
        );
        assert!(
            reading.succeeded,
            "{reader:?} refused a value under the runner's folder: {reading:?}"
        );
        let reading = reader.read(None, Some(&lettered));
        assert!(reading.succeeded, "{reader:?}: {reading:?}");
        let directory = reading.directory.clone().expect("a directory");
        assert!(
            same(
                directory.parent().expect("a parent"),
                &real(Path::new("/tmp"))
            ),
            "{reader:?}: the run's own directory is made under /tmp: {}",
            directory.display()
        );
        std::fs::remove_dir(&directory).expect("removes the directory the run made");
    }
}

/// Stands in for `uname` and `cygpath` so that the shell reader takes the branch that Git Bash runs,
/// on a machine that has no Windows: `uname` says Git Bash, and `cygpath` maps `C:\x` to a folder
/// under `$KR_FAKE_DRIVES/c` and back. The folder it returns is a stub's folder, so the case shows
/// how the reader builds a path and not how Git Bash converts one (the cases on a Windows machine
/// show that).
#[cfg(unix)]
fn windows_stub() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let stub = tempfile::tempdir().expect("a folder for the stubs");
    let programs = [
        ("uname", "#!/bin/sh\necho MINGW64_NT-10.0\n"),
        (
            "cygpath",
            r#"#!/bin/bash
mode=$1
shift
[ "$1" = -- ] && shift
v=${1//\\//}
case $mode in
  -u) printf '%s/%s%s\n' "$KR_FAKE_DRIVES" "$(printf '%s' "${v:0:1}" | tr A-Z a-z)" "${v:2}" ;;
  -w)
    case $v in
      "$KR_FAKE_DRIVES"/?/*)
        rest=${v#"$KR_FAKE_DRIVES"/?}
        d=${v#"$KR_FAKE_DRIVES"/}
        printf '%s:%s\n' "$(printf '%s' "${d:0:1}" | tr a-z A-Z)" "${rest//\//\\}"
        ;;
      *) printf '%s\n' "$v" ;;
    esac
    ;;
esac
"#,
        ),
    ];
    for (name, text) in programs {
        let path = stub.path().join(name);
        std::fs::write(&path, text).expect("writes a stub");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("runs");
    }
    stub
}

/// Every path that a reader builds is built from the form that its own classifier returns, never
/// from the written value: the shell reader's own directory under a temporary folder written behind
/// `\\?\` in backslashes (the folder that the roots accept) is made there, where adding a name to
/// the written folder would put a slash behind the prefix and the reader would refuse its own path.
/// Run under the stubbed Git Bash branch, by the first bash of the search path and by the system's.
#[cfg(unix)]
#[test]
fn the_shell_readers_own_directory_is_made_under_the_folder_in_the_form_it_reads() {
    let drives = tempfile::tempdir().expect("a folder for the drives");
    let drives_real = real(drives.path());
    let folder = drives_real.join("c").join("Users").join("kr").join("Temp");
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    let stub = windows_stub();
    let path = format!(
        "{}:{}",
        stub.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    for reader in [Reader::Shell, Reader::SystemShell] {
        if matches!(reader, Reader::SystemShell) && system_shell().is_none() {
            continue;
        }
        for written in [
            r"C:\Users\kr\Temp",
            r"C:/Users/kr/Temp/",
            r"\\?\C:\Users\kr\Temp",
            r"\\?\C:\Users\kr\Temp\",
        ] {
            let reading = reader.read_with(
                None,
                Some(Path::new(written)),
                &[
                    ("PATH", OsStr::new(&path)),
                    ("KR_FAKE_DRIVES", drives_real.as_os_str()),
                ],
            );
            assert!(
                reading.succeeded,
                "{reader:?} refused the run's own directory under {written}: {reading:?}"
            );
            let directory = reading.directory.clone().expect("a directory");
            assert_eq!(
                directory.parent(),
                Some(folder.as_path()),
                "{reader:?} under {written}: {directory:?}"
            );
            std::fs::remove_dir(&directory).expect("removes the directory the run made");
        }
    }
}

/// A drive's letter is an ASCII letter in every locale: bash 3.2 reads a range such as `A-Za-z` by
/// collation under a UTF-8 locale and would take `é:\x` for a drive.
#[cfg(unix)]
#[test]
fn a_drive_letter_is_an_ascii_letter_in_every_locale() {
    let drives = tempfile::tempdir().expect("a folder for the drives");
    let drives_real = real(drives.path());
    let stub = windows_stub();
    let path = format!(
        "{}:{}",
        stub.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    for reader in readers_and_system_shell()
        .into_iter()
        .filter(|reader| reader.is_shell())
    {
        let reading = reader.read_with(
            Some(OsStr::new("\u{e9}:\\kr-evidence")),
            None,
            &[
                ("PATH", OsStr::new(&path)),
                ("KR_FAKE_DRIVES", drives_real.as_os_str()),
                ("LC_ALL", OsStr::new("en_US.UTF-8")),
            ],
        );
        assert_refused(
            reader,
            &reading,
            "a value that begins with é:",
            "not an absolute path",
        );
    }
}

#[cfg(windows)]
mod windows_paths {
    use super::*;

    /// The value the Windows acceptance run passes (the temporary folder by its long name) where
    /// the machine's own `TEMP` may be its short name, and the same value in another letter case.
    #[test]
    fn the_long_name_and_a_changed_letter_case_of_the_temporary_folder_are_read_by_the_shell_and_powershell()
     {
        for reader in readers() {
            let temporary = tempfile::tempdir().expect("a temporary folder");
            let long = real(temporary.path());
            let evidence = long.join("evidence");
            let lower = PathBuf::from(evidence.to_string_lossy().to_lowercase());
            for value in [evidence.clone(), lower] {
                let reading = reader.read(Some(value.as_os_str()), None);
                assert!(
                    reading.succeeded,
                    "{reader:?} refused {value:?}: {reading:?}"
                );
                let directory = reading.directory.as_deref().expect("a directory");
                assert!(same(directory, &evidence), "{reader:?}: {directory:?}");
            }
        }
    }

    /// `path` as it is written once its links and short names are resolved, where it exists.
    fn resolved(path: &Path) -> PathBuf {
        if path.exists() {
            real(path)
        } else {
            path.to_owned()
        }
    }

    /// Asserts that the Git Bash that ran the reader read `/tmp` as `folder`, so that a case about
    /// what the reader does with that `/tmp` is never about another Git Bash's.
    fn assert_own_slash_tmp(reading: &Reading, folder: &Path) {
        let fold = |path: &Path| {
            resolved(path)
                .to_string_lossy()
                .to_lowercase()
                .replace('/', "\\")
                .trim_end_matches('\\')
                .to_owned()
        };
        let seen = reading
            .slash_tmp
            .as_deref()
            .expect("the shell printed what /tmp is");
        assert!(
            fold(seen) == fold(folder),
            "this Git Bash reads /tmp as {seen:?}, not {folder:?}, so the case says nothing about \
             the reader: {reading:?}"
        );
    }

    /// With the temporary folder at the top of a drive, Git Bash writes the whole drive under
    /// `/tmp`, so a value written there is inside a root that is a drive's top by another name.
    #[test]
    fn a_drive_top_is_no_root_whatever_name_git_bash_gives_it() {
        if shell().is_none() {
            return;
        }
        let top = drive_root();
        let value = Path::new("/tmp/Windows/kr-evidence");
        let reading = Reader::Shell.read_with(
            Some(value.as_os_str()),
            Some(top.as_path()),
            &[("RUNNER_TEMP", top.as_os_str())],
        );
        assert_own_slash_tmp(&reading, &top);
        assert_refused(
            Reader::Shell,
            &reading,
            "a folder under /tmp when /tmp is a drive's top",
            OUTSIDE,
        );
    }

    /// The same where the temporary folder is the top of a share (`\\server\share`), which Git
    /// Bash writes under `/tmp` as the whole share.
    #[test]
    fn a_shares_top_is_no_root_whatever_name_git_bash_gives_it() {
        if shell().is_none() {
            return;
        }
        let Some(share) = by_unc(&drive_root()) else {
            return;
        };
        let value = Path::new("/tmp/Windows/kr-evidence");
        let reading = Reader::Shell.read_with(
            Some(value.as_os_str()),
            Some(share.as_path()),
            &[("RUNNER_TEMP", share.as_os_str())],
        );
        assert_own_slash_tmp(&reading, &share);
        assert_refused(
            Reader::Shell,
            &reading,
            "a folder under /tmp when /tmp is a share's top",
            OUTSIDE,
        );
    }

    #[test]
    fn git_bashs_slash_tmp_is_the_temporary_folder() {
        if shell().is_none() {
            return;
        }
        // One folder for TMPDIR, TEMP and TMP, so that the case does not depend on how the machine's
        // own variables stand to each other.
        let folder = tempfile::tempdir().expect("a temporary folder");
        let reading = Reader::Shell.read(Some(OsStr::new("/tmp/kr-evidence")), Some(folder.path()));
        assert_own_slash_tmp(&reading, &real(folder.path()));
        assert!(reading.succeeded, "{reading:?}");
    }

    /// With `TMP` and `TEMP` apart and no variable set, the run's own directory is made under the
    /// folder `TEMP` names, which is the reader's temporary folder, and not under `/tmp`, which
    /// Git Bash made from `TMP`. The shell's `TMPDIR` is not set, or is `/tmp` as a login shell's
    /// profile exports it (the third leg starts a login shell and so reads that profile).
    #[test]
    fn a_run_whose_tmp_and_temp_differ_gets_its_own_directory_under_temp() {
        if shell().is_none() {
            return;
        }
        let there = tempfile::tempdir().expect("a folder that /tmp is");
        let here = tempfile::tempdir().expect("the reader's temporary folder");
        for (reader, tmpdir) in [
            (Reader::Shell, ""),
            (Reader::Shell, "/tmp"),
            (Reader::Shell, "/tmp/"),
            (Reader::LoginShell, ""),
        ] {
            let named = [
                ("TMP", there.path().as_os_str()),
                ("TEMP", here.path().as_os_str()),
                ("TMPDIR", OsStr::new(tmpdir)),
            ];
            let reading = reader.read_with(None, None, &named);
            assert_own_slash_tmp(&reading, &real(there.path()));
            assert!(
                reading.succeeded,
                "{reader:?} with TMPDIR {tmpdir:?}: {reading:?}"
            );
            let directory = reading.directory.clone().expect("a directory");
            assert!(directory.is_dir(), "{}", directory.display());
            assert!(
                same(directory.parent().expect("a parent"), &real(here.path())),
                "{reader:?} with TMPDIR {tmpdir:?}: the directory is made under TEMP's folder: {}",
                directory.display()
            );
            std::fs::remove_dir(&directory).expect("removes the directory the run made");
        }
    }

    /// A `TEMP` with a line feed at its end names no folder, so Git Bash's `/tmp`, which is the
    /// folder `TEMP` would name without the line feed, is no root: the reader checks the name as it
    /// was given. A run that sets no variable is refused, and nothing is made.
    #[test]
    fn a_temp_that_ends_with_a_line_feed_names_no_folder_and_so_makes_slash_tmp_no_root() {
        if shell().is_none() {
            return;
        }
        let there = tempfile::tempdir().expect("a folder that /tmp is");
        let mut broken = there.path().as_os_str().to_owned();
        broken.push("\n");
        let named = [
            ("TMP", there.path().as_os_str()),
            ("TEMP", broken.as_os_str()),
            ("TMPDIR", OsStr::new("")),
        ];
        let reading = Reader::Shell.read_with(Some(OsStr::new("/tmp/kr-evidence")), None, &named);
        assert_own_slash_tmp(&reading, &real(there.path()));
        assert_refused(
            Reader::Shell,
            &reading,
            "a folder under /tmp when TEMP ends with a line feed",
            OUTSIDE,
        );
        let reading = Reader::Shell.read_with(None, None, &named);
        assert!(!reading.succeeded, "{reading:?}");
        assert!(
            !reading.words.contains("leave it unset"),
            "a run that set nothing is told to leave it unset: {}",
            reading.words
        );
        let left = std::fs::read_dir(there.path())
            .expect("reads the folder")
            .count();
        assert_eq!(left, 0, "a directory was made in /tmp");
    }

    /// Git Bash makes `/tmp` from the `TMP` of the process that starts it (and, with several
    /// running, of the first), so it can be a folder that the reader's own `TEMP` does not name.
    /// Then it is no root of the reader.
    #[test]
    fn git_bashs_slash_tmp_is_a_root_only_where_it_is_the_readers_temporary_folder() {
        if shell().is_none() {
            return;
        }
        let there = tempfile::tempdir().expect("a folder that /tmp is");
        let here = tempfile::tempdir().expect("the reader's temporary folder");
        let named = [
            ("TMP", there.path().as_os_str()),
            ("TEMP", here.path().as_os_str()),
        ];
        let reading = Reader::Shell.read_with(Some(OsStr::new("/tmp/kr-evidence")), None, &named);
        assert_own_slash_tmp(&reading, &real(there.path()));
        assert_refused(
            Reader::Shell,
            &reading,
            "a folder under /tmp when /tmp is not the reader's temporary folder",
            OUTSIDE,
        );
        let value = spelled_for(Reader::Shell, &real(here.path()).join("evidence"));
        let reading = Reader::Shell.read_with(Some(value.as_os_str()), None, &named);
        assert!(reading.succeeded, "{reading:?}");
        let directory = reading.directory.as_deref().expect("a directory");
        assert!(
            same(directory, &real(here.path()).join("evidence")),
            "{directory:?}"
        );
        // A `TMPDIR` of `/tmp/` names the same folder as `/tmp`, which is no root here either.
        let with_slash = [
            ("TMP", there.path().as_os_str()),
            ("TEMP", here.path().as_os_str()),
            ("TMPDIR", OsStr::new("/tmp/")),
        ];
        let reading =
            Reader::Shell.read_with(Some(OsStr::new("/tmp/kr-evidence")), None, &with_slash);
        assert_own_slash_tmp(&reading, &real(there.path()));
        assert_refused(
            Reader::Shell,
            &reading,
            "a folder under /tmp when TMPDIR is /tmp/ and /tmp is not the reader's temporary folder",
            OUTSIDE,
        );
    }

    const POWER: Reader = Reader::PowerShell;

    fn drive_root() -> PathBuf {
        PathBuf::from(r"C:\")
    }

    #[test]
    fn a_runner_folder_that_depends_on_the_current_drive_is_no_root() {
        if powershell().is_none() {
            return;
        }
        let value = PathBuf::from(r"C:\Windows\kr-evidence");
        let reading = POWER.read_all(
            Some(value.as_os_str()),
            None,
            Some(&drive_root()),
            &[("RUNNER_TEMP", OsStr::new(r"\Windows"))],
        );
        assert_refused(
            POWER,
            &reading,
            "a folder under a drive-relative root",
            OUTSIDE,
        );
    }

    #[test]
    fn a_value_that_depends_on_the_current_drive_or_a_drives_current_directory_is_refused() {
        if powershell().is_none() {
            return;
        }
        for value in [
            r"\Windows\kr-evidence",
            "C:kr-evidence",
            r"C:Windows\kr-evidence",
        ] {
            let reading = POWER.read_all(Some(OsStr::new(value)), None, Some(&drive_root()), &[]);
            assert_refused(POWER, &reading, value, "not an absolute path");
        }
    }

    #[test]
    fn an_extended_length_value_inside_the_temporary_folder_is_read() {
        if powershell().is_none() {
            return;
        }
        let temporary = tempfile::tempdir().expect("a temporary folder");
        let ordinary = real(temporary.path());
        let extended = PathBuf::from(format!(r"\\?\{}\evidence", ordinary.display()));
        let reading = POWER.read(Some(extended.as_os_str()), None);
        assert!(reading.succeeded, "{reading:?}");
        let directory = reading.directory.as_deref().expect("a directory");
        assert!(same(directory, &ordinary.join("evidence")), "{directory:?}");
    }

    /// `folder` by the machine's own administrative share of its drive: the same folder, by a UNC
    /// path. `None` where the share cannot be reached, and a hosted run reaches it, so there that
    /// fails.
    fn by_unc(folder: &Path) -> Option<PathBuf> {
        let text = folder.to_string_lossy().into_owned();
        let unc = PathBuf::from(format!(r"\\localhost\{}${}", &text[..1], &text[2..]));
        if std::fs::metadata(&unc).is_ok() {
            return Some(unc);
        }
        assert!(
            std::env::var_os("CI").is_none(),
            "a hosted run reaches {}, and it could not",
            unc.display()
        );
        eprintln!(
            "{} cannot be reached here: the UNC case is not run",
            unc.display()
        );
        None
    }

    #[test]
    fn a_unc_value_is_read_under_a_unc_runner_folder_and_refused_without_one() {
        if powershell().is_none() {
            return;
        }
        let temporary = tempfile::tempdir().expect("a temporary folder");
        let ordinary = real(temporary.path());
        let Some(unc) = by_unc(&ordinary) else {
            return;
        };
        let value = unc.join("evidence");
        let named = POWER.read_with(
            Some(value.as_os_str()),
            None,
            &[("RUNNER_TEMP", unc.as_os_str())],
        );
        assert!(named.succeeded, "{named:?}");
        assert_refused(
            POWER,
            &POWER.read(Some(value.as_os_str()), None),
            "a UNC value under no UNC root",
            OUTSIDE,
        );
    }

    /// `folder` by the machine's own administrative share, as Git Bash writes it (`//localhost/C$/…`),
    /// and as Windows writes it. `None` where the share cannot be reached.
    fn shell_share(folder: &Path) -> Option<(PathBuf, PathBuf)> {
        let windows = by_unc(folder)?;
        let shell = PathBuf::from(windows.to_string_lossy().replace('\\', "/"));
        Some((shell, windows))
    }

    /// A share's path begins with two slashes and keeps them: a value under a runner folder that is
    /// a share's folder is that folder, and is not read as a folder of the local `/localhost/…`.
    #[test]
    fn a_value_under_a_shares_folder_is_read_by_the_shell_reader_as_that_folder() {
        if shell().is_none() {
            return;
        }
        let temporary = tempfile::tempdir().expect("a temporary folder");
        let ordinary = real(temporary.path());
        let Some((share, by_windows)) = shell_share(&ordinary) else {
            return;
        };
        for written in [
            format!("{}/evidence", share.display()),
            format!("{}//evidence", share.display()),
        ] {
            let reading = Reader::Shell.read_with(
                Some(OsStr::new(&written)),
                None,
                &[("RUNNER_TEMP", share.as_os_str())],
            );
            assert!(reading.succeeded, "{written}: {reading:?}");
            let directory = reading.directory.as_deref().expect("a directory");
            // The share's folder may come back by its share or by the drive it is on.
            assert!(
                same(directory, &by_windows.join("evidence"))
                    || same(directory, &ordinary.join("evidence")),
                "{written}: {directory:?}"
            );
        }
    }

    /// With `TMP` a local folder (which Git Bash makes its `/tmp` from) and `TEMP` a share's folder,
    /// the reader's temporary folder is the share's, `TEMP` being the variable it reads: the run's
    /// own directory is made there, and `/tmp` is a local folder that is no root.
    #[test]
    fn a_run_whose_temp_is_a_shares_folder_and_tmp_a_local_folder_gets_its_own_directory_in_the_share()
     {
        if shell().is_none() {
            return;
        }
        let there = tempfile::tempdir().expect("a folder that /tmp is");
        let here = tempfile::tempdir().expect("the share's folder");
        let ordinary = real(here.path());
        let Some((_, by_windows)) = shell_share(&ordinary) else {
            return;
        };
        let named = [
            ("TMP", there.path().as_os_str()),
            ("TEMP", by_windows.as_os_str()),
            ("TMPDIR", OsStr::new("")),
        ];
        let reading = Reader::Shell.read_with(None, None, &named);
        // The case says something only where this Git Bash's /tmp is the local TMP folder.
        assert_own_slash_tmp(&reading, &real(there.path()));
        assert!(reading.succeeded, "{reading:?}");
        let directory = reading.directory.clone().expect("a directory");
        let name = directory.file_name().expect("a name");
        let made = by_windows.join(name);
        assert!(
            made.is_dir(),
            "the directory stands in the share's folder: {}",
            directory.display()
        );
        assert!(
            !real(there.path()).join(name).exists(),
            "and not in the folder that /tmp is: {}",
            directory.display()
        );
        std::fs::remove_dir(&made).expect("removes the directory the run made");
    }

    /// The reader takes the extended-length spelling of a value and of a root (`\\?\C:\…`, and
    /// `\\?\UNC\server\share\…` for a share) as the ordinary one. The temporary folder is another
    /// one, so that only the runner's root can admit the value.
    #[test]
    fn the_extended_length_spelling_of_a_value_or_of_a_runner_folder_is_read_as_the_ordinary_one() {
        if powershell().is_none() {
            return;
        }
        let runner = tempfile::tempdir().expect("a runner folder");
        let other = tempfile::tempdir().expect("a temporary folder");
        let ordinary = real(runner.path());
        let evidence = ordinary.join("evidence");
        let extended = PathBuf::from(format!(r"\\?\{}", ordinary.display()));
        let reading = POWER.read_all(
            Some(evidence.as_os_str()),
            Some(other.path()),
            None,
            &[("RUNNER_TEMP", extended.as_os_str())],
        );
        assert!(reading.succeeded, "an extended runner folder: {reading:?}");
        let directory = reading.directory.as_deref().expect("a directory");
        assert!(same(directory, &evidence), "{directory:?}");

        let Some(unc) = by_unc(&ordinary) else {
            return;
        };
        let share = unc.to_string_lossy().into_owned();
        // `\\localhost\C$\x` is `\\?\UNC\localhost\C$\x`.
        let extended_unc = |path: &str| PathBuf::from(format!(r"\\?\UNC\{}", &path[2..]));
        let value = extended_unc(&share).join("evidence");
        let reading = POWER.read_with(
            Some(value.as_os_str()),
            Some(other.path()),
            &[("RUNNER_TEMP", unc.as_os_str())],
        );
        assert!(reading.succeeded, "an extended UNC value: {reading:?}");
        let root = extended_unc(&share);
        let reading = POWER.read_with(
            Some(unc.join("evidence").as_os_str()),
            Some(other.path()),
            &[("RUNNER_TEMP", root.as_os_str())],
        );
        assert!(
            reading.succeeded,
            "an extended UNC runner folder: {reading:?}"
        );
    }

    /// Git Bash settles a `..` of a Windows path by its text when it converts the path, so the
    /// shell reader looks for it in the value as it was written.
    #[test]
    fn a_windows_path_that_steps_up_is_refused_by_the_shell_reader_as_it_was_written() {
        if shell().is_none() {
            return;
        }
        let temporary = tempfile::tempdir().expect("a temporary folder");
        let value = real(temporary.path())
            .join("evidence")
            .join("..")
            .join("evidence");
        let reading = Reader::Shell.read(Some(value.as_os_str()), None);
        assert_refused(
            Reader::Shell,
            &reading,
            "a Windows path with a step up",
            "steps up a directory",
        );
    }

    const KIND: &str = "a kind this reader does not take";
    const NOT_ABSOLUTE: &str = "not an absolute path";
    /// A mark of the words that say which spellings a reader takes.
    const TAKES: &str = "//server/share/folder";

    /// `folder` (an ordinary drive path) as a platform may give it, each with the separator that
    /// joins a name to it: backslashes, slashes, a slash only at the end, a slash only after the
    /// drive, and the extended-length form.
    fn drive_spellings(folder: &Path) -> Vec<(&'static str, String, char)> {
        let back = folder.to_string_lossy().into_owned();
        let slash = back.replace('\\', "/");
        vec![
            ("a drive path with backslashes", back.clone(), '\\'),
            ("a drive path with slashes", slash, '/'),
            (
                "a drive path with a slash before the name",
                back.clone(),
                '/',
            ),
            (
                "a drive path with a slash after the drive",
                back.replacen('\\', "/", 1),
                '\\',
            ),
            (
                "an extended-length drive path",
                format!(r"\\?\{back}"),
                '\\',
            ),
        ]
    }

    /// `share` (`\\localhost\C$\…`) as a platform or a tool may give it.
    fn share_spellings(share: &str) -> Vec<(&'static str, String, char)> {
        vec![
            ("a share with backslashes", share.to_owned(), '\\'),
            ("a share with slashes", share.replace('\\', "/"), '/'),
            (
                "a share with slashes at its start only",
                share.replacen(r"\\", "//", 1),
                '\\',
            ),
            (
                "a share with a slash after its server",
                share.replacen(r"\\localhost\", r"\\localhost/", 1),
                '\\',
            ),
            (
                "an extended-length share",
                format!(r"\\?\UNC\{}", &share[2..]),
                '\\',
            ),
        ]
    }

    /// The class, for a drive path: every spelling of the temporary folder's drive path that a
    /// platform, a runner or a tool gives is read as the same folder, as a value and as the
    /// runner's folder, by both readers; the temporary folder is another one, so that only the
    /// runner's root can admit the value.
    #[test]
    fn every_spelling_of_a_drive_path_is_read_as_the_same_folder_as_a_value_and_as_a_root() {
        let runner = tempfile::tempdir().expect("a runner folder");
        let other = tempfile::tempdir().expect("a temporary folder");
        let ordinary = real(runner.path());
        let expected = ordinary.join("evidence");
        for reader in readers() {
            for (what, folder, separator) in drive_spellings(&ordinary) {
                let value = format!("{folder}{separator}evidence");
                let reading = reader.read_with(
                    Some(OsStr::new(&value)),
                    Some(other.path()),
                    &[("RUNNER_TEMP", OsStr::new(&folder))],
                );
                assert!(
                    reading.succeeded,
                    "{reader:?} refused {what} ({value}): {reading:?}"
                );
                let directory = reading.directory.as_deref().expect("a directory");
                assert!(
                    same(directory, &expected),
                    "{reader:?}: {what} ({value}) came back as {directory:?}"
                );
            }
        }
    }

    /// The class, for a share: the machine's own share of its drive, in every spelling.
    #[test]
    fn every_spelling_of_a_share_is_read_as_the_same_folder_as_a_value_and_as_a_root() {
        let runner = tempfile::tempdir().expect("a runner folder");
        let other = tempfile::tempdir().expect("a temporary folder");
        let ordinary = real(runner.path());
        let Some(unc) = by_unc(&ordinary) else {
            return;
        };
        let share = unc.to_string_lossy().into_owned();
        for reader in readers() {
            for (what, folder, separator) in share_spellings(&share) {
                let value = format!("{folder}{separator}evidence");
                let reading = reader.read_with(
                    Some(OsStr::new(&value)),
                    Some(other.path()),
                    &[("RUNNER_TEMP", OsStr::new(&folder))],
                );
                assert!(
                    reading.succeeded,
                    "{reader:?} refused {what} ({value}): {reading:?}"
                );
                let directory = reading.directory.as_deref().expect("a directory");
                // The share's folder may come back by its share or by the drive it is on.
                assert!(
                    same(directory, &unc.join("evidence"))
                        || same(directory, &ordinary.join("evidence")),
                    "{reader:?}: {what} ({value}) came back as {directory:?}"
                );
            }
        }
    }

    /// The class, for every other spelling: both readers refuse it in words that say which
    /// spellings they take. A rooted path with no drive and a drive with no root are not absolute.
    #[test]
    fn every_other_windows_spelling_is_refused_in_words_that_say_which_spellings_are_taken() {
        let temporary = tempfile::tempdir().expect("a temporary folder");
        let ordinary = real(temporary.path());
        let back = ordinary.to_string_lossy().into_owned();
        let slash = back.replace('\\', "/");
        let rows = [
            ("a device path", format!(r"\\.\{back}\evidence"), KIND),
            (
                "an extended-length path with a slash behind the prefix",
                format!(r"\\?\{back}\a/evidence"),
                KIND,
            ),
            (
                "an extended-length path written with slashes",
                format!("//?/{slash}/evidence"),
                KIND,
            ),
            (
                "an extended-length volume path",
                r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\evidence".to_owned(),
                KIND,
            ),
            ("a server with no share", r"\\localhost".to_owned(), KIND),
            (
                "a server with a slash and no share",
                "//localhost/".to_owned(),
                KIND,
            ),
            (
                "three separators at the start",
                r"\\\localhost\C$\evidence".to_owned(),
                KIND,
            ),
            (
                "a path that depends on the current drive",
                r"\Windows\kr-evidence".to_owned(),
                NOT_ABSOLUTE,
            ),
            (
                "a path that depends on a drive's current directory",
                "C:kr-evidence".to_owned(),
                NOT_ABSOLUTE,
            ),
            ("a relative path", r"kr-evidence\x".to_owned(), NOT_ABSOLUTE),
        ];
        for reader in readers() {
            for (what, value, why) in &rows {
                let reading = reader.read(Some(OsStr::new(value)), None);
                assert_refused(reader, &reading, what, why);
                assert!(
                    reading.words.contains(TAKES),
                    "{reader:?} refused {what} without saying which spellings it takes: {}",
                    reading.words
                );
            }
        }
    }

    /// Git Bash's own spelling is the shell reader's alone: `/tmp/x` is a rooted path with no
    /// drive to the others, and Git Bash converts such a value for a program it starts.
    #[test]
    fn git_bashs_own_spelling_is_read_by_the_shell_reader_and_is_no_path_to_the_others() {
        if shell().is_none() {
            return;
        }
        let reading = Reader::Shell.read(Some(OsStr::new("/tmp/kr-gitbash-spelling")), None);
        assert!(reading.succeeded, "{reading:?}");
        if powershell().is_some() {
            let reading = POWER.read(Some(OsStr::new("/tmp/kr-gitbash-spelling")), None);
            assert_refused(POWER, &reading, "a Git Bash path", NOT_ABSOLUTE);
        }
    }

    /// On Windows the shell reader reads each backslash of a value as a separator before its step-up
    /// and its root checks: Git Bash settles a path that holds one by its text, and a `..` behind a
    /// backslash climbs out of the folder (`/tmp/a\..\..\x` is `TEMP`'s parent's `x`).
    #[test]
    fn a_backslash_in_a_value_is_read_as_a_separator_before_the_step_up_check() {
        if shell().is_none() {
            return;
        }
        let temporary = tempfile::tempdir().expect("a temporary folder");
        let ordinary = real(temporary.path());
        let slash = ordinary.to_string_lossy().replace('\\', "/");
        let git_bash = spelled_for(Reader::Shell, &ordinary);
        let values = [
            r"/tmp/a\..\..\kr-probe".to_owned(),
            r"/tmp/a\..\kr-probe".to_owned(),
            format!(r"{}/a\..\..\kr-probe", git_bash.display()),
            format!(r"{slash}/a\..\..\kr-probe"),
            format!(r"{}\a\..\..\kr-probe", ordinary.display()),
        ];
        for value in &values {
            let reading = Reader::Shell.read(Some(OsStr::new(value)), None);
            assert_refused(Reader::Shell, &reading, value, "steps up a directory");
        }
        if powershell().is_some() {
            let value = format!(r"{}\a\..\..\kr-probe", ordinary.display());
            let reading = POWER.read(Some(OsStr::new(&value)), None);
            assert_refused(POWER, &reading, &value, "steps up a directory");
        }
    }

    /// A value under a root with backslashes that stays inside is that folder, in the shell reader
    /// and in the others.
    #[test]
    fn a_value_with_backslashes_that_stays_inside_a_root_is_read_as_that_folder() {
        if shell().is_none() {
            return;
        }
        let temporary = tempfile::tempdir().expect("a temporary folder");
        let ordinary = real(temporary.path());
        let expected = ordinary.join("a").join("b").join("evidence");
        let git_bash = spelled_for(Reader::Shell, &ordinary);
        let values = [
            format!(r"{}/a\b\evidence", git_bash.display()),
            format!(r"{}\a/b\evidence", ordinary.display()),
        ];
        for reader in readers() {
            for value in &values {
                if !reader.is_shell() && value.starts_with('/') {
                    continue;
                }
                let reading = reader.read(Some(OsStr::new(value)), None);
                assert!(reading.succeeded, "{reader:?} refused {value}: {reading:?}");
                let directory = reading.directory.as_deref().expect("a directory");
                assert!(
                    same(directory, &expected),
                    "{reader:?}: {value}: {directory:?}"
                );
            }
        }
    }

    /// A refusal that finds no root says so in the shell reader, and shows no empty list. (`pwsh`
    /// makes the folder that `TEMP` names when it starts, so no environment leaves PowerShell with no
    /// root; the Rust and TypeScript readers' words are cased with an empty list of roots.)
    #[test]
    fn a_refusal_with_no_roots_says_that_there_are_none() {
        let nowhere = std::env::temp_dir().join(format!(
            "kr-no-such-temporary-folder-{}",
            std::process::id()
        ));
        assert!(!nowhere.exists());
        for reader in readers().into_iter().filter(|reader| reader.is_shell()) {
            let named = [
                ("TMP", nowhere.as_os_str()),
                ("TEMP", nowhere.as_os_str()),
                ("TMPDIR", OsStr::new("")),
            ];
            let reading =
                reader.read_with(Some(OsStr::new(r"C:\Windows\kr-evidence")), None, &named);
            assert_refused(
                reader,
                &reading,
                "a value with no root to be inside",
                OUTSIDE,
            );
            assert!(
                reading
                    .words
                    .contains("(none: no folder that a temporary variable names exists)"),
                "{reader:?}: {}",
                reading.words
            );
            assert!(
                !reading.words.contains("()"),
                "{reader:?}: {}",
                reading.words
            );
        }
    }

    /// Every path that a reader builds is built from the form that its own classifier returns: the
    /// run's own directory under a temporary folder written behind `\\?\` is made there, by the
    /// shell reader (which reads the folder from `TMPDIR`, set inside Git Bash as a caller's shell
    /// sets it) and by PowerShell (which reads `TMP`).
    #[test]
    fn the_runs_own_directory_is_made_under_a_temporary_folder_written_in_the_extended_form() {
        let temporary = tempfile::tempdir().expect("a temporary folder");
        let ordinary = real(temporary.path());
        let extended = PathBuf::from(format!(r"\\?\{}", ordinary.display()));
        for reader in readers() {
            let named: Vec<(&str, &OsStr)> = if reader.is_shell() {
                vec![
                    ("KR_READER_TMPDIR", extended.as_os_str()),
                    ("TEMP", ordinary.as_os_str()),
                    ("TMP", ordinary.as_os_str()),
                ]
            } else {
                vec![
                    ("TMP", extended.as_os_str()),
                    ("TEMP", extended.as_os_str()),
                ]
            };
            let reading = reader.read_with(None, None, &named);
            assert!(
                reading.succeeded,
                "{reader:?} refused its own directory under {extended:?}: {reading:?}"
            );
            let directory = reading.directory.clone().expect("a directory");
            assert!(
                same(directory.parent().expect("a parent"), &ordinary),
                "{reader:?}: {directory:?}"
            );
            std::fs::remove_dir(&directory).expect("removes the directory the run made");
        }
    }
}
