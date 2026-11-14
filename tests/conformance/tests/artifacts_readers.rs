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
/// drive when one of them was given that top as its temporary folder, and a reader then takes the
/// whole drive for a root. The cases therefore run one Git Bash at a time.
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
    /// What the shell that ran the reader says `/tmp` is, as Windows writes it (`C:\`, `\\server\share`);
    /// `None` for PowerShell and wherever the shell has no `cygpath`.
    slash_tmp: Option<PathBuf>,
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
        && matches!(reader, Reader::Shell)
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

impl Reader {
    /// Runs the reader with `value` as the variable (or with none) and `temporary` as the
    /// temporary folder (or the machine's own).
    fn read(self, value: Option<&OsStr>, temporary: Option<&Path>) -> Reading {
        self.read_in(value, temporary, None)
    }

    /// As [`Reader::read`], with `named` as further variables of the reader's environment.
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
            Reader::Shell => {
                let mut run = Command::new(shell().expect("a shell is installed"));
                run.args([
                    "-c",
                    r#". "$1"
                    printf 'slash_tmp=%s\n' "$(cygpath -w /tmp 2>/dev/null)"
                    kr_artifacts_dir
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
            .env("NO_COLOR", "1")
            .envs(named.iter().copied());
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
        let _alone = matches!(self, Reader::Shell)
            .then(|| ONE_GIT_BASH.lock().unwrap_or_else(|held| held.into_inner()));
        let output = run.output().expect("runs the reader");
        let text = String::from_utf8_lossy(&output.stdout);
        let line = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
                .map(|rest| match self {
                    Reader::Shell => from_bash(rest.trim()),
                    Reader::PowerShell => PathBuf::from(rest.trim()),
                })
        };
        Reading {
            succeeded: output.status.success(),
            directory: line("directory"),
            exported: line("exported"),
            slash_tmp: line("slash_tmp").filter(|path| !path.as_os_str().is_empty()),
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

#[test]
fn a_run_without_the_variable_gets_a_directory_of_its_own_that_exists() {
    for reader in readers() {
        let reading = reader.read(None, None);
        assert!(reading.succeeded, "{reader:?}: {reading:?}");
        let directory = reading.directory.clone().expect("a directory");
        assert!(directory.is_dir(), "{reader:?}: {}", directory.display());
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
/// refused by each reader, spelled with one slash or with two.
#[test]
fn a_filesystem_root_as_the_value_is_refused() {
    for reader in readers() {
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
    let run = Command::new("bash")
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
        .env("TMPDIR", &scratch)
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

#[test]
fn a_temporary_folder_that_is_a_filesystem_root_admits_nothing_beside_the_other_roots() {
    let top = Path::new(if cfg!(windows) { r"C:\" } else { "/" });
    for reader in readers() {
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
            "a folder outside the roots when the temporary folder is a filesystem root",
            OUTSIDE,
        );
        // The top of the file system is no root, so the words do not list it among them.
        if cfg!(unix) {
            for listed in ["(/,", ", /,", ", /)", "(/)"] {
                assert!(
                    !reading.words.contains(listed),
                    "{reader:?} lists the top of the file system as a root: {}",
                    reading.words
                );
            }
        }
    }
}

#[cfg(windows)]
mod windows_paths {
    use super::*;

    /// The value the Windows acceptance run passes (the temporary folder by its long name) where
    /// the machine's own `TEMP` may be its short name, and the same value in another letter case.
    #[test]
    fn the_long_name_and_a_changed_letter_case_of_the_temporary_folder_are_read_by_every_reader() {
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

    /// Asserts that the Git Bash that ran the reader read `/tmp` as `folder`, so that a case about
    /// what the reader does with that `/tmp` is never about another Git Bash's.
    fn assert_own_slash_tmp(reading: &Reading, folder: &Path) {
        let fold = |path: &Path| {
            path.to_string_lossy()
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
        let reading = Reader::Shell.read(Some(OsStr::new("/tmp/kr-evidence")), None);
        assert!(reading.succeeded, "{reading:?}");
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
}
