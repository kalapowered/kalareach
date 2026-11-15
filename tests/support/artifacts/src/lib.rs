//! Where a test run keeps its evidence.
//!
//! Section 27 puts every screenshot and evidence file of a release test run in one directory,
//! `KR_TEST_ARTIFACTS_DIR`, set under a temporary folder for the build. This crate is the one
//! reader of that variable for Rust. A value outside this platform's temporary roots is refused
//! here, where it is used, so a build that gives the variable a wrong value fails at its first read
//! whatever way the value took.
//!
//! The temporary roots are `/tmp` (Unix), the folder `std::env::temp_dir` names (`TMPDIR` on Unix,
//! the user's temporary folder on Windows) and the folder `RUNNER_TEMP` names, where each is an
//! absolute path that exists. Each root is resolved through its links as the platform resolves it
//! (`/tmp` is `/private/tmp` on macOS), and so is the part of the value that exists, so a link
//! inside a root that leads out of it is refused and a root that is itself behind a link is
//! honoured. The value is compared with a root by path components, never by text: `/tmpfoo` is
//! not inside `/tmp`. A relative value, an empty value and a value with a `..` in it are refused.
//!
//! On Windows a value, and each temporary variable, is read as Windows writes a full path:
//! `C:\folder` or `C:/folder`, `\\server\share\folder` or `//server/share/folder`, either of those
//! behind `\\?\` with backslashes only; a folder on a share is given in its ordinary form, as one on
//! a drive is. Any other spelling is refused, in words that say which are taken: a device path, a
//! server with no share, three separators at the start, a path that depends on the current drive
//! and one that depends on a drive's current directory.
//!
//! Where the variable is not set, the first read makes a directory of this run's own under the
//! temporary folder, says where it is on standard error, and every later read of the same process
//! returns the same directory.
//!
//! The reader guards a test run against a mistake: for any value of the evidence variable, and any
//! temporary variable as a platform, a runner, one of our scripts or a developer's shell sets it,
//! with folders and links as tools make them, it returns a folder inside the roots or refuses, and
//! it refuses nothing that the run set right. It is no boundary against a process of the same
//! account, which can write wherever the run can and can change a link or a folder while the reader
//! reads, or between the two checks of a run's own directory. The system resolves both paths before
//! they are compared and the reader folds no letter itself, so on Windows a folder made
//! case-sensitive is told apart.
//!
//! On Windows `std::env::temp_dir` takes the temporary folder from `TMP` first and then `TEMP`, and
//! so does the PowerShell reader; the TypeScript reader takes `TEMP` first and the shell reader
//! takes `TEMP`. Where `TMP` and `TEMP` differ, only a value under the runner's folder satisfies
//! all four readers.

use std::collections::hash_map::RandomState;
use std::ffi::OsStr;
use std::fmt;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

/// The variable that names where a run keeps its evidence.
const VARIABLE: &str = "KR_TEST_ARTIFACTS_DIR";

/// Why an evidence directory is refused, in words that name the variable and the roots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused(String);

impl fmt::Display for Refused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// The directory this run keeps its evidence in: the value of `KR_TEST_ARTIFACTS_DIR` resolved
/// through its links, or, where the variable is not set, a directory of this run's own.
///
/// The directory may not exist yet: whoever writes into it creates it.
///
/// # Panics
///
/// When the variable is set to a value outside this platform's temporary roots, with the words
/// that name the variable and the roots, or when no directory of this run's own can be made.
#[must_use]
pub fn directory() -> PathBuf {
    directory_from(std::env::var_os(VARIABLE).as_deref())
}

fn directory_from(value: Option<&OsStr>) -> PathBuf {
    match value {
        Some(value) => confine(Path::new(value)).unwrap_or_else(|refused| panic!("{refused}")),
        None => own().to_owned(),
    }
}

/// The real path of `value`, which has to be inside one of this platform's temporary roots.
///
/// The path is resolved before anything is created, so a refused directory is never made: the part
/// that exists is resolved by the system, links and all, and the rest is new names under it. A
/// caller that creates the directory resolves it again afterwards and compares.
///
/// # Errors
///
/// Returns why the value is refused.
pub fn confine(value: &Path) -> Result<PathBuf, Refused> {
    confine_in(value, &roots())
}

fn confine_in(value: &Path, roots: &[PathBuf]) -> Result<PathBuf, Refused> {
    check(value, roots).map_err(|why| refused(value, &why, roots))
}

/// The real path of `value` when it is inside one of `roots`; else why not.
fn check(value: &Path, roots: &[PathBuf]) -> Result<PathBuf, String> {
    if value.as_os_str().is_empty() {
        return Err("it is empty".to_owned());
    }
    if cfg!(windows) {
        match windows_spelling(&value.to_string_lossy()) {
            Spelling::Taken => {}
            Spelling::NotAbsolute => return Err(format!("it is not an absolute path ({TAKES})")),
            Spelling::Kind => {
                return Err(format!(
                    "it is a Windows path of a kind this reader does not take ({TAKES})"
                ));
            }
        }
    }
    if !value.is_absolute() {
        return Err("it is not an absolute path".to_owned());
    }
    if value
        .components()
        .any(|component| component == Component::ParentDir)
        || (cfg!(windows)
            && value
                .to_string_lossy()
                .split(['\\', '/'])
                .any(|name| name == ".."))
    {
        return Err("it steps up a directory with `..`".to_owned());
    }
    let real = resolve(value).map_err(|error| format!("it cannot be resolved: {error}"))?;
    if roots
        .iter()
        .any(|root| real != *root && real.starts_with(root))
    {
        Ok(real)
    } else {
        Err("it is not inside a temporary root".to_owned())
    }
}

/// The spellings of an absolute path that this reader takes on Windows, for the words of a refusal.
const TAKES: &str = concat!(
    r"on Windows this reader takes C:\folder or C:/folder, \\server\share\folder or ",
    r"//server/share/folder, and either behind \\?\, as \\?\C:\folder or ",
    r"\\?\UNC\server\share\folder"
);

/// How a Windows path is written: whether this reader takes the spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Spelling {
    /// A drive with a root, or a share with a server and a name, with either separator or both;
    /// either one behind `\\?\` with backslashes only, since Windows reads a slash behind `\\?\`
    /// as a letter of a name.
    Taken,
    /// A relative path, `\folder` (the current drive's root) or `C:folder` (a drive's current
    /// directory).
    NotAbsolute,
    /// Any other spelling: a device path (`\\.\`, or `\\?\` with anything but a drive or a share
    /// behind it), a server with no share, three separators at the start.
    Kind,
}

/// How `text`, a path as Windows writes it, is spelled. The same on every platform, so that the
/// table of spellings is run wherever the tests are.
fn windows_spelling(text: &str) -> Spelling {
    let separator = |character: char| character == '\\' || character == '/';
    let mut path = text.to_owned();
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        if rest.contains('/') {
            return Spelling::Kind;
        }
        let mut letters = rest.chars();
        if rest
            .get(..3)
            .is_some_and(|head| head.eq_ignore_ascii_case("unc"))
            && rest.get(3..4) == Some("\\")
            && rest.len() > 4
        {
            path = format!(r"\\{}", &rest[4..]);
        } else if letters
            .next()
            .is_some_and(|letter| letter.is_ascii_alphabetic())
            && letters.next() == Some(':')
            && letters.next() == Some('\\')
        {
            path = rest.to_owned();
        } else {
            return Spelling::Kind;
        }
    }
    let characters: Vec<char> = path.chars().collect();
    let at = |index: usize| characters.get(index).copied();
    if at(0).is_some_and(separator) && at(1).is_some_and(separator) {
        if at(2).is_some_and(|c| c == '.' || c == '?') && at(3).is_none_or(separator) {
            return Spelling::Kind;
        }
        if at(2).is_none_or(separator) {
            return Spelling::Kind;
        }
        let rest: String = characters[2..].iter().collect();
        return match rest.split_once(separator) {
            Some((_server, share)) if !share.is_empty() && !share.starts_with(separator) => {
                Spelling::Taken
            }
            _ => Spelling::Kind,
        };
    }
    if at(0).is_some_and(|letter| letter.is_ascii_alphabetic()) && at(1) == Some(':') {
        return if at(2).is_some_and(separator) {
            Spelling::Taken
        } else {
            Spelling::NotAbsolute
        };
    }
    Spelling::NotAbsolute
}

/// The roots as the refusal's words list them: never an empty list.
fn listed(roots: &[PathBuf]) -> String {
    if roots.is_empty() {
        return "none: no folder that a temporary variable names exists".to_owned();
    }
    roots
        .iter()
        .map(|root| root.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn refused(value: &Path, why: &str, roots: &[PathBuf]) -> Refused {
    let roots = listed(roots);
    Refused(format!(
        "the evidence directory `{}` (KR_TEST_ARTIFACTS_DIR) is refused: {why}. It has to be an \
         absolute path inside one of this platform's temporary roots ({roots}). Set it to a folder \
         under one of them, or leave it unset and the run makes a directory of its own.",
        value.display()
    ))
}

/// Why the run's own directory cannot be made under `temporary`: nothing was set, so the words
/// name the temporary folder and do not tell the caller to leave the variable unset.
fn refused_own(temporary: &Path, why: &str, roots: &[PathBuf]) -> Refused {
    let roots = listed(roots);
    Refused(format!(
        "no directory of this run's own can be made for its evidence: the temporary folder `{}` is \
         refused: {why}. It has to be an absolute path to a folder inside one of this platform's \
         temporary roots ({roots}). Point TMPDIR (on Windows, TMP) at such a folder, or set \
         KR_TEST_ARTIFACTS_DIR to a folder under one of the roots.",
        temporary.display()
    ))
}

/// The directory of this run's own, made on the first call.
fn own() -> &'static Path {
    static OWN: OnceLock<PathBuf> = OnceLock::new();
    OWN.get_or_init(|| {
        let own = own_in(&std::env::temp_dir(), &roots());
        eprintln!(
            "{VARIABLE} is not set: this run keeps its evidence in {}",
            own.display()
        );
        own
    })
}

/// A directory of this run's own under `temporary`, which has to be inside one of `roots`. The
/// folder is checked before the directory is made in it, so that a temporary folder that is no
/// root is left as it was.
fn own_in(temporary: &Path, roots: &[PathBuf]) -> PathBuf {
    let refuse = |why: String| -> PathBuf { panic!("{}", refused_own(temporary, &why, roots)) };
    check(&temporary.join(OWN_PREFIX), roots).unwrap_or_else(refuse);
    let made = make_own(temporary).unwrap_or_else(|error| {
        panic!("no directory of this run's own can be made for its evidence: {error}")
    });
    check(&made, roots).unwrap_or_else(refuse)
}

/// The start of the name of a run's own directory.
const OWN_PREFIX: &str = "kr-test-artifacts-";

/// Makes a directory under `temporary` that nothing else has, readable by this account only. The
/// name is made exclusively, so a name an earlier run took is never reused.
fn make_own(temporary: &Path) -> std::io::Result<PathBuf> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    let mut attempts = 0_u32;
    loop {
        let suffix = std::hash::BuildHasher::hash_one(&RandomState::new(), attempts);
        let path = temporary.join(format!("{OWN_PREFIX}{suffix:016x}"));
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == ErrorKind::AlreadyExists && attempts < 100 => {
                attempts += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

/// This platform's temporary roots that exist, each resolved through its links.
fn roots() -> Vec<PathBuf> {
    let mut named = vec![std::env::temp_dir()];
    if cfg!(unix) {
        named.push(PathBuf::from("/tmp"));
    }
    named.extend(std::env::var_os("RUNNER_TEMP").map(PathBuf::from));
    let mut roots: Vec<PathBuf> = Vec::new();
    // A temporary variable in a spelling this reader does not take names no root.
    let taken = |root: &&PathBuf| {
        root.is_absolute()
            && (!cfg!(windows) || windows_spelling(&root.to_string_lossy()) == Spelling::Taken)
    };
    for root in named.iter().filter(taken) {
        // A temporary folder that is a filesystem root (`/`, `C:\`) would admit every path on its
        // disk, so it is no root.
        if let Ok(real) = real_path(root)
            && real.parent().is_some()
            && !roots.contains(&real)
        {
            roots.push(real);
        }
    }
    roots
}

/// The path the system resolves `path` to, links and all. On Windows, a path on a drive or a share
/// is given in its ordinary form rather than the extended one the system answers with
/// (`\\?\C:\...`, `\\?\UNC\server\share\...`), which the tests are handed and which not every
/// program they start reads.
fn real_path(path: &Path) -> std::io::Result<PathBuf> {
    let real = std::fs::canonicalize(path)?;
    if cfg!(windows)
        && let Some(text) = real.to_str()
    {
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return Ok(PathBuf::from(format!(r"\\{rest}")));
        }
        if let Some(rest) = text.strip_prefix(r"\\?\")
            && rest.as_bytes().get(1) == Some(&b':')
        {
            return Ok(PathBuf::from(rest));
        }
    }
    Ok(real)
}

/// The real path `path` names, whether or not it exists yet: its longest existing ancestor
/// resolved through every link, and the rest of it after that.
fn resolve(path: &Path) -> std::io::Result<PathBuf> {
    let mut existing = PathBuf::new();
    let mut rest: Vec<Component<'_>> = Vec::new();
    for component in path.components() {
        if rest.is_empty() {
            let candidate = existing.join(component);
            // A drive or share and its root are the start of the path, not names to look for.
            let start = matches!(component, Component::Prefix(_) | Component::RootDir);
            if start || candidate.exists() {
                existing = candidate;
                continue;
            }
        }
        rest.push(component);
    }
    let mut real = real_path(&existing)?;
    for component in rest {
        if let Component::Normal(name) = component {
            real.push(name);
        }
    }
    Ok(real)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::process::Command;

    const CHILD: &str = "KR_TEST_ARTIFACTS_CASE_CHILD";

    fn temporary() -> tempfile::TempDir {
        tempfile::tempdir().expect("a directory under the temporary folder")
    }

    fn real(path: &Path) -> PathBuf {
        real_path(path).expect("resolves")
    }

    #[test]
    fn a_value_inside_a_root_is_accepted_whether_or_not_it_exists_yet() {
        let root = temporary();
        let roots = [real(root.path())];
        let inside = root.path().join("evidence").join("screenshots");
        assert_eq!(
            confine_in(&inside, &roots).expect("inside"),
            real(root.path()).join("evidence").join("screenshots")
        );
        std::fs::create_dir_all(&inside).expect("makes it");
        assert!(confine_in(&inside, &roots).is_ok());
    }

    #[test]
    fn a_value_outside_every_root_is_refused_in_words_that_name_the_variable_and_the_roots() {
        let root = temporary();
        let elsewhere = temporary();
        let roots = [real(root.path())];
        let refused = confine_in(&elsewhere.path().join("evidence"), &roots).expect_err("outside");
        let words = refused.to_string();
        assert!(words.contains(VARIABLE), "{words}");
        assert!(words.contains(&roots[0].display().to_string()), "{words}");
    }

    #[test]
    fn a_name_that_only_begins_like_a_root_is_outside_it() {
        let parent = temporary();
        let root = parent.path().join("tmp");
        let lookalike = parent.path().join("tmpfoo");
        std::fs::create_dir(&root).expect("makes the root");
        std::fs::create_dir(&lookalike).expect("makes the lookalike");
        let roots = [real(&root)];
        assert!(confine_in(&lookalike.join("evidence"), &roots).is_err());
        assert!(confine_in(&root.join("evidence"), &roots).is_ok());
    }

    #[test]
    fn the_root_itself_is_not_an_evidence_directory() {
        let root = temporary();
        assert!(confine_in(root.path(), &[real(root.path())]).is_err());
    }

    #[test]
    fn an_empty_value_a_relative_value_and_a_step_up_are_refused() {
        let root = temporary();
        let roots = [real(root.path())];
        let why = |value: &Path| confine_in(value, &roots).expect_err("refused").to_string();
        assert!(why(Path::new("")).contains("it is empty"));
        assert!(why(Path::new("kr-test-artifacts")).contains("not an absolute path"));
        assert!(why(Path::new("./evidence")).contains("not an absolute path"));
        let up = root.path().join("evidence").join("..").join("elsewhere");
        assert!(why(&up).contains("steps up a directory"));
    }

    #[cfg(unix)]
    #[test]
    fn a_root_behind_a_link_is_honoured_and_a_link_out_of_a_root_is_refused() {
        use std::os::unix::fs::symlink;
        let parent = temporary();
        let target = parent.path().join("target");
        let outside = parent.path().join("outside");
        std::fs::create_dir(&target).expect("makes the target");
        std::fs::create_dir(&outside).expect("makes the outside");
        let link = parent.path().join("link");
        symlink(&target, &link).expect("links the root");
        let roots = [real(&link)];
        assert!(confine_in(&link.join("evidence"), &roots).is_ok());
        assert!(confine_in(&target.join("evidence"), &roots).is_ok());
        symlink(&outside, target.join("leads-out")).expect("links out");
        let refused = confine_in(&link.join("leads-out").join("evidence"), &roots);
        assert!(refused.is_err(), "{refused:?}");
    }

    #[test]
    fn a_run_without_the_variable_gets_one_directory_that_exists() {
        let first = directory_from(None);
        assert!(first.is_dir(), "{}", first.display());
        assert_eq!(directory_from(None), first);
        assert_eq!(real(&first), first, "the directory is given resolved");
        assert!(confine(&first).is_ok());
        std::fs::remove_dir(&first).expect("removes the run's own directory");
    }

    /// Runs this test binary again with `value` as the variable (or none), as a program of its own,
    /// so that the variable is read from a real environment.
    fn read_in_a_run(value: Option<&OsStr>) -> std::process::Output {
        read_in_a_run_with(value, None, &[])
    }

    /// As [`read_in_a_run`], with `directory` as the program's working directory and `named` as
    /// further variables of its environment. The runner's temporary folder is not inherited: only
    /// a run that names it has one.
    fn read_in_a_run_with(
        value: Option<&OsStr>,
        directory: Option<&Path>,
        named: &[(&str, &OsStr)],
    ) -> std::process::Output {
        let mut run = Command::new(std::env::current_exe().expect("this program"));
        if let Some(directory) = directory {
            run.current_dir(directory);
        }
        run.args([
            "--exact",
            "tests::the_variable_is_read_in_a_run",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env_remove(VARIABLE)
        .env_remove("RUNNER_TEMP")
        .envs(named.iter().copied());
        if let Some(value) = value {
            run.env(VARIABLE, value);
        }
        run.output().expect("runs this program")
    }

    fn printed(output: &std::process::Output) -> PathBuf {
        // The test harness prints its own "test ... " prefix on the same line.
        let text = String::from_utf8_lossy(&output.stdout);
        let line = text
            .lines()
            .find_map(|line| line.split_once("directory=").map(|(_, rest)| rest))
            .unwrap_or_else(|| panic!("no directory line in {text}"));
        PathBuf::from(line)
    }

    #[test]
    fn the_variable_is_read_in_a_run() {
        if std::env::var_os(CHILD).is_some() {
            println!("directory={}", directory().display());
            return;
        }
        let root = temporary();
        let inside = root.path().join("evidence");
        let output = read_in_a_run(Some(inside.as_os_str()));
        assert!(output.status.success(), "{output:?}");
        assert_eq!(printed(&output), real(root.path()).join("evidence"));

        let elsewhere = Path::new(if cfg!(windows) { r"C:\Windows" } else { "/etc" });
        let output = read_in_a_run(Some(elsewhere.as_os_str()));
        assert!(!output.status.success(), "{output:?}");
        let words = String::from_utf8_lossy(&output.stderr);
        assert!(words.contains(VARIABLE), "{words}");
        assert!(words.contains("temporary roots"), "{words}");

        for refused in ["", "evidence", "/tmpfoo"] {
            let output = read_in_a_run(Some(OsStr::new(refused)));
            assert!(!output.status.success(), "{refused:?}: {output:?}");
        }

        // A relative name for the runner's temporary folder is no root, though it exists under the
        // working directory: this crate's own `src` folder is not a place for evidence.
        let source = std::env::current_dir()
            .expect("a working directory")
            .join("src");
        let output = read_in_a_run_with(
            Some(source.join("evidence").as_os_str()),
            None,
            &[("RUNNER_TEMP", OsStr::new("src"))],
        );
        assert!(!output.status.success(), "{output:?}");

        // A relative value that names a folder under the working directory, which is inside a
        // root, is still refused: the value has to be absolute.
        std::fs::create_dir(root.path().join("sub")).expect("makes a folder to name");
        let output = read_in_a_run_with(Some(OsStr::new("sub")), Some(root.path()), &[]);
        assert!(!output.status.success(), "{output:?}");
        let words = String::from_utf8_lossy(&output.stderr);
        assert!(words.contains("not an absolute path"), "{words}");

        let output = read_in_a_run(None);
        assert!(output.status.success(), "{output:?}");
        let own = printed(&output);
        assert!(own.is_dir(), "{}", own.display());
        std::fs::remove_dir(&own).expect("removes the run's own directory");
    }

    /// A folder beside this test program, which is outside every platform root.
    fn beside_the_build() -> tempfile::TempDir {
        let beside = std::env::current_exe().expect("this program");
        tempfile::Builder::new()
            .prefix("kr-test-artifacts-case-")
            .tempdir_in(beside.parent().expect("a folder"))
            .expect("a folder beside the build")
    }

    /// The words of a refusal of a backslash off Windows, the same in every reader.
    #[cfg(unix)]
    const BACKSLASH: &str = "a backslash is not taken in the folder's path on this platform";

    /// Off Windows a value that holds a backslash is refused before any other read of it, so that
    /// every reader returns the same folder or refuses: no reader can keep such a folder as
    /// written for the programs that read the variable after it.
    #[cfg(unix)]
    #[test]
    fn a_backslash_in_a_value_is_refused_off_windows() {
        let parent = temporary();
        let root = real(parent.path());
        std::os::unix::fs::symlink("/etc", root.join("out")).expect("a link out of the root");
        for value in [
            format!(r"{}/a\..\..\kr-letters", root.display()),
            format!(r"{}\a\..\..\kr-letters", root.display()),
            format!(r"{}/out\kr-evidence", root.display()),
            format!(r"{}/a\b", root.display()),
            r"\private\tmp\kr-evidence".to_owned(),
        ] {
            let refused = confine(Path::new(&value)).expect_err(&value).to_string();
            assert!(refused.contains(BACKSLASH), "{value}: {refused}");
        }
        assert!(!Path::new("/etc/kr-evidence").exists());
    }

    /// A temporary variable that holds a backslash is passed over as a root, and the run's own
    /// directory is made under the next root, `/tmp`.
    #[cfg(unix)]
    #[test]
    fn a_temporary_variable_with_a_backslash_is_passed_over_as_a_root_off_windows() {
        let parent = beside_the_build();
        let root = real(parent.path());
        let lettered = root.join("a\\b");
        std::fs::create_dir_all(&lettered).expect("a folder with a backslash in its name");
        std::fs::create_dir_all(root.join("a").join("b")).expect("the folder it reads as");
        std::os::unix::fs::symlink(&lettered, root.join("link")).expect("a link");
        let named = [("TMPDIR", lettered.as_os_str())];
        for value in [
            root.join("a").join("b").join("evidence"),
            root.join("link").join("evidence"),
        ] {
            let output = read_in_a_run_with(Some(value.as_os_str()), None, &named);
            assert!(!output.status.success(), "{value:?}: {output:?}");
            let words = String::from_utf8_lossy(&output.stderr);
            assert!(words.contains("not inside a temporary root"), "{words}");
            assert!(!words.contains("a\\b"), "a root that holds a backslash: {words}");
        }
        let output = read_in_a_run_with(None, None, &named);
        assert!(output.status.success(), "{output:?}");
        let own = printed(&output);
        assert_eq!(own.parent(), Some(real(Path::new("/tmp")).as_path()));
        std::fs::remove_dir(&own).expect("removes the run's own directory");
    }

    #[test]
    fn the_runners_temporary_folder_is_a_root_of_a_run_that_names_it_and_of_no_other() {
        let runner = beside_the_build();
        let inside = runner.path().join("evidence");
        let output = read_in_a_run_with(
            Some(inside.as_os_str()),
            None,
            &[("RUNNER_TEMP", runner.path().as_os_str())],
        );
        assert!(output.status.success(), "{output:?}");
        assert_eq!(printed(&output), real(runner.path()).join("evidence"));
        let output = read_in_a_run(Some(inside.as_os_str()));
        assert!(!output.status.success(), "{output:?}");
    }

    #[cfg(unix)]
    #[test]
    fn slash_tmp_is_a_root_where_the_temporary_folder_names_another() {
        let other = beside_the_build();
        let inside =
            Path::new("/tmp").join(format!("kr-test-artifacts-case-{}", std::process::id()));
        let output = read_in_a_run_with(
            Some(inside.as_os_str()),
            None,
            &[("TMPDIR", other.path().as_os_str())],
        );
        assert!(output.status.success(), "{output:?}");
    }

    #[test]
    fn a_temporary_folder_that_is_a_filesystem_root_admits_nothing_beside_the_other_roots() {
        let top = OsStr::new(if cfg!(windows) { r"C:\" } else { "/" });
        let elsewhere =
            Path::new(if cfg!(windows) { r"C:\Windows" } else { "/usr" }).join("kr-evidence");
        let output = read_in_a_run_with(
            Some(elsewhere.as_os_str()),
            None,
            &[
                ("TMPDIR", top),
                ("TEMP", top),
                ("TMP", top),
                ("RUNNER_TEMP", top),
            ],
        );
        assert!(!output.status.success(), "{output:?}");
        let words = String::from_utf8_lossy(&output.stderr);
        assert!(words.contains("temporary roots"), "{words}");
    }

    /// A temporary folder that is no root is left as it was: a run that sets no variable is
    /// refused before the directory of its own is made in it, and the words name that folder. The
    /// case reads through `directory`, as a program does. Off Unix there is no such folder: Windows
    /// makes a relative temporary folder absolute against the working directory, and a folder it
    /// names is a root.
    #[cfg(unix)]
    #[test]
    fn nothing_is_made_in_a_temporary_folder_that_is_no_root() {
        let working = temporary();
        let name = OsStr::new("kr-no-root");
        std::fs::create_dir(working.path().join(name)).expect("a folder");
        // A relative name is no root, though the folder exists under the working directory.
        let output = read_in_a_run_with(
            None,
            Some(working.path()),
            &[("TMPDIR", name), ("TEMP", name), ("TMP", name)],
        );
        assert!(!output.status.success(), "{output:?}");
        let words = String::from_utf8_lossy(&output.stderr);
        assert!(
            words.contains("kr-no-root") && words.contains("not an absolute path"),
            "the words do not name the temporary folder and why it is refused: {words}"
        );
        assert!(
            !words.contains("leave it unset"),
            "a run that set nothing is told to leave it unset: {words}"
        );
        let left = std::fs::read_dir(working.path().join(name))
            .expect("reads the folder")
            .count();
        assert_eq!(
            left, 0,
            "a refused temporary folder was left with a folder in it"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_directory_of_a_runs_own_is_readable_by_this_account_only() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = temporary();
        let own = make_own(temporary.path()).expect("makes a directory");
        let mode = std::fs::metadata(&own)
            .expect("reads it")
            .permissions()
            .mode();
        std::fs::remove_dir(&own).expect("removes it");
        assert_eq!(mode & 0o777, 0o700);
    }

    #[cfg(windows)]
    #[test]
    fn a_drive_folder_is_given_in_its_ordinary_form_and_an_extended_length_value_is_read() {
        let root = temporary();
        let real = real(root.path());
        let text = real.to_str().expect("text");
        assert!(!text.starts_with(r"\\?\"), "{text}");
        assert_eq!(text.as_bytes()[1], b':', "{text}");
        let extended = PathBuf::from(format!(r"\\?\{text}\evidence"));
        assert_eq!(
            confine_in(&extended, std::slice::from_ref(&real)).expect("inside"),
            real.join("evidence")
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_runner_folder_that_depends_on_the_current_drive_is_no_root() {
        let drive = Path::new(r"C:\");
        let value = Path::new(r"C:\Windows").join("kr-evidence");
        let output = read_in_a_run_with(
            Some(value.as_os_str()),
            Some(drive),
            &[("RUNNER_TEMP", OsStr::new(r"\Windows"))],
        );
        assert!(!output.status.success(), "{output:?}");
    }

    /// The table of spellings, the same in every reader: what each one is, whatever platform the
    /// test runs on.
    #[test]
    fn the_table_of_windows_spellings_is_read_as_it_is_in_every_reader() {
        use Spelling::{Kind, NotAbsolute, Taken};
        let table: &[(&str, Spelling)] = &[
            (r"C:\Users\x\Temp\evidence", Taken),
            ("c:/Users/x/Temp/evidence", Taken),
            (r"C:\Users/x\Temp/evidence", Taken),
            (r"\\server\share\evidence", Taken),
            ("//server/share/evidence", Taken),
            (r"\\server/share\evidence", Taken),
            (r"//server\share/evidence", Taken),
            (r"\\localhost\C$\Users\x", Taken),
            (r"\\?\C:\Users\x\Temp\evidence", Taken),
            (r"\\?\c:\Users\x", Taken),
            (r"\\?\UNC\server\share\evidence", Taken),
            (r"\\?\unc\server\share\evidence", Taken),
            (r"C:\", Taken),
            (r"\\?\C:\a/b", Kind),
            (r"\\?\UNC\server\share/b", Kind),
            (r"\\?\Volume{1234}\x", Kind),
            (r"\\?\C:", Kind),
            (r"\\?\UNC\server", Kind),
            (r"\\?\", Kind),
            (r"\\.\C:\Users\x", Kind),
            (r"\\.\pipe\x", Kind),
            ("//?/C:/Users/x", Kind),
            ("//./C:/Users/x", Kind),
            (r"\\.", Kind),
            (r"\\server", Kind),
            ("//server", Kind),
            ("//server/", Kind),
            (r"\\server\", Kind),
            (r"\\server\\share", Kind),
            ("///server/share/x", Kind),
            (r"\\\server\share\x", Kind),
            (r"\Windows\Temp", NotAbsolute),
            ("C:Windows", NotAbsolute),
            ("C:", NotAbsolute),
            (r"relative\x", NotAbsolute),
            ("./x", NotAbsolute),
            (r"/tmp/a\b\c", NotAbsolute),
            ("/c/Users/x/Temp", NotAbsolute),
            ("/", NotAbsolute),
        ];
        for (text, expected) in table {
            assert_eq!(windows_spelling(text), *expected, "{text}");
        }
    }

    /// A refusal that finds no root says so, and does not show an empty list.
    #[test]
    fn a_refusal_with_no_roots_says_that_there_are_none() {
        let refused = confine_in(&std::env::temp_dir().join("evidence"), &[]).expect_err("no root");
        let words = refused.to_string();
        assert!(
            words.contains("(none: no folder that a temporary variable names exists)"),
            "{words}"
        );
        assert!(!words.contains("()"), "{words}");
    }

    /// The spellings that a platform gives are one folder, whichever one the value is written in,
    /// and the extended-length form that Rust's own canonical path takes is read as the ordinary one.
    #[cfg(windows)]
    #[test]
    fn every_spelling_that_a_platform_gives_is_read_as_the_same_folder() {
        let root = temporary();
        let real = real(root.path());
        let text = real.to_str().expect("text").to_owned();
        let canonical = std::fs::canonicalize(&real).expect("canonical");
        assert!(
            canonical.to_str().expect("text").starts_with(r"\\?\"),
            "Rust's canonical path of a drive folder is its extended-length form: {canonical:?}"
        );
        let roots = [real.clone()];
        let written = [
            format!(r"{text}\evidence"),
            format!("{}/evidence", text.replace('\\', "/")),
            format!(r"{text}/evidence"),
            format!(r"{}\evidence", text.replacen('\\', "/", 1)),
            format!(r"\\?\{text}\evidence"),
        ];
        for value in written {
            assert_eq!(
                confine_in(Path::new(&value), &roots).expect(&value),
                real.join("evidence"),
                "{value}"
            );
        }
        for value in [
            format!(r"\\.\{text}\evidence"),
            format!(r"\\?\{text}\a/evidence"),
            format!("//?/{}/evidence", text.replace('\\', "/")),
        ] {
            let words = confine_in(Path::new(&value), &roots)
                .expect_err(&value)
                .to_string();
            assert!(
                words.contains("a kind this reader does not take"),
                "{words}"
            );
            assert!(words.contains("//server/share/folder"), "{words}");
        }
        for value in [
            format!(r"{text}\a\..\..\kr-evidence"),
            format!(r"{text}/a\..\kr-evidence"),
        ] {
            let words = confine_in(Path::new(&value), &roots)
                .expect_err(&value)
                .to_string();
            assert!(words.contains("steps up a directory"), "{words}");
        }
        for value in [r"\Windows\kr-evidence", "C:kr-evidence", "kr-evidence"] {
            let words = confine_in(Path::new(value), &roots)
                .expect_err(value)
                .to_string();
            assert!(
                words.contains("it is not an absolute path (on Windows"),
                "{words}"
            );
        }
    }

    /// A share is given in its ordinary form, as a drive is: the machine's own administrative share
    /// of the drive is the share, as in the other readers' cases.
    #[cfg(windows)]
    #[test]
    fn a_share_is_given_in_its_ordinary_form_and_every_spelling_of_it_is_read() {
        let root = temporary();
        let real = real(root.path());
        let text = real.to_str().expect("text").to_owned();
        let share = format!(r"\\localhost\{}${}", &text[..1], &text[2..]);
        if std::fs::metadata(&share).is_err() {
            assert!(
                std::env::var_os("CI").is_none(),
                "a hosted run reaches {share}, and it could not"
            );
            eprintln!("{share} cannot be reached here: the share case is not run");
            return;
        }
        let canonical = std::fs::canonicalize(&share).expect("canonical");
        assert!(
            canonical.to_str().expect("text").starts_with(r"\\?\UNC\"),
            "Rust's canonical path of a share folder is its extended-length form: {canonical:?}"
        );
        let ordinary = real_path(Path::new(&share)).expect("resolves");
        assert!(
            ordinary
                .to_str()
                .expect("text")
                .starts_with(r"\\localhost\"),
            "{ordinary:?}"
        );
        let roots = [ordinary.clone()];
        let slashes = share.replace('\\', "/");
        let written = [
            format!(r"{share}\evidence"),
            format!("{slashes}/evidence"),
            format!(
                r"{}\evidence",
                share.replacen(r"\\localhost\", r"\\localhost/", 1)
            ),
            format!(r"\\?\UNC\{}\evidence", &share[2..]),
        ];
        for value in written {
            assert_eq!(
                confine_in(Path::new(&value), &roots).expect(&value),
                ordinary.join("evidence"),
                "{value}"
            );
        }
        for value in [r"\\localhost", r"\\\localhost\x\evidence"] {
            let words = confine_in(Path::new(value), &roots)
                .expect_err(value)
                .to_string();
            assert!(
                words.contains("a kind this reader does not take"),
                "{words}"
            );
        }
    }
}
