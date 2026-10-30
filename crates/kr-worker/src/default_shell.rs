//! The shell a session starts when its create request names none.
//!
//! The request's own choice comes first and is never replaced. After it, the shell this host is
//! configured to use, and after that the platform's own. On Windows the platform's own is
//! PowerShell 7, the primary shell; Windows PowerShell and the command interpreter are what a
//! machine without it falls back to, in that order, so the shell a session gets never depends on
//! which of them the system's `ComSpec` happens to name.

use std::path::{Path, PathBuf};

/// Returns the shell a session starts: the request's, else the configured one, else the platform's.
#[must_use]
pub fn resolve(requested: Option<&str>) -> String {
    requested
        .map(str::to_owned)
        .or_else(configured)
        .unwrap_or_else(platform_default)
}

/// The shell this host is configured to launch when a request names none.
///
/// The operating system's own record of the user's shell is what a login uses, so it is what a
/// session uses too. A value that names nothing runnable is ignored rather than launched.
#[must_use]
pub fn configured() -> Option<String> {
    named_shell(&std::env::var("SHELL").ok()?)
}

/// The shell a configured value names: an absolute path to a file, and nothing else. A relative
/// value would name a file in whatever directory the worker happens to run in.
fn named_shell(value: &str) -> Option<String> {
    let path = Path::new(value.trim());
    (path.is_absolute() && path.is_file())
        .then(|| path.to_str().map(str::to_owned))
        .flatten()
}

/// The shell a platform falls back to when nothing else names one.
#[must_use]
pub fn platform_default() -> String {
    #[cfg(target_vendor = "apple")]
    {
        "/bin/zsh".to_owned()
    }
    #[cfg(all(unix, not(target_vendor = "apple")))]
    {
        "/bin/bash".to_owned()
    }
    #[cfg(not(unix))]
    {
        windows_default(&WindowsPlaces::from_environment(), launchable)
    }
}

/// Whether a Windows program can be started from this path.
///
/// PowerShell 7 installed from the Store appears on the search path as an application execution
/// alias. Opening one fails, so a test that opens the file calls it missing; the entry itself is
/// a file the system starts, so the entry is read when the file cannot be.
#[cfg(not(unix))]
fn launchable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
        || std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
}

/// Where the Windows default shell is looked for.
#[derive(Clone, Debug, Default)]
pub struct WindowsPlaces {
    /// The directories of the search path, in order.
    pub search_path: Vec<PathBuf>,
    /// The program-files directories PowerShell 7 installs under.
    pub program_files: Vec<PathBuf>,
    /// The system directory, `%SystemRoot%`.
    pub system_root: Option<PathBuf>,
    /// The command interpreter the system names, `%ComSpec%`.
    pub command_interpreter: Option<String>,
}

impl WindowsPlaces {
    /// Reads the places from this process's environment.
    #[must_use]
    pub fn from_environment() -> Self {
        let directory = |name: &str| std::env::var_os(name).map(PathBuf::from);
        Self {
            search_path: std::env::var_os("PATH")
                .map(|path| std::env::split_paths(&path).collect())
                .unwrap_or_default(),
            program_files: ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
                .into_iter()
                .filter_map(directory)
                .collect(),
            system_root: directory("SystemRoot"),
            command_interpreter: std::env::var("ComSpec").ok(),
        }
    }
}

/// Returns the shell a Windows session starts when nothing names one.
///
/// PowerShell 7 comes first: the directory its installer uses, which names the version and which
/// an administrator owns, then `pwsh.exe` on the search path for an installation elsewhere (a
/// per-user one). Windows PowerShell 5.1, which every supported Windows has, is next, and the command
/// interpreter is the last resort, so a machine that has either of the others never gets it.
/// A search-path entry that is empty or relative is not searched: it would name the directory the
/// worker happens to run in, and a program placed there would become the user's shell.
#[must_use]
pub fn windows_default(places: &WindowsPlaces, is_file: impl Fn(&Path) -> bool) -> String {
    let seven = places
        .program_files
        .iter()
        .map(|directory| directory.join("PowerShell").join("7").join("pwsh.exe"))
        .chain(
            places
                .search_path
                .iter()
                .map(|directory| directory.join("pwsh.exe")),
        );
    let five = places.system_root.iter().map(|root| {
        root.join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe")
    });
    // A candidate that is not text cannot be named in a create request, so it is not one.
    seven
        .chain(five)
        .filter(|candidate| candidate.is_absolute() && is_file(candidate))
        .find_map(|candidate| candidate.to_str().map(str::to_owned))
        .or_else(|| {
            places
                .command_interpreter
                .clone()
                .filter(|interpreter| !interpreter.is_empty())
        })
        .unwrap_or_else(|| "cmd.exe".to_owned())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// A directory that is absolute on the platform the test runs on.
    fn absolute(name: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!(r"C:\{name}"))
        } else {
            PathBuf::from(format!("/{name}"))
        }
    }

    fn present(files: &[PathBuf]) -> impl Fn(&Path) -> bool {
        let files: HashSet<PathBuf> = files.iter().cloned().collect();
        move |path| files.contains(path)
    }

    fn places() -> WindowsPlaces {
        WindowsPlaces {
            search_path: vec![absolute("Tools"), absolute("Other")],
            program_files: vec![absolute("Programs")],
            system_root: Some(absolute("System")),
            command_interpreter: Some(absolute("System").join("cmd.exe").display().to_string()),
        }
    }

    fn seven_on_the_path() -> PathBuf {
        absolute("Other").join("pwsh.exe")
    }

    fn seven_installed() -> PathBuf {
        absolute("Programs")
            .join("PowerShell")
            .join("7")
            .join("pwsh.exe")
    }

    fn five() -> PathBuf {
        absolute("System")
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe")
    }

    /// KR-REQ-03.03: a Windows session that names no shell starts PowerShell 7 when the machine
    /// has it, whichever way it is found, and not the command interpreter the system names.
    #[test]
    fn a_session_that_names_no_shell_gets_powershell_seven_when_the_machine_has_it() {
        let everything = [seven_on_the_path(), seven_installed(), five()];
        assert_eq!(
            windows_default(&places(), present(&everything)),
            seven_installed().to_str().unwrap(),
            "the directory its installer uses is read first"
        );
        assert_eq!(
            windows_default(&places(), present(&[seven_on_the_path(), five()])),
            seven_on_the_path().to_str().unwrap(),
            "and then the search path, for an installation elsewhere"
        );
    }

    /// KR-REQ-03.03: without PowerShell 7 the fallback is Windows PowerShell, and the command
    /// interpreter only when neither is there.
    #[test]
    fn the_fallbacks_are_windows_powershell_and_then_the_command_interpreter() {
        assert_eq!(
            windows_default(&places(), present(&[five()])),
            five().to_str().unwrap()
        );
        let interpreter = places().command_interpreter.expect("the places name one");
        assert_eq!(windows_default(&places(), present(&[])), interpreter);
        assert_eq!(
            windows_default(
                &WindowsPlaces {
                    command_interpreter: None,
                    ..places()
                },
                present(&[])
            ),
            "cmd.exe",
            "a system that names no interpreter still gets one"
        );
    }

    /// KR-REQ-03.03: an empty or relative search-path entry is not the directory the worker runs
    /// in, so a program planted there is not the user's shell.
    #[test]
    fn a_relative_search_path_entry_is_not_searched() {
        let relative = PathBuf::from("planted");
        let planted = relative.join("pwsh.exe");
        let places = WindowsPlaces {
            search_path: vec![PathBuf::new(), relative, PathBuf::from(".")],
            ..places()
        };
        let in_the_current_directory = Path::new(".").join("pwsh.exe");
        assert_eq!(
            windows_default(&places, |path| path == planted
                || path == Path::new("pwsh.exe")
                || path == in_the_current_directory),
            places.command_interpreter.expect("the places name one")
        );
    }

    /// A configured shell is an absolute path to a file: a relative one would name whatever the
    /// worker's current directory holds.
    #[test]
    fn a_configured_shell_is_an_absolute_path_to_a_file() {
        let this_program = std::env::current_exe().expect("this test's program");
        assert_eq!(
            named_shell(this_program.to_str().expect("text")),
            this_program.to_str().map(str::to_owned)
        );
        // Cargo runs a crate's unit cases in the crate's directory, where its manifest is a file
        // a relative name reaches.
        assert!(
            Path::new("Cargo.toml").is_file(),
            "the case needs a file the current directory holds"
        );
        assert_eq!(
            named_shell("Cargo.toml"),
            None,
            "a relative name for a file that is there"
        );
        assert_eq!(named_shell(""), None, "nothing");
        assert_eq!(
            named_shell(
                this_program
                    .parent()
                    .expect("a directory")
                    .to_str()
                    .expect("text")
            ),
            None,
            "a directory"
        );
    }
}
