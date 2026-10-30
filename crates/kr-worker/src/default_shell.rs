//! The shell a session starts when its create request names none.
//!
//! The request's own choice comes first and is never replaced. After it, the shell this host is
//! configured to use, and after that the platform's own. On Windows the platform's own is
//! PowerShell 7, the primary shell, found where it installs; Windows PowerShell and the command
//! interpreter are what a machine without it falls back to, in that order, so the shell a session
//! gets never depends on which of them the system's `ComSpec` happens to name. Each is named by an
//! absolute path.

use std::path::{Path, PathBuf};

/// Returns the shell a session starts: the request's, else the configured one, else the platform's.
#[must_use]
pub fn resolve(requested: Option<&str>) -> String {
    choose(requested, configured, platform_default)
}

/// The request's shell, else the configured one, else the platform's. The configured shell is
/// looked for only when the request names none: looking costs a file lookup, which may be a slow
/// one for a path that is on a network share.
fn choose(
    requested: Option<&str>,
    configured: impl FnOnce() -> Option<String>,
    platform: impl FnOnce() -> String,
) -> String {
    requested
        .map(str::to_owned)
        .or_else(configured)
        .unwrap_or_else(platform)
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
    /// The user's local application-data directory, which holds the Store's application
    /// execution aliases.
    pub local_app_data: Option<PathBuf>,
    /// The system directory, `%SystemRoot%`.
    pub system_root: Option<PathBuf>,
    /// The command interpreter the system names, `%ComSpec%`.
    pub command_interpreter: Option<String>,
}

impl WindowsPlaces {
    /// Reads the places from this process's environment.
    #[must_use]
    pub fn from_environment() -> Self {
        Self::from_variables(|name| std::env::var_os(name))
    }

    /// Reads the places from environment variables given by `get`.
    ///
    /// The system directory is the first of `SystemRoot` and `windir` that is an absolute path,
    /// so a variable that is set to a relative name does not hide the other.
    #[must_use]
    pub fn from_variables(get: impl Fn(&str) -> Option<std::ffi::OsString>) -> Self {
        let directory = |name: &str| get(name).map(PathBuf::from);
        Self {
            search_path: get("PATH")
                .map(|path| std::env::split_paths(&path).collect())
                .unwrap_or_default(),
            program_files: ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
                .into_iter()
                .filter_map(directory)
                .collect(),
            local_app_data: directory("LOCALAPPDATA"),
            system_root: ["SystemRoot", "windir"]
                .into_iter()
                .filter_map(directory)
                .find(|root| root.is_absolute()),
            command_interpreter: get("ComSpec").and_then(|value| value.into_string().ok()),
        }
    }
}

/// Returns the shell a Windows session starts when nothing names one.
///
/// PowerShell 7 comes first: the directory its installer uses, which names the version and which
/// an administrator owns, then a `pwsh.exe` on the search path where PowerShell 7 has a place of
/// its own (a preview's version directory, or the Store's application execution alias). Another
/// `pwsh.exe` on the search path is not PowerShell 7: PowerShell 6 has the same file name, and so
/// can a file in any directory the search path happens to hold. Windows PowerShell 5.1, which
/// every supported Windows has, is next. The command interpreter is the last resort, so a machine
/// that has either of the others never gets it.
///
/// Every program is named by an absolute path. The system looks for a bare or relative program name
/// in the worker's own directory first, so a search-path entry that is empty or relative is not
/// searched, and an interpreter the system names that is not an absolute path to a file that is
/// there is replaced by the system's own: a program placed in the worker's directory would
/// otherwise become the user's shell.
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
                .filter(|directory| holds_powershell_seven(directory, places))
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
                .as_deref()
                .map(Path::new)
                .filter(|interpreter| interpreter.is_absolute() && is_file(interpreter))
                .and_then(Path::to_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| system_command_interpreter(places))
}

/// The command interpreter in the system directory, by its absolute path.
///
/// Windows gives every process `%SystemRoot%`; one without it has lost its environment, and the
/// standard location is then the best name there is.
fn system_command_interpreter(places: &WindowsPlaces) -> String {
    places
        .system_root
        .as_deref()
        .filter(|root| root.is_absolute())
        .and_then(|root| {
            root.join("System32")
                .join("cmd.exe")
                .to_str()
                .map(str::to_owned)
        })
        .unwrap_or_else(|| r"C:\Windows\System32\cmd.exe".to_owned())
}

/// Whether a search-path directory is a place PowerShell 7 lives: a version-7 directory beside the
/// standard one under a program-files directory (`...\PowerShell\7-preview`), or the directory of
/// the Store's application execution aliases.
fn holds_powershell_seven(directory: &Path, places: &WindowsPlaces) -> bool {
    let version_directory = places.program_files.iter().any(|root| {
        directory
            .parent()
            .is_some_and(|parent| same_directory(parent, &root.join("PowerShell")))
            && directory
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| name.starts_with('7'))
    });
    let store_aliases = places
        .local_app_data
        .as_ref()
        .is_some_and(|root| same_directory(directory, &root.join("Microsoft").join("WindowsApps")));
    version_directory || store_aliases
}

/// Whether two paths name the same directory by their components. Windows folds the case of a name,
/// so a directory is the same one however a search path spells it.
fn same_directory(left: &Path, right: &Path) -> bool {
    let (mut left, mut right) = (left.components(), right.components());
    loop {
        match (left.next(), right.next()) {
            (None, None) => return true,
            (Some(first), Some(second))
                if first.as_os_str().eq_ignore_ascii_case(second.as_os_str()) => {}
            _ => return false,
        }
    }
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
            local_app_data: Some(absolute("Users").join("someone")),
            system_root: Some(absolute("System")),
            command_interpreter: Some(absolute("System").join("cmd.exe").display().to_string()),
        }
    }

    fn installed() -> PathBuf {
        absolute("Programs")
            .join("PowerShell")
            .join("7")
            .join("pwsh.exe")
    }

    /// A PowerShell 7 that is installed under its own version directory but is not the standard
    /// one, which is how a preview is laid out.
    fn preview() -> PathBuf {
        absolute("Programs")
            .join("PowerShell")
            .join("7-preview")
            .join("pwsh.exe")
    }

    /// The Store's application execution alias for PowerShell 7.
    fn store_alias() -> PathBuf {
        absolute("Users")
            .join("someone")
            .join("Microsoft")
            .join("WindowsApps")
            .join("pwsh.exe")
    }

    fn on_the_path(places: WindowsPlaces, file: &Path) -> WindowsPlaces {
        WindowsPlaces {
            search_path: vec![file.parent().expect("a directory").to_owned()],
            ..places
        }
    }

    fn five() -> PathBuf {
        absolute("System")
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe")
    }

    fn system_command_interpreter() -> String {
        absolute("System")
            .join("System32")
            .join("cmd.exe")
            .display()
            .to_string()
    }

    /// KR-REQ-03.03: a Windows session that names no shell starts PowerShell 7 when the machine
    /// has it, whichever way it is found, and not the command interpreter the system names.
    #[test]
    fn a_session_that_names_no_shell_gets_powershell_seven_when_the_machine_has_it() {
        assert_eq!(
            windows_default(
                &on_the_path(places(), &preview()),
                present(&[installed(), preview(), five()])
            ),
            installed().to_str().unwrap(),
            "the directory its installer uses is read first"
        );
        for found in [preview(), store_alias()] {
            assert_eq!(
                windows_default(
                    &on_the_path(places(), &found),
                    present(&[found.clone(), five()])
                ),
                found.to_str().unwrap(),
                "and then the search path where PowerShell 7 has a place of its own"
            );
        }
        let upper = PathBuf::from(
            preview()
                .parent()
                .expect("a directory")
                .display()
                .to_string()
                .to_uppercase(),
        )
        .join("pwsh.exe");
        assert_eq!(
            windows_default(
                &on_the_path(places(), &upper),
                present(&[upper.clone(), five()])
            ),
            upper.to_str().unwrap(),
            "a directory is the same directory whatever the case it is written in"
        );
    }

    /// KR-REQ-03.03: a `pwsh.exe` on the search path is the default shell only where PowerShell 7
    /// lives. PowerShell 6 has the same file name, and so has a file put in a directory that is
    /// on the search path for some other reason; neither comes before Windows PowerShell.
    #[test]
    fn a_pwsh_on_the_search_path_is_the_default_shell_only_where_powershell_seven_lives() {
        let six = absolute("Programs")
            .join("PowerShell")
            .join("6")
            .join("pwsh.exe");
        let elsewhere = absolute("Tools").join("pwsh.exe");
        let another_stores_alias = absolute("Other")
            .join("Microsoft")
            .join("WindowsApps")
            .join("pwsh.exe");
        let beside_the_seven = absolute("Programs")
            .join("PowerShell")
            .join("7-preview")
            .join("..")
            .join("..")
            .join("Evil")
            .join("pwsh.exe");
        // A directory whose name merely starts with a 7 is not PowerShell 7's, wherever it is: the
        // standard places are the program-files directory's `PowerShell` and the Store's own
        // alias directory, exactly, and nothing under or beside them.
        let seven_zip = absolute("Programs").join("7-Zip").join("pwsh.exe");
        let seven_tools = absolute("7-tools").join("pwsh.exe");
        let below_the_aliases = absolute("Users")
            .join("someone")
            .join("Microsoft")
            .join("WindowsApps")
            .join("sub")
            .join("pwsh.exe");
        for refused in [
            six,
            elsewhere,
            another_stores_alias,
            beside_the_seven,
            seven_zip,
            seven_tools,
            below_the_aliases,
        ] {
            assert_eq!(
                windows_default(
                    &on_the_path(places(), &refused),
                    present(&[refused.clone(), five()])
                ),
                five().to_str().unwrap(),
                "{} is not PowerShell 7",
                refused.display()
            );
        }
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
        assert_eq!(
            windows_default(&places(), present(&[PathBuf::from(&interpreter)])),
            interpreter,
            "the interpreter the system names, when it is a file that is there"
        );
    }

    /// KR-REQ-03.03: the command interpreter is named by its absolute path, never by a name the
    /// system searches for. The system's search starts in the worker's own directory, so a bare
    /// `cmd.exe`, a blank value or a relative one would start whatever is planted there.
    #[test]
    fn the_command_interpreter_is_always_an_absolute_path() {
        let named = |interpreter: Option<String>| WindowsPlaces {
            command_interpreter: interpreter,
            ..places()
        };
        for refused in [
            None,
            Some(String::new()),
            Some("   ".to_owned()),
            Some("cmd.exe".to_owned()),
            Some(r".\planted.exe".to_owned()),
            Some(absolute("Missing").join("cmd.exe").display().to_string()),
        ] {
            let chosen = windows_default(&named(refused.clone()), present(&[]));
            assert_eq!(
                chosen,
                system_command_interpreter(),
                "the system's own interpreter, not {refused:?}"
            );
            assert!(Path::new(&chosen).is_absolute(), "{chosen}");
        }
        let nothing_named = WindowsPlaces {
            system_root: None,
            command_interpreter: None,
            ..places()
        };
        assert_eq!(
            windows_default(&nothing_named, present(&[])),
            r"C:\Windows\System32\cmd.exe",
            "a system that names no directory of its own still gets the standard one"
        );
    }

    /// KR-REQ-03.03: a command interpreter that is a relative name is not taken even when a file by
    /// that name is there, and the interpreter the system names never comes before PowerShell.
    #[test]
    fn the_interpreter_the_system_names_is_taken_only_as_the_last_resort_and_only_by_a_full_path() {
        let relative = |interpreter: &str| WindowsPlaces {
            command_interpreter: Some(interpreter.to_owned()),
            ..places()
        };
        for value in [r".\planted.exe", "cmd.exe", "planted.exe"] {
            assert_eq!(
                windows_default(&relative(value), present(&[PathBuf::from(value)])),
                system_command_interpreter(),
                "{value} is a file that is there, and it is not a full path"
            );
        }
        let interpreter = PathBuf::from(places().command_interpreter.expect("one is named"));
        for powershell in [installed(), five()] {
            assert_eq!(
                windows_default(
                    &places(),
                    present(&[interpreter.clone(), powershell.clone()])
                ),
                powershell.to_str().unwrap(),
                "the interpreter the system names comes after PowerShell"
            );
        }
        let relative_root = WindowsPlaces {
            system_root: Some(PathBuf::from("System")),
            command_interpreter: None,
            ..places()
        };
        let relative_five = PathBuf::from("System")
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        assert_eq!(
            windows_default(&relative_root, present(&[relative_five])),
            r"C:\Windows\System32\cmd.exe",
            "a relative system directory is neither searched nor used for the interpreter"
        );
    }

    /// KR-REQ-03.03: the system directory is the first of `SystemRoot` and `windir` that is an
    /// absolute path.
    #[test]
    fn the_system_directory_is_read_from_the_first_absolute_variable() {
        let variables = |pairs: Vec<(&'static str, PathBuf)>| {
            WindowsPlaces::from_variables(move |name| {
                pairs
                    .iter()
                    .find(|(candidate, _)| *candidate == name)
                    .map(|(_, value)| value.clone().into_os_string())
            })
        };
        let root = absolute("Real");
        assert_eq!(
            variables(vec![("windir", root.clone())]).system_root,
            Some(root.clone()),
            "windir stands in for a SystemRoot that is not set"
        );
        assert_eq!(
            variables(vec![
                ("SystemRoot", PathBuf::from("relative")),
                ("windir", root.clone())
            ])
            .system_root,
            Some(root.clone()),
            "a relative SystemRoot does not stop windir being read"
        );
        assert_eq!(
            variables(vec![("SystemRoot", PathBuf::from("relative"))]).system_root,
            None
        );
        assert_eq!(
            variables(vec![("SystemRoot", absolute("Other")), ("windir", root)]).system_root,
            Some(absolute("Other")),
            "SystemRoot comes first"
        );
    }

    /// The shell a session starts is the request's, else the configured one, else the platform's.
    #[test]
    fn a_request_names_the_shell_before_the_configured_one_and_that_before_the_platforms() {
        let platform = || "/platform/shell".to_owned();
        let configured = || Some("/configured".to_owned());
        assert_eq!(
            choose(Some("/requested"), configured, platform),
            "/requested"
        );
        assert_eq!(choose(None, configured, platform), "/configured");
        assert_eq!(choose(None, || None, platform), "/platform/shell");
        let looked = std::cell::Cell::new(false);
        choose(
            Some("/requested"),
            || {
                looked.set(true);
                None
            },
            platform,
        );
        assert!(
            !looked.get(),
            "a request that names a shell does not look for the configured one"
        );
        assert_eq!(
            resolve(Some("/requested/shell")),
            "/requested/shell",
            "whatever this machine is configured to use, a request's shell is the one started"
        );
    }

    /// KR-REQ-03.03: an empty or relative search-path entry is not the directory the worker runs
    /// in, so a program planted there is not the user's shell, even where the entry would be
    /// PowerShell 7's own if it were absolute.
    #[test]
    fn a_relative_search_path_entry_is_not_searched() {
        let relative = PathBuf::from("planted");
        let planted = relative.join("pwsh.exe");
        let relative_seven = PathBuf::from("Programs")
            .join("PowerShell")
            .join("7-preview")
            .join("pwsh.exe");
        let places = WindowsPlaces {
            search_path: vec![
                PathBuf::new(),
                relative,
                PathBuf::from("."),
                relative_seven.parent().expect("a directory").to_owned(),
            ],
            program_files: vec![PathBuf::from("Programs")],
            ..places()
        };
        let in_the_current_directory = Path::new(".").join("pwsh.exe");
        assert_eq!(
            windows_default(&places, |path| path == planted
                || path == relative_seven
                || path == Path::new("pwsh.exe")
                || path == in_the_current_directory),
            system_command_interpreter()
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
