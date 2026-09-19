//! The shell a test drives, on whichever machine the test is running on.
//!
//! A worker's own behaviour - the terminal it creates, what it drains, what it owns, what it
//! closes - is the same whatever runs inside the terminal. The tests that check it need a program
//! that prints, echoes and waits on demand, and they have always spelled that as a POSIX script
//! given to `/bin/sh`. Windows has no such path, so every one of those tests failed there at the
//! launch rather than at anything it meant to check.
//!
//! So the script stays and the interpreter is resolved per machine. On Unix it is `/bin/sh`. On
//! Windows it is the POSIX shell Git for Windows installs, which is a prerequisite of the Windows
//! test machine and ships with the GitHub-hosted Windows runners; `docs/host/README.md` says so.
//! A machine without one fails loudly rather than skipping quietly, because a suite that says it
//! passed while running nothing is worse than one that says what it is missing.
//!
//! What this module is *not* is the Windows qualification. A POSIX script proves that the
//! pseudo-console carries a console application's bytes; it says nothing about PowerShell, the
//! shell the product actually launches there. That is `crates/kr-worker/tests/windows.rs`, which
//! drives PowerShell 7 itself.

use crate::pty::ShellCommand;

/// The environment every test shell is given.
///
/// `TERM` because the engine reads it, an empty `PS1` because a prompt in the output would be
/// noise in an assertion, and a `PATH` that finds the utilities the scripts use.
fn environment() -> Vec<(String, String)> {
    let mut environment = vec![
        ("TERM".to_owned(), "xterm-256color".to_owned()),
        ("PS1".to_owned(), String::new()),
    ];
    environment.push(("PATH".to_owned(), search_path()));
    environment
}

/// Builds the command that runs one POSIX script as a session's root shell.
///
/// # Panics
///
/// Panics when this machine has no POSIX shell, naming what to install. A test that quietly did
/// nothing instead would report a pass it never earned.
#[must_use]
pub fn posix_script(script: &str) -> ShellCommand {
    ShellCommand {
        program: posix_shell(),
        arguments: vec!["-c".to_owned(), script.to_owned()],
        cwd: working_directory(),
        environment: environment(),
    }
}

/// Returns the path of this machine's POSIX shell.
///
/// # Panics
///
/// Panics when there is none, naming what to install.
#[must_use]
pub fn posix_shell() -> String {
    find_posix_shell().unwrap_or_else(|| {
        panic!(
            "this machine has no POSIX shell to run a test script with. On Windows the one these \
             tests use is the shell Git for Windows installs, at \
             C:\\Program Files\\Git\\usr\\bin\\sh.exe; install Git for Windows or put an sh.exe \
             on PATH. See docs/host/README.md."
        )
    })
}

#[cfg(unix)]
fn find_posix_shell() -> Option<String> {
    std::path::Path::new("/bin/sh")
        .exists()
        .then(|| "/bin/sh".to_owned())
}

/// Finds the POSIX shell Git for Windows installs.
///
/// Its own directory is deliberately *not* put on `PATH`: it holds Unix-named utilities that
/// shadow Windows ones, and a session that inherited it would not be the session the product
/// creates. The shell finds its own utilities through the path its `PATH` carries.
#[cfg(windows)]
fn find_posix_shell() -> Option<String> {
    for root in windows_git_roots() {
        let candidate = root.join("usr").join("bin").join("sh.exe");
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    which_on_path("sh.exe")
}

/// The places Git for Windows installs itself.
#[cfg(windows)]
fn windows_git_roots() -> Vec<std::path::PathBuf> {
    let mut roots = Vec::new();
    // The command line's own `git.exe` is the most direct answer: its parent is `<root>\cmd` or
    // `<root>\bin`, so the root is one level above that.
    if let Some(git) = which_on_path("git.exe")
        && let Some(root) = std::path::Path::new(&git)
            .parent()
            .and_then(std::path::Path::parent)
    {
        roots.push(root.to_path_buf());
    }
    for variable in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        if let Some(base) = std::env::var_os(variable) {
            roots.push(std::path::Path::new(&base).join("Git"));
            roots.push(std::path::Path::new(&base).join("Programs").join("Git"));
        }
    }
    roots
}

/// Returns the first `name` on this process's `PATH`.
#[cfg(windows)]
fn which_on_path(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .map(|candidate| candidate.to_string_lossy().into_owned())
}

/// The `PATH` a test shell is given.
#[cfg(unix)]
fn search_path() -> String {
    "/usr/bin:/bin".to_owned()
}

/// The `PATH` a test shell is given.
///
/// The POSIX shell's own utility directory, because a script that calls `printf` or `stty` has to
/// find one, followed by the system directory so that a script can still reach a Windows program.
#[cfg(windows)]
fn search_path() -> String {
    let mut directories: Vec<std::path::PathBuf> = Vec::new();
    for root in windows_git_roots() {
        let utilities = root.join("usr").join("bin");
        if utilities.is_dir() && !directories.contains(&utilities) {
            directories.push(utilities);
        }
    }
    if let Some(root) = std::env::var_os("SystemRoot") {
        directories.push(std::path::Path::new(&root).join("System32"));
    }
    std::env::join_paths(directories).map_or_else(
        |_| String::new(),
        |joined| joined.to_string_lossy().into_owned(),
    )
}

/// The directory a test shell starts in.
#[cfg(unix)]
fn working_directory() -> String {
    "/".to_owned()
}

/// The directory a test shell starts in.
///
/// The system drive's root, which is the nearest thing this platform has to `/`: it exists, it is
/// readable, and it is not the build tree.
#[cfg(windows)]
fn working_directory() -> String {
    std::env::var("SystemDrive").map_or_else(|_| "C:\\".to_owned(), |drive| format!("{drive}\\"))
}

/// Builds the command that runs one PowerShell command as a session's root shell.
///
/// PowerShell 7 is the shell this product launches on Windows, so a test about *that* shell asks
/// for it by name rather than taking whatever `powershell` resolves to, which is Windows
/// PowerShell 5.1 and a different reader with a different module.
///
/// # Panics
///
/// Panics when PowerShell 7 is not installed, naming what to install.
#[cfg(windows)]
#[must_use]
pub fn powershell_command(command: &str) -> ShellCommand {
    ShellCommand {
        program: powershell(),
        arguments: vec![
            "-NoLogo".to_owned(),
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-Command".to_owned(),
            command.to_owned(),
        ],
        cwd: working_directory(),
        environment: environment(),
    }
}

/// Returns the path of PowerShell 7.
///
/// # Panics
///
/// Panics when it is not installed, naming what to install.
#[cfg(windows)]
#[must_use]
pub fn powershell() -> String {
    find_powershell().unwrap_or_else(|| {
        panic!(
            "PowerShell 7 is not installed on this machine. It is the shell this product launches \
             on Windows and the one these tests qualify; install it from \
             https://aka.ms/powershell or with `winget install Microsoft.PowerShell`. See \
             docs/host/README.md."
        )
    })
}

#[cfg(windows)]
fn find_powershell() -> Option<String> {
    if let Some(found) = which_on_path("pwsh.exe") {
        return Some(found);
    }
    for variable in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(base) = std::env::var_os(variable) {
            let candidate = std::path::Path::new(&base)
                .join("PowerShell")
                .join("7")
                .join("pwsh.exe");
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_machine_has_a_posix_shell_to_run_a_script_with() {
        // The message is the point: a machine without one is told what to install rather than
        // left with a suite that passed by doing nothing.
        let shell = posix_shell();
        assert!(
            std::path::Path::new(&shell).exists(),
            "{shell} is a path that exists"
        );
    }

    #[test]
    fn a_script_shell_starts_in_a_directory_that_is_not_the_build_tree() {
        let command = posix_script("exit 0");
        let cwd = std::path::Path::new(&command.cwd);
        assert!(cwd.is_dir(), "{} is a directory", command.cwd);
        assert_ne!(
            std::env::current_dir().ok().as_deref(),
            Some(cwd),
            "a session never starts where the test process is building"
        );
        assert!(
            command
                .environment
                .iter()
                .any(|(name, value)| name == "PATH" && !value.is_empty()),
            "a script can find the utilities it calls"
        );
    }
}
