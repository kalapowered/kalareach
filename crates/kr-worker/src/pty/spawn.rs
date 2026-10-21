//! Starting the root shell on a Unix terminal without reading a path once the start is admitted.
//!
//! A start can be held to a moment: past it, no process is created. That is only as true as what
//! stands between the last look at the clock and the process. The terminal library looks again at
//! the directory it is given, and starts the shell in the account's home directory when it is not
//! there, so a directory that went in between would run the shell somewhere nobody chose, and a
//! look that waited on a mount would carry the start past its moment. So the directory is opened
//! here, before the clock is read, and the shell is started in the directory that was opened: the
//! child changes into the descriptor, and no path is read between the last admission and the
//! process.
//!
//! The program is not looked at before the start: the operating system looks it up as it runs it,
//! and a program that cannot be run is reported by the start, as an error of the process that
//! would have run it.
//!
//! The shell is to have the terminal and nothing else of the worker's descriptors. Every descriptor
//! the child holds is marked to close when the shell is run ([`kr_ipc::inheritance`]), found in the
//! child itself at the moment it is made, so that nothing the worker opened, whenever and above
//! whatever limit, is missed. Where the system cannot give the list, the start fails; only a Unix
//! system this does not ship on is walked as far as its soft limit instead, and says so where it
//! is.

#![expect(
    unsafe_code,
    reason = "running code in the child between the fork and the exec has no safe form"
)]

use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt as _;

use super::ShellCommand;

/// What a start reads from the file system, read before the start is admitted.
#[derive(Debug)]
pub(super) struct Reads {
    /// Whether the directory the command names was there.
    named_is_there: bool,
    /// The directory the shell starts in: the named one, or the account's home where that was not
    /// there, as the terminal library started a shell in one it could not find. A directory that
    /// is there and cannot be entered is not replaced: the start fails with the reason.
    opened: std::io::Result<OwnedFd>,
    /// What the child needs to find its descriptors, made here because the child cannot make it.
    room: kr_ipc::inheritance::TableRoom,
}

impl Reads {
    /// Opens the directory `command` names, or the account's home directory where there is no
    /// such directory: the `HOME` of the environment the shell is given, else the home directory
    /// the account database names, else the root.
    pub(super) fn read(command: &ShellCommand) -> Self {
        let named = std::path::Path::new(&command.cwd);
        let (named_is_there, opened) = match open_directory(named) {
            Ok(opened) => (true, Ok(opened)),
            // A directory that is there and cannot be entered is a start that fails, as it was
            // when the terminal library found it with a look and failed to change into it.
            Err(error) if named.is_dir() => (true, Err(error)),
            Err(_) => {
                let home: std::path::PathBuf = command
                    .environment
                    .iter()
                    .find_map(|(name, value)| (name == "HOME").then(|| value.into()))
                    .or_else(|| {
                        kr_ipc::paths::passwd_entry()
                            .and_then(|entry| entry.home)
                            .map(Into::into)
                    })
                    .unwrap_or_else(|| "/".into());
                (false, open_directory(&home))
            }
        };
        Self {
            named_is_there,
            opened,
            room: kr_ipc::inheritance::TableRoom::make(),
        }
    }

    /// Whether the directory the command names was there.
    pub(super) const fn named_is_there(&self) -> bool {
        self.named_is_there
    }
}

/// Opens a directory for the one thing the start does with it, which is to enter it.
///
/// Entering a directory needs the right to search it and not the right to list it, so it is not
/// opened for reading: a directory that can be entered and not listed is one a shell can start in.
fn open_directory(path: &std::path::Path) -> std::io::Result<OwnedFd> {
    #[cfg(target_os = "linux")]
    let open = rustix::fs::OFlags::PATH;
    #[cfg(target_vendor = "apple")]
    let open = rustix::fs::OFlags::from_bits_retain(libc::O_SEARCH as _);
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    let open = rustix::fs::OFlags::RDONLY;
    rustix::fs::open(
        path,
        open | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(Into::into)
}

/// Starts `command` on `terminal` in `directory`, as a session leader with the terminal for its
/// controlling terminal, and with nothing of the worker's descriptors but the terminal.
///
/// # Errors
///
/// Returns the operating system's error when the directory could not be opened, or the process
/// could not be started, a program that cannot be run included.
pub(super) fn start(
    terminal: &OwnedFd,
    reads: Reads,
    command: &ShellCommand,
) -> std::io::Result<std::process::Child> {
    let directory = reads.opened?;
    let mut room = reads.room;
    let mut process = std::process::Command::new(&command.program);
    process
        .args(&command.arguments)
        .env_clear()
        .envs(
            command
                .environment
                .iter()
                .map(|(name, value)| (name, value)),
        )
        .stdin(terminal.try_clone()?)
        .stdout(terminal.try_clone()?)
        .stderr(terminal.try_clone()?);
    // SAFETY: the closure runs in the child between the fork and the exec, which in a process with
    // other threads allows only what is safe to call from a signal handler. It calls system calls
    // and nothing that allocates or takes a lock, and it touches nothing the parent's threads hold.
    unsafe {
        process.pre_exec(move || {
            // Nothing the worker ignores or blocks is ignored or blocked in the shell.
            for signal in [
                libc::SIGCHLD,
                libc::SIGHUP,
                libc::SIGINT,
                libc::SIGQUIT,
                libc::SIGTERM,
                libc::SIGALRM,
            ] {
                libc::signal(signal, libc::SIG_DFL);
            }
            let mut none = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
            libc::sigemptyset(none.as_mut_ptr());
            libc::sigprocmask(libc::SIG_SETMASK, none.as_ptr(), std::ptr::null_mut());

            // A session of its own, and the terminal on standard input as its controlling one.
            rustix::process::setsid()?;
            // SAFETY: descriptor 0 is the terminal, which the standard library has put there
            // before this runs, and it stays open for the whole of the closure.
            let standard_input = std::os::fd::BorrowedFd::borrow_raw(0);
            rustix::process::ioctl_tiocsctty(standard_input)?;
            // The directory that was opened, not a path to it.
            rustix::process::fchdir(&directory)?;
            kr_ipc::inheritance::mark_close_on_exec(&mut room)
        });
    }
    process.spawn()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A missing directory falls back to the home directory the environment names, and a directory
    /// that is there does not.
    #[test]
    fn a_missing_directory_falls_back_to_the_home_directory_and_one_that_is_there_does_not() {
        use std::os::unix::fs::MetadataExt as _;

        let host = kr_ipc::testing::TempHost::create();
        let home = host.root().join("home");
        std::fs::create_dir(&home).expect("the home directory");
        let mut command = crate::testing::posix_script("exit 0");
        command
            .environment
            .push(("HOME".to_owned(), home.display().to_string()));
        command.cwd = host.root().join("not-there").display().to_string();
        let missing = Reads::read(&command);
        assert!(!missing.named_is_there());
        let opened = std::fs::File::from(missing.opened.expect("the home directory opens"));
        let home = std::fs::metadata(&home).expect("the home directory is there");
        let found = opened.metadata().expect("what was opened");
        assert_eq!(
            (found.dev(), found.ino()),
            (home.dev(), home.ino()),
            "it is the home directory the environment names that was opened"
        );
        command.cwd = host.root().display().to_string();
        assert!(Reads::read(&command).named_is_there());
    }
}
