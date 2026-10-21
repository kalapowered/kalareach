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
//! The shell is to have the terminal and nothing else of the worker's descriptors. Which ones the
//! worker has open is read with the directory, before the start is admitted, and they are marked
//! to close when the shell is run.

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
    /// The highest descriptor the worker has open, where the system lists them.
    highest_descriptor: Option<libc::c_int>,
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
            highest_descriptor: highest_descriptor(),
        }
    }

    /// Whether the directory the command names was there.
    pub(super) const fn named_is_there(&self) -> bool {
        self.named_is_there
    }
}

/// The highest descriptor this process has open, from the system's list of them.
fn highest_descriptor() -> Option<libc::c_int> {
    std::fs::read_dir("/dev/fd")
        .ok()?
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .max()
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

/// Marks every descriptor above the standard three to close when the shell is run, so that the
/// shell has the terminal and nothing else of the worker's.
///
/// A descriptor is marked rather than closed, because the channel the standard library reports a
/// failed run through is among them: it is already marked, and closed by a good run, and it has to
/// be open for a failed one to be reported.
///
/// Linux marks them all in one call from kernel 5.11. Where it cannot, and on the other systems,
/// the descriptors up to the highest one the worker was found to have open, and a few above it for
/// any opened since, are marked one by one; where the system lists none, those below the soft
/// limit on descriptors, and never more than [`MOST_WALKED`] of them. A descriptor that is not
/// open is refused by the call, which is the only way it can fail, and there is nothing to be done
/// about that in the child.
///
/// This allocates nothing and calls only system calls, as it has to between the fork and the run.
fn mark_close_on_exec(highest_open: Option<libc::c_int>) {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: the call takes no pointer, and marks descriptors of this process only.
        let marked = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3 as libc::c_uint,
                libc::c_uint::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        };
        if marked == 0 {
            return;
        }
    }
    let end = match highest_open {
        Some(highest) => highest.saturating_add(OPENED_SINCE),
        None => {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: `limit` is this function's own and outlives the call.
            let known = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } == 0;
            let walked = if known {
                limit.rlim_cur.min(MOST_WALKED)
            } else {
                MOST_WALKED
            };
            libc::c_int::try_from(walked).unwrap_or(libc::c_int::MAX)
        }
    };
    mark_range_close_on_exec(3, end);
}

/// The most descriptors walked one by one where the system lists none.
const MOST_WALKED: libc::rlim_t = 1 << 16;

/// How many descriptors above the highest one found open are marked as well, for any opened
/// between the finding and the fork.
const OPENED_SINCE: libc::c_int = 64;

/// Marks the descriptors from `from` up to, not including, `to` to close when the shell is run.
fn mark_range_close_on_exec(from: libc::c_int, to: libc::c_int) {
    for descriptor in from..to {
        // SAFETY: the call takes no pointer; a descriptor that is not open is refused.
        unsafe {
            libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
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
    let highest_open = reads.highest_descriptor;
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
            mark_close_on_exec(highest_open);
            Ok(())
        });
    }
    process.spawn()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The descriptors from the first to the last given are marked, and the ones past it are not,
    /// whatever number they have: past what a fixed bound would have walked, where the limit
    /// allows one.
    #[test]
    fn a_range_of_descriptors_is_marked_to_close_when_the_shell_is_run() {
        use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

        let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        let room = limit
            .current
            .unwrap_or(1 << 20)
            .min(limit.maximum.unwrap_or(1 << 20));
        let first = libc::c_int::try_from((room.saturating_sub(8)).min(70_000)).expect("a number");
        let held = std::fs::File::open("/").expect("a descriptor to place");
        let placed: Vec<OwnedFd> = (first..first + 3)
            .map(|number| {
                // SAFETY: the number is one this case has chosen to use for a descriptor of its
                // own, high enough that nothing else of this process holds it, and the descriptor
                // it makes is owned from here on.
                unsafe {
                    assert_eq!(
                        libc::dup2(held.as_raw_fd(), number),
                        number,
                        "a descriptor at {number}"
                    );
                    OwnedFd::from_raw_fd(number)
                }
            })
            .collect();
        for descriptor in &placed {
            rustix::io::fcntl_setfd(descriptor, rustix::io::FdFlags::empty())
                .expect("left open on exec");
        }
        mark_range_close_on_exec(first, first + 2);
        let marked = |index: usize| {
            rustix::io::fcntl_getfd(&placed[index])
                .expect("flags")
                .contains(rustix::io::FdFlags::CLOEXEC)
        };
        assert!(marked(0) && marked(1), "the range is marked");
        assert!(!marked(2), "and nothing past it");
    }

    /// The directory the shell is to start in is told apart from one that is there and cannot be
    /// entered, and from one that is not there.
    #[test]
    fn a_missing_directory_falls_back_to_the_home_directory_and_one_that_is_there_does_not() {
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
        assert!(missing.opened.is_ok(), "the home directory opens");
        command.cwd = host.root().display().to_string();
        assert!(Reads::read(&command).named_is_there());
    }
}
