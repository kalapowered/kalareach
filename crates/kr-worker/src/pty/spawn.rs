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

#![expect(
    unsafe_code,
    reason = "running code in the child between the fork and the exec has no safe form"
)]

use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt as _;

use super::ShellCommand;

/// The directory a shell is to start in, opened before the start is admitted.
#[derive(Debug)]
pub(super) struct Directory {
    /// Whether the directory the command names was there to be entered.
    named_is_there: bool,
    /// The directory the shell starts in: the named one, or the account's home where that was not
    /// there, as the terminal library started a shell in one it could not find.
    opened: std::io::Result<OwnedFd>,
}

impl Directory {
    /// Opens the directory `command` names, or the account's home directory where it names one
    /// that cannot be entered: the `HOME` of the environment the shell is given, else the home
    /// directory the account database names, else the root.
    pub(super) fn open(command: &ShellCommand) -> Self {
        match open_directory(std::path::Path::new(&command.cwd)) {
            Ok(opened) => Self {
                named_is_there: true,
                opened: Ok(opened),
            },
            Err(_) => {
                let home = command
                    .environment
                    .iter()
                    .find_map(|(name, value)| (name == "HOME").then(|| value.into()))
                    .or_else(account_home)
                    .unwrap_or_else(|| "/".into());
                Self {
                    named_is_there: false,
                    opened: open_directory(&home),
                }
            }
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

/// The home directory the account database names for the user this process runs as.
pub(super) fn account_home() -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;

    let mut buffer = vec![0_u8; 1024];
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: the entry and the buffer are this function's own and outlive the call, the
        // buffer's length is the one passed, and `found` is read only after the call has set it.
        let status = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &raw mut found,
            )
        };
        if status == libc::ERANGE && buffer.len() < (1 << 20) {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if status != 0 || found.is_null() {
            return None;
        }
        // SAFETY: the call found an entry, so `pw_dir` points to a NUL-terminated string in the
        // buffer, which is still alive.
        let home = unsafe { std::ffi::CStr::from_ptr((*found).pw_dir) };
        return Some(std::ffi::OsString::from_vec(home.to_bytes().to_vec()).into());
    }
}

/// Marks every descriptor above the standard three to close when the shell is run, so that the
/// shell has the terminal and nothing else of the worker's.
///
/// A descriptor is marked rather than closed, because the channel the standard library reports a
/// failed run through is among them: it is already marked, and closed by a good run, and it has to
/// be open for a failed one to be reported.
///
/// This allocates nothing and calls only system calls, as it has to between the fork and the run.
fn mark_close_on_exec() {
    /// `CLOSE_RANGE_CLOEXEC`, which asks `close_range` to mark the descriptors instead.
    #[cfg(target_os = "linux")]
    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    /// The most descriptors walked one by one, where there is no call for the range.
    const MOST_WALKED: libc::rlim_t = 1 << 16;

    #[cfg(target_os = "linux")]
    {
        // SAFETY: the call takes no pointer, and marks descriptors of this process only.
        let marked = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3 as libc::c_uint,
                libc::c_uint::MAX,
                CLOSE_RANGE_CLOEXEC,
            )
        };
        if marked == 0 {
            return;
        }
    }
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is this function's own and outlives the call.
    let known = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } == 0;
    let end = if known {
        limit.rlim_cur.min(MOST_WALKED)
    } else {
        MOST_WALKED
    };
    for descriptor in 3..end {
        // SAFETY: the call takes no pointer; a descriptor that is not open is refused.
        unsafe {
            libc::fcntl(descriptor as libc::c_int, libc::F_SETFD, libc::FD_CLOEXEC);
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
    directory: Directory,
    command: &ShellCommand,
) -> std::io::Result<std::process::Child> {
    let directory = directory.opened?;
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
            mark_close_on_exec();
            Ok(())
        });
    }
    process.spawn()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_account_database_names_a_home_directory_that_is_there() {
        let home = account_home().expect("the user this runs as has an entry");
        assert!(home.is_dir(), "{home:?}");
    }
}
