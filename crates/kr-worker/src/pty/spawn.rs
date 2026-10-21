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
    /// What bounds the descriptors the worker can have open.
    descriptors: Descriptors,
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
            descriptors: Descriptors::read(),
        }
    }

    /// Whether the directory the command names was there.
    pub(super) const fn named_is_there(&self) -> bool {
        self.named_is_there
    }
}

/// What bounds the descriptors the worker has open, read with the directory so that nothing is
/// asked of the system between the admission of the start and the process.
#[derive(Clone, Copy, Debug)]
pub(super) struct Descriptors {
    /// One past the highest descriptor the system lists as open, or zero where it lists none.
    listed_end: libc::c_int,
    /// One past the highest number the system gives any descriptor.
    table_end: libc::c_int,
}

impl Descriptors {
    fn read() -> Self {
        Self {
            listed_end: std::fs::read_dir("/dev/fd")
                .ok()
                .into_iter()
                .flatten()
                .filter_map(|entry| {
                    entry
                        .ok()?
                        .file_name()
                        .to_str()?
                        .parse::<libc::c_int>()
                        .ok()
                })
                .max()
                .map_or(0, |highest| highest.saturating_add(1)),
            table_end: table_end(),
        }
    }
}

/// One past the highest number the system gives any descriptor of a process.
///
/// Apple systems refuse a descriptor at or above `kern.maxfilesperproc` whatever the soft limit
/// says; the limit is read here, and the call that reads it is not one for the child.
#[cfg(target_vendor = "apple")]
fn table_end() -> libc::c_int {
    let mut limit: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    // SAFETY: the name is a NUL-terminated string, and the value and its size are this function's
    // own and outlive the call.
    let read = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            (&raw mut limit).cast(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if read == 0 && limit > 0 {
        limit
    } else {
        libc::c_int::MAX
    }
}

/// One past the highest number the system gives any descriptor of a process.
#[cfg(not(target_vendor = "apple"))]
const fn table_end() -> libc::c_int {
    libc::c_int::MAX
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
/// every number is marked up to the highest of two: one past the highest descriptor that was
/// listed open when the start was read, which covers what is open now whatever the limit has been
/// lowered to since, and the soft limit on descriptors as the child finds it, which covers what
/// was opened after that, because a descriptor is given a number below the soft limit in force. The
/// system's own highest number bounds the second, and a soft limit that names no bound (and a
/// system that listed no descriptors) is walked as far as [`MOST_WALKED`].
///
/// A descriptor that is not open is refused by the call, and that is no failure. Any other refusal
/// is returned, so that a shell is not started with a descriptor that could not be marked.
///
/// This allocates nothing and calls only system calls, as it has to between the fork and the run.
fn mark_close_on_exec(descriptors: Descriptors) -> std::io::Result<()> {
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
            return Ok(());
        }
    }
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is this function's own and outlives the call.
    let known = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } == 0;
    let soft_end = if known && limit.rlim_cur != libc::RLIM_INFINITY {
        libc::c_int::try_from(limit.rlim_cur)
            .unwrap_or(libc::c_int::MAX)
            .min(descriptors.table_end)
    } else if descriptors.listed_end > 0 {
        0
    } else {
        libc::c_int::try_from(MOST_WALKED).unwrap_or(libc::c_int::MAX)
    };
    mark_range_close_on_exec(3, descriptors.listed_end.max(soft_end))
}

/// The most descriptors walked one by one where the soft limit names no bound and the system lists
/// none.
const MOST_WALKED: libc::rlim_t = 1 << 16;

/// Marks the descriptors from `from` up to, not including, `to` to close when the shell is run.
fn mark_range_close_on_exec(from: libc::c_int, to: libc::c_int) -> std::io::Result<()> {
    for descriptor in from..to {
        // SAFETY: the call takes no pointer; a descriptor that is not open is refused.
        let marked = unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) };
        if marked == -1 {
            let refusal = std::io::Error::last_os_error();
            if refusal.raw_os_error() != Some(libc::EBADF) {
                return Err(refusal);
            }
        }
    }
    Ok(())
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
    let descriptors = reads.descriptors;
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
            mark_close_on_exec(descriptors)
        });
    }
    process.spawn()
}

#[cfg(test)]
pub(super) mod tests {
    use std::os::fd::{AsRawFd, OwnedFd};

    use super::*;

    /// A descriptor of the worker's as far up the table as the system lets one go, left open on
    /// exec, and the number it has.
    ///
    /// Placed by asking for the first free number at or above a high one, which takes nothing
    /// another case holds, and tried lower until the system accepts one: the highest number it
    /// gives is below its own limit on descriptors, which is not always the soft limit.
    pub(in crate::pty) fn descriptor_far_up(like: &std::fs::File) -> OwnedFd {
        let mut wanted = 70_000;
        loop {
            match rustix::io::fcntl_dupfd_cloexec(like, wanted) {
                Ok(placed) => {
                    rustix::io::fcntl_setfd(&placed, rustix::io::FdFlags::empty())
                        .expect("left open on exec");
                    return placed;
                }
                Err(_) if wanted > 512 => wanted /= 2,
                Err(error) => panic!("no descriptor could be placed far up the table: {error}"),
            }
        }
    }

    /// The descriptors from the first to the last given are marked, and the ones past it are not,
    /// whatever number they have.
    #[test]
    fn a_range_of_descriptors_is_marked_to_close_when_the_shell_is_run() {
        let held = std::fs::File::open("/").expect("a descriptor to copy");
        let first = descriptor_far_up(&held);
        let placed = [
            first,
            rustix::io::fcntl_dupfd_cloexec(&held, 0).expect("another"),
        ];
        for descriptor in &placed {
            rustix::io::fcntl_setfd(descriptor, rustix::io::FdFlags::empty())
                .expect("left open on exec");
        }
        let (low, high) = (
            placed.iter().map(AsRawFd::as_raw_fd).min().expect("two"),
            placed.iter().map(AsRawFd::as_raw_fd).max().expect("two"),
        );
        mark_range_close_on_exec(low, high).expect("marks");
        let marked = |descriptor: &OwnedFd| {
            rustix::io::fcntl_getfd(descriptor)
                .expect("flags")
                .contains(rustix::io::FdFlags::CLOEXEC)
        };
        let (below, at) = if placed[0].as_raw_fd() == low {
            (&placed[0], &placed[1])
        } else {
            (&placed[1], &placed[0])
        };
        assert!(marked(below), "the range is marked");
        assert!(!marked(at), "and nothing past it");
    }

    /// What the system lists as open is what bounds the walk, so a descriptor above the soft limit
    /// as it is now, or far up the table, is among them.
    #[test]
    fn the_descriptors_the_system_lists_include_one_far_up_the_table() {
        let held = std::fs::File::open("/").expect("a descriptor to copy");
        let far = descriptor_far_up(&held);
        let descriptors = Descriptors::read();
        assert!(
            descriptors.listed_end > far.as_raw_fd(),
            "the listing ends at {}, below the descriptor at {}",
            descriptors.listed_end,
            far.as_raw_fd()
        );
        assert!(
            descriptors.table_end > far.as_raw_fd(),
            "the table ends at {}, below a descriptor the system gave, at {}",
            descriptors.table_end,
            far.as_raw_fd()
        );
    }

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
