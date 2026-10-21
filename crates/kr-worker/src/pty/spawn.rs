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
//! the child holds is marked to close when the shell is run, found in the child itself at the
//! moment it is made, so that nothing the worker opened, whenever and above whatever limit, is
//! missed (on the systems this ships on; the one that is walked instead is named where it is).

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
    room: TableRoom,
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
            room: TableRoom::make(),
        }
    }

    /// Whether the directory the command names was there.
    pub(super) const fn named_is_there(&self) -> bool {
        self.named_is_there
    }
}

/// What the child needs to find its descriptors, made before the fork because the child may not
/// allocate.
#[derive(Debug)]
pub(super) struct TableRoom {
    /// Room for the kernel's list of the process's descriptors, with room above what is open now
    /// for any opened before the fork.
    #[cfg(target_vendor = "apple")]
    list: Vec<libc::proc_fdinfo>,
    /// One past the highest number the system gives a descriptor, which is walked as far as when
    /// the list does not hold them all.
    #[cfg(target_vendor = "apple")]
    table_end: libc::c_int,
}

impl TableRoom {
    #[cfg(target_vendor = "apple")]
    fn make() -> Self {
        /// Descriptors that can be opened between asking how many there are and the fork.
        const OPENED_SINCE: usize = 512;

        // SAFETY: a null buffer of no size asks only how much room the list needs.
        let needed = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDLISTFDS,
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        let entries = usize::try_from(needed).unwrap_or(0)
            / std::mem::size_of::<libc::proc_fdinfo>()
            + OPENED_SINCE;
        Self {
            list: vec![
                libc::proc_fdinfo {
                    proc_fd: 0,
                    proc_fdtype: 0,
                };
                entries
            ],
            table_end: table_end(),
        }
    }

    #[cfg(not(target_vendor = "apple"))]
    const fn make() -> Self {
        Self {}
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
        FALLBACK_TABLE_END
    }
}

/// The end of the table where the system will not say: well above what it gives by default.
#[cfg(target_vendor = "apple")]
const FALLBACK_TABLE_END: libc::c_int = 1 << 20;

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
/// Every descriptor the child has is found in the child, at the moment it is made, so no limit or
/// timing in the worker can hide one:
///
/// * Linux marks them all in one call from kernel 5.11, and where that call is not available lists
///   the child's own table (`/proc/self/fd`) and marks each. Where neither can be done the start
///   fails, rather than going ahead with descriptors it could not account for.
/// * Apple systems list the process's descriptors in the room made for it before the fork, which
///   is complete when the list leaves room over. When it does not (more descriptors than the room
///   made for, or the list is refused), every number is marked up to the larger of what the list
///   named and `kern.maxfilesperproc`, above which the system gives no descriptor a number: about
///   7 ms at the default of 92,160, in the child, before the shell runs. A system that will not
///   say that number is walked as far as 2^20, which is a guess. A descriptor opened above a limit
///   that was lowered by an administrator after it was opened is in the list, and in the walk only
///   if the walk reaches it.
/// * Other Unix systems are walked as far as the soft limit, which does not cover a descriptor
///   above a limit lowered since it was opened.
///
/// A descriptor that is not open is refused by the call, and that is no failure. Any other refusal
/// is returned, so that a shell is not started with a descriptor that could not be marked.
///
/// This allocates nothing and calls only system calls, as it has to between the fork and the run.
fn mark_close_on_exec(room: &mut TableRoom) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _ = room;
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
        mark_listed_close_on_exec()
    }
    #[cfg(target_vendor = "apple")]
    {
        mark_by_the_kernels_list(room).map(|_| ())
    }
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    {
        let _ = room;
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is this function's own and outlives the call.
        let known = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } == 0;
        let end = if known && limit.rlim_cur != libc::RLIM_INFINITY {
            libc::c_int::try_from(limit.rlim_cur).unwrap_or(libc::c_int::MAX)
        } else {
            1 << 16
        };
        mark_range_close_on_exec(3, end)
    }
}

/// Marks each descriptor the kernel lists for this process, and, when the list may not hold them
/// all, every number up to where the system gives descriptors. Says whether the list was complete.
#[cfg(target_vendor = "apple")]
fn mark_by_the_kernels_list(room: &mut TableRoom) -> std::io::Result<bool> {
    let entry = std::mem::size_of::<libc::proc_fdinfo>();
    let capacity = room.list.len() * entry;
    let Ok(capacity_bytes) = libc::c_int::try_from(capacity) else {
        mark_range_close_on_exec(3, room.table_end)?;
        return Ok(false);
    };
    // SAFETY: the buffer is the room made before the fork, `capacity` bytes of it, and nothing else
    // holds it; the call is a thin wrapper of the system call and allocates nothing.
    let bytes = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDLISTFDS,
            0,
            room.list.as_mut_ptr().cast(),
            capacity_bytes,
        )
    };
    let filled = usize::try_from(bytes).unwrap_or(0).min(capacity) / entry;
    // The kernel fills what fits and reports what it filled, so a list that leaves room over is
    // the whole of them, and a full one may not be.
    let complete = bytes > 0 && usize::try_from(bytes).is_ok_and(|bytes| bytes < capacity);
    let mut end = 3;
    for listed in &room.list[..filled] {
        end = end.max(listed.proc_fd.saturating_add(1));
        if listed.proc_fd > 2 {
            mark_range_close_on_exec(listed.proc_fd, listed.proc_fd + 1)?;
        }
    }
    if !complete {
        mark_range_close_on_exec(3, end.max(room.table_end))?;
    }
    Ok(complete)
}

/// Marks each descriptor the child's own table lists to close when the shell is run, reading the
/// list into room on the stack.
#[cfg(target_os = "linux")]
fn mark_listed_close_on_exec() -> std::io::Result<()> {
    let table = rustix::fs::open(
        "/proc/self/fd",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let mut room = [std::mem::MaybeUninit::<u8>::uninit(); 4096];
    let mut entries = rustix::fs::RawDir::new(&table, &mut room);
    while let Some(entry) = entries.next() {
        let entry = entry?;
        // The table's own entries, `.` and `..`, are not numbers.
        let Some(descriptor) = std::str::from_utf8(entry.file_name().to_bytes())
            .ok()
            .and_then(|name| name.parse::<libc::c_int>().ok())
        else {
            continue;
        };
        if descriptor > 2 {
            mark_range_close_on_exec(descriptor, descriptor + 1)?;
        }
    }
    Ok(())
}

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
            mark_close_on_exec(&mut room)
        });
    }
    process.spawn()
}

#[cfg(test)]
pub(super) mod tests {
    use std::os::fd::OwnedFd;

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
                Err(_) if wanted > 64 => wanted /= 2,
                Err(error) => panic!("no descriptor could be placed far up the table: {error}"),
            }
        }
    }

    /// Every descriptor the child holds is marked to close when the shell is run, whatever number
    /// it has and whatever the soft limit on descriptors has been lowered to since it was opened.
    ///
    /// Run in a process of its own, since marking is done to the whole table and the limit is the
    /// process's: the test binary runs this one case again with the variable set. In it, the room
    /// the child needs is made, a descriptor low in the table and one far up it are placed
    /// after (as the ones opened between the making and the fork are), the soft limit is lowered
    /// below both, and every way of finding them is run on a pair of its own: the start's, and on
    /// Linux the listing of the table as well as the one call that marks it, which the other would
    /// hide; on Apple systems it is also said that the kernel's list was the whole of them.
    #[test]
    fn every_descriptor_the_child_holds_is_marked_to_close_when_the_shell_is_run() {
        const IN_CHILD: &str = "KR_MARK_DESCRIPTORS_IN_CHILD";
        const THIS_CASE: &str = "pty::spawn::tests::every_descriptor_the_child_holds_is_marked_to_close_when_the_shell_is_run";

        if std::env::var_os(IN_CHILD).is_some() {
            let held = std::fs::File::open("/").expect("a descriptor to copy");
            let mut room = TableRoom::make();
            let pair = || {
                let low = rustix::io::fcntl_dupfd_cloexec(&held, 100).expect("one low");
                rustix::io::fcntl_setfd(&low, rustix::io::FdFlags::empty()).expect("inheritable");
                [low, descriptor_far_up(&held)]
            };
            let marked = |descriptor: &OwnedFd| {
                rustix::io::fcntl_getfd(descriptor)
                    .expect("flags")
                    .contains(rustix::io::FdFlags::CLOEXEC)
            };
            // The soft limit as it was, to be lowered below the far descriptors and given back.
            let was = rustix::process::getrlimit(rustix::process::Resource::Nofile);
            let set = |current| {
                rustix::process::setrlimit(
                    rustix::process::Resource::Nofile,
                    rustix::process::Rlimit {
                        current,
                        maximum: was.maximum,
                    },
                )
                .expect("the soft limit is set")
            };

            let first = pair();
            assert!(
                !marked(&first[0]) && !marked(&first[1]),
                "inheritable to begin with"
            );
            set(Some(64));
            #[cfg(target_os = "linux")]
            mark_listed_close_on_exec().expect("marks by the listing");
            #[cfg(target_vendor = "apple")]
            assert!(
                mark_by_the_kernels_list(&mut room).expect("marks by the list"),
                "the kernel's list held all of the descriptors"
            );
            #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
            mark_close_on_exec(&mut room).expect("marks");
            assert!(
                marked(&first[0]),
                "the descriptor low in the table is marked"
            );
            assert!(marked(&first[1]), "and the one far up it");

            // The call that marks the whole table at once, where there is one, on a pair of its own.
            set(was.current);
            let second = pair();
            assert!(
                !marked(&second[0]) && !marked(&second[1]),
                "inheritable to begin with"
            );
            set(Some(64));
            mark_close_on_exec(&mut room).expect("marks");
            assert!(
                marked(&second[0]),
                "marked by the start's way: the descriptor low in the table"
            );
            assert!(
                marked(&second[1]),
                "marked by the start's way: and the one far up it"
            );

            // Room for one descriptor is not room for the table this process holds. The kernel's
            // list is then not the whole of it, and a start that cannot account for every
            // descriptor does not go ahead.
            #[cfg(target_vendor = "apple")]
            {
                let mut cramped = TableRoom {
                    list: vec![
                        libc::proc_fdinfo {
                            proc_fd: 0,
                            proc_fdtype: 0,
                        };
                        1
                    ],
                    table_end: table_end(),
                };
                assert!(
                    mark_close_on_exec(&mut cramped).is_err(),
                    "a list that may not hold every descriptor fails the start"
                );
            }
            return;
        }
        let ran = std::process::Command::new(std::env::current_exe().expect("this binary"))
            .args(["--exact", THIS_CASE, "--test-threads=1"])
            .env(IN_CHILD, "1")
            .output()
            .expect("the case runs in a process of its own");
        let said = String::from_utf8_lossy(&ran.stdout);
        assert!(
            ran.status.success() && said.contains("test result: ok. 1 passed"),
            "the marking did not hold, or the case did not run: {}\n{said}\n{}",
            ran.status,
            String::from_utf8_lossy(&ran.stderr)
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
