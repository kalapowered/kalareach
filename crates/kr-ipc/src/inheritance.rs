//! What a child process inherits of its parent's descriptors.
//!
//! A descriptor is inherited across `exec` unless it is marked to close there. A host that starts
//! a child (the shell a session runs, Git inside its boundary) holds descriptors of its own that
//! the child has no business with: a store, a socket, a directory it opened without the mark.
//! Marking is done in the child, between the fork and the run, where the table is the child's own
//! and no limit or timing in the parent can hide a descriptor from it; the room that needs is made
//! in the parent, before the fork, because the child may not allocate.
//!
//! Hosts only: a phone starts no such child, so nothing here is compiled for one.

#![expect(
    unsafe_code,
    reason = "the kernel's list of a process's descriptors, and marking one, have no safe interface \
              a forked child may call"
)]

/// What the child needs to find its descriptors, made before the fork because the child may not
/// allocate.
///
/// Made once per start by [`TableRoom::make`], and handed to [`mark_close_on_exec`] in the child.
#[derive(Debug)]
pub struct TableRoom {
    /// Room for the kernel's list of the process's descriptors, with room above what is open now
    /// for any opened before the fork.
    #[cfg(target_vendor = "apple")]
    list: Vec<libc::proc_fdinfo>,
}

impl TableRoom {
    /// Makes the room, in the parent, before the fork: on Apple systems the room for the kernel's
    /// list of this process's descriptors, with room above what is open now.
    #[cfg(target_vendor = "apple")]
    #[must_use]
    pub fn make() -> Self {
        /// Room for descriptors opened between asking how many there are and the fork. With more,
        /// the list is full and the start fails.
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
        }
    }

    /// Makes the room, in the parent, before the fork: none is needed on this system.
    #[cfg(not(target_vendor = "apple"))]
    #[must_use]
    pub const fn make() -> Self {
        Self {}
    }
}

/// Marks every descriptor above the standard three to close when the child runs its program, so
/// that the program has the standard three and nothing else of its parent's.
///
/// Called in the child between the fork and the run. A descriptor is marked rather than closed,
/// because the channel the standard library reports a failed run through is among them: it is
/// already marked, and closed by a good run, and it has to be open for a failed one to be
/// reported.
///
/// Every descriptor the child has is found in the child, at the moment it is made, so no limit or
/// timing in the parent can hide one:
///
/// * Linux marks them all in one call from kernel 5.11, and where that call is not available lists
///   the child's own table (`/proc/self/fd`) and marks each. Where neither can be done the call
///   fails, rather than going ahead with descriptors it could not account for.
/// * Apple systems ask the kernel for the list of the process's descriptors, into the room made
///   for it before the fork, and mark each. The list is the whole of them when it leaves room over
///   (the kernel fills what fits and reports what it filled). When it does not (more descriptors
///   than the room made for, or the call is refused), the call fails: a walk to some number would
///   leave open any descriptor above it, such as one opened above a limit an administrator has
///   since lowered, and nothing here can say there is none.
/// * Other Unix systems are walked as far as the soft limit, which does not cover a descriptor
///   above a limit lowered since it was opened.
///
/// A descriptor that is not open is refused by the call, and that is no failure. Any other refusal
/// is returned, so that a program is not run with a descriptor that could not be marked.
///
/// This allocates nothing and calls only system calls, as it has to between the fork and the run.
///
/// # Errors
///
/// Returns the system's error when a descriptor cannot be marked, "no buffer space" when the room
/// made before the fork does not leave room over, and the system's refusal of the list on Apple
/// systems.
pub fn mark_close_on_exec(room: &mut TableRoom) -> std::io::Result<()> {
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
        mark_by_the_kernels_list(room)
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

/// Marks each descriptor the kernel lists for this process, or fails when the list may not hold
/// them all.
///
/// # Errors
///
/// Returns "no buffer space" when the room made does not leave room over, and the system's error
/// when the call is refused; neither allocates.
#[cfg(target_vendor = "apple")]
fn mark_by_the_kernels_list(room: &mut TableRoom) -> std::io::Result<()> {
    let too_small = || std::io::Error::from_raw_os_error(libc::ENOBUFS);
    let entry = std::mem::size_of::<libc::proc_fdinfo>();
    let capacity = room.list.len() * entry;
    let capacity_bytes = libc::c_int::try_from(capacity).map_err(|_| too_small())?;
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
    if bytes <= 0 {
        // Refused: the call reports it as zero, and the system's error says why.
        let refusal = std::io::Error::last_os_error();
        return Err(if refusal.raw_os_error().is_some_and(|code| code != 0) {
            refusal
        } else {
            std::io::Error::from_raw_os_error(libc::EIO)
        });
    }
    let bytes = usize::try_from(bytes).map_err(|_| too_small())?;
    // The kernel fills what fits and reports what it filled, so a list that leaves room over is
    // the whole of them, and a full one may not be.
    if bytes >= capacity {
        return Err(too_small());
    }
    for listed in &room.list[..bytes / entry] {
        if listed.proc_fd > 2 {
            mark_range_close_on_exec(listed.proc_fd, listed.proc_fd + 1)?;
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;

    use super::*;
    use crate::testing::descriptor_far_up;

    /// Every descriptor the child holds is marked to close when the shell is run, whatever number
    /// it has and whatever the soft limit on descriptors has been lowered to since it was opened.
    ///
    /// Run in a process of its own, since marking is done to the whole table and the limit is the
    /// process's: the test binary runs this one case again with the variable set. In it, the room
    /// the child needs is made, a descriptor low in the table and one far up it are placed
    /// after (as the ones opened between the making and the fork are), the soft limit is lowered
    /// below both, and every way of finding them is run on a pair of its own: the start's, and on
    /// Linux the listing of the table as well as the one call that marks it, which the other would
    /// hide; on Apple systems it is also said that a list that may not hold every descriptor fails
    /// the start.
    #[test]
    fn every_descriptor_the_child_holds_is_marked_to_close_when_the_shell_is_run() {
        const IN_CHILD: &str = "KR_MARK_DESCRIPTORS_IN_CHILD";
        const THIS_CASE: &str = "inheritance::tests::every_descriptor_the_child_holds_is_marked_to_close_when_the_shell_is_run";

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
            mark_by_the_kernels_list(&mut room)
                .expect("the kernel's list held all of the descriptors, and marks them");
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
                };
                assert!(
                    mark_close_on_exec(&mut cramped).is_err(),
                    "a list that may not hold every descriptor fails the start"
                );
                // A call the kernel refuses gives no list: room for none is refused before anything
                // is listed, and the refusal is not the full room's.
                let mut none = TableRoom { list: Vec::new() };
                assert!(
                    mark_close_on_exec(&mut none)
                        .is_err_and(|refusal| refusal.raw_os_error() != Some(libc::ENOBUFS)),
                    "a call the kernel refuses fails the start, as a refusal"
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
}
