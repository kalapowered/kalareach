//! Collecting a process the worker adopted once it has ended.
//!
//! On Linux the worker is the child subreaper ([`crate::ownership::adopt_orphans`]): a process of
//! the session whose parent ends becomes the worker's own child. When that process ends, its exit
//! status stays in the process table until the worker collects it, and the entry counts against the
//! account's process limit (`RLIMIT_NPROC`) for as long as it stays.
//!
//! The worker also has children whose status something waits for: the root shell, the servers the
//! broker starts, and every other child it holds. Collecting a status takes it from whoever waits
//! for it, so nothing here looks at the worker's children to find one to collect. The caller names a
//! process that the kernel's own facts say the worker did not start, and [`collect`] takes that one
//! process's status and no other's.
//!
//! It needs a kernel that gives a process descriptor (5.3) and waits on one (5.4). On an older one,
//! or under a filter that refuses either call, nothing is collected, and the entries stay as they
//! were.

use std::os::fd::{AsFd as _, OwnedFd};

use kr_ipc::identity::ProcessQuery;
use kr_protocol::identity::ProcessStartIdentity;
use rustix::io::Errno;
use rustix::process::{Pid, PidfdFlags, WaitId, WaitIdOptions, pidfd_open, waitid};

/// What collecting one process came to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Collected {
    /// The process had ended and its status was taken.
    Taken,
    /// Nothing holds the recorded identity: its parent collected it, or its number passed to
    /// another process.
    Gone,
    /// The process is there and nothing was taken: it still runs, it is not this worker's child
    /// (yet), or the kernel gave no descriptor for it. Asking again later can change the answer.
    Left,
}

/// Takes the exit status of the process `identity` records, if it is a child of this worker's that
/// has ended, so that its entry leaves the process table.
///
/// The process is held by a process descriptor for the length of the check and the collection, and
/// the identity is read before the descriptor is opened and again after, both times as the one
/// recorded: a number that passed to another process takes no status, because the descriptor
/// names the process that held the number between the two readings.
pub(crate) fn collect(identity: &ProcessStartIdentity) -> Collected {
    collect_opening(identity, |pid| pidfd_open(pid, PidfdFlags::empty()))
}

/// [`collect`], with the opening of the process descriptor given.
fn collect_opening(
    identity: &ProcessStartIdentity,
    open: impl FnOnce(Pid) -> rustix::io::Result<OwnedFd>,
) -> Collected {
    let Ok(raw) = u32::try_from(identity.pid.get()) else {
        return Collected::Gone;
    };
    if raw == std::process::id() {
        return Collected::Left;
    }
    let Some(pid) = i32::try_from(raw).ok().and_then(Pid::from_raw) else {
        return Collected::Gone;
    };
    let recorded = || match kr_ipc::identity::query_process(raw) {
        ProcessQuery::Present(now) if now == *identity => Ok(()),
        ProcessQuery::Present(_) | ProcessQuery::Gone => Err(Collected::Gone),
        ProcessQuery::CannotEstablish(_) => Err(Collected::Left),
    };
    if let Err(answer) = recorded() {
        return answer;
    }
    let descriptor = match open(pid) {
        Ok(descriptor) => descriptor,
        Err(Errno::SRCH) => return Collected::Gone,
        Err(_) => return Collected::Left,
    };
    if let Err(answer) = recorded() {
        return answer;
    }
    match waitid(
        WaitId::PidFd(descriptor.as_fd()),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG,
    ) {
        Ok(Some(_)) => Collected::Taken,
        // Still running, or not this worker's child: its parent collects it, or the worker does
        // once it has adopted it.
        Ok(None) | Err(_) => Collected::Left,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::identity::ProcessStartSource;
    use rustix::process::{Signal, kill_process};

    /// Waits, without taking its status, until the child `pid` has ended.
    fn ended(pid: u32) {
        let pid = i32::try_from(pid)
            .ok()
            .and_then(Pid::from_raw)
            .expect("a process number");
        waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        )
        .expect("the child is waited for");
    }

    fn child_that_ends_with(code: u8) -> std::process::Child {
        std::process::Command::new("sh")
            .args(["-c", &format!("exit {code}")])
            .spawn()
            .expect("starts a process")
    }

    /// A process's status is taken only for the process that was recorded, and only once it has
    /// ended: a number that now belongs to another process loses nothing, a process that still runs
    /// is left to run, and a descriptor the kernel will not give leaves the process as it is, to be
    /// asked about again.
    #[test]
    fn a_status_is_taken_only_from_the_ended_process_that_was_recorded() {
        // The same number with another start is what a number that passed to another process
        // looks like to a record made before it did.
        let mut other = child_that_ends_with(3);
        ended(other.id());
        let held = kr_ipc::identity::process_start_identity(other.id()).expect("its identity");
        let before_it_passed = ProcessStartIdentity::new(
            held.pid.get(),
            ProcessStartSource::LinuxProcStat,
            held.start_value.get() - 1,
        );
        assert_eq!(
            collect(&before_it_passed),
            Collected::Gone,
            "a process that is not the one recorded is not collected"
        );
        assert_eq!(
            collect_opening(&held, |_| Err(Errno::MFILE)),
            Collected::Left,
            "a descriptor the kernel would not give leaves the process to be asked about again"
        );
        assert_eq!(
            other.wait().expect("its status is still there").code(),
            Some(3),
            "and its status is still its parent's to read"
        );

        let mut running = std::process::Command::new("sleep")
            .arg("600")
            .spawn()
            .expect("starts a process");
        let identity =
            kr_ipc::identity::process_start_identity(running.id()).expect("its identity");
        let taken = collect(&identity);
        let pid = Pid::from_raw(i32::try_from(running.id()).expect("a number")).expect("a pid");
        kill_process(pid, Signal::KILL).expect("ends the process");
        let status = running.wait().expect("collects the process");
        assert_eq!(
            taken,
            Collected::Left,
            "a process that runs is not collected"
        );
        assert!(!status.success());

        // Its status is taken by `collect`, which is what is shown, not by a wait of the case's own.
        #[allow(clippy::zombie_processes)]
        let ended_child = child_that_ends_with(4);
        ended(ended_child.id());
        let identity =
            kr_ipc::identity::process_start_identity(ended_child.id()).expect("its identity");
        assert_eq!(
            collect(&identity),
            Collected::Taken,
            "an ended process that was recorded is collected"
        );
        assert_eq!(
            collect(&identity),
            Collected::Gone,
            "and nothing holds it afterwards, so its parent has nothing left to collect"
        );
    }
}
