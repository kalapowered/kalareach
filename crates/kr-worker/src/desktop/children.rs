//! The programs the desktop checks and the platform readings start, and how each of them ends.
//!
//! A program that starts others must not leave them running once it is done, whether it exited on
//! its own, failed or was stopped at its bound. Each child therefore starts in a process group of
//! its own, and the group is ended with it: after a normal exit while the child's own entry in the
//! process table still holds the group's number, so that the number cannot name another group by
//! then, and at the bound before the child is collected.

use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

/// Starts the child in a process group of its own, whose number is the child's.
pub(super) fn in_a_group_of_its_own(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        command.process_group(0);
    }
    #[cfg(not(unix))]
    let _ = command;
}

/// Asks a running child whether it has finished and, when it has, ends everything it started and
/// collects it.
///
/// The child is not collected before its group is ended: a collected child no longer keeps its
/// group's number, and a number nobody holds can name a group that is not this child's.
///
/// # Errors
///
/// Returns the error of the wait itself, which says nothing about the child.
pub(super) fn poll(child: &mut Child) -> std::io::Result<Option<ExitStatus>> {
    #[cfg(unix)]
    {
        if !finished(child)? {
            return Ok(None);
        }
        end_group(child);
    }
    child.try_wait()
}

/// How long a child that was asked to stop is waited for before the caller answers anyway.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
pub(super) const COLLECT: Duration = Duration::from_secs(2);

/// Collects a child that was ended, for at most `bound`, and says whether it was collected.
///
/// A child that cannot be collected at once, one that the system has not finished taking down, is
/// not a reason for the call that ended it to stop answering: the call gives up waiting and says
/// so, and the caller decides what becomes of the child.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
pub(super) fn collect_within(child: &mut Child, bound: Duration) -> bool {
    let until = Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Err(_) => return false,
            Ok(None) if Instant::now() >= until => return false,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

/// Collects a child that was ended: within `bound` where the system has taken it down by then, and
/// otherwise on a thread of its own, which waits for it for as long as it takes.
///
/// The caller waits at most `bound` for the collection and then goes on. That is an allowance and
/// not the time the call returns at: the start of the thread and the last short sleep of the wait
/// come after it. A child that was not collected by then is collected on that thread once the
/// system has finished with it, so it does not stay in the process table, unless the system
/// refuses to start the thread. It says whether the child was collected within `bound`.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
pub(super) fn collect_by(mut child: Child, bound: Duration) -> bool {
    if collect_within(&mut child, bound) {
        return true;
    }
    // A thread that cannot be started leaves the child to the process table, as a child that was
    // never waited for would be.
    let _ = std::thread::Builder::new()
        .name("kr-desktop-collect".to_owned())
        .spawn(move || {
            let _ = child.wait();
        });
    false
}

/// Ends the child's whole group, the child and everything it started.
///
/// Only for a child that has not been collected yet, because a collected child's number may name
/// another group by now. A group that is already gone cannot be signalled, which is the outcome
/// wanted.
pub(super) fn end_group(child: &Child) {
    #[cfg(unix)]
    if let Some(group) = i32::try_from(child.id())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    }
    #[cfg(not(unix))]
    let _ = child;
}

/// Waits, for at most `bound`, until a process is gone, for a case that looks for what a child left
/// behind.
///
/// A process is gone when a signal finds no process of that number, or, where the platform lists
/// its processes, when it is a zombie: a process that was ended and that nothing has collected yet
/// still takes a signal, and it runs nothing.
#[cfg(all(test, unix))]
pub(super) fn gone_within(number: i32, bound: std::time::Duration) -> bool {
    let Some(pid) = rustix::process::Pid::from_raw(number) else {
        return true;
    };
    let until = std::time::Instant::now() + bound;
    loop {
        if rustix::process::test_kill_process(pid) == Err(rustix::io::Errno::SRCH) {
            return true;
        }
        let zombie = std::fs::read_to_string(format!("/proc/{number}/stat"))
            .ok()
            .and_then(|stat| {
                stat.rsplit_once(')')
                    .map(|(_, rest)| rest.trim_start().to_owned())
            })
            .is_some_and(|rest| rest.starts_with('Z'));
        if zombie {
            return true;
        }
        if std::time::Instant::now() >= until {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Whether the child has finished, without collecting it: it stays in the process table, and keeps
/// its group's number, until it is collected.
#[cfg(unix)]
fn finished(child: &Child) -> std::io::Result<bool> {
    use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};

    let Some(pid) = i32::try_from(child.id()).ok().and_then(Pid::from_raw) else {
        return Err(std::io::Error::other("the child has no process number"));
    };
    match waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG,
    ) {
        Ok(status) => Ok(status.is_some()),
        Err(rustix::io::Errno::INTR) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::process::Stdio;
    use std::time::Duration;

    use super::*;

    /// KR-REQ-03.29, S-8: a child that cannot be collected at once is waited for only within a
    /// bound, so the call that ended it answers anyway.
    #[test]
    fn a_child_that_cannot_be_collected_at_once_is_waited_for_only_within_a_bound() {
        // A child that is still running is one that cannot be collected: the wait has nothing to
        // return until it ends, which is what a child the system cannot finish taking down is
        // like from here.
        let mut command = Command::new("/bin/sleep");
        command
            .arg("120")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        in_a_group_of_its_own(&mut command);
        let child = command.spawn().expect("the stand-in starts");
        let number = child.id();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut child = child;
            let began = Instant::now();
            let collected = collect_within(&mut child, Duration::from_millis(300));
            let _ = sender.send((collected, began.elapsed()));
            end_group(&child);
            let _ = child.kill();
            let _ = child.wait();
        });
        let answered = receiver.recv_timeout(Duration::from_secs(5));
        if answered.is_err() {
            // The case's own cleanup: a wait that did not give up leaves nothing running.
            if let Some(group) = i32::try_from(number)
                .ok()
                .and_then(rustix::process::Pid::from_raw)
            {
                let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            }
        }
        let (collected, took) = answered.expect("the call gave up at its bound and answered");
        assert!(
            !collected,
            "a child that was still running was not collected"
        );
        assert!(
            took < Duration::from_secs(2),
            "the call took {took:?} for a bound of 300 ms"
        );
    }

    /// KR-REQ-03.29, S-8: a child that stays uncollected past the bound is handed on: the call
    /// answers by the bound, and the child is collected after it, not left in the process table.
    #[test]
    fn a_child_still_uncollected_at_the_bound_is_collected_after_the_call_has_answered() {
        // A child that is still running is one that cannot be collected: the wait has nothing to
        // return until it ends.
        let mut command = Command::new("/bin/sleep");
        command
            .arg("120")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        in_a_group_of_its_own(&mut command);
        let child = command.spawn().expect("the stand-in starts");
        let group = i32::try_from(child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .expect("a process number");
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let began = Instant::now();
            let collected = collect_by(child, Duration::from_millis(300));
            let _ = sender.send((collected, began.elapsed()));
        });
        let answered = receiver.recv_timeout(Duration::from_secs(5));
        if answered.is_err() {
            // The case's own cleanup: a wait that did not give up leaves nothing running.
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
        let (collected_at_the_bound, took) =
            answered.expect("the call gave up at its bound and answered");
        assert!(
            !collected_at_the_bound,
            "a child that was still running was not collected at the bound"
        );
        assert!(
            took < Duration::from_secs(2),
            "the call took {took:?} for a bound of 300 ms"
        );
        assert!(
            rustix::process::test_kill_process(group).is_ok(),
            "the child was still there when the call answered"
        );
        // The system finishes taking the child down now. A zombie still takes a signal and a
        // collected child does not, so the number's absence is the child's collection.
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        let until = Instant::now() + Duration::from_secs(5);
        let collected = loop {
            if rustix::process::test_kill_process(group) == Err(rustix::io::Errno::SRCH) {
                break true;
            }
            if Instant::now() >= until {
                break false;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            collected,
            "the child that was not collected at the bound stayed in the process table"
        );
    }

    /// KR-REQ-03.29, S-6: a child that exits on its own, by success or by failure, is ended with the
    /// descendants it started, before it is collected.
    #[test]
    fn a_child_that_exits_takes_the_descendants_it_started_with_it() {
        for (what, code) in [("a success", "0"), ("a failure", "3")] {
            let root = kr_ipc::testing::PrivateTempDir::create();
            let file = root.path().join("descendant.pid");
            let script = format!("/bin/sleep 120 & echo $! > \"$1\"; exit {code}");
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", &script, "sh", file.to_str().expect("text")])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            in_a_group_of_its_own(&mut command);
            let mut child = command.spawn().expect("the stand-in starts");
            let status = loop {
                match poll(&mut child).expect("the wait") {
                    Some(status) => break status,
                    None => std::thread::sleep(Duration::from_millis(10)),
                }
            };
            assert_eq!(status.success(), code == "0", "{what}");
            let number = std::fs::read_to_string(&file)
                .expect("the stand-in wrote the number of what it started")
                .trim()
                .parse::<i32>()
                .expect("a process number");
            let gone = gone_within(number, Duration::from_secs(5));
            if !gone {
                // The case's own cleanup: nothing it started is left running by a failure of it.
                if let Some(pid) = rustix::process::Pid::from_raw(number) {
                    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
                }
            }
            assert!(
                gone,
                "{what}: process {number} outlived the child that started it"
            );
        }
    }
}
