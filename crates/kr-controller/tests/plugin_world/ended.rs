//! Ending the processes a plugin test started, and seeing that they ended.
//!
//! Included by `plugin_world` and, by path, by the plugin runtime suite, which keeps a world of its
//! own: one copy of the loop that decides whether a host is gone.

use std::time::{Duration, Instant};

use kr_ipc::identity::{ProcessState, Stop, Stopped, stop_process};
use kr_protocol::identity::ProcessStartIdentity;

/// Ends a process by the identity it was started under, and no other: the product's own stop holds
/// the process by something other than its number while it checks and signals, so a number that
/// passes to a different process meanwhile is left alone. An answer that is neither that the
/// signal was delivered nor that the process is gone is printed.
pub fn kill(process: &ProcessStartIdentity) {
    let answer = stop_process(process, Stop::Kill);
    if !matches!(answer, Stopped::Signalled | Stopped::Gone) {
        eprintln!(
            "the process {} was not stopped: {answer:?}",
            process.pid.get()
        );
    }
}

/// Ends `hosts` and waits until each has been read as ended, or `deadline` passes, and says which
/// were not seen to end, with what the system last said of each and of the last stop of it.
///
/// A host that has been read as ended is ended: the system numbers a process once, and a later
/// reading of the same process can meet the moment its parent collects it, which the reader does
/// not call an end. So each host is asked until it answers once that it has ended, and is not asked
/// again. A host that is read as still there is stopped again: a stop the system did not carry out
/// (it did not answer, or the reading of the host failed once) must not leave a host running.
#[must_use]
pub fn end_hosts(hosts: &[ProcessStartIdentity], deadline: Instant) -> Vec<String> {
    /// One host, whether it has been read as ended, and what the last stop of it came to.
    struct Watched<'a> {
        identity: &'a ProcessStartIdentity,
        ended: bool,
        last_stop: Option<Stopped>,
    }

    let mut watched: Vec<Watched<'_>> = hosts
        .iter()
        .map(|identity| Watched {
            identity,
            ended: false,
            last_stop: None,
        })
        .collect();
    for host in &mut watched {
        host.last_stop = Some(stop_process(host.identity, Stop::Kill));
    }
    loop {
        for host in &mut watched {
            host.ended =
                host.ended || kr_ipc::identity::process_state(host.identity) == ProcessState::Ended;
        }
        if watched.iter().all(|host| host.ended) || Instant::now() >= deadline {
            break;
        }
        for host in watched.iter_mut().filter(|host| !host.ended) {
            host.last_stop = Some(stop_process(host.identity, Stop::Kill));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    watched
        .iter()
        .filter(|host| !host.ended)
        .map(|host| {
            format!(
                "{}: {:?}, the last stop of it: {:?}",
                host.identity.pid.get(),
                kr_ipc::identity::process_state(host.identity),
                host.last_stop
            )
        })
        .collect()
}
