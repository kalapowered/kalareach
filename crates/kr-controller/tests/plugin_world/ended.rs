//! Ending the processes a plugin test started, and seeing that they ended.
//!
//! Included by `plugin_world` and, by path, by the plugin runtime suite, which keeps a world of its
//! own: one copy of the loop that decides whether a host is gone.

use std::time::{Duration, Instant};

use kr_ipc::identity::{ProcessState, Stop, stop_process};
use kr_protocol::identity::ProcessStartIdentity;

/// Ends a process by the identity it was started under, and no other: the product's own stop holds
/// the process by something other than its number while it checks and signals, so a number that
/// passes to a different process meanwhile is left alone.
pub fn kill(process: &ProcessStartIdentity) {
    let _ = stop_process(process, Stop::Kill);
}

/// Ends `hosts` and waits until each has been read as ended, or `deadline` passes, and says which
/// were not seen to end, with what the system last said of each.
///
/// A host that has been read as ended is ended: the system numbers a process once, and a later
/// reading of the same process can meet the moment its parent collects it, which the reader does
/// not call an end. So each host is asked until it answers once that it has ended, and is not asked
/// again. A host that is read as still there is stopped again: a stop the system did not carry out
/// (it did not answer, or the reading of the host failed once) must not leave a host running.
#[must_use]
pub fn end_hosts(hosts: &[ProcessStartIdentity], deadline: Instant) -> Vec<String> {
    for host in hosts {
        kill(host);
    }
    let mut ended = vec![false; hosts.len()];
    loop {
        for (host, ended) in hosts.iter().zip(ended.iter_mut()) {
            *ended = *ended || kr_ipc::identity::process_state(host) == ProcessState::Ended;
        }
        if ended.iter().all(|ended| *ended) || Instant::now() >= deadline {
            break;
        }
        for (host, _) in hosts.iter().zip(&ended).filter(|(_, ended)| !**ended) {
            kill(host);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    hosts
        .iter()
        .zip(&ended)
        .filter(|(_, ended)| !**ended)
        .map(|(host, _)| {
            format!(
                "{}: {:?}",
                host.pid.get(),
                kr_ipc::identity::process_state(host)
            )
        })
        .collect()
}
