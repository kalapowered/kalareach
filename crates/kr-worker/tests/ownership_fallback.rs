//! What a session's ownership observation says when it cannot read the worker's process tree on
//! Linux and reads the terminal instead.
//!
//! This is a test binary of its own because the condition is a property of the whole process: a
//! process is the child subreaper once any session in it has made it one, and every case that opens
//! a session does. Here nothing does until the case says so.

#![cfg(any(target_os = "linux", target_os = "android"))]

use kr_worker::ownership::{OwnedProcesses, OwnershipBoundary};

/// KR-REQ-07.60: an observation that falls back from the worker's tree to the terminal names the
/// gap, and one that reads the tree does not.
///
/// A process that is not the child subreaper has no tree to read: a process whose parent exits
/// does not become its child. The observation then records the terminal's processes and says what
/// that leaves out. Once the process is the subreaper, a new observation reads the tree and says
/// nothing of the sort.
#[test]
fn kr_req_07_60_an_observation_that_cannot_read_the_tree_says_what_the_terminal_leaves_out() {
    let root = kr_ipc::identity::current_process_start_identity().expect("this process");
    let group = rustix::process::getpgrp()
        .as_raw_nonzero()
        .get()
        .unsigned_abs();
    let boundary = || OwnershipBoundary::TerminalGroup {
        group,
        terminal: None,
    };
    let said = |owned: &OwnedProcesses| {
        owned
            .unestablished()
            .iter()
            .any(|note| note.contains("could not be read") && note.contains("terminal"))
    };

    let mut without = OwnedProcesses::establish(boundary(), root.clone());
    without.observe();
    assert!(
        said(&without),
        "an observation that read the terminal names the gap: {:?}",
        without.unestablished()
    );

    kr_worker::ownership::adopt_orphans();
    let mut with = OwnedProcesses::establish(boundary(), root);
    with.observe();
    assert!(
        !said(&with),
        "one that read the tree does not: {:?}",
        with.unestablished()
    );
}
