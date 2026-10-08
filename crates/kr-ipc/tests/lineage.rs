//! A process's identity and the facts that tie it to a session, read from one reading.
//!
//! The processes here are real children this test started. What is checked is what a caller relies
//! on to refuse a stranger that took an identifier a list named: the reading names the parent and
//! the group of the process that holds the identifier now, so a list that says "a child of this
//! process" or "a member of this group" can be held against it.

#![cfg(unix)]

use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

use kr_ipc::identity::{process_lineage, process_start_identity};

#[test]
fn a_reading_names_the_parent_and_the_group_of_the_process_that_holds_the_number() {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exec sleep 600"])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("starts a child");
    let pid = child.id();
    let lineage = process_lineage(pid).expect("reads the child");
    assert_eq!(
        lineage.identity,
        process_start_identity(pid).expect("its identity"),
        "the start in the reading is the process's identity"
    );
    assert_eq!(
        lineage.parent,
        std::process::id(),
        "the child is this process's own"
    );
    assert_eq!(lineage.group, pid, "and leads a group of its own");
    let own = process_lineage(std::process::id()).expect("reads this process");
    assert_ne!(
        lineage.group, own.group,
        "a list of this process's group does not include it"
    );
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn a_process_that_has_gone_has_no_reading() {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("starts a child");
    let pid = child.id();
    child.wait().expect("collects the child");
    assert!(process_lineage(pid).is_err(), "nothing holds {pid}");
}
