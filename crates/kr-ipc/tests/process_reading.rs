//! A recorded process read for a process view: whether it is still the recorded process, who its
//! parent is and what executable it runs.
//!
//! The processes here are real children this test started: copies of this test binary that wait
//! on their standard input, so each has an executable whose name the test knows, and ends when the
//! test closes the pipe.

#![cfg(unix)]

use std::io::BufRead as _;
use std::process::{Child, Command, Stdio};

use kr_ipc::identity::{ProcessFacts, ProcessReading, process_start_identity, read_process};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};

/// The half of these tests that runs as a child: it waits until its standard input closes.
#[test]
#[ignore = "the child half of the process reading tests, run only as their own child"]
fn wait_for_the_pipe_to_close() {
    std::io::stdin().lock().lines().for_each(drop);
}

/// Starts the child half named `half` of the binary at `program`. The process is running its own
/// executable once this returns, whatever the harness has reached.
fn child_of(program: &std::path::Path, half: &str) -> Child {
    Command::new(program)
        .args([
            "--exact",
            half,
            "--ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("starts a child")
}

/// A child that is a copy of this test binary, which the half named `half` runs in.
fn child(half: &str) -> Child {
    child_of(&std::env::current_exe().expect("this binary"), half)
}

fn end(mut child: Child) {
    drop(child.stdin.take());
    child.wait().expect("collects the child");
}

fn own_name() -> String {
    std::env::current_exe()
        .expect("this binary")
        .file_name()
        .expect("a file name")
        .to_string_lossy()
        .into_owned()
}

/// KR-REQ-25.06: a running recorded process is read with its parent as an identity and the base
/// name of its executable, from the operating system's own process interface, and never with a
/// path.
#[test]
fn a_running_child_is_read_with_its_parent_and_its_executable() {
    let child = child("wait_for_the_pipe_to_close");
    let identity = process_start_identity(child.id()).expect("the child's identity");
    let ProcessReading::Running(ProcessFacts { parent, name }) = read_process(&identity) else {
        panic!("a running child reads as running");
    };
    assert_eq!(
        parent,
        Some(process_start_identity(std::process::id()).expect("this process")),
        "the parent is this process, with its start"
    );
    assert_eq!(name.as_deref(), Some(own_name().as_str()));
    assert!(!name.expect("a name").contains('/'));
    end(child);
}

/// KR-REQ-25.06: a process that ended is ended, and an identifier that now has another start is
/// another process, so a reused identifier is never given the recorded process's standing.
#[test]
fn an_ended_process_and_a_reused_identifier_read_as_ended() {
    let child = child("wait_for_the_pipe_to_close");
    let identity = process_start_identity(child.id()).expect("the child's identity");
    let reused = ProcessStartIdentity::new(
        identity.pid.get(),
        identity.source,
        identity.start_value.get() + 1,
    );
    assert_eq!(
        read_process(&reused),
        ProcessReading::Ended,
        "the identifier is held by a process with another start"
    );
    end(child);
    assert_eq!(read_process(&identity), ProcessReading::Ended);
}

/// KR-REQ-25.06: a running process that will not give its executable stays running, with no name.
/// The process runs a copy of this binary that nobody can read, which the kernel marks as not
/// dumpable, so no reader but one with the superuser's privilege may follow its executable's link.
#[cfg(target_os = "linux")]
#[test]
fn a_process_that_refuses_its_executable_is_still_running() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = kr_ipc::testing::PrivateTempDir::create();
    let program = directory.path().join("unreadable");
    std::fs::copy(std::env::current_exe().expect("this binary"), &program).expect("a copy");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o111))
        .expect("a program that can be run and not read");
    let child = child_of(&program, "wait_for_the_pipe_to_close");
    let identity = process_start_identity(child.id()).expect("the child's identity");
    if std::fs::read_link(format!("/proc/{}/exe", child.id())).is_ok() {
        // The superuser reads every link, so no process refuses this reader: the case cannot be
        // made here, and it says so rather than passing as if it had.
        eprintln!("not run: this account reads every process's executable link");
        end(child);
        return;
    }
    let ProcessReading::Running(facts) = read_process(&identity) else {
        panic!("the process runs");
    };
    assert_eq!(facts.name, None, "its executable is not given");
    assert!(facts.parent.is_some(), "its parent still is");
    end(child);
}

/// KR-REQ-25.06: an identity in whole seconds cannot tell two processes apart, so it is unknown
/// without any process being read.
#[test]
fn an_identity_in_whole_seconds_is_unknown_and_no_process_is_read() {
    let identity = ProcessStartIdentity::new(
        u64::from(std::process::id()),
        ProcessStartSource::WindowsProcessStartSeconds,
        1,
    );
    #[cfg(target_os = "linux")]
    let (reading, read) = kr_ipc::identity::processes_read_during(|| read_process(&identity));
    #[cfg(not(target_os = "linux"))]
    let reading = read_process(&identity);
    assert!(
        matches!(reading, ProcessReading::Unknown { .. }),
        "{reading:?}"
    );
    #[cfg(target_os = "linux")]
    assert!(read.is_empty(), "no process was read: {read:?}");
}

/// KR-REQ-25.06: the process is asked about before and after its facts are read, and an answer
/// that changes between the two is the answer: a process that ended meanwhile is ended and has no
/// facts, and a second question the system cannot answer is unknown.
#[cfg(target_os = "linux")]
#[test]
fn an_answer_that_changes_between_the_two_questions_is_the_answer() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    let child = child("wait_for_the_pipe_to_close");
    let identity = process_start_identity(child.id()).expect("the child's identity");
    let child = Rc::new(RefCell::new(Some(child)));

    // The control: with no hook the same child reads as running.
    assert!(matches!(
        read_process(&identity),
        ProcessReading::Running(_)
    ));

    let asked = Rc::new(Cell::new(0_u32));
    let ending = Rc::clone(&child);
    let counting = Rc::clone(&asked);
    let hook = kr_ipc::identity::before_each_running_check(move |_| {
        counting.set(counting.get() + 1);
        if counting.get() == 2
            && let Some(child) = ending.borrow_mut().take()
        {
            end(child);
        }
        None
    });
    assert_eq!(read_process(&identity), ProcessReading::Ended);
    assert_eq!(asked.get(), 2, "the process was asked about twice");
    drop(hook);

    let second = process_start_identity(std::process::id()).expect("this process");
    let counting = Rc::new(Cell::new(0_u32));
    let seen = Rc::clone(&counting);
    let hook = kr_ipc::identity::before_each_running_check(move |_| {
        seen.set(seen.get() + 1);
        (seen.get() == 2).then(|| std::io::Error::other("the system does not answer"))
    });
    assert!(
        matches!(read_process(&second), ProcessReading::Unknown { .. }),
        "a second question that is not answered leaves the process unknown"
    );
    drop(hook);
}
