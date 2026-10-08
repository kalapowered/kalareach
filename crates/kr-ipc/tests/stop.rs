//! Stopping a process that was recorded by its identifier and start, and no other.
//!
//! The processes here are real children this test started. The claim is isolation: a recorded
//! identity stops the process that was recorded, and an identifier that no longer names that
//! process, or a process that is this one, is left alone.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use kr_ipc::identity::{
    ProcessState, Stop, Stopped, process_start_identity, process_state, stop_process,
};
use kr_protocol::identity::ProcessStartIdentity;

/// A process that runs until it is ended and, on Unix, ignores terminate and hang-up.
fn stubborn() -> Child {
    #[cfg(unix)]
    let mut command = {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "trap '' TERM HUP; exec sleep 600"]);
        command
    };
    #[cfg(windows)]
    let mut command = {
        let root = std::env::var_os("SystemRoot").expect("the system directory");
        let mut command = Command::new(
            std::path::Path::new(&root)
                .join("System32")
                .join("PING.EXE"),
        );
        command.args(["-n", "600", "127.0.0.1"]);
        command
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("starts the process")
}

/// Reads the identity of a child once its program is the one it was started to run.
fn identity_of(child: &Child) -> ProcessStartIdentity {
    let started = Instant::now();
    loop {
        if let Ok(identity) = process_start_identity(child.id()) {
            // A child that has not yet run `exec` is the shell; its start does not change at
            // `exec`, so this is the identity of the process whichever program it runs.
            return identity;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the child never appeared"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Waits for a child this test started to end, and says whether it did within the bound.
fn ended(child: &mut Child) -> bool {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(60) {
        if child.try_wait().expect("asks the child").is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Ends a child this test started, whatever the test did.
struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_recorded_process_is_ended_by_its_identity() {
    // The control: the identity that was recorded stops the process that was recorded.
    let mut child = Reaped(stubborn());
    let identity = identity_of(&child.0);
    assert_eq!(stop_process(&identity, Stop::Kill), Stopped::Signalled);
    assert!(ended(&mut child.0), "the process ended");
    assert_eq!(process_state(&identity), ProcessState::Ended);
}

#[test]
fn a_number_that_names_another_process_is_left_alone() {
    // The isolation claim: the identifier is right and the start is not, which is what an
    // identifier looks like once the kernel has given it to another process.
    let child = Reaped(stubborn());
    let identity = identity_of(&child.0);
    let other = ProcessStartIdentity::new(
        identity.pid.get(),
        identity.source,
        identity.start_value.get().wrapping_add(1_000_000),
    );
    assert_eq!(stop_process(&other, Stop::Kill), Stopped::Gone);
    assert_eq!(
        process_state(&identity),
        ProcessState::Running,
        "the process that holds the number was not touched"
    );
}

#[test]
fn a_process_that_has_ended_is_gone() {
    let mut child = Reaped(stubborn());
    let identity = identity_of(&child.0);
    child.0.kill().expect("ends the child");
    child.0.wait().expect("collects the child");
    assert_eq!(stop_process(&identity, Stop::Kill), Stopped::Gone);
}

#[test]
fn the_process_asking_is_never_stopped() {
    let own = process_start_identity(std::process::id()).expect("this process");
    assert!(matches!(
        stop_process(&own, Stop::Kill),
        Stopped::Refused(_)
    ));
    assert_eq!(process_state(&own), ProcessState::Running);
}

#[cfg(unix)]
#[test]
fn a_request_to_end_can_be_ignored_and_force_cannot() {
    use std::os::unix::process::ExitStatusExt as _;

    let mut child = Reaped(stubborn());
    let identity = identity_of(&child.0);
    // A shell that has not yet reached `exec` has not yet set its traps; wait for the program.
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(60) {
        let listing = Command::new("ps")
            .args(["-o", "comm=", "-p", &child.0.id().to_string()])
            .output()
            .expect("lists the process");
        if String::from_utf8_lossy(&listing.stdout).contains("sleep") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(stop_process(&identity, Stop::Terminate), Stopped::Signalled);
    assert_eq!(stop_process(&identity, Stop::Kill), Stopped::Signalled);
    let status = child.0.wait().expect("collects the child");
    assert_eq!(
        status.signal(),
        Some(9),
        "the request was ignored, so it was the force that ended the process: {status:?}"
    );
}

#[cfg(windows)]
#[test]
fn there_is_no_request_to_end_that_is_not_the_end() {
    let child = Reaped(stubborn());
    let identity = identity_of(&child.0);
    assert_eq!(
        stop_process(&identity, Stop::Terminate),
        Stopped::Unsupported
    );
    assert_eq!(process_state(&identity), ProcessState::Running);
}
