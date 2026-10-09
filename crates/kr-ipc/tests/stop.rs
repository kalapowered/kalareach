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

/// A process that runs a new program between the reading and the signal has the identifier and
/// start that were recorded and a new version, and the kernel answers the old version with no such
/// process. That is not the process having ended: it is stopped under the version it has now.
///
/// The process waits on a pipe until the stop has read it, then runs a new program, and the test
/// waits for the new program before the signal is sent.
#[cfg(target_os = "macos")]
#[test]
fn a_process_that_runs_a_new_program_while_it_is_being_stopped_is_still_stopped() {
    let directory = std::env::temp_dir().join(format!("kr-stop-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("a directory for the pipe");
    let pipe = directory.join("go");
    assert!(
        Command::new("/usr/bin/mkfifo")
            .arg(&pipe)
            .status()
            .expect("makes the pipe")
            .success()
    );
    let mut child = Reaped(
        Command::new("/bin/sh")
            .args(["-c", "read line < \"$0\"; exec sleep 600"])
            .arg(&pipe)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("starts the process"),
    );
    let identity = identity_of(&child.0);
    let pid = child.0.id().to_string();

    let release = pipe.clone();
    let stopped = kr_ipc::identity::after_instance_read(
        move || {
            std::fs::write(&release, b"go\n").expect("lets the process go on");
            let started = Instant::now();
            loop {
                let program = Command::new("/bin/ps")
                    .args(["-o", "comm=", "-p", &pid])
                    .output()
                    .expect("asks for the program");
                if String::from_utf8_lossy(&program.stdout).contains("sleep") {
                    break;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(60),
                    "the process runs its new program"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        },
        || stop_process(&identity, Stop::Terminate),
    );

    assert!(
        matches!(stopped, Stopped::Signalled),
        "the same process under its new version is signalled: {stopped:?}"
    );
    assert!(ended(&mut child.0), "and it ends");
    let _ = std::fs::remove_dir_all(&directory);
}

/// A process that holds the signals a stop sends, and, when the test says so, writes down which of
/// them are waiting for it, one word to a line.
///
/// It blocks them and sets its own handlers, so a hang-up that the test process inherited as ignored
/// (as it is under `nohup`) is not one this process ignores, and a signal sent to it stays pending
/// until the test asks: a stop has sent every signal it sends by the time it returns, so what is
/// pending then is everything it sent, and the answer does not rest on how long anything took.
#[cfg(unix)]
fn holding(trigger: &std::path::Path, ready: &std::path::Path, report: &std::path::Path) -> Child {
    const PROGRAM: &str = r#"
        use POSIX qw(sigprocmask sigpending SIG_BLOCK SIGHUP SIGTERM SIGCONT);
        my ($trigger, $ready, $report) = @ARGV;
        $SIG{HUP} = sub { };
        $SIG{TERM} = sub { };
        $SIG{CONT} = sub { };
        my $held = POSIX::SigSet->new(SIGHUP, SIGTERM, SIGCONT);
        sigprocmask(SIG_BLOCK, $held);
        open(my $out, '>', $ready); close $out;
        select(undef, undef, undef, 0.02) until -e $trigger;
        my $pending = POSIX::SigSet->new;
        sigpending($pending);
        open($out, '>', "$report.part");
        print $out "HUP\n" if $pending->ismember(SIGHUP);
        print $out "TERM\n" if $pending->ismember(SIGTERM);
        print $out "CONT\n" if $pending->ismember(SIGCONT);
        close $out;
        rename "$report.part", $report;
        select(undef, undef, undef, 0.02) while 1;
    "#;
    Command::new("/usr/bin/perl")
        .args(["-e", PROGRAM])
        .arg(trigger)
        .arg(ready)
        .arg(report)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("starts the process")
}

/// Waits until the process holds the signals, sends one request, asks the process which signals are
/// waiting for it, and returns them.
#[cfg(unix)]
fn signals_sent(stop: Stop) -> Vec<String> {
    let directory = std::env::temp_dir().join(format!(
        "kr-stop-{}-{}",
        std::process::id(),
        kr_ipc::new_uuid()
    ));
    std::fs::create_dir_all(&directory).expect("a directory");
    let (trigger, ready, report) = (
        directory.join("trigger"),
        directory.join("ready"),
        directory.join("report"),
    );
    let child = Reaped(holding(&trigger, &ready, &report));
    let identity = identity_of(&child.0);
    let started = Instant::now();
    while !ready.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the process never held the signals"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(stop_process(&identity, stop), Stopped::Signalled);
    std::fs::write(&trigger, b"").expect("asks which are waiting");
    let started = Instant::now();
    while !report.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the process never said which signals were waiting"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let seen = std::fs::read_to_string(&report)
        .expect("the report")
        .lines()
        .map(str::to_owned)
        .collect();
    let _ = std::fs::remove_dir_all(&directory);
    seen
}

/// A request to terminate that is not a hang-up is a terminate and a continue and nothing else, and
/// a hang-up is a hang-up and a continue: the server of an application dies on the one and ends
/// what it started on the other.
#[cfg(unix)]
#[test]
fn a_terminate_without_a_hang_up_and_a_hang_up_alone_send_what_they_name() {
    assert_eq!(signals_sent(Stop::Term), ["TERM", "CONT"]);
    assert_eq!(signals_sent(Stop::Hangup), ["HUP", "CONT"]);
    assert_eq!(signals_sent(Stop::Terminate), ["HUP", "TERM", "CONT"]);
}

#[cfg(windows)]
#[test]
fn no_request_but_force_is_made_to_a_process_on_this_platform() {
    let child = Reaped(stubborn());
    let identity = identity_of(&child.0);
    assert_eq!(stop_process(&identity, Stop::Term), Stopped::Unsupported);
    assert_eq!(stop_process(&identity, Stop::Hangup), Stopped::Unsupported);
    assert_eq!(process_state(&identity), ProcessState::Running);
}
