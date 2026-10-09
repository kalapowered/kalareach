//! A server the worker starts for a session is a root of the session's record of what it owns.
//!
//! The processes here are real. A server is a shell that starts a command which leaves the server's
//! process group and its session, as the commands of an application's server do, and the
//! owned-process record is the one a worker keeps: it reads the trees below a server by parentage
//! and start identity, so the command is recorded while its parent runs and is still the session's
//! after its parent has gone.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-07.60 | a server's commands are recorded below it, each below its own server, whether or not the server runs; a descendant of one whose server has gone is found too |
//! | KR-REQ-07.66 | the session's request to stop reaches a server's commands and leaves the server to its owner; the record names the server, so that a later daemon asks it without a hang-up |

#![cfg(unix)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use kr_ipc::identity::{ProcessState, Stop, Stopped, process_lineage, process_state, stop_process};
use kr_protocol::identity::ProcessStartIdentity;
use kr_worker::ownership::{OwnedProcesses, OwnershipBoundary, force_stop, request_stop};

/// How long a test waits for something that should happen promptly, before it calls it a failure.
const LIVENESS: Duration = Duration::from_secs(60);

/// A process the test started, ended whatever the test did.
struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A command a server started in a group and a session of its own, ended whatever the test did.
struct Escaped(Option<ProcessStartIdentity>);

impl Drop for Escaped {
    fn drop(&mut self) {
        if let Some(identity) = self.0.take() {
            let _ = stop_process(&identity, Stop::Kill);
        }
    }
}

fn identity_of(child: &Child) -> ProcessStartIdentity {
    kr_ipc::identity::process_start_identity(child.id()).expect("the child's identity")
}

fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let started = Instant::now();
    while !condition() {
        assert!(started.elapsed() < LIVENESS, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn ended(identity: &ProcessStartIdentity) -> bool {
    matches!(process_state(identity), ProcessState::Ended)
}

fn pid_of(identity: &ProcessStartIdentity) -> u32 {
    identity.pid.get().try_into().expect("a process number")
}

/// Starts `program` with `arguments` under `perl`, which gives it the default disposition for a
/// hang-up whatever this test process inherited: a hang-up is ignored in a process started under
/// `nohup`, and a server or a command that ignored one would make "it was never sent" and "it was
/// sent and ignored" the same.
fn start(program: &str, arguments: &[&str]) -> Child {
    Command::new("/usr/bin/perl")
        .args(["-e", "$SIG{HUP} = q(DEFAULT); exec @ARGV", program])
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("starts the process")
}

/// One server, the command it started, and where the command left to.
struct Server {
    process: Reaped,
    identity: ProcessStartIdentity,
    command: Escaped,
    command_identity: ProcessStartIdentity,
}

impl Server {
    /// Starts a server, which runs until it is ended, and a command it starts with `script`, in a
    /// session of its own, whose process number the server writes in `directory/name`.
    fn start(directory: &Path, name: &str, script: &str) -> Self {
        let written = directory.join(name);
        let command = format!(
            "perl -MPOSIX -e '$SIG{{HUP}} = q(DEFAULT); POSIX::setsid(); exec @ARGV' \
             /bin/sh -c '{script}' & \
             echo $! > '{file}.part' && mv '{file}.part' '{file}'; \
             while :; do sleep 0.2; done",
            file = written.display()
        );
        let process = Reaped(start("/bin/sh", &["-c", &command]));
        let identity = identity_of(&process.0);
        eventually("the server never started its command", || written.exists());
        let command_pid: u32 = std::fs::read_to_string(&written)
            .expect("the command's number")
            .trim()
            .parse()
            .expect("a number");
        let command_identity =
            kr_ipc::identity::process_start_identity(command_pid).expect("the command's identity");
        // The command has been started, and not yet necessarily left: it leaves when it has set up
        // its session, a moment after the server wrote its number down.
        let server_group = process_lineage(process.0.id())
            .expect("the server's lineage")
            .group;
        eventually("the command never left the server's group", || {
            process_lineage(command_pid).is_ok_and(|lineage| lineage.group != server_group)
        });
        Self {
            process,
            identity,
            command: Escaped(Some(command_identity.clone())),
            command_identity,
        }
    }
}

/// A record established for a session whose root shell is `shell`, over a group number no process
/// leads, so the boundary lists nothing of its own.
fn record_for(shell: &Reaped) -> OwnedProcesses {
    OwnedProcesses::establish(
        OwnershipBoundary::TerminalGroup {
            group: u32::MAX - 1,
            terminal: None,
        },
        identity_of(&shell.0),
    )
}

fn a_shell() -> Reaped {
    Reaped(start("/bin/sh", &["-c", "exec sleep 600"]))
}

/// Observes until `wanted` is recorded below `root`.
fn observe_until_below(
    owned: &mut OwnedProcesses,
    root: &ProcessStartIdentity,
    wanted: &ProcessStartIdentity,
) {
    eventually("the process was never recorded below the server", || {
        owned.observe();
        owned.below_backend(root).contains(wanted)
    });
}

/// KR-REQ-07.60, KR-REQ-07.66. The command is recorded below the server while the server runs,
/// though it is in no group or session the session's boundary holds, and the session's request to
/// stop reaches the command and leaves the server, which its owner asks to end. The record names
/// the server beside the command, so that a daemon that finds it after a crash can ask it without
/// a hang-up, and a record of a session with no server is the record it was before servers.
#[test]
fn kr_req_07_60_a_servers_commands_are_recorded_below_it_and_the_session_s_stop_leaves_the_server()
{
    let directory = kr_ipc::testing::TempHost::create();
    let shell = a_shell();
    let mut server = Server::start(directory.root(), "command", "exec sleep 600");
    let mut owned = record_for(&shell);
    let plain = owned.record();
    owned.add_backend(server.identity.clone());
    observe_until_below(&mut owned, &server.identity, &server.command_identity);

    let command = process_lineage(pid_of(&server.command_identity)).expect("the command's lineage");
    let parent = process_lineage(pid_of(&server.identity)).expect("the server's lineage");
    assert_ne!(
        command.group, parent.group,
        "the command has a group of its own"
    );
    assert_eq!(
        u64::from(command.parent),
        server.identity.pid.get(),
        "and the server is its parent"
    );

    let record = owned.record();
    assert_eq!(record.backends, vec![server.identity.clone()]);
    assert!(
        record.processes.contains(&server.identity)
            && record.processes.contains(&server.command_identity),
        "the record holds the server and its command: {record:?}"
    );
    let encoded = kr_cbor::to_canonical_vec(&record).expect("encodes");
    let decoded: kr_worker::ownership::OwnedRecord =
        kr_cbor::from_canonical_slice(&encoded, &kr_cbor::Limits::DEFAULT).expect("decodes");
    assert_eq!(decoded, record, "and it reads back as it was written");
    let plain_encoded = kr_cbor::to_canonical_vec(&plain).expect("encodes");
    assert!(
        !plain_encoded.windows(8).any(|window| window == b"backends"),
        "a record with no server does not name the member, so it is the record it was before"
    );
    let from_before: kr_worker::ownership::OwnedRecord =
        kr_cbor::from_canonical_slice(&plain_encoded, &kr_cbor::Limits::DEFAULT)
            .expect("a record without the member decodes");
    assert!(from_before.backends.is_empty());

    request_stop(&owned);
    eventually(
        "the session's request to stop never reached the command",
        || ended(&server.command_identity),
    );
    assert_eq!(
        process_state(&server.identity),
        ProcessState::Running,
        "the hang-up that ended the command was not sent to the server, which its owner asks"
    );

    force_stop(&owned);
    eventually("the force never reached the server", || {
        ended(&server.identity)
    });
    let _ = server.process.0.wait();
    server.command.0 = None;
}

/// KR-REQ-07.60. A command whose server has gone is still the session's: it was recorded while its
/// parent ran, a process it starts afterwards is found, and each is stopped by its identity after
/// the server has been reparented away.
#[test]
fn kr_req_07_60_a_command_whose_server_has_gone_is_still_read_and_stopped() {
    let directory = kr_ipc::testing::TempHost::create();
    let go = directory.root().join("go");
    let grandchild = directory.root().join("grandchild");
    // The command waits for the test to say the server is gone, and only then starts a process of
    // its own, so that process is one the walk can only find from the command.
    let script = format!(
        "while [ ! -e {go} ]; do sleep 0.05; done; sleep 600 & echo $! > {grandchild}.part; mv {grandchild}.part {grandchild}; wait",
        go = go.display(),
        grandchild = grandchild.display()
    );
    let shell = a_shell();
    let mut server = Server::start(directory.root(), "command", &script);
    let mut owned = record_for(&shell);
    owned.add_backend(server.identity.clone());
    observe_until_below(&mut owned, &server.identity, &server.command_identity);

    assert_eq!(
        stop_process(&server.identity, Stop::Kill),
        Stopped::Signalled
    );
    let _ = server.process.0.wait();
    assert!(ended(&server.identity));
    std::fs::write(&go, b"").expect("lets the command go on");
    eventually("the command never started its process", || {
        grandchild.exists()
    });
    let grandchild_pid: u32 = std::fs::read_to_string(&grandchild)
        .expect("the process's number")
        .trim()
        .parse()
        .expect("a number");
    let grandchild_identity =
        kr_ipc::identity::process_start_identity(grandchild_pid).expect("its identity");
    let grandchild_guard = Escaped(Some(grandchild_identity.clone()));

    eventually(
        "the process the orphaned command started was never recorded",
        || {
            owned.observe();
            owned.record().processes.contains(&grandchild_identity)
        },
    );
    assert_ne!(
        u64::from(
            process_lineage(pid_of(&server.command_identity))
                .expect("lineage")
                .parent
        ),
        server.identity.pid.get(),
        "the command has been given to another parent"
    );
    assert!(
        owned
            .below_backend(&server.identity)
            .contains(&grandchild_identity),
        "and the process it started is below the server it was read below"
    );

    request_stop(&owned);
    eventually(
        "the session's request to stop never reached the process",
        || ended(&grandchild_identity) && ended(&server.command_identity),
    );
    drop(grandchild_guard);
    server.command.0 = None;
}

/// KR-REQ-07.60. What is recorded below one server is below that server and no other: a session can
/// hold two, and stopping the commands of the one must not name the other or its commands.
#[test]
fn kr_req_07_60_what_is_recorded_below_a_server_is_below_that_server_only() {
    let directory = kr_ipc::testing::TempHost::create();
    let shell = a_shell();
    let first = Server::start(directory.root(), "first", "exec sleep 600");
    let second = Server::start(directory.root(), "second", "exec sleep 600");
    let mut owned = record_for(&shell);
    owned.add_backend(first.identity.clone());
    owned.add_backend(second.identity.clone());
    observe_until_below(&mut owned, &first.identity, &first.command_identity);
    observe_until_below(&mut owned, &second.identity, &second.command_identity);

    for (server, other) in [(&first, &second), (&second, &first)] {
        let below = owned.below_backend(&server.identity);
        assert!(
            below.contains(&server.command_identity),
            "the server's own command is below it: {below:?}"
        );
        assert!(
            !below.contains(&other.identity) && !below.contains(&other.command_identity),
            "nothing of the other server is below this one: {below:?}"
        );
    }
}

/// KR-REQ-07.60. A session whose boundary is complete does not read as completely covered once a
/// server runs outside it, though the server has ended and nothing is left: what it started was
/// read by parentage, and a process that left between two readings was not seen.
#[test]
fn kr_req_07_60_a_session_that_had_a_server_never_reads_complete() {
    let mut shell = a_shell();
    let mut owned = OwnedProcesses::establish(
        OwnershipBoundary::ControlGroup {
            path: std::path::PathBuf::from("/sys/fs/cgroup/kalareach/session"),
        },
        kr_ipc::identity::ended_process_identity(4_000_003),
    );
    assert_eq!(
        owned.coverage(),
        kr_protocol::session::OwnershipCoverage::Complete,
        "the control: with nothing left and a complete boundary the cover is complete"
    );
    let server = identity_of(&shell.0);
    owned.add_backend(server.clone());
    shell.0.kill().expect("ends the server");
    let _ = shell.0.wait();
    assert!(ended(&server));
    owned.observe();
    assert!(
        owned.surviving().is_empty(),
        "nothing of the server is left"
    );
    assert_eq!(
        owned.coverage(),
        kr_protocol::session::OwnershipCoverage::Incomplete,
        "and the cover is incomplete all the same"
    );
    assert!(
        owned
            .unestablished()
            .iter()
            .any(|note| note.contains("parentage")),
        "because a server's commands are read by parentage, which the record says: {:?}",
        owned.unestablished()
    );
}

/// KR-REQ-07.66. A process the session's stop could not signal is noted as something this host could
/// not do, so the receipt says why it is still running. The process here is this test, which a stop
/// never signals, as a process with no hold the platform offers is one it must not signal by number.
#[test]
fn kr_req_07_66_a_process_the_session_s_stop_could_not_signal_is_noted() {
    let mut owned = OwnedProcesses::establish(
        OwnershipBoundary::TerminalGroup {
            group: u32::MAX - 1,
            terminal: None,
        },
        kr_ipc::identity::current_process_start_identity().expect("this process"),
    );
    owned.observe();
    assert!(
        owned.unestablished().is_empty(),
        "the control: nothing is noted before the stop"
    );
    request_stop(&owned);
    assert!(
        owned
            .unestablished()
            .iter()
            .any(|note| note.contains("was not signalled")),
        "the stop says that it could not signal the process: {:?}",
        owned.unestablished()
    );
}
