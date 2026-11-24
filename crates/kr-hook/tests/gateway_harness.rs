//! The harness the gateway suites share, on each platform it runs on.
//!
//! The gateway suites (`gateway_launch.rs`, `gateway_remote.rs`) run where a worker runs a
//! gateway, and what they stand on is proved here on its own: the stand-in the harness places, the
//! group every launch of a test runs in, and the file a launched program's output goes to. A case
//! of a suite that failed for one of these would name the gateway, so each is a case of its own.
//! Build the stand-in before a package-scoped run (`cargo build -p kr-codex-stand-in`); a run of
//! the workspace builds it.

mod common;

use std::path::Path;
use std::process::Command;

use common::gateway::{COMMAND, Gateway, built_stand_in, eventually};
use common::session::LaunchGroup;
use kr_ipc::identity::{ProcessState, process_start_identity, process_state};

/// The command a server starts for a turn, as a program a test can start: it stays for two
/// minutes and has a process of its own below it.
fn lingering() -> Command {
    let argv: Vec<String> = serde_json::from_str(COMMAND).expect("the harness's command is a list");
    let (program, arguments) = argv.split_first().expect("a program");
    let mut command = Command::new(program);
    command.args(arguments);
    command
}

/// Waits until the process `identity` names has ended.
fn ends(what: &str, identity: &kr_protocol::identity::ProcessStartIdentity) {
    eventually(what, || process_state(identity) == ProcessState::Ended);
}

/// The harness places the stand-in the build produced as the `codex` a shell finds, and the
/// copy it places is that program, not another that happens to start.
#[test]
fn the_harness_places_the_built_stand_in_as_the_codex_a_shell_finds() {
    let shell = Gateway::new();
    let name = shell
        .executable
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .expect("a text name");
    assert_eq!(name, if cfg!(windows) { "codex.exe" } else { "codex" });
    assert_eq!(
        std::fs::read(&shell.executable).expect("the placed stand-in"),
        std::fs::read(built_stand_in()).expect("the built stand-in"),
        "the placed copy is the built program"
    );
    let version = Command::new(&shell.executable)
        .arg("--version")
        .output()
        .expect("the placed stand-in starts");
    assert!(
        version.status.success(),
        "the placed stand-in answers its version: {}",
        String::from_utf8_lossy(&version.stderr)
    );
    assert!(
        shell.servers().is_empty(),
        "a session that launched nothing runs no server"
    );
}

/// What a launched program prints reaches the file the test reads, line by line, and the program's
/// end is read as its own status.
#[test]
fn a_launched_program_prints_to_the_file_the_test_reads_and_ends_with_its_status() {
    let shell = Gateway::new();
    #[cfg(unix)]
    let command = {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "echo first line; echo second line; exit 3"]);
        command
    };
    #[cfg(windows)]
    let command = {
        let mut command = Command::new("cmd.exe");
        command.args(["/d", "/c", "echo first line& echo second line& exit /b 3"]);
        command
    };
    let mut launched = shell.start(command, "printed");
    launched.prints("first line");
    launched.prints("second line");
    assert_eq!(launched.ends().code(), Some(3));
}

/// A launch ends with its group: the program a test started in the group is gone once the group
/// has been dropped, which is what keeps a launch that waits for something only its test does from
/// outliving the test.
#[test]
fn a_group_ends_a_launch_when_it_is_dropped() {
    let group = LaunchGroup::new();
    let mut launched = group.spawn(&mut lingering()).expect("the launch starts");
    assert!(
        launched
            .try_wait()
            .expect("the launch is readable")
            .is_none(),
        "the launch runs"
    );

    drop(group);
    eventually("the launch ended with its group", || {
        launched
            .try_wait()
            .expect("the launch is readable")
            .is_some()
    });
}

/// The job a launch runs in holds what the launch started, wherever it is below it, and ends
/// all of it with the group.
#[cfg(windows)]
#[test]
fn a_groups_job_holds_what_a_launch_started_and_ends_it() {
    let group = LaunchGroup::new();
    let mut launched = group.spawn(&mut lingering()).expect("the launch starts");
    let mut members = Vec::new();
    eventually("the launch started a process of its own", || {
        members = group.members();
        members.len() >= 2
    });
    assert!(
        members.contains(&launched.id()),
        "the job holds the launch itself: {members:?}"
    );
    let identities: Vec<_> = members
        .iter()
        .map(|pid| process_start_identity(*pid).expect("a member is a process"))
        .collect();

    drop(group);
    for identity in &identities {
        ends("everything the launch held ended with its group", identity);
    }
    let _ = launched.wait();
}

/// A launch that was created held and has no job yet is ended and collected when what holds it is
/// dropped, as it is when its placement in the group's job fails.
#[cfg(windows)]
#[test]
fn a_held_launch_that_no_job_took_is_ended_when_it_is_dropped() {
    let held =
        common::session::HeldChild::start(&mut lingering()).expect("the launch is created held");
    let identity = process_start_identity(held.id()).expect("a process");
    assert_eq!(
        process_state(&identity),
        ProcessState::Running,
        "the launch was created and is held, so it has not ended"
    );

    drop(held);
    assert_eq!(
        process_state(&identity),
        ProcessState::Ended,
        "the launch was ended and collected when what held it was dropped"
    );
}

/// The role the test binary takes when a case starts it again to be the process that holds a group
/// and then goes without letting go of it.
const HOLDER: &str = "KR_HARNESS_GROUP_HOLDER";

/// Holds a group and a launch in it, says which, waits to be told, and ends without dropping
/// anything, as a test whose process is killed does.
fn hold(directory: &Path) -> ! {
    let group = LaunchGroup::new();
    let launched = group.spawn(&mut lingering()).expect("the launch starts");
    let named = directory.join("program.new");
    std::fs::write(&named, launched.id().to_string()).expect("the launch is named");
    std::fs::rename(&named, directory.join("program")).expect("the name is published");
    eventually("the case said to go", || directory.join("go").exists());
    // `exit` runs no destructor: neither the group nor the launch is let go of by this process.
    std::process::exit(0)
}

/// A group ends what it holds by itself when the test's process is gone: the process that held it
/// ends without dropping it, and the program the group held is ended all the same.
#[test]
fn a_group_ends_what_it_holds_when_the_test_process_is_gone() {
    if let Some(directory) = std::env::var_os(HOLDER) {
        hold(Path::new(&directory));
    }
    let host = kr_ipc::testing::TempHost::create();
    let mut holder = Command::new(std::env::current_exe().expect("this test's program"))
        .args([
            "--exact",
            "a_group_ends_what_it_holds_when_the_test_process_is_gone",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HOLDER, host.root())
        .stdin(std::process::Stdio::null())
        .spawn()
        .expect("the holder starts");
    eventually("the holder started its launch", || {
        host.root().join("program").exists()
    });
    let pid: u32 = std::fs::read_to_string(host.root().join("program"))
        .expect("the launch's name")
        .trim()
        .parse()
        .expect("a process identifier");
    let identity = process_start_identity(pid).expect("the launch is a process");
    assert_eq!(process_state(&identity), ProcessState::Running);

    std::fs::write(host.root().join("go"), b"").expect("the holder is told");
    assert!(holder.wait().expect("the holder ends").success());
    // On Windows the system ends it when the job's last handle goes with the holder; on Unix the
    // group's leader does, which looks once a second.
    ends(
        "the launch ended with the process that held its group",
        &identity,
    );
}
